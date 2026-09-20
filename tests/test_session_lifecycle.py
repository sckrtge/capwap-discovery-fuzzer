"""State machine, responder and oracle tests with a scripted fake transport."""

from __future__ import annotations

import queue
import struct

import pytest

from capwap_discovery_fuzzer.session import builders
from capwap_discovery_fuzzer.session.oracle import (
    DISJOIN_REASON_MAP,
    Outcome,
    classify_reply,
    verdict_for,
)
from capwap_discovery_fuzzer.session.responder import Responder
from capwap_discovery_fuzzer.session.statemachine import (
    Stage,
    SessionStateMachine,
    TIMEOUT_JOIN_RESPONSE,
)
from tests.test_session_builders import _golden_identity


class FakeTransport:
    """Scripted duplex transport: pop answers inbound, records outbound."""

    def __init__(self, inbound: list[bytes] | None = None):
        self.inbound = list(inbound or [])
        self.sent: list[bytes] = []
        self.alive = True

    def recv(self, timeout: float = 0.0) -> bytes:
        return self.inbound.pop(0) if self.inbound else b""

    def send(self, data: bytes) -> None:
        if not self.alive:
            raise OSError("dead")
        self.sent.append(data)

    @property
    def is_alive(self) -> bool:
        return self.alive


# ------------------------------------------------------------- state machine

def test_state_machine_happy_path():
    sm = SessionStateMachine(identity=_golden_identity())
    sm.advance(Stage.DTLS)
    sm.advance(Stage.JOIN)
    frame = sm.make_join(session_id=bytes(16))
    assert isinstance(frame, bytes) and frame[:1] == b"\x00"
    sm.advance(Stage.CONFIG)
    assert sm.make_config_status()
    sm.advance(Stage.DATA_CHECK)
    assert sm.make_change_state()
    sm.advance(Stage.RUN)
    assert sm.make_echo(seq_num=9)
    assert sm.make_config_update_response(seq_num=9)
    lifetime = sm.mark_dead()
    assert lifetime > 0
    with pytest.raises(RuntimeError):
        sm.advance(Stage.JOIN)  # DEAD is terminal


def test_state_machine_rejects_wrong_stage_send():
    sm = SessionStateMachine()
    with pytest.raises(RuntimeError, match="state violation"):
        sm.make_config_status()  # still in DISCOVERY


def test_illegal_transition():
    sm = SessionStateMachine()
    with pytest.raises(RuntimeError, match="illegal transition"):
        sm.advance(Stage.RUN)  # DISCOVERY -> RUN


def test_timeouts_are_measured_values():
    assert TIMEOUT_JOIN_RESPONSE == 15.0


# ------------------------------------------------------------------ responder

def _fips_update(seq: int = 2) -> bytes:
    """AC Configuration Update Request with the FIPS VSP, as seen in life44."""
    ident = _golden_identity()
    fips_vsp = bytes.fromhex("0040960000fc") + b"\x00\x00\x01\x00"
    from capwap_discovery_fuzzer.vendors.cisco.creator import _element
    from capwap_discovery_fuzzer.session.builders import _control_frame
    from capwap_discovery_fuzzer.session.builders import MSG_CONFIG_UPDATE_REQUEST
    return _control_frame(ident, MSG_CONFIG_UPDATE_REQUEST, seq,
                          [_element(37, fips_vsp)])


def test_responder_answers_config_update():
    ft = FakeTransport(inbound=[_fips_update(seq=2)])
    ident = _golden_identity()
    r = Responder(ft, ident)
    answered = r.poll_once()
    assert answered == 1
    assert len(ft.sent) == 1
    msgs = builders.parse_control_messages(ft.sent[0])
    assert msgs[0]["msg_type"] == builders.MSG_CONFIG_UPDATE_RESPONSE
    assert msgs[0]["seq"] == 2                       # echoes request seq
    from capwap_discovery_fuzzer.session.builders import result_code_of
    assert result_code_of(msgs[0]) == 0
    # and echoes the request's vendor payload back
    echoed = [t for t, _l, _v in msgs[0]["elements"] if t == 37]
    assert echoed == [37]


def test_responder_thread_answers_repeatedly():
    ft = FakeTransport(inbound=[_fips_update(seq=2), _fips_update(seq=3)])
    r = Responder(ft, _golden_identity(), poll_interval=0.05)
    r.start()
    import time
    deadline = time.time() + 2.0
    while len(r.answered) < 2 and time.time() < deadline:
        time.sleep(0.05)
    r.stop()
    assert len(r.answered) == 2
    assert len(ft.sent) == 2


def test_responder_survives_transport_errors():
    ft = FakeTransport()
    ft.alive = False
    r = Responder(ft, _golden_identity(), poll_interval=0.02)
    r.start()
    import time
    time.sleep(0.1)
    r.stop()  # must not have propagated the OSError


# --------------------------------------------------------------------- oracle

def test_classify_silence():
    assert classify_reply(b"") == (Outcome.SILENCE, None)


def test_classify_alert():
    alert = b"\x15" + bytes(30)
    assert classify_reply(alert) == (Outcome.ALERT, None)


def _join_response_bytes(code: int) -> bytes:
    ident = _golden_identity()
    from capwap_discovery_fuzzer.vendors.cisco.creator import (
        _element, _mac_optional_field, _vsp_value)
    from scapy.packet import Raw
    from capwap_discovery_fuzzer.request_creater import CAPWAP_Header, Control_Header
    elems = (_element(33, struct.pack(">I", code))
             / _element(37, _vsp_value(5, b"n")))
    hdr = CAPWAP_Header(version=0, type=0, Hlen=4, Rid=0, WBID=1, M=1)
    ch = Control_Header(MsgType=4, SeqNum=0, MsgElemsLen=len(bytes(elems)) + 3)
    return bytes(hdr / Raw(load=_mac_optional_field(ident.ap_mac)) / ch / elems)


def test_classify_result_code_success():
    outcome, code = classify_reply(_join_response_bytes(0))
    assert outcome == Outcome.ANSWERED and code == 0


def test_classify_result_code_failure():
    outcome, code = classify_reply(_join_response_bytes(8))
    assert outcome == Outcome.ANSWERED and code == 8  # HW not supported


def test_verdict_disjoin_gap_mapping():
    v = verdict_for("join", b"", disjoin_reason="Failure decoding max message size")
    assert v.outcome == Outcome.DISJOIN
    assert "Type 29" in (v.gap or "")
    assert v.gap == DISJOIN_REASON_MAP["Failure decoding max message size"]


def test_verdict_answered_dict_shape():
    v = verdict_for("join", _join_response_bytes(0), mutation={"method": "fuzz_elem_value"})
    d = v.as_dict()
    assert d["outcome"] == "answered"
    assert d["result_code"] == 0
    assert d["mutation"] == {"method": "fuzz_elem_value"}
    assert "gap" not in d
