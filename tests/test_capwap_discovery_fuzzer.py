"""Regression tests for capwap-discovery-fuzzer bug fixes.

Covers the defects verified on 2026-09-10:
- message-element iteration (Scapy getlayer nb starts at 1; name-based
  matching misses MessageElement_Valid) — previously every fuzz_elem_*
  method was a silent no-op
- fuzz_elem_duplicate splicing (add_payload would drop the rest of the chain)
- --seed reproducibility of mutated bytes (mutations previously used the
  unseeded global random module)
- load_request_from_pcap returns a clonable Packet (previously bytes, which
  crashed base_pkt.copy()) and the loaded packet is element-fuzzable
- ResponseParser must not strip a bogus "IP header" from CAPWAP version=4
  responses
- /proc/<pid>/stat parsing with spaces in the process name
"""

import json
import random
import socket
import struct
import threading
from pathlib import Path

import pytest
from scapy.packet import Packet
from typer.testing import CliRunner

from tests.cli_helpers import flat, invoke_cli
from capwap_discovery_fuzzer import lock_fuzzer
from capwap_discovery_fuzzer.capwap_discovery_fuzzer import CAPWAPDiscoveryFuzzer
from capwap_discovery_fuzzer.cli import app
from capwap_discovery_fuzzer.lock_fuzzer import parse_lock_fields
from capwap_discovery_fuzzer.payload_fuzzer import Payload_Fuzzer
from capwap_discovery_fuzzer.request_creater import (
    CAPWAP_Header,
    Control_Header,
    MessageElement,
    Payload_Creator,
)
from capwap_discovery_fuzzer.response_parser import ResponseParser
from capwap_discovery_fuzzer.vendors.cisco.creator import CiscoPayloadCreator
from capwap_discovery_fuzzer.vendors.cisco.fuzzer import CiscoCAPWAPDiscoveryFuzzer
from capwap_discovery_fuzzer.vendors.opencapwap.fuzzer import _parse_stat_cpu_times

def _locate_pcap() -> Path:
    here = Path(__file__).resolve().parent
    for base in (here.parent, Path.cwd(), Path.cwd().parent):
        candidate = base / "pcaps" / "sample_discovery_request.pcap"
        if candidate.exists():
            return candidate
    pytest.skip("pcaps/sample_discovery_request.pcap not found")


_PCAP = _locate_pcap()

ELEM_METHODS = [
    "fuzz_elem_type",
    "fuzz_elem_length",
    "fuzz_elem_length_zero",
    "fuzz_elem_length_overflow",
    "fuzz_elem_value",
    "fuzz_elem_drop",
    "fuzz_elem_drop_required",
    "fuzz_elem_duplicate",
    "fuzz_elem_insert_unknown",
]


@pytest.fixture
def generic_base():
    return Payload_Creator(rng=random.Random(1)).create_discovery_request(valid=True)


@pytest.fixture
def cisco_base():
    return CiscoPayloadCreator(rng=random.Random(2)).create_discovery_request(valid=True)


# ---------------------------------------------------------------- elements

def test_iter_message_elements_generic(generic_base):
    assert len(Payload_Fuzzer(generic_base)._iter_message_elements(generic_base)) == 5


def test_iter_message_elements_cisco(cisco_base):
    assert len(Payload_Fuzzer(cisco_base)._iter_message_elements(cisco_base)) == 11


@pytest.mark.parametrize("method_name", ELEM_METHODS)
def test_elem_methods_mutate_packet(generic_base, method_name):
    f = Payload_Fuzzer(generic_base, rng=random.Random(42))
    before = bytes(generic_base)
    after = bytes(getattr(f, method_name)(generic_base))
    assert after != before, f"{method_name} did not change the packet"


@pytest.mark.parametrize("msg_type", [38, 39])
def test_elem_value_by_type_mutates(generic_base, msg_type):
    f = Payload_Fuzzer(generic_base, rng=random.Random(7))
    assert bytes(f.fuzz_elem_value_by_type(msg_type, generic_base)) != bytes(generic_base)


def test_elem_duplicate_preserves_rest_of_chain(generic_base):
    f = Payload_Fuzzer(generic_base, rng=random.Random(3))
    out = f.fuzz_elem_duplicate(generic_base)
    assert len(f._iter_message_elements(out)) == 6


def test_elem_order_shuffle_mutates_packet(generic_base):
    # shuffle can legitimately yield the identity permutation for a single
    # seed, so require a change across several seeds
    for seed in range(10):
        f = Payload_Fuzzer(generic_base, rng=random.Random(seed))
        if bytes(f.fuzz_elem_order_shuffle(generic_base)) != bytes(generic_base):
            return
    pytest.fail("fuzz_elem_order_shuffle produced no change for seeds 0-9")


def test_elem_methods_work_on_cisco_base(cisco_base):
    f = Payload_Fuzzer(cisco_base, rng=random.Random(5))
    out = f.fuzz_elem_value_by_type(38, cisco_base)
    assert bytes(out) != bytes(cisco_base)


# ---------------------------------------------------------------- seed

def _simulate_round(seed: int) -> str:
    rng = random.Random(seed)
    base = Payload_Creator(rng=rng).create_discovery_request(valid=True)
    f = Payload_Fuzzer(base, rng=rng)
    pool = [f.fuzz_capwap_header, f.fuzz_elem_value, f.fuzz_elem_duplicate, f.fuzz_elem_drop]
    chosen = rng.choices(pool, k=2)
    pkt = base.copy()
    for m in chosen:
        pkt = m(pkt)
    return bytes(pkt).hex()


def test_same_seed_reproduces_mutated_bytes():
    assert _simulate_round(123) == _simulate_round(123)


def test_different_seed_produces_different_bytes():
    assert _simulate_round(123) != _simulate_round(999)


# ---------------------------------------------------------------- pcap

def test_load_request_from_pcap_returns_clonable_packet():
    pkt = CAPWAPDiscoveryFuzzer.load_request_from_pcap(str(_PCAP))
    assert isinstance(pkt, Packet)
    assert pkt.copy() is not None  # fuzzing() clones the base packet each round


def test_pcap_loaded_packet_is_element_fuzzable():
    pkt = CAPWAPDiscoveryFuzzer.load_request_from_pcap(str(_PCAP))
    f = Payload_Fuzzer(pkt, rng=random.Random(5))
    assert len(f._iter_message_elements(pkt)) >= 1
    assert bytes(f.fuzz_elem_type(pkt)) != bytes(pkt)


# ---------------------------------------------------------------- response parser

def _build_response(version: int) -> bytes:
    elems = (
        MessageElement(Type=1, Length=2, Value=b"\x00\x01")
        / MessageElement(Type=4, Length=2, Value=b"ac")
        / MessageElement(Type=10, Length=6, Value=b"\x0a\x00\x00\x01\x00\x05")
    )
    ctrl = Control_Header(MsgType=2, SeqNum=1, MsgElemsLen=len(bytes(elems)) + 3, Flags=0)
    hdr = CAPWAP_Header(version=version, Hlen=2, WBID=1)
    return bytes(hdr / ctrl / elems)


@pytest.mark.parametrize("version", [0, 4])
def test_response_parser_accepts_any_capwap_version(version):
    result = ResponseParser().parse_response(_build_response(version))
    assert result["response_type"] == "valid"
    assert result["error_type"] is None


# ---------------------------------------------------------------- proc stat

def test_parse_stat_cpu_times_with_spaced_comm():
    line = "1234 (my fancy proc) S 1 0 0 0 -1 4194624 10 20 30 40 777 888 0 0"
    assert _parse_stat_cpu_times(line) == (777, 888)


def test_parse_stat_cpu_times_malformed_returns_none():
    assert _parse_stat_cpu_times("garbage") is None


# ---------------------------------------------------------------- lock mode

ALL_TOKENS = {"capwap-header", "msgtype", "msgelemslen", "cisco-fingerprint"}


def test_parse_lock_fields_off_by_default():
    assert parse_lock_fields(None) is None


def test_parse_lock_fields_all_expands():
    assert parse_lock_fields("all") == ALL_TOKENS


def test_parse_lock_fields_tolerates_case_and_spaces():
    assert parse_lock_fields(" MsgType , CISCO-FINGERPRINT ") == {
        "msgtype", "cisco-fingerprint"
    }


@pytest.mark.parametrize("value", ["", "  ", "msgtype,bogus", "msgelemslenn"])
def test_parse_lock_fields_rejects_bad_input(value):
    with pytest.raises(ValueError):
        parse_lock_fields(value)


def test_lock_layout_matches_cisco_seed(cisco_base):
    raw = bytes(cisco_base)
    layout = lock_fuzzer.parse_layout(raw)

    assert layout.header_end == 16          # Hlen=4: 16-byte header incl. Radio MAC
    assert layout.ctrl_off == 16
    # The seed's own MsgElemsLen counts MsgElemsLen(2)+Flags(1)+elements (RFC 5415).
    assert struct.unpack_from(">H", raw, layout.ctrl_off + 5)[0] == 231
    assert [e.type for e in layout.elements] == [
        20, 38, 39, 41, 44, 45, 28, 1048, 1048, 37, 37
    ]
    # Element region = 231 - 3 = 228 bytes = 11 TLV headers (4B each) + 184 value bytes.
    tlv_bytes = 4 * len(layout.elements)
    assert sum(lock_fuzzer.len_elem(e) for e in layout.elements) == len(raw) - 24 - tlv_bytes
    assert len(raw) - 24 - tlv_bytes == 184


def test_lock_frozen_framing_is_byte_identical(cisco_base):
    raw = bytes(cisco_base)
    layout = lock_fuzzer.parse_layout(raw)
    spans = lock_fuzzer.mutable_spans(raw, ALL_TOKENS)
    mutated, label = lock_fuzzer.mutate_equal_length(raw, spans, random.Random(7))

    assert len(mutated) == len(raw)                     # equal length
    assert mutated[:layout.header_end] == raw[:layout.header_end]
    assert mutated[layout.ctrl_off:layout.ctrl_off + 4] == raw[layout.ctrl_off:layout.ctrl_off + 4]
    assert mutated[layout.ctrl_off + 5:layout.ctrl_off + 7] == raw[layout.ctrl_off + 5:layout.ctrl_off + 7]
    assert mutated != raw                               # the edit did happen
    assert label.startswith("locked_equal_length_value:value-type")


def test_lock_conservative_set_leaves_only_non_fingerprint_values(cisco_base):
    raw = bytes(cisco_base)
    spans = lock_fuzzer.mutable_spans(raw, ALL_TOKENS)

    assert sorted(s.label for s in spans) == [
        "value-type1048", "value-type1048", "value-type41", "value-type44"
    ]
    assert sum(len(s) for s in spans) == 12


def test_lock_releasing_fingerprint_opens_every_element_value(cisco_base):
    raw = bytes(cisco_base)
    spans = lock_fuzzer.mutable_spans(raw, {"capwap-header", "msgtype", "msgelemslen"})

    assert len(spans) == 11
    # Only element *value* bytes are mutable in v1, so the 11 four-byte TLV
    # headers are excluded: 228 - 44 = 184.
    assert sum(len(s) for s in spans) == len(raw) - 24 - 4 * 11


def test_lock_fingerprint_values_untouched(cisco_base):
    raw = bytes(cisco_base)
    layout = lock_fuzzer.parse_layout(raw)
    base_values = {e.header_start: raw[e.value_start:e.value_end] for e in layout.elements}
    spans = lock_fuzzer.mutable_spans(raw, ALL_TOKENS)

    for seed in range(25):
        mutated, _ = lock_fuzzer.mutate_equal_length(raw, spans, random.Random(seed))
        for e in layout.elements:
            if e.type in lock_fuzzer.CISCO_FINGERPRINT_TYPES:
                assert mutated[e.value_start:e.value_end] == base_values[e.header_start]


def test_lock_mutation_stays_inside_a_mutable_span(cisco_base):
    raw = bytes(cisco_base)
    spans = lock_fuzzer.mutable_spans(raw, ALL_TOKENS)
    mutable_bytes = {i for s in spans for i in range(s.start, s.end)}

    # A one-byte span can legitimately draw its original value back (1/256), so
    # assert on the union across seeds instead of requiring every round to differ.
    all_changed: set[int] = set()
    for seed in range(25):
        mutated, _ = lock_fuzzer.mutate_equal_length(raw, spans, random.Random(seed))
        all_changed |= {i for i, (a, b) in enumerate(zip(raw, mutated)) if a != b}

    assert all_changed, "locked mode never changed a byte across 25 seeds"
    assert all_changed <= mutable_bytes


def test_lock_element_headers_and_lengths_untouched(cisco_base):
    raw = bytes(cisco_base)
    layout = lock_fuzzer.parse_layout(raw)
    spans = lock_fuzzer.mutable_spans(raw, {"msgtype", "msgelemslen"})

    mutated, _ = lock_fuzzer.mutate_equal_length(raw, spans, random.Random(3))
    for e in layout.elements:
        # TLV header (Type/Length) must survive; only Value bytes may change.
        assert mutated[e.header_start:e.value_start] == raw[e.header_start:e.value_start]
    # Element count/order and every declared Length are unchanged by construction.
    assert lock_fuzzer.parse_layout(mutated).elements == layout.elements


def test_lock_same_seed_reproduces_bytes_and_label(cisco_base):
    raw = bytes(cisco_base)
    spans = lock_fuzzer.mutable_spans(raw, ALL_TOKENS)

    first = lock_fuzzer.mutate_equal_length(raw, spans, random.Random(4242))
    second = lock_fuzzer.mutate_equal_length(raw, spans, random.Random(4242))
    third = lock_fuzzer.mutate_equal_length(raw, spans, random.Random(4243))

    assert first == second
    assert first[1] == second[1]
    assert first != third


def test_lock_without_mutable_span_returns_seed():
    # Framing frozen and the only element is a fingerprint type: nothing may move.
    raw = bytes(CAPWAP_Header(version=0, Hlen=2, WBID=1)
                / Control_Header(MsgType=1, SeqNum=0, MsgElemsLen=4, Flags=0)
                / MessageElement(Type=20, Length=1, Value=b"\x01"))
    spans = lock_fuzzer.mutable_spans(raw, ALL_TOKENS)

    assert spans == []
    mutated, label = lock_fuzzer.mutate_equal_length(raw, spans, random.Random(1))
    assert mutated == raw
    assert label == "locked_equal_length_value:none"


def test_lock_mode_off_keeps_original_pools(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)          # keep the session's capwap_log/ out of the repo
    fuzzer = CAPWAPDiscoveryFuzzer(ac_ip="127.0.0.1", seed=1)
    assert fuzzer.lock_fields is None


def test_cli_rejects_unknown_lock_token():
    # flat()/invoke_cli keep this width-independent: rich wraps error panels to
    # the terminal width, so a raw substring check passes locally and can fail in CI.
    result = invoke_cli(app, ["--ac-ip", "127.0.0.1", "--lock-fields", "msgtype,nonsense"])
    assert result.exit_code != 0
    assert "nonsense" in flat(result.output)


# ------------------------------------------------- lock mode, end to end

def _start_responder():
    """Local UDP responder so the fuzzing path can run without a real AC."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    stop = threading.Event()

    def serve():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                _, peer = sock.recvfrom(65535)
            except OSError:
                continue
            sock.sendto(b"\x00" * 8, peer)   # shape irrelevant; only requests are inspected

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return sock, port, stop, thread


def test_lock_end_to_end_requests_satisfy_invariants(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sock, port, stop, thread = _start_responder()
    try:
        fuzzer = CiscoCAPWAPDiscoveryFuzzer(
            ac_ip="127.0.0.1", ac_port=port, timeout=0.3, seed=7,
            lock_fields=ALL_TOKENS,
        )
        for i in range(20):
            fuzzer.fuzzing(round_number=i + 1)
    finally:
        stop.set()
        thread.join(timeout=2)
        sock.close()

    seed = bytes(CiscoPayloadCreator().create_discovery_request(valid=True))
    layout = lock_fuzzer.parse_layout(seed)
    records = [json.loads(line) for line in fuzzer.records_path.read_text().splitlines()]
    assert len(records) == 20

    mutated_something = False
    for record in records:
        data = bytes.fromhex(record["request_hex"])
        assert len(data) == len(seed)                       # 等长
        assert data[:layout.header_end] == seed[:layout.header_end]
        assert data[layout.ctrl_off:layout.ctrl_off + 4] == seed[layout.ctrl_off:layout.ctrl_off + 4]
        assert data[layout.ctrl_off + 5:layout.ctrl_off + 7] == seed[layout.ctrl_off + 5:layout.ctrl_off + 7]
        for elem in layout.elements:
            if elem.type in lock_fuzzer.CISCO_FINGERPRINT_TYPES:
                assert data[elem.value_start:elem.value_end] == seed[elem.value_start:elem.value_end]
        assert record["method_chain"][0].startswith("locked_equal_length_value:")
        mutated_something |= data != seed

    assert mutated_something, "locked mode never changed a packet in 20 rounds"


def test_unlocked_end_to_end_uses_original_pool(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sock, port, stop, thread = _start_responder()
    try:
        fuzzer = CiscoCAPWAPDiscoveryFuzzer(
            ac_ip="127.0.0.1", ac_port=port, timeout=0.3, seed=7,
        )
        for i in range(10):
            fuzzer.fuzzing(round_number=i + 1)
    finally:
        stop.set()
        thread.join(timeout=2)
        sock.close()

    records = [json.loads(line) for line in fuzzer.records_path.read_text().splitlines()]
    assert len(records) == 10
    for record in records:
        assert record["method_chain"]
        # Without --lock-fields the general safe/brutal pools must still be used.
        assert not any(m.startswith("locked_") for m in record["method_chain"])


def test_cli_records_lock_fields_in_session_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sock, port, stop, thread = _start_responder()
    try:
        result = CliRunner().invoke(app, [
            "--ac-ip", "127.0.0.1", "--ac-port", str(port),
            "--vendor", "cisco", "--rounds", "2", "--sleep", "0",
            "--lock-fields", "all",
        ])
    finally:
        stop.set()
        thread.join(timeout=2)
        sock.close()

    assert result.exit_code == 0, result.output
    session_files = list(tmp_path.glob("capwap_log/*/session.json"))
    assert len(session_files) == 1
    session = json.loads(session_files[0].read_text())
    assert session["lock_fields"] == sorted(ALL_TOKENS)


