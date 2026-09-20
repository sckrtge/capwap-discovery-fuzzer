"""Golden-byte and behaviour tests for :mod:`capwap_discovery_fuzzer.session`.

The golden files under ``tests/golden/`` are the exact bytes the C9800
controller accepted in the 2026-09-20 live round (life44: Join Response Result
Code 0, ``show ap summary`` showing ``CN  -C  ...  Registered``); builders must
reproduce them byte for byte so protocol knowledge survives refactoring.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from capwap_discovery_fuzzer.session import builders
from capwap_discovery_fuzzer.session.vsp import (
    CISCO_VENDOR_ID_U32,
    VSP_ELEM_REG_DOMAIN,
    build_reg_domain_vsp,
    decode_reg_domain_payload,
    decode_vsp,
    domain_string_for_code,
    encode_reg_domain_payload,
    encode_vsp,
)

GOLDEN = Path(__file__).parent / "golden"

#: Identity used for every golden capture (life44 parameters).
GOLDEN_IDENTITY_KWARGS = dict(
    radios=((0, 0x0D), (1, 0x0A)),
    num_encrypt=1,
    model=b"C9105AXI-C",
)


def _golden(name: str) -> bytes:
    return (GOLDEN / name).read_bytes()


def _golden_identity():
    from capwap_discovery_fuzzer.vendors.cisco.creator import ApIdentity
    return ApIdentity(**GOLDEN_IDENTITY_KWARGS)


# ------------------------------------------------------------------- builders

def test_build_join_request_matches_golden():
    ident = _golden_identity()
    pkt = builders.build_join_request(ident, session_id=bytes(16),
                                      local_ip="192.168.10.128", seq_num=0)
    assert bytes(pkt) == _golden("golden_join.bin")


def test_build_config_status_matches_golden():
    pkt = builders.build_config_status(_golden_identity(), seq_num=1)
    assert bytes(pkt) == _golden("golden_csr.bin")


def test_build_change_state_matches_golden():
    pkt = builders.build_change_state(_golden_identity(), seq_num=2)
    assert bytes(pkt) == _golden("golden_cse.bin")


def test_build_echo_matches_golden():
    pkt = builders.build_echo(_golden_identity(), seq_num=3)
    assert bytes(pkt) == _golden("golden_echo.bin")


def test_build_join_rejects_short_session_id():
    with pytest.raises(ValueError):
        builders.build_join_request(_golden_identity(), session_id=b"\x00" * 8)


def test_build_join_session_id_is_parameterised():
    sid = bytes(range(16))
    pkt = builders.build_join_request(_golden_identity(), session_id=sid)
    assert sid in bytes(pkt)
    assert sid not in _golden("golden_join.bin")  # golden used all-zero id


# ------------------------------------------------------------------ round trip

def test_roundtrip_parse_join():
    msgs = builders.parse_control_messages(_golden("golden_join.bin"))
    assert len(msgs) == 1
    msg = msgs[0]
    assert msg["msg_type"] == 3
    assert msg["seq"] == 0
    types = [t for t, _l, _v in msg["elements"]]
    assert types == [38, 39, 41, 44, 45, 28, 126, 126, 1048, 1048,
                     35, 29, 53, 30, 37, 37, 169]
    assert builders.result_code_of(msg) is None


def test_result_code_of_join_response():
    # Synthetic Join Response: header + Result Code success.
    from capwap_discovery_fuzzer.vendors.cisco.creator import (
        ApIdentity, _element, _mac_optional_field, _vsp_value)
    from scapy.packet import Raw
    from capwap_discovery_fuzzer.request_creater import CAPWAP_Header, Control_Header
    ident = ApIdentity()
    elems = (_element(33, (0).to_bytes(4, "big"))
             / _element(37, _vsp_value(5, b"x")))
    hdr = CAPWAP_Header(version=0, type=0, Hlen=4, Rid=0, WBID=1, M=1)
    ch = Control_Header(MsgType=4, SeqNum=0, MsgElemsLen=len(bytes(elems)) + 3)
    raw = bytes(hdr / Raw(load=_mac_optional_field(ident.ap_mac)) / ch / elems)
    msgs = builders.parse_control_messages(raw)
    assert builders.result_code_of(msgs[0]) == 0


def test_truncated_element_list_tolerated():
    # a truncated datagram must not crash the parser; it yields whatever
    # complete messages fit
    msgs = builders.parse_control_messages(_golden("golden_csr.bin")[:-6])
    assert isinstance(msgs, list)


# ------------------------------------------------------------------------ VSP

def test_vsp_encode_header_is_six_bytes():
    value = encode_vsp(0x7E, b"\x01\x02")
    assert value[:4] == CISCO_VENDOR_ID_U32.to_bytes(4, "big")
    assert value[4:6] == b"\x00\x7e"
    assert len(value) == 6 + 2


def test_vsp_decode_roundtrip():
    elem_id, data = decode_vsp(encode_vsp(0x00CF, bytes(4)))
    assert (elem_id, data) == (0x00CF, bytes(4))


def test_vsp_decode_rejects_wrong_vendor():
    import pytest
    with pytest.raises(ValueError):
        decode_vsp(b"\x00\x00\x00\x09\x00\x7e" + b"\x00" * 5)


def test_vsp_decode_rejects_short():
    import pytest
    with pytest.raises(ValueError):
        decode_vsp(b"\x00\x40\x96\x00\x00")


def test_reg_domain_vsp_layout():
    """The exact bytes the controller parsed in life44 (slot1/band1, code 0x10)."""
    vsp = build_reg_domain_vsp(0x01, 0x01, 0x01, 0x0010)
    assert vsp == bytes.fromhex("00409600007e") + bytes([0x01, 0x01, 0x01, 0x00, 0x10])
    assert decode_reg_domain_payload(vsp[6:]) == (0x01, 0x01, 0x01, 0x0010)


def test_reg_domain_rejects_out_of_range():
    import pytest
    with pytest.raises(ValueError):
        encode_reg_domain_payload(0x100, 1, 1, 1)
    with pytest.raises(ValueError):
        encode_reg_domain_payload(0, 1, 1, 0x10000)


def test_domain_string_table():
    assert domain_string_for_code(0x10) == "-C"
    assert domain_string_for_code(0x00) == "-A"
    assert domain_string_for_code(0x0B) == "-A"
    assert domain_string_for_code(0x99) == "NA"


def test_regdom_vsp_in_config_status_is_exactly_six_byte_header():
    """Regression: a 7-byte VSP header shifts ElemID to 0x0000 and the payload
    is dropped as unknown by the controller (live-verified 2026-09-20)."""
    raw = builders.build_config_status(_golden_identity(), seq_num=1)
    msgs = builders.parse_control_messages(raw)
    vsps = [(v[:6], v) for t, _l, v in msgs[0]["elements"] if t == 37]
    regdom_vsps = [v for hdr, v in vsps if int.from_bytes(hdr[4:6], "big") == 0x7E]
    assert len(regdom_vsps) == 2
    for v in regdom_vsps:
        assert decode_vsp(v)[0] == 0x7E          # ElemID intact
        assert len(decode_vsp(v)[1]) == 5        # 5-byte payload
