"""RFC 5415 / RFC 5416 conformance-checker tests.

Fixtures marked "measured" are verbatim payloads captured from the lab C9800-CL
(17.14.01) on 2026-09-11, so the checker is validated against real traffic, not
against packets written to match the checker.
"""

import json

import pytest

from capwap_discovery_fuzzer import conformance as cf
from capwap_discovery_fuzzer.request_creater import (
    CAPWAP_Header,
    Control_Header,
    MessageElement,
    Payload_Creator,
)
from capwap_discovery_fuzzer.vendors.cisco.creator import CiscoPayloadCreator
from capwap_discovery_fuzzer.vendors.cisco.fuzzer import CiscoCAPWAPDiscoveryFuzzer

# ---------------------------------------------------------------- measured traffic

# 93-byte Primary Discovery Response: AC Descriptor + AC Name (empty) +
# Control IPv4 + Radio Info + two Cisco VSPs.
RESPONSE_93B = bytes.fromhex(
    "001000000000000000000014000050000001001800002710000003e8020100020040960000"
    "010004110e004f00040000000a0006c0a82186000004180005000000000e00250007004096"
    "0000d0000025000b0040960000976aa3fa2000"
)

# 84-byte variant of the same reply with the Type 1048 element absent
# (MsgElemsLen 0x47 = 71 is self-consistent, so this is the AC's own shape).
RESPONSE_84B = bytes.fromhex(
    "001000000000000000000014000047000001001800002710000003e8020100020040960000"
    "010004110e004f00040000000a0006c0a821860000002500070040960000d0000025000b00"
    "40960000976aa3ff3d00"
)


def _subelement(vendor: int, stype: int, data: bytes) -> bytes:
    return vendor.to_bytes(4, "big") + stype.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def _ac_descriptor(with_versions: bool = True) -> bytes:
    """AC Descriptor with the §4.6.1 mandatory vendor-0 version sub-elements."""
    value = (0).to_bytes(2, "big") + (10000).to_bytes(2, "big")
    value += (0).to_bytes(2, "big") + (1000).to_bytes(2, "big")
    value += bytes([0x02, 0x01, 0x00, 0x02])   # Security, R-MAC, Reserved, DTLS Policy
    if with_versions:
        value += _subelement(0, cf.AC_INFO_HARDWARE_VERSION, b"hw")
        value += _subelement(0, cf.AC_INFO_SOFTWARE_VERSION, b"sw")
    return value


def _radio_info(radio_id: int = 1) -> bytes:
    return bytes([radio_id]) + (0x0E).to_bytes(4, "big")   # A/G/N bits set


def _build(msg_type: int, seq: int = 0, elements=() , wbid: int = 1) -> bytes:
    elems = None
    for element in elements:
        elems = element if elems is None else elems / element
    payload = elems if elems is not None else MessageElement(Type=0, Length=0, Value=b"")
    ctrl = Control_Header(MsgType=msg_type, SeqNum=seq,
                          MsgElemsLen=len(bytes(payload)) + 3, Flags=0)
    hdr = CAPWAP_Header(version=0, type=0, Hlen=2, Rid=0, WBID=wbid,
                        T=0, F=0, L=0, W=0, M=0, K=0, Flags=0,
                        FragmentID=0, FragmentOffset=0, Rsvd=0)
    return bytes(hdr / ctrl / payload)


def _conformant_response(msg_type: int = cf.MSG_PRIMARY_DISCOVERY_RESPONSE, seq: int = 0) -> bytes:
    return _build(msg_type, seq, [
        MessageElement(Type=cf.ELEM_AC_DESCRIPTOR, Length=len(_ac_descriptor()),
                       Value=_ac_descriptor()),
        MessageElement(Type=cf.ELEM_AC_NAME, Length=0, Value=b""),
        MessageElement(Type=cf.ELEM_CAPWAP_CONTROL_IPV4, Length=6,
                       Value=bytes([192, 168, 33, 134, 0, 0])),
        MessageElement(Type=cf.ELEM_IEEE80211_WTP_RADIO_INFO, Length=5, Value=_radio_info()),
    ])


# ------------------------------------------------------------------ naming lock-in

def test_element_names_follow_the_rfc():
    """Guards the naming corrections: these were wrong in the code before."""
    assert cf.ELEMENT_NAMES[10] == "CAPWAP Control IPv4 Address"   # not "AC Name w/ Priority"
    assert cf.ELEMENT_NAMES[5] == "AC Name with Priority"
    assert cf.ELEMENT_NAMES[1048] == "IEEE 802.11 WTP Radio Information"
    assert cf.ELEMENT_NAMES[38] == "WTP Board Data"
    assert cf.ELEMENT_NAMES[39] == "WTP Descriptor"
    assert cf.ELEMENT_NAMES[41] == "WTP Frame Tunnel Mode"
    assert cf.ELEMENT_NAMES[44] == "WTP MAC Type"
    assert cf.ELEMENT_NAMES[33] == "Result Code"


# -------------------------------------------------------- request-side conformance

def test_cisco_seed_request_has_exactly_the_radio_id_violation():
    """The shipped seed advertises Radio ID 0; RFC 5416 §6.25 requires 1..31."""
    report = cf.check_message(bytes(CiscoPayloadCreator().create_discovery_request(valid=True)))

    assert report.msg_type == cf.MSG_PRIMARY_DISCOVERY_REQUEST
    assert not report.conformant
    assert any("Radio ID 0" in v for v in report.violations)
    assert not any("missing mandatory" in v for v in report.violations)   # MUST set is complete
    assert cf.ELEM_WTP_NAME in report.element_types and cf.ELEM_LOCATION_DATA in report.element_types


def test_generic_seed_request_conformant():
    report = cf.check_message(bytes(Payload_Creator().create_discovery_request(valid=True)))
    # The generic seed has no 1048 at all, so the binding requirement fails.
    assert any("IEEE 802.11 WTP Radio Information" in v for v in report.violations)


# ------------------------------------------------------- response-side conformance

def test_measured_response_is_shape_valid_but_not_conformant():
    report = cf.check_message(RESPONSE_93B)

    assert report.msg_type == cf.MSG_PRIMARY_DISCOVERY_RESPONSE
    assert report.msg_name == "Primary Discovery Response"
    joined = " | ".join(report.violations)
    assert "Hardware Version" in joined and "Software Version" in joined   # §4.6.1
    assert "Radio ID 0" in joined                                          # RFC 5416 §6.25
    assert any("WBID=0 is Reserved" in d for d in report.deviations)       # §4.3
    assert any("AC Name present but empty" in n for n in report.notes)


def test_measured_short_response_missing_mandatory_radio_info():
    report = cf.check_message(RESPONSE_84B)

    assert cf.ELEM_IEEE80211_WTP_RADIO_INFO not in report.element_types
    assert any("missing mandatory IEEE 802.11 WTP Radio Information" in v
               for v in report.violations)
    assert not report.conformant


def test_conformant_response_passes_cleanly():
    report = cf.check_message(_conformant_response())

    assert report.conformant, report.violations
    assert report.deviations == []          # WBID=1, no reserved values used
    assert report.violations == []


def test_missing_one_of_control_address_is_a_violation():
    msg = _build(cf.MSG_PRIMARY_DISCOVERY_RESPONSE, 0, [
        MessageElement(Type=cf.ELEM_AC_DESCRIPTOR, Length=len(_ac_descriptor()),
                       Value=_ac_descriptor()),
        MessageElement(Type=cf.ELEM_AC_NAME, Length=0, Value=b""),
        MessageElement(Type=cf.ELEM_IEEE80211_WTP_RADIO_INFO, Length=5, Value=_radio_info()),
    ])
    report = cf.check_message(msg)
    assert any("missing mandatory one-of" in v for v in report.violations)


def test_reserved_wbid_is_a_deviation_not_a_violation():
    report = cf.check_message(_conformant_response())
    assert report.conformant

    reserved = cf.check_message(_build(cf.MSG_PRIMARY_DISCOVERY_RESPONSE, 0, [
        MessageElement(Type=cf.ELEM_AC_DESCRIPTOR, Length=len(_ac_descriptor()),
                       Value=_ac_descriptor()),
        MessageElement(Type=cf.ELEM_AC_NAME, Length=0, Value=b""),
        MessageElement(Type=cf.ELEM_CAPWAP_CONTROL_IPV4, Length=6, Value=b"\x01\x02\x03\x04\x00\x00"),
        MessageElement(Type=cf.ELEM_IEEE80211_WTP_RADIO_INFO, Length=5, Value=_radio_info()),
    ], wbid=0))
    assert any("WBID=0" in d for d in reserved.deviations)
    assert reserved.conformant


def test_wrong_control_ipv4_length_is_a_violation():
    msg = _build(cf.MSG_PRIMARY_DISCOVERY_RESPONSE, 0, [
        MessageElement(Type=cf.ELEM_AC_DESCRIPTOR, Length=len(_ac_descriptor()),
                       Value=_ac_descriptor()),
        MessageElement(Type=cf.ELEM_AC_NAME, Length=0, Value=b""),
        MessageElement(Type=cf.ELEM_CAPWAP_CONTROL_IPV4, Length=4, Value=b"\x01\x02\x03\x04"),
        MessageElement(Type=cf.ELEM_IEEE80211_WTP_RADIO_INFO, Length=5, Value=_radio_info()),
    ])
    assert any("CAPWAP Control IPv4 Address length 4 != 6" in v
               for v in cf.check_message(msg).violations)


# ------------------------------------------------------------------- pairing rules

def test_pair_check_accepts_matching_sequence_number():
    request = _build(cf.MSG_PRIMARY_DISCOVERY_REQUEST, 5, [
        MessageElement(Type=cf.ELEM_DISCOVERY_TYPE, Length=1, Value=b"\x01"),
    ])
    response = _conformant_response(seq=5)
    report = cf.check_pair(request, response)
    assert not any("SeqNum" in v for v in report.violations)


def test_pair_check_flags_sequence_number_mismatch():
    request = _build(cf.MSG_PRIMARY_DISCOVERY_REQUEST, 5, [
        MessageElement(Type=cf.ELEM_DISCOVERY_TYPE, Length=1, Value=b"\x01"),
    ])
    response = _conformant_response(seq=9)
    report = cf.check_pair(request, response)
    assert any("SeqNum 9 != request SeqNum 5" in v and "§4.5.1.2" in v
               for v in report.violations)


def test_pair_check_flags_wrong_response_type():
    request = _build(cf.MSG_PRIMARY_DISCOVERY_REQUEST, 0, [
        MessageElement(Type=cf.ELEM_DISCOVERY_TYPE, Length=1, Value=b"\x01"),
    ])
    # Reply with MsgType 2 (Discovery Response) to a type-19 request: §4.5.1.1
    # requires the response type to be the request type plus one.
    response = _conformant_response(cf.MSG_DISCOVERY_RESPONSE, seq=0)
    report = cf.check_pair(request, response)
    assert any("is not request type 19 + 1" in v for v in report.violations)


# --------------------------------------------------------------- result code (Join)

def test_join_response_result_code_is_decoded():
    msg = _build(cf.MSG_JOIN_RESPONSE, 0, [
        MessageElement(Type=cf.ELEM_RESULT_CODE, Length=4, Value=(9).to_bytes(4, "big")),
        MessageElement(Type=cf.ELEM_AC_DESCRIPTOR, Length=len(_ac_descriptor()),
                       Value=_ac_descriptor()),
        MessageElement(Type=cf.ELEM_AC_NAME, Length=0, Value=b""),
        MessageElement(Type=cf.ELEM_IEEE80211_WTP_RADIO_INFO, Length=5, Value=_radio_info()),
        MessageElement(Type=cf.ELEM_ECN_SUPPORT, Length=1, Value=b"\x00"),
        MessageElement(Type=cf.ELEM_CAPWAP_CONTROL_IPV4, Length=6, Value=b"\x01\x02\x03\x04\x00\x00"),
        MessageElement(Type=cf.ELEM_CAPWAP_LOCAL_IPV4, Length=4, Value=b"\x01\x02\x03\x04"),
    ])
    report = cf.check_message(msg)
    assert report.conformant, report.violations
    assert any("Result Code 9: Join Failure (Binding Not Supported)" in n for n in report.notes)


def test_join_response_missing_result_code_is_a_violation():
    msg = _build(cf.MSG_JOIN_RESPONSE, 0, [
        MessageElement(Type=cf.ELEM_AC_DESCRIPTOR, Length=len(_ac_descriptor()),
                       Value=_ac_descriptor()),
    ])
    report = cf.check_message(msg)
    assert any("missing mandatory Result Code" in v for v in report.violations)


# ------------------------------------------------------------------- session scan

def test_scan_records_tallies_conformance(tmp_path):
    path = tmp_path / "records.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in [
        {"round": 1, "response_hex": RESPONSE_93B.hex()},
        {"round": 2, "response_hex": RESPONSE_84B.hex()},
        {"round": 3, "response_hex": ""},                       # timeout: not judged
        {"round": 4, "response_hex": _conformant_response().hex()},
    ]) + "\n", encoding="utf-8")

    summary = cf.scan_records(path)
    assert summary["records"] == 4
    assert summary["messages_checked"] == 3
    assert summary["conformant"] == 1
    assert summary["non_conformant"] == 2
    assert summary["deviations"] == 2          # both measured replies use WBID=0
    assert any("Radio ID 0" in k for k in summary["by_violation"])
    assert {e["round"] for e in summary["examples"]} == {1, 2}


# ------------------------------------------------------- wiring into the fuzzer

def test_fuzzer_records_rfc_conformance_without_changing_response_type(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Cisco variant: it accepts MsgType=20 (Primary Discovery Response), which is
    # what the C9800 sends in reply to our MsgType=19 seed.
    fuzzer = CiscoCAPWAPDiscoveryFuzzer(ac_ip="127.0.0.1", seed=1)
    request = bytes(CiscoPayloadCreator().create_discovery_request(valid=True))

    resp_type, _ = fuzzer.classify_discovery_response(request, RESPONSE_93B)
    record = json.loads(fuzzer.records_path.read_text().splitlines()[-1])

    assert resp_type == "valid"                     # shape verdict unchanged
    assert record["rfc"]["response_conformant"] is False
    assert any("Radio ID 0" in v for v in record["rfc"]["response_violations"])
    assert record["rfc"]["request_conformant"] is False   # seed's Radio ID 0
