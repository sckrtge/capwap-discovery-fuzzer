"""RFC 5415 / RFC 5416 conformance checks for CAPWAP Discovery messages.

Every rule here names its source section. The field and type numbers come from
the RFC texts themselves — the read-only copies in the project workspace at
``docs/evidence/rfc/`` — specifically the ``Type: N for <name>`` lines, since
RFC 5415's §4.6.x numbering is not the element type number (§4.6.33 is Type 31).

What this is for
----------------
An AC's silence during Discovery cannot be interpreted without knowing whether
the request was even conformant, and the Discovery family carries no verdict
field (RFC 5415 has no Result Code in §5.2/§5.4). So conformance is checked
separately from, and in addition to, the response-type classification:

* :func:`check_message` — validate one message against the MUST/MAY sets of its
  message type.
* :func:`check_pair` — request/response linkage rules (§4.5.1.1 message type
  pairing, §4.5.1.2 sequence number copy).
* :func:`scan_records` — run the check over a session's ``records.jsonl``.

Verdicts are split by severity: ``violations`` are MUST-level, ``deviations`` are
defined-value violations (an RFC value used with its reserved meaning), and
``notes`` are observations that are not non-conformance (an empty AC Name, an
unusual element present).
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from pathlib import Path

from .lock_fuzzer import parse_layout

# ---------------------------------------------------------------- message types
# RFC 5415 §4.5.1.1: 32-bit field = IANA Enterprise Number (3B) + message type
# (1B); IANA namespace = enterprise number 0; requests are odd, responses even.
MSG_DISCOVERY_REQUEST = 1
MSG_DISCOVERY_RESPONSE = 2
MSG_JOIN_REQUEST = 3
MSG_JOIN_RESPONSE = 4
MSG_PRIMARY_DISCOVERY_REQUEST = 19
MSG_PRIMARY_DISCOVERY_RESPONSE = 20

MSG_NAMES = {
    MSG_DISCOVERY_REQUEST: "Discovery Request",
    MSG_DISCOVERY_RESPONSE: "Discovery Response",
    MSG_JOIN_REQUEST: "Join Request",
    MSG_JOIN_RESPONSE: "Join Response",
    MSG_PRIMARY_DISCOVERY_REQUEST: "Primary Discovery Request",
    MSG_PRIMARY_DISCOVERY_RESPONSE: "Primary Discovery Response",
}

# --------------------------------------------------------- message element types
# RFC 5415 element types, from each section's "Type: N for <name>" line; the
# section is given because type number and section number differ.
ELEM_AC_DESCRIPTOR = 1              # §4.6.1
ELEM_AC_IPV4_LIST = 2               # §4.6.2
ELEM_AC_IPV6_LIST = 3               # §4.6.3
ELEM_AC_NAME = 4                    # §4.6.4
ELEM_AC_NAME_WITH_PRIORITY = 5      # §4.6.5
ELEM_CAPWAP_CONTROL_IPV4 = 10       # §4.6.9
ELEM_CAPWAP_CONTROL_IPV6 = 11       # §4.6.10
ELEM_DISCOVERY_TYPE = 20            # §4.6.21
ELEM_LOCATION_DATA = 28             # §4.6.30
ELEM_RESULT_CODE = 33               # §4.6.35
ELEM_VENDOR_SPECIFIC_PAYLOAD = 37   # §4.6.39
ELEM_WTP_BOARD_DATA = 38            # §4.6.40
ELEM_WTP_DESCRIPTOR = 39            # §4.6.41
ELEM_WTP_FRAME_TUNNEL_MODE = 41     # §4.6.43
ELEM_WTP_MAC_TYPE = 44              # §4.6.44
ELEM_WTP_NAME = 45                  # §4.6.45
ELEM_MTU_DISCOVERY_PADDING = 52     # §4.6.32
ELEM_CAPWAP_TRANSPORT_PROTOCOL = 51  # §4.6.14
ELEM_MAXIMUM_MESSAGE_LENGTH = 29    # §4.6.31
ELEM_WTP_REBOOT_STATISTICS = 48     # §4.6.47
ELEM_IMAGE_IDENTIFIER = 25          # §4.6.27
ELEM_SESSION_ID = 35                # §4.6.37
ELEM_CAPWAP_LOCAL_IPV4 = 30         # §4.6.11
ELEM_CAPWAP_LOCAL_IPV6 = 50         # §4.6.12
ELEM_ECN_SUPPORT = 53               # §4.6.25
ELEM_IEEE80211_WTP_RADIO_INFO = 1048  # RFC 5416 §6.25 (block 1024-2047)

ELEMENT_NAMES = {
    ELEM_AC_DESCRIPTOR: "AC Descriptor",
    ELEM_AC_IPV4_LIST: "AC IPv4 List",
    ELEM_AC_IPV6_LIST: "AC IPv6 List",
    ELEM_AC_NAME: "AC Name",
    ELEM_AC_NAME_WITH_PRIORITY: "AC Name with Priority",
    ELEM_CAPWAP_CONTROL_IPV4: "CAPWAP Control IPv4 Address",
    ELEM_CAPWAP_CONTROL_IPV6: "CAPWAP Control IPv6 Address",
    ELEM_DISCOVERY_TYPE: "Discovery Type",
    ELEM_LOCATION_DATA: "Location Data",
    ELEM_RESULT_CODE: "Result Code",
    ELEM_VENDOR_SPECIFIC_PAYLOAD: "Vendor Specific Payload",
    ELEM_WTP_BOARD_DATA: "WTP Board Data",
    ELEM_WTP_DESCRIPTOR: "WTP Descriptor",
    ELEM_WTP_FRAME_TUNNEL_MODE: "WTP Frame Tunnel Mode",
    ELEM_WTP_MAC_TYPE: "WTP MAC Type",
    ELEM_WTP_NAME: "WTP Name",
    ELEM_MTU_DISCOVERY_PADDING: "MTU Discovery Padding",
    ELEM_CAPWAP_TRANSPORT_PROTOCOL: "CAPWAP Transport Protocol",
    ELEM_MAXIMUM_MESSAGE_LENGTH: "Maximum Message Length",
    ELEM_WTP_REBOOT_STATISTICS: "WTP Reboot Statistics",
    ELEM_IMAGE_IDENTIFIER: "Image Identifier",
    ELEM_SESSION_ID: "Session ID",
    ELEM_CAPWAP_LOCAL_IPV4: "CAPWAP Local IPv4 Address",
    ELEM_CAPWAP_LOCAL_IPV6: "CAPWAP Local IPv6 Address",
    ELEM_ECN_SUPPORT: "ECN Support",
    ELEM_IEEE80211_WTP_RADIO_INFO: "IEEE 802.11 WTP Radio Information",
}

# AC Information sub-element enumerated types; §4.6.1 requires BOTH to be present
# and requires their Vendor Identifier to be zero.
AC_INFO_HARDWARE_VERSION = 4
AC_INFO_SOFTWARE_VERSION = 5
AC_INFO_NAMES = {AC_INFO_HARDWARE_VERSION: "Hardware Version",
                 AC_INFO_SOFTWARE_VERSION: "Software Version"}

# RFC 5416 §6.25: Radio ID is 1..31.
RADIO_ID_MIN, RADIO_ID_MAX = 1, 31

# ------------------------------------------------------------ stage requirements
# MUST/MAY sets, straight from the normative text.
_DISCOVERY_REQUEST_MUST = (
    ELEM_DISCOVERY_TYPE,            # §5.1 / §5.3
    ELEM_WTP_BOARD_DATA,            # §5.1 / §5.3
    ELEM_WTP_DESCRIPTOR,            # §5.1 / §5.3
    ELEM_WTP_FRAME_TUNNEL_MODE,     # §5.1 / §5.3
    ELEM_WTP_MAC_TYPE,              # §5.1 / §5.3
    ELEM_IEEE80211_WTP_RADIO_INFO,  # RFC 5416 §5.1 / §5.4
)
_DISCOVERY_REQUEST_MAY = (ELEM_MTU_DISCOVERY_PADDING, ELEM_VENDOR_SPECIFIC_PAYLOAD)

_RESPONSE_MUST = (
    ELEM_AC_DESCRIPTOR,             # §5.2 / §5.4
    ELEM_AC_NAME,                   # §5.2 / §5.4
    ELEM_IEEE80211_WTP_RADIO_INFO,  # RFC 5416 §5.4
)
_RESPONSE_ONE_OF = ((ELEM_CAPWAP_CONTROL_IPV4, ELEM_CAPWAP_CONTROL_IPV6),)  # §5.2/§5.4
_RESPONSE_MAY = (ELEM_VENDOR_SPECIFIC_PAYLOAD,)

# Join stage, from the normative lists in §6.1 / §6.2 (needed by the DTLS/Join
# work: the Join Response's Result Code is CAPWAP's only admission verdict).
_JOIN_REQUEST_MUST = (
    ELEM_LOCATION_DATA,             # §6.1
    ELEM_WTP_BOARD_DATA,
    ELEM_WTP_DESCRIPTOR,
    ELEM_WTP_NAME,
    ELEM_SESSION_ID,
    ELEM_WTP_FRAME_TUNNEL_MODE,
    ELEM_WTP_MAC_TYPE,
    ELEM_IEEE80211_WTP_RADIO_INFO,
    ELEM_ECN_SUPPORT,
)
_JOIN_REQUEST_MAY = (ELEM_CAPWAP_TRANSPORT_PROTOCOL, ELEM_MAXIMUM_MESSAGE_LENGTH,
                     ELEM_WTP_REBOOT_STATISTICS, ELEM_VENDOR_SPECIFIC_PAYLOAD)
_JOIN_REQUEST_ONE_OF = ((ELEM_CAPWAP_LOCAL_IPV4, ELEM_CAPWAP_LOCAL_IPV6),)

_JOIN_RESPONSE_MUST = (
    ELEM_RESULT_CODE,               # §6.2
    ELEM_AC_DESCRIPTOR,
    ELEM_AC_NAME,
    ELEM_IEEE80211_WTP_RADIO_INFO,
    ELEM_ECN_SUPPORT,
)
_JOIN_RESPONSE_MAY = (ELEM_AC_IPV4_LIST, ELEM_AC_IPV6_LIST,
                      ELEM_CAPWAP_TRANSPORT_PROTOCOL, ELEM_IMAGE_IDENTIFIER,
                      ELEM_MAXIMUM_MESSAGE_LENGTH, ELEM_VENDOR_SPECIFIC_PAYLOAD)
_JOIN_RESPONSE_ONE_OF = (
    (ELEM_CAPWAP_CONTROL_IPV4, ELEM_CAPWAP_CONTROL_IPV6),
    (ELEM_CAPWAP_LOCAL_IPV4, ELEM_CAPWAP_LOCAL_IPV6),
)

_STAGE_RULES = {
    MSG_DISCOVERY_REQUEST: (_DISCOVERY_REQUEST_MUST, _DISCOVERY_REQUEST_MAY, ()),
    MSG_PRIMARY_DISCOVERY_REQUEST: (_DISCOVERY_REQUEST_MUST, _DISCOVERY_REQUEST_MAY, ()),
    MSG_DISCOVERY_RESPONSE: (_RESPONSE_MUST, _RESPONSE_MAY, _RESPONSE_ONE_OF),
    MSG_PRIMARY_DISCOVERY_RESPONSE: (_RESPONSE_MUST, _RESPONSE_MAY, _RESPONSE_ONE_OF),
    MSG_JOIN_REQUEST: (_JOIN_REQUEST_MUST, _JOIN_REQUEST_MAY, _JOIN_REQUEST_ONE_OF),
    MSG_JOIN_RESPONSE: (_JOIN_RESPONSE_MUST, _JOIN_RESPONSE_MAY, _JOIN_RESPONSE_ONE_OF),
}

# Result Code enum, RFC 5415 §4.6.35 — the only admission verdict CAPWAP carries,
# and it appears in the Join Response (§6.2), not in the Discovery family.
RESULT_CODES = {
    0: "Success",
    1: "Failure (AC List Message Element MUST Be Present)",
    2: "Success (NAT Detected)",
    3: "Join Failure (Unspecified)",
    4: "Join Failure (Resource Depletion)",
    5: "Join Failure (Unknown Source)",
    6: "Join Failure (Incorrect Data)",
    7: "Join Failure (Session ID Already in Use)",
    8: "Join Failure (WTP Hardware Not Supported)",
    9: "Join Failure (Binding Not Supported)",
    10: "Reset Failure (Unable to Reset)",
    11: "Reset Failure (Firmware Write Error)",
    12: "Configuration Failure (Unable to Apply - Service Provided Anyhow)",
    13: "Configuration Failure (Unable to Apply - Service Not Provided)",
    14: "Image Data Error (Invalid Checksum)",
    15: "Image Data Error (Invalid Data Length)",
    16: "Image Data Error (Other Error)",
    17: "Image Data Error (Image Already Present)",
    18: "Message Unexpected (Invalid in Current State)",
    19: "Message Unexpected (Unrecognized Request)",
    20: "Failure - Missing Mandatory Message Element",
    21: "Failure - Unrecognized Message Element",
    22: "Data Transfer Error (No Information to Transfer)",
}


@dataclass
class Report:
    """Outcome of one conformance check."""

    msg_type: int
    msg_name: str
    violations: list[str] = field(default_factory=list)   # MUST-level
    deviations: list[str] = field(default_factory=list)   # reserved value used
    notes: list[str] = field(default_factory=list)        # observations
    element_types: list[int] = field(default_factory=list)

    @property
    def conformant(self) -> bool:
        return not self.violations

    def as_dict(self) -> dict:
        return {
            "msg_type": self.msg_type,
            "msg_name": self.msg_name,
            "conformant": self.conformant,
            "violations": self.violations,
            "deviations": self.deviations,
            "notes": self.notes,
            "element_types": self.element_types,
        }


def _elem_name(etype: int) -> str:
    return ELEMENT_NAMES.get(etype, f"element {etype}")


def _check_ac_descriptor(value: bytes, report: Report) -> None:
    """§4.6.1: Length >= 12, then vendor-0 Hardware/Software Version sub-elements."""
    if len(value) < 12:
        report.violations.append(
            f"AC Descriptor length {len(value)} < 12 (RFC 5415 §4.6.1)")
        return

    offset = 12
    subelements = []
    while offset + 8 <= len(value):
        vendor, stype, slen = struct.unpack_from(">IHH", value, offset)
        data_end = offset + 8 + slen
        if data_end > len(value):
            report.violations.append(
                f"AC Information sub-element at offset {offset} declares length {slen} "
                f"beyond element end (RFC 5415 §4.6.1)")
            break
        subelements.append((vendor, stype, value[offset + 8:data_end]))
        offset = data_end

    defined = {(v, t) for v, t, _ in subelements if v == 0}
    for stype in (AC_INFO_HARDWARE_VERSION, AC_INFO_SOFTWARE_VERSION):
        if (0, stype) not in defined:
            report.violations.append(
                f"AC Descriptor missing mandatory {AC_INFO_NAMES[stype]} sub-element "
                f"(vendor id 0, type {stype}) (RFC 5415 §4.6.1)")
    for vendor, stype, data in subelements:
        if len(data) > 1024:
            report.violations.append(
                f"AC Information sub-element data {len(data)} > 1024 (RFC 5415 §4.6.1)")
        elif vendor != 0:
            report.notes.append(
                f"AC Information sub-element uses private vendor id 0x{vendor:08x} "
                f"(type {stype}, {len(data)}B)")


def _check_radio_information(value: bytes, report: Report) -> None:
    """RFC 5416 §6.25: Length 5; Radio ID 1..31; Radio Type bit field."""
    if len(value) != 5:
        report.violations.append(
            f"IEEE 802.11 WTP Radio Information length {len(value)} != 5 (RFC 5416 §6.25)")
        return
    radio_id = value[0]
    if not RADIO_ID_MIN <= radio_id <= RADIO_ID_MAX:
        report.violations.append(
            f"Radio ID {radio_id} outside 1..{RADIO_ID_MAX} (RFC 5416 §6.25)")
    radio_type = int.from_bytes(value[1:5], "big")
    if radio_type & 0x0F == 0:   # low bits B|A|G|N per §6.25 bit field
        report.notes.append(
            f"Radio Type 0x{radio_type:08x} sets no PHY bit (B/A/G/N) (RFC 5416 §6.25)")


def _check_result_code(value: bytes, report: Report) -> None:
    if len(value) != 4:
        report.violations.append(
            f"Result Code length {len(value)} != 4 (RFC 5415 §4.6.35)")
        return
    code = int.from_bytes(value, "big")
    report.notes.append(
        f"Result Code {code}: {RESULT_CODES.get(code, 'unknown')} (RFC 5415 §4.6.35)")


def check_message(raw: bytes) -> Report:
    """Validate one CAPWAP control message against its stage's MUST/MAY sets."""
    try:
        layout = parse_layout(raw)
    except ValueError as exc:
        return Report(msg_type=-1, msg_name="<unparsable>",
                      violations=[f"payload too short to parse: {exc}"])

    msg_type = int.from_bytes(raw[layout.ctrl_off:layout.ctrl_off + 4], "big")
    # IANA namespace: enterprise number 0, so the low byte is the message type.
    enterprise, type_byte = msg_type >> 8, msg_type & 0xFF
    report = Report(msg_type=type_byte, msg_name=MSG_NAMES.get(type_byte, f"type {type_byte}"))
    if enterprise != 0:
        report.notes.append(f"non-IANA enterprise number 0x{enterprise:06x} (RFC 5415 §15.4)")

    w0 = struct.unpack_from(">I", raw, 0)[0]
    version = (w0 >> 28) & 0x0F
    hlen_words = (w0 >> 19) & 0x1F
    wbid = (w0 >> 9) & 0x1F
    if version != 0:
        report.notes.append(f"CAPWAP version {version} (RFC 5415 defines 0)")
    if layout.header_end < 8:
        report.violations.append(f"Hlen implies {layout.header_end}B header < 8B (RFC 5415 §4.3)")
    if wbid == 0:
        report.deviations.append(
            "WBID=0 is Reserved; 1 is IEEE 802.11 (RFC 5415 §4.3)")

    values = {}
    report.element_types = [e.type for e in layout.elements]
    for elem in layout.elements:
        value = raw[elem.value_start:elem.value_end]
        values.setdefault(elem.type, []).append(value)

    must, may, one_of = _STAGE_RULES.get(type_byte, ((), (), ()))
    for etype in must:
        if etype not in values:
            report.violations.append(
                f"missing mandatory {_elem_name(etype)} (type {etype})")
    for group in one_of:
        if not any(t in values for t in group):
            names = " or ".join(_elem_name(t) for t in group)
            report.violations.append(f"missing mandatory one-of: {names}")

    known = set(must) | set(may) | {t for g in one_of for t in g}
    for etype in values:
        if etype not in known:
            report.notes.append(f"element {_elem_name(etype)} (type {etype}) not named by this stage")

    for value in values.get(ELEM_AC_DESCRIPTOR, []):
        _check_ac_descriptor(value, report)
    for value in values.get(ELEM_IEEE80211_WTP_RADIO_INFO, []):
        _check_radio_information(value, report)
    for value in values.get(ELEM_RESULT_CODE, []):
        _check_result_code(value, report)
    for value in values.get(ELEM_AC_NAME, []):
        if not value:
            report.notes.append("AC Name present but empty (RFC 5415 §4.6.4 does not forbid it)")
    if ELEM_CAPWAP_CONTROL_IPV4 in values:
        for value in values[ELEM_CAPWAP_CONTROL_IPV4]:
            if len(value) != 6:
                report.violations.append(
                    f"CAPWAP Control IPv4 Address length {len(value)} != 6 "
                    f"(4B address + 2B WTP Count) (RFC 5415 §4.6.9)")

    return report


def check_pair(request_raw: bytes, response_raw: bytes) -> Report:
    """Linkage rules between a request and its response.

    §4.5.1.1: a response's message type value is the request's plus one.
    §4.5.1.2: the Sequence Number field value is copied into the response.
    """
    report = check_message(response_raw)
    try:
        req_layout = parse_layout(request_raw)
        resp_layout = parse_layout(response_raw)
    except ValueError:
        report.violations.append("payload could not be parsed for pairing checks")
        return report

    req_type = int.from_bytes(request_raw[req_layout.ctrl_off:req_layout.ctrl_off + 4], "big") & 0xFF
    resp_type = report.msg_type
    if req_type in MSG_NAMES and resp_type in MSG_NAMES and resp_type != req_type + 1:
        report.violations.append(
            f"response type {resp_type} is not request type {req_type} + 1 (RFC 5415 §4.5.1.1)")
    req_seq = request_raw[req_layout.ctrl_off + 4]
    resp_seq = response_raw[resp_layout.ctrl_off + 4]
    if req_seq != resp_seq:
        report.violations.append(
            f"response SeqNum {resp_seq} != request SeqNum {req_seq} (RFC 5415 §4.5.1.2)")
    return report


def scan_records(jsonl_path: str | Path, request_side: bool = False) -> dict:
    """Check every recorded message in a session's ``records.jsonl``.

    ``request_side=False`` (default) judges the AC's replies; ``True`` judges the
    requests we sent. Returns counts plus per-reason tallies so a run can report
    a conformance rate next to the response rate.
    """
    path = Path(jsonl_path)
    summary = {
        "path": str(path),
        "side": "request" if request_side else "response",
        "records": 0,
        "messages_checked": 0,
        "conformant": 0,
        "non_conformant": 0,
        "deviations": 0,
        "by_violation": {},
        "examples": [],
    }
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        summary["records"] += 1
        hex_field = record["request_hex"] if request_side else record.get("response_hex", "")
        if not hex_field:
            continue
        summary["messages_checked"] += 1
        report = check_message(bytes.fromhex(hex_field))
        if report.conformant:
            summary["conformant"] += 1
        else:
            summary["non_conformant"] += 1
            if len(summary["examples"]) < 5:
                summary["examples"].append({
                    "round": record.get("round"),
                    "msg": report.msg_name,
                    "violations": report.violations,
                })
        if report.deviations:
            summary["deviations"] += 1
        for violation in report.violations:
            key = violation.split(" (RFC")[0]
            summary["by_violation"][key] = summary["by_violation"].get(key, 0) + 1
    return summary
