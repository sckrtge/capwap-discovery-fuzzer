"""Cisco C9800-specific CAPWAP Discovery Response parser.

Type numbers and section references below follow the RFC texts kept at
``docs/evidence/rfc/`` (RFC 5415 §4.6.x "Type: N for <name>" lines; the section
number is not the type number).

Differences from the generic ResponseParser:
- Accepts MsgType=2  (Discovery Response, RFC 5415 §5.2)
  and MsgType=20 (Primary Discovery Response, RFC 5415 §5.4)
  as valid responses.  The C9800 returns MsgType=20 in reply to the
  MsgType=19 (Primary Discovery Request) seed this project sends.
- Extracts Cisco VSP sub-elements (ElemID=208 AC capability,
  ElemID=151 a 4-byte value that tracks the AC's clock) into the result dict.
- Required elements: {1 AC Descriptor (§4.6.1), 4 AC Name (§4.6.4),
  10 CAPWAP Control IPv4 Address (§4.6.9)} — these three are exactly the
  §5.2/§5.4 mandatory set.  AC Name is allowed to be empty (Length=0) as
  observed in C9800 responses.  This shape test says nothing about admission:
  the Discovery family carries no verdict field, and RFC 5416 §5.4's mandatory
  IEEE 802.11 WTP Radio Information (Type 1048) is checked separately by
  ``conformance.py``, not here.
"""

import struct
from typing import Any, Dict, Optional

from capwap_discovery_fuzzer.errors import (
    CAPWAPFuzzerError,
    MissingCapwapHeaderError,
    MissingControlHeaderError,
    MissingRequiredElementError,
    NoResponseError,
    UnexpectedMsgTypeError,
)
from capwap_discovery_fuzzer.response_parser import ResponseParser, ResponseType

# MsgType values accepted as valid Discovery Responses from C9800
_VALID_MSG_TYPES = {
    2,   # Discovery Response
    20,  # Primary Discovery Response
}

# Cisco vendor ID
_CISCO_VENDOR_ID = 4232704

# Cisco VSP ElemIDs of interest
_VSP_AC_CAPABILITY  = 208
_VSP_SESSION_TOKEN  = 151


def _parse_elements(capwap_payload: bytes, ctrl_offset: int) -> Dict[int, list]:
    """Return a dict mapping element Type -> list of raw value bytes."""
    elems: Dict[int, list] = {}
    off = ctrl_offset + 8  # skip 8-byte Control Header
    while off + 4 <= len(capwap_payload):
        etype = struct.unpack_from(">H", capwap_payload, off)[0]
        elen  = struct.unpack_from(">H", capwap_payload, off + 2)[0]
        val   = capwap_payload[off + 4: off + 4 + elen]
        elems.setdefault(etype, []).append(val)
        off += 4 + elen
    return elems


def _parse_cisco_vsp(elems: Dict[int, list]) -> Dict[str, Any]:
    """Extract Cisco Vendor Specific Payload details from element list.

    Type 37 is Vendor Specific Payload (RFC 5415 §4.6.39); the ElemID namespace
    inside it is Cisco's own, so the two IDs below are labelled from observation
    only.  151 is reported as ``vsp_151`` rather than "session token": its value
    was measured to track the AC's clock (RFC 5415 defines Session ID as Type 35
    with a different wire format, so this is not that element).
    """
    cisco_info: Dict[str, Any] = {}
    for val in elems.get(37, []):
        if len(val) < 6:
            continue
        vendor_id = struct.unpack_from(">I", val, 0)[0]
        elem_id   = struct.unpack_from(">H", val, 4)[0]
        data      = val[6:]
        if vendor_id != _CISCO_VENDOR_ID:
            continue
        if elem_id == _VSP_AC_CAPABILITY:
            cisco_info["ac_capability"] = data.hex()
        elif elem_id == _VSP_SESSION_TOKEN:
            cisco_info["vsp_151"] = data.hex()
        else:
            cisco_info[f"vsp_{elem_id}"] = data.hex()
    return cisco_info


def _extract_ac_ip(elems: Dict[int, list]) -> Optional[str]:
    """AC's control IPv4 address from Type=10 (RFC 5415 §4.6.9).

    Wire format is 4B address + 2B WTP Count; only the address is returned here,
    the count is exposed separately as ``control_ipv4_wtp_count``.
    """
    for val in elems.get(10, []):
        if len(val) >= 4:
            return ".".join(str(b) for b in val[:4])
    return None


def _extract_control_ipv4_wtp_count(elems: Dict[int, list]) -> Optional[int]:
    """WTPs currently connected on that interface (RFC 5415 §4.6.9)."""
    for val in elems.get(10, []):
        if len(val) >= 6:
            return struct.unpack_from(">H", val, 4)[0]
    return None


def _extract_ac_name(elems: Dict[int, list]) -> Optional[str]:
    """Extract AC Name from Type=4 element (may be empty)."""
    for val in elems.get(4, []):
        return val.decode("ascii", errors="replace") if val else ""
    return None


class CiscoResponseParser(ResponseParser):
    """CAPWAP Discovery Response parser tuned for Cisco C9800 WLC."""

    def parse_response(self, raw_data: bytes, request_info: Optional[Dict] = None) -> Dict[str, Any]:
        request_info = request_info or {}
        if not raw_data:
            raise NoResponseError(
                "No response received",
                request_info.get("ac_ip"),
                request_info.get("ac_port"),
            )

        result: Dict[str, Any] = {
            "scapy_pkt": None,
            "scapy_pkt_obj": None,
            "hex_dump": raw_data.hex(),
            "request_info": request_info,
            "response_type": ResponseType.UNKNOWN,
            "error_type": None,
            "cisco": {},
        }

        try:
            self._bind_layers()

            # raw_data is the UDP payload from recvfrom() — no IP/UDP header present.
            data = raw_data

            # Parse with Scapy for structured result
            from capwap_discovery_fuzzer.request_creater import CAPWAP_Header, Control_Header
            pkt = CAPWAP_Header(data)
            result["scapy_pkt_obj"] = pkt
            result["scapy_pkt"] = self.scapy_to_dict(pkt)

            if not pkt.haslayer(CAPWAP_Header):
                raise MissingCapwapHeaderError("CAPWAP header missing", data)
            if not pkt.haslayer(Control_Header):
                raise MissingControlHeaderError("Control header missing", data)

            # CAPWAP header: determine actual header length and control offset
            w0 = struct.unpack_from(">I", data, 0)[0]
            hlen_bytes = ((w0 >> 19) & 0x1F) * 4
            ctrl_offset = hlen_bytes

            msg_type = struct.unpack_from(">I", data, ctrl_offset)[0]

            if msg_type not in _VALID_MSG_TYPES:
                raise UnexpectedMsgTypeError(
                    f"Unexpected MsgType {msg_type} (expected {_VALID_MSG_TYPES})", data
                )

            # Parse elements
            elems = _parse_elements(data, ctrl_offset)

            # §5.2/§5.4 mandatory set: AC Descriptor, AC Name, and one of the
            # CAPWAP Control IPv4/IPv6 Address elements (Type 10/11 here).
            required = {1, 4, 10}
            if not required.issubset(elems.keys()):
                raise MissingRequiredElementError(
                    f"Missing required elements. Present: {set(elems.keys())}, Required: {required}",
                    data,
                )

            # Enrich result with Cisco-specific info
            result["cisco"] = {
                "msg_type": msg_type,
                "msg_type_name": "Discovery Response" if msg_type == 2 else "Primary Discovery Response",
                "ac_name": _extract_ac_name(elems),
                "ac_ip": _extract_ac_ip(elems),
                "control_ipv4_wtp_count": _extract_control_ipv4_wtp_count(elems),
                **_parse_cisco_vsp(elems),
            }

            result["response_type"] = ResponseType.VALID
            self.stats[ResponseType.VALID] += 1

        except CAPWAPFuzzerError as e:
            result["response_type"] = ResponseType.ERROR
            result["error_type"] = type(e).__name__
        except Exception:
            result["response_type"] = ResponseType.ERROR
            result["error_type"] = "UnknownError"
        finally:
            self._unbind_layers()
            self.total_responses += 1
            return result
