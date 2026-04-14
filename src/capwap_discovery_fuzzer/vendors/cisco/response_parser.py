"""Cisco C9800-specific CAPWAP Discovery Response parser.

Differences from the generic ResponseParser:
- Accepts MsgType=2  (Discovery Response, RFC 5415 Section 8.3)
  and MsgType=20 (Primary Discovery Response, RFC 5415 Section 8.7)
  as valid responses.  The C9800 returns MsgType=20 when it interprets
  a request as a Primary Discovery Request (observed with certain
  fuzz mutations).
- Extracts Cisco VSP sub-elements (ElemID=208 AC capability,
  ElemID=151 session token) and includes them in the result dict.
- Required elements: {1 (AC Descriptor), 4 (AC Name), 10 (AC Name w/ Priority)}.
  AC Name is allowed to be empty (Length=0) as observed in C9800 responses.
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
    """Extract Cisco Vendor Specific Payload details from element list."""
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
            cisco_info["session_token"] = data.hex()
    return cisco_info


def _extract_ac_ip(elems: Dict[int, list]) -> Optional[str]:
    """Extract AC IP from Type=10 (AC Name w/ Priority) element."""
    for val in elems.get(10, []):
        if len(val) >= 4:
            return ".".join(str(b) for b in val[:4])
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

            # Strip IP + UDP headers if present
            data = raw_data
            if data and data[0] >> 4 == 4:
                ip_len = (data[0] & 0x0F) * 4
                data = data[ip_len + 8:]

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
