"""Pure constructors for the post-Discovery CAPWAP control messages.

Every builder is a pure function and, with default arguments, reproduces the
traffic the controller accepted during the 2026-09-20 live round **byte for
byte** — ``tests/golden/`` pins those bytes:

======================  ==========================================  ======
builder                 golden                                      bytes
======================  ==========================================  ======
:func:`build_join_request`            ``golden_join.bin``            318
:func:`build_config_status`           ``golden_csr.bin``             132
:func:`build_change_state`            ``golden_cse.bin``              46
:func:`build_echo`                    ``golden_echo.bin``             24
======================  ==========================================  ======

Anchors for the non-obvious fields (all live-verified, see the E5–E7 round
notes and ``docs/reference/CAPWAP-join链路-完整路径-runbook.md``):

* **Join** carries Maximum Message Length (Type 29, RFC 5415 §4.6.31 — its
  absence is a guaranteed ``Failure decoding max message size`` disjoin), the
  Cisco regulatory-domain elements (Type 126), radio ids that start at **0**
  (the controller's 6 GHz-presence check requires slot 0), and the AP Domain
  element (Cisco Type 169, ``{enable u8, len u16 BE, name}``).
* **Configuration Status** must declare the regulatory domain as *vendor*
  payloads: element 37, ElemID 126, 6-byte header, 5-byte payload — the
  controller walks these at Configure state (``apmgr_process_regulatory_domain_payload``).
* **Change State Event** reports every radio operational (state 1 = enabled);
  the controller refuses the country push while any radio is stuck down.

Message framing follows RFC 5415 §4.5.1.1: MsgElemsLen counts from after the
SeqNum field, i.e. it includes its own 2 bytes plus the 1-byte Flags field —
hence the ``+ 3``.
"""

from __future__ import annotations

import struct

from scapy.packet import Packet, Raw

from capwap_discovery_fuzzer.request_creater import CAPWAP_Header, Control_Header
from capwap_discovery_fuzzer.vendors.cisco.creator import (
    ApIdentity,
    _VSP207_DATA,
    _element,
    _mac_optional_field,
    _vsp_value,
)
from capwap_discovery_fuzzer.session.vsp import build_reg_domain_vsp
from capwap_discovery_fuzzer.vendors.cisco.elements import (
    BOARD_DATA_OPTIONS_ELEM_ID,
    RAD_NAME_ELEM_ID,
)

#: Message types, RFC 5415 §4.5.1.1 table.
MSG_CONFIG_STATUS_REQUEST = 5
MSG_CONFIG_STATUS_RESPONSE = 6
MSG_CONFIG_UPDATE_REQUEST = 7
MSG_CONFIG_UPDATE_RESPONSE = 8
MSG_CHANGE_STATE_EVENT_REQUEST = 11
MSG_CHANGE_STATE_EVENT_RESPONSE = 12
MSG_ECHO_REQUEST = 13
MSG_ECHO_RESPONSE = 14

#: RFC 5415 §4.6.31 Maximum Message Length — the value seen in Cisco AP captures.
DEFAULT_MAX_MESSAGE_LENGTH = 14400

#: Cisco Type 169 AP Domain: the controller logs "AP_DOMAIN payload count is 0"
#: when a Join Request omits it (2026-09-20 live trace).
DEFAULT_AP_DOMAIN_NAME = b"default"

#: Default regulatory-domain code: 0x0010 = "-C" (China); the lab controller
#: runs ``ap country CN``.  Override for other countries (0x00/0x0B = -A/US).
DEFAULT_REG_DOMAIN_CODE = 0x0010

#: Result Code (RFC 5415 §4.6.35) value for "Success".
RESULT_CODE_SUCCESS = 0


def _control_frame(identity: ApIdentity, msg_type: int, seq_num: int,
                   element_list: list[Packet] | None) -> bytes:
    """Frame one control message: CAPWAP header (M=1) + control header + elements."""
    raw = b""
    if element_list:
        chain = None
        for part in element_list:
            chain = part if chain is None else chain / part
        raw = bytes(chain)
    capwap_header = CAPWAP_Header(
        version=0, type=0, Hlen=4, Rid=0, WBID=1,
        T=0, F=0, L=0, W=0, M=1, K=0, Flags=0,
        FragmentID=0, FragmentOffset=0, Rsvd=0,
    )
    control_header = Control_Header(
        MsgType=msg_type, SeqNum=seq_num, MsgElemsLen=len(raw) + 3, Flags=0)
    return bytes(capwap_header / Raw(load=_mac_optional_field(identity.ap_mac))
                 / control_header / Raw(load=raw))


def build_join_request(identity: ApIdentity, session_id: bytes = bytes(16),
                       local_ip: str = "192.168.10.128", seq_num: int = 0,
                       max_message_length: int = DEFAULT_MAX_MESSAGE_LENGTH,
                       reg_domain_code: int = 0x0101,
                       ap_domain_name: bytes | None = DEFAULT_AP_DOMAIN_NAME,
                       ) -> bytes:
    """Join Request (RFC 5415 §6.1) with the C9800-required Cisco extensions.

    Defaults reproduce ``tests/golden/golden_join.bin``.  The element order
    matters for golden equality; it mirrors the successful live round.
    ``reg_domain_code`` is the raw join-time Type-126 declaration (two code
    bytes; the accepted capture carries 0x0101 — the *enforced* codes live in
    the Configuration Status vendor payloads, see :func:`build_config_status`).
    """
    if len(session_id) != 16:
        raise ValueError(f"Session ID must be 16B (RFC 5415 §4.6.37), got {len(session_id)}")

    code = reg_domain_code.to_bytes(2, "big")
    parts = [
        _element(38, identity.board_data()),
        _element(39, identity.descriptor()),
        _element(41, b"\x04"),
        _element(44, b"\x01"),
        _element(45, identity.ap_name),
        _element(28, b"default location"),
        # Cisco Type 126, 5-byte form {band, set, slot, code0, code1}, one per band
        _element(126, bytes([0x00, 0x01, 0x00]) + code),
        _element(126, bytes([0x01, 0x01, 0x01]) + code),
    ]
    parts.extend(_element(1048, _radio_information(rid, rtype))
                 for rid, rtype in identity.radios)
    parts.append(_element(35, session_id))
    parts.append(_element(29, struct.pack(">H", max_message_length)))
    parts.append(_element(53, b"\x00"))                       # Limited ECN (§4.6.25)
    parts.append(_element(30, _ipv4(local_ip)))               # §4.6.11 one-of
    parts.append(_element(37, _vsp_value(BOARD_DATA_OPTIONS_ELEM_ID, _VSP207_DATA)))
    parts.append(_element(37, _vsp_value(RAD_NAME_ELEM_ID, identity.ap_name)))
    if ap_domain_name is not None:
        parts.append(_element(169, bytes([0x01])
                              + len(ap_domain_name).to_bytes(2, "big") + ap_domain_name))
    return _control_frame(identity, 3, seq_num, parts)


def _radio_information(radio_id: int, radio_type: int) -> bytes:
    """IEEE 802.11 WTP Radio Information (RFC 5416 §6.25): ID(1) + type bits(4)."""
    return bytes([radio_id]) + radio_type.to_bytes(4, "big")


def _ipv4(dotted: str) -> bytes:
    import socket
    return socket.inet_aton(dotted)


def build_config_status(identity: ApIdentity, ac_name: bytes = b"C9800-LAB",
                        seq_num: int = 1, reg_domain_code: int = DEFAULT_REG_DOMAIN_CODE,
                        statistics_timer: int = 30,
                        include_rad_name: bool = True) -> bytes:
    """Configuration Status Request (RFC 5415 §8.2) with the VSP-126 declarations.

    Defaults reproduce ``tests/golden/golden_csr.bin``.  The regulatory domain
    is declared as *vendor* payloads (element 37, ElemID 126): slot0/band0 and
    slot1/band1 — exactly the pairs the controller verifies at this stage.
    """
    code = reg_domain_code.to_bytes(2, "big")
    parts = [
        _element(4, ac_name),
        _element(31, bytes([0, 1])),    # Radio Administrative State: rid0 enabled
        _element(31, bytes([1, 1])),    # rid1 enabled
        _element(36, struct.pack(">H", statistics_timer)),
        _element(48, bytes(15)),        # WTP Reboot Statistics (§4.6.47, 15B, all zero)
        _element(37, build_reg_domain_vsp(0x00, 0x01, 0x00, int.from_bytes(code, "big"))),
        _element(37, build_reg_domain_vsp(0x01, 0x01, 0x01, int.from_bytes(code, "big"))),
    ]
    if include_rad_name:
        parts.append(_element(37, _vsp_value(RAD_NAME_ELEM_ID, identity.ap_name)))
    return _control_frame(identity, MSG_CONFIG_STATUS_REQUEST, seq_num, parts)


def build_change_state(identity: ApIdentity, seq_num: int = 2,
                       radio_states: tuple[tuple[int, int, int], ...] = ((0, 1, 0), (1, 1, 0)),
                       result_code: int = RESULT_CODE_SUCCESS,
                       include_vsp: bool = True) -> bytes:
    """Change State Event Request (RFC 5415 §8.6).

    Each ``radio_states`` entry is ``(radio_id, state, cause)``; defaults declare
    both radios enabled with a normal cause.  Defaults reproduce
    ``tests/golden/golden_cse.bin`` (with ``include_vsp=True``).
    """
    parts: list[Packet] = []
    for rid, state, cause in radio_states:
        parts.append(_element(32, bytes([rid, state, cause])))
    parts.append(_element(33, struct.pack(">I", result_code)))
    if include_vsp:
        parts.append(_element(37, _vsp_value(BOARD_DATA_OPTIONS_ELEM_ID, _VSP207_DATA)))
        parts.append(_element(37, _vsp_value(RAD_NAME_ELEM_ID, identity.ap_name)))
    return _control_frame(identity, MSG_CHANGE_STATE_EVENT_REQUEST, seq_num, parts)


def build_echo(identity: ApIdentity, seq_num: int = 3) -> bytes:
    """Echo Request (RFC 5415 §7.1): keep-alive, no message elements."""
    return _control_frame(identity, MSG_ECHO_REQUEST, seq_num, [])


def build_config_update_response(identity: ApIdentity, seq_num: int,
                                 result_code: int = RESULT_CODE_SUCCESS,
                                 echo_elements: tuple[tuple[int, bytes], ...] = (),
                                 ) -> bytes:
    """Configuration Update Response (RFC 5415 §8.5): Result Code (+ echoes).

    ``echo_elements`` takes ``(type, value)`` pairs to mirror payload(s) from
    the request — the controller's country/FIPS pushes are answered with the
    original payload attached (live-verified 2026-09-20, life44).
    """
    parts: list[Packet] = [_element(33, struct.pack(">I", result_code))]
    parts.extend(_element(t, v) for t, v in echo_elements)
    return _control_frame(identity, MSG_CONFIG_UPDATE_RESPONSE, seq_num, parts)


# --------------------------------------------------------------------- parsing

def parse_control_messages(raw: bytes) -> list[dict]:
    """Parse concatenated control messages; returns one dict per message.

    Each dict: ``{"msg_type", "seq", "msg_elems_len", "elements": [(type, len, bytes)]}``.
    Parsing is driven by MsgElemsLen (RFC 5415 §4.5.1.1), so trailing garbage
    after the last message is ignored and a truncated element list is tolerated.
    """
    out: list[dict] = []
    i = 0
    while i + 8 <= len(raw):
        hlen_words = (raw[i + 1] >> 3) & 0x1F
        hlen = hlen_words * 4
        if hlen < 4 or i + hlen + 8 > len(raw):
            break
        msg_type = int.from_bytes(raw[i + hlen:i + hlen + 4], "big")
        seq = raw[i + hlen + 4]
        elems_len = int.from_bytes(raw[i + hlen + 5:i + hlen + 7], "big")
        total = hlen + 5 + elems_len
        if total <= 0 or i + total > len(raw):
            break
        elements: list[tuple[int, int, bytes]] = []
        o = i + hlen + 8
        end = i + total
        while o + 4 <= end:
            et = int.from_bytes(raw[o:o + 2], "big")
            el = int.from_bytes(raw[o + 2:o + 4], "big")
            val = raw[o + 4:min(o + 4 + el, end)]
            elements.append((et, el, val))
            o += 4 + el
        out.append({"msg_type": msg_type, "seq": seq,
                    "msg_elems_len": elems_len, "elements": elements})
        i += total
    return out


def result_code_of(msg: dict) -> int | None:
    """Result Code (Type 33) of one parsed message, or None when absent."""
    for et, _el, val in msg["elements"]:
        if et == 33 and len(val) >= 4:
            return int.from_bytes(val[:4], "big")
    return None
