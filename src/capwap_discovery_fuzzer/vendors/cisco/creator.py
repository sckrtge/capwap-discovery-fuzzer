"""CiscoPayloadCreator — builds a valid Cisco C9800-compatible Discovery Request.

Field and type numbers follow RFC 5415 / RFC 5416 as read from the workspace's
read-only copies (docs/evidence/rfc/): Type 20 Discovery Type, 38 WTP Board Data,
39 WTP Descriptor, 41 WTP Frame Tunnel Mode, 44 WTP MAC Type, 45 WTP Name,
28 Location Data, 37 Vendor Specific Payload (§4.6.x) and 1048 IEEE 802.11 WTP
Radio Information (RFC 5416 §6.25).

CAPWAP header note:
  Real Cisco APs set M=1 (Radio MAC present) and Hlen=4 (16-byte header).
  The existing CAPWAP_Header Scapy class only covers the fixed 8-byte base.
  We insert the 8-byte optional MAC field as a Raw layer between CAPWAP_Header
  and Control_Header.  Scapy's getlayer() traverses through Raw, so all safe
  fuzz methods (fuzz_capwap_header, fuzz_ctrl_*, fuzz_elem_*) still work
  correctly on the resulting packet.

Element order matches the real AP capture (cisco_ap_discovery.json):
  Type 20 → 38 → 39 → 41 → 44 → 45 → 28 → 1048 × 2 → 37(VSP207) → 37(VSP5)

Identity parameterisation (E/3a): every identity-bearing value is now an
`ApIdentity` field, so an experiment can vary the claimed AP without touching
code.  The defaults reproduce the captured bytes exactly — asserted by
tests/test_identity.py — so lock-mode and baseline sessions stay comparable.
"""

import struct
from dataclasses import dataclass, field
from typing import Optional

from scapy.packet import Packet, Raw

from capwap_discovery_fuzzer.request_creater import (
    CAPWAP_Header,
    Control_Header,
    MessageElement,
    Payload_Creator,
)
from capwap_discovery_fuzzer.vendors.cisco.elements import (
    AP_MAC,
    AP_NAME,
    BOARD_DATA_OPTIONS_ELEM_ID,
    CISCO_VENDOR_ID,
    RAD_NAME_ELEM_ID,
    make_board_data,
    make_descriptor,
    make_radio_information,
)

#: Discovery Type value carried in the Cisco seed (element Type 20, §4.6.21).
CISCO_DISCOVERY_TYPE_VALUE = b"\x01"

#: Message type the seed uses: 19 = Primary Discovery Request (§5.3).  Cisco APs
#: send this rather than 1 (Discovery Request, §5.1); both have identical
#: mandatory element sets, so the same seed body works for either value.
CISCO_PRIMARY_DISCOVERY_REQUEST = 0x13
DISCOVERY_REQUEST = 0x01

#: Cisco-proprietary VSP payload for ElemID 207 (Board Data Options), lifted from
#: the capture.  Not an RFC element: the ElemID namespace belongs to Cisco.
_VSP207_DATA = bytes.fromhex("01000003")


@dataclass(frozen=True)
class ApIdentity:
    """Everything the seed claims about the AP it is impersonating.

    Defaults reproduce the real C9105AXI-H capture byte for byte.
    """

    ap_name: bytes = AP_NAME
    ap_mac: bytes = AP_MAC                     # CAPWAP optional Radio MAC field
    model: bytes = b"C9105AXI-H"               # WTP Board Data sub-element 0
    serial: bytes = b"FGL2718LPQY"             # WTP Board Data sub-element 1
    base_mac: bytes = bytes.fromhex("10a82901d6b0")   # Board Data sub-element 4
    #: (Radio ID, Radio Type) per radio; Type bit field |Reservd|N|G|A|B|.
    radios: tuple[tuple[int, int], ...] = ((0, 0x01), (1, 0x02))
    max_radios: int = 2
    radios_in_use: int = 2
    #: RFC 5415 §4.6.41 requires 1..255; the capture carries 0 (non-conformant).
    num_encrypt: int = 0
    #: 0x13 = Primary Discovery Request (Cisco), 0x01 = Discovery Request (§5.1).
    msg_type: int = CISCO_PRIMARY_DISCOVERY_REQUEST
    #: Element types to leave out of the seed, for presence/absence ablation (E/3b).
    omit_elements: frozenset[int] = field(default_factory=frozenset)

    def board_data(self) -> bytes:
        return make_board_data(self.model, self.serial, self.base_mac)

    def descriptor(self) -> bytes:
        return make_descriptor(self.max_radios, self.radios_in_use, self.num_encrypt)


def _vsp_value(elem_id: int, data: bytes) -> bytes:
    """Vendor Specific Payload value: VendorID(4) + ElemID(2) + Data (§4.6.39)."""
    return CISCO_VENDOR_ID.to_bytes(4, "big") + elem_id.to_bytes(2, "big") + data


def _mac_optional_field(mac: bytes = AP_MAC) -> bytes:
    """Return the 8-byte optional Radio MAC field (length + mac + 1-byte pad)."""
    return struct.pack("B", 6) + mac + b"\x00"


def _element(type_: int, value: bytes) -> MessageElement:
    return MessageElement(Type=type_, Length=len(value), Value=value)


class CiscoPayloadCreator(Payload_Creator):
    """Payload creator that produces Cisco C9800-compatible Discovery Requests."""

    def __init__(self, rng=None, identity: Optional[ApIdentity] = None):
        super().__init__(rng=rng)
        self.identity = identity or ApIdentity()

    def create_discovery_request(self, valid: bool = False) -> Packet:
        if not valid:
            return super().create_discovery_request(valid=False)

        ident = self.identity
        omit = set(ident.omit_elements)

        # ---- message elements (in capture order) ----
        parts: list[MessageElement] = [
            _element(20, CISCO_DISCOVERY_TYPE_VALUE),
            _element(38, ident.board_data()),
            _element(39, ident.descriptor()),
            _element(41, b"\x04"),
            _element(44, b"\x01"),
            _element(45, ident.ap_name),
            _element(28, b"default location"),
        ]
        parts.extend(_element(1048, make_radio_information(rid, rtype))
                     for rid, rtype in ident.radios)
        parts.append(_element(37, _vsp_value(BOARD_DATA_OPTIONS_ELEM_ID, _VSP207_DATA)))
        parts.append(_element(37, _vsp_value(RAD_NAME_ELEM_ID, ident.ap_name)))

        elements = None
        for part in parts:
            if part.Type in omit:
                continue
            elements = part if elements is None else elements / part
        if elements is None:
            raise ValueError("every seed element was omitted; nothing left to send")

        # MsgElemsLen (RFC 5415 §4.5.1.1): counts from after SeqNum, i.e.
        # MsgElemsLen(2B) + Flags(1B) + element bytes.
        control_header = Control_Header(
            MsgType=ident.msg_type, SeqNum=0, MsgElemsLen=len(bytes(elements)) + 3, Flags=0
        )

        # CAPWAP header: M=1, Hlen=4, WBID=1, all others 0
        capwap_header = CAPWAP_Header(
            version=0, type=0, Hlen=4, Rid=0, WBID=1,
            T=0, F=0, L=0, W=0, M=1, K=0, Flags=0,
            FragmentID=0, FragmentOffset=0, Rsvd=0,
        )

        return (capwap_header / Raw(load=_mac_optional_field(ident.ap_mac))
                / control_header / elements)
