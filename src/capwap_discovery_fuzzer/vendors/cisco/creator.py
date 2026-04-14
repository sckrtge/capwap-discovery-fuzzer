"""CiscoPayloadCreator — builds a valid Cisco C9800-compatible Discovery Request.

CAPWAP header note:
  Real Cisco APs set M=1 (Radio MAC present) and Hlen=4 (16-byte header).
  The existing CAPWAP_Header Scapy class only covers the fixed 8-byte base.
  We insert the 8-byte optional MAC field as a Raw layer between CAPWAP_Header
  and Control_Header.  Scapy's getlayer() traverses through Raw, so all safe
  fuzz methods (fuzz_capwap_header, fuzz_control_header, fuzz_any_msg_*) still
  work correctly on the resulting packet.

Element order matches the real AP capture (cisco_ap_discovery.json):
  Type 20 → 38 → 39 → 41 → 44 → 45 → 28 → 1048 × 2 → 37(VSP207) → 37(VSP5)
"""

import struct
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
    RAD_NAME_ELEM_ID,
    WTP_BOARD_DATA_VALUE,
    WTP_DESCRIPTOR_VALUE,
    make_vsp,
)


def _mac_optional_field(mac: bytes = AP_MAC) -> bytes:
    """Return the 8-byte optional Radio MAC field (length + mac + 1-byte pad)."""
    return struct.pack("B", 6) + mac + b"\x00"


class CiscoPayloadCreator(Payload_Creator):
    """Payload creator that produces Cisco C9800-compatible Discovery Requests."""

    def create_discovery_request(self, valid: bool = False) -> Packet:
        if not valid:
            return super().create_discovery_request(valid=False)

        # ---- message elements (in capture order) ----
        elements = (
            MessageElement(Type=20,   Length=1,                    Value=b"\x01")
            / MessageElement(Type=38, Length=len(WTP_BOARD_DATA_VALUE),   Value=WTP_BOARD_DATA_VALUE)
            / MessageElement(Type=39, Length=len(WTP_DESCRIPTOR_VALUE),   Value=WTP_DESCRIPTOR_VALUE)
            / MessageElement(Type=41, Length=1,                    Value=b"\x04")
            / MessageElement(Type=44, Length=1,                    Value=b"\x01")
            / MessageElement(Type=45, Length=len(AP_NAME),         Value=AP_NAME)
            / MessageElement(Type=28, Length=16,                   Value=b"default location")
            / MessageElement(Type=1048, Length=5,                  Value=b"\x00\x00\x00\x00\x01")
            / MessageElement(Type=1048, Length=5,                  Value=b"\x01\x00\x00\x00\x02")
            / MessageElement(Type=37, Length=10,
                             Value=bytes.fromhex("0040960000cf01000003"))
            / MessageElement(Type=37, Length=22,
                             Value=bytes.fromhex("004096000005") + AP_NAME)
        )

        # MsgType=0x13 matches the real Cisco AP capture (not standard Type=1).
        # MsgElemsLen (RFC 5415): counts from after SeqNum, i.e.
        # MsgElemsLen(2B) + Flags(1B) + element bytes = len(elements) + 3.
        msg_elems_len = len(bytes(elements)) + 3
        control_header = Control_Header(
            MsgType=0x13, SeqNum=0, MsgElemsLen=msg_elems_len, Flags=0
        )

        # CAPWAP header: M=1, Hlen=4, WBID=1, all others 0
        capwap_header = CAPWAP_Header(
            version=0, type=0, Hlen=4, Rid=0, WBID=1,
            T=0, F=0, L=0, W=0, M=1, K=0, Flags=0,
            FragmentID=0, FragmentOffset=0, Rsvd=0,
        )

        return capwap_header / Raw(load=_mac_optional_field()) / control_header / elements
