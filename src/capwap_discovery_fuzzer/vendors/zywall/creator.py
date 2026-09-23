"""ZywallPayloadCreator — ZyWALL 310-compatible Discovery Request seeds.

The ZyWALL seed is a raw datagram (no Scapy layering): the firmware demands
HLEN=2, so there is no optional-field region for the generic CAPWAP_Header
class to model, and every mutation layer in discovery_stage.py already works
on the serialised bytes.

Authoritative layouts: vendors/zywall/elements.py and the workspace field
table docs/reference/ZyWALL310-CAPWAP头部与Discovery字段表-20260923.md.
"""

from dataclasses import dataclass, field

from scapy.packet import Packet, Raw

from capwap_discovery_fuzzer.request_creater import Payload_Creator
from capwap_discovery_fuzzer.vendors.zywall.elements import (
    CW_VERSION_1_00_03,
    ELEM_T37_FISH,
    ELEM_T39_MAX_USED_IANA,
    NWA5123AC_MODEL_ID,
    ZYXEL_IANA,
    build_discovery_datagram,
    build_element,
    build_t37_fish_value,
    build_t39_value,
)

#: MsgType 1 = Discovery Request (RFC 5415 §5.1; ZyWALL numbering identical).
DISCOVERY_REQUEST = 0x01
#: MsgType 19 = Primary Discovery Request — zero element validation, always
#: answered (the in-loop oracle used to verify CAPWAP reachability, G-Z2).
PRIMARY_DISCOVERY_REQUEST = 0x13


@dataclass(frozen=True)
class ZywallIdentity:
    """What the seed claims about the impersonated ZyXel WTP (NWA5123-AC line)."""

    ap_mac: bytes = bytes.fromhex("000c29aabbcc")  # feeds the non-zero-MAC gate
    #: four gates: 0 < max_radios < 5 and 0 < used_radios <= max_radios
    max_radios: int = 2
    used_radios: int = 2
    model_id: int = NWA5123AC_MODEL_ID
    #: 1 = Discovery Request (four gates); 19 = Primary (always-answer oracle).
    msg_type: int = DISCOVERY_REQUEST
    cw_version: int = CW_VERSION_1_00_03
    #: Element types to omit, for presence/absence ablation.
    omit_elements: frozenset[int] = field(default_factory=frozenset)

    def gates_ok(self) -> bool:
        return (0 < self.max_radios < 5) and (0 < self.used_radios <= self.max_radios)


class ZywallPayloadCreator(Payload_Creator):
    """Builds gate-passing ZyWALL Discovery datagrams as raw packets."""

    def __init__(self, rng=None, identity: ZywallIdentity | None = None):
        super().__init__(rng=rng)
        self.identity = identity or ZywallIdentity()

    def create_discovery_request(self, valid: bool = False) -> Packet:
        if not valid:
            return super().create_discovery_request(valid=False)

        ident = self.identity
        omit = set(ident.omit_elements)

        parts: list[bytes] = []
        t39 = build_t39_value(max_radios=ident.max_radios,
                              used_radios=ident.used_radios,
                              iana=ZYXEL_IANA, model_id=ident.model_id)
        t37 = build_t37_fish_value(mac=ident.ap_mac,
                                   cw_version=ident.cw_version)
        if ELEM_T39_MAX_USED_IANA not in omit:
            parts.append(build_element(ELEM_T39_MAX_USED_IANA, t39))
        if ELEM_T37_FISH not in omit:
            parts.append(build_element(ELEM_T37_FISH, t37))
        if not parts:
            raise ValueError("every seed element was omitted; nothing left to send")

        raw = build_discovery_datagram(
            msg_type=ident.msg_type, seq=0, elements=b"".join(parts))
        return Raw(load=raw)
