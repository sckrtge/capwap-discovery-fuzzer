"""ZyWALL 310 (ZLD 4.73, capwapVersion 1.00.03) Discovery wire elements.

Everything here follows the reverse-engineered field table —
docs/reference/ZyWALL310-CAPWAP头部与Discovery字段表-20260923.md (workspace
authoritative copy, derived from capwap_srv/libcapwap* disassembly plus the
in-loop Primary-Discovery oracle) — NOT the RFC: the two vendors' element
numbering overlaps (RFC 38/39 are Board Data/Descriptor; ZyWALL uses 39 as a
private Max/Used/IANA container and 37 as a VSP "fish" container).

Wire rules that differ from the C9800 seed (all verified in-loop):
  * header: HLEN must equal 2 (8-byte fixed header only — any optional field
    is dropped at the entrance), so the M bit and the Radio MAC field never
    appear; version nibble must be 0.
  * control header MsgElemsLen counts 3 bytes beyond the element area
    ("Len = elements + 3").
  * Discovery (MsgType 1) passes four admission gates fed by exactly two
    elements: 39 (Max/Used/IANA) and 37 (non-zero MAC inside the "fish"
    container).
"""

import struct

#: Zyxel IANA enterprise number (0x37A) — the AC's IANA gate demands exactly
#: this value ("Srv IANA=890" in its debug log).
ZYXEL_IANA = 890

#: Magic opening the t37 sub-element container (0x66697368).
FISH_MAGIC = b"fish"

#: t37 sub-element identifiers (field table §Discovery(1) element 37).
T37_SUB_MAC = 2          # 6-byte MAC — feeds the non-zero-MAC gate
T37_SUB_X3 = 3           # 8 bytes, purpose unlabelled
T37_SUB_RADIOMAC = 6     # 4 x 6-byte radio MACs
T37_SUB_CW_VERSION = 7   # u32 compared against capwapVersion "1.00.03"

#: Element type numbers reused by ZyWALL inside a Discovery Request.
ELEM_T39_MAX_USED_IANA = 39
ELEM_T37_FISH = 37

#: capwapVersion 1.00.03 as carried by t37 sub-element 7 (u32 BE).
CW_VERSION_1_00_03 = 0x00010003

#: Model id for NWA5123-AC per the AP firmware's model_info.h — the value a
#: real managed-mode WTP of this line would claim.
NWA5123AC_MODEL_ID = 0x26E1


def _be16(v: int) -> bytes:
    return struct.pack(">H", v & 0xFFFF)


def _be32(v: int) -> bytes:
    return struct.pack(">I", v & 0xFFFFFFFF)


def build_t39_value(*, max_radios: int, used_radios: int, iana: int = ZYXEL_IANA,
                    model_id: int = NWA5123AC_MODEL_ID,
                    fw_version: bytes = b"6.10(###.10)b1",
                    str2: bytes = b"NWA5123-AC", flags: int = 0) -> bytes:
    """Element 39 value — sole feeder of the Max/Used/IANA gates, modelId and
    fwVersion (in-loop calibrated 2026-09-23 + disassembly-verified,
    ``capwap_msg_get_t39`` @ capwap_srv 0x100417f8; value-relative, all BE):

      +0  u8  Max          -> wtpInfo 0x9b0   (gate: 0 < Max < 5)
      +1  u8  Used         -> wtpInfo 0x9b4   (gate: 0 < Used <= Max)
      +2  u8  flags        !=0 swallows +3..+5 and shifts the rest by 3
      +3  u32 IANA_A       intermediate write to 0x93c
      +7  u16 discarded
      +9  u16 discarded
      +11 u16 modelId      -> wtpInfo 0x940   (0x26E1 = NWA5123-AC)
      +13 u32 IANA_B       intermediate write to 0x93c
      +17 u16 discarded
      +19 u16 len1         (cap = element TLV Len; cap < len1 -> msg dropped)
      +21 len1 str1        -> wtpInfo 0x96d   = WTP fwVersion
      +21+len1 u32 IANA_C  final value in 0x93c = the IANA gate (== 890)
      +25+len1 u16 discarded
      +27+len1 u16 len2
      +29+len1 len2 str2   -> wtpInfo 0x98e
    """
    return b"".join([
        struct.pack(">BBB", max_radios & 0xFF, used_radios & 0xFF, flags & 0xFF),
        _be32(iana), _be16(0), _be16(0), _be16(model_id),
        _be32(iana), _be16(0), _be16(len(fw_version)), fw_version,
        _be32(iana), _be16(0), _be16(len(str2)), str2,
    ])


def build_t37_fish_value(*, mac: bytes, iana: int = ZYXEL_IANA,
                         cw_version: int | None = CW_VERSION_1_00_03,
                         extra_subs: tuple[tuple[int, bytes], ...] = ()) -> bytes:
    """Element 37 value — the "fish" VSP container carrying the WTP identity.

    Layout (field table, BE):
      u32 iana, u32 x, u16 x, u32 x, u16 x, u32 magic "fish",
      then sub-elements { u16 id, fixed-length value }:
        2 = MAC (6B, feeds the non-zero-MAC gate), 3 = 8B, 6 = 24B radio MACs,
        7 = u32 capwapVersion.
    Unknown ids abort the container walk on the AC — only known ids allowed.
    """
    if len(mac) != 6:
        raise ValueError("mac must be 6 bytes")
    subs: list[bytes] = [_be16(T37_SUB_MAC) + mac]
    if cw_version is not None:
        subs.append(_be16(T37_SUB_CW_VERSION) + _be32(cw_version))
    for sub_id, value in extra_subs:
        subs.append(_be16(sub_id) + value)
    return _be32(iana) + _be32(0) + _be16(0) + _be32(0) + _be16(0) \
        + FISH_MAGIC + b"".join(subs)


def build_element(elem_type: int, value: bytes) -> bytes:
    """RFC-shaped TLV (u16 Type, u16 Len) as used by this firmware."""
    if len(value) > 0xFFFF:
        raise ValueError("element value too long")
    return _be16(elem_type) + _be16(len(value)) + value


def build_discovery_datagram(*, msg_type: int, seq: int, elements: bytes,
                             wbid: int = 0) -> bytes:
    """Assemble one plaintext control datagram the ZyWALL entrance accepts.

    Header: version 0, preamble type 0, HLEN=2 (no optional fields — the
    entrance drops anything longer), RID/T/K/F/L/W/M/K/Flags all 0.  ``wbid``
    defaults to 0 because that is the byte-exact form verified in-loop
    (G-Z2 recipe ``00 10 00 00 ...`` → answered); the AC's own replies carry
    WBID=1, so 1 is the "realistic 802.11 WTP" variant to probe separately.
    Control: u32 MsgType, u8 Seq, u16 MsgElemsLen = len(elements)+3, u8 Flags.
    """
    if len(elements) > 0xFFFF:
        raise ValueError("element area too long")
    header = bytes([0x00, 0x02 << 3 | 0x00, (wbid & 0x1F) << 1, 0x00,
                    0x00, 0x00, 0x00, 0x00])
    control = _be32(msg_type) + bytes([seq & 0xFF]) \
        + _be16(len(elements) + 3) + b"\x00"
    return header + control + elements
