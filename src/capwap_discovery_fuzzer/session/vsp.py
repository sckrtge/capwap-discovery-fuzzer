"""Cisco Vendor Specific Payload (message element 37, RFC 5415 §4.6.39) codec.

Wire layout of the element value::

    Vendor ID (4B, big-endian) + Elem ID (2B, big-endian) + payload data

Cisco's vendor id is the OUI-derived constant ``0x00409600`` (verified against
live traffic, 2026-09-20; note the IANA enterprise form "00 00 00 09" is NOT
what Cisco C9800 implementations emit or expect).

Known element ids — every entry below was observed on the wire or confirmed by
disassembly of ``libewlc_capwapctrlmsg.so`` (17.14.01), see the E7 round notes:

======================  =======  =============================================
constant                value    meaning
======================  =======  =============================================
``RAD_NAME``            5        AP name string
``CLIENT_CONTEXT_REQ``  75       Run-state "report your client list" probe
``SPAM_VENDOR_SPEC``    104      wrapper: data is another full VSP
``REG_DOMAIN``          126      AP regulatory domain (5-byte payload)
``BOARD_DATA_OPTIONS``  207      ant-type / flex-connect / ap-type
``TLV_PAYLOAD``         215      nested TLV list
``FIPS``                252      FIPS mode push (Run state)
======================  =======  =============================================

The regulatory-domain payload is 5 bytes::

    band_id (1) | set (1) | slot_id (1) | code (2, big-endian)

The controller keeps a per-(slot, band) record; at Configuration Status time it
runs ``apmgr_verify_reg_domain_slot`` on every radio and refuses the session's
country push while any declared domain is missing or invalid ("Blank regulatory
Domain" / "regulatory domain validation failed for country CN").

Domain *codes* are small integers resolved by ``reg_domain_get_string_from_reg_dom_code``
in ``libewlc_regulatory.so`` (disassembled 2026-09-20, function at +0xc180, string
table at +0x1a13f).  Verified entries:

====  ====  ==========
code  band  domain
====  ====  ==========
0x00  any   -A
0x06  any   -I
0x09  any   -J
0x0B  any   -A
0x0F  any   -T
0x10  any   -C  (China — the value that passes for ``ap country CN``)
0x14  any   -T
0x55  any   -UX  (universal / ROW APs; the controller compares against
                    this literal in ``apmgr_ap_process_cfg_status_request``)
====  ====  ==========

(The function covers further ranges 0x18-0x32/0x36-0x39; they are not needed
for the CN/US paths and are left undocumented rather than guessed.)
"""

from __future__ import annotations

import struct

#: Cisco vendor id inside element 37, big-endian bytes ``00 40 96 00``.
CISCO_VENDOR_ID_U32 = 0x00409600

VSP_ELEM_RAD_NAME = 0x0005
VSP_ELEM_CLIENT_CONTEXT_REQ = 0x004B
VSP_ELEM_SPAM_VENDOR_SPECIFIC = 0x0068
VSP_ELEM_REG_DOMAIN = 0x007E          # 126 — AP Regulatory Domain
VSP_ELEM_BOARD_DATA_OPTIONS = 0x00CF  # 207
VSP_ELEM_TLV_PAYLOAD = 0x00D7         # 215
VSP_ELEM_FIPS = 0x00FC                # 252

#: Size of the VSP header (VendorID 4B + ElemID 2B).  The header is exactly six
#: bytes; one padding byte too many shifts the ElemID to 0x0000 and the payload
#: is silently dropped as unknown by the controller's VSP router (live-verified
#: 2026-09-20 with a uprobe on the router's default branch).
VSP_HEADER_LEN = 6

REG_DOMAIN_CODES: dict[int, str] = {
    0x00: "-A",
    0x06: "-I",
    0x09: "-J",
    0x0B: "-A",
    0x0F: "-T",
    0x10: "-C",   # China
    0x14: "-T",
    0x55: "-UX",
}

DOMAIN_STRING_UNKNOWN = "NA"


def encode_vsp(elem_id: int, data: bytes) -> bytes:
    """Return the full element-37 *value* for one vendor payload."""
    if not 0 <= elem_id <= 0xFFFF:
        raise ValueError(f"elem_id {elem_id} outside u16")
    return (struct.pack(">IH", CISCO_VENDOR_ID_U32, elem_id) + data)


def decode_vsp(value: bytes) -> tuple[int, bytes]:
    """Split one element-37 *value* into ``(elem_id, payload_data)``.

    Raises :class:`ValueError` when the vendor id is not Cisco's or the buffer
    is shorter than the fixed header — the same conditions under which the
    controller's parser discards the payload.
    """
    if len(value) < VSP_HEADER_LEN:
        raise ValueError(f"VSP value too short: {len(value)}B < {VSP_HEADER_LEN}B")
    vendor, elem_id = struct.unpack_from(">IH", value, 0)
    if vendor != CISCO_VENDOR_ID_U32:
        raise ValueError(f"vendor id 0x{vendor:08x} != 0x{CISCO_VENDOR_ID_U32:08x}")
    return elem_id, value[VSP_HEADER_LEN:]


def encode_reg_domain_payload(band_id: int, set_flag: int, slot_id: int,
                              code: int) -> bytes:
    """Return the 5-byte regulatory-domain payload (see module docstring)."""
    for name, value in (("band_id", band_id), ("set", set_flag), ("slot_id", slot_id)):
        if not 0 <= value <= 0xFF:
            raise ValueError(f"{name} {value} outside u8")
    if not 0 <= code <= 0xFFFF:
        raise ValueError(f"code {code} outside u16")
    return struct.pack(">BBBH", band_id, set_flag, slot_id, code)


def build_reg_domain_vsp(band_id: int, set_flag: int, slot_id: int, code: int) -> bytes:
    """Full element-37 value declaring one (slot, band) regulatory domain."""
    return encode_vsp(VSP_ELEM_REG_DOMAIN,
                      encode_reg_domain_payload(band_id, set_flag, slot_id, code))


def decode_reg_domain_payload(data: bytes) -> tuple[int, int, int, int]:
    """Inverse of :func:`encode_reg_domain_payload`; returns (band, set, slot, code)."""
    if len(data) != 5:
        raise ValueError(f"reg-domain payload must be 5B, got {len(data)}B")
    band, set_flag, slot, code = struct.unpack(">BBBH", data)
    return band, set_flag, slot, code


def domain_string_for_code(code: int) -> str:
    """Human-readable domain letter for a code, or ``"NA"`` when unmapped."""
    return REG_DOMAIN_CODES.get(code, DOMAIN_STRING_UNKNOWN)
