"""Cisco-specific CAPWAP constants and raw element bytes.

Raw value bytes for WTP Board Data (Type 38) and WTP Descriptor (Type 39)
are extracted verbatim from a real C9105AXI-H AP capture (cisco_ap_discovery.json),
guaranteeing C9800 WLC compatibility.
"""

import struct

# Cisco vendor ID: 0x40A000 = 4232704
CISCO_VENDOR_ID: int = 4232704

# Vendor Specific Payload sub-element IDs (embedded inside Type=37 elements)
RAD_NAME_ELEM_ID: int = 5        # AP name string
BOARD_DATA_OPTIONS_ELEM_ID: int = 207  # ant-type / flex-connect / ap-type / failover-priority

# AP identity used in the probe packet (matches the captured AP)
AP_NAME: bytes = b"AP10A8.2901.D6B0"
AP_MAC: bytes = bytes.fromhex("10a829926100")  # Radio MAC from pcap capture

# ---------------------------------------------------------------------------
# Raw value bytes extracted from cisco_ap_discovery.json
# (Type/Length header NOT included — these are the Value fields only)
# ---------------------------------------------------------------------------

# Type 38, Length 67 — WTP Board Data (RFC 5415 §4.6.40: Vendor Identifier +
# Board Data sub-elements of Type(2)/Length(2)/Value).
# Sub-element layout read off the capture:
#   0 -> 10B  "C9105AXI-H"   AP model
#   1 -> 11B  "FGL2718LPQY"  serial number
#   2 -> 2B   0xffff         (vendor-defined)
#   3 -> 14B  "Linux Revision"
#   4 -> 6B   base radio MAC
BOARD_SUBELEM_MODEL = 0
BOARD_SUBELEM_SERIAL = 1
BOARD_SUBELEM_VENDOR_FLAG = 2
BOARD_SUBELEM_OS = 3
BOARD_SUBELEM_BASE_MAC = 4

WTP_BOARD_DATA_VALUE: bytes = bytes.fromhex(
    "004096000000000a43393130354158492d48"
    "0001000b46474c323731384c505159"
    "00020002ffff"
    "0003000e4c696e7578205265766973696f6e"
    "0004000610a82901d6b0"
)

# Type 39, Length 40 — WTP Descriptor (RFC 5415 §4.6.41:
# Max Radios(1) | Radios in use(1) | Num Encrypt(1) | Encryption Sub-Element(s)
# | Descriptor Sub-Element(s)).
# NOTE: this template — taken verbatim from the real AP capture — has
# Num Encrypt = 0, while §4.6.41 requires 1..255 and at least one Encryption
# sub-element. That non-conformance is inherited from Cisco's AP, not introduced
# here; it is reported by conformance.check_message().
WTP_DESCRIPTOR_HEADER: bytes = bytes.fromhex("020200")
WTP_DESCRIPTOR_TAIL: bytes = bytes.fromhex(
    "010040960000000004010000000040960000010004110e004f004096000002000401010204"
)
WTP_DESCRIPTOR_VALUE: bytes = WTP_DESCRIPTOR_HEADER + WTP_DESCRIPTOR_TAIL


def make_board_data(model: bytes = b"C9105AXI-H",
                    serial: bytes = b"FGL2718LPQY",
                    base_mac: bytes = bytes.fromhex("10a82901d6b0"),
                    vendor_id: int = CISCO_VENDOR_ID) -> bytes:
    """Build the WTP Board Data value; defaults reproduce the captured bytes."""
    return (
        vendor_id.to_bytes(4, "big")
        + make_element(BOARD_SUBELEM_MODEL, model)
        + make_element(BOARD_SUBELEM_SERIAL, serial)
        + make_element(BOARD_SUBELEM_VENDOR_FLAG, b"\xff\xff")
        + make_element(BOARD_SUBELEM_OS, b"Linux Revision")
        + make_element(BOARD_SUBELEM_BASE_MAC, base_mac)
    )


def make_descriptor(max_radios: int = 2, radios_in_use: int = 2,
                    num_encrypt: int = 0) -> bytes:
    """Build the WTP Descriptor value; defaults reproduce the captured bytes.

    ``num_encrypt=1`` is the value RFC 5415 §4.6.41 requires (1..255) and the
    head of the tail below is the captured Encryption sub-element, so raising
    this field makes the element conformant.
    """
    return bytes([max_radios, radios_in_use, num_encrypt]) + WTP_DESCRIPTOR_TAIL


def make_radio_information(radio_id: int = 1, radio_type: int = 0x0E) -> bytes:
    """Build an IEEE 802.11 WTP Radio Information value (RFC 5416 §6.25).

    Length is fixed at 5: Radio ID(1) + Radio Type(4, bit field |Reservd|N|G|A|B|).
    Radio ID must be 1..31; the captured Cisco AP uses 0, which the conformance
    checker reports as a violation (see conformance.check_message).
    """
    return bytes([radio_id]) + radio_type.to_bytes(4, "big")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def make_vsp(elem_id: int, data: bytes) -> bytes:
    """Build a complete Vendor Specific Payload element (Type=37, RFC 5415 §4.6.39).

    Wire format:
        [Type=37, 2B][Length=len(data)+6, 2B][VendorID, 4B][ElemID, 2B][Data]
    """
    vendor_id_bytes = struct.pack(">I", CISCO_VENDOR_ID)
    elem_id_bytes = struct.pack(">H", elem_id)
    length = len(data) + 6  # 4B VendorID + 2B ElemID + data
    header = struct.pack(">HH", 37, length)
    return header + vendor_id_bytes + elem_id_bytes + data


def make_element(type_: int, value: bytes) -> bytes:
    """Build a standard CAPWAP message element: [Type 2B][Length 2B][Value]."""
    return struct.pack(">HH", type_, len(value)) + value
