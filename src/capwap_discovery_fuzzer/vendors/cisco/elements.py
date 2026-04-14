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

# Type 38, Length 67 — WTP Board Data
WTP_BOARD_DATA_VALUE: bytes = bytes.fromhex(
    "004096000000000a43393130354158492d48"
    "0001000b46474c323731384c505159"
    "00020002ffff"
    "0003000e4c696e7578205265766973696f6e"
    "0004000610a82901d6b0"
)

# Type 39, Length 40 — WTP Descriptor
WTP_DESCRIPTOR_VALUE: bytes = bytes.fromhex(
    "020200010040960000000004010000000040"
    "960000010004110e004f004096000002000401010204"
)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def make_vsp(elem_id: int, data: bytes) -> bytes:
    """Build a complete Vendor Specific Payload element (Type=37).

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
