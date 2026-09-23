"""ZyWALL 310 vendor package (field table: docs/reference/ZyWALL310-*)."""

from capwap_discovery_fuzzer.vendors.zywall.creator import (
    DISCOVERY_REQUEST,
    PRIMARY_DISCOVERY_REQUEST,
    ZywallIdentity,
    ZywallPayloadCreator,
)
from capwap_discovery_fuzzer.vendors.zywall.elements import (
    CW_VERSION_1_00_03,
    FISH_MAGIC,
    NWA5123AC_MODEL_ID,
    ZYXEL_IANA,
    build_discovery_datagram,
    build_element,
    build_t37_fish_value,
    build_t39_value,
)

__all__ = [
    "CW_VERSION_1_00_03",
    "DISCOVERY_REQUEST",
    "FISH_MAGIC",
    "NWA5123AC_MODEL_ID",
    "PRIMARY_DISCOVERY_REQUEST",
    "ZYXEL_IANA",
    "ZywallIdentity",
    "ZywallPayloadCreator",
    "build_discovery_datagram",
    "build_element",
    "build_t37_fish_value",
    "build_t39_value",
]
