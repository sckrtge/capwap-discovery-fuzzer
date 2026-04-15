"""Vendor extension registry.

To add a new vendor:
  1. Create vendors/<name>/  with fuzzer.py (and optionally creator.py,
     response_parser.py, elements.py)
  2. Import the fuzzer class below and add it to _VENDOR_MAP

Default vendor is "opencapwap" (gray-box mode for OpenCAPWAP AC).
Use "generic" to force the base black-box CAPWAPDiscoveryFuzzer.

默认 vendor 为 "opencapwap"（OpenCAPWAP AC 灰盒模式）。
如需强制使用基类纯黑盒模式，传入 "generic"。
"""

from typing import Optional, Type

from capwap_discovery_fuzzer.capwap_discovery_fuzzer import CAPWAPDiscoveryFuzzer
from capwap_discovery_fuzzer.vendors.cisco.fuzzer import CiscoCAPWAPDiscoveryFuzzer
from capwap_discovery_fuzzer.vendors.opencapwap.fuzzer import OpenCAPWAPFuzzer

#: Vendor name → fuzzer class mapping.
#: 厂商名称 → fuzzer 类的映射表。
_VENDOR_MAP: dict[str, Type[CAPWAPDiscoveryFuzzer]] = {
    "opencapwap": OpenCAPWAPFuzzer,
    "cisco":      CiscoCAPWAPDiscoveryFuzzer,
    "generic":    CAPWAPDiscoveryFuzzer,   # explicit black-box fallback / 显式黑盒降级
}

#: Default vendor name used when --vendor is not specified on the CLI.
#: CLI 未指定 --vendor 时使用的默认厂商名称。
DEFAULT_VENDOR = "opencapwap"


def get_vendor(name: str) -> Optional[Type[CAPWAPDiscoveryFuzzer]]:
    """Return the fuzzer class for *name*, or None if the name is unknown.

    Lookup is case-insensitive.
    查找不区分大小写，name 未知时返回 None。
    """
    return _VENDOR_MAP.get(name.lower())
