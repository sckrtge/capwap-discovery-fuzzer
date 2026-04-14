"""Vendor extension registry.

To add a new vendor:
  1. Create vendors/<name>/  with elements.py, creator.py, fuzzer.py
  2. Import the fuzzer class below and add it to _VENDOR_MAP
"""

from typing import Optional, Type

from capwap_discovery_fuzzer.capwap_discovery_fuzzer import CAPWAPDiscoveryFuzzer
from capwap_discovery_fuzzer.vendors.cisco.fuzzer import CiscoCAPWAPDiscoveryFuzzer

_VENDOR_MAP: dict[str, Type[CAPWAPDiscoveryFuzzer]] = {
    "cisco": CiscoCAPWAPDiscoveryFuzzer,
}


def get_vendor(name: str) -> Optional[Type[CAPWAPDiscoveryFuzzer]]:
    """Return the fuzzer class for *name*, or None if unknown."""
    return _VENDOR_MAP.get(name.lower())
