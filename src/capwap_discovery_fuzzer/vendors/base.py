from abc import ABC, abstractmethod
from scapy.packet import Packet


class VendorFuzzer(ABC):
    """Abstract base class for vendor-specific fuzzer extensions.

    To add a new vendor:
    1. Create vendors/<vendor>/elements.py  — constants and raw byte blobs
    2. Create vendors/<vendor>/creator.py   — subclass Payload_Creator
    3. Create vendors/<vendor>/fuzzer.py    — subclass CAPWAPDiscoveryFuzzer,
       override __init__ to swap self.payload_creator
    4. Register the fuzzer class in vendors/__init__.get_vendor()
    """

    @abstractmethod
    def create_vendor_discovery_request(self, valid: bool = True) -> Packet:
        """Return a vendor-specific CAPWAP Discovery Request packet."""
