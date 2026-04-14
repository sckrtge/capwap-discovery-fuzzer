"""CiscoCAPWAPDiscoveryFuzzer — targets Cisco C9800 WLC."""

from capwap_discovery_fuzzer.capwap_discovery_fuzzer import CAPWAPDiscoveryFuzzer
from capwap_discovery_fuzzer.vendors.cisco.creator import CiscoPayloadCreator
from capwap_discovery_fuzzer.vendors.cisco.response_parser import CiscoResponseParser


class CiscoCAPWAPDiscoveryFuzzer(CAPWAPDiscoveryFuzzer):
    """Fuzzer variant for Cisco C9800 WLC.

    Overrides __init__ to swap in:
    - CiscoPayloadCreator: builds C9800-compatible Discovery Requests
    - CiscoResponseParser: accepts MsgType=2 and MsgType=20 as valid,
      extracts Cisco VSP fields

    All other fuzzing logic, crash detection, logging, and replay are
    inherited from CAPWAPDiscoveryFuzzer unchanged.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.payload_creator = CiscoPayloadCreator(rng=self._rng)
        self.response_parser = CiscoResponseParser()
