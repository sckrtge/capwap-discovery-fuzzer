"""CiscoCAPWAPDiscoveryFuzzer — targets Cisco C9800 WLC."""

from capwap_discovery_fuzzer.capwap_discovery_fuzzer import CAPWAPDiscoveryFuzzer
from capwap_discovery_fuzzer.vendors.cisco.creator import CiscoPayloadCreator


class CiscoCAPWAPDiscoveryFuzzer(CAPWAPDiscoveryFuzzer):
    """Fuzzer variant for Cisco C9800 WLC.

    Only __init__ is overridden to swap in CiscoPayloadCreator.
    All fuzzing logic, crash detection, logging, and replay are inherited
    from CAPWAPDiscoveryFuzzer unchanged.

    Because is_target_alive() calls self.payload_creator.create_discovery_request(valid=True),
    the Cisco-format probe is sent automatically — no override needed.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.payload_creator = CiscoPayloadCreator(rng=self._rng)
