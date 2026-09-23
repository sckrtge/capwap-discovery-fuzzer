"""ZywallCAPWAPDiscoveryFuzzer — targets ZyWALL 310 (ZLD 4.73) emulated AC."""

from capwap_discovery_fuzzer.capwap_discovery_fuzzer import CAPWAPDiscoveryFuzzer
from capwap_discovery_fuzzer.vendors.zywall.creator import (
    ZywallIdentity,
    ZywallPayloadCreator,
)


class ZywallCAPWAPDiscoveryFuzzer(CAPWAPDiscoveryFuzzer):
    """Fuzzer variant for the ZyWALL 310 CAPWAP server (capwap_srv).

    Swaps in ZywallPayloadCreator: gate-passing Discovery datagrams built from
    the reverse-engineered field table (HLEN=2 header, MsgElemsLen=elements+3,
    element 39 Max/Used/IANA + element 37 "fish" MAC container).  All fuzzing
    logic, crash detection, logging and replay are inherited unchanged.
    """

    def __init__(self, identity: ZywallIdentity | None = None, **kwargs):
        super().__init__(**kwargs)
        self.identity = identity
        self.payload_creator = ZywallPayloadCreator(rng=self._rng, identity=identity)
