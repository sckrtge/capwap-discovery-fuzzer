"""Main module."""
import socket
from scapy.all import *
import capwap_discovery_fuzzer.errors as errors
from capwap_discovery_fuzzer.utils import *
import random
import time
import json
from pathlib import Path
from capwap_discovery_fuzzer.payload_creater import *
from capwap_discovery_fuzzer.payload_fuzzer import *
from scapy.config import conf

MUTATUION_COUNT = 10

class CAPWAPDiscoveryFuzzer:
    def __init__(
        self,
        ac_ip: str | None,
        ac_port: int = 5246,
        timeout: float = 3.0,
        seed: int | None = None,
        broadcast: bool = False,
        iface: str | None = None,
    ):
        self.ac_ip = ac_ip
        self.ac_port = ac_port
        self.timeout = timeout
        self.broadcast = broadcast
        self.iface = iface

        self.sock = None
        self.sequence = 0
        self._rng = random.Random()
        self.seed = seed

        if seed is not None:
            self._rng.seed(seed)

    def load_request_from_pcap(self, pcap_path: str) -> bytes:
        """
        Load and extract a CAPWAP Discovery Request from a pcap file.
        """
        pkts = rdpcap(pcap_path)
        for pkt in pkts:
            if not pkt.haslayer("UDP"):
                continue

            udp = pkt["UDP"]
            if udp.dport != 5246:
                continue

            payload = udp.payload
            return payload

        raise ValueError("No CAPWAP Discovery Request found in pcap!")

    def is_discovery_response(self, discovery_response) -> bool:
        """
        only determine whether any response is received.
        """
        if discovery_response is None:
            logging.info(f"Discovery Response Timeout")
            return False
        logging.info(f"Discovery Response:\n{hexdump(bytes(discovery_response))}")
        return True
    
    def send_discovery_request(self, discovery_request):
        conf.verb = 0
        sport = random.randint(20000,60000)
        pkt = IP(dst=self.ac_ip) / UDP(sport=sport, dport=self.ac_port) / discovery_request # type: ignore
        logging.info(f"Send Discovery Request:\n{pkt.show(dump=True)}\n")
        # logging.info(f"Send Discovery Request:\n{hexdump(bytes(pkt))}\n")
        resp = sr1(pkt, timeout=self.timeout)
        # time.sleep(1)
        return resp
    
    def fuzzing(
        self,
        pcap_path: str | None,
    ) -> dict[str, int]:

        status = {
            'timeout': 0,
            'valid': 0,
            'total': 0
        }

        creator = Payload_Creator()

        if pcap_path is not None:
            base_pkt = parse_discovery_request(
                bytes(self.load_request_from_pcap(pcap_path))
            )
            logging.info(
                f"PCAP Discovery Request:\n{base_pkt.show(dump=True)}"
            )
        else:
            base_pkt = creator.create_discovery_request(valid=True)

        fuzzer = Payload_Fuzzer(base_pkt)

        fuzz_methods = [
            fuzzer.fuzz_capwap_header,
            fuzzer.fuzz_control_header,
            fuzzer.fuzz_any_tlv_length,
            fuzzer.fuzz_any_tlv_value,
            lambda: fuzzer.fuzz_specific_tlv(38),
            lambda: fuzzer.fuzz_specific_tlv(39),
            fuzzer.fuzz_duplicate_tlv,
            fuzzer.fuzz_drop_last_tlv,
        ]

        for _ in range(MUTATUION_COUNT):
            mutate = random.choice(fuzz_methods)
            send_pkt = mutate()

            resp = self.send_discovery_request(send_pkt)

            if self.is_discovery_response(resp):
                status['valid'] += 1
            else:
                status['timeout'] += 1

            status['total'] += 1

        return status
