"""Main module."""
import socket
from scapy.all import rdpcap
import capwap_discovery_fuzzer.errors as errors
from capwap_discovery_fuzzer.utils import hexdump
import random
import time
import json
from pathlib import Path

REQUESTS_PER_SECOND = 0

class CAPWAPDiscoveryFuzzer:
    def __init__(self, ac_ip: str, ac_port: int = 5246, timeout: float = 3.0, seed: int | None = None):
        self.ac_ip = ac_ip
        self.ac_port = ac_port
        self.timeout = timeout

        self.sock = None
        self.sequence = 0
        self._rng = random.Random()
        self.seed = seed

        if seed is not None:
            self._rng.seed(seed)

    def _open_socket(self):
        if self.sock is not None:
            return

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", 0))
        self.sock.settimeout(self.timeout)

    def _close_socket(self):
        if self.sock is None:
            return
        try:
            self.sock.close()
        finally:
            self.sock = None

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

            payload = bytes(udp.payload)
            # check payload
            return payload

        raise ValueError("No CAPWAP Discovery Request found in pcap")

    def is_discovery_response(self, data: bytes) -> bool:
        """
        only determine whether any response is received.
        """
        if data is None:
            return False
        if not isinstance(data, (bytes, bytearray)):
            return False
        if len(data) == 0:
            return False
        return True

    def send_discovery_request(self, payload: bytes) -> bytes | None:
        """
        Send a CAPWAP Discovery Request and wait for a response.
        """
        if self.sock is None:
            self._open_socket()

        try:
            self.sock.sendto(payload, (self.ac_ip, self.ac_port))
            resp, addr = self.sock.recvfrom(4096)
            return resp
        except socket.timeout:
            return None
        finally:
            self._close_socket()
            if REQUESTS_PER_SECOND > 0:
                time.sleep(1 / REQUESTS_PER_SECOND)



    def split_capwap_control_message(
        self, payload: bytes
    ) -> tuple[bytes, bytes, list[tuple[int, int, bytes]]]:
        """
        Split CAPWAP Control Message into:
        - CAPWAP transport header (bytes)
        - CAPWAP control header (bytes)
        - Message elements: list of (type, length, value_bytes)

        No semantic validation is performed.
        """
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes!")

        if len(payload) < 8:
            raise ValueError("payload to short for CAPWAP Header")

        # Byte 1: | HLEN (5) | RID (3) |
        hlen = (payload[1] >> 3) & 0x1f
        capwap_header_len = hlen * 4

        if len(payload) < capwap_header_len:
            raise ValueError("invalid hlen for CAPWAP Header")

        capwap_header, payload = payload[:capwap_header_len], payload[capwap_header_len:]

        control_header_len = 8

        if len(payload) < control_header_len:
            raise ValueError("payload to short for Control Header")

        control_header, payload = payload[:control_header_len], payload[control_header_len:]

        message_elements = []
        i = 0

        while i + 4 <= len(payload):
            element_type = int.from_bytes(payload[i:i+2], byteorder='big')
            element_length = int.from_bytes(payload[i+2:i+4], byteorder='big')
            i += 4

            if i + element_length > len(payload):
                raise ValueError(f'Message Element length {element_length} exceeds remaining payload size {len(payload)}')

            element_value = payload[i:i+element_length]
            message_elements.append((element_type, element_length, element_value))
            i += element_length
        return capwap_header, control_header, message_elements

    def fuzz_message_element(
        self,
        element: tuple[int, int, bytes],
    ) -> list[tuple[int, int, bytes]] :
        """
        Generate fuzzed variants of a single message element.
        Returns a list of mutated elements.
        """

        element_type, element_length, element_value = element
        fuzz = []

        # fuzz.append((element_type, element_length, element_value))

        # # length mutation
        # fuzz.append((element_type, min(1 << 16, element_length + 1), element_value))
        # fuzz.append((element_type, max(element_length - 1, 0), element_value))

        # random_length = self._rngrandrange(0, 1 << 16)
        # fuzz.append((element_type, random_length, element_value))

        random_value = self._rng.getrandbits(element_length * 8).to_bytes(element_length, byteorder='big')
        fuzz.append((element_type, element_length, random_value))

        return fuzz

    def _build_message_elements(
            self,
            elements: list[tuple[int, int, bytes]]
    ) -> bytes:
        """
        Build message_elements from list[(type, lenght, value)]
        """
        buf = bytearray()

        for elements_type, elements_length, elements_value in elements:
            buf += elements_type.to_bytes(length=2, byteorder='big')
            buf += elements_length.to_bytes(length=2, byteorder='big')
            buf += elements_value

        return bytes(buf)

    def rebuild_capwap_control_message(
            self,
            capwap_header: bytes,
            control_header: bytes,
            message_elements: list[tuple[int, int, bytes]]
    ) -> bytes:
        """
        rebuild capwap control message with [capwap_header, control_header, message_elements]
        """
        bytes_elements = self._build_message_elements(message_elements)
        return capwap_header + control_header + bytes_elements
    

    def save_discovery_response(self, payload: bytes, resp: bytes | None, result: str, element_type: int) -> None:
        path = Path("discovery_messages.json")

        if path.exists():
            with open(path) as f:
                cases = json.load(f)
        else:
            cases = []

        cases.append({
            "timestamp": time.time_ns(),
            "seed": self.seed,
            "result": result,
            "element_type": element_type,
            "request_hex": payload.hex(),
            "response_hex": resp.hex() if resp else None
        })

        with open(path, "w") as f:
            json.dump(cases, f, indent=2)


    def simple_fuzzing_with_pcap(
        self,
        pcap_path: str,
    ) -> dict[str, int]:
        """
        run a simple fuzzing with pcap
        """
        status = {
            'timeout': 0,
            'invalid': 0,
            'valid': 0,
            'total': 0
        }
        payload = self.load_request_from_pcap(pcap_path)
        capwap_header, control_header, message_elements = self.split_capwap_control_message(payload)
        for i, element in enumerate(message_elements):
            fuzzed_now_elements = self.fuzz_message_element(element)
            for fuzzed_now_element in fuzzed_now_elements:
                new_elements = message_elements.copy()
                new_elements[i] = fuzzed_now_element
                new_payload = self.rebuild_capwap_control_message(capwap_header, control_header, new_elements)
                resp = self.send_discovery_request(new_payload)
                result = ''
                if resp is None:
                    result = 'timeout'
                elif self.is_discovery_response(resp):
                    result = 'valid'
                else:
                    result = 'invalid'
                self.save_discovery_response(payload=new_payload, resp=resp, result=result, element_type=fuzzed_now_element[0])
                status[result] += 1
                status['total'] += 1
        return status

