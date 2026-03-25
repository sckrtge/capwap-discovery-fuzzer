import logging
from pathlib import Path
import random
import time
from datetime import datetime
from scapy.all import *
from .request_creater import Payload_Creator, parse_discovery_request
from .payload_fuzzer import Payload_Fuzzer
from .response_parser import ResponseParser
from .errors import *
import json

MUTATUION_COUNT = 10

class CAPWAPDiscoveryFuzzer:
    def __init__(self, ac_ip: str | None, ac_port: int = 5246, timeout: float = 3.0,
                 seed: int | None = None, broadcast: bool = False):
        self.ac_ip = ac_ip
        self.ac_port = ac_port
        self.timeout = timeout
        self.broadcast = broadcast
        self.sequence = 0
        self._rng = random.Random()
        if seed: self._rng.seed(seed)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_dir = Path("./capwap_log") / timestamp
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.responses_dir = self.log_dir / "responses"
        self.responses_dir.mkdir(exist_ok=True)
        self.log_file = self.log_dir / "fuzzer.log"
        logging.basicConfig(
            filename=str(self.log_file),
            filemode="w",
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
        )
        logging.info("CAPWAP Fuzzer initialized")
        logging.info(f"Broadcast mode: {self.broadcast}, AC IP: {self.ac_ip}, AC port: {self.ac_port}")

        self.response_parser = ResponseParser(log_dir=self.responses_dir)

    def send_discovery_request(self, discovery_request):
        conf.verb = 0
        sport = random.randint(20000, 60000)
        pkt = IP(dst=self.ac_ip)/UDP(sport=sport,dport=self.ac_port)/discovery_request
        logging.info(f"Sending Discovery Request:\n{pkt.show(dump=True)}")
        resp = sr1(pkt, timeout=self.timeout)
        return pkt, resp

    def classify_discovery_response(self, request_pkt, discovery_response, request_info=None):
        raw_request = bytes(request_pkt)
        raw_response = bytes(discovery_response) if discovery_response else b""
        try:
            result = self.response_parser.parse_response(raw_response, request_info)
            response_type = result["response_type"]
            error_type = result.get("error_type", None)
        except NoResponseError:
            response_type = "timeout"
            error_type = "NoResponseError"
        except CAPWAPFuzzerError as e:
            response_type = "error"
            error_type = type(e).__name__
        except Exception:
            response_type = "error"
            error_type = "UnknownError"

        filename = self.responses_dir / f"response_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
        with open(filename, "w") as f:
            json.dump({
                "request_bytes": raw_request.hex(),
                "response_bytes": raw_response.hex(),
                "response_type": response_type,
                "error_type": error_type,
                "request_info": request_info
            }, f, indent=2)

        logging.info(f"Response Classification: {response_type}, ErrorType: {error_type}")
        return response_type, error_type

    def _extract_capwap_payload(self, pkt):
        try:
            if pkt.haslayer(UDP) and pkt[UDP].payload:
                return bytes(pkt[UDP].payload)
        except Exception as e:
            logging.warning(f"Failed to extract CAPWAP payload: {e}")
        return None

    def fuzzing(self, pcap_path: str | None = None):
        status = {"valid":0,"timeout":0,"error":0,"total":0,"error_types":{}}
        creator = Payload_Creator()
        if pcap_path:
            base_pkt = parse_discovery_request(bytes(self.load_request_from_pcap(pcap_path)))
        else:
            base_pkt = creator.create_discovery_request(valid=True)

        fuzzer = Payload_Fuzzer(base_pkt)
        fuzz_methods = [
            fuzzer.fuzz_capwap_header,
            fuzzer.fuzz_control_header,
            fuzzer.fuzz_any_msg_length,
            fuzzer.fuzz_any_msg_value,
            lambda: fuzzer.fuzz_specific_msg(38),
            lambda: fuzzer.fuzz_specific_msg(39),
            fuzzer.fuzz_duplicate_msg,
            fuzzer.fuzz_drop_last_msg,
            fuzzer.fuzz_shuffle_msgs
        ]

        for i in range(MUTATUION_COUNT):
            method = random.choice(fuzz_methods)
            send_pkt = method()
            request_info = {"iteration": i+1,"method": getattr(method,"__name__",str(method))}
            try:
                req_pkt, resp = self.send_discovery_request(send_pkt)
                resp_type, error_type = self.classify_discovery_response(req_pkt, resp, request_info)
                status[resp_type] += 1
                if resp_type=="error" and error_type:
                    status["error_types"].setdefault(error_type,0)
                    status["error_types"][error_type]+=1
                status["total"]+=1
            except Exception as e:
                logging.error(f"Fuzz iteration {i+1} failed: {e}")
                status["error"]+=1
                status["error_types"].setdefault(type(e).__name__,0)
                status["error_types"][type(e).__name__]+=1
                status["total"]+=1

        logging.info(f"Fuzzing Summary: {status}")
        return status

    def load_request_from_pcap(self, pcap_path: str) -> bytes:
        pkts = rdpcap(pcap_path)
        for pkt in pkts:
            if pkt.haslayer(UDP) and pkt["UDP"].dport == 5246:
                return bytes(pkt["UDP"].payload)
        raise ValueError("No CAPWAP Discovery Request found in pcap!")