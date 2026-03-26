# capwap_discovery_fuzzer.py
import random
import logging
from pathlib import Path
from datetime import datetime
import json
from scapy.all import *
from .request_creater import Payload_Creator, parse_discovery_request
from .payload_fuzzer import Payload_Fuzzer
from .response_parser import ResponseParser
from .errors import *

MUTATION_COUNT = 10

class CAPWAPDiscoveryFuzzer:
    def __init__(self, ac_ip: str | None, ac_port: int = 5246, timeout: float = 3.0,
                 seed: int | None = None, broadcast: bool = False):
        self.ac_ip = ac_ip
        self.ac_port = ac_port
        self.timeout = timeout
        self.broadcast = broadcast
        # 如果没传 seed，就用当前时间生成随机 seed
        self.seed = seed if seed is not None else random.SystemRandom().randint(0, 2**32 - 1)
        self._rng = random.Random(self.seed)

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
        logging.info(f"CAPWAP Fuzzer initialized with seed {self.seed}")

        self.response_parser = ResponseParser()
        self.payload_creator = Payload_Creator(rng=self._rng)

    def send_discovery_request(self, discovery_request):
        conf.verb = 0
        sport = self._rng.randint(20000, 60000)
        pkt = IP(dst=self.ac_ip)/UDP(sport=sport,dport=self.ac_port)/discovery_request
        resp = sr1(pkt, timeout=self.timeout)
        return pkt, resp

    def _scapy_to_json(self, pkt):
        """
        将 scapy Packet 转换为嵌套 JSON 结构
        """
        if pkt is None:
            return None
        res = {
            "layer": pkt.name,
            "fields": {k: (v.hex() if isinstance(v, bytes) else v) for k,v in pkt.fields.items()},
        }
        payload = pkt.payload
        if payload and payload.name != 'NoPayload':
            res["payload"] = self._scapy_to_json(payload)
        return res

    def classify_discovery_response(self, request_pkt, discovery_response, request_info=None):
        raw_request = bytes(request_pkt)
        raw_response = bytes(discovery_response) if discovery_response else b""

        try:
            parsed = self.response_parser.parse_response(raw_response, request_info)
            response_type = parsed.get("response_type", "error")
            error_type = parsed.get("error_type", None)
        except NoResponseError:
            parsed = {}
            response_type = "timeout"
            error_type = "NoResponseError"
        except Exception as e:
            parsed = {}
            response_type = "error"
            error_type = type(e).__name__

        try:
            request_structure = self._scapy_to_json(request_pkt)
        except Exception as e:
            request_structure = {"error": f"Failed to parse request: {e}"}

        filename = self.responses_dir / f"response_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
        with open(filename, "w") as f:
            json.dump({
                "request_bytes": raw_request.hex(),
                "request_structure": request_structure,
                "response_bytes": raw_response.hex(),
                "parsed_response": parsed,
                "response_type": response_type,
                "error_type": error_type,
                "request_info": request_info
            }, f, indent=2, default=str)

        logging.info(f"Response Classification: {response_type}, ErrorType: {error_type}")
        return response_type, error_type

    def fuzzing(self, pcap_path: str | None = None):
        status = {"valid":0,"timeout":0,"error":0,"total":0,"error_types":{}}
        if pcap_path:
            base_pkt = parse_discovery_request(bytes(self.load_request_from_pcap(pcap_path)))
        else:
            base_pkt = self.payload_creator.create_discovery_request(valid=True)

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

        for i in range(MUTATION_COUNT):
            method = self._rng.choice(fuzz_methods)
            send_pkt = method()
            send_pkt = base_pkt
            request_info = {"iteration": i+1, "method": getattr(method,"__name__",str(method))}
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