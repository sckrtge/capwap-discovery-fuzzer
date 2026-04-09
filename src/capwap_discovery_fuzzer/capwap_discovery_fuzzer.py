# capwap_discovery_fuzzer.py
import random
import logging
import socket as _socket
from pathlib import Path
from datetime import datetime
import json
from scapy.all import *
from .request_creater import Payload_Creator, parse_discovery_request
from .payload_fuzzer import Payload_Fuzzer
from .response_parser import ResponseParser
from .errors import *

MUTATION_COUNT = 1  # 每轮发送一条报文

class CAPWAPDiscoveryFuzzer:
    def __init__(self, ac_ip: str | None, ac_port: int = 5246, timeout: float = 3.0,
                 seed: int | None = None, broadcast: bool = False, iface: str = 'lo'):
        self.ac_ip = ac_ip
        self.ac_port = ac_port
        self.timeout = timeout
        self.broadcast = broadcast
        self.iface = iface
        self.seed = seed if seed is not None else random.SystemRandom().randint(0, 2**32 - 1)
        self._rng = random.Random(self.seed)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_dir = Path("./capwap_log") / timestamp
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.responses_dir = self.log_dir / "responses"
        self.responses_dir.mkdir(exist_ok=True)

        logging.info(f"CAPWAP Fuzzer initialized with seed {self.seed}, log_dir={self.log_dir}")

        self.response_parser = ResponseParser()
        self.payload_creator = Payload_Creator(rng=self._rng)

    # -------------------- 发送报文 --------------------
    def send_discovery_request(self, discovery_request):
        sport = self._rng.randint(20000, 60000)
        dst = "255.255.255.255" if self.broadcast else self.ac_ip
        payload_bytes = bytes(discovery_request)

        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        if self.broadcast:
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)
        sock.bind(('', sport))
        sock.settimeout(self.timeout)

        # 构造用于日志记录的 Scapy 包对象（不用于实际发送）
        pkt = IP(dst=dst) / UDP(sport=sport, dport=self.ac_port) / discovery_request

        try:
            sock.sendto(payload_bytes, (dst, self.ac_port))
            raw_resp, addr = sock.recvfrom(65535)
            resp = IP(raw_resp) if raw_resp[0] >> 4 == 4 else Raw(raw_resp)
        except _socket.timeout:
            resp = None
        finally:
            sock.close()

        return pkt, resp

    # -------------------- 转 JSON --------------------
    def _scapy_to_json(self, pkt):
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

    # -------------------- 响应分类 --------------------
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

    # -------------------- 存活探测 --------------------
    def is_target_alive(self, retries: int = 3, probe_timeout: float | None = None) -> bool:
        """Send a valid Discovery Request and check if the target AC responds.

        This method is designed as an extension point: subclasses targeting specific
        vendor ACs (e.g. vSmartZone) can override it to implement alternative liveness
        strategies (e.g. ICMP ping, vendor-specific keepalive, HTTP health endpoint).

        Args:
            retries: Number of probe attempts before declaring the target dead.
            probe_timeout: Per-attempt socket timeout in seconds.  Falls back to
                           ``self.timeout`` when not specified.

        Returns:
            ``True`` if at least one probe attempt receives a response, ``False``
            if all attempts time out or raise a network error.
        """
        timeout = probe_timeout if probe_timeout is not None else self.timeout
        probe_pkt = self.payload_creator.create_discovery_request(valid=True)
        dst = "255.255.255.255" if self.broadcast else self.ac_ip

        for attempt in range(1, retries + 1):
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            if self.broadcast:
                sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)
            sock.settimeout(timeout)
            sport = self._rng.randint(20000, 60000)
            sock.bind(('', sport))
            try:
                sock.sendto(bytes(probe_pkt), (dst, self.ac_port))
                raw_resp, _ = sock.recvfrom(65535)
                if raw_resp:
                    logging.debug("Probe attempt %d/%d: target responded", attempt, retries)
                    return True
            except _socket.timeout:
                logging.debug("Probe attempt %d/%d: timed out", attempt, retries)
            except OSError as e:
                logging.debug("Probe attempt %d/%d: network error: %s", attempt, retries, e)
            finally:
                sock.close()

        logging.info("All %d probe attempts failed — target may have crashed", retries)
        return False

    # -------------------- 从 PCAP 加载 --------------------
    def load_request_from_pcap(self, pcap_path: str) -> bytes:
        pkts = rdpcap(pcap_path)
        for pkt in pkts:
            if pkt.haslayer(UDP) and pkt["UDP"].dport == 5246:
                return bytes(pkt["UDP"].payload)
        raise ValueError("No CAPWAP Discovery Request found in pcap!")

    # -------------------- Fuzzing --------------------
    def fuzzing(self, pcap_path: str | None = None, max_safe_methods: int = 3, max_brutal_methods: int = 3):
        status = {"valid": 0, "timeout": 0, "error": 0, "total": 0, "error_types": {}}

        if pcap_path:
            base_pkt = parse_discovery_request(bytes(self.load_request_from_pcap(pcap_path)))
        else:
            base_pkt = self.payload_creator.create_discovery_request(valid=True)

        fuzzer = Payload_Fuzzer(base_pkt)

        def fuzz_msg_38(pkt=None): return fuzzer.fuzz_specific_msg(38, pkt)
        def fuzz_msg_39(pkt=None): return fuzzer.fuzz_specific_msg(39, pkt)

        safe_methods = [
            fuzzer.fuzz_capwap_header,
            fuzzer.fuzz_control_header,
            fuzzer.fuzz_any_msg_length,
            fuzzer.fuzz_any_msg_value,
            fuzz_msg_38,
            fuzz_msg_39,
            fuzzer.fuzz_duplicate_msg,
            fuzzer.fuzz_drop_last_msg,
            fuzzer.fuzz_shuffle_msgs,
            fuzzer.fuzz_capwap_flags,
        ]

        brutal_methods = [
            fuzzer.brutal_random_bytes,
            fuzzer.brutal_insert_random_bytes,
            fuzzer.brutal_delete_random_bytes,
            fuzzer.brutal_shuffle_bytes,
            fuzzer.brutal_duplicate_segments,
            fuzzer.brutal_reverse_segment,
        ]

        def sort_key(method):
            name = getattr(method, "__name__", str(method))
            if "capwap_header" in name or "control_header" in name:
                return 0
            elif "length" in name or "value" in name or "msg_3" in name or "capwap_flags" in name:
                return 1
            elif "duplicate_msg" in name or "drop_last_msg" in name:
                return 2
            elif "shuffle" in name:
                return 3
            else:
                return 4

        for i in range(MUTATION_COUNT):
            pkt = base_pkt.copy()
            method_chain = []

            num_safe = self._rng.randint(1, min(max_safe_methods, len(safe_methods)))
            chosen_safe = self._rng.sample(safe_methods, num_safe)
            chosen_safe.sort(key=sort_key)

            for method in chosen_safe:
                pkt = method(pkt)
                method_chain.append(getattr(method, "__name__", str(method)))

            num_brutal = self._rng.randint(0, max_brutal_methods)
            chosen_brutal = self._rng.choices(brutal_methods, k=num_brutal)
            for method in chosen_brutal:
                pkt = method(pkt)
                method_chain.append(getattr(method, "__name__", str(method)))

            request_info = {"iteration": i + 1, "method_chain": method_chain}
            logging.info("Composite Fuzz iteration %d: method chain: %s", i + 1, method_chain)

            try:
                req_pkt, resp = self.send_discovery_request(pkt)
                resp_type, error_type = self.classify_discovery_response(req_pkt, resp, request_info)
                status[resp_type] += 1
                if resp_type == "error" and error_type:
                    status["error_types"].setdefault(error_type, 0)
                    status["error_types"][error_type] += 1
                status["total"] += 1
            except Exception as e:
                logging.error(f"Composite Fuzz iteration {i + 1} failed: {e}")
                status["error"] += 1
                status["error_types"].setdefault(type(e).__name__, 0)
                status["error_types"][type(e).__name__] += 1
                status["total"] += 1

        logging.info(f"Composite Fuzzing Summary: {status}")
        return status

    # -------------------- 复现单个 JSON --------------------
    def replay_request_from_json(self, json_path: str, src_port: int | None = None):
        path = Path(json_path)
        if not path.exists():
            raise FileNotFoundError(f"JSON file not found: {json_path}")

        with open(path, "r") as f:
            data = json.load(f)

        if "request_bytes" not in data:
            raise ValueError("JSON does not contain 'request_bytes' field")

        raw_payload = bytes.fromhex(data["request_bytes"])
        sport = src_port or self._rng.randint(20000, 60000)
        pkt = IP(dst=self.ac_ip)/UDP(sport=sport, dport=self.ac_port)/Raw(load=raw_payload)

        conf.verb = 0
        resp = sr1(pkt, timeout=self.timeout, verbose=0)

        resp_type, error_type = self.classify_discovery_response(pkt, resp, request_info=data.get("request_info"))
        return pkt, resp, resp_type, error_type

    # -------------------- 批量复现 JSON 目录 --------------------
    def replay_requests_from_dir(self, json_dir: str, src_port: int | None = None):
        path = Path(json_dir)
        if not path.exists() or not path.is_dir():
            raise FileNotFoundError(f"JSON directory not found or not a directory: {json_dir}")

        results = []
        json_files = sorted(path.glob("*.json"))
        if not json_files:
            raise ValueError(f"No JSON files found in directory: {json_dir}")

        for json_file in json_files:
            try:
                pkt, resp, resp_type, error_type = self.replay_request_from_json(str(json_file), src_port=src_port)
                logging.info(f"Replayed {json_file.name}: response_type={resp_type}, error_type={error_type}")
                results.append((pkt, resp, resp_type, error_type))
            except Exception as e:
                logging.error(f"Failed to replay {json_file.name}: {e}")
        return results
