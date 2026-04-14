# capwap_discovery_fuzzer.py
import random
import logging
import socket as _socket
import time
from pathlib import Path
from datetime import datetime
import json
from scapy.all import *
from .request_creater import Payload_Creator, parse_discovery_request
from .payload_fuzzer import Payload_Fuzzer
from .response_parser import ResponseParser
from .errors import *

MUTATION_COUNT = 1  # 每轮发送报文条数

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
        self.records_path = self.log_dir / "records.jsonl"

        logging.info(f"CAPWAP Fuzzer initialized with seed {self.seed}, log_dir={self.log_dir}")

        self.response_parser = ResponseParser()
        self.payload_creator = Payload_Creator(rng=self._rng)

    # -------------------- 会话元数据 --------------------
    def write_session_json(self, extra: dict | None = None):
        """写 session.json，记录本次会话的基础参数。extra 可传入 CLI 层的附加信息（vendor、rounds 等）。"""
        session = {
            "session_id": self.log_dir.name,
            "seed": self.seed,
            "target_ip": self.ac_ip,
            "target_port": self.ac_port,
            "broadcast": self.broadcast,
            "iface": self.iface,
            "started_at": datetime.now().isoformat(),
        }
        if extra:
            session.update(extra)
        with open(self.log_dir / "session.json", "w") as f:
            json.dump(session, f, indent=2)

    # -------------------- 发送报文 --------------------
    def send_discovery_request(self, discovery_request):
        """发送 CAPWAP Discovery Request，返回 (capwap_bytes, raw_response_or_None)。
        capwap_bytes 是实际发出的 UDP payload（无 IP/UDP 头），供日志和重放直接使用。
        raw_response 是 recvfrom 返回的完整字节（含 IP/UDP 头），供 ResponseParser 解析。
        """
        sport = self._rng.randint(20000, 60000)
        dst = "255.255.255.255" if self.broadcast else self.ac_ip
        payload_bytes = bytes(discovery_request)

        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        if self.broadcast:
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)
        sock.bind(('', sport))
        sock.settimeout(self.timeout)

        try:
            sock.sendto(payload_bytes, (dst, self.ac_port))
            raw_resp, _ = sock.recvfrom(65535)
        except _socket.timeout:
            raw_resp = None
        finally:
            sock.close()

        return payload_bytes, raw_resp

    # -------------------- 响应分类 + 写 JSONL --------------------
    def classify_discovery_response(self, capwap_bytes: bytes, raw_response: bytes | None,
                                     request_info: dict | None = None, elapsed_ms: int | None = None):
        """分类响应并追加一条记录到 records.jsonl。
        capwap_bytes: 发出的 CAPWAP payload（无 IP/UDP 头）。
        raw_response: recvfrom 返回的原始字节（含 IP/UDP 头），None 表示超时。
        """
        try:
            parsed = self.response_parser.parse_response(raw_response or b"", request_info)
            response_type = parsed.get("response_type", "error")
            error_type = parsed.get("error_type", None)
        except NoResponseError:
            response_type = "timeout"
            error_type = "NoResponseError"
        except Exception as e:
            response_type = "error"
            error_type = type(e).__name__

        record = {
            "round": request_info.get("iteration") if request_info else None,
            "timestamp": datetime.now().isoformat(),
            "method_chain": request_info.get("method_chain", []) if request_info else [],
            "response_type": response_type,
            "error_type": error_type,
            "request_hex": capwap_bytes.hex(),
            "response_hex": raw_response.hex() if raw_response else "",
            "elapsed_ms": elapsed_ms,
        }
        with open(self.records_path, "a") as f:
            f.write(json.dumps(record) + "\n")

        logging.info(f"Response Classification: {response_type}, ErrorType: {error_type}")
        return response_type, error_type

    # -------------------- 存活探测 --------------------
    def is_target_alive(self, retries: int = 3, probe_timeout: float | None = None, pcap_path: str | None = None) -> bool:
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
        if pcap_path:
            probe_pkt = self.load_request_from_pcap(pcap_path)
        else:
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
            base_pkt = self.load_request_from_pcap(pcap_path)
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
                t0 = time.monotonic()
                capwap_bytes, raw_resp = self.send_discovery_request(pkt)
                elapsed_ms = int((time.monotonic() - t0) * 1000)
                resp_type, error_type = self.classify_discovery_response(
                    capwap_bytes, raw_resp, request_info, elapsed_ms=elapsed_ms
                )
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

    # -------------------- 复现单条记录 --------------------
    def replay_request_from_record(self, record: dict, src_port: int | None = None):
        """从 records.jsonl 的一条记录重放请求，使用原生 socket（与 fuzzing 路径一致）。"""
        raw_payload = bytes.fromhex(record["request_hex"])
        sport = src_port or self._rng.randint(20000, 60000)
        dst = "255.255.255.255" if self.broadcast else self.ac_ip

        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        if self.broadcast:
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)
        sock.bind(('', sport))
        sock.settimeout(self.timeout)

        t0 = time.monotonic()
        try:
            sock.sendto(raw_payload, (dst, self.ac_port))
            raw_resp, _ = sock.recvfrom(65535)
        except _socket.timeout:
            raw_resp = None
        finally:
            sock.close()
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        request_info = {
            "iteration": record.get("round"),
            "method_chain": record.get("method_chain", []),
        }
        resp_type, error_type = self.classify_discovery_response(
            raw_payload, raw_resp, request_info, elapsed_ms=elapsed_ms
        )
        return resp_type, error_type

    # -------------------- 批量复现 JSONL --------------------
    def replay_requests_from_jsonl(self, jsonl_path: str, filter_fn=None, src_port: int | None = None):
        """从 records.jsonl 批量重放。filter_fn(record) -> bool 可按任意字段过滤。
        例：只重放 error 记录：filter_fn=lambda r: r["response_type"] == "error"
        """
        path = Path(jsonl_path)
        if not path.exists():
            raise FileNotFoundError(f"JSONL file not found: {jsonl_path}")

        results = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if filter_fn and not filter_fn(record):
                    continue
                try:
                    resp_type, error_type = self.replay_request_from_record(record, src_port=src_port)
                    logging.info(
                        "Replayed round %s: response_type=%s, error_type=%s",
                        record.get("round"), resp_type, error_type
                    )
                    results.append((record, resp_type, error_type))
                except Exception as e:
                    logging.error("Failed to replay round %s: %s", record.get("round"), e)
        return results

    # -------------------- 写汇总 --------------------
    def write_summary(self, total_status: dict):
        """读取 records.jsonl，计算方法有效性和响应时间统计，写入 summary.json。"""
        method_stats: dict[str, dict] = {}
        elapsed_list: list[int] = []

        try:
            with open(self.records_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    r = json.loads(line)
                    if r.get("elapsed_ms") is not None:
                        elapsed_list.append(r["elapsed_ms"])
                    rt = r.get("response_type", "error")
                    for method in r.get("method_chain", []):
                        ms = method_stats.setdefault(method, {"uses": 0, "valid": 0, "timeout": 0, "error": 0})
                        ms["uses"] += 1
                        ms[rt] = ms.get(rt, 0) + 1
        except FileNotFoundError:
            pass

        summary = dict(total_status)
        summary["method_effectiveness"] = method_stats
        if elapsed_list:
            sorted_e = sorted(elapsed_list)
            p95_idx = int(len(sorted_e) * 0.95)
            summary["response_time_stats"] = {
                "mean_ms": int(sum(elapsed_list) / len(elapsed_list)),
                "min_ms": sorted_e[0],
                "max_ms": sorted_e[-1],
                "p95_ms": sorted_e[min(p95_idx, len(sorted_e) - 1)],
            }

        with open(self.log_dir / "summary.json", "w") as f:
            json.dump(summary, f, indent=2)
        logging.info("Summary written to %s", self.log_dir / "summary.json")
