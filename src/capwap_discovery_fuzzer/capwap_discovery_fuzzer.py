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

    # -------------------- 进程存活（供子类覆盖） --------------------
    def is_process_alive(self) -> bool | None:
        """Return True/False if process liveness can be determined, None if unknown (black-box).

        Base implementation always returns None — no process to inspect in black-box mode.
        Subclasses with process access (e.g. OpenCAPWAPFuzzer) override this to return
        a definitive True/False via kill -0.

        基类始终返回 None（黑盒模式，无法检查进程）。
        具有进程访问权限的子类（如 OpenCAPWAPFuzzer）覆盖此方法，通过 kill -0 返回确定值。
        """
        return None

    # -------------------- Fuzzing --------------------
    def fuzzing(self, pcap_path: str | None = None, max_safe_methods: int = 3,
                max_brutal_methods: int = 3, round_number: int | None = None):
        status = {"valid": 0, "timeout": 0, "error": 0, "total": 0, "error_types": {}}

        if pcap_path:
            base_pkt = self.load_request_from_pcap(pcap_path)
        else:
            base_pkt = self.payload_creator.create_discovery_request(valid=True)

        fuzzer = Payload_Fuzzer(base_pkt)

        def fuzz_elem_value_type38(pkt=None): return fuzzer.fuzz_elem_value_by_type(38, pkt)
        def fuzz_elem_value_type39(pkt=None): return fuzzer.fuzz_elem_value_by_type(39, pkt)

        safe_methods = [
            # CAPWAP Header mutations / CAPWAP 头部变异
            fuzzer.fuzz_capwap_header,
            fuzzer.fuzz_capwap_wbid,
            fuzzer.fuzz_capwap_flags,
            fuzzer.fuzz_capwap_fragment,
            # Control Header mutations / Control 头部变异
            fuzzer.fuzz_ctrl_msgtype,
            fuzzer.fuzz_ctrl_seqnum,
            fuzzer.fuzz_ctrl_msgelemslen,
            fuzzer.fuzz_ctrl_flags,
            # MessageElement field mutations / 消息元素字段变异
            fuzzer.fuzz_elem_type,
            fuzzer.fuzz_elem_length,
            fuzzer.fuzz_elem_length_zero,
            fuzzer.fuzz_elem_length_overflow,
            fuzzer.fuzz_elem_value,
            fuzz_elem_value_type38,
            fuzz_elem_value_type39,
            # MessageElement structural mutations / 消息元素结构变异
            fuzzer.fuzz_elem_insert_unknown,
            fuzzer.fuzz_elem_drop,
            fuzzer.fuzz_elem_drop_required,
            fuzzer.fuzz_elem_duplicate,
            fuzzer.fuzz_elem_order_shuffle,
        ]

        brutal_methods = [
            fuzzer.brutal_random_bytes,
            fuzzer.brutal_insert_random_bytes,
            fuzzer.brutal_delete_random_bytes,
            fuzzer.brutal_shuffle_bytes,
            fuzzer.brutal_duplicate_segment,
            fuzzer.brutal_reverse_segment,
            fuzzer.brutal_bitflip,
            fuzzer.brutal_zero_segment,
            fuzzer.brutal_fill_segment,
            fuzzer.brutal_truncate,
        ]

        # brutal_shuffle_bytes destroys all structure; any brutal method after it
        # is redundant.  Keep it in the pool but enforce it as the terminal step.
        # brutal_shuffle_bytes 彻底破坏结构，其后的任何 brutal 方法均无额外价值，
        # 保留在池中但强制作为 brutal 链的最后一步。
        TERMINAL_BRUTAL = {fuzzer.brutal_shuffle_bytes}

        def sort_key(method):
            # Enforce safe-method execution order:
            #   1. CAPWAP Header fields  (must come first — Hlen affects parsing of everything below)
            #   2. Control Header fields (depend on correct CAPWAP Header)
            #   3. Element field mutations (Type / Length / Value — operate on existing elements)
            #   4. Element structural mutations (insert / drop / duplicate / shuffle order)
            #      insert_unknown must precede order_shuffle so the new element participates in shuffle
            #
            # 强制 safe 方法执行顺序：
            #   1. CAPWAP 头字段（最先 — Hlen 影响后续所有层的解析）
            #   2. Control 头字段（依赖正确的 CAPWAP Header）
            #   3. 元素字段变异（Type / Length / Value — 对现有元素操作）
            #   4. 元素结构变异（insert / drop / duplicate / shuffle — insert 必须先于 shuffle）
            name = getattr(method, "__name__", str(method))
            if "capwap_" in name:
                return 0
            elif "ctrl_" in name:
                return 1
            elif "elem_length" in name or "elem_value" in name or "elem_type" in name:
                return 2
            elif "elem_insert" in name:
                return 3
            elif "elem_drop" in name or "elem_duplicate" in name or "elem_order" in name:
                return 4
            else:
                return 5

        for i in range(MUTATION_COUNT):
            pkt = base_pkt.copy()
            method_chain = []

            # Allow repeated selection so methods like fuzz_elem_value can mutate
            # multiple different elements in a single round.
            # 允许重复选取，使 fuzz_elem_value 等方法能在同一轮内变异多个不同元素。
            num_safe = self._rng.randint(1, max_safe_methods)
            chosen_safe = self._rng.choices(safe_methods, k=num_safe)
            chosen_safe.sort(key=sort_key)

            for method in chosen_safe:
                pkt = method(pkt)
                method_chain.append(getattr(method, "__name__", str(method)))

            # brutal_shuffle_bytes is terminal: if selected, move it to the end and
            # drop any brutal methods that were chosen after it (they'd be no-ops).
            # brutal_shuffle_bytes 是终结步：若被选中，移至末尾并丢弃其后的方法。
            num_brutal = self._rng.randint(1 if self._rng.random() < 0.75 else 0, max_brutal_methods)
            chosen_brutal = self._rng.choices(brutal_methods, k=num_brutal)
            if any(m in TERMINAL_BRUTAL for m in chosen_brutal):
                chosen_brutal = [m for m in chosen_brutal if m not in TERMINAL_BRUTAL]
                chosen_brutal.append(fuzzer.brutal_shuffle_bytes)

            for method in chosen_brutal:
                pkt = method(pkt)
                method_chain.append(getattr(method, "__name__", str(method)))

            iteration = round_number if round_number is not None else (i + 1)
            request_info = {"iteration": iteration, "method_chain": method_chain}
            logging.info("Composite Fuzz iteration %d: method chain: %s", iteration, method_chain)

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

    # -------------------- 写崩溃前驱序列 --------------------
    def write_crash_sequence(self, last_n: int = 50):
        """Extract the last *last_n* records from records.jsonl and write them
        to crash_sequence.jsonl in the same log directory.

        Called automatically when a crash is confirmed, so the triggering
        sequence is preserved separately for easy replay and thesis analysis.

        从 records.jsonl 提取最后 last_n 条记录，写入 crash_sequence.jsonl。
        在确认 Crash 时自动调用，便于单独重放和论文中展示触发序列。
        """
        src = self.records_path
        dst = self.log_dir / "crash_sequence.jsonl"
        if not src.exists():
            logging.warning("write_crash_sequence: records.jsonl not found, skipping")
            return

        lines = []
        try:
            with open(src) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        lines.append(line)
        except OSError as e:
            logging.warning("write_crash_sequence: failed to read records: %s", e)
            return

        tail = lines[-last_n:]
        with open(dst, "w") as f:
            for line in tail:
                f.write(line + "\n")
        logging.info(
            "crash_sequence.jsonl written: %d records (last %d of %d total)",
            len(tail), last_n, len(lines)
        )

    # -------------------- 写汇总 --------------------
    def write_summary(self, total_status: dict, crash_at_round: int | None = None):
        """读取 records.jsonl，计算方法有效性和响应时间统计，写入 summary.json。

        crash_at_round: 若发生了 Crash，传入崩溃轮次，用于统计 top_crash_methods
                        和 response_time_trend。
        """
        method_stats: dict[str, dict] = {}
        elapsed_list: list[int] = []
        all_records: list[dict] = []

        try:
            with open(self.records_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    r = json.loads(line)
                    all_records.append(r)
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

        # Response time stats
        if elapsed_list:
            sorted_e = sorted(elapsed_list)
            p95_idx = int(len(sorted_e) * 0.95)
            summary["response_time_stats"] = {
                "mean_ms": int(sum(elapsed_list) / len(elapsed_list)),
                "min_ms": sorted_e[0],
                "max_ms": sorted_e[-1],
                "p95_ms": sorted_e[min(p95_idx, len(sorted_e) - 1)],
            }

        # Crash-specific enhancements
        crash_seq_path = self.log_dir / "crash_sequence.jsonl"
        crash_detected = crash_at_round is not None or crash_seq_path.exists()
        summary["crash_detected"] = crash_detected
        if crash_at_round is not None:
            summary["crash_at_round"] = crash_at_round

        if crash_detected and crash_seq_path.exists():
            # top_crash_methods: most frequent methods in the crash-preceding sequence
            # 崩溃前驱序列中出现频次最高的变异方法
            method_counts: dict[str, int] = {}
            try:
                with open(crash_seq_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        r = json.loads(line)
                        for m in r.get("method_chain", []):
                            method_counts[m] = method_counts.get(m, 0) + 1
            except OSError:
                pass
            top = sorted(method_counts.items(), key=lambda x: x[1], reverse=True)
            summary["top_crash_methods"] = [m for m, _ in top[:5]]

        # Response time trend: compare first 50 vs last 50 rounds
        # 响应时间趋势：对比前 50 轮与后 50 轮的平均响应时间
        if len(all_records) >= 10:
            def _mean_elapsed(records):
                vals = [r["elapsed_ms"] for r in records if r.get("elapsed_ms") is not None]
                return int(sum(vals) / len(vals)) if vals else None

            head50 = all_records[:50]
            tail50 = all_records[-50:]
            head_mean = _mean_elapsed(head50)
            tail_mean = _mean_elapsed(tail50)
            if head_mean is not None and tail_mean is not None:
                summary["response_time_trend"] = {
                    "first_50_rounds_mean_ms": head_mean,
                    "last_50_rounds_mean_ms": tail_mean,
                    "degradation_ratio": round(tail_mean / head_mean, 2) if head_mean > 0 else None,
                }

        with open(self.log_dir / "summary.json", "w") as f:
            json.dump(summary, f, indent=2)
        logging.info("Summary written to %s", self.log_dir / "summary.json")

    # -------------------- 疑似事件记录 --------------------
    def write_suspected_event(self, round_number: int, total_status: dict):
        """Write suspected_event.json on the first probe failure.

        Called only once per session (enforced by the caller).  Records the
        round number and timestamp of the first failure with type='unknown'
        — it is unknown at this point whether the cause is a crash or DoS.

        首次探测失败时写入 suspected_event.json（由调用方保证只调用一次）。
        此时尚无法区分崩溃还是 DoS，type 置为 'unknown'。
        """
        event = {
            "type": "unknown",
            "first_fail_round": round_number,
            "timestamp": datetime.now().isoformat(),
            "probe_attempts": 3,
            "ac_ip": self.ac_ip,
            "ac_port": self.ac_port,
            "total_status_at_fail": dict(total_status),
        }
        path = self.log_dir / "suspected_event.json"
        with open(path, "w") as f:
            json.dump(event, f, indent=2)
        logging.warning("suspected_event.json written at round %d", round_number)

    def update_suspected_event_recovered(self, round_number: int):
        """Update suspected_event.json when the target recovers after a failure.

        Reads the existing file and appends recovery information, changing
        type to 'dos_suspected'.  If the file does not exist (e.g. probe_fail
        mode was 'stop'), this is a no-op.

        目标在失败后恢复响应时更新 suspected_event.json，追加恢复信息并将
        type 改为 'dos_suspected'。若文件不存在则静默忽略。
        """
        path = self.log_dir / "suspected_event.json"
        if not path.exists():
            return
        with open(path) as f:
            event = json.load(f)
        event["type"] = "dos_suspected"
        event["recovered_at_round"] = round_number
        event["recovery_timestamp"] = datetime.now().isoformat()
        with open(path, "w") as f:
            json.dump(event, f, indent=2)
        logging.info("suspected_event.json updated: target recovered at round %d (dos_suspected)", round_number)
