"""OpenCAPWAPFuzzer — gray-box fuzzer variant for the OpenCAPWAP AC process.

Gray-box capabilities (only available when the AC process is found locally):
  1. Process-level liveness check via kill -0 <pid>, with UDP probe as fallback.
     Distinguishes three states:
       - process gone              → confirmed Crash
       - process alive, no UDP reply → suspected deadlock / DoS
       - process alive + UDP reply   → healthy
  2. Process health monitor sidecar thread: samples /proc/<pid>/status and
     /proc/<pid>/stat every second, writes process_monitor.csv to the log dir.

Graceful degradation:
  If the AC process cannot be found via pgrep (e.g. not yet started, or running
  on a remote host), a warning is logged and the fuzzer falls back to pure UDP
  liveness checks — identical to the base CAPWAPDiscoveryFuzzer behaviour.

OpenCAPWAPFuzzer 是针对 OpenCAPWAP AC 进程的灰盒变体。

灰盒能力（仅在本地找到 AC 进程时启用）：
  1. 通过 kill -0 <pid> 进行进程级存活检测，UDP 探测作为补充。
     可区分三种状态：
       - 进程消失              → 确认 Crash
       - 进程存在 + 无 UDP 回包  → 疑似死锁 / DoS
       - 进程存在 + 有 UDP 回包  → 正常
  2. 进程健康监控侧车线程：每秒采样 /proc/<pid>/status 和 /proc/<pid>/stat，
     将结果写入 log 目录的 process_monitor.csv。

降级策略：
  若通过 pgrep 找不到 AC 进程（如尚未启动或运行在远程主机），
  记录警告并降级为纯 UDP 存活检测，行为与基类完全一致。
"""

import csv
import logging
import os
import signal
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

from capwap_discovery_fuzzer.capwap_discovery_fuzzer import CAPWAPDiscoveryFuzzer


# ---------------------------------------------------------------------------
# Process introspection helpers
# ---------------------------------------------------------------------------

def _find_ac_pid(proc_name: str = "AC") -> int | None:
    """Return the PID of the first process matching *proc_name*, or None.

    Uses pgrep for exact-name matching.  If multiple matches are found,
    the first (lowest) PID is returned and a warning is logged.

    使用 pgrep 精确匹配进程名，返回第一个匹配的 PID，找不到返回 None。
    存在多个匹配时取最小 PID 并记录警告。
    """
    try:
        result = subprocess.run(
            ["pgrep", "-x", proc_name],
            capture_output=True, text=True
        )
        pids = [int(p) for p in result.stdout.strip().splitlines() if p.strip()]
        if not pids:
            return None
        if len(pids) > 1:
            logging.warning(
                "pgrep found %d processes named '%s' (PIDs: %s); using PID %d",
                len(pids), proc_name, pids, pids[0]
            )
        return pids[0]
    except Exception as e:
        logging.warning("pgrep failed: %s", e)
        return None


def _pid_alive(pid: int) -> bool:
    """Return True if *pid* exists and is accessible via kill -0.

    通过 kill -0 检查进程是否存在（不发送实际信号）。
    """
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but we lack permission — still alive.
        # 进程存在但权限不足，仍视为存活。
        return True


def _read_vmrss_kb(pid: int) -> int | None:
    """Read VmRSS (resident set size) from /proc/<pid>/status in kB.

    从 /proc/<pid>/status 读取 VmRSS（物理内存占用），单位 kB。
    """
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return None


def _read_vmvirt_kb(pid: int) -> int | None:
    """Read VmSize (virtual memory size) from /proc/<pid>/status in kB.

    从 /proc/<pid>/status 读取 VmSize（虚拟内存占用），单位 kB。
    """
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmSize:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return None


def _read_cpu_times(pid: int) -> tuple[int, int] | None:
    """Read (utime, stime) from /proc/<pid>/stat.

    Returns the sum of user-mode and kernel-mode CPU ticks, or None on error.
    从 /proc/<pid>/stat 读取 (utime, stime)，返回用户态+内核态 CPU 滴答数之和。
    """
    try:
        with open(f"/proc/{pid}/stat") as f:
            fields = f.read().split()
        # utime=field[13], stime=field[14] (0-indexed)
        return int(fields[13]), int(fields[14])
    except (OSError, IndexError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Process monitor sidecar
# ---------------------------------------------------------------------------

class _ProcessMonitor:
    """Background thread that samples process health once per second.

    Writes one CSV row per sample to *csv_path*.  The current fuzzing round
    is read from *round_ref* (a list of length 1 used as a mutable integer).

    后台线程，每秒采样一次进程健康指标，写入 CSV 文件。
    当前轮次从 round_ref[0] 读取（用长度为 1 的 list 作为可变整数）。
    """

    CSV_HEADER = ["timestamp", "round", "pid_alive",
                  "vmrss_kb", "vmvirt_kb", "cpu_percent"]

    def __init__(self, pid: int, csv_path: Path, round_ref: list[int]):
        self._pid = pid
        self._csv_path = csv_path
        self._round_ref = round_ref
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="proc-monitor"
        )

    def start(self):
        """Start the monitor thread and write the CSV header.
        启动监控线程并写入 CSV 表头。
        """
        with open(self._csv_path, "w", newline="") as f:
            csv.writer(f).writerow(self.CSV_HEADER)
        self._thread.start()
        logging.info("Process monitor started for PID %d → %s", self._pid, self._csv_path)

    def stop(self):
        """Signal the monitor thread to stop and wait for it to finish.
        通知监控线程停止并等待其退出。
        """
        self._stop_event.set()
        self._thread.join(timeout=3)
        logging.info("Process monitor stopped")

    def _run(self):
        """Main sampling loop — runs in the background thread.
        采样主循环，在后台线程中运行。
        """
        prev_cpu: tuple[int, int] | None = None
        prev_time: float = time.monotonic()
        hz = os.sysconf("SC_CLK_TCK")  # CPU clock ticks per second

        while not self._stop_event.is_set():
            now = time.monotonic()
            ts = datetime.now().isoformat(timespec="seconds")
            current_round = self._round_ref[0]
            alive = _pid_alive(self._pid)

            vmrss = _read_vmrss_kb(self._pid) if alive else None
            vmvirt = _read_vmvirt_kb(self._pid) if alive else None

            # CPU % = Δticks / (Δwall_seconds × hz) × 100
            cpu_pct: float | None = None
            if alive:
                curr_cpu = _read_cpu_times(self._pid)
                if curr_cpu and prev_cpu:
                    delta_ticks = (curr_cpu[0] + curr_cpu[1]) - (prev_cpu[0] + prev_cpu[1])
                    delta_wall = now - prev_time
                    if delta_wall > 0:
                        cpu_pct = round(delta_ticks / (delta_wall * hz) * 100, 2)
                prev_cpu = curr_cpu
            else:
                prev_cpu = None

            prev_time = now

            row = [ts, current_round, alive, vmrss, vmvirt, cpu_pct]
            try:
                with open(self._csv_path, "a", newline="") as f:
                    csv.writer(f).writerow(row)
            except OSError as e:
                logging.warning("process_monitor write failed: %s", e)

            self._stop_event.wait(timeout=1.0)


# ---------------------------------------------------------------------------
# OpenCAPWAPFuzzer
# ---------------------------------------------------------------------------

class OpenCAPWAPFuzzer(CAPWAPDiscoveryFuzzer):
    """Gray-box fuzzer variant for the OpenCAPWAP AC process.

    Adds process-level liveness detection and a background process health
    monitor on top of the standard CAPWAPDiscoveryFuzzer.  Falls back to
    pure UDP behaviour when the AC process cannot be located.

    OpenCAPWAP AC 进程的灰盒变体。
    在标准 CAPWAPDiscoveryFuzzer 之上增加进程级存活检测和后台进程健康监控。
    找不到 AC 进程时自动降级为纯 UDP 模式。
    """

    #: Name of the AC executable to search for via pgrep.
    #: 通过 pgrep 搜索的 AC 可执行文件名。
    AC_PROC_NAME = "AC"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Shared round counter: fuzzing() writes here; monitor thread reads it.
        # 共享轮次计数器：fuzzing() 写入，监控线程读取。
        self._current_round: list[int] = [0]

        self._ac_pid: int | None = _find_ac_pid(self.AC_PROC_NAME)
        self._monitor: _ProcessMonitor | None = None

        if self._ac_pid is not None:
            logging.info(
                "OpenCAPWAPFuzzer: AC process found (PID %d) — gray-box mode active",
                self._ac_pid
            )
        else:
            logging.warning(
                "OpenCAPWAPFuzzer: AC process '%s' not found — "
                "falling back to UDP-only liveness check (black-box mode)",
                self.AC_PROC_NAME
            )

    # ------------------------------------------------------------------
    # Liveness detection
    # ------------------------------------------------------------------

    def is_target_alive(self, retries: int = 3,
                        probe_timeout: float | None = None,
                        pcap_path: str | None = None) -> bool:
        """Three-state liveness check for OpenCAPWAP.

        When a PID is known:
          1. If the process is gone → return False immediately (confirmed crash).
          2. If the process is alive → send UDP probes (base class logic).
             - Response received → True (healthy)
             - No response        → False (suspected deadlock / DoS)

        When no PID is known (degraded mode):
          Falls back to base class UDP-only check.

        OpenCAPWAP 三态存活检测。

        已知 PID 时：
          1. 进程消失 → 立即返回 False（确认 Crash）
          2. 进程存在 → 发 UDP 探测（基类逻辑）
             - 有回包 → True（正常）
             - 无回包 → False（疑似死锁 / DoS）

        未知 PID 时（降级模式）：退化为基类纯 UDP 检测。
        """
        if self._ac_pid is None:
            # Degraded: no PID — try to find it now (AC may have started later)
            # 降级模式：重新尝试查找 PID（AC 可能在 fuzzer 初始化后才启动）
            self._ac_pid = _find_ac_pid(self.AC_PROC_NAME)

        if self._ac_pid is not None:
            if not _pid_alive(self._ac_pid):
                logging.warning(
                    "OpenCAPWAP AC process (PID %d) is gone — confirmed crash",
                    self._ac_pid
                )
                return False
            # Process is alive; check UDP response
            # 进程存在；进一步检查 UDP 响应
            udp_alive = super().is_target_alive(
                retries=retries,
                probe_timeout=probe_timeout,
                pcap_path=pcap_path,
            )
            if not udp_alive:
                logging.warning(
                    "OpenCAPWAP AC process (PID %d) is alive but not responding "
                    "to UDP probes — suspected deadlock or DoS",
                    self._ac_pid
                )
            return udp_alive

        # No PID at all — pure UDP fallback
        # 完全没有 PID — 纯 UDP 降级
        return super().is_target_alive(
            retries=retries,
            probe_timeout=probe_timeout,
            pcap_path=pcap_path,
        )

    # ------------------------------------------------------------------
    # Fuzzing — wrap base method to maintain round counter and monitor
    # ------------------------------------------------------------------

    def is_process_alive(self) -> bool | None:
        """Check AC process liveness via kill -0.

        Returns True if the process exists, False if it has died, None if PID is unknown.
        Used by cli.py to distinguish DoS (process alive, no UDP) from Crash (process dead).

        通过 kill -0 检查 AC 进程是否存活。
        返回 True 表示进程存在，False 表示进程已死亡，None 表示 PID 未知。
        供 cli.py 区分 DoS（进程存活但无 UDP 回包）与 Crash（进程已死亡）。
        """
        if self._ac_pid is None:
            self._ac_pid = _find_ac_pid(self.AC_PROC_NAME)
        if self._ac_pid is not None:
            return _pid_alive(self._ac_pid)
        return None

    def fuzzing(self, pcap_path: str | None = None,
                max_safe_methods: int = 3,
                max_brutal_methods: int = 3,
                round_number: int | None = None) -> dict:
        """Run one fuzzing round, keeping the round counter up to date.

        The process monitor sidecar (if running) reads self._current_round[0]
        to correlate each CSV sample with the correct fuzzing round.

        运行一轮 fuzzing，同时维护轮次计数器。
        进程监控侧车（若运行中）通过 self._current_round[0] 将 CSV 采样
        与对应的 fuzzing 轮次关联。
        """
        self._current_round[0] += 1
        return super().fuzzing(
            pcap_path=pcap_path,
            max_safe_methods=max_safe_methods,
            max_brutal_methods=max_brutal_methods,
            round_number=self._current_round[0],
        )

    # ------------------------------------------------------------------
    # Process monitor lifecycle
    # ------------------------------------------------------------------

    def start_process_monitor(self):
        """Start the background process health monitor sidecar.

        Creates process_monitor.csv in self.log_dir and begins sampling
        every second.  No-op if PID is unknown or monitor already running.

        启动后台进程健康监控侧车。
        在 self.log_dir 创建 process_monitor.csv 并开始每秒采样。
        若 PID 未知或监控已启动则静默忽略。
        """
        if self._ac_pid is None:
            logging.info(
                "start_process_monitor: no PID available, skipping monitor"
            )
            return
        if self._monitor is not None:
            logging.info("start_process_monitor: monitor already running")
            return
        csv_path = self.log_dir / "process_monitor.csv"
        self._monitor = _ProcessMonitor(
            pid=self._ac_pid,
            csv_path=csv_path,
            round_ref=self._current_round,
        )
        self._monitor.start()

    def stop_process_monitor(self):
        """Stop the background process health monitor sidecar.

        停止后台进程健康监控侧车。
        """
        if self._monitor is not None:
            self._monitor.stop()
            self._monitor = None
