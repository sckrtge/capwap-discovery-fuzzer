"""Tests for the internalized gray-box monitor (C) and crash forensics (D).

Both features are exercised through an injected SSH transport, so the suite
needs no real device: `FakeSession` stands in for paramiko, and a local UDP
responder stands in for the target in the end-to-end crash test.
"""

import json
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from capwap_discovery_fuzzer import forensics, monitor
from capwap_discovery_fuzzer.cli import app

# ------------------------------------------------------------------ fakes


class FakeSession:
    """Stands in for monitor.ParamikoSSHSession."""

    def __init__(self, outputs=None, fail_on=None, fail_connect=False, delay=0.0):
        self.outputs = outputs or {}
        self.fail_on = fail_on or set()
        self.fail_connect = fail_connect
        self.delay = delay
        self.closed = False
        self.commands = []

    def connect(self):
        if self.fail_connect:
            raise OSError("no route to host")

    def run(self, command, timeout=None):
        self.commands.append(command)
        if self.delay:
            time.sleep(self.delay)
        if command in self.fail_on:
            raise TimeoutError("command timed out")
        return self.outputs.get(command, "")

    def close(self):
        self.closed = True


# Verbatim excerpts from C9800-CL 17.14.01 (captured 2026-09-11); these formats
# are what the parsers must handle — two of them were wrong until checked here.
CPU_OUTPUT = (
    "CPU utilization for five seconds:  6%, one minute:  7%, five minutes:  7%\n"
    "Core 0: CPU utilization for five seconds:  4%, one minute:  3%, five minutes:  2%\n"
    "Core 3: CPU utilization for five seconds:  9%, one minute: 10%, five minutes:  9%"
)
MEM_OUTPUT = (
    "System memory: 8082280K total, 3604304K used, 4477976K free,\n"
    "Lowest: 4405312K\n"
    "   Pid    Text      Data   Stack   Dynamic       RSS              Name\n"
    "----------------------------------------------------------------------\n"
    " 23140  403843    964668     136       472    964668   linux_iosd-imag\n"
    " 20870    1007    255196     136     10192    255196            wncd_0\n"
    " 14477     985    112908     136     28092    112908             smand"
)
AP_OUTPUT = (
    "Number of APs: 0\n\nCC = Country Code\nRD = Regulatory Domain\n\n"
    "AP Name    Slots AP Model    Ethernet MAC   Radio MAC   CC   RD   IP Address   State   Location\n"
)
CLOCK_OUTPUT = "*13:47:15.175 UTC Fri Sep 11 2026"
STDOUT_OUTPUT = (
    "  8301       1  S            11288  pvp.sh\n"
    " 20870   20653  S           255128  wncd_0\n"
    " 32566   32468  S            13632  nginx"
)

DEFAULT_OUTPUTS = {
    "show clock": CLOCK_OUTPUT,
    "show processes cpu platform": CPU_OUTPUT,
    "show processes memory platform sorted": MEM_OUTPUT,
    "show ap summary": AP_OUTPUT,
    "show processes platform | include wncd|nginx|pvp|linux_iosd|DEAD": STDOUT_OUTPUT,
}


def _config(**kw):
    base = dict(host="192.0.2.10", user="lab", password="secret", interval=0.05)
    base.update(kw)
    return monitor.MonitorConfig(**base)


# ------------------------------------------------------------- C: parsers

def test_parse_cpu_reads_platform_total_not_a_core():
    assert monitor.parse_cpu(CPU_OUTPUT) == {"5s": 6, "5s_irq": None, "1m": 7, "5m": 7}


def test_parse_cpu_prefers_aggregate_over_per_core_lines():
    # Core lines also carry the same phrase; only the platform total is wanted.
    reordered = "\n".join(CPU_OUTPUT.splitlines()[1:]) + "\n" + CPU_OUTPUT.splitlines()[0]
    assert monitor.parse_cpu(reordered)["1m"] == 7


def test_parse_cpu_returns_none_on_unknown_output():
    assert monitor.parse_cpu("no counters here") is None


def test_parse_sysmem_handles_kilo_suffix():
    # Regression: 17.14.01 prints "8082280K total"; a regex without the optional
    # K left sysmem null in every sample of the increment-0 monitor output.
    assert monitor.parse_sysmem(MEM_OUTPUT) == {
        "total_kb": 8082280, "used_kb": 3604304, "free_kb": 4477976
    }
    assert monitor.parse_sysmem("System memory: 100 total, 60 used, 40 free") is not None


def test_parse_proc_holding_takes_rss_column():
    holding = monitor.parse_proc_holding(MEM_OUTPUT)
    assert holding["wncd"] == 255196          # RSS column, not "Holding"
    assert holding["smand"] == 112908
    assert "linux_iosd" in holding


def test_parse_ap_count():
    assert monitor.parse_ap_count(AP_OUTPUT) == 0
    assert monitor.parse_ap_count("garbage") is None


# ------------------------------------------------------- C: record building

def test_build_record_keeps_raw_and_round_window():
    record = monitor.build_record(
        poll=3, round_at_start=10, round_at_end=14,
        window_start="2026-09-11T13:00:00", window_end="2026-09-11T13:00:18",
        duration_s=18.4, raw=DEFAULT_OUTPUTS, include_raw=True,
    )
    assert record["ssh_ok"] is True
    assert record["valid_sample"] is True
    assert record["round_at_start"] == 10 and record["round_at_end"] == 14
    assert record["duration_s"] == 18.4
    assert record["device_clock"] == CLOCK_OUTPUT
    assert record["cpu"]["1m"] == 7
    assert record["sysmem"]["used_kb"] == 3604304
    assert record["mem_procs"]["wncd"] == 255196
    assert record["raw"]["show clock"] == CLOCK_OUTPUT


def test_build_record_marks_ssh_failure_per_command():
    raw = dict(DEFAULT_OUTPUTS)
    raw["show ap summary"] = f"{monitor.MONITOR_ERROR_PREFIX} TimeoutError: slow"
    record = monitor.build_record(0, 1, 1, "t0", "t1", 1.0, raw, True)

    assert record["ssh_ok"] is False          # an anomaly signal...
    assert record["valid_sample"] is True     # ...but other commands answered
    assert "show ap summary" in record["error"]


def test_build_record_flags_empty_sample():
    raw = {cmd: "" for cmd in DEFAULT_OUTPUTS}
    record = monitor.build_record(0, 1, 1, "t0", "t1", 1.0, raw, False)

    assert record["ssh_ok"] is True
    assert record["valid_sample"] is False    # answered but said nothing
    assert "raw" not in record                # --no-monitor-raw


def test_monitor_config_public_dict_hides_secret(tmp_path):
    secret = tmp_path / "cred"
    secret.write_text("hunter2\n")
    cfg = _config(password=None, credential_file=str(secret))

    public = cfg.public_dict()
    assert "hunter2" not in json.dumps(public)
    assert public["credential_source"] == "file:cred"
    assert cfg.resolve_password() == "hunter2"   # stripped


def test_monitor_config_requires_a_credential_source():
    with pytest.raises(ValueError):
        _config(password=None).resolve_password()


# ------------------------------------------------------- C: polling thread

def test_monitor_thread_writes_records_and_stops(tmp_path):
    session = FakeSession(outputs=DEFAULT_OUTPUTS)
    mon = monitor.C9800Monitor(_config(), tmp_path / "monitor.jsonl", [7],
                               session_factory=lambda cfg: session)
    mon.start()
    time.sleep(0.4)
    mon.stop()

    records = [json.loads(l) for l in (tmp_path / "monitor.jsonl").read_text().splitlines()]
    assert len(records) >= 2
    assert all(r["ssh_ok"] for r in records)
    assert all(r["round_at_start"] == 7 for r in records)
    assert session.closed is True
    assert mon.summary()["polls"] == len(records)


def test_monitor_records_connection_failure_without_raising(tmp_path):
    mon = monitor.C9800Monitor(
        _config(), tmp_path / "monitor.jsonl", [1],
        session_factory=lambda cfg: FakeSession(fail_connect=True),
    )
    mon.start()
    time.sleep(0.3)
    mon.stop()

    records = [json.loads(l) for l in (tmp_path / "monitor.jsonl").read_text().splitlines()]
    assert records
    assert records[0]["ssh_ok"] is False
    assert "OSError" in records[0]["error"]
    assert mon.failed_polls >= 1
    assert mon.first_ssh_failure_ts is not None


def test_monitor_records_unavailable_paramiko_once(tmp_path):
    def factory(cfg):
        raise ImportError("No module named 'paramiko'")

    mon = monitor.C9800Monitor(_config(), tmp_path / "monitor.jsonl", [1], session_factory=factory)
    mon.start()
    time.sleep(0.2)
    mon.stop()

    records = [json.loads(l) for l in (tmp_path / "monitor.jsonl").read_text().splitlines()]
    assert len(records) == 1
    assert "paramiko unavailable" in records[0]["error"]
    assert mon.unavailable_reason is not None


def test_monitor_poll_commands_records_one_bad_command(tmp_path):
    session = FakeSession(outputs=DEFAULT_OUTPUTS, fail_on={"show ap summary"})
    mon = monitor.C9800Monitor(_config(), tmp_path / "monitor.jsonl", [1],
                               session_factory=lambda cfg: session)
    raw = mon.poll_commands(session)

    assert raw["show ap summary"].startswith(monitor.MONITOR_ERROR_PREFIX)
    assert raw["show clock"] == CLOCK_OUTPUT


def test_monitor_noop_when_not_configured():
    from capwap_discovery_fuzzer.capwap_discovery_fuzzer import CAPWAPDiscoveryFuzzer

    fuzzer = CAPWAPDiscoveryFuzzer(ac_ip="127.0.0.1", seed=1)
    assert fuzzer.monitor_config is None
    fuzzer.start_monitor()            # must not create a thread or raise
    assert fuzzer.monitor_summary() is None
    assert fuzzer.device_session_factory() is None
    fuzzer.stop_monitor()


# ------------------------------------------------------------ D: forensics

def test_code_fingerprint_identifies_running_code():
    info = forensics.code_fingerprint()
    assert len(info["package_sha256"]) == 64
    assert info["package_files"] > 0

    git = info.get("git", {})
    if not git.get("available"):
        pytest.skip("not a git checkout")
    assert len(git["commit"]) == 40
    assert isinstance(git["dirty"], bool)
    assert len(git["status_sha256"]) == 64


def test_artifact_index_hashes_files(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    (tmp_path / "b.txt").write_text("world")
    index = {e["name"]: e for e in forensics.artifact_index(tmp_path)}

    assert index["a.txt"]["bytes"] == 5
    assert index["a.txt"]["sha256"] == forensics.sha256_file(tmp_path / "a.txt")


def test_write_local_evidence_summarises_monitor_window(tmp_path):
    (tmp_path / "monitor.jsonl").write_text(
        "\n".join(json.dumps(r) for r in [
            {"local_ts": "2026-09-11T13:00:00", "ssh_ok": True, "valid_sample": True,
             "window_start": "2026-09-11T13:00:00", "window_end": "2026-09-11T13:00:18",
             "round_at_start": 1, "round_at_end": 3, "cpu": {"1m": 19}},
            {"local_ts": "2026-09-11T13:00:20", "ssh_ok": False, "valid_sample": False,
             "window_start": "2026-09-11T13:00:20", "window_end": "2026-09-11T13:00:21",
             "round_at_start": 4, "round_at_end": 4, "error": "OSError: down"},
        ]) + "\n", encoding="utf-8")

    path = forensics.write_local_evidence(
        tmp_path, reason="crash", round_number=42,
        status={"valid": 1, "timeout": 9}, probe={"alive": False},
    )
    evidence = json.loads(path.read_text(encoding="utf-8"))

    assert evidence["reason"] == "crash"
    assert evidence["round"] == 42
    assert evidence["monitor"]["present"] is True
    assert evidence["monitor"]["polls"] == 2
    assert evidence["monitor"]["failed_polls"] == 1
    assert evidence["monitor"]["first_ssh_failure_ts"] == "2026-09-11T13:00:20"
    assert any(a["name"] == "monitor.jsonl" for a in evidence["artifacts"])
    assert "python" in evidence["runtime"]


def test_collect_device_evidence_writes_files_and_index(tmp_path):
    commands = ("show clock", "show version | include Version")
    session = FakeSession(outputs={"show clock": CLOCK_OUTPUT, "show version | include Version": "17.14.01"})
    index = forensics.collect_device_evidence(
        tmp_path, lambda: session, commands=commands, total_timeout=10)

    assert len(index["captured"]) == 2
    assert index["failed"] == [] and index["skipped"] == []
    for entry in index["captured"]:
        text = (tmp_path / "device_evidence" / entry["file"]).read_text(encoding="utf-8")
        assert entry["sha256"] == forensics.sha256_file(tmp_path / "device_evidence" / entry["file"])
        assert entry["bytes"] == len(text.encode())
    assert session.closed is True
    assert (tmp_path / "device_evidence" / "device_evidence.json").exists()


def test_collect_device_evidence_records_unreachable_target(tmp_path):
    index = forensics.collect_device_evidence(
        tmp_path, lambda: FakeSession(fail_connect=True), commands=("show clock",))

    assert index["session_error"] is not None
    assert index["captured"] == []
    assert (tmp_path / "device_evidence" / "device_evidence.json").exists()


def test_collect_device_evidence_skips_past_deadline(tmp_path):
    commands = tuple(f"show thing {i}" for i in range(6))
    session = FakeSession(outputs={c: "ok" for c in commands}, delay=0.25)
    index = forensics.collect_device_evidence(
        tmp_path, lambda: session, commands=commands,
        total_timeout=0.6, per_command_timeout=10.0)

    assert index["skipped"], "deadline should have cut the command list short"
    assert len(index["captured"]) + len(index["skipped"]) == len(commands)


def test_collect_device_evidence_keeps_going_after_one_failure(tmp_path):
    commands = ("show clock", "show ap summary")
    session = FakeSession(outputs={"show clock": CLOCK_OUTPUT}, fail_on={"show ap summary"})
    index = forensics.collect_device_evidence(
        tmp_path, lambda: session, commands=commands, total_timeout=10)

    assert len(index["captured"]) == 1
    assert len(index["failed"]) == 1
    assert "TimeoutError" in index["failed"][0]["error"]


def test_collect_on_anomaly_writes_local_first_when_device_is_gone(tmp_path):
    result = forensics.collect_on_anomaly(
        tmp_path, reason="crash", round_number=5, status={"valid": 0},
        device_session_factory=lambda: FakeSession(fail_connect=True),
    )

    assert (tmp_path / "evidence.json").exists()          # local evidence survived
    assert result["device"]["session_error"] is not None


def test_collect_on_anomaly_skips_device_without_credentials(tmp_path):
    result = forensics.collect_on_anomaly(tmp_path, reason="dos_suspected", round_number=3)

    assert (tmp_path / "evidence.json").exists()
    assert result["device"] == {"attempted": False, "reason": "no device credentials configured"}


# ------------------------------------- D: end-to-end through the CLI crash path

def _responder(answer_first_n=1):
    """Answer the pre-flight probe, then go silent (simulates a dying target)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    stop = threading.Event()
    served = [0]

    def serve():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                _, peer = sock.recvfrom(65535)
            except OSError:
                continue
            if served[0] < answer_first_n:
                served[0] += 1
                sock.sendto(b"\x00" * 8, peer)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return sock, port, stop, thread


def test_cli_crash_path_writes_crash_and_forensic_evidence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sock, port, stop, thread = _responder(answer_first_n=1)
    try:
        result = CliRunner().invoke(app, [
            "--ac-ip", "127.0.0.1", "--ac-port", str(port),
            "--vendor", "cisco", "--rounds", "10", "--timeout", "0.3",
            "--sleep", "0", "--seed", "5", "--probe-interval", "2",
        ])
    finally:
        stop.set()
        thread.join(timeout=2)
        sock.close()

    assert result.exit_code == 2, result.output
    session_dirs = list(tmp_path.glob("capwap_log/*"))
    assert len(session_dirs) == 1
    session = session_dirs[0]

    for name in ("crash_report.json", "crash_sequence.jsonl", "summary.json", "evidence.json"):
        assert (session / name).exists(), f"missing {name}"

    evidence = json.loads((session / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["reason"] == "crash"
    assert evidence["probe"]["alive"] is False
    assert evidence["monitor"]["present"] is False          # no --monitor-host given
    assert len(evidence["code"]["package_sha256"]) == 64
    assert any(a["name"] == "crash_sequence.jsonl" for a in evidence["artifacts"])
