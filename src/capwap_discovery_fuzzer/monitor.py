"""C9800 gray-box monitor, internalized into the fuzzing process.

This replaces the standalone ``tools/c9800_monitor.py`` sidecar. The fuzzing
process now owns the SSH polling loop, so a sample and the round it belongs to
are produced by the same program: every record carries the poll's start/end
timestamps, its duration, and the fuzzing round counter at both ends. A sample
can therefore be tied to a round either by that counter or, post hoc, by the
timestamps in ``records.jsonl``.

Design points that came out of the increment-0 review:

* ``--monitor-interval`` is the **sampling period**: the loop sleeps
  ``interval - elapsed``, so start-to-start spacing is ~interval. (The old
  standalone script slept *after* each poll, so a 20s setting produced ~38s.)
* ``raw`` per-command output is written by default, so a parser that silently
  fails on a new software version can still be fixed offline. (Two such
  failures were found by checking the parsers against a real 17.14.01 device:
  the system-memory regex missed the ``K`` suffix, and the memory column
  captured is RSS, not the "Holding" the old script's comment claimed.)
* ``ssh_ok=false`` is only an anomaly *signal*. It is never treated as a crash
  on its own; the UDP probe remains the authority on liveness.
* The SSH transport is injected, so the polling logic is testable without a
  device and so a missing ``paramiko`` degrades to a recorded warning rather
  than an exception.

Everything is read-only: the command set is plain ``show`` output.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

#: Read-only polling commands. Kept short: `show processes memory platform
#: sorted` is the slowest one and dominates the ~18s poll time, so trimming this
#: list is the lever for a shorter sampling period.
DEFAULT_POLL_COMMANDS: tuple[str, ...] = (
    "show clock",
    "show processes cpu platform",
    "show processes memory platform sorted",
    "show ap summary",
    "show processes platform | include wncd|nginx|pvp|linux_iosd|DEAD",
)

#: Processes worth tracking for a residency/leak signal.
KEY_PROCS = ("wncd", "nginx", "pvp", "linux_iosd", "plogd", "btman", "stack_mgr", "smand")

CPU_RE = re.compile(
    r"CPU utilization for five seconds:\s*(\d+)(?:%/(\d+))?%,?\s*"
    r"one minute:\s*(\d+)%,?\s*five minutes:\s*(\d+)%"
)
# 17.14.01 prints the numbers with a "K" suffix ("8082280K total"); other
# versions omit it, so the suffix is optional. Getting this wrong is silent:
# the regex simply never matches and the field stays null — which is exactly
# what happened to the increment-0 sample's sysmem field.
SYSMEM_RE = re.compile(
    r"System memory:\s*(\d+)K?\s*total,\s*(\d+)K?\s*used,\s*(\d+)K?\s*free"
)
AP_COUNT_RES = (
    re.compile(r"[Tt]otal (?:number of )?APs:?\s*(\d+)"),
    re.compile(r"[Nn]umber of APs(?:\s+joined)?:?\s*(\d+)"),
)
PROMPT_RE = re.compile(rb"[A-Za-z0-9._()-]+[#>]\s*$")
PROMPT_LINE_RE = re.compile(r"^[A-Za-z0-9._()-]+[#>]\s*$")

MONITOR_ERROR_PREFIX = "__MONITOR_ERROR__"


@dataclass
class MonitorConfig:
    """Where and how often to poll. A credential file is preferred to a literal."""

    host: str
    user: str = "lab"
    credential_file: str | None = None
    password: str | None = None
    interval: float = 20.0
    commands: tuple[str, ...] = DEFAULT_POLL_COMMANDS
    raw: bool = True
    connect_timeout: float = 15.0
    command_timeout: float = 25.0

    def resolve_password(self) -> str:
        """Read the password from the credential file, falling back to the literal.

        The value is never logged or serialised.
        """
        if self.credential_file:
            return Path(self.credential_file).expanduser().read_text().strip()
        if self.password:
            return self.password
        raise ValueError("monitor config needs --monitor-credential-file or a password")

    def public_dict(self) -> dict:
        """Config summary safe to write into session.json (no secret)."""
        return {
            "host": self.host,
            "user": self.user,
            "interval": self.interval,
            "raw": self.raw,
            "commands": list(self.commands),
            "credential_source": (
                f"file:{Path(self.credential_file).name}" if self.credential_file
                else ("literal" if self.password else None)
            ),
        }


def parse_cpu(text: str) -> dict | None:
    """Platform-wide CPU load, ignoring the per-core lines that follow it.

    ``5s_irq`` stays None on 17.14.01 (this platform does not print the
    ``%/N%`` interrupt figure); the group is kept for output variants that do.
    """
    for line in text.splitlines():
        if "CPU utilization for five seconds" in line and not line.strip().startswith("Core"):
            m = CPU_RE.search(line)
            if not m:
                continue
            five, five_irq, one, five_min = m.groups()
            return {
                "5s": int(five),
                "5s_irq": int(five_irq) if five_irq else None,
                "1m": int(one),
                "5m": int(five_min),
            }
    return None


def parse_sysmem(text: str) -> dict | None:
    m = SYSMEM_RE.search(text)
    if not m:
        return None
    total, used, free = m.groups()
    return {"total_kb": int(total), "used_kb": int(used), "free_kb": int(free)}


def parse_ap_count(text: str) -> int | None:
    for rx in AP_COUNT_RES:
        m = rx.search(text)
        if m:
            return int(m.group(1))
    return None


def parse_proc_holding(text: str) -> dict[str, int]:
    """Per-process resident memory (KB) from `show processes memory platform sorted`.

    Columns on 17.14.01 are ``Pid Text Data Stack Dynamic RSS Name``, so the
    value taken is the **RSS** column (second to last) — this platform's output
    has no "Holding" column at all. Line shape:

        20870    1007    255196     136     10192    255196            wncd_0

    Raw text is stored alongside every sample, so a column shift can be
    corrected offline instead of silently producing wrong numbers.
    """
    result: dict[str, int] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or not fields[0].isdigit():
            continue
        name = fields[-1].lstrip("(").rstrip(")")
        for key in KEY_PROCS:
            if name.startswith(key):
                try:
                    result[key] = int(fields[-2])
                except ValueError:
                    pass
                break
    return result


def build_record(poll: int, round_at_start: int, round_at_end: int,
                 window_start: str, window_end: str, duration_s: float,
                 raw: dict[str, str], include_raw: bool) -> dict:
    """Turn one poll's raw command output into a JSONL record.

    ``ssh_ok`` is false when any command errored; ``valid_sample`` is false when
    no command produced output at all (the target answered but said nothing
    useful), which distinguishes "poll broken" from "target down".
    """
    errored = [c for c, v in raw.items() if v.startswith(MONITOR_ERROR_PREFIX)]
    non_empty = [c for c, v in raw.items() if v.strip() and c not in errored]

    record: dict = {
        "local_ts": window_start,
        "window_start": window_start,
        "window_end": window_end,
        "duration_s": round(duration_s, 2),
        "poll": poll,
        "round_at_start": round_at_start,
        "round_at_end": round_at_end,
        "ssh_ok": not errored,
        "valid_sample": bool(non_empty),
    }

    clock_lines = raw.get("show clock", "").strip().splitlines()
    record["device_clock"] = clock_lines[-1].strip() if clock_lines else None
    record["cpu"] = parse_cpu(raw.get("show processes cpu platform", ""))
    mem_text = raw.get("show processes memory platform sorted", "")
    record["sysmem"] = parse_sysmem(mem_text)
    record["mem_procs"] = parse_proc_holding(mem_text)
    record["ap_count"] = parse_ap_count(raw.get("show ap summary", ""))

    if errored:
        record["error"] = "; ".join(
            f"{cmd}: {raw[cmd][len(MONITOR_ERROR_PREFIX):].strip()}" for cmd in errored
        )
    if include_raw:
        record["raw"] = raw
    return record


class ParamikoSSHSession:
    """Interactive single-vty session over paramiko.

    A shell channel rather than exec_command: on this target exec channels die
    once output grows past a few lines.
    """

    def __init__(self, config: MonitorConfig):
        self._config = config
        self._client = None
        self._shell = None

    def connect(self) -> None:
        import paramiko  # imported here so the module stays usable without it

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            self._config.host,
            username=self._config.user,
            password=self._config.resolve_password(),
            timeout=self._config.connect_timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        client.get_transport().set_keepalive(15)
        shell = client.invoke_shell(width=511)
        shell.settimeout(2)
        self._client, self._shell = client, shell
        self._read_until_prompt(self._config.command_timeout)
        self._send("terminal length 0")
        self._send("terminal width 511")

    def _read_until_prompt(self, timeout: float) -> str:
        buf = bytearray()
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._shell.recv_ready():
                buf.extend(self._shell.recv(8192))
                if b"\n" in buf and PROMPT_RE.search(bytes(buf).split(b"\n")[-1]):
                    break
            else:
                time.sleep(0.2)
        return bytes(buf).decode(errors="replace")

    def _send(self, command: str) -> str:
        self._shell.send(command + "\n")
        return self._read_until_prompt(self._config.command_timeout)

    def run(self, command: str, timeout: float | None = None) -> str:
        text = self._send(command)
        lines = text.splitlines()
        if lines and command.split()[0] in lines[0]:
            lines = lines[1:]  # drop the echoed command
        while lines and (not lines[-1].strip() or PROMPT_LINE_RE.match(lines[-1].strip())):
            lines = lines[:-1]
        return "\n".join(lines)

    def close(self) -> None:
        for obj in (self._shell, self._client):
            try:
                if obj is not None:
                    obj.close()
            except Exception:  # noqa: BLE001 - closing must never raise
                pass


class C9800Monitor:
    """Background SSH poller writing one JSONL record per sample."""

    def __init__(self, config: MonitorConfig, jsonl_path: Path,
                 round_ref: list[int], session_factory=ParamikoSSHSession):
        self._config = config
        self._path = Path(jsonl_path)
        self._round_ref = round_ref
        self._session_factory = session_factory
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="c9800-monitor")
        self.polls = 0
        self.failed_polls = 0
        self.first_ssh_failure_ts: str | None = None
        self.unavailable_reason: str | None = None

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text("", encoding="utf-8")
        self._thread.start()
        logging.info("C9800 monitor started: %s every %ss -> %s",
                     self._config.host, self._config.interval, self._path)

    def stop(self, timeout: float = 30.0) -> None:
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)
        logging.info("C9800 monitor stopped (%d polls, %d failed)", self.polls, self.failed_polls)

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    # ------------------------------------------------------------------- polling
    def _run(self) -> None:
        session = None
        try:
            while not self._stop_event.is_set():
                started = time.monotonic()
                window_start = datetime.now().isoformat(timespec="seconds")
                round_at_start = self._round_ref[0] if self._round_ref else 0
                record = None

                try:
                    if session is None:
                        session = self._session_factory(self._config)
                        session.connect()
                    raw = self.poll_commands(session)
                    record = build_record(
                        self.polls, round_at_start,
                        self._round_ref[0] if self._round_ref else 0,
                        window_start, datetime.now().isoformat(timespec="seconds"),
                        time.monotonic() - started, raw, self._config.raw,
                    )
                except ImportError as exc:
                    # paramiko missing: record once and stop rather than spamming.
                    self.unavailable_reason = f"paramiko unavailable: {exc}"
                    logging.warning("C9800 monitor disabled — %s", self.unavailable_reason)
                    record = {
                        "local_ts": window_start, "poll": self.polls, "ssh_ok": False,
                        "valid_sample": False, "error": self.unavailable_reason,
                    }
                    self._append(record)
                    return
                except Exception as exc:  # noqa: BLE001 - target down is a recorded state
                    self.failed_polls += 1
                    if self.first_ssh_failure_ts is None:
                        self.first_ssh_failure_ts = window_start
                    record = {
                        "local_ts": window_start,
                        "window_start": window_start,
                        "window_end": datetime.now().isoformat(timespec="seconds"),
                        "duration_s": round(time.monotonic() - started, 2),
                        "poll": self.polls,
                        "round_at_start": round_at_start,
                        "round_at_end": self._round_ref[0] if self._round_ref else 0,
                        "ssh_ok": False,
                        "valid_sample": False,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                    # Drop the session so the next poll reconnects from scratch.
                    if session is not None:
                        try:
                            session.close()
                        except Exception:  # noqa: BLE001
                            pass
                        session = None

                self._append(record)
                self.polls += 1

                # Sampling-period semantics: start-to-start spacing ~= interval.
                remaining = self._config.interval - (time.monotonic() - started)
                if remaining > 0:
                    self._stop_event.wait(remaining)
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:  # noqa: BLE001
                    pass

    def poll_commands(self, session) -> dict[str, str]:
        """Run the configured read-only commands, recording failures per command."""
        out: dict[str, str] = {}
        for command in self._config.commands:
            try:
                out[command] = session.run(command, self._config.command_timeout)
            except Exception as exc:  # noqa: BLE001 - one bad command must not kill the poll
                out[command] = f"{MONITOR_ERROR_PREFIX} {type(exc).__name__}: {exc}"
        return out

    def _append(self, record: dict) -> None:
        try:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as exc:
            logging.warning("C9800 monitor: failed to write %s: %s", self._path, exc)

    # ------------------------------------------------------------------ reporting
    def summary(self) -> dict:
        return {
            "host": self._config.host,
            "polls": self.polls,
            "failed_polls": self.failed_polls,
            "first_ssh_failure_ts": self.first_ssh_failure_ts,
            "unavailable_reason": self.unavailable_reason,
            "jsonl": str(self._path),
        }
