"""Crash forensics: local evidence first, then a time-boxed device pull.

Ordering matters and is enforced by :func:`collect_on_anomaly`:

1. **Local evidence is written first** — the last requests and responses, the
   seed, the method chains, the monitor window and the first anomaly timestamp,
   the probe results, and a fingerprint of the code that was running. None of
   this needs the target, so it survives a target that has stopped answering
   entirely.
2. **Device-side collection is attempted second, under a hard deadline.** When a
   device is unwell its SSH service is often unwell too, so a failure here is
   recorded and never blocks the run's exit. Each command's output is written to
   its own file with a sha256 and a length, and the index says which commands
   were skipped because the deadline ran out.

The command set is read-only ``show``/``dir`` output; nothing on the device is
changed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import platform
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

#: Read-only commands worth capturing after an anomaly. Deliberately narrow:
#: `show tech-support` is far too large to pull while a device may be unwell.
DEFAULT_FORENSICS_COMMANDS: tuple[str, ...] = (
    "show clock",
    "show version | include Version",
    "show processes cpu platform | include CPU utilization",
    "show processes memory platform sorted",
    "dir bootflash: | include crashinfo",
    "show logging | include %SYS-2|%SYS-3|Traceback|CRASH",
)

#: Hash files up to this size in full; larger ones are hashed in the same way
#: but the index notes that only a prefix was read.
HASH_CHUNK = 1 << 20


def sha256_file(path: Path, max_bytes: int | None = None) -> str:
    h = hashlib.sha256()
    read = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(HASH_CHUNK)
            if not chunk:
                break
            h.update(chunk)
            read += len(chunk)
            if max_bytes is not None and read >= max_bytes:
                break
    return h.hexdigest()


def _find_repo_root(start: Path) -> Path | None:
    for candidate in [start, *start.parents]:
        if (candidate / ".git").exists():
            return candidate
    return None


def code_fingerprint(package_dir: Path | None = None) -> dict:
    """Identify the code that is running, dirty tree included.

    A commit hash alone is not enough: the lab ships fixes as uncommitted
    working-tree changes, which is exactly the situation where "which code was
    this?" gets asked. So we also hash the tracked-vs-working diff and the
    package sources.
    """
    pkg = package_dir or Path(__file__).resolve().parent
    info: dict = {"package_dir": str(pkg)}

    sources = sorted(pkg.rglob("*.py"))
    digest = hashlib.sha256()
    for path in sources:
        digest.update(path.relative_to(pkg).as_posix().encode())
        digest.update(path.read_bytes())
    info["package_sha256"] = digest.hexdigest()
    info["package_files"] = len(sources)

    root = _find_repo_root(pkg)
    if root is None:
        info["git"] = {"available": False}
        return info

    info["repo_root"] = str(root)
    git = {"available": True}
    try:
        git["commit"] = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        git["branch"] = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        porcelain = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True, text=True, timeout=10,
        ).stdout
        git["dirty"] = bool(porcelain.strip())
        git["dirty_paths"] = sorted(
            line[3:].strip() for line in porcelain.splitlines() if line.strip()
        )
        git["status_sha256"] = hashlib.sha256(porcelain.encode()).hexdigest()
    except (OSError, subprocess.SubprocessError) as exc:
        git["error"] = f"{type(exc).__name__}: {exc}"
    info["git"] = git
    return info


def artifact_index(log_dir: Path) -> list[dict]:
    """Size and hash of every evidence file in the session directory."""
    out = []
    for path in sorted(Path(log_dir).iterdir()):
        if not path.is_file():
            continue
        try:
            out.append({
                "name": path.name,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            })
        except OSError as exc:
            out.append({"name": path.name, "error": f"{type(exc).__name__}: {exc}"})
    return out


def _monitor_window(log_dir: Path) -> dict:
    """Summarise the monitor samples around the anomaly, if any were taken."""
    path = Path(log_dir) / "monitor.jsonl"
    if not path.exists():
        return {"present": False}

    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    failures = [r for r in records if not r.get("ssh_ok", True)]
    return {
        "present": True,
        "polls": len(records),
        "failed_polls": len(failures),
        "first_ssh_failure_ts": failures[0].get("local_ts") if failures else None,
        "last_window": {k: records[-1].get(k) for k in ("window_start", "window_end", "round_at_start", "round_at_end")} if records else None,
        "last_cpu": records[-1].get("cpu") if records else None,
        "last_mem_procs": records[-1].get("mem_procs") if records else None,
    }


def write_local_evidence(log_dir: Path, reason: str, round_number: int | None,
                         status: dict | None = None, probe: dict | None = None,
                         extra: dict | None = None) -> Path:
    """Write ``evidence.json``: everything we know without touching the target.

    This runs before any device-side attempt, so a target that is gone (or whose
    SSH is gone) cannot cost us the local record.
    """
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    evidence = {
        "reason": reason,
        "detected_at": datetime.now().isoformat(),
        "round": round_number,
        "status": status or {},
        "probe": probe or {},
        "runtime": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "scapy": _scapy_version(),
        },
        "code": code_fingerprint(),
        "monitor": _monitor_window(log_dir),
        "artifacts": artifact_index(log_dir),
    }
    if extra:
        evidence.update(extra)
    path = log_dir / "evidence.json"
    path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
    logging.info("Local evidence written to %s", path)
    return path


def _scapy_version() -> str | None:
    try:
        import scapy
        return getattr(scapy, "__version__", None)
    except Exception:  # noqa: BLE001
        return None


def _safe_name(command: str) -> str:
    keep = [c if (c.isalnum() or c in "._-") else "_" for c in command]
    return "".join(keep)[:80]


def collect_device_evidence(log_dir: Path, session_factory, commands=DEFAULT_FORENSICS_COMMANDS,
                            total_timeout: float = 60.0,
                            per_command_timeout: float = 20.0) -> dict:
    """Pull read-only diagnostics from the target, under a hard deadline.

    Never raises: a failure is data. Returns an index of what was captured, what
    failed and what the deadline forced us to skip.
    """
    log_dir = Path(log_dir)
    out_dir = log_dir / "device_evidence"
    out_dir.mkdir(parents=True, exist_ok=True)

    index: dict = {
        "attempted_at": datetime.now().isoformat(),
        "total_timeout_s": total_timeout,
        "captured": [],
        "failed": [],
        "skipped": [],
        "session_error": None,
    }
    deadline = time.monotonic() + total_timeout
    session = None

    try:
        try:
            session = session_factory()
            session.connect()
        except Exception as exc:  # noqa: BLE001 - device may be unreachable
            index["session_error"] = f"{type(exc).__name__}: {exc}"
            logging.warning("Device evidence: could not open SSH session: %s", exc)
            (out_dir / "device_evidence.json").write_text(
                json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")
            return index

        for position, command in enumerate(commands):
            if time.monotonic() >= deadline:
                index["skipped"].extend(commands[position:])
                break
            budget = max(1.0, min(per_command_timeout, deadline - time.monotonic()))
            started = time.monotonic()
            try:
                text = session.run(command, budget)
                name = f"{position:02d}_{_safe_name(command)}.txt"
                (out_dir / name).write_text(text, encoding="utf-8")
                index["captured"].append({
                    "command": command,
                    "file": name,
                    "duration_s": round(time.monotonic() - started, 2),
                    "bytes": len(text.encode()),
                    "sha256": hashlib.sha256(text.encode()).hexdigest(),
                })
            except Exception as exc:  # noqa: BLE001 - keep going, record the failure
                index["failed"].append({
                    "command": command,
                    "error": f"{type(exc).__name__}: {exc}",
                    "duration_s": round(time.monotonic() - started, 2),
                })
    finally:
        if session is not None:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass

    (out_dir / "device_evidence.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")
    logging.info(
        "Device evidence: %d captured, %d failed, %d skipped",
        len(index["captured"]), len(index["failed"]), len(index["skipped"]),
    )
    return index


def collect_on_anomaly(log_dir: Path, reason: str, round_number: int | None,
                       status: dict | None = None, probe: dict | None = None,
                       device_session_factory=None,
                       device_commands=DEFAULT_FORENSICS_COMMANDS,
                       device_timeout: float = 60.0,
                       extra: dict | None = None) -> dict:
    """The full order of operations: local evidence, then best-effort device pull."""
    write_local_evidence(log_dir, reason, round_number, status=status, probe=probe, extra=extra)
    result = {"local_evidence": str(Path(log_dir) / "evidence.json"), "device": None}
    if device_session_factory is None:
        result["device"] = {"attempted": False, "reason": "no device credentials configured"}
        return result
    result["device"] = collect_device_evidence(
        log_dir, device_session_factory, commands=device_commands, total_timeout=device_timeout)
    return result
