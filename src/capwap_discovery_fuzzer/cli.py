import json
import sys
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from pathlib import Path
import time
import logging
from datetime import datetime

from .capwap_discovery_fuzzer import CAPWAPDiscoveryFuzzer
from .errors import CrashDetectedError
from . import forensics
from . import monitor
from . import weights
from .lock_fuzzer import parse_lock_fields
from .vendors import get_vendor, DEFAULT_VENDOR
from .vendors.opencapwap.fuzzer import OpenCAPWAPFuzzer

app = typer.Typer()
console = Console()


def _parse_hex_bytes(value: str, option: str, expect_len: int | None = None) -> bytes:
    """Parse a hex string (colons/dashes allowed), e.g. an AP MAC."""
    cleaned = value.replace(":", "").replace("-", "").replace(" ", "")
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError:
        raise typer.BadParameter(f"{option} must be hex digits, got {value!r}")
    if expect_len is not None and len(raw) != expect_len:
        raise typer.BadParameter(
            f"{option} must be {expect_len} bytes ({expect_len * 2} hex digits), got {len(raw)}")
    return raw


def _parse_int_list(value: str, option: str) -> list[int]:
    out: list[int] = []
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            out.append(int(chunk, 0))
        except ValueError:
            raise typer.BadParameter(f"{option} must be a comma-separated integer list, got {value!r}")
    if not out:
        raise typer.BadParameter(f"{option} was given but contains no value")
    return out


def _build_identity(values: dict):
    """Turn the seed-identity CLI options into an ApIdentity (E/3a).

    Unset options keep the captured defaults, so the default run stays
    byte-identical to previous sessions (asserted in tests/test_identity.py).
    """
    from dataclasses import replace

    from .vendors.cisco.creator import ApIdentity

    kwargs: dict = {}
    if values["--ap-name"] is not None:
        kwargs["ap_name"] = values["--ap-name"].encode()
    if values["--ap-mac"] is not None:
        kwargs["ap_mac"] = _parse_hex_bytes(values["--ap-mac"], "--ap-mac", expect_len=6)
    if values["--ap-model"] is not None:
        kwargs["model"] = values["--ap-model"].encode()
    if values["--ap-serial"] is not None:
        kwargs["serial"] = values["--ap-serial"].encode()
    if values["--ap-base-mac"] is not None:
        kwargs["base_mac"] = _parse_hex_bytes(values["--ap-base-mac"], "--ap-base-mac", expect_len=6)
    if values["--ap-radio-ids"] is not None:
        ids = _parse_int_list(values["--ap-radio-ids"], "--ap-radio-ids")
        captured_types = (0x01, 0x02)   # from the capture, in order
        kwargs["radios"] = tuple(
            (rid, captured_types[i] if i < len(captured_types) else 0x0E)
            for i, rid in enumerate(ids)
        )
        kwargs["max_radios"] = len(ids)
        kwargs["radios_in_use"] = len(ids)
    if values["--num-encrypt"] is not None:
        kwargs["num_encrypt"] = values["--num-encrypt"]
    if values["--msg-type"] is not None:
        kwargs["msg_type"] = values["--msg-type"]
    if values["--omit-element"] is not None:
        kwargs["omit_elements"] = frozenset(
            _parse_int_list(values["--omit-element"], "--omit-element"))
    return replace(ApIdentity(), **kwargs)


def _describe_identity(identity) -> dict | None:
    """Serialise the seed identity for session.json (no secrets involved)."""
    if identity is None:
        return None
    return {
        "ap_name": identity.ap_name.decode(errors="replace"),
        "ap_mac": identity.ap_mac.hex(),
        "model": identity.model.decode(errors="replace"),
        "serial": identity.serial.decode(errors="replace"),
        "base_mac": identity.base_mac.hex(),
        "radios": [list(r) for r in identity.radios],
        "max_radios": identity.max_radios,
        "radios_in_use": identity.radios_in_use,
        "num_encrypt": identity.num_encrypt,
        "msg_type": identity.msg_type,
        "omit_elements": sorted(identity.omit_elements),
    }


def _collect_forensics(fuzzer, reason: str, round_number, status: dict, probe: dict,
                       enabled: bool) -> None:
    """Write local evidence, then attempt a time-boxed device pull.

    Never raises: a failure to collect evidence must not mask the anomaly that
    triggered it, and must not stop the process from exiting.
    """
    if not enabled:
        return
    try:
        result = forensics.collect_on_anomaly(
            fuzzer.log_dir, reason=reason, round_number=round_number, status=status,
            probe=probe,
            device_session_factory=fuzzer.device_session_factory(),
            extra={"monitor_summary": fuzzer.monitor_summary()},
        )
        console.print(f"[yellow][*] Forensics : local evidence -> {result['local_evidence']}[/yellow]")
        device = result.get("device") or {}
        if device.get("attempted") is False:
            console.print(f"[dim]    device evidence skipped: {device.get('reason')}[/dim]")
        else:
            console.print(
                f"[dim]    device evidence: {len(device.get('captured', []))} captured, "
                f"{len(device.get('failed', []))} failed, "
                f"{len(device.get('skipped', []))} skipped[/dim]"
            )
    except Exception as exc:  # noqa: BLE001 - forensics must never mask the anomaly
        logging.warning("forensics collection failed: %s", exc)
        console.print(f"[red][-] Forensics collection failed: {exc}[/red]")


@app.command()
def fuzz(
    pcap: Path | None = typer.Option(
        None,
        '--pcap',
        exists=True,
        readable=True,
        help='PCAP file containing only one CAPWAP Discovery Request message'
    ),
    ac_ip: str = typer.Option(
        None,
        '--ac-ip',
        help='Target AC IP address (unicast mode)'
    ),
    ac_port: int = typer.Option(
        5246,
        '--ac-port',
        help='Target AC control port (default 5246)'
    ),
    broadcast: bool = typer.Option(
        False,
        '--broadcast',
        help='Use UDP broadcast for CAPWAP Discovery'
    ),
    rounds: int = typer.Option(
        1,
        '--rounds',
        help='Rounds of fuzzing iterations',
        min=1
    ),
    seed: int = typer.Option(
        None,
        '--seed',
        help='Random seed for fuzzing'
    ),
    timeout: float = typer.Option(
        3.0,
        '--timeout',
        help='Limit time for waiting for response'
    ),
    sleep_per_round: float = typer.Option(
        1.0,
        '--sleep',
        help='Sleep seconds per fuzzing round'
    ),
    replay_jsonl: Path | None = typer.Option(
        None,
        '--replay-jsonl',
        exists=True,
        file_okay=True,
        dir_okay=False,
        help='records.jsonl file to replay for crash reproduction (replaces fuzzing)'
    ),
    replay_filter: str | None = typer.Option(
        None,
        '--replay-filter',
        help='Filter records by response_type when replaying, e.g. "error" or "timeout"'
    ),
    iface: str = typer.Option(
        'lo',
        '--iface',
        help='Network interface for sending/sniffing (default: lo)'
    ),
    probe_interval: int = typer.Option(
        10,
        '--probe-interval',
        help='Check target liveness every N rounds (0 = disabled). On crash: saves crash_report.json and exits with code 2.',
        min=0
    ),
    on_probe_fail: str = typer.Option(
        'continue',
        '--on-probe-fail',
        help=(
            'Action when a liveness probe fails: '
            '"continue" (default) keeps fuzzing and records a suspected_event.json; '
            '"stop" halts immediately (original behaviour). '
            'In continue mode, 3 consecutive probe failures trigger a definitive crash stop.'
        )
    ),
    monitor_host: str | None = typer.Option(
        None,
        '--monitor-host',
        help=(
            'Enable gray-box SSH monitoring against this host (default: off). Read-only show '
            'commands are polled into monitor.jsonl with raw output, timestamps and the fuzz '
            'round range each sample covers.'
        )
    ),
    monitor_user: str = typer.Option(
        'lab',
        '--monitor-user',
        help='SSH user for --monitor-host'
    ),
    monitor_credential_file: Path | None = typer.Option(
        None,
        '--monitor-credential-file',
        exists=True,
        readable=True,
        dir_okay=False,
        help='File holding the SSH password for --monitor-host (the value is never written to session.json)'
    ),
    monitor_interval: float = typer.Option(
        20.0,
        '--monitor-interval',
        help=(
            'Monitor sampling PERIOD in seconds, start to start. One poll takes ~18s on a '
            'C9800-CL, so smaller values overlap instead of sampling faster.'
        )
    ),
    monitor_raw: bool = typer.Option(
        True,
        '--monitor-raw/--no-monitor-raw',
        help='Store raw per-command output in monitor.jsonl (default: on)'
    ),
    forensics_enabled: bool = typer.Option(
        True,
        '--forensics/--no-forensics',
        help=(
            'On anomaly: write local evidence first (always possible), then pull read-only device '
            'diagnostics under a deadline. Device pull needs --monitor-host for credentials.'
        )
    ),
    ap_name: str | None = typer.Option(
        None,
        '--ap-name',
        help='Override the AP name the seed claims (element 45 and VSP-5). --vendor cisco only.'
    ),
    ap_mac: str | None = typer.Option(
        None,
        '--ap-mac',
        help='Override the Radio MAC in the CAPWAP optional field, 12 hex digits. --vendor cisco only.'
    ),
    ap_model: str | None = typer.Option(
        None,
        '--ap-model',
        help='Override the model string in WTP Board Data sub-element 0. --vendor cisco only.'
    ),
    ap_serial: str | None = typer.Option(
        None,
        '--ap-serial',
        help='Override the serial in WTP Board Data sub-element 1. --vendor cisco only.'
    ),
    ap_base_mac: str | None = typer.Option(
        None,
        '--ap-base-mac',
        help='Override the base radio MAC in WTP Board Data sub-element 4, 12 hex digits. --vendor cisco only.'
    ),
    ap_radio_ids: str | None = typer.Option(
        None,
        '--ap-radio-ids',
        help=(
            'Comma-separated Radio IDs for the Type 1048 elements (RFC 5416 §6.25 requires 1..31). '
            'Default keeps the captured "0,1", which is non-conformant.'
        )
    ),
    num_encrypt: int | None = typer.Option(
        None,
        '--num-encrypt',
        help='WTP Descriptor Num Encrypt (RFC 5415 §4.6.41 requires 1..255). Default keeps the captured 0.'
    ),
    msg_type: int | None = typer.Option(
        None,
        '--msg-type',
        help='Seed message type: 19 = Primary Discovery Request (default), 1 = Discovery Request (§5.1).'
    ),
    omit_element: str | None = typer.Option(
        None,
        '--omit-element',
        help='Comma-separated element types to leave out of the seed, for presence/absence ablation.'
    ),
    adapt_weights: bool = typer.Option(
        False,
        '--adapt-weights/--no-adapt-weights',
        help=(
            'F: schedule mutations by observed outcomes instead of uniformly. Uses one unit per '
            'round so every sample is attributable, and writes weights.jsonl. NOTE: this breaks '
            '--seed byte-for-byte reproducibility by design.'
        )
    ),
    adapt_floor: float = typer.Option(
        0.10,
        '--adapt-floor',
        help='Minimum share of uniform probability kept for every unit (default 0.10).'
    ),
    adapt_reward: str = typer.Option(
        'response',
        '--adapt-reward',
        help='"response" (any reply counts, the default) or "valid" (RFC-shaped reply only).'
    ),
    lock_fields: str | None = typer.Option(
        None,
        '--lock-fields',
        help=(
            'Enable locked mutation mode (default: off). Comma-separated tokens name the '
            'regions to FREEZE: capwap-header, msgtype, msgelemslen, cisco-fingerprint, '
            'or "all". Each round then makes one equal-length overwrite inside a mutable '
            'span only, preserving packet length and element structure.'
        )
    ),
    vendor: str = typer.Option(
        DEFAULT_VENDOR,
        '--vendor',
        help=(
            'Vendor mode. Default: "opencapwap" (gray-box, auto-detects AC process). '
            '"cisco" for Cisco C9800 WLC. '
            '"generic" for plain black-box mode (base class, no process monitoring).'
        )
    )
):
    """Run CAPWAP Discovery fuzzing or replay records.jsonl for crash reproduction"""

    if not broadcast and not ac_ip:
        raise typer.BadParameter("Either --ac-ip (unicast) or --broadcast must be specified")

    if on_probe_fail not in ("continue", "stop"):
        raise typer.BadParameter("--on-probe-fail must be 'continue' or 'stop'")

    try:
        lock_set = parse_lock_fields(lock_fields)
    except ValueError as exc:
        raise typer.BadParameter(str(exc))

    if adapt_reward not in (weights.REWARD_RESPONSE, weights.REWARD_VALID):
        raise typer.BadParameter(
            f"--adapt-reward must be '{weights.REWARD_RESPONSE}' or '{weights.REWARD_VALID}'")
    if not 0.0 <= adapt_floor < 1.0:
        raise typer.BadParameter("--adapt-floor must be in [0, 1)")

    monitor_config = None
    if monitor_host:
        if monitor_credential_file is None:
            raise typer.BadParameter("--monitor-host requires --monitor-credential-file")
        monitor_config = monitor.MonitorConfig(
            host=monitor_host,
            user=monitor_user,
            credential_file=str(monitor_credential_file.expanduser().resolve()),
            interval=monitor_interval,
            raw=monitor_raw,
        )

    # -------------------- 种子身份参数化（E/3a，仅 Cisco）--------------------
    identity = None
    identity_overrides = {
        "--ap-name": ap_name, "--ap-mac": ap_mac, "--ap-model": ap_model,
        "--ap-serial": ap_serial, "--ap-base-mac": ap_base_mac,
        "--ap-radio-ids": ap_radio_ids, "--num-encrypt": num_encrypt,
        "--msg-type": msg_type, "--omit-element": omit_element,
    }
    if any(value is not None for value in identity_overrides.values()):
        if vendor != "cisco":
            raise typer.BadParameter(
                "seed identity options (--ap-*, --num-encrypt, --msg-type, --omit-element) "
                "only apply to --vendor cisco"
            )
        identity = _build_identity(identity_overrides)

    if seed is None:
        seed = int(time.time_ns())

    # 初始化 Fuzzer（log_dir 在内部创建）
    fuzzer_cls = get_vendor(vendor)
    if fuzzer_cls is None:
        supported = "opencapwap, cisco, generic"
        raise typer.BadParameter(f"Unknown vendor '{vendor}'. Supported: {supported}")
    fuzzer_kwargs = dict(ac_ip=ac_ip, ac_port=ac_port, timeout=timeout, broadcast=broadcast,
                         seed=seed, iface=iface, lock_fields=lock_set,
                         monitor_config=monitor_config, adaptive_weights=adapt_weights,
                         adapt_floor=adapt_floor, adapt_reward=adapt_reward)
    if vendor == "cisco":
        fuzzer_kwargs["identity"] = identity
    fuzzer = fuzzer_cls(**fuzzer_kwargs)

    # 统一配置 logging，写入 fuzzer 的 log 目录。
    # 必须先清除 root logger 上已有的 handlers（fuzzer __init__ 内的 logging 调用
    # 会触发 lastResort handler 并阻止 basicConfig 生效）。
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    log_file = fuzzer.log_dir / "fuzzer.log"
    logging.basicConfig(
        filename=str(log_file),
        filemode="w",
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    root_logger.handlers = [h for h in root_logger.handlers if isinstance(h, logging.FileHandler)]

    pcap_path = str(pcap.expanduser().resolve()) if pcap else None

    # 写 session.json（含 CLI 层参数）
    fuzzer.write_session_json(extra={
        "vendor": vendor,
        "rounds": rounds,
        "timeout": timeout,
        "sleep_per_round": sleep_per_round,
        "probe_interval": probe_interval,
        "pcap": pcap_path,
        "replay_jsonl": str(replay_jsonl) if replay_jsonl else None,
        "lock_fields": sorted(lock_set) if lock_set else None,
        "monitor": monitor_config.public_dict() if monitor_config else None,
        "forensics": forensics_enabled,
        "seed_identity": _describe_identity(identity),
        "adaptive_weights": (
            {"enabled": True, "floor": adapt_floor, "reward": adapt_reward,
             "attribution": "single_unit"} if adapt_weights else None
        ),
    })

    console.rule("[bold blue]CAPWAP Discovery Fuzzing[/bold blue]")

    if broadcast and ac_ip:
        console.print("[yellow][!] --ac-ip will be ignored in broadcast mode[/yellow]")

    console.print(f"[+] Mode      : {'Broadcast' if broadcast else 'Unicast'}")
    target = f"255.255.255.255:{ac_port}" if broadcast else f"{ac_ip}:{ac_port}"
    console.print(f"[+] Target    : {target}")
    console.print(f"[+] Rounds    : {rounds}")
    console.print(f"[*] Seed      : {seed}")
    if lock_set:
        console.print(
            f"[+] Lock      : {', '.join(sorted(lock_set))} "
            f"(equal-length value mutation only)"
        )
    if adapt_weights:
        console.print(
            f"[+] Adapt     : reward={adapt_reward} floor={adapt_floor:g} "
            f"(one unit per round; --seed reproducibility off)"
        )
    if monitor_config:
        console.print(
            f"[+] Monitor   : {monitor_config.host} as {monitor_config.user} "
            f"every {monitor_config.interval:g}s -> {fuzzer.log_dir / 'monitor.jsonl'}"
        )
    console.print(f"[+] Log dir   : {fuzzer.log_dir}")

    if pcap_path:
        console.print(f"[+] PCAP      : {pcap_path}")
    else:
        console.print("[+] Seed pkt  : random")

    if replay_jsonl:
        console.print(f"[+] Replay    : {replay_jsonl}")
        if replay_filter:
            console.print(f"[+] Filter    : response_type == {replay_filter!r}")

    logging.info("Mode: %s, Target: %s, Rounds: %d, Seed: %d", 'Broadcast' if broadcast else 'Unicast', target, rounds, seed)

    # -------------------- 启动前存活检测 --------------------
    console.print("[*] Pre-flight check: probing target AC...")
    if not fuzzer.is_target_alive(pcap_path=pcap_path):
        console.print(f"[bold red][!] Target AC {target} is not reachable or not running. Aborting.[/bold red]")
        logging.error("Pre-flight check failed: target AC %s did not respond", target)
        raise typer.Exit(code=1)
    console.print("[green][+] Target AC is alive. Starting fuzzing...[/green]")

    total_status = {"total": 0, "valid": 0, "timeout": 0, "error": 0, "error_types": {}}

    # -------------------- Replay 模式 --------------------
    if replay_jsonl:
        # Gray-box observability during replay (bug fix): start the process
        # monitor so a target death mid-replay is captured in
        # process_monitor.csv instead of replay silently exiting 0.
        if isinstance(fuzzer, OpenCAPWAPFuzzer):
            fuzzer.start_process_monitor()
        fuzzer.start_monitor()
        filter_fn = (lambda r: r.get("response_type") == replay_filter) if replay_filter else None
        console.print(f"[cyan][*] Replaying records from {replay_jsonl}...[/cyan]")
        results = fuzzer.replay_requests_from_jsonl(str(replay_jsonl), filter_fn=filter_fn)
        for _record, resp_type, error_type in results:
            total_status[resp_type] = total_status.get(resp_type, 0) + 1
            if error_type:
                total_status["error_types"].setdefault(error_type, 0)
                total_status["error_types"][error_type] += 1
            total_status["total"] += 1
        console.print(f"[green][+] Replayed {len(results)} records.[/green]")

        # Bug fix: detect a target that died during replay (previously replay
        # exited 0 with no crash artifacts even after killing the target).
        fuzzer.stop_monitor()
        if isinstance(fuzzer, OpenCAPWAPFuzzer):
            fuzzer.stop_process_monitor()
            if fuzzer.is_process_alive() is False:
                crash_round = results[-1][0].get("round") if results else None
                crash_report = {
                    "crash_detected_at_round": crash_round,
                    "context": "replay",
                    "probe_attempts": 0,
                    "ac_ip": ac_ip,
                    "ac_port": ac_port,
                    "timestamp": datetime.now().isoformat(),
                    "total_status": total_status,
                }
                report_path = fuzzer.log_dir / "crash_report.json"
                with open(report_path, "w") as f:
                    json.dump(crash_report, f, indent=2, default=str)
                console.print(f"[bold red][!] AC process died during replay — crash report saved to {report_path}[/bold red]")
                fuzzer.write_crash_sequence(last_n=50)
                fuzzer.write_summary(total_status, crash_at_round=crash_round)
                _collect_forensics(
                    fuzzer, reason="crash", round_number=crash_round, status=total_status,
                    probe={"context": "replay", "probe_attempts": 0}, enabled=forensics_enabled,
                )
                sys.exit(2)

    # -------------------- Fuzzing 模式 --------------------
    else:
        # 启动进程监控侧车（仅 OpenCAPWAPFuzzer 有此方法）
        # Start process monitor sidecar (only available on OpenCAPWAPFuzzer)
        if isinstance(fuzzer, OpenCAPWAPFuzzer):
            fuzzer.start_process_monitor()
        fuzzer.start_monitor()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:

            task = progress.add_task('[bold cyan]Fuzzing CAPWAP Discovery[/bold cyan]', total=rounds)

            crash_error: CrashDetectedError | None = None

            # Probe failure tracking for "continue" mode
            # "continue" 模式下的探测失败状态跟踪
            consecutive_probe_failures = 0
            suspected_recorded = False          # suspected_event.json 只写一次
            first_fail_round: int | None = None
            MAX_CONSECUTIVE_FAILURES = 3        # 连续失败超过此值视为 crash

            def _record_local_evidence(reason: str, rnd: int, probe_info: dict) -> None:
                """Write local evidence at the first liveness failure.

                Local only: this runs inside the fuzzing loop, so it must stay
                fast. The full local + device collection happens on a confirmed
                crash (see the crash-report block below).
                """
                if not forensics_enabled:
                    return
                try:
                    forensics.write_local_evidence(
                        fuzzer.log_dir, reason=reason, round_number=rnd,
                        status=total_status, probe=probe_info,
                        extra={"monitor_summary": fuzzer.monitor_summary()},
                    )
                except Exception as exc:  # noqa: BLE001 - evidence must not break the loop
                    logging.warning("local evidence failed: %s", exc)

            for i in range(rounds):
                try:
                    logging.info(f"Starting round {i + 1}/{rounds}")

                    # -------------------- 存活探测 --------------------
                    if probe_interval > 0 and i > 0 and i % probe_interval == 0:
                        logging.info("Probe check at round %d", i + 1)
                        alive = fuzzer.is_target_alive(pcap_path=pcap_path)

                        if not alive:
                            if on_probe_fail == "stop":
                                # 原有行为：立即停止
                                raise CrashDetectedError(
                                    f"Target stopped responding after round {i}",
                                    round_number=i,
                                    probe_attempts=3,
                                    ac_ip=ac_ip,
                                    ac_port=ac_port,
                                )

                            # continue 模式：区分 DoS（进程存活）和 Crash（进程死亡）
                            proc_alive = fuzzer.is_process_alive()

                            if proc_alive is False:
                                # 进程已死亡 → 确认 Crash，立即停止
                                raise CrashDetectedError(
                                    f"AC process is gone at round {i + 1} (confirmed crash)",
                                    round_number=i,
                                    probe_attempts=3,
                                    ac_ip=ac_ip,
                                    ac_port=ac_port,
                                )
                            elif proc_alive is True:
                                # 进程存活但无 UDP 回包 → DoS / 死锁，记录并继续
                                if not suspected_recorded:
                                    first_fail_round = i
                                    fuzzer.write_suspected_event(round_number=i, total_status=total_status)
                                    suspected_recorded = True
                                    _record_local_evidence(
                                        "dos_suspected", i,
                                        {"alive": False, "proc_alive": proc_alive},
                                    )
                                    progress.console.print(
                                        f"[yellow][!] Probe failed at round {i + 1} — "
                                        f"process alive, no UDP reply → DoS suspected, continuing...[/yellow]"
                                    )
                                    logging.warning(
                                        "Probe failed at round %d — process alive, no UDP → DoS suspected",
                                        i + 1
                                    )
                                else:
                                    progress.console.print(
                                        f"[yellow][!] Still no UDP reply at round {i + 1} "
                                        f"(process alive — DoS ongoing)[/yellow]"
                                    )
                                    logging.warning(
                                        "No UDP reply at round %d (process alive — DoS ongoing)", i + 1
                                    )
                                # DoS 不计入 consecutive_probe_failures，继续 fuzzing
                            else:
                                # proc_alive is None：黑盒模式，无法判断进程状态，沿用旧逻辑
                                consecutive_probe_failures += 1
                                if not suspected_recorded:
                                    first_fail_round = i
                                    fuzzer.write_suspected_event(round_number=i, total_status=total_status)
                                    suspected_recorded = True
                                    _record_local_evidence(
                                        "dos_suspected", i,
                                        {"alive": False, "proc_alive": proc_alive},
                                    )
                                    progress.console.print(
                                        f"[yellow][!] Probe failed at round {i + 1} "
                                        f"(consecutive: {consecutive_probe_failures}) — "
                                        f"suspected crash/DoS, continuing...[/yellow]"
                                    )
                                    logging.warning(
                                        "Probe failed at round %d (consecutive: %d) — suspected crash/DoS",
                                        i + 1, consecutive_probe_failures
                                    )
                                else:
                                    progress.console.print(
                                        f"[yellow][!] Probe still failing at round {i + 1} "
                                        f"(consecutive: {consecutive_probe_failures})[/yellow]"
                                    )
                                    logging.warning(
                                        "Probe still failing at round %d (consecutive: %d)",
                                        i + 1, consecutive_probe_failures
                                    )

                                if consecutive_probe_failures >= MAX_CONSECUTIVE_FAILURES:
                                    raise CrashDetectedError(
                                        f"Target failed {MAX_CONSECUTIVE_FAILURES} consecutive probes "
                                        f"(first at round {first_fail_round})",
                                        round_number=first_fail_round,
                                        probe_attempts=3,
                                        ac_ip=ac_ip,
                                        ac_port=ac_port,
                                    )

                        else:
                            # 探测成功
                            if consecutive_probe_failures > 0 or suspected_recorded:
                                progress.console.print(
                                    f"[green][+] Target recovered at round {i + 1} — likely DoS, not crash[/green]"
                                )
                                logging.info(
                                    "Target recovered at round %d — likely DoS", i + 1
                                )
                                if suspected_recorded:
                                    fuzzer.update_suspected_event_recovered(round_number=i)
                            consecutive_probe_failures = 0

                    status = fuzzer.fuzzing(pcap_path=pcap_path, round_number=i + 1)
                    for k in ("valid", "timeout", "error", "total"):
                        total_status[k] += status.get(k, 0)
                    for etype, count in status.get("error_types", {}).items():
                        total_status["error_types"].setdefault(etype, 0)
                        total_status["error_types"][etype] += count

                except CrashDetectedError as e:
                    progress.console.print(f"[bold red][!] CRASH DETECTED at round {i + 1}: {e}[/bold red]")
                    logging.error("Crash detected at round %d: %s", i + 1, e)
                    crash_error = e
                    progress.advance(task, 1)
                    break

                except Exception as e:
                    progress.console.print(f"[red][-] Round {i + 1} error: {e}[/red]")
                    logging.exception(f"Round {i + 1} failed: {e}")

                finally:
                    if crash_error is None:
                        progress.advance(task, 1)
                    time.sleep(sleep_per_round)

        # -------------------- 停止进程监控 / 灰盒采样 --------------------
        if isinstance(fuzzer, OpenCAPWAPFuzzer):
            fuzzer.stop_process_monitor()
        fuzzer.stop_monitor()

        # -------------------- Crash 报告 --------------------
        if crash_error is not None:
            crash_report = {
                "crash_detected_at_round": crash_error.round_number,
                "probe_attempts": crash_error.probe_attempts,
                "ac_ip": crash_error.ac_ip,
                "ac_port": crash_error.ac_port,
                "timestamp": datetime.now().isoformat(),
                "total_status": total_status,
            }
            report_path = fuzzer.log_dir / "crash_report.json"
            with open(report_path, "w") as f:
                json.dump(crash_report, f, indent=2, default=str)
            console.print(f"[bold red][!] Crash report saved to {report_path}[/bold red]")
            fuzzer.write_crash_sequence(last_n=50)
            console.print(f"[bold red][!] Crash sequence saved to {fuzzer.log_dir / 'crash_sequence.jsonl'}[/bold red]")
            fuzzer.write_summary(total_status, crash_at_round=crash_error.round_number)
            _collect_forensics(
                fuzzer, reason="crash", round_number=crash_error.round_number,
                status=total_status,
                probe={
                    "alive": False,
                    "probe_attempts": crash_error.probe_attempts,
                    "ac_ip": crash_error.ac_ip,
                    "ac_port": crash_error.ac_port,
                },
                enabled=forensics_enabled,
            )
            sys.exit(2)

    # -------------------- 汇总统计 --------------------
    fuzzer.write_summary(total_status)

    summary_table = Table(title="CAPWAP Fuzzing Summary")
    summary_table.add_column("Type", style="bold")
    summary_table.add_column("Count", justify="right")
    for k in ("valid", "timeout", "error", "total"):
        summary_table.add_row(k, str(total_status.get(k, 0)))
    console.print(summary_table)

    if total_status["error_types"]:
        error_table = Table(title="Error Type Distribution")
        error_table.add_column("Error Type", style="bold red")
        error_table.add_column("Count", justify="right")
        for etype, count in sorted(total_status["error_types"].items(), key=lambda x: x[1], reverse=True):
            error_table.add_row(etype, str(count))
        console.print(error_table)

    console.print(f"[dim]Records : {fuzzer.records_path}[/dim]")
    console.print(f"[dim]Summary : {fuzzer.log_dir / 'summary.json'}[/dim]")


def main():
    app()


if __name__ == "__main__":
    main()
