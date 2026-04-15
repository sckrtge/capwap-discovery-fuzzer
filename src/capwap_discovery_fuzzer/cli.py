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
from .vendors import get_vendor, DEFAULT_VENDOR
from .vendors.opencapwap.fuzzer import OpenCAPWAPFuzzer

app = typer.Typer()
console = Console()


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

    if seed is None:
        seed = int(time.time_ns())

    # 初始化 Fuzzer（log_dir 在内部创建）
    fuzzer_cls = get_vendor(vendor)
    if fuzzer_cls is None:
        supported = "opencapwap, cisco, generic"
        raise typer.BadParameter(f"Unknown vendor '{vendor}'. Supported: {supported}")
    fuzzer = fuzzer_cls(ac_ip=ac_ip, ac_port=ac_port, timeout=timeout, broadcast=broadcast, seed=seed, iface=iface)

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
    })

    console.rule("[bold blue]CAPWAP Discovery Fuzzing[/bold blue]")

    if broadcast and ac_ip:
        console.print("[yellow][!] --ac-ip will be ignored in broadcast mode[/yellow]")

    console.print(f"[+] Mode      : {'Broadcast' if broadcast else 'Unicast'}")
    target = f"255.255.255.255:{ac_port}" if broadcast else f"{ac_ip}:{ac_port}"
    console.print(f"[+] Target    : {target}")
    console.print(f"[+] Rounds    : {rounds}")
    console.print(f"[*] Seed      : {seed}")
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

    # -------------------- Fuzzing 模式 --------------------
    else:
        # 启动进程监控侧车（仅 OpenCAPWAPFuzzer 有此方法）
        # Start process monitor sidecar (only available on OpenCAPWAPFuzzer)
        if isinstance(fuzzer, OpenCAPWAPFuzzer):
            fuzzer.start_process_monitor()

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

                            # continue 模式
                            consecutive_probe_failures += 1
                            if not suspected_recorded:
                                # 第一次失败：写 suspected_event.json，仅此一次
                                first_fail_round = i
                                fuzzer.write_suspected_event(round_number=i, total_status=total_status)
                                suspected_recorded = True
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
                                # 连续失败达阈值，视为 crash，停止
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
                            if consecutive_probe_failures > 0:
                                # 之前失败过，现在恢复 → DoS 而非 Crash
                                progress.console.print(
                                    f"[green][+] Target recovered at round {i + 1} "
                                    f"after {consecutive_probe_failures} failed probe(s) — "
                                    f"likely DoS, not crash[/green]"
                                )
                                logging.info(
                                    "Target recovered at round %d after %d failure(s) — likely DoS",
                                    i + 1, consecutive_probe_failures
                                )
                                fuzzer.update_suspected_event_recovered(round_number=i)
                            consecutive_probe_failures = 0

                    status = fuzzer.fuzzing()
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

        # -------------------- 停止进程监控 --------------------
        if isinstance(fuzzer, OpenCAPWAPFuzzer):
            fuzzer.stop_process_monitor()

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
