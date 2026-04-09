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
    replay_json_dir: Path | None = typer.Option(
        None,
        '--replay-json-dir',
        exists=True,
        file_okay=False,
        dir_okay=True,
        help='Directory containing JSON request logs to replay instead of fuzzing'
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
    )
):
    """Run CAPWAP Discovery fuzzing or replay JSON requests for crash reproduction"""

    if not broadcast and not ac_ip:
        raise typer.BadParameter("Either --ac-ip (unicast) or --broadcast must be specified")

    if seed is None:
        seed = int(time.time_ns())

    # 初始化 Fuzzer（log_dir 在内部创建）
    fuzzer = CAPWAPDiscoveryFuzzer(ac_ip=ac_ip, ac_port=ac_port, timeout=timeout, broadcast=broadcast, seed=seed, iface=iface)

    # 统一配置 logging，写入 fuzzer 的 log 目录
    log_file = fuzzer.log_dir / "fuzzer.log"
    logging.basicConfig(
        filename=str(log_file),
        filemode="w",
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    # 禁止 logging 向 stderr 输出，所有日志只写文件
    logging.getLogger().handlers = [h for h in logging.getLogger().handlers if isinstance(h, logging.FileHandler)]

    pcap_path = pcap.expanduser().resolve() if pcap else None

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

    if replay_json_dir:
        console.print(f"[+] Replay dir: {replay_json_dir}")

    logging.info("Mode: %s, Target: %s, Rounds: %d, Seed: %d", 'Broadcast' if broadcast else 'Unicast', target, rounds, seed)

    # -------------------- 启动前存活检测 --------------------
    console.print("[*] Pre-flight check: probing target AC...")
    if not fuzzer.is_target_alive():
        console.print(f"[bold red][!] Target AC {target} is not reachable or not running. Aborting.[/bold red]")
        logging.error("Pre-flight check failed: target AC %s did not respond", target)
        raise typer.Exit(code=1)
    console.print("[green][+] Target AC is alive. Starting fuzzing...[/green]")

    total_status = {"total": 0, "valid": 0, "timeout": 0, "error": 0, "error_types": {}}

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

        for i in range(rounds):
            try:
                logging.info(f"Starting round {i + 1}/{rounds}")

                # -------------------- Crash 探测 --------------------
                if probe_interval > 0 and i > 0 and i % probe_interval == 0:
                    logging.info("Probe check at round %d", i + 1)
                    if not fuzzer.is_target_alive():
                        raise CrashDetectedError(
                            f"Target stopped responding after round {i}",
                            round_number=i,
                            probe_attempts=3,
                            ac_ip=ac_ip,
                            ac_port=ac_port,
                        )

                # -------------------- JSON Replay 模式 --------------------
                if replay_json_dir:
                    json_files = sorted(replay_json_dir.glob("*.json"))
                    for json_file in json_files:
                        logging.info(f"Replaying JSON request: {json_file}")
                        pkt, resp, resp_type, error_type = fuzzer.replay_request_from_json(json_file)
                        total_status[resp_type] += 1
                        if error_type:
                            total_status["error_types"].setdefault(error_type, 0)
                            total_status["error_types"][error_type] += 1
                        total_status["total"] += 1

                # -------------------- 原版 Fuzzing 模式 --------------------
                else:
                    status = fuzzer.fuzzing(pcap_path)
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
        sys.exit(2)

    # 输出总统计表
    summary_table = Table(title="CAPWAP Fuzzing/Replay Summary")
    summary_table.add_column("Type", style="bold")
    summary_table.add_column("Count", justify="right")
    for k in ("valid", "timeout", "error", "total"):
        summary_table.add_row(k, str(total_status.get(k, 0)))
    console.print(summary_table)

    # 输出错误类型统计（按数量排序）
    if total_status["error_types"]:
        error_table = Table(title="Error Type Distribution")
        error_table.add_column("Error Type", style="bold red")
        error_table.add_column("Count", justify="right")
        for etype, count in sorted(total_status["error_types"].items(), key=lambda x: x[1], reverse=True):
            error_table.add_row(etype, str(count))
        console.print(error_table)


def main():
    app()


if __name__ == "__main__":
    main()
