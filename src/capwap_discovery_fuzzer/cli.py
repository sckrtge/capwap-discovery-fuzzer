import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from pathlib import Path
from datetime import datetime
import time
import logging

from .capwap_discovery_fuzzer import CAPWAPDiscoveryFuzzer

app = typer.Typer()
console = Console()
DEFAULT_PCAP = Path('pcaps/sample_discovery_request.pcap')


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
    )
):
    """Run CAPWAP Discovery fuzzing"""

    # 初始化日志目录
    LOG_DIR_ROOT = Path("./capwap_log")
    LOG_DIR_ROOT.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = LOG_DIR_ROOT / timestamp
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "fuzzer.log"

    logging.basicConfig(
        filename=str(log_file),
        filemode="w",
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # PCAP路径
    pcap_path = pcap.expanduser().resolve() if pcap else None

    if not broadcast and not ac_ip:
        raise typer.BadParameter("Either --ac-ip (unicast) or --broadcast must be specified")
    if broadcast and ac_ip:
        msg = "--ac-ip will be ignored in broadcast mode"
        console.print(f"[yellow][!] {msg}[/yellow]")
        logging.warning(msg)

    console.rule("[bold blue]CAPWAP Discovery Fuzzing[/bold blue]")

    if pcap_path:
        msg = f"PCAP file: {pcap_path}"
        console.print(f"[+] {msg}")
        logging.info(msg)
    else:
        msg = "Using Random Discovery Request"
        console.print(f"[+] {msg}")
        logging.info(msg)

    mode = "Broadcast" if broadcast else "Unicast"
    console.print(f"[+] Mode      : {mode}")
    logging.info("Mode: %s", mode)

    target = f"255.255.255.255:{ac_port}" if broadcast else f"{ac_ip}:{ac_port}"
    console.print(f"[+] Target    : {target}")
    logging.info("Target: %s", target)

    console.print(f"[+] Rounds    : {rounds}")
    logging.info("Rounds: %d", rounds)

    if seed is None:
        seed = int(time.time_ns())
    console.print(f"[*] Using random seed: {seed}")
    logging.info("Random seed: %d", seed)

    # 初始化 Fuzzer
    fuzzer = CAPWAPDiscoveryFuzzer(ac_ip=ac_ip, ac_port=ac_port, timeout=timeout, broadcast=broadcast, seed=seed)

    total_status = {
        "total": 0,
        "valid": 0,
        "timeout": 0,
        "error": 0,
        "error_types": {}
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:

        task = progress.add_task('[bold cyan]Fuzzing CAPWAP Discovery[/bold cyan]', total=rounds)

        for i in range(rounds):
            try:
                status = fuzzer.fuzzing(pcap_path)

                # 更新总统计
                for k in ("valid", "timeout", "error", "total"):
                    total_status[k] += status.get(k, 0)
                # 合并 error_type 统计
                for etype, count in status.get("error_types", {}).items():
                    total_status["error_types"].setdefault(etype, 0)
                    total_status["error_types"][etype] += count

            except Exception as e:
                progress.console.print(f"[red][-] Round {i + 1} error: {e}[/red]")
                logging.exception(f"Fuzz iteration {i + 1} failed: {e}")

            finally:
                progress.advance(task, 1)
                time.sleep(sleep_per_round)

    # 输出总统计表
    summary_table = Table(title="CAPWAP Fuzzing Summary")
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