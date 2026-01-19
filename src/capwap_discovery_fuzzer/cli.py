"""Console script for capwap_discovery_fuzzer."""

import typer
from rich.console import Console
import random as rd
from capwap_discovery_fuzzer import utils
from .capwap_discovery_fuzzer import CAPWAPDiscoveryFuzzer
from pathlib import Path
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
import time
import capwap_discovery_fuzzer as cdf
import random
import logging
from datetime import datetime

app = typer.Typer()
console = Console()
DEFAULT_PCAP = 'pcaps/sample_discovery_request.pcap'

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
        help='Rounds of fuzzing iterations'
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
    )
):
    """
    Run a CAPWAP Discovery Request fuzzing (unicast or broadcast)
    """
    LOG_DIR = Path("./capwap_log")
    LOG_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    LOG_FILE = LOG_DIR / f"{timestamp}.log"

    logging.basicConfig(
        filename=str(LOG_FILE),
        filemode="w",
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    if not broadcast and not ac_ip:
        raise typer.BadParameter(
            "Either --ac-ip (unicast) or --broadcast must be specified"
        )

    if broadcast and ac_ip:
        console.print(
            "[yellow][!] --ac-ip will be ignored in broadcast mode[/yellow]"
        )
    pcap_path = None
    if pcap is not None:
        pcap = pcap.expanduser().resolve()
        pcap_path = str(pcap)

    console.rule('[bold blue]CAPWAP Discovery Fuzzing[/bold blue]')
    logging.info("=== CAPWAP Discovery Fuzzing ===")

    if pcap is not None:
        msg = f"PCAP file : {pcap}"
        console.print(f'[+] {msg}')
        logging.info(msg)
    else:
        msg = "Using Random Discovery Request"
        console.print(f'[+] {msg}')
        logging.info(msg)

    mode = "Broadcast" if broadcast else "Unicast"
    console.print(f'[+] Mode      : {mode}')
    logging.info("Mode: %s", mode)

    if broadcast:
        target = f"255.255.255.255:{ac_port}"
    else:
        target = f"{ac_ip}:{ac_port}"

    console.print(f'[+] Target    : {target}')
    logging.info("Target: %s", target)

    console.print(f'[+] Rounds    : {rounds}')
    logging.info("Rounds: %d", rounds)

    if seed is not None:
        console.print(f"[*] Using random seed: {seed}")
        logging.info("Using random seed: %d", seed)
    else:
        seed = int(time.time_ns())
        console.print(f"[*] Using random seed: {seed}")
        logging.info("Generated random seed: %d", seed)

    
    # 构造 Fuzzer
    fuzzer = CAPWAPDiscoveryFuzzer(
        ac_ip=ac_ip,
        ac_port=ac_port,
        timeout=timeout,
        broadcast=broadcast,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:

        total_status = {
            "total": 0,
            "valid": 0,
            "timeout": 0,
        }

        task = progress.add_task(
            '[bold cyan]Fuzzing CAPWAP Discovery[/bold cyan]',
            total=rounds
        )

        for i in range(rounds):
            try:
                status = fuzzer.fuzzing(pcap_path)
                for k in total_status:
                    total_status[k] += status.get(k, 0)

            except Exception as e:
                progress.console.print(
                    f'[red][-] Round {i + 1} error : {e}[/red]'
                )

            finally:
                progress.advance(task, 1)
                time.sleep(2)

        table = Table(title="CAPWAP Fuzzing Summary")
        table.add_column("Type", style="bold")
        table.add_column("Count", justify="right")

        for k in ("valid", "timeout", "total"):
            table.add_row(k, str(total_status[k]))

        console.print(table)



def main():
    app()


if __name__ == "__main__":
    main()
