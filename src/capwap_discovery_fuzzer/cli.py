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

app = typer.Typer()
console = Console()
DEFAULT_PCAP = 'pcaps/sample_discovery_request.pcap'

@app.command()
def fuzz(
    pcap: Path = typer.Option(
        DEFAULT_PCAP,
        '--pcap',
        exists=True,
        readable=True,
        help='PCAP file containing only one CAPWAP Discovery Request message'
    ),
    ac_ip: str = typer.Option(
        ...,
        '--ac-ip',
        help='Target AC IP address'
    ),
    ac_port: int = typer.Option(
        5246,
        '--ac-port',
        help='Target AC control port(default 5246)'
    ),
    rounds: int = typer.Option(
        1,
        '--rounds',
        help='Rounds of fuzzing iterations'
    ),
    seed: int = typer.Option(
        None,
        '--seed',
        help='Radom Seed for fuzzing'
    ),
    timeout: float = typer.Option(
        3.0,
        '--timeout',
        help='Limit Time for waiting for response'
    )
):
    """
    Run a simple CAPWAP Discovery Request fuzzing
    """
    pcap = pcap.expanduser().resolve()
    console.rule('[bold blue]CAPWAP Discovery Fuzzing[/bold blue]')
    console.print(f'[+] PCAP file : {pcap}')
    console.print(f'[+] Target AC : {ac_ip}:{ac_port}')
    console.print(f'[+] Rounds    : {rounds}')
    if seed is not None:
        console.print(f"[*] Using random seed: {seed}")

    fuzzer = CAPWAPDiscoveryFuzzer(
        ac_ip=ac_ip,
        ac_port=ac_port,
        timeout=timeout,
        seed=seed
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
            "invalid": 0,
            "timeout": 0,
        }

        task = progress.add_task(
            '[bold cyan]Fuzzing CAPWAP Discovey[/bold cyan]',
            total=rounds
        )
        for i in range(0, rounds):
            try:
                status = fuzzer.simple_fuzzing_with_pcap(str(pcap))
                for k in total_status:
                    total_status[k] += status.get(k, 0)
            except Exception as e:
                progress.console.print(f'[red][-] Round {i+1} error : {e}[/red]')
            finally:
                progress.advance(task, 1)
                time.sleep(2)
        table = Table(title="CAPWAP Fuzzing Summary")
        table.add_column("Type", style="bold")
        table.add_column("Count", justify="right")

        for k in ("valid", "invalid", "timeout", "total"):
            table.add_row(k, str(total_status[k]))

        console.print(table)




def main():
    app()


if __name__ == "__main__":
    main()
