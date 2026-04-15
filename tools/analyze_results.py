#!/usr/bin/env python3
"""analyze_results.py — Single-session analysis and chart generation.

Usage:
    python tools/analyze_results.py <log_dir> [--out <output_dir>]

Reads one capwap_log/<timestamp>/ directory and produces:
    1. response_type_pie.png      — valid / timeout / error distribution
    2. method_effectiveness.png   — per-method error / timeout / valid counts
    3. response_time_series.png   — elapsed_ms over rounds
    4. process_memory.png         — vmrss_kb and vmvirt_kb over time (gray-box only)
    5. process_cpu.png            — cpu_percent over time (gray-box only)
    6. error_type_bar.png         — error type distribution (if any errors)

All charts are saved to <output_dir> (default: <log_dir>/charts/).
A summary of key findings is printed to stdout.

读取单个 capwap_log/<timestamp>/ 目录，生成以上图表。
"""

import argparse
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")   # headless rendering / 无头渲染
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import pandas as pd


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_records(log_dir: Path) -> pd.DataFrame:
    path = log_dir / "records.jsonl"
    if not path.exists():
        return pd.DataFrame()
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def load_summary(log_dir: Path) -> dict:
    path = log_dir / "summary.json"
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def load_process_monitor(log_dir: Path) -> pd.DataFrame | None:
    path = log_dir / "process_monitor.csv"
    if not path.exists():
        return None
    df = pd.read_csv(path, parse_dates=["timestamp"])
    df["vmrss_mb"] = df["vmrss_kb"] / 1024
    df["vmvirt_mb"] = df["vmvirt_kb"] / 1024
    return df


def load_session(log_dir: Path) -> dict:
    path = log_dir / "session.json"
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Chart helpers
# ---------------------------------------------------------------------------

COLORS = {
    "valid":   "#2ecc71",
    "timeout": "#f39c12",
    "error":   "#e74c3c",
}


def _save(fig, path: Path, title: str):
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  [+] {title} → {path.name}")


# ---------------------------------------------------------------------------
# Chart 1: Response type pie
# ---------------------------------------------------------------------------

def chart_response_pie(summary: dict, out_dir: Path):
    counts = {k: summary.get(k, 0) for k in ("valid", "timeout", "error")}
    total = sum(counts.values())
    if total == 0:
        print("  [!] No response data for pie chart, skipping")
        return

    labels, sizes, colors = [], [], []
    for k, v in counts.items():
        if v > 0:
            labels.append(f"{k}\n{v} ({v/total*100:.1f}%)")
            sizes.append(v)
            colors.append(COLORS[k])

    fig, ax = plt.subplots(figsize=(6, 6))
    ax.pie(sizes, labels=labels, colors=colors,
           autopct=None, startangle=90,
           wedgeprops={"edgecolor": "white", "linewidth": 1.5})
    ax.set_title(f"Response Type Distribution\n(total={total})", fontsize=13)
    _save(fig, out_dir / "response_type_pie.png", "Response type pie")


# ---------------------------------------------------------------------------
# Chart 2: Method effectiveness horizontal bar
# ---------------------------------------------------------------------------

def chart_method_effectiveness(summary: dict, out_dir: Path):
    me = summary.get("method_effectiveness", {})
    if not me:
        print("  [!] No method_effectiveness data, skipping")
        return

    # Sort by total uses descending
    methods = sorted(me.items(), key=lambda x: x[1].get("uses", 0), reverse=True)
    # Limit to top 25 for readability
    methods = methods[:25]

    names = [m[0] for m in methods]
    valids   = [m[1].get("valid", 0)   for m in methods]
    timeouts = [m[1].get("timeout", 0) for m in methods]
    errors   = [m[1].get("error", 0)   for m in methods]

    y = range(len(names))
    fig, ax = plt.subplots(figsize=(10, max(5, len(names) * 0.4)))
    ax.barh(y, errors,   color=COLORS["error"],   label="error",   left=[v+t for v,t in zip(valids, timeouts)])
    ax.barh(y, timeouts, color=COLORS["timeout"], label="timeout", left=valids)
    ax.barh(y, valids,   color=COLORS["valid"],   label="valid")
    ax.set_yticks(list(y))
    ax.set_yticklabels(names, fontsize=8)
    ax.set_xlabel("Number of rounds used in")
    ax.set_title("Mutation Method Effectiveness (top 25 by usage)", fontsize=12)
    ax.legend(loc="lower right")
    ax.invert_yaxis()
    _save(fig, out_dir / "method_effectiveness.png", "Method effectiveness")


# ---------------------------------------------------------------------------
# Chart 3: Response time series
# ---------------------------------------------------------------------------

def chart_response_time(df: pd.DataFrame, summary: dict, out_dir: Path):
    if df.empty or "elapsed_ms" not in df.columns:
        print("  [!] No elapsed_ms data, skipping")
        return

    # One row per round (records.jsonl has MUTATION_COUNT=1, so round≈row)
    df_plot = df[df["elapsed_ms"].notna()].copy()
    if df_plot.empty:
        return

    fig, ax = plt.subplots(figsize=(12, 4))

    # Colour points by response type
    for rt, colour in COLORS.items():
        sub = df_plot[df_plot["response_type"] == rt]
        if not sub.empty:
            ax.scatter(sub["round"], sub["elapsed_ms"], c=colour,
                       s=8, alpha=0.6, label=rt, zorder=3)

    # Rolling mean (window=20)
    if len(df_plot) >= 20:
        rolling = df_plot.set_index("round")["elapsed_ms"].rolling(20, min_periods=5).mean()
        ax.plot(rolling.index, rolling.values, color="navy",
                linewidth=1.2, label="rolling mean (20)", zorder=4)

    # Mark crash round if present
    crash_round = summary.get("crash_at_round")
    if crash_round:
        ax.axvline(crash_round, color="red", linestyle="--",
                   linewidth=1.5, label=f"crash @ round {crash_round}")

    ax.set_xlabel("Round")
    ax.set_ylabel("Elapsed (ms)")
    ax.set_title("Response Time per Round", fontsize=12)
    ax.legend(markerscale=2, fontsize=8)
    ax.yaxis.set_minor_locator(ticker.AutoMinorLocator())
    _save(fig, out_dir / "response_time_series.png", "Response time series")


# ---------------------------------------------------------------------------
# Chart 4 & 5: Process memory and CPU (gray-box only)
# ---------------------------------------------------------------------------

def chart_process_memory(pm: pd.DataFrame, summary: dict, out_dir: Path):
    if pm is None or pm.empty:
        return

    crash_round = summary.get("crash_at_round")

    fig, ax = plt.subplots(figsize=(12, 4))
    ax.plot(pm["round"], pm["vmrss_mb"], color="#3498db",
            linewidth=1.2, label="VmRSS (physical, MB)")
    ax.plot(pm["round"], pm["vmvirt_mb"], color="#9b59b6",
            linewidth=1.0, linestyle="--", label="VmSize (virtual, MB)", alpha=0.7)

    if crash_round:
        ax.axvline(crash_round, color="red", linestyle="--",
                   linewidth=1.5, label=f"crash @ round {crash_round}")

    ax.set_xlabel("Round")
    ax.set_ylabel("Memory (MB)")
    ax.set_title("AC Process Memory Usage over Rounds", fontsize=12)
    ax.legend(fontsize=9)
    _save(fig, out_dir / "process_memory.png", "Process memory")


def chart_process_cpu(pm: pd.DataFrame, summary: dict, out_dir: Path):
    if pm is None or pm.empty:
        return
    if "cpu_percent" not in pm.columns or pm["cpu_percent"].isna().all():
        return

    crash_round = summary.get("crash_at_round")

    fig, ax = plt.subplots(figsize=(12, 4))
    ax.plot(pm["round"], pm["cpu_percent"].fillna(0),
            color="#e67e22", linewidth=1.0, alpha=0.8, label="CPU %")

    # Rolling mean
    rolling = pm["cpu_percent"].fillna(0).rolling(10, min_periods=3).mean()
    ax.plot(pm["round"], rolling, color="darkred",
            linewidth=1.5, label="rolling mean (10s)")

    if crash_round:
        ax.axvline(crash_round, color="red", linestyle="--",
                   linewidth=1.5, label=f"crash @ round {crash_round}")

    ax.set_xlabel("Round")
    ax.set_ylabel("CPU %")
    ax.set_title("AC Process CPU Usage over Rounds", fontsize=12)
    ax.legend(fontsize=9)
    _save(fig, out_dir / "process_cpu.png", "Process CPU")


# ---------------------------------------------------------------------------
# Chart 6: Error type distribution
# ---------------------------------------------------------------------------

def chart_error_types(summary: dict, out_dir: Path):
    et = summary.get("error_types", {})
    et = {k: v for k, v in et.items() if v > 0}
    if not et:
        print("  [!] No error types recorded, skipping error_type_bar")
        return

    items = sorted(et.items(), key=lambda x: x[1], reverse=True)
    names = [i[0] for i in items]
    counts = [i[1] for i in items]

    fig, ax = plt.subplots(figsize=(max(6, len(names) * 1.2), 5))
    bars = ax.bar(range(len(names)), counts, color="#e74c3c", edgecolor="white")
    ax.bar_label(bars, padding=3, fontsize=9)
    ax.set_xticks(range(len(names)))
    ax.set_xticklabels(names, rotation=30, ha="right", fontsize=9)
    ax.set_ylabel("Count")
    ax.set_title("Error Type Distribution", fontsize=12)
    _save(fig, out_dir / "error_type_bar.png", "Error type bar")


# ---------------------------------------------------------------------------
# Text summary
# ---------------------------------------------------------------------------

def print_summary(log_dir: Path, summary: dict, df: pd.DataFrame, session: dict, pm):
    print("\n" + "=" * 60)
    print(f"Session : {log_dir.name}")
    print(f"Target  : {session.get('target_ip', 'N/A')}:{session.get('target_port', 'N/A')}")
    print(f"Vendor  : {session.get('vendor', 'N/A')}")
    print(f"Seed    : {session.get('seed', 'N/A')}")
    print(f"Rounds  : {summary.get('total', 0)}")
    print("-" * 60)

    total = summary.get("total", 0)
    for rt in ("valid", "timeout", "error"):
        n = summary.get(rt, 0)
        pct = f"{n/total*100:.1f}%" if total else "—"
        print(f"  {rt:<10} {n:>6}  ({pct})")

    print("-" * 60)

    # Crash info
    if summary.get("crash_detected"):
        print(f"  CRASH detected at round {summary.get('crash_at_round', '?')}")
        top = summary.get("top_crash_methods", [])
        if top:
            print(f"  Top methods before crash: {', '.join(top)}")
    else:
        print("  No crash detected")

    # Response time trend
    trend = summary.get("response_time_trend", {})
    if trend:
        ratio = trend.get("degradation_ratio")
        print(f"  Response time — first 50 mean: {trend.get('first_50_rounds_mean_ms')} ms  "
              f"last 50 mean: {trend.get('last_50_rounds_mean_ms')} ms  "
              f"ratio: {ratio}x")

    # Memory trend (gray-box)
    if pm is not None and not pm.empty and "vmrss_mb" in pm.columns:
        start_mb = pm["vmrss_mb"].iloc[0]
        end_mb = pm["vmrss_mb"].iloc[-1]
        delta_mb = end_mb - start_mb
        print(f"  Memory (VmRSS) — start: {start_mb:.1f} MB  end: {end_mb:.1f} MB  "
              f"delta: {delta_mb:+.1f} MB")

    # Top error methods
    me = summary.get("method_effectiveness", {})
    if me:
        error_contrib = sorted(
            ((k, v.get("error", 0)) for k, v in me.items()),
            key=lambda x: x[1], reverse=True
        )
        top_err = [(k, n) for k, n in error_contrib if n > 0][:5]
        if top_err:
            print("  Top error-triggering methods:")
            for name, n in top_err:
                print(f"    {name:<45} {n} errors")

    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyse a single capwap_log session and generate charts."
    )
    parser.add_argument("log_dir", help="Path to capwap_log/<timestamp>/ directory")
    parser.add_argument("--out", default=None,
                        help="Output directory for charts (default: <log_dir>/charts/)")
    args = parser.parse_args()

    log_dir = Path(args.log_dir).resolve()
    if not log_dir.is_dir():
        print(f"[!] Not a directory: {log_dir}", file=sys.stderr)
        sys.exit(1)

    # Default output dir: ./charts/<session_name>/ relative to CWD.
    # Avoids permission issues when log_dir was written by sudo.
    # 默认输出到当前工作目录下的 charts/<session_name>/，
    # 避免 log_dir 由 sudo 写入导致的权限问题。
    out_dir = Path(args.out).resolve() if args.out else Path.cwd() / "charts" / log_dir.name
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Analysing {log_dir} ...")

    df      = load_records(log_dir)
    summary = load_summary(log_dir)
    pm      = load_process_monitor(log_dir)
    session = load_session(log_dir)

    print(f"[*] Loaded {len(df)} records, process_monitor: {'yes' if pm is not None else 'no'}")
    print(f"[*] Generating charts in {out_dir} ...")

    chart_response_pie(summary, out_dir)
    chart_method_effectiveness(summary, out_dir)
    chart_response_time(df, summary, out_dir)
    chart_process_memory(pm, summary, out_dir)
    chart_process_cpu(pm, summary, out_dir)
    chart_error_types(summary, out_dir)

    print_summary(log_dir, summary, df, session, pm)


if __name__ == "__main__":
    main()
