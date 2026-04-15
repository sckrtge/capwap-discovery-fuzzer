#!/usr/bin/env python3
"""compare_sessions.py — Multi-session comparison and aggregated chart generation.

Usage:
    python tools/compare_sessions.py <log_dir1> [<log_dir2> ...] [--out <output_dir>]
    python tools/compare_sessions.py capwap_log/          # auto-discover all sessions
    python tools/compare_sessions.py capwap_log/ --vendor opencapwap  # filter by vendor

Reads multiple capwap_log/<timestamp>/ directories and produces:
    1. session_overview.png        — response type stacked bar per session
    2. mttc_comparison.png         — crash round per session (if any crashed)
    3. method_heatmap.png          — method × session error-rate heatmap
    4. memory_overlay.png          — VmRSS trends overlaid (gray-box sessions only)
    5. response_time_overlay.png   — rolling-mean elapsed_ms overlaid per session
    6. sessions_table.csv          — aggregated numeric summary for all sessions

Text summary printed to stdout.

读取多个 capwap_log/<timestamp>/ 目录，生成多会话对比图表。
"""

import argparse
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Data loading (reuse same helpers as analyze_results.py)
# ---------------------------------------------------------------------------

def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def _load_records(log_dir: Path) -> pd.DataFrame:
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


def _load_process_monitor(log_dir: Path) -> pd.DataFrame | None:
    path = log_dir / "process_monitor.csv"
    if not path.exists():
        return None
    df = pd.read_csv(path, parse_dates=["timestamp"])
    df["vmrss_mb"] = df["vmrss_kb"] / 1024
    return df


def load_session_data(log_dir: Path) -> dict:
    """Load all relevant data for one session directory.
    加载单个会话目录的所有相关数据。
    """
    summary = _load_json(log_dir / "summary.json")
    session = _load_json(log_dir / "session.json")
    records = _load_records(log_dir)
    pm      = _load_process_monitor(log_dir)
    return {
        "name":    log_dir.name,
        "log_dir": log_dir,
        "summary": summary,
        "session": session,
        "records": records,
        "pm":      pm,
    }


def discover_sessions(base: Path, vendor_filter: str | None = None) -> list[Path]:
    """Return all session subdirectories under *base*, sorted by name.
    返回 base 目录下所有会话子目录，按名称排序。
    """
    dirs = sorted(
        [d for d in base.iterdir() if d.is_dir() and (d / "summary.json").exists()]
    )
    if vendor_filter:
        filtered = []
        for d in dirs:
            s = _load_json(d / "session.json")
            if s.get("vendor", "").lower() == vendor_filter.lower():
                filtered.append(d)
        dirs = filtered
    return dirs


# ---------------------------------------------------------------------------
# Chart helpers
# ---------------------------------------------------------------------------

COLORS = {"valid": "#2ecc71", "timeout": "#f39c12", "error": "#e74c3c"}
_CMAP  = matplotlib.colormaps["tab10"]


def _save(fig, path: Path, title: str):
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  [+] {title} → {path.name}")


def _session_label(s: dict) -> str:
    """Short label: last 6 chars of session name + vendor."""
    name = s["name"][-6:]
    vendor = s["session"].get("vendor", "?")[:5]
    return f"{name}\n({vendor})"


# ---------------------------------------------------------------------------
# Chart 1: Session overview — stacked bar of response types
# ---------------------------------------------------------------------------

def chart_session_overview(sessions: list[dict], out_dir: Path):
    if not sessions:
        return

    labels   = [_session_label(s) for s in sessions]
    valids   = [s["summary"].get("valid",   0) for s in sessions]
    timeouts = [s["summary"].get("timeout", 0) for s in sessions]
    errors   = [s["summary"].get("error",   0) for s in sessions]
    totals   = [s["summary"].get("total",   1) for s in sessions]

    x = np.arange(len(sessions))
    fig, ax = plt.subplots(figsize=(max(8, len(sessions) * 1.4), 5))

    b_v = ax.bar(x, [v/t*100 for v,t in zip(valids,   totals)],
                 color=COLORS["valid"],   label="valid")
    b_t = ax.bar(x, [v/t*100 for v,t in zip(timeouts, totals)],
                 bottom=[v/t*100 for v,t in zip(valids, totals)],
                 color=COLORS["timeout"], label="timeout")
    b_e = ax.bar(x, [v/t*100 for v,t in zip(errors,   totals)],
                 bottom=[(v+to)/t*100 for v,to,t in zip(valids, timeouts, totals)],
                 color=COLORS["error"],   label="error")

    # Annotate total rounds on top
    for i, t in enumerate(totals):
        ax.text(i, 101, f"n={t}", ha="center", va="bottom", fontsize=7)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("Percentage (%)")
    ax.set_ylim(0, 115)
    ax.set_title("Response Type Distribution per Session", fontsize=12)
    ax.legend(loc="upper right")
    _save(fig, out_dir / "session_overview.png", "Session overview")


# ---------------------------------------------------------------------------
# Chart 2: Mean Time to Crash (MTTC) per session
# ---------------------------------------------------------------------------

def chart_mttc(sessions: list[dict], out_dir: Path):
    crashed = [(s["name"][-6:], s["summary"]["crash_at_round"])
               for s in sessions
               if s["summary"].get("crash_detected") and s["summary"].get("crash_at_round")]
    if not crashed:
        print("  [!] No crashed sessions — skipping mttc_comparison")
        return

    names, rounds = zip(*crashed)
    fig, ax = plt.subplots(figsize=(max(5, len(crashed) * 1.2), 4))
    bars = ax.bar(range(len(crashed)), rounds, color="#e74c3c", edgecolor="white")
    ax.bar_label(bars, padding=3, fontsize=9)
    ax.set_xticks(range(len(crashed)))
    ax.set_xticklabels(names, rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("Round number at crash")
    ax.set_title("Crash Round per Session (MTTC proxy)", fontsize=12)
    mean_r = np.mean(rounds)
    ax.axhline(mean_r, color="navy", linestyle="--", linewidth=1.2,
               label=f"mean = {mean_r:.0f}")
    ax.legend()
    _save(fig, out_dir / "mttc_comparison.png", "MTTC comparison")


# ---------------------------------------------------------------------------
# Chart 3: Method × session error-rate heatmap
# ---------------------------------------------------------------------------

def chart_method_heatmap(sessions: list[dict], out_dir: Path):
    # Collect all method names across sessions
    all_methods: set[str] = set()
    for s in sessions:
        all_methods.update(s["summary"].get("method_effectiveness", {}).keys())
    if not all_methods:
        print("  [!] No method_effectiveness data — skipping heatmap")
        return

    methods = sorted(all_methods)
    s_labels = [s["name"][-8:] for s in sessions]

    # Build matrix: error_rate = errors / uses for each (method, session)
    matrix = np.zeros((len(methods), len(sessions)))
    for j, s in enumerate(sessions):
        me = s["summary"].get("method_effectiveness", {})
        for i, m in enumerate(methods):
            if m in me and me[m].get("uses", 0) > 0:
                matrix[i, j] = me[m].get("error", 0) / me[m]["uses"]

    fig, ax = plt.subplots(figsize=(max(8, len(sessions) * 1.2),
                                    max(6, len(methods) * 0.35)))
    im = ax.imshow(matrix, aspect="auto", cmap="YlOrRd", vmin=0, vmax=1)
    fig.colorbar(im, ax=ax, label="Error rate (errors / uses)")

    ax.set_xticks(range(len(sessions)))
    ax.set_xticklabels(s_labels, rotation=30, ha="right", fontsize=8)
    ax.set_yticks(range(len(methods)))
    ax.set_yticklabels(methods, fontsize=7)
    ax.set_title("Mutation Method Error Rate per Session", fontsize=12)
    _save(fig, out_dir / "method_heatmap.png", "Method heatmap")


# ---------------------------------------------------------------------------
# Chart 4: Memory overlay (gray-box sessions only)
# ---------------------------------------------------------------------------

def chart_memory_overlay(sessions: list[dict], out_dir: Path):
    gray = [(s, s["pm"]) for s in sessions if s["pm"] is not None and not s["pm"].empty]
    if not gray:
        print("  [!] No process_monitor data in any session — skipping memory overlay")
        return

    fig, ax = plt.subplots(figsize=(12, 5))
    for idx, (s, pm) in enumerate(gray):
        color = _CMAP(idx / max(len(gray), 1))
        label = s["name"][-8:]
        ax.plot(pm["round"], pm["vmrss_mb"], color=color,
                linewidth=1.2, alpha=0.85, label=label)
        crash = s["summary"].get("crash_at_round")
        if crash:
            ax.axvline(crash, color=color, linestyle=":", linewidth=1.0)

    ax.set_xlabel("Round")
    ax.set_ylabel("VmRSS (MB)")
    ax.set_title("AC Process Memory (VmRSS) — All Gray-box Sessions", fontsize=12)
    ax.legend(fontsize=8, ncol=2)
    _save(fig, out_dir / "memory_overlay.png", "Memory overlay")


# ---------------------------------------------------------------------------
# Chart 5: Response time rolling mean overlay
# ---------------------------------------------------------------------------

def chart_response_time_overlay(sessions: list[dict], out_dir: Path):
    valid_sessions = [(s, s["records"]) for s in sessions
                      if not s["records"].empty and "elapsed_ms" in s["records"].columns]
    if not valid_sessions:
        print("  [!] No elapsed_ms data — skipping response time overlay")
        return

    fig, ax = plt.subplots(figsize=(12, 5))
    for idx, (s, df) in enumerate(valid_sessions):
        color = _CMAP(idx / max(len(valid_sessions), 1))
        label = s["name"][-8:]
        df_s = df[df["elapsed_ms"].notna()].copy()
        if df_s.empty:
            continue
        rolling = df_s.set_index("round")["elapsed_ms"].rolling(20, min_periods=5).mean()
        ax.plot(rolling.index, rolling.values, color=color,
                linewidth=1.2, alpha=0.85, label=label)
        crash = s["summary"].get("crash_at_round")
        if crash:
            ax.axvline(crash, color=color, linestyle=":", linewidth=1.0)

    ax.set_xlabel("Round")
    ax.set_ylabel("Elapsed ms (rolling mean, w=20)")
    ax.set_title("Response Time Trend — All Sessions", fontsize=12)
    ax.legend(fontsize=8, ncol=2)
    _save(fig, out_dir / "response_time_overlay.png", "Response time overlay")


# ---------------------------------------------------------------------------
# CSV summary table
# ---------------------------------------------------------------------------

def write_csv_table(sessions: list[dict], out_dir: Path):
    rows = []
    for s in sessions:
        sm = s["summary"]
        pm = s["pm"]
        total = sm.get("total", 0)

        mem_delta = None
        if pm is not None and not pm.empty and "vmrss_mb" in pm.columns:
            mem_delta = round(pm["vmrss_mb"].iloc[-1] - pm["vmrss_mb"].iloc[0], 2)

        trend = sm.get("response_time_trend", {})
        rows.append({
            "session":             s["name"],
            "vendor":              s["session"].get("vendor", ""),
            "seed":                s["session"].get("seed", ""),
            "rounds_total":        total,
            "valid":               sm.get("valid", 0),
            "timeout":             sm.get("timeout", 0),
            "error":               sm.get("error", 0),
            "valid_pct":           round(sm.get("valid",   0) / total * 100, 1) if total else 0,
            "timeout_pct":         round(sm.get("timeout", 0) / total * 100, 1) if total else 0,
            "error_pct":           round(sm.get("error",   0) / total * 100, 1) if total else 0,
            "crash_detected":      sm.get("crash_detected", False),
            "crash_at_round":      sm.get("crash_at_round", ""),
            "mean_elapsed_ms":     sm.get("response_time_stats", {}).get("mean_ms", ""),
            "p95_elapsed_ms":      sm.get("response_time_stats", {}).get("p95_ms", ""),
            "rt_first50_mean_ms":  trend.get("first_50_rounds_mean_ms", ""),
            "rt_last50_mean_ms":   trend.get("last_50_rounds_mean_ms", ""),
            "rt_degradation_ratio":trend.get("degradation_ratio", ""),
            "mem_delta_mb":        mem_delta if mem_delta is not None else "",
        })

    df = pd.DataFrame(rows)
    path = out_dir / "sessions_table.csv"
    df.to_csv(path, index=False)
    print(f"  [+] Sessions table → {path.name}  ({len(rows)} sessions)")


# ---------------------------------------------------------------------------
# Text summary
# ---------------------------------------------------------------------------

def print_summary(sessions: list[dict]):
    print("\n" + "=" * 70)
    print(f"{'Session':<20} {'Vendor':<12} {'Total':>6} {'Valid%':>7} "
          f"{'TO%':>7} {'Err%':>7} {'Crash':>7} {'MemΔMB':>8}")
    print("-" * 70)
    for s in sessions:
        sm = s["summary"]
        total = sm.get("total", 0) or 1
        pm = s["pm"]
        mem_delta = ""
        if pm is not None and not pm.empty and "vmrss_mb" in pm.columns:
            mem_delta = f"{pm['vmrss_mb'].iloc[-1] - pm['vmrss_mb'].iloc[0]:+.1f}"

        crash_info = str(sm.get("crash_at_round", "—")) if sm.get("crash_detected") else "—"
        print(
            f"{s['name'][-20:]:<20} "
            f"{s['session'].get('vendor','?'):<12} "
            f"{sm.get('total',0):>6} "
            f"{sm.get('valid',0)/total*100:>6.1f}% "
            f"{sm.get('timeout',0)/total*100:>6.1f}% "
            f"{sm.get('error',0)/total*100:>6.1f}% "
            f"{crash_info:>7} "
            f"{mem_delta:>8}"
        )
    print("=" * 70 + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Compare multiple capwap_log sessions and generate overlay charts."
    )
    parser.add_argument(
        "paths", nargs="+",
        help="Session directories or a single capwap_log/ parent directory"
    )
    parser.add_argument(
        "--out", default=None,
        help="Output directory for charts (default: ./charts/compare_<N>sessions/)"
    )
    parser.add_argument(
        "--vendor", default=None,
        help="Filter sessions by vendor name (e.g. opencapwap, cisco)"
    )
    args = parser.parse_args()

    # Resolve session directories
    session_dirs: list[Path] = []
    for p in args.paths:
        path = Path(p).resolve()
        if not path.exists():
            print(f"[!] Path not found: {path}", file=sys.stderr)
            continue
        if (path / "summary.json").exists():
            # Direct session directory
            session_dirs.append(path)
        elif path.is_dir():
            # Parent directory — auto-discover
            found = discover_sessions(path, vendor_filter=args.vendor)
            session_dirs.extend(found)

    if not session_dirs:
        print("[!] No valid session directories found.", file=sys.stderr)
        sys.exit(1)

    if len(session_dirs) < 2:
        print(f"[!] Only {len(session_dirs)} session(s) found — "
              f"comparison is most useful with 2+.  Proceeding anyway.")

    print(f"[*] Loading {len(session_dirs)} session(s)...")
    sessions = [load_session_data(d) for d in session_dirs]
    # Filter by vendor if flag given and not already filtered
    if args.vendor and not all((Path(p) / "summary.json").exists() for p in args.paths):
        sessions = [s for s in sessions
                    if s["session"].get("vendor", "").lower() == args.vendor.lower()]

    out_dir = (Path(args.out).resolve() if args.out
               else Path.cwd() / "charts" / f"compare_{len(sessions)}sessions")
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Generating charts in {out_dir} ...")

    chart_session_overview(sessions, out_dir)
    chart_mttc(sessions, out_dir)
    chart_method_heatmap(sessions, out_dir)
    chart_memory_overlay(sessions, out_dir)
    chart_response_time_overlay(sessions, out_dir)
    write_csv_table(sessions, out_dir)

    print_summary(sessions)


if __name__ == "__main__":
    main()
