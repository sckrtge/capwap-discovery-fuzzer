#!/usr/bin/env python3
"""check_conformance.py — RFC 5415 / RFC 5416 conformance audit of recorded sessions.

Usage:
    python tools/check_conformance.py capwap_log/20260911_140132
    python tools/check_conformance.py capwap_log/          # every session with records.jsonl
    python tools/check_conformance.py capwap_log/ --side request

Judges each recorded message against the MUST/MAY sets of its stage, using the
type numbers and section citations in ``capwap_discovery_fuzzer.conformance``
(which follow the RFC texts kept in the project workspace at docs/evidence/rfc/).
Useful because the Discovery family carries no admission verdict: conformance is
the only standards-based statement we can make about recorded Discovery traffic.

对已记录会话做 RFC 合规审计：按各阶段 MUST/MAY 清单逐条判定请求与响应。
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from capwap_discovery_fuzzer.conformance import scan_records  # noqa: E402


def _session_dirs(paths):
    for path in paths:
        if (path / "records.jsonl").exists():
            yield path
        else:
            yield from sorted(p for p in path.glob("*") if (p / "records.jsonl").exists())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+", type=Path,
                        help="session directory, or a capwap_log/ root to scan")
    parser.add_argument("--side", choices=("request", "response"), default="response",
                        help="which direction to judge (default: response)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args()

    results = [scan_records(d / "records.jsonl", request_side=args.side == "request")
               for d in _session_dirs(args.paths)]
    if not results:
        print("no records.jsonl found under the given paths", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return 0

    checked_total = conformant_total = 0
    violation_totals: dict[str, int] = {}
    for r in results:
        checked, ok = r["messages_checked"], r["conformant"]
        checked_total += checked
        conformant_total += ok
        for key, count in r["by_violation"].items():
            violation_totals[key] = violation_totals.get(key, 0) + count
        rate = f"{100 * ok / checked:.1f}%" if checked else "n/a"
        print(f"{Path(r['path']).parent.name:<22} {r['side']:<8} checked={checked:<4} "
              f"conformant={ok:<4} rate={rate:<7} deviations={r['deviations']}")
        for example in r["examples"][:3]:
            print(f"    round {example['round']}: {example['msg']} -> {example['violations']}")

    print()
    overall = f"{100 * conformant_total / checked_total:.1f}%" if checked_total else "n/a"
    print(f"TOTAL {args.side}: checked={checked_total} conformant={conformant_total} rate={overall}")
    if violation_totals:
        print("violations by reason:")
        for key, count in sorted(violation_totals.items(), key=lambda kv: -kv[1]):
            print(f"  {count:>5}  {key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
