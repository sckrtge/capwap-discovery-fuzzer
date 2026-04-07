# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

This project uses `just` as a task runner and `uv` for Python environment management.

```bash
just qa          # format, lint (ruff), type-check (ty), and test
just test        # run pytest (pass extra args after: just test -k test_name)
just test -k "pattern"  # run a single test matching pattern
just pdb         # run tests with ipdb debugger on failure
just coverage    # run coverage and generate HTML report
just build       # build the package
just clean       # remove all build/test/pyc artifacts
```

Install dev dependencies: `uv sync --extra test`

Linter: `ruff` (line-length 120). Type checker: `ty`. Tests: `pytest`.

## Architecture

The tool fuzzes CAPWAP (Control And Provisioning of Wireless Access Points) Discovery Requests over UDP port 5246 and classifies AC responses.

**Data flow:**
1. `cli.py` — Typer CLI entry point, handles `--ac-ip`/`--broadcast`/`--pcap`/`--replay-json-dir`/`--iface` options, drives fuzzing rounds
2. `capwap_discovery_fuzzer.py` — `CAPWAPDiscoveryFuzzer` orchestrates: creates/loads base packet, applies mutations, sends via Python native `socket` (UDP), classifies responses, writes per-response JSON logs to `./capwap_log/<timestamp>/responses/`
3. `request_creater.py` — Scapy packet class definitions (`CAPWAP_Header`, `Control_Header`, `MessageElement`, `WTPDescriptor`, etc.) + `Payload_Creator` for constructing valid or random discovery requests + `parse_discovery_request()` for loading from pcap
4. `payload_fuzzer.py` — `Payload_Fuzzer` wraps a base packet; provides structured "safe" fuzz methods (header fields, message element length/value/type, duplicate/drop/shuffle elements, flag combos) and "brutal" raw-byte methods (random overwrite, insert, delete, shuffle, duplicate segment, reverse segment)
5. `response_parser.py` — `ResponseParser` parses raw response bytes using Scapy, classifies as `valid`/`error`/`timeout`/`unknown`, raises typed errors from `errors.py`
6. `errors.py` — Exception hierarchy: `CAPWAPFuzzerError` → `NoResponseError`, `InvalidResponseError` → `MissingCapwapHeaderError`, `MissingControlHeaderError`, `UnexpectedMsgTypeError`, `MissingRequiredElementError`, etc.

**Fuzzing strategy** (`CAPWAPDiscoveryFuzzer.fuzzing`): each round sends 1 packet (`MUTATION_COUNT=1`), randomly chains 1–3 "safe" structured mutations followed by 0–3 "brutal" byte-level mutations. Results are bucketed as valid/timeout/error and written to JSON for later replay.

**Replay mode**: `--replay-json-dir` replays saved JSON request logs (hex bytes) against the target — useful for crash reproduction.

**Scapy layer binding**: `request_creater.py` and `response_parser.py` temporarily `bind_layers` / `split_layers` around parsing to avoid global state pollution.

**Untracked files** (`VSmartZone_fuzzer.py`, `VSmartZone_request_creater.py`) appear to be in-progress vendor-specific extensions — they are not yet integrated.

## Running the fuzzer

```bash
# Unicast mode targeting local AC (AC runs on the same machine)
sudo bash run_fuzzing.sh

# Broadcast mode
sudo bash run_fuzzing_broadcast.sh

# Manual invocation examples
sudo /path/to/venv/bin/python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.33.128 \
  --rounds 10 \
  --timeout 3 \
  --iface lo

sudo /path/to/venv/bin/python -m capwap_discovery_fuzzer \
  --broadcast \
  --ac-port 5246 \
  --rounds 10 \
  --timeout 3 \
  --iface lo

# Replay saved JSON logs for crash reproduction
sudo /path/to/venv/bin/python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.33.128 \
  --replay-json-dir ./capwap_log/20240101_120000/responses/
```

Does NOT require root privileges (uses Python native UDP socket, not raw socket).

## Key findings & fixes (2026-04-07)

### Bugs fixed
1. **Broadcast destination was `None`** — `send_discovery_request` used `self.ac_ip` directly; when `--broadcast` is set `ac_ip=None`, causing Scapy to error silently every iteration. Fixed: use `"255.255.255.255"` when `broadcast=True`.
2. **Brutal mutation methods ignored their `pkt` argument** — all six `brutal_*` methods called `self._clone()` instead of operating on the passed `pkt`, breaking the mutation chain. Fixed: operate directly on `pkt`.
3. **Safe mutation methods didn't chain** — each safe method always started from `self.base` via `_clone()`, so only the last safe mutation survived. Fixed: all safe methods accept optional `pkt` parameter and clone from it when provided.
4. **`ResponseParser._bind_layers()` called in `__init__`** — polluted global Scapy layer state permanently until first `parse_response` call. Fixed: removed `_bind_layers()` from `__init__`, only bind/unbind inside `parse_response`.
5. **Double `logging.basicConfig`** — both `cli.py` and `CAPWAPDiscoveryFuzzer.__init__` called `basicConfig`; second call was a no-op, log files were split across two directories. Fixed: `basicConfig` called once in CLI after fuzzer is created, using `fuzzer.log_dir`.
6. **Scapy `sr1` cannot reach local IP** — target AC runs on the same machine (`192.168.33.128`); Linux routes local IPs via loopback (`lo`), Scapy's L3 raw socket cannot see responses. Scapy L2 (`srp1`) also fails on `lo` due to no ARP. Fixed: replaced Scapy send/receive with Python native `socket` (UDP), which works correctly for local destinations.

### Network topology
- Virtual AC runs as a local process on the same machine, bound to `192.168.33.128:5246` (and `0.0.0.0:5246`).
- `ip route get 192.168.33.128` returns `local ... dev lo` — all traffic to this IP goes through loopback.
- Native UDP socket bypasses ARP/routing issues entirely and reaches the AC correctly.
- Verified: 2/10 valid responses received after the fix.
