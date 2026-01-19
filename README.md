# CAPWAP Discovery Fuzzer

This project focuses on **structure-aware fuzzing** of CAPWAP Discovery control messages
as defined in **RFC 5415**, targeting Access Controllers (ACs) during the WTP discovery phase.

> ⚠️ This tool is intended **for academic research and authorized security testing only**.

---

## Overview

CAPWAP Discovery is the first control-plane interaction between a Wireless Termination Point (WTP)
and an Access Controller (AC).  
Malformed or unexpected Discovery messages may expose parsing errors, robustness issues,
or implementation flaws in AC implementations.

This tool is designed to help researchers:

- Start from a **real, valid Discovery Request** captured in a PCAP
- Parse CAPWAP transport and control structures according to RFC 5415
- Apply controlled fuzzing to individual CAPWAP message elements
- Rebuild and transmit mutated Discovery Requests
- Observe and classify AC responses (valid / invalid / timeout)

---

## Features

- RFC 5415–aware CAPWAP Control Message parsing
- Message Element (TLV)–level fuzzing
- PCAP-based seed input
- Deterministic fuzzing via random seed
- CLI interface based on Typer
- Rich-based progress bar and structured console output
- Designed for academic research and protocol robustness analysis

---

## Installation

### From source

```bash
git clone https://github.com/sckrt/capwap-discovery-fuzzer.git
cd capwap-discovery-fuzzer
pip install .[test]
```

---

## Usage

### Basic fuzzing run

```bash
# run in ./capwap_discovery_fuzzer
python -m capwap_discovery_fuzzer \
  --pcap ./pcaps/sample_discovery_request.pcap \
  --ac-ip 192.168.10.128 \
  --ac-port 5246 \
  --rounds 1 \
  --seed 1337
```

---

## Fuzzing Strategy

The current fuzzing strategy is **element-oriented and incremental**:

1. Load a valid CAPWAP Discovery Request from a PCAP file
2. Split the payload into:

   * CAPWAP transport header
   * CAPWAP control header
   * A list of Message Elements (TLV format)
3. For each Message Element:

   * Generate multiple mutated variants
   * Replace only the current element
   * Keep all other elements unchanged
4. Rebuild the CAPWAP Control Message
5. Send the mutated request to the target AC
6. Record the outcome:

   * Valid response received
   * Invalid / unexpected response
   * No response (timeout)

This design prioritizes **parser coverage and robustness testing**
over full protocol semantic correctness.

---

## Message Element Format

CAPWAP Message Elements use a TLV encoding:

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              Type             |             Length            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Value ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Fuzzing targets include:

* `Type` field mutations
* `Length` field inconsistencies
* Randomized or malformed `Value` payloads

---

## Project Structure

```
capwap_discovery_fuzzer/
├── cli.py              # CLI entry point (Typer)
├── capwap.py           # CAPWAP parsing and rebuilding logic
├── fuzzing.py          # Message Element fuzzing strategies
├── transport.py        # UDP socket handling
├── utils.py            # Helpers (hexdump, etc.)
├── errors.py           # Custom exception definitions
└── __main__.py         # python -m entry point
```

---

## Limitations

* No DTLS support (CAPWAP Control over UDP only)
* No automatic crash or memory fault detection on AC side
* High fuzzing rates may trigger AC-side rate limiting or protection mechanisms
* IPv4 only (no IPv6 support at the moment)

---

## Ethical Notice

This tool is provided **strictly for educational, academic, and authorized testing purposes**.

You must ensure that:

* You own the target device, or
* You have explicit permission to perform testing

The author assumes no responsibility for misuse.

---

## License

MIT License

---

## Credits

* RFC 5415 – *CAPWAP Protocol Specification*
* Built with:

  * [Typer](https://typer.tiangolo.com/)
  * [Rich](https://github.com/Textualize/rich)
  * [Scapy](https://scapy.net/)