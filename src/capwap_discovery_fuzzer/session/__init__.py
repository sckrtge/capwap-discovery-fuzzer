"""Stateful CAPWAP session fuzzing (plan v3, docs/fuzzer-全链路化升级计划-20260920.md).

Layers, bottom-up:

* :mod:`.vsp`        — Cisco Vendor Specific Payload (element 37) codec and the
                       vendor element-id namespace (126 regulatory domain, 207
                       board-data options, ...), verified against the live
                       controller in the 2026-09-20 E7 round.
* :mod:`.builders`   — pure constructors for Join / Configuration Status /
                       Change State Event / Echo / Configuration Update
                       Response, byte-identical to the traffic that the
                       controller accepted (``tests/golden/``).
* :mod:`.transport`  — DTLS transport abstraction; the shipped implementation
                       drives ``openssl s_client`` through a local prefix-proxy
                       (Cisco frames every 5246/udp datagram with a 4-byte
                       ``01 00 00 00`` header).
* :mod:`.statemachine` — the Discovery → DTLS → Join → Configure → Data Check
                       → Run progression (RFC 5415 §2.3) with measured timeouts.
* :mod:`.responder`  — the Run-state answer loop; the controller retransmits
                       its Configuration Update Requests every 4 s and tears the
                       session down after 6 misses, so responses must be
                       continuous, not poll-driven.
* :mod:`.oracle`     — per-round verdict collection (Result Code enum, alert /
                       silence / disjoin classification, session lifetime).

Everything protocol-related here is anchored to the read-only RFC copies in
``docs/evidence/rfc/`` or to a live-verification round; deviations are marked.
"""
