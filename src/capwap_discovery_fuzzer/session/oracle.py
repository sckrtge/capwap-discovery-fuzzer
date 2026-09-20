"""Per-round verdict collection for the session fuzzer.

A CAPWAP round has four possible outcomes, and only one of them ("answered")
carries a protocol verdict.  Everything else must be *classified*, not counted
as a rejection:

``answered``
    a response arrived; ``result_code`` (RFC 5415 §4.6.35, Type 33) is the
    verdict.  0 = accepted; anything else is a named rejection.
``alert``
    the controller answered with a DTLS alert record (content type 0x15) —
    crypto/certificate/state layer rejection.
``silence``
    nothing came back.  Only meaningful together with a liveness check: after
    the LB-gate patch a healthy controller answers Discovery in milliseconds,
    so silence almost always means the gate is closed (patch lost, process
    down) rather than "the fuzzer found something".
``disjoin``
    the controller accepted the message but tore the session down; the reason
    string comes from ``show logging process wncd`` (btrace decode) and maps
    1:1 to a payload gap — the table below is the E5–E7 measured version.

The reason map is the fuzzer's attribution engine: given a disjoin reason it
names the exact payload gap, so every round reports *why*, not just *what*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

RESULT_CODE_SUCCESS = 0

#: Disjoin reason string (as emitted by CAPWAPAC_SMGR_TRACE_MESSAGE) → payload
#: gap that caused it.  Measured on C9800-CL 17.14.01, E5–E7 rounds.
DISJOIN_REASON_MAP: dict[str, str] = {
    "Internal Error":
        "radio/reg-domain layer: check Radio ID base (0/1), radio-type bitmask, "
        "or the VSP-126 domain declaration in Configuration Status",
    "Failure decoding max message size":
        "Join Request missing Maximum Message Length (RFC 5415 §4.6.31, Type 29)",
    "Failure encoding auth token payload":
        "controller-side: token getter broken — cfmgr memory patch applied; "
        "restore original bytes",
    "Max Retransmission to AP":
        "session answered too slowly or not at all: Run-state Configuration "
        "Update Requests need a continuous responder (4s retry / 6 attempts)",
    "Heart beat timer expiry":
        "no traffic within the heartbeat window — driver stalled or network loss",
    "AP Auth Failure":
        "authorization layer rejected the certificate (authorize-mac enabled)",
}

DTLS_ALERT_CONTENT_TYPE = 0x15


class Outcome(str, Enum):
    ANSWERED = "answered"
    ALERT = "alert"
    SILENCE = "silence"
    DISJOIN = "disjoin"


@dataclass
class RoundVerdict:
    """Everything recorded for one fuzz round."""

    stage: str
    outcome: Outcome
    result_code: int | None = None
    result_code_name: str | None = None
    disjoin_reason: str | None = None
    gap: str | None = None                 # payload gap from DISJOIN_REASON_MAP
    session_lifetime_s: float | None = None
    mutation: dict = field(default_factory=dict)
    raw_reply_hex: str | None = None

    def as_dict(self) -> dict:
        d = {"stage": self.stage, "outcome": self.outcome.value,
             "mutation": self.mutation}
        for key in ("result_code", "result_code_name", "disjoin_reason",
                    "gap", "session_lifetime_s", "raw_reply_hex"):
            value = getattr(self, key)
            if value is not None:
                d[key] = value
        return d


def classify_reply(reply: bytes) -> tuple[Outcome, int | None]:
    """Classify one decrypted reply blob; returns (outcome, result_code)."""
    if not reply:
        return Outcome.SILENCE, None
    if reply[0] == DTLS_ALERT_CONTENT_TYPE:
        return Outcome.ALERT, None
    msgs = parse_messages_loose(reply)
    for msg in msgs:
        for etype, _elen, val in msg["elements"]:
            if etype == 33 and len(val) >= 4:
                return Outcome.ANSWERED, int.from_bytes(val[:4], "big")
    return Outcome.ANSWERED, None


def parse_messages_loose(raw: bytes) -> list[dict]:
    """Tolerant re-parse used by the oracle (mirrors builders.parse_control_messages)."""
    from capwap_discovery_fuzzer.session.builders import parse_control_messages
    return parse_control_messages(raw)


def verdict_for(stage: str, reply: bytes, mutation: dict | None = None,
                disjoin_reason: str | None = None,
                session_lifetime_s: float | None = None) -> RoundVerdict:
    """Build a :class:`RoundVerdict` from one round's raw results.

    An explicit ``disjoin_reason`` (from the controller trace) wins over the
    wire classification: a teardown renders any reply meaningless, and an empty
    reply plus a reason is a disjoin, not a silence.
    """
    outcome, code = classify_reply(reply)
    if disjoin_reason:
        outcome = Outcome.DISJOIN
        code = None
    reason = disjoin_reason
    gap = DISJOIN_REASON_MAP.get(reason) if reason else None
    return RoundVerdict(
        stage=stage, outcome=outcome, result_code=code,
        disjoin_reason=reason, gap=gap,
        session_lifetime_s=session_lifetime_s,
        mutation=mutation or {},
        raw_reply_hex=reply.hex()[:256] if reply else None,
    )
