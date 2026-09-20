"""Session state machine for a fuzzed CAPWAP control channel (RFC 5415 §2.3).

States and the fuzzable traffic each carries::

    DISCOVERY ── discovery request/response (plaintext, optional)
    DTLS      ── handshake (never fuzzed by default)
    JOIN      ── Join Request → Join Response          ← Join mutations
    CONFIG    ── Configuration Status Request/Response  ← Config mutations
    DATA_CHECK── Change State Event Request/Response
    RUN       ── Echo keep-alive + Config Update answering ← Run mutations

Timeouts are the *measured* values from the 2026-09-20 live rounds, not RFC
defaults: the controller starts pushing Configuration Updates ~8 s into Run,
retransmits every 4 s, and tears the session down after 6 unanswered attempts
("Max Retransmission to AP").  A fuzz driver that only answers inside its own
wait windows will therefore die at ~30 s; run :class:`session.responder.Responder`
continuously instead.
"""

from __future__ import annotations

import enum
import time

from capwap_discovery_fuzzer.session import builders


class Stage(enum.Enum):
    DISCOVERY = enum.auto()
    DTLS = enum.auto()
    JOIN = enum.auto()
    CONFIG = enum.auto()
    DATA_CHECK = enum.auto()
    RUN = enum.auto()
    DEAD = enum.auto()


#: Measured budgets, seconds.  Documented in the runbook §6.
TIMEOUT_HANDSHAKE = 25.0      # s_client negotiation incl. server cert flight
#: Join Response arrival after Join Request.  A *successful* join answers within
#: ~100 ms of the server flight closing (runbook §4), so 15 s is a ceiling for
#: the failing case only; the stage fuzzer defaults to a much shorter cap
#: (``JoinFuzzConfig.join_timeout``) to stop paying it on every silent round.
TIMEOUT_JOIN_RESPONSE = 15.0
#: How long the controller keeps a session for an AP after the client leaves,
#: during which a new handshake for that same identity is swallowed.  Measured
#: 2026-09-20: Join-phase btrace shows "Heart beat timer expiry, Phase: Join"
#: after ~32 s; the practical penalty is one swallowed attempt (~20 s) per
#: round with a fresh source port.  Rotating source ports / identities (plan
#: P4.5) is the mitigation; the exact key is still undetermined.
SESSION_CLEANUP_WINDOW_S = 20.0
TIMEOUT_CONFIG_RESPONSE = 12.0
TIMEOUT_CHANGE_STATE_RESPONSE = 12.0
TIMEOUT_ECHO_RESPONSE = 8.0
FIPS_UPDATE_INTERVAL = 4.0    # controller retransmit cadence, Run state
MAX_UPDATE_RETRIES = 6        # after this: "Max Retransmission to AP" teardown
SESSION_LIFETIME_BEFORE = 26.0  # observed ceiling without a responder (s)


class SessionStateMachine:
    """Tracks and drives the control-channel progression.

    The machine is *passive*: it validates transitions and records timing, but
    the fuzz driver decides what to send (that is the point of a fuzzer).
    ``require()`` is the guard used before each send so a driver bug cannot
    attribute traffic to the wrong stage.
    """

    def __init__(self, identity=None) -> None:
        self.identity = identity
        self.stage = Stage.DISCOVERY
        self.entered_at: dict[Stage, float] = {Stage.DISCOVERY: time.time()}
        self.session_id: bytes | None = None

    def require(self, *stages: Stage) -> None:
        if self.stage not in stages:
            raise RuntimeError(
                f"state violation: in {self.stage.name}, expected "
                f"{'/'.join(s.name for s in stages)}")

    def advance(self, stage: Stage) -> None:
        allowed = {
            Stage.DISCOVERY: {Stage.DTLS},
            Stage.DTLS: {Stage.JOIN, Stage.DEAD},
            Stage.JOIN: {Stage.CONFIG, Stage.DEAD},
            Stage.CONFIG: {Stage.DATA_CHECK, Stage.DEAD},
            Stage.DATA_CHECK: {Stage.RUN, Stage.DEAD},
            Stage.RUN: {Stage.DEAD},
            Stage.DEAD: set(),
        }[self.stage]
        if stage not in allowed:
            raise RuntimeError(
                f"illegal transition {self.stage.name} -> {stage.name}")
        self.stage = stage
        self.entered_at[stage] = time.time()

    def seconds_in(self, stage: Stage | None = None) -> float:
        stage = stage or self.stage
        if stage not in self.entered_at:
            return 0.0
        return time.time() - self.entered_at[stage]

    # -------------------------------------------------------------- builders
    # Thin wrappers so a driver never sends a raw frame without the machine
    # knowing which stage produced it.

    def make_join(self, **kwargs) -> bytes:
        self.require(Stage.JOIN)
        kwargs.setdefault("identity", self.identity)
        return builders.build_join_request(**kwargs)

    def make_config_status(self, **kwargs) -> bytes:
        self.require(Stage.CONFIG)
        kwargs.setdefault("identity", self.identity)
        return builders.build_config_status(**kwargs)

    def make_change_state(self, **kwargs) -> bytes:
        self.require(Stage.DATA_CHECK)
        kwargs.setdefault("identity", self.identity)
        return builders.build_change_state(**kwargs)

    def make_echo(self, **kwargs) -> bytes:
        self.require(Stage.RUN)
        kwargs.setdefault("identity", self.identity)
        return builders.build_echo(**kwargs)

    def make_config_update_response(self, **kwargs) -> bytes:
        self.require(Stage.RUN, Stage.CONFIG, Stage.DATA_CHECK)
        kwargs.setdefault("identity", self.identity)
        return builders.build_config_update_response(**kwargs)

    def mark_dead(self) -> float:
        """Record teardown; returns session lifetime in seconds."""
        lifetime = time.time() - self.entered_at[Stage.DISCOVERY]
        self.stage = Stage.DEAD
        self.entered_at[Stage.DEAD] = time.time()
        return lifetime
