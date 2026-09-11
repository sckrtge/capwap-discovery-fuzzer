"""Feedback-driven mutation scheduling (F).

The thesis's first future-work item and this project's step F: instead of drawing
mutations uniformly at random, weight them by observed outcomes.

Two design decisions worth stating, because they are what make the result usable:

**Attribution over throughput.** A round that chains three mutations cannot say
which of them caused the response, so crediting all three is how a scheduler
learns noise. In adaptive mode a round therefore carries exactly *one* unit
(a structured method, a byte-level method, or - under --lock-fields - one mutable
span), and only that unit is credited. The cost is chain diversity; the gain is
that every sample is evidence.

**Exploration floor.** Probabilities are floored so that no unit is ever starved:
``p = floor/n + (1 - floor) * smoothed_success / sum(smoothed_success)``. Without
it a unit that starts unlucky is never revisited, which is exactly the failure
mode that makes learned schedules unreproducible in a bad way.

Reward is configurable: ``valid`` counts only RFC-shaped replies, ``response``
counts any reply (the metric this project uses for entry-filter pass-through,
since C9800 answers only frames it accepts). Both are recorded either way, so a
session can be re-scored offline.

Enabling this breaks the ``--seed`` byte-for-byte reproducibility contract - the
scheduler's next choice depends on past outcomes - so the full trace is written
to ``weights.jsonl`` and the config is recorded in ``session.json``.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

#: Keep a unit's selection probability at least this share of uniform.
DEFAULT_FLOOR = 0.10

REWARD_VALID = "valid"
REWARD_RESPONSE = "response"


@dataclass
class UnitStats:
    uses: int = 0
    successes: int = 0
    last_reward: bool | None = None

    @property
    def rate(self) -> float:
        return self.successes / self.uses if self.uses else 0.0


class WeightScheduler:
    """Laplace-smoothed success weights with an exploration floor."""

    def __init__(self, units, floor: float = DEFAULT_FLOOR,
                 prior_success: float = 1.0, prior_failure: float = 1.0):
        units = list(units)
        if not units:
            raise ValueError("WeightScheduler needs at least one unit")
        if not 0.0 <= floor < 1.0:
            raise ValueError(f"floor must be in [0, 1), got {floor}")
        self.units = tuple(units)
        self.floor = floor
        self.prior_success = prior_success
        self.prior_failure = prior_failure
        self.stats: dict[str, UnitStats] = {u: UnitStats() for u in self.units}

    # ------------------------------------------------------------------ scoring
    def smoothed_rate(self, unit: str) -> float:
        s = self.stats[unit]
        return (s.successes + self.prior_success) / (
            s.uses + self.prior_success + self.prior_failure)

    def probabilities(self) -> dict[str, float]:
        """Selection probabilities after smoothing and the floor mix."""
        rates = {u: self.smoothed_rate(u) for u in self.units}
        total = sum(rates.values())
        n = len(self.units)
        out = {}
        for unit, rate in rates.items():
            mixed = (rate / total) if total > 0 else 1.0 / n
            out[unit] = self.floor / n + (1.0 - self.floor) * mixed
        # renormalise against floating-point drift
        drift = sum(out.values())
        return {u: p / drift for u, p in out.items()}

    # ------------------------------------------------------------------ choosing
    def choose(self, rng: random.Random) -> tuple[str, float]:
        """Weighted draw; returns the unit and the probability it was given."""
        probs = self.probabilities()
        threshold = rng.random()
        cumulative = 0.0
        for unit in self.units:
            cumulative += probs[unit]
            if threshold <= cumulative:
                return unit, probs[unit]
        return self.units[-1], probs[self.units[-1]]

    # ------------------------------------------------------------------ feedback
    def record(self, unit: str, reward: bool) -> None:
        if unit not in self.stats:
            raise KeyError(f"unknown unit {unit!r}")
        s = self.stats[unit]
        s.uses += 1
        s.successes += int(bool(reward))
        s.last_reward = bool(reward)

    # ----------------------------------------------------------------- reporting
    def snapshot(self) -> dict:
        probs = self.probabilities()
        return {
            unit: {
                "uses": s.uses,
                "successes": s.successes,
                "success_rate": round(s.rate, 4),
                "probability": round(probs[unit], 4),
            }
            for unit, s in self.stats.items()
        }


def reward_for(response_type: str, mode: str = REWARD_RESPONSE) -> bool:
    """Map a response classification onto the scheduler's reward.

    ``response``: any reply counts (entry-filter pass-through).
    ``valid``: only an RFC-shaped reply counts.
    ``error`` never counts as success under either mode.
    """
    if mode == REWARD_VALID:
        return response_type == "valid"
    if mode == REWARD_RESPONSE:
        return response_type in ("valid", "error")
    raise ValueError(f"unknown reward mode {mode!r}")
