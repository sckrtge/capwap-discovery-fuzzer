"""Adaptive mutation-scheduling tests (F).

Two properties matter most and are both asserted here: with the feature off the
original uniform draw is untouched, and with it on every round carries exactly
one unit so the reward it receives is attributable.
"""

import json
import random
import socket
import threading

import pytest
from typer.testing import CliRunner

from capwap_discovery_fuzzer import weights
from capwap_discovery_fuzzer.cli import app
from capwap_discovery_fuzzer.weights import WeightScheduler, reward_for

# ------------------------------------------------------------- scheduler maths

def test_starts_uniform_and_normalised():
    sched = WeightScheduler(["a", "b", "c"])
    probs = sched.probabilities()
    assert pytest.approx(sum(probs.values()), abs=1e-9) == 1.0
    assert all(pytest.approx(p, abs=1e-9) == 1 / 3 for p in probs.values())


def test_success_raises_probability_and_failure_lowers_it():
    sched = WeightScheduler(["good", "bad"])
    for _ in range(20):
        sched.record("good", True)
        sched.record("bad", False)

    probs = sched.probabilities()
    assert probs["good"] > probs["bad"]
    assert sched.stats["good"].rate == 1.0
    assert sched.stats["bad"].rate == 0.0


def test_exploration_floor_keeps_every_unit_alive():
    sched = WeightScheduler(["a", "b", "c", "d"], floor=0.20)
    for _ in range(50):
        sched.record("a", True)
    for _ in range(50):
        sched.record("b", False)

    probs = sched.probabilities()
    floor_share = 0.20 / 4
    assert all(p >= floor_share - 1e-9 for p in probs.values()), probs
    # the never-tried units keep a real chance
    assert probs["c"] > floor_share


def test_floor_zero_still_normalises():
    sched = WeightScheduler(["a", "b"], floor=0.0)
    assert pytest.approx(sum(sched.probabilities().values()), abs=1e-9) == 1.0


def test_choose_is_deterministic_for_a_seed_and_follows_the_weights():
    sched = WeightScheduler(["lucky", "unlucky"], floor=0.0)
    for _ in range(30):
        sched.record("lucky", True)
        sched.record("unlucky", False)

    first = [sched.choose(random.Random(7))[0] for _ in range(50)]
    second = [sched.choose(random.Random(7))[0] for _ in range(50)]
    assert first == second                       # same seed, same draws
    assert first.count("lucky") > first.count("unlucky")


def test_choose_returns_the_probability_it_used():
    sched = WeightScheduler(["a", "b"], floor=0.25)
    unit, prob = sched.choose(random.Random(1))
    assert prob == sched.probabilities()[unit]


def test_record_rejects_unknown_units():
    sched = WeightScheduler(["a"])
    with pytest.raises(KeyError):
        sched.record("nope", True)


def test_scheduler_rejects_bad_configuration():
    with pytest.raises(ValueError):
        WeightScheduler([])
    with pytest.raises(ValueError):
        WeightScheduler(["a"], floor=1.0)


def test_reward_mapping():
    assert reward_for("valid", weights.REWARD_RESPONSE) is True
    assert reward_for("error", weights.REWARD_RESPONSE) is True   # a reply arrived
    assert reward_for("timeout", weights.REWARD_RESPONSE) is False
    assert reward_for("valid", weights.REWARD_VALID) is True
    assert reward_for("error", weights.REWARD_VALID) is False
    with pytest.raises(ValueError):
        reward_for("valid", "nonsense")


def test_snapshot_reports_uses_and_probabilities():
    sched = WeightScheduler(["a", "b"])
    sched.record("a", True)
    snap = sched.snapshot()

    assert snap["a"]["uses"] == 1 and snap["a"]["successes"] == 1
    assert snap["b"]["uses"] == 0
    assert pytest.approx(sum(v["probability"] for v in snap.values()), abs=1e-6) == 1.0


# --------------------------------------------------------- fuzzer integration

def _responder():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    stop = threading.Event()

    def serve():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                _, peer = sock.recvfrom(65535)
            except OSError:
                continue
            sock.sendto(b"\x00" * 8, peer)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return sock, port, stop, thread


def _run(tmp_path, extra_args, rounds=30):
    sock, port, stop, thread = _responder()
    try:
        result = CliRunner().invoke(app, [
            "--ac-ip", "127.0.0.1", "--ac-port", str(port), "--vendor", "cisco",
            "--rounds", str(rounds), "--timeout", "0.3", "--sleep", "0", "--seed", "11",
        ] + extra_args)
    finally:
        stop.set()
        thread.join(timeout=2)
        sock.close()
    session = next(tmp_path.glob("capwap_log/*"))
    records = [json.loads(l) for l in (session / "records.jsonl").read_text().splitlines()]
    return result, session, records


def test_adaptive_off_keeps_the_original_chained_schedule(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result, session, records = _run(tmp_path, [])

    assert result.exit_code == 0, result.output
    assert len(records) == 30
    assert any(len(r["method_chain"]) > 1 for r in records)   # chaining still happens
    assert not (session / "weights.jsonl").exists()
    assert json.loads((session / "summary.json").read_text()).get("adaptive_weights") is None


def test_adaptive_on_uses_one_unit_per_round_and_records_the_trace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result, session, records = _run(tmp_path, ["--adapt-weights"])

    assert result.exit_code == 0, result.output
    assert all(len(r["method_chain"]) == 1 for r in records), \
        "adaptive mode must not chain mutations (credit assignment)"

    trace = [json.loads(l) for l in (session / "weights.jsonl").read_text().splitlines()]
    assert len(trace) == 30
    assert all(set(line) >= {"round", "unit", "reward", "probability"} for line in trace)
    assert all(line["unit"] == rec["method_chain"][0] for line, rec in zip(trace, records))

    summary = json.loads((session / "summary.json").read_text())
    adaptive = summary["adaptive_weights"]
    assert adaptive["enabled"] is True
    assert adaptive["attribution"] == "single_unit"
    assert adaptive["attributed_rounds"] == 30
    assert adaptive["reward"] == "response"
    assert "units" in adaptive and adaptive["units"]
    # probabilities stay normalised after the run (each is rounded to 4 dp in the
    # snapshot, so allow for accumulated rounding across all units)
    assert pytest.approx(sum(v["probability"] for v in adaptive["units"].values()), abs=0.02) == 1.0

    session_meta = json.loads((session / "session.json").read_text())
    assert session_meta["adaptive_weights"]["attribution"] == "single_unit"


def test_adaptive_in_lock_mode_schedules_spans(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result, session, records = _run(tmp_path, ["--adapt-weights", "--lock-fields", "all"])

    assert result.exit_code == 0, result.output
    assert all(len(r["method_chain"]) == 1 for r in records)
    assert all(r["method_chain"][0].startswith("locked_equal_length_value:value-type")
               for r in records)
    units = json.loads((session / "summary.json").read_text())["adaptive_weights"]["units"]
    assert set(units) == {"locked_equal_length_value:value-type41",
                          "locked_equal_length_value:value-type44",
                          "locked_equal_length_value:value-type1048"}


def test_adaptive_valid_reward_mode_is_recorded(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result, session, _ = _run(tmp_path, ["--adapt-weights", "--adapt-reward", "valid"], rounds=5)

    assert result.exit_code == 0, result.output
    assert json.loads((session / "summary.json").read_text())["adaptive_weights"]["reward"] == "valid"


def test_cli_rejects_bad_adapt_options():
    for args, expected in (
        (["--adapt-reward", "nonsense"], "--adapt-reward must be"),
        (["--adapt-floor", "1.5"], "--adapt-floor must be in"),
    ):
        result = CliRunner().invoke(app, ["--ac-ip", "127.0.0.1"] + args)
        assert result.exit_code != 0
        assert expected in result.output
