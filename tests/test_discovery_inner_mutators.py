"""m7/m8/m9 mutation layers (2026-09-23 audit implementation) + probe/crash
oracle.  Byte-level expectations follow vendors/zywall/elements.py (the
authoritative t39 layout) and the F2 evidence (docs/evidence/zywall310-20260922/
F2-预认证崩溃复现与定向化-20260923.md: len2=0x4000 + TLV=0xFFFF = one-packet
SIGSEGV in capwap_msg_get_t39).

Mutants that lie in an element TLV length are intentionally unparseable by
_element_offsets (the honest walk breaks) — tests therefore take offsets from
the honest seed and read lying TLV bytes directly.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from capwap_discovery_fuzzer.discovery_stage import (
    LAYER_METHODS,
    MUTATORS,
    ZYWALL_ONLY_VARIANTS,
    DiscoveryStageFuzzer,
    _ctrl_off,
    _get_msgelemslen,
    _set_msgtype,
    expand_variants,
)
from capwap_discovery_fuzzer.stage_fuzzer import _element_offsets
from capwap_discovery_fuzzer.vendors.cisco.creator import ApIdentity
from capwap_discovery_fuzzer.vendors.zywall.creator import ZywallIdentity


ZIDENT = ZywallIdentity()
CIDENT = ApIdentity(radios=((0, 0x0D), (1, 0x0A)), num_encrypt=1,
                    model=b"C9105AXI-C")


def _zy_fuzzer() -> DiscoveryStageFuzzer:
    return DiscoveryStageFuzzer(ac_addr=("127.0.0.1", 5246), out_dir=Path("unused"),
                                identities=(ZIDENT,), variants=["base"],
                                rounds_per_variant=0, probe=False)


@pytest.fixture(scope="module")
def zseed() -> bytes:
    return _zy_fuzzer()._build_seed(ZIDENT)


def _honest_geom(zseed: bytes) -> dict:
    """t39/t37 geometry of the honest seed: starts, value offsets, len1/l2."""
    elems = _element_offsets(zseed)
    i39 = next(i for i, (t, _s, _l) in enumerate(elems) if t == 39)
    i37 = next(i for i, (t, _s, _l) in enumerate(elems) if t == 37)
    _t, s39, l39 = elems[i39]
    _t, s37, l37 = elems[i37]
    v = zseed[s39 + 4:s39 + 4 + l39]
    len1 = int.from_bytes(v[19:21], "big")
    return {"s39": s39, "l39": l39, "v39": v, "s37": s37, "l37": l37,
            "len1": len1, "l2_off": 27 + len1}


def _build(zseed: bytes, name: str, rng: random.Random) -> tuple[list[bytes], dict]:
    fuzzer = _zy_fuzzer()
    _layer, builder = MUTATORS[name]
    fn = fuzzer._builder_for(name, builder, ZIDENT)
    return fn(zseed, rng)


# --------------------------------------------------------------------------
# registry integrity: existing behaviour untouched

def test_registry_grew_from_35_keeps_names():
    assert len(MUTATORS) == 56
    for name in ("base", "len-decl-gt", "len-elem-overrun", "frag-overlap",
                 "hdr-version-1", "nest-depth-4", "plain-non-disc",
                 "classic-random"):
        assert name in MUTATORS
    assert {"m7", "m8", "m9"} <= set(LAYER_METHODS)
    assert expand_variants("m7") == [n for n in MUTATORS
                                     if MUTATORS[n][0] == "m7"]


# --------------------------------------------------------------------------
# m7 — t39 inner fields

def test_t39_len2_joint_matches_f2_weapon(zseed):
    g = _honest_geom(zseed)
    dgrams, desc = _build(zseed, "t39-len2-joint", random.Random(1))
    (pkt,) = dgrams
    assert int.from_bytes(pkt[g["s39"] + 2:g["s39"] + 4], "big") == 0xFFFF
    v = pkt[g["s39"] + 4:g["s39"] + 4 + g["l39"]]      # value length unchanged
    assert int.from_bytes(v[g["l2_off"]:g["l2_off"] + 2], "big") == 0x4000
    assert v[:2] == g["v39"][:2]                        # max/used untouched
    assert desc["op"] == "t39-len2-joint"
    assert _get_msgelemslen(pkt) == _get_msgelemslen(zseed)  # stays honest


def test_t39_len1_joint_targets_first_copy(zseed):
    g = _honest_geom(zseed)
    dgrams, _ = _build(zseed, "t39-len1-joint", random.Random(1))
    (pkt,) = dgrams
    assert int.from_bytes(pkt[g["s39"] + 2:g["s39"] + 4], "big") == 0xFFFF
    v = pkt[g["s39"] + 4:g["s39"] + 4 + g["l39"]]
    assert int.from_bytes(v[19:21], "big") == 0x4000


def test_t39_flags_shift_sets_flag_keeps_layout(zseed):
    g = _honest_geom(zseed)
    dgrams, desc = _build(zseed, "t39-flags-shift", random.Random(0))
    (pkt,) = dgrams
    assert int.from_bytes(pkt[g["s39"] + 2:g["s39"] + 4], "big") == 0xFFFF
    v = pkt[g["s39"] + 4:g["s39"] + 4 + g["l39"]]
    assert v[2] in (1, 0x7F, 0x80, 0xFF)
    assert v[19:21] == g["v39"][19:21]                  # layout untouched
    assert desc["op"] == "t39-flags-shift"


def test_t39_flags_pad_negative_control(zseed):
    g = _honest_geom(zseed)
    dgrams, _ = _build(zseed, "t39-flags-pad", random.Random(0))
    (pkt,) = dgrams
    v = pkt[g["s39"] + 4:]                              # honest TLV → walkable
    assert v[2] == 0xFF and v[3:6] == b"\x00\x00\x00"
    # shifted parser cursor (value offset +6) lands on the honest len1 bytes
    assert int.from_bytes(v[22:24], "big") == g["len1"]
    assert int.from_bytes(v[30 + g["len1"]:32 + g["len1"]], "big") \
        == int.from_bytes(g["v39"][g["l2_off"]:g["l2_off"] + 2], "big")


def test_t39_len2_ship_short_truncates_value(zseed):
    g = _honest_geom(zseed)
    dgrams, _ = _build(zseed, "t39-len2-ship-short", random.Random(0))
    (pkt,) = dgrams
    tail_elems = len(zseed) - (g["s37"])                # t37 element bytes after t39
    assert len(pkt) == g["s39"] + 4 + 29 + g["len1"] + tail_elems
    v = pkt[g["s39"] + 4:g["s39"] + 4 + 29 + g["len1"]]
    assert int.from_bytes(v[g["l2_off"]:g["l2_off"] + 2], "big") == 0x8000


def test_t37_subelem_sweep_appends_known_id(zseed):
    g = _honest_geom(zseed)
    dgrams, desc = _build(zseed, "t37-subelem-sweep", random.Random(3))
    (pkt,) = dgrams
    new_l37 = int.from_bytes(pkt[g["s37"] + 2:g["s37"] + 4], "big")
    assert new_l37 == g["l37"] + 2 + desc["vlen"]
    sub_id = int.from_bytes(pkt[g["s37"] + 4 + g["l37"]:
                                g["s37"] + 6 + g["l37"]], "big")
    assert sub_id == int(desc["sub_id"], 16)
    assert sub_id in (0x3, 0x6, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                      0x1A, 0x1C, 0x1D)


def test_gate_boundary_and_modelid_write_fields(zseed):
    g = _honest_geom(zseed)
    for name, check in (
        ("t39-gate-boundary",
         lambda v, d: (v[0], v[1]) == (d["max_radios"], d["used"])),
        ("t39-modelid-sweep",
         lambda v, d: int.from_bytes(v[11:13], "big") == int(d["model_id"], 16)),
    ):
        dgrams, desc = _build(zseed, name, random.Random(9))
        (pkt,) = dgrams
        v = pkt[g["s39"] + 4:g["s39"] + 4 + g["l39"]]
        assert check(v, desc)


# --------------------------------------------------------------------------
# m8 — structural operations

def test_elem_dup_t39_appends_second_copy(zseed):
    dgrams, _ = _build(zseed, "elem-dup-t39", random.Random(0))
    (pkt,) = dgrams
    types = [t for t, _s, _l in _element_offsets(pkt)]
    assert types.count(39) == 2
    assert _get_msgelemslen(pkt) == len(pkt) - _ctrl_off(pkt) - 8 + 3


def test_elem_swap_39_37_keeps_lengths(zseed):
    g = _honest_geom(zseed)
    dgrams, _ = _build(zseed, "elem-swap-39-37", random.Random(0))
    (pkt,) = dgrams
    types = [t for t, _s, _l in _element_offsets(pkt)]
    assert types[:2] == [37, 39]                        # swapped
    assert len(pkt) == len(zseed)
    assert _get_msgelemslen(pkt) == _get_msgelemslen(zseed)


def test_elem_drop_t39_and_len_shrink(zseed):
    dgrams, _ = _build(zseed, "elem-drop-t39", random.Random(0))
    (pkt,) = dgrams
    assert all(t != 39 for t, _s, _l in _element_offsets(pkt))
    dgrams, desc = _build(zseed, "elem-len-shrink", random.Random(1))
    (pkt,) = dgrams
    assert desc["new_len"] < desc["old_len"]


def test_datagram_trunc_cuts_after_len2_field(zseed):
    g = _honest_geom(zseed)
    dgrams, desc = _build(zseed, "datagram-trunc-t39", random.Random(0))
    (pkt,) = dgrams
    cut = g["s39"] + 4 + g["l2_off"] + 2                # end of the len2 field
    assert len(pkt) == desc["cut_at"] == cut


def test_len_tiny_band_writes_control_len(zseed):
    dgrams, desc = _build(zseed, "len-tiny-band", random.Random(5))
    (pkt,) = dgrams
    assert _get_msgelemslen(pkt) == desc["new"]


# --------------------------------------------------------------------------
# m9 — stacked / grooming / dictionary

def test_groom_then_trigger_is_four_datagrams(zseed):
    g = _honest_geom(zseed)
    dgrams, desc = _build(zseed, "groom-then-trigger", random.Random(0))
    assert len(dgrams) == 4 and desc["op"] == "groom-then-trigger"
    trig = dgrams[-1]
    assert int.from_bytes(trig[g["s39"] + 2:g["s39"] + 4], "big") == 0xFFFF
    tv = trig[g["s39"] + 4:g["s39"] + 4 + g["l39"]]
    assert int.from_bytes(tv[g["l2_off"]:g["l2_off"] + 2], "big") == 0x4000
    groom_v = dgrams[0][g["s39"] + 4:g["s39"] + 4 + g["l39"]]
    assert groom_v[21:21 + g["len1"]] == (b"\xff\x7f" * 8)[:g["len1"]]
    assert groom_v[19:21] == g["v39"][19:21]            # declared len1 honest


def test_stacked_havoc_deterministic_and_header_intact(zseed):
    d1, desc1 = _build(zseed, "stacked-havoc", random.Random(42))
    d2, desc2 = _build(zseed, "stacked-havoc", random.Random(42))
    assert d1[0] == d2[0] and desc1 == desc2
    assert 2 <= desc1["n_ops"] <= 6 and len(desc1["ops"]) == desc1["n_ops"]
    pkt = d1[0]
    assert (pkt[1] >> 3) & 0x1F == 2                    # HLEN untouched


def test_magic_dict_len_hits_chosen_field(zseed):
    g = _honest_geom(zseed)
    dgrams, desc = _build(zseed, "magic-dict-len", random.Random(7))
    (pkt,) = dgrams
    if desc["field"] == "msgelemslen":
        assert _get_msgelemslen(pkt) == desc["value"]
    elif desc["field"] == "tlv39":
        assert int.from_bytes(pkt[g["s39"] + 2:g["s39"] + 4], "big") == desc["value"]
    elif desc["field"] == "tlv37":
        assert int.from_bytes(pkt[g["s37"] + 2:g["s37"] + 4], "big") == desc["value"]
    else:
        v = pkt[g["s39"] + 4:g["s39"] + 4 + g["l39"]]
        off = 19 if desc["field"] == "l1" else g["l2_off"]
        assert int.from_bytes(v[off:off + 2], "big") == desc["value"]


# --------------------------------------------------------------------------
# vendor dispatch + probe/crash oracle

def test_cisco_identity_skips_zywall_only_variants():
    fuzzer = DiscoveryStageFuzzer(ac_addr=("127.0.0.1", 5246), out_dir=Path("unused"),
                                  identities=(CIDENT,), variants=["base"],
                                  rounds_per_variant=0, probe=False)
    for name in ZYWALL_ONLY_VARIANTS:
        _layer, default = MUTATORS[name]
        assert fuzzer._builder_for(name, default, CIDENT).__name__ == "_m_vendor_skip"


def test_probe_and_crash_evidence(tmp_path, monkeypatch):
    fuzzer = DiscoveryStageFuzzer(ac_addr=("127.0.0.1", 5246), out_dir=tmp_path,
                                  identities=(ZIDENT,), variants=["base"],
                                  rounds_per_variant=0, probe=True)
    path = fuzzer._record_crash(12, "t39-len2-joint", [b"\xde\xad"], {"op": "x"},
                                alive=False)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["datagrams_hex"] == ["dead"] and data["probe_alive_after"] is False
    assert path.parent.name == "crash"


def test_probe_on_loopback_detects_death(tmp_path):
    """Integration: responder answers the first packets then dies — the round
    whose probe goes silent right after a live one is flagged crash_suspect
    with a full evidence file."""
    import socket
    import threading

    responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    responder.bind(("127.0.0.1", 0))
    port = responder.getsockname()[1]
    fuzzer = DiscoveryStageFuzzer(
        ac_addr=("127.0.0.1", port), out_dir=tmp_path,
        identities=(ZIDENT,), variants=["base"], rounds_per_variant=3,
        seed=1, response_timeout=0.5, round_gap=0.0, probe=True,
        probe_timeout=0.4)

    def serve():
        probe_fuzzer = DiscoveryStageFuzzer(
            ac_addr=("127.0.0.1", port), out_dir=tmp_path,
            identities=(ZIDENT,), variants=[], rounds_per_variant=0)
        reply = bytearray(probe_fuzzer._build_seed(ZIDENT))
        reply = bytearray(_set_msgtype(bytes(reply), 20))
        n = 0
        while n < 9:                       # baseline + 3 rounds × (dgram+probe)
            try:
                data, addr = responder.recvfrom(65535)
            except socket.timeout:
                break
            n += 1
            if n <= 5:                     # baseline + rounds 1-2 fully, die at r3
                responder.sendto(bytes(reply), addr)

    responder.settimeout(6.0)
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    summary = fuzzer.run()          # run() opens with a baseline probe (n=1)
    t.join(timeout=8)
    responder.close()

    assert summary["totals"]["answered"] == 2
    assert summary["totals"]["crash_suspect"] == 1
    assert len(summary["crash_files"]) == 1
    lines = (tmp_path / "session.jsonl").read_text().splitlines()
    rec3 = json.loads(lines[2])
    assert rec3["crash_suspect"] is True
    assert rec3["probe_alive"] is False
    assert rec3["req_hex"] and bytes.fromhex(rec3["req_hex"])
    evidence = json.loads(Path(summary["crash_files"][0]).read_text(
        encoding="utf-8"))
    assert evidence["datagrams_hex"] == [rec3["req_hex"]]


def test_probe_on_loopback_round1_kill(tmp_path):
    """F3 smoke finding: a first-round kill (baseline probe alive, round-1
    probe silent) must be recorded — prev_alive starts from the baseline."""
    import socket
    import threading

    responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    responder.bind(("127.0.0.1", 0))
    port = responder.getsockname()[1]
    fuzzer = DiscoveryStageFuzzer(
        ac_addr=("127.0.0.1", port), out_dir=tmp_path,
        identities=(ZIDENT,), variants=["base"], rounds_per_variant=1,
        seed=1, response_timeout=0.5, round_gap=0.0, probe=True,
        probe_timeout=0.4)

    def serve():
        probe_fuzzer = DiscoveryStageFuzzer(
            ac_addr=("127.0.0.1", port), out_dir=tmp_path,
            identities=(ZIDENT,), variants=[], rounds_per_variant=0)
        reply = bytes(bytearray(_set_msgtype(
            bytearray(probe_fuzzer._build_seed(ZIDENT)), 20)))
        n = 0
        while n < 2:                       # baseline probe + round-1 datagram
            try:
                data, addr = responder.recvfrom(65535)
            except socket.timeout:
                break
            n += 1
            responder.sendto(reply, addr)  # round-1 probe never answered

    responder.settimeout(6.0)
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    summary = fuzzer.run()
    t.join(timeout=8)
    responder.close()

    assert summary["totals"]["answered"] == 1
    assert summary["totals"]["crash_suspect"] == 1
    lines = (tmp_path / "session.jsonl").read_text().splitlines()
    rec1 = json.loads(lines[0])
    assert rec1["round"] == 1 and rec1["crash_suspect"] is True
