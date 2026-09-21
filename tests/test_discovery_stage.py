"""Discovery stage (plan D0/D1): mutators, canary, CLI switch, loopback run.

Field assertions follow docs/reference/RFC5415-头部与分片字段表-20260921.md
(RFC 5415 §4.1/§4.3/§4.5.1) — the same authority the mutators cite.
"""

from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

import pytest

from capwap_discovery_fuzzer.discovery_stage import (
    LAYER_METHODS,
    MUTATORS,
    DiscoveryStageFuzzer,
    _ctrl_off,
    _get_msgelemslen,
    _get_msgtype,
    _set_bits3,
    _set_frag,
    _set_msgtype,
    canary_check,
    expand_variants,
)
from capwap_discovery_fuzzer.stage_fuzzer import _element_offsets
from capwap_discovery_fuzzer.vendors.cisco.creator import ApIdentity


IDENT = ApIdentity(radios=((0, 0x0D), (1, 0x0A)), num_encrypt=1,
                   model=b"C9105AXI-C")


@pytest.fixture(scope="module")
def seed() -> bytes:
    fuzzer = DiscoveryStageFuzzer(ac_addr=("127.0.0.1", 5246), out_dir=Path("unused"),
                                  identities=(IDENT,), variants=["base"],
                                  rounds_per_variant=0)
    return fuzzer._build_seed(IDENT)


# --------------------------------------------------------------------------
# seed sanity

def test_seed_shape(seed):
    hlen = (seed[1] >> 3) & 0x1F
    assert hlen == 4 and len(seed) > hlen * 4
    assert seed[0] == 0x00  # preamble: version 0, payload type 0 (§4.1)
    # layout lock (§4.3): byte2 = RID[1:0]<<6 | WBID<<1 | T; byte3 = F L W M K Flags
    assert (seed[2] >> 1) & 0x1F == 1        # WBID = 1 (IEEE 802.11)
    assert seed[2] & 1 == 0                  # T = 0
    assert seed[3] == 0x10                   # M=1 only (0b000_10000)
    types = [t for t, _s, _l in _element_offsets(seed)]
    assert types[0] == 20 and types.count(37) == 2 and 1048 in types
    # MsgElemsLen counts from after SeqNum: = elements + MsgElemsLen(2) + Flags(1)
    declared = _get_msgelemslen(seed)
    assert len(seed) == hlen * 4 + 5 + declared


# --------------------------------------------------------------------------
# m1 — length crossings

def test_m1_len_decl_gt(seed):
    datagrams, desc = MUTATORS["len-decl-gt"][1](seed, None)
    (d,) = datagrams
    assert len(d) == len(seed)  # bytes unchanged, only the declaration moved
    assert _get_msgelemslen(d) == _get_msgelemslen(seed) + 64
    assert desc["cite"] == "RFC5415 §4.5.1.3"


def test_m1_len_decl_lt(seed):
    (d,) = MUTATORS["len-decl-lt"][1](seed, None)[0]
    assert _get_msgelemslen(d) == 0


def test_m1_len_elem_overrun(seed):
    (d,) = MUTATORS["len-elem-overrun"][1](seed, None)[0]
    # walk the *unmutated* seed for element 38's offset: the mutated frame no
    # longer parses past the overrun element (that is the point of the variant)
    t38 = next(s for t, s, l in _element_offsets(seed) if t == 38)
    assert int.from_bytes(d[t38 + 2:t38 + 4], "big") == 0xFFFF
    assert len(d) == len(seed)


def test_m1_len_hlen_mismatch(seed):
    (d,) = MUTATORS["len-hlen-mismatch"][1](seed, None)[0]
    assert ((d[1] >> 3) & 0x1F) == 2


# --------------------------------------------------------------------------
# m2 — fragment fields (RFC 5415 §4.3)

def _hdr_of(d):
    """Fragment/header fields at their RFC 5415 §4.3 bit positions."""
    return {
        "F": (d[3] >> 7) & 1, "L": (d[3] >> 6) & 1,
        "frag_id": int.from_bytes(d[4:6], "big"),
        "offset_units": ((d[6] << 8) | d[7]) >> 3,
    }


def test_m2_frag_single_off(seed):
    (d,) = MUTATORS["frag-single-off"][1](seed, None)[0]
    h = _hdr_of(d)
    assert h["F"] == 1 and h["L"] == 1 and h["frag_id"] == 1
    assert h["offset_units"] == 0


def test_m2_frag_missing_truncates_tail(seed):
    (d,) = MUTATORS["frag-missing"][1](seed, None)[0]
    h = _hdr_of(d)
    assert h["F"] == 1 and h["L"] == 0 and h["offset_units"] == 0
    assert len(d) < len(seed)


def test_m2_frag_overlap_offsets_overlap(seed):
    d1, d2 = MUTATORS["frag-overlap"][1](seed, None)[0]
    h1, h2 = _hdr_of(d1), _hdr_of(d2)
    assert h1["frag_id"] == h2["frag_id"]
    end1 = h1["offset_units"] * 8 + len(d1) - (seed[1] >> 3 & 0x1F) * 4
    assert h2["offset_units"] * 8 < end1  # RFC-forbidden overlap, txt 2717


def test_m2_frag_oob_offset(seed):
    (d,) = MUTATORS["frag-oob-offset"][1](seed, None)[0]
    assert _hdr_of(d)["offset_units"] == 0x1FFF


def test_m2_frag_rsvd_nonzero(seed):
    (d,) = MUTATORS["frag-rsvd-nonzero"][1](seed, None)[0]
    assert (d[7] & 0x7) == 0x7


def test_m2_set_frag_roundtrip(seed):
    d = _set_frag(seed, frag_id=0xBEEF, offset_units=0x1234)
    assert int.from_bytes(d[4:6], "big") == 0xBEEF
    assert ((d[6] << 8) | d[7]) >> 3 == 0x1234


# --------------------------------------------------------------------------
# m3 — header matrix

def test_m3_version_and_ptype(seed):
    (d1,) = MUTATORS["hdr-version-1"][1](seed, None)[0]
    (d15,) = MUTATORS["hdr-version-15"][1](seed, None)[0]
    (dt,) = MUTATORS["hdr-ptype-dtls"][1](seed, None)[0]
    assert d1[0] == 0x10 and d15[0] == 0xF0 and dt[0] == 0x01


def test_m3_wbid_reserved(seed):
    for name, val in [("hdr-wbid-0", 0), ("hdr-wbid-2", 2), ("hdr-wbid-31", 31)]:
        (d,) = MUTATORS[name][1](seed, None)[0]
        assert ((d[2] >> 1) & 0x1F) == val


def test_m3_t_k_bits(seed):
    (dt,) = MUTATORS["hdr-t-bit"][1](seed, None)[0]
    (dk,) = MUTATORS["hdr-k-bit"][1](seed, None)[0]
    assert dt[2] & 0x1 and not seed[2] & 0x1
    assert dk[3] & 0x08 and not seed[3] & 0x08


def test_m3_m0_keeps_header_bytes(seed):
    (d,) = MUTATORS["hdr-m0"][1](seed, None)[0]
    assert not d[3] & 0x10
    assert len(d) == len(seed) and ((d[1] >> 3) & 0x1F) == 4


def test_m3_rid_and_flags(seed):
    (dr,) = MUTATORS["hdr-rid-31"][1](seed, None)[0]
    assert (((dr[1] & 0x7) << 2) | (dr[2] >> 6)) == 31
    (df,) = MUTATORS["hdr-flags-nonzero"][1](seed, None)[0]
    assert (df[3] & 0x7) == 0x7


def test_m3_wsi_grows_header(seed):
    (d,) = MUTATORS["hdr-wsi-present"][1](seed, None)[0]
    assert ((d[1] >> 3) & 0x1F) == 6
    assert d[3] & 0x20
    assert len(d) == len(seed) + 8


# --------------------------------------------------------------------------
# m4 / m5

def test_m4_nest_and_elemid_sweep(seed):
    (dn,) = MUTATORS["nest-depth-4"][1](seed, None)[0]
    types = [t for t, _s, _l in _element_offsets(dn)]
    assert types.count(37) == 3  # seed had 2
    (ds,) = MUTATORS["elemid-sweep"][1](seed, None)[0]
    vsps = [int.from_bytes(ds[s + 8:s + 10], "big")
            for t, s, l in _element_offsets(ds)
            if t == 37 and l >= 6]
    assert vsps[-4:] == [1, 255, 32767, 65535]


def test_m5_msgtypes_and_seq(seed):
    (d5,) = MUTATORS["plain-non-disc"][1](seed, None)[0]
    (d13,) = MUTATORS["plain-echo"][1](seed, None)[0]
    (d100,) = MUTATORS["msgtype-undef"][1](seed, None)[0]
    assert _get_msgtype(d5) == 5 and _get_msgtype(d13) == 13
    assert _get_msgtype(d100) == 100
    (dj,) = MUTATORS["seq-jump"][1](seed, None)[0]
    assert dj[_ctrl_off(dj) + 4] == 200
    dup = MUTATORS["seq-dup"][1](seed, None)[0]
    assert dup == [seed, seed]


def test_m6_classic_random_differs(seed):
    import random
    (d,) = MUTATORS["classic-random"][1](seed, random.Random(42))[0]
    assert d != seed


# --------------------------------------------------------------------------
# registry / selection

def test_expand_variants_layers_and_all():
    assert expand_variants("m1") == [
        "len-decl-gt", "len-decl-lt", "len-elem-overrun", "len-hlen-mismatch"]
    assert "frag-overlap" in expand_variants("m2,base")
    assert expand_variants("all") == list(MUTATORS)
    assert LAYER_METHODS["m6"] == ["classic-random"]
    with pytest.raises(ValueError):
        expand_variants("nope")


# --------------------------------------------------------------------------
# canary (declared vs actual, RFC 5415 §4.5.1.3)

def test_canary_exact_reply_is_not_suspect(seed):
    reply = _set_msgtype(seed, 2)
    c = canary_check(reply)
    assert c["parse"] == "ok" and c["msgtype"] == 2
    assert c["extra_bytes"] == 0 and not c["leak_suspect"]


def test_canary_flags_extra_bytes(seed):
    reply = _set_msgtype(seed, 2) + b"\xde\xad" * 8
    c = canary_check(reply)
    assert c["leak_suspect"] and c["extra_bytes"] == 16


def test_canary_short_inputs():
    assert canary_check(b"\x00")["parse"] == "too-short"
    assert canary_check(b"\x00" * 9)["parse"] in ("short-header", "ok")


# --------------------------------------------------------------------------
# D0: CLI switch

def test_cli_discovery_is_default_and_needs_no_cert(tmp_path, monkeypatch):
    from capwap_discovery_fuzzer import stage_fuzzer as sf

    # discovery on a closed loopback port: one silent round, no cert args
    rc = sf.main(["--ac-ip", "127.0.0.1", "--ac-port", "5246",
                  "--out-dir", str(tmp_path / "out"), "--rounds", "1",
                  "--round-gap", "0", "--stage-timeout", "0.2",
                  "--variants", "base", "--seed", "1"])
    assert rc == 0
    summary = json.loads((tmp_path / "out" / "summary.json").read_text())
    assert summary["stage"] == "discovery"
    assert summary["totals"]["rounds"] == 1
    lines = (tmp_path / "out" / "session.jsonl").read_text().splitlines()
    rec = json.loads(lines[-1])
    assert rec["stage"] == "discovery" and rec["outcome"] == "silence"


def test_cli_join_requires_cert(tmp_path):
    from capwap_discovery_fuzzer import stage_fuzzer as sf
    with pytest.raises(SystemExit):
        sf.main(["--stage", "join", "--out-dir", str(tmp_path / "o")])


# --------------------------------------------------------------------------
# loopback answered round with leaky reply

def test_loopback_answered_with_leak_detection(tmp_path):
    responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    responder.bind(("127.0.0.1", 0))
    port = responder.getsockname()[1]
    fuzzer = DiscoveryStageFuzzer(
        ac_addr=("127.0.0.1", port), out_dir=tmp_path,
        identities=(IDENT,), variants=["base", "len-decl-gt"],
        rounds_per_variant=1, seed=7, response_timeout=1.0, round_gap=0.0)

    def serve():
        fuzzer_probe = DiscoveryStageFuzzer(
            ac_addr=("127.0.0.1", port), out_dir=tmp_path,
            identities=(IDENT,), variants=[], rounds_per_variant=0)
        reply = bytearray(fuzzer_probe._build_seed(IDENT))
        reply = bytearray(_set_msgtype(bytes(reply), 2))
        leaky = bytes(reply) + b"\xff" * 16
        for _ in range(2):
            data, addr = responder.recvfrom(65535)
            responder.sendto(leaky, addr)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    summary = fuzzer.run()
    t.join(timeout=5)
    responder.close()

    assert summary["totals"]["answered"] == 2
    assert summary["totals"]["leak_suspect"] == 2
    lines = (tmp_path / "session.jsonl").read_text().splitlines()
    rec = json.loads(lines[0])
    assert rec["canary"]["leak_suspect"] is True
    assert rec["canary"]["extra_bytes"] == 16
