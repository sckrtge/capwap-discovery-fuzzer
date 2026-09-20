"""Join-variant construction and round execution (mock transport)."""

from __future__ import annotations

from pathlib import Path

import pytest

from capwap_discovery_fuzzer.session.builders import parse_control_messages
from capwap_discovery_fuzzer.stage_fuzzer import (
    JoinFuzzConfig,
    _shift_board_subelem_types,
    build_variant,
)
from tests.test_session_builders import _golden_identity

AC = ("192.168.10.201", 5246)


def _cfg(tmp_path) -> JoinFuzzConfig:
    return JoinFuzzConfig(ac_addr=AC, cert_path="c.pem", key_path="k.pem",
                          identity=_golden_identity(), out_dir=tmp_path)


KNOWN_VARIANTS = [
    "base", "omit-126", "omit-169", "omit-37", "omit-29", "omit-53", "omit-30",
    "maxmsglen-0", "maxmsglen-65535", "radio-1base", "radio-type-b-a",
    "regdom-code-0", "regdom-code-FFFF", "boarddata-shift",
    "session-zero", "session-short8",
]


def test_all_variants_build():
    cfg = _cfg(None)
    for name in KNOWN_VARIANTS:
        raw = build_variant(name, cfg, session_id=bytes(16))
        # every variant still parses as exactly one Join Request
        msgs = parse_control_messages(raw)
        assert len(msgs) == 1 and msgs[0]["msg_type"] == 3, name


def test_base_variant_omits_nothing():
    cfg = _cfg(None)
    msgs = parse_control_messages(build_variant("base", cfg, bytes(16)))
    types = [t for t, _l, _v in msgs[0]["elements"]]
    for t in (29, 30, 35, 53, 126, 169):
        assert t in types


def test_omit_variants_drop_exactly_their_element():
    cfg = _cfg(None)
    sid = bytes(16)
    cases = {
        "omit-126": 126, "omit-169": 169, "omit-37": 37, "omit-29": 29,
        "omit-53": 53, "omit-30": 30,
    }
    for name, absent in cases.items():
        types = [t for m in parse_control_messages(build_variant(name, cfg, sid))
                 for t, _l, _v in m["elements"]]
        assert absent not in types, name


def test_maxmsglen_values_on_wire():
    cfg = _cfg(None)
    for name, expected in (("maxmsglen-0", 0), ("maxmsglen-65535", 65535)):
        msgs = parse_control_messages(build_variant(name, cfg, bytes(16)))
        val = next(v for t, _l, v in msgs[0]["elements"] if t == 29)
        assert int.from_bytes(val, "big") == expected


def test_radio_1base_changes_radio_ids():
    cfg = _cfg(None)
    msgs = parse_control_messages(build_variant("radio-1base", cfg, bytes(16)))
    ids = [v[0] for t, _l, v in msgs[0]["elements"] if t == 1048]
    assert ids == [1, 2]


def test_boarddata_shift_moves_subelem_types():
    ident = _golden_identity()
    board = ident.board_data()
    shifted = _shift_board_subelem_types(board, +1)
    assert shifted[:4] == board[:4]                      # vendor id untouched
    assert len(shifted) == len(board)                    # lengths preserved
    import struct
    t_orig = struct.unpack_from(">H", board, 4)[0]
    t_shift = struct.unpack_from(">H", shifted, 4)[0]
    assert t_shift == (t_orig + 1) & 0xFFFF


def test_unknown_variant_rejected():
    with pytest.raises(ValueError):
        build_variant("no-such-variant", _cfg(None), bytes(16))


def test_session_variants_roundtrip():
    cfg = _cfg(None)
    for name in ("session-zero", "session-short8"):
        msgs = parse_control_messages(build_variant(name, cfg, bytes(16)))
        assert len(msgs) == 1 and msgs[0]["msg_type"] == 3, name
    # session-short8 really shrinks the element value to 8 bytes
    msgs = parse_control_messages(build_variant("session-short8", cfg, bytes(16)))
    sid = next(v for t, _l, v in msgs[0]["elements"] if t == 35)
    assert len(sid) == 8


def test_unlocked_mutates_only_open_elements():
    import random
    from capwap_discovery_fuzzer.stage_fuzzer import (
        LOCKED_ELEMENT_TYPES, build_unlocked_variant)
    cfg = _cfg(None)
    rng = random.Random(7)
    for _ in range(50):
        raw, mut = build_unlocked_variant(cfg, rng, session_id=bytes(16))
        assert mut["type"] not in LOCKED_ELEMENT_TYPES
        msgs = parse_control_messages(raw)
        assert len(msgs) == 1 and msgs[0]["msg_type"] == 3
        # frozen identity elements stay present in every unlocked round
        types = [t for t, _l, _v in msgs[0]["elements"]]
        assert 38 in types and 35 in types and 29 in types


# ------------------------------------------------------- identity pool (P4.5)

def test_identity_pool_derives_distinct_identities():
    from capwap_discovery_fuzzer.stage_fuzzer import build_identity_pool
    base = _golden_identity()
    pool = build_identity_pool(base, 4)
    assert len(pool) == 4
    assert pool[0] is base                       # the base identity is reused
    macs = [i.ap_mac for i in pool]
    assert len(set(macs)) == 4                   # all distinct
    for ident in pool[1:]:
        # only the identifiable fields move; everything else is untouched
        assert ident.model == base.model
        assert ident.radios == base.radios
        assert ident.num_encrypt == base.num_encrypt
        assert ident.ap_name.startswith(b"AP")
        assert len(ident.ap_name) == 16          # APxxxx.xxxx.xxxx
        assert ident.ap_name[2:6] == ident.ap_mac.hex().upper().encode()[:4]


def test_identity_pool_of_one_is_empty():
    from capwap_discovery_fuzzer.stage_fuzzer import build_identity_pool
    assert build_identity_pool(_golden_identity(), 1) == ()
    assert build_identity_pool(_golden_identity(), 0) == ()


def test_round_robin_over_identity_pool(tmp_path):
    from capwap_discovery_fuzzer.stage_fuzzer import (
        JoinStageFuzzer, build_identity_pool)
    base = _golden_identity()
    pool = build_identity_pool(base, 3)
    cfg = JoinFuzzConfig(ac_addr=AC, cert_path="c.pem", key_path="k.pem",
                         identity=base, out_dir=tmp_path, identity_pool=pool)
    fuzzer = JoinStageFuzzer(cfg)
    picked = [fuzzer._identity_for(n).ap_mac for n in range(1, 8)]
    assert picked == [pool[n % 3].ap_mac for n in range(7)]
    assert len(set(picked)) == 3


def test_variant_honours_identity_override():
    from capwap_discovery_fuzzer.stage_fuzzer import build_identity_pool
    cfg = _cfg(None)
    alt = build_identity_pool(_golden_identity(), 2)[1]
    base_frame = build_variant("base", cfg, session_id=bytes(16))
    alt_frame = build_variant("base", cfg, session_id=bytes(16), identity=alt)
    assert base_frame != alt_frame
    # the override is what the controller sees as the AP: its WTP name
    # (element 45) and board-data base MAC both reach the wire
    msgs = parse_control_messages(alt_frame)
    name = next(v for t, _l, v in msgs[0]["elements"] if t == 45)
    assert alt.ap_name in name
    assert alt.base_mac in \
        next(v for t, _l, v in msgs[0]["elements"] if t == 38)


def test_single_identity_defaults_unchanged():
    """Pool of one must reproduce the historical frame byte for byte."""
    from capwap_discovery_fuzzer.stage_fuzzer import build_identity_pool
    cfg = _cfg(None)
    assert build_identity_pool(cfg.identity, 1) == ()
    assert cfg.identities() == (cfg.identity,)
    assert build_variant("base", cfg, session_id=bytes(16)) == \
        build_variant("base", cfg, session_id=bytes(16), identity=cfg.identity)


# ------------------------------------------------- P5 config / change state

def test_config_variants_parse_and_base_is_golden():
    from capwap_discovery_fuzzer.stage_fuzzer import (
        CONFIG_VARIANTS, build_config_variant)
    cfg = _cfg(None)
    ident = _golden_identity()
    for name in CONFIG_VARIANTS:
        raw = build_config_variant(name, cfg, ident)
        msgs = parse_control_messages(raw)
        assert len(msgs) == 1 and msgs[0]["msg_type"] == 5, name
    golden = (Path(__file__).parent / "golden" / "golden_csr.bin").read_bytes()
    assert build_config_variant("base", cfg, ident) == golden


def test_change_state_variants_parse_and_base_is_golden():
    from capwap_discovery_fuzzer.stage_fuzzer import (
        CHANGE_STATE_VARIANTS, build_change_state_variant)
    cfg = _cfg(None)
    ident = _golden_identity()
    for name in CHANGE_STATE_VARIANTS:
        raw = build_change_state_variant(name, cfg, ident)
        msgs = parse_control_messages(raw)
        assert len(msgs) == 1 and msgs[0]["msg_type"] == 11, name
    golden = (Path(__file__).parent / "golden" / "golden_cse.bin").read_bytes()
    assert build_change_state_variant("base", cfg, ident) == golden


def _seq_of(raw):
    """Control_Header SeqNum: MsgType(4B) then SeqNum(1B), at hlen + 4."""
    return raw[((raw[1] >> 3) & 0x1F) * 4 + 4]


def _types(raw):
    return [t for t, _l, _v in parse_control_messages(raw)[0]["elements"]]


def _vsp_values(raw, elem_id):
    out = []
    for t, _l, v in parse_control_messages(raw)[0]["elements"]:
        if t == 37 and int.from_bytes(v[4:6], "big") == elem_id:
            out.append(v)
    return out


def test_config_must_ablations_drop_their_element():
    from capwap_discovery_fuzzer.stage_fuzzer import build_config_variant
    cfg, ident = _cfg(None), _golden_identity()
    base_types = _types(build_config_variant("base", cfg, ident))
    for name, etype in (("omit-4", 4), ("omit-timer36", 36), ("omit-reboot48", 48)):
        assert base_types.count(etype) == 1
        assert etype not in _types(build_config_variant(name, cfg, ident))
    assert base_types.count(31) == 2
    assert 31 not in _types(build_config_variant("omit-radio-admin", cfg, ident))


def test_config_vsp126_variants_reproduce_the_e7_bug():
    from capwap_discovery_fuzzer.stage_fuzzer import build_config_variant
    from capwap_discovery_fuzzer.session.vsp import VSP_ELEM_REG_DOMAIN
    cfg, ident = _cfg(None), _golden_identity()
    base = build_config_variant("base", cfg, ident)
    assert len(_vsp_values(base, VSP_ELEM_REG_DOMAIN)) == 2

    # 7-byte header: the ElemID parses as 0x0000 (E7's silent-drop switch) —
    # byte-identical to the pre-fix golden (132 B / 16d283e1...)
    len7 = build_config_variant("vsp126-len7", cfg, ident)
    assert len(len7) == len(base) + 2 and not _vsp_values(len7, VSP_ELEM_REG_DOMAIN)
    assert len7.hex().find("0040960000007e") >= 0

    assert not _vsp_values(build_config_variant("vsp126-elemid-0", cfg, ident),
                           VSP_ELEM_REG_DOMAIN)
    assert not _vsp_values(build_config_variant("vsp126-elemid-207", cfg, ident),
                           VSP_ELEM_REG_DOMAIN)
    assert len(_vsp_values(build_config_variant("omit-vsp126", cfg, ident),
                           VSP_ELEM_REG_DOMAIN)) == 0
    for name, code in (("vsp126-code-0", b"\x00\x00"),
                       ("vsp126-code-ffff", b"\xff\xff")):
        vals = _vsp_values(build_config_variant(name, cfg, ident), VSP_ELEM_REG_DOMAIN)
        assert len(vals) == 2 and all(v[9:11] == code for v in vals)


def test_config_order_duplicate_and_seq_variants():
    from capwap_discovery_fuzzer.stage_fuzzer import build_config_variant
    cfg, ident = _cfg(None), _golden_identity()
    base = build_config_variant("base", cfg, ident)
    assert _types(build_config_variant("dup-radio-admin", cfg, ident)).count(31) == 3
    assert _types(build_config_variant("swap-first-two", cfg, ident))[:2] == [31, 4]
    assert _seq_of(build_config_variant("seq-old", cfg, ident)) == 0
    assert _seq_of(build_config_variant("base", cfg, ident)) == 1
    with pytest.raises(ValueError):
        build_config_variant("nope", cfg, ident)


def test_change_state_rc_and_ablation_variants():
    from capwap_discovery_fuzzer.stage_fuzzer import build_change_state_variant
    cfg, ident = _cfg(None), _golden_identity()
    base = build_change_state_variant("base", cfg, ident)
    assert _seq_of(base) == 2
    for name, rc in (("rc-1", 1), ("rc-255", 255)):
        msgs = parse_control_messages(build_change_state_variant(name, cfg, ident))
        value = next(v for t, _l, v in msgs[0]["elements"] if t == 33)
        assert int.from_bytes(value, "big") == rc
    assert 33 not in _types(build_change_state_variant("omit-result", cfg, ident))
    assert 32 not in _types(build_change_state_variant("omit-radio-op", cfg, ident))
    assert 37 not in _types(build_change_state_variant("omit-vsp", cfg, ident))
    assert _types(build_change_state_variant("dup-radio-op", cfg, ident)).count(32) == 3


def test_stage_round_joins_with_base_then_sends_the_stage_variant(monkeypatch, tmp_path):
    """A config/change-state round must join with `base`, not with the variant."""
    import capwap_discovery_fuzzer.stage_fuzzer as sf
    sent: list[bytes] = []

    # real Join Response captured from C9800-fresh 17.14.01 (Result Code 0);
    # its envelope is enough for the config leg to be reached
    join_response = bytes.fromhex(
        "0010000000000000000000040000730000210004000000000001001800002710000003e802"
        "0100020040960000010004110e004f0004000943393830302d4c414204180005000000000e"
        "000a0006c0a80ac90000001d000214000025000f0040960000d70553000505540001000025"
        "000f0040960000d708a800050001000100")

    class _FakeTransport:
        def __init__(self, ac_addr, **kw):
            pass

        def connect(self, timeout=25.0):
            pass

        def wait_handshake(self, timeout=25.0):
            pass

        def snapshot(self):
            return len(sent)

        def send(self, data):
            sent.append(data)

        def recv_since(self, mark, timeout=3.0):
            return join_response

        @property
        def is_alive(self):
            return True

        def close(self):
            pass

    monkeypatch.setattr(sf, "SClientTransport", _FakeTransport)
    cfg = JoinFuzzConfig(ac_addr=AC, cert_path="c.pem", key_path="k.pem",
                         identity=_golden_identity(), out_dir=tmp_path,
                         retries=0, round_gap_s=0.0, discovery_prelude=False)
    ident = _golden_identity()
    verdict = sf.JoinStageFuzzer(cfg)._attempt("omit-4", 1, None, ident, "config")
    # join (golden) + the mutated config + the Change State survival probe
    assert [parse_control_messages(f)[0]["msg_type"] for f in sent] == [3, 5, 11]
    assert sent[0][:12] == build_variant("base", cfg, bytes(16),
                                         identity=ident)[:12]
    assert 4 not in _types(sent[1])             # the omit-4 variant really applied
    assert verdict.mutation["join_rc"] == 0     # envelope recorded separately
    assert verdict.mutation["variant"] == "omit-4"


def test_round_plumbs_tuned_timeouts_into_transport(monkeypatch, tmp_path):
    """Round timings come from the config, not from module constants."""
    import capwap_discovery_fuzzer.stage_fuzzer as sf
    seen: dict = {}

    class _FakeTransport:
        def __init__(self, ac_addr, **kw):
            seen.update(kw)
            self.kw = kw
            seen["ac_addr"] = ac_addr

        def connect(self, timeout=25.0):
            pass

        def wait_handshake(self, timeout=25.0):
            pass

        def snapshot(self):
            return 0

        def send(self, data):
            seen["sent"] = len(data)

        def recv_since(self, mark, timeout=3.0):
            seen["join_timeout"] = timeout
            return b""

        @property
        def is_alive(self):
            return True

        def close(self):
            pass

    monkeypatch.setattr(sf, "SClientTransport", _FakeTransport)
    cfg = JoinFuzzConfig(ac_addr=AC, cert_path="c.pem", key_path="k.pem",
                         identity=_golden_identity(), out_dir=tmp_path,
                         join_timeout=2.5, handshake_settle=0.7,
                         close_wait=0.2, round_gap_s=0.0,
                         discovery_prelude=False)
    sf.JoinStageFuzzer(cfg)._attempt("base", 1)
    assert seen["handshake_settle"] == 0.7
    assert seen["close_wait"] == 0.2
    assert seen["join_timeout"] == 2.5
    assert seen["sent"] > 0
