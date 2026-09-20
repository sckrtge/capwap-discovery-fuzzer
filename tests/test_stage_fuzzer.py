"""Join-variant construction and round execution (mock transport)."""

from __future__ import annotations

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
