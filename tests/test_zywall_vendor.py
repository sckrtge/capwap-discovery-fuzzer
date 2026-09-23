"""ZyWALL 310 vendor module tests (D4 seed correctness).

Golden-byte expectations are computed from the reverse-engineered field table
(docs/reference/ZyWALL310-CAPWAP头部与Discovery字段表-20260923.md) and, where a
packet was verified in-loop, from the recorded wire bytes (G-Z2 Primary
Discovery recipe).  If a test here and the field table ever disagree, the
field table wins — fix the builder, not the test.
"""

import struct

import pytest

from capwap_discovery_fuzzer.vendors.zywall.creator import (
    DISCOVERY_REQUEST,
    PRIMARY_DISCOVERY_REQUEST,
    ZywallIdentity,
    ZywallPayloadCreator,
)
from capwap_discovery_fuzzer.vendors.zywall.elements import (
    CW_VERSION_1_00_03,
    FISH_MAGIC,
    NWA5123AC_MODEL_ID,
    ZYXEL_IANA,
    build_discovery_datagram,
    build_element,
    build_t37_fish_value,
    build_t39_value,
)


class TestT39Layout:
    """Authoritative layout: capwap_msg_get_t39 @ capwap_srv 0x100417f8,
    in-loop calibrated 2026-09-23 (modelId landed as `modelID 26e1` in the
    daemon's WTP entry; IANA_C fed the IANA gate; fwVersion landed in str1)."""

    def test_golden_bytes(self):
        v = build_t39_value(max_radios=2, used_radios=1, iana=890,
                            model_id=0x26E1, fw_version=b"6.10(###.10)b1",
                            str2=b"NWA5123-AC")
        expected = (
            b"\x02\x01\x00"
            + struct.pack(">IHHH", 890, 0, 0, 0x26E1)
            + struct.pack(">IHH", 890, 0, 14) + b"6.10(###.10)b1"
            + struct.pack(">IHH", 890, 0, 10) + b"NWA5123-AC"
        )
        assert v == expected
        assert len(v) == 3 + 10 + 22 + 18

    def test_gate_and_identity_offsets(self):
        v = build_t39_value(max_radios=3, used_radios=2, iana=890,
                            model_id=0x26E1, fw_version=b"1.2", str2=b"x")
        assert v[0] == 3                    # Max  -> gate
        assert v[1] == 2                    # Used -> gate
        assert v[2] == 0                    # flags
        assert struct.unpack(">I", v[3:7])[0] == 890        # IANA_A (mid)
        assert struct.unpack(">H", v[11:13])[0] == 0x26E1   # modelId
        assert struct.unpack(">H", v[19:21])[0] == 3        # len1
        # IANA_C — the final write to 0x93c and the value the gate compares
        off = 21 + 3
        assert struct.unpack(">I", v[off:off + 4])[0] == 890
        assert v[off + 4:off + 6] == b"\x00\x00"            # discarded u16
        assert struct.unpack(">H", v[off + 6:off + 8])[0] == 1   # len2

    def test_iana_gate_slot_follows_str1(self):
        # a different fw_version length moves IANA_C with it — the gate value
        # is position-dependent on len1, not fixed-offset
        for fw in (b"", b"1.00.03", b"6.10(###.10)b1"):
            v = build_t39_value(max_radios=2, used_radios=2,
                                fw_version=fw, str2=b"")
            off = 21 + len(fw)
            assert struct.unpack(">I", v[off:off + 4])[0] == 890


class TestT37FishLayout:
    def test_golden_bytes(self):
        mac = bytes.fromhex("000c29aabbcc")
        v = build_t37_fish_value(mac=mac, cw_version=CW_VERSION_1_00_03)
        expected = (
            struct.pack(">I", ZYXEL_IANA)
            + struct.pack(">I", 0) + struct.pack(">H", 0)
            + struct.pack(">I", 0) + struct.pack(">H", 0)
            + FISH_MAGIC
            + struct.pack(">H", 2) + mac
            + struct.pack(">H", 7) + struct.pack(">I", CW_VERSION_1_00_03)
        )
        assert v == expected
        assert len(v) == 20 + 8 + 6

    def test_mac_validation(self):
        with pytest.raises(ValueError):
            build_t37_fish_value(mac=b"\x00" * 5)

    def test_version_omittable(self):
        v = build_t37_fish_value(mac=b"\x01" * 6, cw_version=None)
        assert b"\x00\x07" not in v  # no sub-element 7 when disabled


class TestDatagramAssembly:
    def test_primary_discovery_recipe_matches_verified_wire(self):
        # G-Z2 in-loop verified: 16-byte Primary Discovery with zero elements
        # got answered (Type=20 echo).  Reproduce those bytes exactly.
        raw = build_discovery_datagram(msg_type=0x13, seq=0x2A, elements=b"")
        assert raw.hex() == "00100000" + "00000000" + "000000132a000300"

    def test_msgelemslen_counts_three_extra(self):
        elems = build_element(39, build_t39_value(max_radios=2, used_radios=1))
        raw = build_discovery_datagram(msg_type=1, seq=0, elements=elems)
        declared = struct.unpack(">H", raw[13:15])[0]
        assert declared == len(elems) + 3
        assert len(raw) == 8 + 8 + len(elems)

    def test_header_shape(self):
        raw = build_discovery_datagram(msg_type=1, seq=0, elements=b"")
        assert raw[0] == 0x00              # version 0 / preamble type 0
        assert raw[1] == 0x10              # HLEN=2 → 8-byte header, no optional
        assert raw[2] == 0x00 and raw[3] == 0x00   # RID/WBID/T, F/L/W/M/K/Flags

    def test_wbid_variant(self):
        raw = build_discovery_datagram(msg_type=1, seq=0, elements=b"", wbid=1)
        assert raw[2] == 0x02              # WBID=1 (802.11), as the AC replies


class TestIdentityAndCreator:
    def test_default_identity_passes_gates(self):
        ident = ZywallIdentity()
        assert ident.gates_ok()
        assert ident.msg_type == DISCOVERY_REQUEST

    def test_gate_boundaries(self):
        assert not ZywallIdentity(max_radios=0).gates_ok()
        assert not ZywallIdentity(max_radios=5).gates_ok()
        assert not ZywallIdentity(used_radios=0).gates_ok()
        assert not ZywallIdentity(max_radios=2, used_radios=3).gates_ok()
        assert ZywallIdentity(max_radios=4, used_radios=4).gates_ok()

    def test_seed_shape(self):
        seed = bytes(ZywallPayloadCreator().create_discovery_request(valid=True))
        assert seed[:4].hex() == "00100000"
        assert struct.unpack(">I", seed[8:12])[0] == DISCOVERY_REQUEST
        # element walk: t39 then t37, TLV-consistent with MsgElemsLen
        declared = struct.unpack(">H", seed[13:15])[0]
        assert declared == len(seed) - 16 + 3

    def test_seed_carries_gate_feeders(self):
        seed = bytes(ZywallPayloadCreator().create_discovery_request(valid=True))
        body = seed[16:]
        types = []
        off = 0
        while off < len(body):
            et, el = struct.unpack(">HH", body[off:off + 4])
            types.append(et)
            off += 4 + el
        assert types == [39, 37]
        # the t39 element value must open with the gate bytes and carry the
        # calibrated modelId / IANA_C slots
        v39_len = struct.unpack(">H", body[2:4])[0]
        v39 = body[4:4 + v39_len]
        assert v39[0] == 2 and v39[1] == 2
        assert struct.unpack(">H", v39[11:13])[0] == NWA5123AC_MODEL_ID
        off_c = 21 + struct.unpack(">H", v39[19:21])[0]
        assert struct.unpack(">I", v39[off_c:off_c + 4])[0] == ZYXEL_IANA

    def test_omit_ablation(self):
        creator = ZywallPayloadCreator(
            identity=ZywallIdentity(omit_elements=frozenset({39})))
        seed = bytes(creator.create_discovery_request(valid=True))
        body = seed[16:]
        et, _ = struct.unpack(">HH", body[:4])
        assert et == 37
        both = ZywallPayloadCreator(
            identity=ZywallIdentity(omit_elements=frozenset({39, 37})))
        with pytest.raises(ValueError):
            both.create_discovery_request(valid=True)

    def test_identity_pool_derivation(self):
        from dataclasses import replace
        base = ZywallIdentity()
        pool = [base]
        for i in range(1, 3):
            mac = bytearray(base.ap_mac)
            mac[-1] = (mac[-1] + i) % 256
            pool.append(replace(base, ap_mac=bytes(mac)))
        assert len({i.ap_mac for i in pool}) == 3
        assert all(i.gates_ok() for i in pool)


class TestM1VendorOverrun:
    """len-elem-overrun vendor extension: ZyWALL seeds target element 39
    (WTP Descriptor — modelId/fwVersion), Cisco seeds keep element 38
    (WTP Board Data).  Wire behavior for Cisco is unchanged (regression:
    tests/test_discovery_stage.py::test_m1_len_elem_overrun)."""

    def _zywall_seed(self) -> bytes:
        creator = ZywallPayloadCreator(identity=ZywallIdentity())
        return bytes(creator.create_discovery_request(valid=True))

    def test_overrun_targets_element_39_on_zywall(self):
        from capwap_discovery_fuzzer.discovery_stage import (
            MUTATORS,
            DiscoveryStageFuzzer,
        )
        from capwap_discovery_fuzzer.stage_fuzzer import _element_offsets
        from capwap_discovery_fuzzer.vendors.cisco.creator import ApIdentity

        seed = self._zywall_seed()
        ident = ZywallIdentity()
        default = MUTATORS["len-elem-overrun"][1]
        builder = DiscoveryStageFuzzer._builder_for(
            "len-elem-overrun", default, ident)
        (d,), desc = builder(seed, None)
        # walk the *unmutated* seed for element 39's offset (same pattern as
        # the Cisco regression test)
        t39 = next(s for t, s, l in _element_offsets(seed) if t == 39)
        assert int.from_bytes(d[t39 + 2:t39 + 4], "big") == 0xFFFF
        assert len(d) == len(seed)
        assert desc["elem_type"] == 39
        # element 37 untouched
        t37 = next(s for t, s, l in _element_offsets(seed) if t == 37)
        assert d[t37:t37 + 4] == seed[t37:t37 + 4]

    def test_cisco_identity_keeps_default_builder(self):
        from capwap_discovery_fuzzer.discovery_stage import (
            MUTATORS,
            DiscoveryStageFuzzer,
        )
        from capwap_discovery_fuzzer.vendors.cisco.creator import ApIdentity

        default = MUTATORS["len-elem-overrun"][1]
        ident = ApIdentity(radios=((0, 0x0D), (1, 0x0A)), num_encrypt=1,
                           model=b"C9105AXI-C")
        assert DiscoveryStageFuzzer._builder_for(
            "len-elem-overrun", default, ident) is default
        # non-overrun variants are never redirected
        assert DiscoveryStageFuzzer._builder_for(
            "base", MUTATORS["base"][1], ZywallIdentity()) \
            is MUTATORS["base"][1]


class TestCanaryVendorPad:
    """ZyWALL fills MsgElemsLen as the net element-area length (counted
    from after the Flags byte), whereas RFC 5415 Sec 4.5.1.3 wording counts
    from the Sequence Number (including Len(2)+Flags(1)) and C9800 follows
    the RFC (D3: extra==0).  In-loop measurement 2026-09-23: 251B Discovery
    Reply, 2-byte Len at offset 13 reads 235 = 251-16 -> constant +3 under
    the RFC formula; len_pad=3 zeroes it, keeping over-emission visible."""

    def _reply(self, elems_len):
        # 8B CAPWAP header + MsgType(4) + Seq(1) + Len(2) + Flags(1) + elements
        return (bytes.fromhex("0010020000000000")
                + struct.pack(">I", 2) + bytes([7])
                + struct.pack(">H", elems_len) + bytes([0])
                + bytes([66]) * elems_len)

    def test_pad_clears_constant_offset(self):
        from capwap_discovery_fuzzer.discovery_stage import canary_check
        raw = self._reply(4)  # total 20, declared 4 (net semantics)
        plain = canary_check(raw)
        assert plain["extra_bytes"] == 3 and plain["leak_suspect"] is True
        padded = canary_check(raw, len_pad=3)
        assert padded["extra_bytes"] == 0 and padded["leak_suspect"] is False
        bigger = self._reply(5) + bytes(2)  # genuine 2B over-emission
        assert canary_check(bigger, len_pad=3)["extra_bytes"] == 2

    def test_measured_wire_shape(self):
        from capwap_discovery_fuzzer.discovery_stage import canary_check
        raw = self._reply(235)  # the in-loop measured 251B reply
        assert len(raw) == 251
        r = canary_check(raw, len_pad=3)
        assert r["extra_bytes"] == 0 and r["leak_suspect"] is False
        assert canary_check(raw)["extra_bytes"] == 3
