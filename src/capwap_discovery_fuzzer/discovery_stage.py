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
import time
from pathlib import Path
from typing import Callable

from capwap_discovery_fuzzer.stage_fuzzer import _element_offsets, _hlen
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
                 datagram_gap: float = 0.03):
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
        39 (WTP Descriptor) for ZyWALL; everything else is vendor-neutral."""
        if variant == "len-elem-overrun" and isinstance(identity, ZywallIdentity):
            return _len_elem_overrun(39)
        return default

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
        with jsonl_path.open("a", encoding="utf-8") as jf:
            for variant in self.variants:
                layer, builder = MUTATORS[variant]
                stat = per_variant.setdefault(variant, {
                    "layer": layer, "rounds": 0, "answered": 0, "silent": 0,
                    "leak_suspect": 0, "resp_msgtypes": {}})
                for _ in range(self.rounds_per_variant):
                    round_no += 1
                    identity = self.identities[(round_no - 1) % len(self.identities)]
                    seed = self._build_seed(identity)
                    fn = self._builder_for(variant, builder, identity)
                    datagrams, desc = fn(seed, self.rng)
                    reply, addr = self._exchange(datagrams)
                    canary = canary_check(reply, self.canary_pad) if reply else None
                    outcome = "answered" if reply else "silence"
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
                        "mutation": desc,
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
            "totals": {
                "rounds": sum(s["rounds"] for s in per_variant.values()),
                "answered": sum(s["answered"] for s in per_variant.values()),
                "silent": sum(s["silent"] for s in per_variant.values()),
                "leak_suspect": sum(s["leak_suspect"] for s in per_variant.values()),
            },
        }
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                                encoding="utf-8")
        return summary
