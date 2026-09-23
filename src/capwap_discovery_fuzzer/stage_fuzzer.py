"""Join-stage session fuzzer (plan v3 P4).

Sends mutated Join Requests over per-round DTLS sessions and records a
:class:`~capwap_discovery_fuzzer.session.oracle.RoundVerdict` per round.

Variants are *directed*: each one toggles exactly one thing the E4–E7 rounds
proved load-bearing, so any verdict change attributes to that field:

======================  ==========================================================
variant                 mutation
======================  ==========================================================
``base``                golden parameters (locked join-v1: random Session ID is
                        the only per-round difference)
``omit-126``            drop the two join-time Type-126 domain declarations
``omit-169``            drop the AP Domain element
``omit-37``             drop both vendor payloads (board options / RAD_NAME)
``omit-29``             drop Maximum Message Length (§4.6.31)
``omit-53``             drop Limited ECN
``omit-30``             drop CAPWAP Local IPv4
``maxmsglen-0``         Maximum Message Length = 0
``maxmsglen-65535``     Maximum Message Length = 65535
``radio-1base``         Radio IDs 1/2 instead of 0/1
``radio-type-b-a``      radio type bitmasks 0x01/0x02 (band-record mismatch)
``regdom-code-0``       join-time Type-126 code 0x0000
``regdom-code-FFFF``    join-time Type-126 code 0xFFFF
``boarddata-shift``     board-data sub-element type numbers shifted by +1
                        (known whole-message silent-drop switch, E4)
======================  ==========================================================

Every round runs on a fresh DTLS session and a fresh source port, records end
up in ``<out_dir>/session.jsonl`` plus a ``summary.json``; the s_client child
is killed between rounds (orphaned clients poison later sessions).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

from capwap_discovery_fuzzer.session import builders
from capwap_discovery_fuzzer.session import oracle
from capwap_discovery_fuzzer.session.builders import parse_control_messages
from capwap_discovery_fuzzer.session.oracle import (
    RESULT_CODE_SUCCESS,
    Outcome,
    RoundVerdict,
)
from capwap_discovery_fuzzer.session.transport import SClientTransport
from capwap_discovery_fuzzer.session.vsp import (
    VSP_ELEM_BOARD_DATA_OPTIONS,
    VSP_ELEM_RAD_NAME,
    VSP_ELEM_REG_DOMAIN,
)
from capwap_discovery_fuzzer.vendors.cisco.creator import ApIdentity

#: Board Data sub-element ids the controller's join parser expects
#: (parse_wtp_board_data_msgelement: 0=model, 1=serial, 2=board_id(?),
#: 3=revision, 4=base_mac).  Shifting these is a known silent-drop switch.
BOARD_SUBELEM_MODEL = 0
BOARD_SUBELEM_SERIAL = 1


@dataclass
class JoinFuzzConfig:
    ac_addr: tuple[str, int]
    cert_path: str
    key_path: str
    identity: ApIdentity
    out_dir: Path
    local_ip: str = "192.168.10.128"
    connect_timeout: float = 25.0
    round_gap_s: float = 1.0
    #: extra attempts on a fresh session when a round ends non-ANSWERED.  The
    #: controller keeps the previous joined session bound to the AP MAC and
    #: drops the next join until its cleanup settles, which shows up as a
    #: strict one-out-of-two alternation across ephemeral source ports
    #: (measured 2026-09-20).  Retrying on a fresh port removes that flake
    #: without changing the variant under test.
    retries: int = 1
    discovery_prelude: bool = True
    #: Seconds to wait for the Join Response before calling the round silent.
    #: A successful join answers within ~100 ms of the flight closing (runbook
    #: §4); the old 15 s cap was pure dead time on every swallowed attempt.
    join_timeout: float = 3.0
    #: Quiet window that marks the server's DTLS flight complete.
    handshake_settle: float = 1.5
    #: Grace given to close_notify before SIGKILL.
    close_wait: float = 0.5
    #: Extra AP identities to rotate over (plan P4.5).  Empty = single identity,
    #: which is the historical behaviour.
    identity_pool: tuple[ApIdentity, ...] = ()
    #: Regulatory-domain code declared in Config Status (0x10 = -C China).
    reg_domain_code: int = builders.DEFAULT_REG_DOMAIN_CODE
    #: Seconds to wait for a Config Status / Change State response (P5).
    stage_timeout: float = 5.0

    def identities(self) -> tuple[ApIdentity, ...]:
        return self.identity_pool or (self.identity,)


def derive_identity(base: ApIdentity, mac: bytes,
                    serial_suffix: str = "") -> ApIdentity:
    """Copy ``base`` with the identity fields replaced by ``mac``.

    Only what makes an AP identifiable moves — the CAPWAP optional Radio MAC,
    the board-data base MAC, the WTP name (``APxxxx.xxxx.xxxx``) and an
    optional serial suffix.
    """
    hexs = mac.hex().upper().encode()
    serial = base.serial
    if serial_suffix:
        serial = (base.serial[:-len(serial_suffix)] + serial_suffix.encode())
    return ApIdentity(
        ap_name=b"AP" + hexs[0:4] + b"." + hexs[4:8] + b"." + hexs[8:12],
        ap_mac=mac, model=base.model, serial=serial, base_mac=mac,
        radios=base.radios, max_radios=base.max_radios,
        radios_in_use=base.radios_in_use, num_encrypt=base.num_encrypt,
        msg_type=base.msg_type)


def build_identity_pool(base: ApIdentity, count: int) -> tuple[ApIdentity, ...]:
    """``count`` distinct AP identities derived from ``base`` (plan P4.5).

    Only the fields that make an AP *identifiable* vary — the CAPWAP optional
    Radio MAC, the board-data base MAC, the WTP name and the serial suffix —
    so a pool run and a single-identity run differ in the identity rotation
    and nothing else.  ``count <= 1`` returns the base identity unchanged.
    """
    if count <= 1:
        return ()
    pool = [base]
    for i in range(1, count):
        mac = bytearray(base.ap_mac)
        mac[-1] = (mac[-1] + i) % 256
        pool.append(derive_identity(base, bytes(mac), serial_suffix=f"{i:02d}"))
    return tuple(pool)


def _shift_board_subelem_types(board: bytes, delta: int = 1) -> bytes:
    """Board Data value = vendor id(4) + sub-elements {type u16, len u16, val}.

    Returns a copy with every sub-element type shifted by ``delta``.
    """
    out = bytearray(board[:4])
    o = 4
    while o + 4 <= len(board):
        etype, elen = struct.unpack_from(">HH", board, o)
        val = board[o + 4:o + 4 + elen]
        out += struct.pack(">HH", (etype + delta) & 0xFFFF, elen) + val
        o += 4 + elen
    return bytes(out)


def _element_offsets(raw: bytes) -> list[tuple[int, int, int]]:
    """Return ``(elem_type, elem_start, value_len)`` for each element of one frame."""
    hlen = ((raw[1] >> 3) & 0x1F) * 4
    out: list[tuple[int, int, int]] = []
    o = hlen + 8
    while o + 4 <= len(raw):
        etype = int.from_bytes(raw[o:o + 2], "big")
        elen = int.from_bytes(raw[o + 2:o + 4], "big")
        if o + 4 + elen > len(raw):
            break
        out.append((etype, o, elen))
        o += 4 + elen
    return out


def _patch_element(raw: bytes, elem_index: int, new_value: bytes | None) -> bytes:
    """Replace (or drop, when ``new_value is None``) one element; fix lengths.

    Adjusts the element's Length field and the Control_Header MsgElemsLen
    (RFC 5415 §4.5.1.1 counts from after SeqNum: 2B length field + 1B flags +
    element bytes).
    """
    hlen = ((raw[1] >> 3) & 0x1F) * 4
    elems = _element_offsets(raw)
    etype, start, elen = elems[elem_index]
    end = start + 4 + elen
    if new_value is None:
        body = raw[:start] + raw[end:]
    else:
        body = (raw[:start] + struct.pack(">HH", etype, len(new_value)) + new_value
                + raw[end:])
    # Control_Header: MsgType(4) SeqNum(1) MsgElemsLen(2) Flags(1)
    old_elems_len = int.from_bytes(raw[hlen + 5:hlen + 7], "big")
    delta = len(body) - len(raw)
    new_elems_len = old_elems_len + delta
    out = bytearray(body)
    out[hlen + 5:hlen + 7] = struct.pack(">H", new_elems_len)
    return bytes(out)


#: Element types the plan's join lock set v1 freezes (DTLS-required identity);
#: everything else is open to the unlocked baseline's random mutation.
LOCKED_ELEMENT_TYPES = frozenset({38, 35, 29, 1048})

#: RFC 5415 §8.3 MUST list for the Configuration Status Response
#: (``rfc5415.txt`` 6414-6430): CAPWAP Timers(12), Decryption Error Report
#: Period(16), Idle Timeout(23), WTP Fallback(40), plus "one or both" of
#: AC IPv4 List(2) / AC IPv6 List(3).  **Result Code is not in that list** —
#: unlike the request, this response carries no verdict element, so the P5
#: oracle scores the element set (and session survival) instead of a code.
CONFIG_RESPONSE_MUST = (12, 16, 23, 40)
CONFIG_RESPONSE_MUST_EITHER = (2, 3)


def build_unlocked_variant(cfg: JoinFuzzConfig, rng,
                           session_id: bytes | None = None,
                           identity: ApIdentity | None = None) -> tuple[bytes, dict]:
    """One random mutation of one *open* (non-frozen) element.

    Realises the plan's "未锁定对照": frozen identity elements stay byte-exact,
    everything else gets one of: value byte-flip / value zero-fill / value
    truncation / element drop.  Returns ``(frame, mutation_descriptor)``.
    """
    raw = build_variant("base", cfg, session_id=session_id, identity=identity)
    elems = _element_offsets(raw)
    open_idx = [i for i, (t, _s, _l) in enumerate(elems)
                if t not in LOCKED_ELEMENT_TYPES]
    i = rng.choice(open_idx)
    etype, start, elen = elems[i]
    value = raw[start + 4:start + 4 + elen]
    op = rng.choice(["flip", "zero", "truncate", "drop"])
    if op == "drop":
        return _patch_element(raw, i, None), {"op": "drop", "type": etype}
    if op == "truncate" and elen > 1:
        k = rng.randrange(1, elen)
        new = value[:k]
    elif op == "zero":
        new = bytes(elen)
    else:
        new = bytearray(value)
        if elen:
            pos = rng.randrange(elen)
            new[pos] ^= 1 << rng.randrange(8)
        new = bytes(new)
    return _patch_element(raw, i, new), {"op": op, "type": etype,
                                         "old_len": elen, "new_len": len(new)}


def _hlen(raw: bytes) -> int:
    return ((raw[1] >> 3) & 0x1F) * 4


def _set_seq(raw: bytes, seq: int) -> bytes:
    """Rewrite the Control_Header SeqNum (RFC 5415 §4.5.1.1, at hlen+4)."""
    out = bytearray(raw)
    out[_hlen(raw) + 4] = seq & 0xFF
    return bytes(out)


def _insert_after(raw: bytes, idx: int, value: bytes) -> bytes:
    """Insert a copy of element ``idx`` carrying ``value`` right after it."""
    elems = _element_offsets(raw)
    etype, start, elen = elems[idx]
    end = start + 4 + elen
    body = raw[:end] + struct.pack(">HH", etype, len(value)) + value + raw[end:]
    hlen = _hlen(raw)
    out = bytearray(body)
    out[hlen + 5:hlen + 7] = struct.pack(
        ">H", int.from_bytes(raw[hlen + 5:hlen + 7], "big") + 4 + len(value))
    return bytes(out)


def _swap_elements(raw: bytes, i: int, j: int) -> bytes:
    """Swap two elements' positions (order is significant in §8.x flows)."""
    elems = _element_offsets(raw)
    (ti, si, li), (tj, sj, lj) = elems[i], elems[j]
    if si > sj:
        return _swap_elements(raw, j, i)
    head, mid_end = raw[:si], sj + 4 + lj
    return (head + raw[sj:sj + 4 + lj] + raw[si + 4 + li:sj]
            + raw[si:si + 4 + li] + raw[mid_end:])


def _vsp_indices(raw: bytes, elem_id: int | None = None) -> list[int]:
    """Indices of vendor-payload elements (Type 37), optionally by ElemID."""
    out = []
    for i, (etype, start, elen) in enumerate(_element_offsets(raw)):
        if etype != 37 or elen < 6:
            continue
        value = raw[start + 4:start + 4 + elen]
        if elem_id is None or int.from_bytes(value[4:6], "big") == elem_id:
            out.append(i)
    return out


def _patch_vsp(raw: bytes, elem_id: int, transform) -> bytes:
    """Apply ``transform(value)->value`` to every Type-37 element with ElemID."""
    for i in _vsp_indices(raw, elem_id):
        elems = _element_offsets(raw)
        _t, start, elen = elems[i]
        raw = _patch_element(raw, i, transform(raw[start + 4:start + 4 + elen]))
    return raw


#: Config Status variants.  ``base`` is the golden frame; the rest are single
#: wire-level changes so a verdict difference attributes to that change.
CONFIG_VARIANTS = [
    "base",
    "omit-4",             # AC Name (§8.2 MUST)
    "omit-radio-admin",   # both Radio Administrative State (Type 31, MUST)
    "omit-timer36",       # Statistics Timer (MUST)
    "omit-reboot48",      # WTP Reboot Statistics (MUST)
    "omit-radname",       # RAD_NAME vendor payload
    "omit-vsp126",        # the two regulatory-domain declarations (E7's switch)
    "vsp126-len7",        # 7-byte VSP header (E7's bug: ElemID parses as 0x0000)
    "vsp126-elemid-0",    # ElemID -> 0x0000
    "vsp126-elemid-207",  # ElemID -> 0x00cf (board options)
    "vsp126-code-0",      # regulatory code 0x0000
    "vsp126-code-ffff",   # regulatory code 0xffff
    "dup-radio-admin",    # duplicated Type 31
    "swap-first-two",     # element order swapped
    "seq-old",            # SeqNum back to 0 -> §4.5.3 duplicate-sequence rule
]

#: Change State Event variants (same rules, §8.6 MUST set).
CHANGE_STATE_VARIANTS = [
    "base",
    "omit-radio-op",      # Radio Operational State (Type 32, MUST)
    "omit-result",        # Result Code (Type 33, MUST)
    "rc-1",               # Result Code 1 (unsupported)
    "rc-255",             # Result Code 255
    "dup-radio-op",       # duplicated Type 32
    "omit-vsp",           # drop both vendor payloads
    "seq-old",            # SeqNum 0
]


def build_config_variant(name: str, cfg: JoinFuzzConfig, ident: ApIdentity,
                         seq_num: int = 1) -> bytes:
    """Configuration Status Request variant (RFC 5415 §8.2)."""
    raw = builders.build_config_status(ident, seq_num=seq_num,
                                       reg_domain_code=cfg.reg_domain_code)
    if name == "base":
        return raw
    if name == "omit-4":
        return _drop_type(raw, 4)
    if name == "omit-radio-admin":
        return _drop_type(raw, 31, all_=True)
    if name == "omit-timer36":
        return _drop_type(raw, 36)
    if name == "omit-reboot48":
        return _drop_type(raw, 48)
    if name == "omit-radname":
        return _patch_vsp(raw, VSP_ELEM_RAD_NAME, lambda _v: None)
    if name == "omit-vsp126":
        for i in reversed(_vsp_indices(raw, VSP_ELEM_REG_DOMAIN)):
            raw = _patch_element(raw, i, None)
        return raw
    if name == "vsp126-len7":
        return _patch_vsp(raw, VSP_ELEM_REG_DOMAIN, lambda v: v[:4] + b"\x00" + v[4:])
    if name == "vsp126-elemid-0":
        return _patch_vsp(raw, VSP_ELEM_REG_DOMAIN,
                          lambda v: v[:4] + b"\x00\x00" + v[6:])
    if name == "vsp126-elemid-207":
        return _patch_vsp(raw, VSP_ELEM_REG_DOMAIN,
                          lambda v: v[:4] + VSP_ELEM_BOARD_DATA_OPTIONS.to_bytes(2, "big") + v[6:])
    if name == "vsp126-code-0":
        return _patch_vsp(raw, VSP_ELEM_REG_DOMAIN,
                          lambda v: v[:9] + b"\x00\x00")
    if name == "vsp126-code-ffff":
        return _patch_vsp(raw, VSP_ELEM_REG_DOMAIN,
                          lambda v: v[:9] + b"\xff\xff")
    if name == "dup-radio-admin":
        return _insert_after(raw, _first_index(raw, 31),
                             _element_value(raw, _first_index(raw, 31)))
    if name == "swap-first-two":
        return _swap_elements(raw, 0, 1)
    if name == "seq-old":
        return _set_seq(raw, 0)
    raise ValueError(f"unknown config variant: {name}")


def build_change_state_variant(name: str, cfg: JoinFuzzConfig, ident: ApIdentity,
                               seq_num: int = 2) -> bytes:
    """Change State Event Request variant (RFC 5415 §8.6)."""
    raw = builders.build_change_state(ident, seq_num=seq_num)
    if name == "base":
        return raw
    if name == "omit-radio-op":
        return _drop_type(raw, 32, all_=True)
    if name == "omit-result":
        return _drop_type(raw, 33)
    if name == "rc-1":
        return _patch_element(raw, _first_index(raw, 33), struct.pack(">I", 1))
    if name == "rc-255":
        return _patch_element(raw, _first_index(raw, 33), struct.pack(">I", 255))
    if name == "dup-radio-op":
        return _insert_after(raw, _first_index(raw, 32),
                             _element_value(raw, _first_index(raw, 32)))
    if name == "omit-vsp":
        for i in reversed(_vsp_indices(raw)):
            raw = _patch_element(raw, i, None)
        return raw
    if name == "seq-old":
        return _set_seq(raw, 0)
    raise ValueError(f"unknown change-state variant: {name}")


def _element_value(raw: bytes, idx: int) -> bytes:
    _t, start, elen = _element_offsets(raw)[idx]
    return raw[start + 4:start + 4 + elen]


def _first_index(raw: bytes, etype: int) -> int:
    for i, (t, _s, _l) in enumerate(_element_offsets(raw)):
        if t == etype:
            return i
    raise ValueError(f"no element of type {etype}")


def _drop_type(raw: bytes, etype: int, all_: bool = False) -> bytes:
    """Drop the first (or all) elements of ``etype``."""
    for i in reversed([i for i, (t, _s, _l) in enumerate(_element_offsets(raw))
                       if t == etype]):
        raw = _patch_element(raw, i, None)
        if not all_:
            break
    return raw


def _shorten_session_id(raw: bytes, size: int) -> bytes:
    """Shrink the Session ID element's value to ``size`` bytes (wire-level)."""
    for i, (etype, _start, _elen) in enumerate(_element_offsets(raw)):
        if etype == 35:
            cur = _element_offsets(raw)[i]
            value = raw[cur[1] + 4:cur[1] + 4 + cur[2]][:size]
            return _patch_element(raw, i, value)
    raise ValueError("no Session ID element to shorten")


def build_variant(name: str, cfg: JoinFuzzConfig,
                  session_id: bytes | None = None,
                  identity: ApIdentity | None = None) -> bytes:
    """Build one Join Request for the named variant (defaults = ``base``).

    ``identity`` overrides ``cfg.identity`` — the identity pool rotates over it.
    """
    ident = identity if identity is not None else cfg.identity
    sid = session_id if session_id is not None else secrets.token_bytes(16)
    kwargs: dict = dict(identity=ident, session_id=sid, local_ip=cfg.local_ip)

    if name == "base":
        pass
    elif name == "session-zero":
        kwargs["session_id"] = bytes(16)
    elif name == "session-short8":
        raw = builders.build_join_request(**kwargs)
        return _shorten_session_id(raw, 8)
    elif name == "omit-126":
        kwargs["reg_domain_code"] = None
    elif name == "omit-169":
        kwargs["ap_domain_name"] = None
    elif name == "omit-37":
        kwargs["omit_vsp"] = True
    elif name == "omit-29":
        kwargs["max_message_length"] = None
    elif name == "omit-53":
        kwargs["omit_ecn"] = True
    elif name == "omit-30":
        kwargs["local_ip"] = None
    elif name == "maxmsglen-0":
        kwargs["max_message_length"] = 0
    elif name == "maxmsglen-65535":
        kwargs["max_message_length"] = 65535
    elif name == "radio-1base":
        kwargs["identity"] = ApIdentity(
            ap_name=ident.ap_name, ap_mac=ident.ap_mac, model=ident.model,
            serial=ident.serial, base_mac=ident.base_mac,
            radios=((1, 0x0D), (2, 0x0A)), num_encrypt=1)
    elif name == "radio-type-b-a":
        kwargs["identity"] = ApIdentity(
            ap_name=ident.ap_name, ap_mac=ident.ap_mac, model=ident.model,
            serial=ident.serial, base_mac=ident.base_mac,
            radios=((0, 0x01), (1, 0x02)), num_encrypt=1)
    elif name == "regdom-code-0":
        kwargs["reg_domain_code"] = 0x0000
    elif name == "regdom-code-FFFF":
        kwargs["reg_domain_code"] = 0xFFFF
    elif name == "boarddata-shift":
        kwargs["board_data_override"] = _shift_board_subelem_types(ident.board_data())
    else:
        raise ValueError(f"unknown variant: {name}")
    return builders.build_join_request(**kwargs)


#: RoundVerdict-compatible alias kept for typing clarity.
Verdict = RoundVerdict


class JoinStageFuzzer:
    """Run join-variant rounds over fresh DTLS sessions."""

    def __init__(self, cfg: JoinFuzzConfig, openssl_bin: str = "openssl",
                 seed: int | None = None):
        import random
        self.cfg = cfg
        self.openssl_bin = openssl_bin
        self.seed = seed
        self._rng = random.Random(seed)
        self.records: list[dict] = []

    # ------------------------------------------------------------------ rounds

    def run_round(self, variant: str, round_no: int,
                  session_id: bytes | None = None,
                  stage: str = "join") -> RoundVerdict:
        """One variant, up to ``config.retries + 1`` fresh sessions.

        Each session carries at most one Join Request plus (for the later
        stages) one mutated Config Status / Change State.  A round is retried
        when the **join** leg is not answered — every stage needs a live
        session — but never because the mutated stage message itself was
        dropped: that *is* the measurement.
        """
        ident = self._identity_for(round_no)
        attempts = 0
        verdict = None
        while attempts <= self.cfg.retries:
            attempts += 1
            verdict = self._attempt(variant, round_no, session_id, ident, stage)
            if "transport_error" in verdict.mutation:
                break
            if stage == "join":
                if verdict.outcome == Outcome.ANSWERED:
                    break
            elif verdict.mutation.get("join_rc") == RESULT_CODE_SUCCESS:
                break
        verdict.mutation["attempts"] = attempts
        return verdict

    def _identity_for(self, round_no: int) -> ApIdentity:
        """Round-robin over the identity pool (plan P4.5); index 0 = base AP."""
        pool = self.cfg.identities()
        return pool[(round_no - 1) % len(pool)]

    def _attempt(self, variant: str, round_no: int,
                 session_id: bytes | None = None,
                 ident: ApIdentity | None = None,
                 stage: str = "join") -> RoundVerdict:
        cfg = self.cfg
        ident = ident if ident is not None else cfg.identity
        discovery = self._discovery_bytes(ident) if cfg.discovery_prelude else b""
        t = SClientTransport(cfg.ac_addr, cert_path=cfg.cert_path,
                             key_path=cfg.key_path, openssl_bin=self.openssl_bin,
                             prelude=discovery,
                             handshake_settle=cfg.handshake_settle,
                             close_wait=cfg.close_wait)
        v = None
        try:
            t.connect(timeout=cfg.connect_timeout)
            t.wait_handshake(timeout=cfg.connect_timeout)
            mark = t.snapshot()          # ignore handshake-flight bytes
            # the variant name space belongs to the stage under test: a
            # config/change-state round always joins with the golden frame
            if stage == "join" and variant == "unlocked":
                raw, mut = build_unlocked_variant(cfg, self._rng, session_id=session_id,
                                                  identity=ident)
            else:
                join_variant = variant if stage == "join" else "base"
                raw, mut = build_variant(join_variant, cfg, session_id=session_id,
                                         identity=ident), None
            t.send(raw)
            reply = t.recv_since(mark, timeout=cfg.join_timeout)
            outcome, code = oracle.classify_reply(reply)
            if outcome == Outcome.SILENCE and not t.is_alive:
                # the controller closed the DTLS session right after our send —
                # an application-layer rejection (alert) rather than silence
                outcome = Outcome.ALERT
            if outcome == Outcome.ANSWERED:
                for m in parse_control_messages(reply):
                    if m["msg_type"] == 4:
                        code = builders.result_code_of(m)
            m = {"variant": variant, "round": round_no,
                 "ap_mac": ident.ap_mac.hex()}
            if mut:
                m.update(mut)
            if stage != "join":
                # the join leg is the envelope, not the measurement: record it
                # so a failed envelope cannot be mistaken for a stage verdict
                m["join_outcome"] = outcome.value
                m["join_rc"] = code
                if code == RESULT_CODE_SUCCESS:
                    if stage == "change-state":
                        # §2.3.1(g): the Configure state is entered by a
                        # Configuration Status Request, and Change State only
                        # makes sense after it — send the golden one first
                        _r, cfg_outcome, _c = self._stage_round(
                            t, builders.build_config_status(
                                ident, reg_domain_code=cfg.reg_domain_code), 6)
                        m["config_outcome"] = cfg_outcome.value
                    stage_raw = (build_config_variant(variant, cfg, ident)
                                 if stage == "config"
                                 else build_change_state_variant(variant, cfg, ident))
                    want = 6 if stage == "config" else 12
                    reply, outcome, code = self._stage_round(t, stage_raw, want)
                    m["stage_rc"] = code
                    if stage == "config" and outcome == Outcome.ANSWERED:
                        # §8.3 has no Result Code: score the response's element
                        # set against the RFC MUST list instead
                        types = {t_ for msg in parse_control_messages(reply)
                                 if msg["msg_type"] == want
                                 for t_, _l, _v in msg["elements"]}
                        m["resp_types"] = sorted(types)
                        missing = [t_ for t_ in CONFIG_RESPONSE_MUST
                                   if t_ not in types]
                        if not types & set(CONFIG_RESPONSE_MUST_EITHER):
                            missing.append("2|3")
                        m["missing_must"] = missing
                    if stage == "config":
                        # survival probe: a config the AC accepted leaves the
                        # session able to complete the Change State handshake
                        _r, fut_outcome, fut_code = self._stage_round(
                            t, builders.build_change_state(ident, seq_num=2), 12)
                        m["survives"] = fut_outcome == Outcome.ANSWERED
                        m["survives_rc"] = fut_code
            if reply:
                # raw_reply_hex is truncated for the record; the digest covers
                # the WHOLE reply so "the controller answered identically" can
                # be a byte-exact claim (P5)
                m["reply_sha256"] = hashlib.sha256(reply).hexdigest()
                m["reply_len"] = len(reply)
            v = RoundVerdict(
                stage=stage, outcome=outcome, result_code=code,
                mutation=m, raw_reply_hex=reply.hex()[:256] if reply else None)
        except Exception as exc:  # noqa: BLE001 - transport failures are data
            v = RoundVerdict(stage=stage, outcome=Outcome.SILENCE,
                             mutation={"variant": variant, "round": round_no,
                                       "ap_mac": ident.ap_mac.hex(),
                                       "transport_error": str(exc)[:200]})
            if not isinstance(exc, (TimeoutError,)):
                # surface driver bugs immediately instead of poisoning the run
                raise
        finally:
            t.close()
            time.sleep(self.cfg.round_gap_s)
        return v

    def _stage_round(self, t, frame: bytes, want_msg_type: int):
        """Send one post-join frame and classify its response.

        Returns ``(reply, outcome, result_code)`` where ``result_code`` comes
        from the ``want_msg_type`` response's Result Code element (Type 33).
        """
        mark = t.snapshot()
        t.send(frame)
        reply = t.recv_since(mark, timeout=self.cfg.stage_timeout)
        outcome, code = oracle.classify_reply(reply)
        if outcome == Outcome.ANSWERED:
            for msg in parse_control_messages(reply):
                if msg["msg_type"] == want_msg_type:
                    code = builders.result_code_of(msg)
        if outcome == Outcome.SILENCE and not t.is_alive:
            outcome = Outcome.ALERT
        return reply, outcome, code

    def _discovery_bytes(self, ident: ApIdentity | None = None) -> bytes:
        """Discovery Request prelude (same 5-tuple as the DTLS session)."""
        from capwap_discovery_fuzzer.vendors.cisco.creator import CiscoPayloadCreator
        return bytes(CiscoPayloadCreator(identity=ident or self.cfg.identity)
                     .create_discovery_request(valid=True))

    def run(self, variants: list[str], rounds_per_variant: int = 1,
            progress=None, stage: str = "join") -> dict:
        out: dict[str, dict] = {}
        round_no = 0
        for variant in variants:
            stats = {"answered": 0, "success": 0, "silence": 0, "alert": 0,
                     "codes": {}}
            for _ in range(rounds_per_variant):
                round_no += 1
                v = self.run_round(variant, round_no, stage=stage)
                rec = {"round": round_no, "ts": time.time(), **v.as_dict()}
                self.records.append(rec)
                key = v.outcome.value
                stats[key] = stats.get(key, 0) + 1
                if v.outcome == Outcome.ANSWERED:
                    stats["codes"][str(v.result_code)] = \
                        stats["codes"].get(str(v.result_code), 0) + 1
                    if v.result_code == RESULT_CODE_SUCCESS:
                        stats["success"] += 1
                if progress:
                    progress(round_no, variant, v)
            out[variant] = stats
        return out

    # ------------------------------------------------------------------ output

    def write_jsonl(self, path: Path) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            for rec in self.records:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ----------------------------------------------------------------------- CLI

ALL_VARIANTS = [
    "base", "omit-126", "omit-169", "omit-37", "omit-29", "omit-53", "omit-30",
    "maxmsglen-0", "maxmsglen-65535", "radio-1base", "radio-type-b-a",
    "regdom-code-0", "regdom-code-FFFF", "boarddata-shift",
    "session-zero", "session-short8",
]


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        description="Join-stage CAPWAP session fuzzer (per-round DTLS sessions)")
    ap.add_argument("--ac-ip", default="192.168.10.201")
    ap.add_argument("--ac-port", type=int, default=5246)
    ap.add_argument("--cert", default=None)
    ap.add_argument("--key", default=None)
    ap.add_argument("--model", default="C9105AXI-C")
    ap.add_argument("--local-ip", default="192.168.10.128")
    ap.add_argument("--regdom-config", type=lambda x: int(x, 0),
                    default=builders.DEFAULT_REG_DOMAIN_CODE,
                    help="code declared in Config Status (0x10 = -C China)")
    ap.add_argument("--variants", default="base",
                    help="comma list, 'all' for the full matrix, or 'unlocked' "
                         "for the random open-element baseline")
    ap.add_argument("--stage", default="discovery",
                    choices=["discovery", "join", "config", "change-state"],
                    help="fuzzing stage: plaintext Discovery (default, no "
                         "certificate needed), the join variants (P4), or a "
                         "mutated Configuration Status (§8.2) / Change State "
                         "(§8.6) sent inside a session that joined first (P5)")
    ap.add_argument("--vendor", default="cisco",
                    choices=["cisco", "zywall"],
                    help="Discovery-stage seed vendor: cisco (C9800 golden "
                         "capture form) or zywall (ZyWALL 310 field-table form, "
                         "HLEN=2 + element 39/37 gates; D4)")
    ap.add_argument("--seed", type=int, default=None,
                    help="RNG seed for the unlocked mode (recorded in summary)")
    ap.add_argument("--rounds", type=int, default=None,
                    help="alias for --rounds-per-variant")
    ap.add_argument("--rounds-per-variant", type=int, default=1)
    ap.add_argument("--round-gap", type=float, default=1.0,
                    help="seconds between rounds; the controller keeps a "
                         "joined session for a while and drops the next join "
                         "until its cleanup settles")
    ap.add_argument("--stage-timeout", type=float, default=5.0,
                    help="seconds to wait for a Config Status / Change State response")
    ap.add_argument("--join-timeout", type=float, default=3.0,
                    help="seconds to wait for the Join Response (a successful "
                         "join answers within ~100 ms; the old 15 s cap was dead "
                         "time on every swallowed attempt)")
    ap.add_argument("--settle", type=float, default=1.5,
                    help="quiet window that marks the server DTLS flight done")
    ap.add_argument("--close-wait", type=float, default=0.5,
                    help="grace for close_notify before SIGKILL")
    ap.add_argument("--identity-pool", type=int, default=1,
                    help="rotate over N derived AP identities (plan P4.5); "
                         "1 = single identity (default, historical behaviour)")
    ap.add_argument("--identity-base-mac", default=None,
                    help="hex MAC the pool starts from (e.g. 10a829927000). "
                         "Use it to test identities the controller has never "
                         "seen — the default AP MAC has history by then")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--openssl", default="openssl")
    args = ap.parse_args(argv)

    if args.rounds is not None:
        args.rounds_per_variant = args.rounds

    if args.stage != "discovery" and not (args.cert and args.key):
        ap.error(f"--stage {args.stage} requires --cert and --key (only the "
                 "plaintext discovery stage runs without a DTLS identity)")

    if args.stage == "discovery":
        # D0: plaintext-UDP dispatch; same jsonl/summary contract as the
        # session stages so cross-stage and cross-vendor runs stay comparable.
        from capwap_discovery_fuzzer.discovery_stage import (
            DiscoveryStageFuzzer,
            expand_variants,
        )
        try:
            variants = expand_variants(args.variants)
        except ValueError as exc:
            raise SystemExit(str(exc))
        if args.vendor == "zywall":
            # ZyWALL 310 (ZLD 4.73): identity = MAC + the four admission-gate
            # feeders; --model is Cisco-specific and ignored here.
            from dataclasses import replace as _dc_replace
            from capwap_discovery_fuzzer.vendors.zywall.creator import ZywallIdentity
            identity = ZywallIdentity()
            if args.identity_base_mac:
                mac = bytes.fromhex(args.identity_base_mac)
                if len(mac) != 6:
                    raise SystemExit("--identity-base-mac must be a 6-byte hex MAC")
                identity = _dc_replace(identity, ap_mac=mac)
            pool = ()
            if args.identity_pool > 1:
                pool = [identity]
                for i in range(1, args.identity_pool):
                    mac = bytearray(identity.ap_mac)
                    mac[-1] = (mac[-1] + i) % 256
                    pool.append(_dc_replace(identity, ap_mac=bytes(mac)))
                pool = tuple(pool)
        else:
            identity = ApIdentity(radios=((0, 0x0D), (1, 0x0A)), num_encrypt=1,
                                  model=args.model.encode())
            if args.identity_base_mac:
                mac = bytes.fromhex(args.identity_base_mac)
                if len(mac) != 6:
                    raise SystemExit("--identity-base-mac must be a 6-byte hex MAC")
                identity = derive_identity(identity, mac)
            pool = build_identity_pool(identity, args.identity_pool)
        fuzzer = DiscoveryStageFuzzer(
            ac_addr=(args.ac_ip, args.ac_port),
            out_dir=Path(args.out_dir),
            identities=pool or (identity,),
            variants=variants,
            rounds_per_variant=args.rounds_per_variant,
            seed=args.seed,
            response_timeout=args.stage_timeout,
            round_gap=args.round_gap)
        summary = fuzzer.run()
        print(json.dumps(summary, indent=2))
        return 0

    all_for_stage = {"join": ALL_VARIANTS, "config": CONFIG_VARIANTS,
                     "change-state": CHANGE_STATE_VARIANTS}[args.stage]
    variants = all_for_stage if args.variants == "all" else \
        [v.strip() for v in args.variants.split(",") if v.strip()]

    identity = ApIdentity(radios=((0, 0x0D), (1, 0x0A)), num_encrypt=1,
                          model=args.model.encode())
    if args.identity_base_mac:
        mac = bytes.fromhex(args.identity_base_mac)
        if len(mac) != 6:
            raise SystemExit("--identity-base-mac must be a 6-byte hex MAC")
        identity = derive_identity(identity, mac)
    pool = build_identity_pool(identity, args.identity_pool)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg = JoinFuzzConfig(ac_addr=(args.ac_ip, args.ac_port),
                         cert_path=args.cert, key_path=args.key,
                         identity=identity, out_dir=out_dir,
                         local_ip=args.local_ip, round_gap_s=args.round_gap,
                         join_timeout=args.join_timeout, handshake_settle=args.settle,
                         close_wait=args.close_wait, identity_pool=pool,
                         reg_domain_code=args.regdom_config,
                         stage_timeout=args.stage_timeout)
    fuzzer = JoinStageFuzzer(cfg, openssl_bin=args.openssl, seed=args.seed)

    def progress(round_no: int, variant: str, v: RoundVerdict) -> None:
        extra = f" rc={v.result_code}" if v.result_code is not None else ""
        print(f"[{round_no:3d}] {variant:20s} {v.outcome.value}{extra}",
              flush=True)

    summary = fuzzer.run(variants, args.rounds_per_variant, progress=progress,
                          stage=args.stage)
    fuzzer.write_jsonl(out_dir / "session.jsonl")
    (out_dir / "summary.json").write_text(
        json.dumps({"stage": args.stage,
                    "variants": variants,
                    "rounds_per_variant": args.rounds_per_variant,
                    "seed": args.seed,
                    "round_gap_s": args.round_gap,
                    "stage_timeout_s": args.stage_timeout,
                    "join_timeout_s": args.join_timeout,
                    "handshake_settle_s": args.settle,
                    "close_wait_s": args.close_wait,
                    "identity_pool": [i.ap_mac.hex() for i in cfg.identities()],
                    "model": args.model,
                    "ac_ip": args.ac_ip,
                    "summary": summary}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
