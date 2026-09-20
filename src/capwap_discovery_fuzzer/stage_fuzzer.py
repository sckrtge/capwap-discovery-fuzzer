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
from capwap_discovery_fuzzer.session.statemachine import TIMEOUT_JOIN_RESPONSE
from capwap_discovery_fuzzer.session.transport import SClientTransport
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


def build_unlocked_variant(cfg: JoinFuzzConfig, rng,
                           session_id: bytes | None = None) -> tuple[bytes, dict]:
    """One random mutation of one *open* (non-frozen) element.

    Realises the plan's "未锁定对照": frozen identity elements stay byte-exact,
    everything else gets one of: value byte-flip / value zero-fill / value
    truncation / element drop.  Returns ``(frame, mutation_descriptor)``.
    """
    raw = build_variant("base", cfg, session_id=session_id)
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


def _shorten_session_id(raw: bytes, size: int) -> bytes:
    """Shrink the Session ID element's value to ``size`` bytes (wire-level)."""
    for i, (etype, _start, _elen) in enumerate(_element_offsets(raw)):
        if etype == 35:
            cur = _element_offsets(raw)[i]
            value = raw[cur[1] + 4:cur[1] + 4 + cur[2]][:size]
            return _patch_element(raw, i, value)
    raise ValueError("no Session ID element to shorten")


def build_variant(name: str, cfg: JoinFuzzConfig,
                  session_id: bytes | None = None) -> bytes:
    """Build one Join Request for the named variant (defaults = ``base``)."""
    ident = cfg.identity
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
                  session_id: bytes | None = None) -> RoundVerdict:
        """One variant, up to ``config.retries + 1`` fresh sessions.

        Each session can carry at most one Join Request; a non-ANSWERED
        outcome is retried on a new session (new ephemeral source port)
        because the controller's per-AP-MAC session cleanup makes roughly
        every second attempt go silent regardless of the payload.
        """
        attempts = 0
        verdict = None
        while attempts <= self.cfg.retries:
            attempts += 1
            verdict = self._attempt(variant, round_no, session_id)
            if verdict.outcome == Outcome.ANSWERED or \
                    "transport_error" in verdict.mutation:
                break
        verdict.mutation["attempts"] = attempts
        return verdict

    def _attempt(self, variant: str, round_no: int,
                 session_id: bytes | None = None) -> RoundVerdict:
        cfg = self.cfg
        discovery = self._discovery_bytes() if cfg.discovery_prelude else b""
        t = SClientTransport(cfg.ac_addr, cert_path=cfg.cert_path,
                             key_path=cfg.key_path, openssl_bin=self.openssl_bin,
                             prelude=discovery)
        v = None
        try:
            t.connect(timeout=cfg.connect_timeout)
            t.wait_handshake(timeout=cfg.connect_timeout)
            mark = t.snapshot()          # ignore handshake-flight bytes
            if variant == "unlocked":
                raw, mut = build_unlocked_variant(cfg, self._rng, session_id=session_id)
            else:
                raw, mut = build_variant(variant, cfg, session_id=session_id), None
            t.send(raw)
            reply = t.recv_since(mark, timeout=TIMEOUT_JOIN_RESPONSE)
            outcome, code = oracle.classify_reply(reply)
            if outcome == Outcome.SILENCE and not t.is_alive:
                # the controller closed the DTLS session right after our send —
                # an application-layer rejection (alert) rather than silence
                outcome = Outcome.ALERT
            if outcome == Outcome.ANSWERED:
                for m in parse_control_messages(reply):
                    if m["msg_type"] == 4:
                        code = builders.result_code_of(m)
            m = {"variant": variant, "round": round_no}
            if mut:
                m.update(mut)
            v = RoundVerdict(
                stage="join", outcome=outcome, result_code=code,
                mutation=m, raw_reply_hex=reply.hex()[:256] if reply else None)
        except Exception as exc:  # noqa: BLE001 - transport failures are data
            v = RoundVerdict(stage="join", outcome=Outcome.SILENCE,
                             mutation={"variant": variant, "round": round_no,
                                       "transport_error": str(exc)[:200]})
            if not isinstance(exc, (TimeoutError,)):
                # surface driver bugs immediately instead of poisoning the run
                raise
        finally:
            t.close()
            time.sleep(self.cfg.round_gap_s)
        return v

    def _discovery_bytes(self) -> bytes:
        """Discovery Request prelude (same 5-tuple as the DTLS session)."""
        from capwap_discovery_fuzzer.vendors.cisco.creator import CiscoPayloadCreator
        return bytes(CiscoPayloadCreator(identity=self.cfg.identity)
                     .create_discovery_request(valid=True))

    def run(self, variants: list[str], rounds_per_variant: int = 1,
            progress=None) -> dict:
        out: dict[str, dict] = {}
        round_no = 0
        for variant in variants:
            stats = {"answered": 0, "success": 0, "silence": 0, "alert": 0,
                     "codes": {}}
            for _ in range(rounds_per_variant):
                round_no += 1
                v = self.run_round(variant, round_no)
                self.records.append({"round": round_no, **v.as_dict()})
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
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--model", default="C9105AXI-C")
    ap.add_argument("--local-ip", default="192.168.10.128")
    ap.add_argument("--regdom-config", type=lambda x: int(x, 0),
                    default=builders.DEFAULT_REG_DOMAIN_CODE,
                    help="code declared in Config Status (0x10 = -C China)")
    ap.add_argument("--variants", default="base",
                    help="comma list, 'all' for the full matrix, or 'unlocked' "
                         "for the random open-element baseline")
    ap.add_argument("--stage", default="join", choices=["join"],
                    help="fuzzing stage (only join is implemented in P4)")
    ap.add_argument("--seed", type=int, default=None,
                    help="RNG seed for the unlocked mode (recorded in summary)")
    ap.add_argument("--rounds", type=int, default=None,
                    help="alias for --rounds-per-variant")
    ap.add_argument("--rounds-per-variant", type=int, default=1)
    ap.add_argument("--round-gap", type=float, default=1.0,
                    help="seconds between rounds; the controller keeps a "
                         "joined session for a while and drops the next join "
                         "until its cleanup settles")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--openssl", default="openssl")
    args = ap.parse_args(argv)

    if args.rounds is not None:
        args.rounds_per_variant = args.rounds

    variants = ALL_VARIANTS if args.variants == "all" else \
        [v.strip() for v in args.variants.split(",") if v.strip()]

    identity = ApIdentity(radios=((0, 0x0D), (1, 0x0A)), num_encrypt=1,
                          model=args.model.encode())
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg = JoinFuzzConfig(ac_addr=(args.ac_ip, args.ac_port),
                         cert_path=args.cert, key_path=args.key,
                         identity=identity, out_dir=out_dir,
                         local_ip=args.local_ip, round_gap_s=args.round_gap)
    fuzzer = JoinStageFuzzer(cfg, openssl_bin=args.openssl, seed=args.seed)

    def progress(round_no: int, variant: str, v: RoundVerdict) -> None:
        extra = f" rc={v.result_code}" if v.result_code is not None else ""
        print(f"[{round_no:3d}] {variant:20s} {v.outcome.value}{extra}",
              flush=True)

    summary = fuzzer.run(variants, args.rounds_per_variant, progress=progress)
    fuzzer.write_jsonl(out_dir / "session.jsonl")
    (out_dir / "summary.json").write_text(
        json.dumps({"variants": variants,
                    "rounds_per_variant": args.rounds_per_variant,
                    "seed": args.seed,
                    "round_gap_s": args.round_gap,
                    "model": args.model,
                    "ac_ip": args.ac_ip,
                    "summary": summary}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
