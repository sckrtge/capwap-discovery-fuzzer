#!/usr/bin/env python3
"""G0.5 plaintext Join gate probe (docs/expired/G05-明文Join门禁验证计划.md).

Builds an RFC 5415 §6.1-compliant Join Request by importing the fuzzer's Cisco
element constructors READ-ONLY (no fuzzer code is modified), validates it with
conformance.check_message(), then optionally sends it to the AC and parses any
reply for the Join Response Result Code (Type 33, §4.6.35).

Runs on the Ubuntu host (192.168.33.128); the AC is C9800-pwn 192.168.33.134.

Usage:
  python3 probe_c9800_join.py build
  python3 probe_c9800_join.py send --variant discovery-only --count 1
  python3 probe_c9800_join.py send --variant cold --count 1
  python3 probe_c9800_join.py send --variant after-discovery --count 1

Every request and reply is appended to $G05_OUT/probe_session.jsonl (default
/home/gxm/projects/g05) with timestamps, raw hex and sha256.
"""

import argparse
import hashlib
import json
import os
import socket
import sys
import time

sys.path.insert(0, "/home/gxm/projects/fuzzing/capwap-discovery-fuzzer/src")

from scapy.packet import Raw  # noqa: E402

from capwap_discovery_fuzzer import conformance  # noqa: E402
from capwap_discovery_fuzzer.request_creater import (  # noqa: E402
    CAPWAP_Header,
    Control_Header,
)
from capwap_discovery_fuzzer.vendors.cisco.creator import (  # noqa: E402
    ApIdentity,
    CiscoPayloadCreator,
    _element,
    _mac_optional_field,
    _vsp_value,
    _VSP207_DATA,
)
from capwap_discovery_fuzzer.vendors.cisco.elements import (  # noqa: E402
    BOARD_DATA_OPTIONS_ELEM_ID,
    RAD_NAME_ELEM_ID,
    make_radio_information,
)

AC_IP = __import__("os").environ.get("AC_IP", "192.168.33.134")
AC_PORT = 5246
LOCAL_IP = __import__("os").environ.get("LOCAL_IP", "192.168.33.128")
MSG_JOIN_REQUEST = 3
MSG_PRIMARY_DISCOVERY_REQUEST = 19


def join_board_data(ident: ApIdentity) -> bytes:
    """JOIN-time WTP Board Data: byte-identical to the Discovery board data
    (ident.board_data, sub-elements 0=model / 1=serial / 4=base_mac).

    E4 authority (parse_wtp_board_data_msgelement@ctrlmsg 0x173ef0): the
    join-time parser uses the SAME sub-element type ids as Discovery
    (0=model, 1=serial, 2=board_id, 3=revision, 4=base_mac, 5=base_name).
    The earlier "join-specific ids" variant put the model string at type 4,
    which lands in the base_mac parser and silently kills the whole message
    (A/B-verified 2026-09-19) — that variant produced the run49b+ silence.
    """
    return ident.board_data()


def compliant_identity() -> ApIdentity:
    """Capture-faithful identity with the two known RFC deviations fixed.

    E/3b verified this variant keeps 8/8 valid Discovery responses on
    C9800-pwn (NumEncrypt 1 per §4.6.41, Radio IDs 1..2 per RFC 5416 §6.25).
    Model is env-overridable (AP_MODEL): the config-status phase validates the
    declared model's supported regulatory domains against the configured
    country ("country validation on AP failed", wlife19) — use the region SKU
    matching the WLC country (e.g. C9105AXI-A for US).
    """
    import os as _os
    return ApIdentity(radios=((1, 0x01), (2, 0x02)), num_encrypt=1,
                      model=_os.environ.get("AP_MODEL", "C9105AXI-H").encode())


def build_join_request(ident: ApIdentity, session_id: bytes,
                       seq_num: int = 0, msg_type: int = MSG_JOIN_REQUEST,
                       local_ip: str = LOCAL_IP) -> bytes:
    # Seed order minus Discovery Type(20, not in the §6.1 MUST list), with the
    # Join-only elements appended after the radio information elements.
    parts = [
        _element(38, join_board_data(ident)),
        _element(39, ident.descriptor()),
        _element(41, b"\x04"),
        _element(44, b"\x01"),
        _element(45, ident.ap_name),
        _element(28, b"default location"),
    ]
    # (join radio elements are appended below with join-specific type bitmasks;
    # ident.radios stays discovery-only)
    # Cisco Type 126 "AP Regulatory Domain" (actube CISCO_ELEM_AP_REGULATORY_DOMAIN;
    # ctrlmsg parse_ap_regulatory_domain_vendor_payload_data: band_id u8 @0, set u8 @1,
    # slotid u8 @2, code u16 @4 -> 5-byte form). Allowed in JOIN state per actube
    # element tables; without it the per-radio reg-domain chk status is never set and
    # join dies at "reg domain chk status failed" (run61 btrace 2026-09-19).
    # WLC verifies (slot0, band0) and (slot1, band1) at config-status time
    # ("Failed to verify reg domain slot ... slot 0 band 0 radio_type 1", wlife9) —
    # band ids are 0-based: 0=2.4G, 1=5G. Domain codes: env-overridable, default 1.
    import os as _os
    _dom = int(_os.environ.get("AP_REG_DOMAIN_CODE", "1"))
    parts.append(_element(126, bytes([0x00, 0x01, 0x00, _dom, _dom])))  # band0, set, slot0
    parts.append(_element(126, bytes([0x01, 0x01, 0x01, _dom, _dom])))  # band1, set, slot1
    # Join-time radio type bitmasks: per RFC 5416 §6.25 |R|N|G|A|B| — slot1 2.4G = B|G|N
    # (0x0D), slot2 5G = A|N (0x0A). The old 0x01/0x02 (B-only / A-only) match no band
    # record for this AP model -> "Band record retrieval error:22" -> reg domain unset.
    import re as _re
    _jr = _os.environ.get("JRADIOS", "1:0x0d,2:0x0a")
    _jradios = [(int(m.group(1)), int(m.group(2), 16))
                for m in _re.finditer(r"(\d+):0x([0-9a-fA-F]+)", _jr)]
    parts += [_element(1048, make_radio_information(rid, rtype))
              for rid, rtype in _jradios]
    parts.append(_element(35, session_id))
    # Maximum Message Length — RFC 5415 §4.6.31, Type 29, Length 2 (u16); a Join
    # Request MUST include it. Absence -> disjoin "Failure decoding max message size"
    # (run69 2026-09-19). 14400 = value seen in Cisco AP join captures.
    parts.append(_element(29, int(_os.environ.get("AP_MAX_MSG_LEN", "14400")).to_bytes(2, "big")))
    parts.append(_element(53, b"\x00"))                       # Limited ECN (§4.6.25)
    parts.append(_element(30, socket.inet_aton(local_ip)))    # §4.6.11 one-of
    parts.append(_element(37, _vsp_value(BOARD_DATA_OPTIONS_ELEM_ID, _VSP207_DATA)))
    parts.append(_element(37, _vsp_value(RAD_NAME_ELEM_ID, ident.ap_name)))
    # Cisco Type 169 "AP Domain" (actube CISCO_ELEM_AP_DOMAIN, struct
    # cisco_ap_static_domain = {bool enable, bstr16 name}): join complains
    # "AP_DOMAIN payload count is 0" without it (wlife20).
    import os as _os
    _domname = _os.environ.get("AP_DOMAIN_NAME", "default").encode()
    parts.append(_element(169, bytes([0x01]) + len(_domname).to_bytes(2, "big") + _domname))

    elements = None
    for part in parts:
        elements = part if elements is None else elements / part

    control_header = Control_Header(
        MsgType=msg_type, SeqNum=seq_num,
        MsgElemsLen=len(bytes(elements)) + 3,  # §4.5.1.1: + MsgElemsLen(2B)+Flags(1B)
        Flags=0)
    capwap_header = CAPWAP_Header(
        version=0, type=0, Hlen=4, Rid=0, WBID=1,
        T=0, F=0, L=0, W=0, M=1, K=0, Flags=0,
        FragmentID=0, FragmentOffset=0, Rsvd=0)
    return bytes(capwap_header / Raw(load=_mac_optional_field(ident.ap_mac))
                 / control_header / elements)


def build_discovery_request(ident: ApIdentity) -> bytes:
    return bytes(CiscoPayloadCreator(identity=ident).create_discovery_request(valid=True))


def decode_elements(raw: bytes) -> list[dict]:
    hlen = ((raw[1] >> 3) & 0x1F) * 4
    out = []
    off = hlen + 8  # control header: MsgType(4)+SeqNum(1)+MsgElemsLen(2)+Flags(1)
    elems = raw[off:]
    o = 0
    while o + 4 <= len(elems):
        etype = int.from_bytes(elems[o:o + 2], "big")
        elen = int.from_bytes(elems[o + 2:o + 4], "big")
        out.append({"type": etype, "len": elen,
                    "value_hex": elems[o + 4:o + 4 + elen].hex()})
        if elen < 0 or o + 4 + elen > len(elems):
            break
        o += 4 + elen
    return out


def conformance_line(raw: bytes) -> str:
    rep = conformance.check_message(raw)
    bits = [f"conformance: type={rep.msg_type}({rep.msg_name})",
            f"elements={rep.element_types}"]
    if rep.violations:
        bits.append(f"VIOLATIONS={rep.violations}")
    if rep.deviations:
        bits.append(f"deviations={rep.deviations}")
    if rep.notes:
        bits.append(f"notes={rep.notes}")
    return " ".join(bits)


def parse_reply(d: bytes, src) -> dict:
    rec: dict = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                 "src": f"{src[0]}:{src[1]}" if src else None,
                 "reply_len": len(d), "reply_hex": d.hex()}
    if not d:
        return rec
    if d[0] == 0x16:
        rec["kind"] = "dtls_record"
        rec["content_type"] = d[0]
        if len(d) > 13:
            rec["handshake_type"] = d[13]
        return rec
    if len(d) < 12:
        rec["kind"] = "short_non_capwap"
        return rec
    hlen = ((d[1] >> 3) & 0x1F) * 4
    if len(d) < hlen + 8:
        rec["kind"] = "truncated_capwap"
        rec["hlen"] = hlen
        return rec
    rec["kind"] = "capwap"
    rec["hlen"] = hlen
    rec["msg_type"] = int.from_bytes(d[hlen:hlen + 4], "big") & 0xFF
    rec["seq_num"] = d[hlen + 4]
    rec["msg_elems_len"] = int.from_bytes(d[hlen + 5:hlen + 7], "big")
    rec["elements"] = decode_elements(d)
    for e in rec["elements"]:
        if e["type"] == 33 and e["len"] == 4:
            rec["result_code"] = int(e["value_hex"], 16)
    return rec


def log(out_path: str, entry: dict) -> None:
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def cmd_build(a: argparse.Namespace) -> int:
    ident = compliant_identity()
    sid = bytes.fromhex(a.session_id) if a.session_id else os.urandom(16)
    join = build_join_request(ident, sid)
    disc = build_discovery_request(ident)
    print(f"identity: ap_name={ident.ap_name!r} radios={ident.radios} "
          f"num_encrypt={ident.num_encrypt} ap_mac={ident.ap_mac.hex()}")
    print(f"session_id: {sid.hex()}")
    for name, raw in (("discovery_seed(19)", disc), ("join_request(3)", join)):
        print(f"== {name}: {len(raw)}B sha256={hashlib.sha256(raw).hexdigest()}")
        print(f"   hex={raw.hex()}")
        hlen = ((raw[1] >> 3) & 0x1F) * 4
        print(f"   hlen={hlen}B msg_type={int.from_bytes(raw[hlen:hlen+4],'big')&0xFF} "
              f"seq={raw[hlen+4]} msgelemslen={int.from_bytes(raw[hlen+5:hlen+7],'big')}")
        for e in decode_elements(raw):
            print(f"   elem type={e['type']} len={e['len']} value={e['value_hex']}")
        print(f"   {conformance_line(raw)}")
        log(a.out, {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": "build",
                    "name": name, "len": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(), "hex": raw.hex(),
                    "session_id": sid.hex() if name.startswith("join") else None,
                    "conformance": str(conformance.check_message(raw))})
    return 0


def send_and_receive(s: socket.socket, raw: bytes, tag: str, a: argparse.Namespace,
                     request_meta: dict) -> None:
    sha = hashlib.sha256(raw).hexdigest()
    print(f"[{tag}] sending {len(raw)}B sha256={sha} to {AC_IP}:{AC_PORT}")
    s.sendto(raw, (AC_IP, AC_PORT))
    deadline = time.time() + a.timeout
    got_reply = False
    while time.time() < deadline:
        s.settimeout(max(0.2, deadline - time.time()))
        try:
            d, src = s.recvfrom(4096)
        except socket.timeout:
            break
        rec = parse_reply(d, src)
        rec.update({"event": "reply", "variant": tag, "request_sha256": sha,
                    "request_hex": raw.hex(), **request_meta})
        log(a.out, rec)
        got_reply = True
        if rec.get("kind") == "dtls_record":
            print(f"[{tag}] DTLS record {rec['reply_len']}B "
                  f"handshake_type={rec.get('handshake_type')} from {rec['src']}")
        elif rec.get("kind") == "capwap":
            rc = rec.get("result_code")
            print(f"[{tag}] CAPWAP reply {rec['reply_len']}B from {rec['src']} "
                  f"msg_type={rec['msg_type']} seq={rec['seq_num']} "
                  f"msgelemslen={rec['msg_elems_len']} result_code={rc}")
            print(f"[{tag}] elements: "
                  f"{[(e['type'], e['len']) for e in rec['elements']]}")
            pair = conformance.check_pair(raw, d)
            print(f"[{tag}] pair-check: violations={pair.violations} "
                  f"deviations={pair.deviations}")
        else:
            print(f"[{tag}] {rec.get('kind')} {rec['reply_len']}B from {rec['src']}")
        # keep listening briefly for further datagrams (e.g. DTLS after CAPWAP)
    if not got_reply:
        rec = {"event": "reply", "variant": tag, "request_sha256": sha,
               "request_hex": raw.hex(), "reply_len": 0, "reply_hex": "",
               "note": f"no reply within {a.timeout}s", **request_meta}
        log(a.out, rec)
        print(f"[{tag}] no reply within {a.timeout}s")


def cmd_send(a: argparse.Namespace) -> int:
    ident = compliant_identity()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((a.bind_ip, a.bind_port))
    s.settimeout(a.timeout)

    if a.variant == "discovery-only":
        for i in range(a.count):
            disc = build_discovery_request(ident)
            send_and_receive(s, disc, f"discovery-only#{i+1}", a,
                             {"msg": "discovery", "attempt": i + 1})
    elif a.variant == "cold":
        for i in range(a.count):
            sid = os.urandom(16)  # fresh 128-bit Session ID per attempt (§4.6.37)
            join = build_join_request(ident, sid)
            send_and_receive(s, join, f"cold-join#{i+1}", a,
                             {"msg": "join", "attempt": i + 1, "session_id": sid.hex()})
    elif a.variant == "after-discovery":
        for i in range(a.count):
            disc = build_discovery_request(ident)
            send_and_receive(s, disc, f"after-discovery#{i+1}:discovery", a,
                             {"msg": "discovery", "attempt": i + 1})
            time.sleep(0.3)
            sid = os.urandom(16)
            join = build_join_request(ident, sid)
            send_and_receive(s, join, f"after-discovery#{i+1}:join", a,
                             {"msg": "join", "attempt": i + 1, "session_id": sid.hex()})
    s.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pb = sub.add_parser("build", help="offline build + conformance check (no packets)")
    pb.add_argument("--session-id", help="fixed Session ID hex (default random)")
    ps = sub.add_parser("send", help="send probes to the AC")
    ps.add_argument("--variant", required=True,
                    choices=["discovery-only", "cold", "after-discovery"])
    ps.add_argument("--count", type=int, default=1)
    ps.add_argument("--timeout", type=float, default=5.0)
    ps.add_argument("--bind-ip", default=LOCAL_IP)
    ps.add_argument("--bind-port", type=int, default=5246)
    for p in (pb, ps):
        p.add_argument("--out", default="/home/gxm/projects/g05/probe_session.jsonl")
    a = ap.parse_args()
    return cmd_build(a) if a.cmd == "build" else cmd_send(a)


if __name__ == "__main__":
    sys.exit(main())
