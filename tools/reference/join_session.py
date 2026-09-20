#!/usr/bin/env python3
"""CAPWAP registered-state lifecycle driver (E5 leftovers).

join -> Configuration Status Request (5) -> Change State Event Request (11) ->
data-channel DTLS (5247) + Data Channel Keep-Alive -> Echo Request (13) loop.

Control channel: UDP 5246 via prefix proxy; data channel: UDP 5247 via second
proxy, same client cert. Message types per RFC 5415 sec 4.5.1.1 table; MUST
elements per sec 8.2 (Config Status) / 8.6 (Change State) / 4.4.1 (keepalive).

Usage: AC_IP=... JRADIOS="0:0x0d,1:0x0a" RUN_SECONDS=120 \
       CERT=... KEY=... python3 join_session.py [tag]
"""
import os
import secrets
import select
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, "/home/gxm/projects/g05")
sys.path.insert(0, "/home/gxm/projects/fuzzing/capwap-discovery-fuzzer/src")

from scapy.packet import Raw  # noqa: E402

from probe_join_env import build_discovery_request, build_join_request, compliant_identity  # noqa: E402
from capwap_discovery_fuzzer.request_creater import CAPWAP_Header, Control_Header  # noqa: E402
from capwap_discovery_fuzzer.vendors.cisco.creator import (  # noqa: E402
    _element, _mac_optional_field, _vsp_value, _VSP207_DATA,
)
from capwap_discovery_fuzzer.vendors.cisco.elements import (  # noqa: E402
    BOARD_DATA_OPTIONS_ELEM_ID, RAD_NAME_ELEM_ID,
)

WLC = (os.environ.get("AC_IP", "192.168.10.201"), 5246)
WLC_DATA = (WLC[0], 5247)
LOCAL_IP = os.environ.get("LOCAL_IP", "192.168.10.128")
SRC_PORT = int(os.environ.get("SRC_PORT", "5260"))
PROXY_PORT = 9446
DATA_PROXY_PORT = 9447
PREFIX = bytes.fromhex("01000000")
OUT = "/home/gxm/projects/g05"
ECHO_INTERVAL = int(os.environ.get("ECHO_INTERVAL", "25"))
RUN_SECONDS = int(os.environ.get("RUN_SECONDS", "120"))

TAG = sys.argv[1] if len(sys.argv) > 1 else "sess"
T0 = time.time()


def log(msg):
    print(f"[{time.time() - T0:7.2f}s] {msg}", flush=True)


ident = compliant_identity()
session_id = secrets.token_bytes(16)
disc = build_discovery_request(ident)
join = build_join_request(ident, session_id, local_ip=LOCAL_IP)
log(f"[id] mac={ident.ap_mac.hex(':')} session_id={session_id.hex()}")
log(f"[build] discovery={len(disc)}B join={len(join)}B")


def control_frame(msg_type: int, seq: int, element_list) -> bytes:
    raw = b""
    if element_list:
        e = None
        for part in element_list:
            e = part if e is None else e / part
        raw = bytes(e)
    hdr = CAPWAP_Header(version=0, type=0, Hlen=4, Rid=0, WBID=1,
                        T=0, F=0, L=0, W=0, M=1, K=0, Flags=0,
                        FragmentID=0, FragmentOffset=0, Rsvd=0)
    ch = Control_Header(MsgType=msg_type, SeqNum=seq,
                        MsgElemsLen=len(raw) + 3, Flags=0)
    return bytes(hdr / Raw(load=_mac_optional_field(ident.ap_mac)) / ch / Raw(load=raw))


def data_keepalive() -> bytes:
    payload = bytes(_element(35, session_id))
    hdr = CAPWAP_Header(version=0, type=0, Hlen=0, Rid=0, WBID=0,
                        T=0, F=0, L=0, W=0, M=0, K=1, Flags=0,
                        FragmentID=0, FragmentOffset=0, Rsvd=0)
    return bytes(hdr / Raw(load=struct.pack(">H", 2 + len(payload)))
                 / Raw(load=payload))


def parse_messages(d: bytes):
    """Parse concatenated CAPWAP control messages -> [(msgtype, seq, [(etype,elen,val)])]"""
    out = []
    i = 0
    while i + 8 <= len(d):
        hlen = ((d[i + 1] >> 3) & 0x1F) * 4
        if hlen < 4 or i + hlen + 8 > len(d):
            break
        msgtype = int.from_bytes(d[i + hlen:i + hlen + 4], "big")
        seq = d[i + hlen + 4]
        o = i + hlen + 8
        elems = []
        while o + 4 <= len(d):
            et = int.from_bytes(d[o:o + 2], "big")
            el = int.from_bytes(d[o + 2:o + 4], "big")
            elems.append((et, el, d[o + 4:o + 4 + el]))
            o += 4 + el
            if el == 0 and et == 0:
                break
        out.append((msgtype, seq, elems))
        i = o
    return out


def dump(tag, msgs):
    for mt, seq, elems in msgs:
        names = {4: "JoinResp", 5: "ConfigStatusReq", 6: "ConfigStatusResp",
                 7: "ConfigUpdateReq", 8: "ConfigUpdateResp", 9: "WTPEventReq",
                 10: "WTPEventResp", 11: "ChangeStateReq", 12: "ChangeStateResp",
                 13: "EchoReq", 14: "EchoResp", 25: "StationCfgReq",
                 26: "StationCfgResp"}
        extra = ""
        for et, el, v in elems:
            if et == 33:
                extra += f" result_code={int.from_bytes(v[:4], 'big')}"
        log(f"[{tag}] MsgType={mt}({names.get(mt, '?')}) seq={seq} "
            f"elems={[(e[0], e[1]) for e in elems]}{extra}")
        for et, el, v in elems:
            if et in (33, 1, 4, 10, 29, 35, 37):
                log(f"[{tag}]   elem {et} len={el} v={v.hex()[:64]}")


# ---------- control channel: socket + discovery ----------
wsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
wsock.bind((LOCAL_IP, SRC_PORT))
wsock.settimeout(2.0)
wsock.sendto(disc, WLC)
try:
    d, src = wsock.recvfrom(4096)
    log(f"[discovery] reply {len(d)}B from {src}")
except socket.timeout:
    log("[discovery] NO REPLY - aborting (gate patch not active?)")
    sys.exit(1)
wsock.settimeout(0.2)

# local proxy endpoints for the two s_client DTLS engines
lsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
lsock.bind(("127.0.0.1", PROXY_PORT))
lsock.settimeout(0.2)
dlsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dlsock.bind(("127.0.0.1", DATA_PROXY_PORT))
dlsock.settimeout(0.2)

client_addr = [None]
data_client_addr = [None]
stop = False
wire_ctl = []          # (t, rec_type) of W->C control records, for CCS wait


def proxy_loop(csock, asock, peer, caddr, tag):
    """csock = s_client-facing socket; asock = WLC-facing UDP socket."""
    while not stop:
        r, _, _ = select.select([csock, asock], [], [], 0.2)
        for s in r:
            try:
                d, a = s.recvfrom(65535)
            except OSError:
                continue
            if s is csock:
                caddr[0] = a
                asock.sendto(PREFIX + d, peer)
            else:
                d4 = d[4:] if d[:4] == PREFIX else d
                if tag == "ctl" and d4:
                    wire_ctl.append((time.time() - T0, d4[0] if d4 else -1))
                if caddr[0]:
                    csock.sendto(d4, caddr[0])
                if os.environ.get("WIRE_DEBUG") and d4:
                    log(f"[{tag}] w2c {len(d4)}B rec0=0x{d4[0]:02x}")


threading.Thread(target=proxy_loop, args=(lsock, wsock, WLC, client_addr, "ctl"),
                 daemon=True).start()

# ---------- data channel socket (early bind, port chosen now) ----------
dsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dsock.bind((LOCAL_IP, 0))
dsock.settimeout(0.2)
threading.Thread(target=proxy_loop, args=(dlsock, dsock, WLC_DATA, data_client_addr, "dat"),
                 daemon=True).start()


def start_s_client(local_proxy_port, tag):
    args = ["openssl", "s_client", "-dtls1_2", "-quiet", "-ign_eof",
            "-mtu", "512", "-connect", f"127.0.0.1:{local_proxy_port}"]
    if os.environ.get("CERT"):
        args += ["-cert", os.environ["CERT"]]
        if os.environ.get("KEY"):
            args += ["-key", os.environ["KEY"]]
    errf = open(f"{OUT}/sess_{tag}_{TAG}.err", "wb")
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=errf, bufsize=0)
    buf = bytearray()
    lock = threading.Lock()

    def reader():
        while True:
            b = p.stdout.read(1)
            if not b:
                break
            with lock:
                buf.extend(b)

    threading.Thread(target=reader, daemon=True).start()
    return p, buf, lock


def send_app(p, data, tag):
    p.stdin.write(data)
    p.stdin.flush()
    log(f"[{tag}] sent {len(data)}B app data")


def wait_app(buf, lock, want, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        with lock:
            if len(buf) >= want:
                return bytes(buf)
        time.sleep(0.2)
    with lock:
        return bytes(buf)


# ---------- control DTLS + join ----------
cp, cbuf, clock = start_s_client(PROXY_PORT, "ctl")

# wait for the server's handshake flight to settle (first w2c record + 2.5s)
t0 = time.time()
while time.time() - t0 < 25 and not wire_ctl:
    time.sleep(0.25)
time.sleep(2.5)
log(f"[dtls] server flight arrived after {time.time() - t0:.1f}s")
send_app(cp, join, "join")

processed = 0       # bytes of cbuf already parsed
seen_join_ok = False
pending = {}        # msgtype -> list of (seq, elems) requests awaiting our response
parse_lock = threading.Lock()


def drain_new():
    """Incrementally parse new complete control messages from the s_client buffer."""
    global processed, seq
    with parse_lock:
        with clock:
            buf = bytes(cbuf)
    msgs = []
    while True:
        if len(buf) - processed < 13:
            break
        i = processed
        hlen = ((buf[i + 1] >> 3) & 0x1F) * 4
        if hlen < 4 or len(buf) - i < hlen + 8:
            break
        msgtype = int.from_bytes(buf[i + hlen:i + hlen + 4], "big")
        msgelemslen = int.from_bytes(buf[i + hlen + 5:i + hlen + 7], "big")
        total = hlen + 5 + msgelemslen
        if total <= 0 or len(buf) - i < total:
            break
        seqno = buf[i + hlen + 4]
        o = i + hlen + 8
        elems = []
        while o + 4 <= i + total:
            et = int.from_bytes(buf[o:o + 2], "big")
            el = int.from_bytes(buf[o + 2:o + 4], "big")
            elems.append((et, el, buf[o + 4:o + 4 + el]))
            o += 4 + el
        msgs.append((msgtype, seqno, elems))
        processed = i + total
    return msgs


def respond(mt_req, mt_resp, elems_extra=()):
    """Answer every pending AC request of type mt_req with the paired response."""
    global seq
    for sreq, _ in pending.pop(mt_req, []):
        elems = list(elems_extra)
        frame = control_frame(mt_resp, sreq, elems)
        send_app(cp, frame, f"resp-{mt_resp}-seq{sreq}")


def service_requests():
    """Drain new control messages once; answer AC-initiated requests; return msgs."""
    msgs = drain_new()
    for mt, sreq, elems in msgs:
        if mt == 4:
            continue
        if mt % 2 == 1:                      # AC-initiated request
            log(f"[ac-req] MsgType={mt} seq={sreq} elems={[(e[0], e[1], e[2].hex()) for e in elems]}")
            pending.setdefault(mt, []).append((sreq, elems))
            if mt == 7:                      # Configuration Update -> Response + Result Code
                echo = [_element(37, v) for t, _, v in elems if t == 37]
                respond(7, 8, [_element(33, (0).to_bytes(4, "big"))] + echo)
            elif mt == 25:                   # Station Configuration -> Response + Result Code
                respond(25, 26, [_element(33, (0).to_bytes(4, "big"))])
            elif mt == 17:                   # Reset Request -> Response (empty)
                respond(17, 18)
            else:                            # unknown request: RFC 4.5.1.1 - reply +1 Unrecognized
                respond(mt, mt + 1, [_element(33, (1).to_bytes(4, "big"))])
    return msgs


def wait_for(want_types, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        msgs = service_requests()
        if any(m[0] in want_types for m in msgs):
            return msgs
        time.sleep(0.3)
    return []


time.sleep(1.0)
msgs = wait_for((4,), 15)
dump("join-reply", [m for m in msgs if m[0] == 4])
if not any(m[0] == 4 for m in msgs):
    with clock:
        log(f"[join] no reply; raw buffer: {bytes(cbuf).hex()[:200]}")
seen_join_ok = any(mt == 4 and any(et == 33 and int.from_bytes(v[:4], "big") == 0
                                   for et, _, v in el) for mt, _, el in msgs)
log(f"[join] result_code_ok={seen_join_ok}")
if not seen_join_ok:
    log("[join] NOT accepted - stopping")
    stop = True
    sys.exit(2)

# respond to AC-initiated requests CONTINUOUSLY — the WLC's Run-state config
# pushes (FIPS etc.) retransmit every 4s and tear the session down on 6 misses
# ("Max Retransmission to AP"); wait-window-only draining answers too late.
def responder():
    while not stop:
        try:
            service_requests()
        except Exception as exc:  # noqa: BLE001
            log(f"[responder] {exc}")
            break
        time.sleep(0.3)

threading.Thread(target=responder, daemon=True).start()

seq = 1

_h = int(os.environ.get("HOLD_BEFORE_CONFIG", "0"))
if _h:
    log(f"[hold] holding {_h}s after join before config status")
    time.sleep(_h)

# ---------- Configuration Status Request (sec 8.2 MUST) ----------
# Cisco VSP (element 37) with nested sub-type 126 = AP Regulatory Domain.
# Wire: VendorID u32 BE (0x00409600) + ElemID u16 BE (0x007e) + data
# {band u8, set u8, slot u8, code u16}. Header must be exactly 6 bytes —
# "0040960000007e" (7B) puts a stray 00 in the elemid and the payload is
# dropped as unknown (uprobe-deflt eid=0x0 evidence, life35 2026-09-20).
_rd0 = bytes.fromhex(os.environ.get("REGDOM0", "4100"))
_rd1 = bytes.fromhex(os.environ.get("REGDOM1", "4100"))
_VSP_REGDOM_HDR = bytes.fromhex("00409600") + (0x00).to_bytes(1, "big") + (0x7e).to_bytes(1, "big")

csr_elems = [
    _element(4, b"C9800-LAB"),                    # AC Name
    _element(31, bytes([0, 1])),                  # Radio Admin State: rid0 enabled
    _element(31, bytes([1, 1])),                  # rid1 enabled
    _element(36, (30).to_bytes(2, "big")),        # Statistics Timer
    _element(48, bytes(15)),                      # WTP Reboot Statistics
    _element(37, _VSP_REGDOM_HDR + bytes([0x00, 0x01, 0x00]) + _rd0),
    _element(37, _VSP_REGDOM_HDR + bytes([0x01, 0x01, 0x01]) + _rd1),
    _element(37, _vsp_value(RAD_NAME_ELEM_ID, ident.ap_name)),
]
send_app(cp, control_frame(5, seq, csr_elems), "config-status")
seq += 1
dump("config-status-reply", [m for m in wait_for((6,), 10) if m[0] == 6])

# sweep runs in the CONFIG phase (Run-state config status is dropped early)
sweep = os.environ.get("SWEEP_CODES", "")
if sweep:
    for code_hex in sweep.split(","):
        b = bytes.fromhex(code_hex)
        csr = [
            _element(4, b"C9800-LAB"),
            _element(31, bytes([0, 1])),
            _element(31, bytes([1, 1])),
            _element(36, (30).to_bytes(2, "big")),
            _element(48, bytes(15)),
            _element(37, (_VSP_REGDOM_HDR)
                     + bytes([0x00, 0x01, 0x00]) + b),
            _element(37, (_VSP_REGDOM_HDR)
                     + bytes([0x01, 0x01, 0x01]) + b),
            _element(37, _vsp_value(RAD_NAME_ELEM_ID, ident.ap_name)),
        ]
        try:
            send_app(cp, control_frame(5, seq, csr), f"sweep-{code_hex}")
            seq = (seq + 1) % 256
        except (BrokenPipeError, OSError) as exc:
            log(f"[sweep] send failed at {code_hex}: {exc}")
            break
        time.sleep(1.0)
    log("[sweep] done")

# ---------- Change State Event Request (sec 8.6 MUST) ----------
cse_elems = [
    _element(32, bytes([0, 1, 0])),               # Radio Op State: rid0 enabled/normal
    _element(32, bytes([1, 1, 0])),               # rid1
    _element(33, (0).to_bytes(4, "big")),         # Result Code success
    _element(37, _vsp_value(BOARD_DATA_OPTIONS_ELEM_ID, _VSP207_DATA)),
    _element(37, _vsp_value(RAD_NAME_ELEM_ID, ident.ap_name)),
]
send_app(cp, control_frame(11, seq, cse_elems), "change-state")
seq += 1
dump("change-state-reply", [m for m in wait_for((12,), 10) if m[0] == 12])

# ---------- data channel DTLS + keepalive (sec 4.4.1) ----------
try:
    dp, dbuf, dlock = start_s_client(DATA_PROXY_PORT, "dat")
    time.sleep(3.0)
    ka = data_keepalive()
    send_app(dp, ka, "data-ka")
    time.sleep(1.0)
    send_app(dp, ka, "data-ka")
    t0 = time.time()
    got = b""
    while time.time() - t0 < 10:
        with dlock:
            got = bytes(dbuf)
        if got:
            break
        time.sleep(0.3)
    log(f"[data-ka] echoed {len(got)}B: {got.hex()[:64]}")
    if got == ka:
        log("[data-ka] VERBATIM ECHO - data channel bound")
except Exception as exc:  # noqa: BLE001
    log(f"[data-ka] FAILED: {exc}")

# ---------- echo loop with AC-request servicing ----------
log(f"[echo] entering loop interval={ECHO_INTERVAL}s for {RUN_SECONDS}s")
t_end = time.time() + RUN_SECONDS
n = 0
while time.time() < t_end:
    time.sleep(ECHO_INTERVAL)
    n += 1
    try:
        send_app(cp, control_frame(13, seq, []), f"echo{n}")
        seq = (seq + 1) % 256
    except (BrokenPipeError, OSError) as exc:
        log(f"[echo{n}] send failed: {exc}")
        break
    t0 = time.time()
    got_echo = False
    while time.time() - t0 < 8:
        for mt, sreq, elems in service_requests():
            if mt == 14:
                got_echo = True
                log(f"[echo{n}] Echo Response seq={sreq}")
        if got_echo:
            break
        time.sleep(0.3)
    if not got_echo:
        log(f"[echo{n}] no echo response within 8s")

stop = True
# kill both s_clients — otherwise they linger and their DTLS retransmits get
# proxied into the NEXT run's control channel, replacing the real session
# ("Unable to fetch wtp session" -> Max Retransmission teardown, life2-41).
for proc in (cp, dp if "dp" in dir() else None):
    if proc:
        try:
            proc.kill()
        except OSError:
            pass
log("[done]")
