#!/usr/bin/env python3
"""E2 (2026-09-18): full CAPWAP join chain over DTLS against the patched WLC.

Pipeline: [prefix proxy] adds/strips Cisco's 4-byte DTLS framing prefix
(01 00 00 00) around every datagram between a local openssl s_client DTLS
session and the WLC's 5246 socket, so a stock DTLS client can speak CAPWAP.

Steps: Discovery preamble (same 5-tuple) -> s_client DTLS 1.2 handshake ->
send the RFC-compliant Join Request as app data -> capture decrypted replies.

Usage: AC_IP=192.168.10.201 python3 e2_join_chain.py [attempt-tag]
Optional env: CERT=/path/ap.crt KEY=/path/ap.key (client certificate).
"""
import os
import select
import secrets
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, "/home/gxm/projects/g05")
sys.path.insert(0, "/home/gxm/projects/fuzzing/capwap-discovery-fuzzer/src")

TAG = sys.argv[1] if len(sys.argv) > 1 else "a1"
WLC = (os.environ.get("AC_IP", "192.168.10.201"), 5246)
LOCAL_IP = os.environ.get("LOCAL_IP", "192.168.10.128")
SRC_PORT = int(os.environ.get("SRC_PORT", "5260"))
PROXY_PORT = 9446
PREFIX = bytes.fromhex("01000000")
OUT = "/home/gxm/projects/g05"

from probe_join_env import build_discovery_request, build_join_request, compliant_identity  # noqa: E402

ident = compliant_identity()
session_id = secrets.token_bytes(16)
disc = build_discovery_request(ident)
join = build_join_request(ident, session_id, local_ip=LOCAL_IP)
open(f"{OUT}/e2_discovery.bin", "wb").write(disc)
open(f"{OUT}/e2_join.bin", "wb").write(join)
print(f"[id] mac={ident.ap_mac.hex(':')} name={getattr(ident, 'ap_name', b'')} "
      f"session_id={session_id.hex()}")
print(f"[build] discovery={len(disc)}B join={len(join)}B (tag={TAG})")

# --- WLC-facing socket + Discovery preamble (same 5-tuple as the DTLS session)
wsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
wsock.bind((LOCAL_IP, SRC_PORT))
wsock.settimeout(2.0)
wsock.sendto(disc, WLC)
try:
    d, src = wsock.recvfrom(4096)
    print(f"[discovery] reply {len(d)}B from {src}")
except socket.timeout:
    print("[discovery] NO REPLY — aborting (gate patch not active?)")
    sys.exit(1)
wsock.settimeout(0.2)

# --- prefix proxy
lsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
lsock.bind(("127.0.0.1", PROXY_PORT))
lsock.settimeout(0.2)
client_addr = None
events = []
stop = False


def proxy_loop():
    global client_addr
    while not stop:
        r, _, _ = select.select([lsock, wsock], [], [], 0.2)
        for s in r:
            try:
                d, a = s.recvfrom(65535)
            except OSError:
                continue
            if s is lsock:
                client_addr = a
                events.append((round(time.time() - T0, 2), "c2w", d[0] if d else -1, len(d)))
                print(f"    [wire] c2w {len(d)}B: {d[:40].hex()}")
                wsock.sendto(PREFIX + d, WLC)
            else:
                if d[:4] == PREFIX:
                    d4 = d[4:]
                else:
                    d4 = d
                events.append((round(time.time() - T0, 2), "w2c", d4[0] if d4 else -1, len(d)))
                print(f"    [wire] w2c {len(d)}B (stripped {len(d4)}B rec0=0x{d4[0]:02x}): {d4[:40].hex()}")
                if client_addr:
                    lsock.sendto(d4, client_addr)


T0 = time.time()
threading.Thread(target=proxy_loop, daemon=True).start()

# --- s_client DTLS session
args = ["openssl", "s_client", "-dtls1_2", "-quiet", "-ign_eof",
        "-mtu", "512",
        "-connect", f"127.0.0.1:{PROXY_PORT}"]
if os.environ.get("CERT"):
    args += ["-cert", os.environ["CERT"]]
    if os.environ.get("KEY"):
        args += ["-key", os.environ["KEY"]]
print("[s_client]", " ".join(args))
errf = open(f"{OUT}/e2_sclient_{TAG}.err", "wb")
p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=errf, bufsize=0)
app = bytearray()
app_events = []


def reader():
    while True:
        b = p.stdout.read(1)
        if not b:
            break
        app.extend(b)
        if len(app) % 1 == 0 and (not app_events or len(app) - app_events[-1][0] >= 1):
            app_events.append((len(app), round(time.time() - T0, 2)))


threading.Thread(target=reader, daemon=True).start()

# --- wait for server ChangeCipherSpec (handshake essentially done)
t0 = time.time()
ccs = False
while time.time() - t0 < 27 and not app_events or (time.time() - t0 < 27):
    if any(e[1] == "w2c" and e[2] == 0x14 for e in events):
        ccs = True
        break
    time.sleep(0.25)
time.sleep(1.5)
print(f"[dtls] server CCS seen={ccs} at +{time.time()-T0:.1f}s; wire events:")
for e in events:
    print(f"    +{e[0]:6.2f}s {e[1]} rec=0x{e[2]:02x} len={e[3]}" if e[2] >= 0
          else f"    +{e[0]:6.2f}s {e[1]} rec=- len={e[3]}")

# --- send Join Request as app data
try:
    p.stdin.write(join)
    p.stdin.flush()
    time.sleep(3.0)
    p.stdin.write(join)   # second copy: first-app-record drop quirk probe
    p.stdin.flush()
    print(f"[join] {len(join)}B plaintext sent as DTLS app data")
except (BrokenPipeError, OSError) as exc:
    print(f"[join] FAILED to write to s_client: {exc}")

# --- collect decrypted replies
t0 = time.time()
while time.time() - t0 < 45 and not app:
    time.sleep(0.3)
time.sleep(2.0)  # post-reply settle
reply = bytes(app)
print(f"[reply] {len(reply)}B decrypted: {reply.hex()}")

# light parse: CAPWAP control message -> msgtype + Result Code (type 33)
if len(reply) > 12:
    hlen = ((reply[1] >> 3) & 0x1F) * 4
    msgtype = int.from_bytes(reply[hlen:hlen + 4], "big")
    print(f"[parse] capwap hlen={hlen} control MsgType={msgtype}")
    o = hlen + 8
    while o + 4 <= len(reply):
        et = int.from_bytes(reply[o:o + 2], "big")
        el = int.from_bytes(reply[o + 2:o + 4], "big")
        v = reply[o + 4:o + 4 + el]
        extra = f" result_code={int.from_bytes(v[:4], 'big')}" if et == 33 else ""
        print(f"    elem type={et} len={el} v={v[:24].hex()}{'...' if el > 24 else ''}{extra}")
        if el < 0 or o + 4 + el > len(reply):
            break
        o += 4 + el

stop = True
try:
    p.kill()
except OSError:
    pass
print(f"[done] tag={TAG} events={len(events)} app_bytes={len(reply)}")
