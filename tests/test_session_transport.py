"""Loopback tests for :mod:`capwap_discovery_fuzzer.session.transport`.

Runs a real ``openssl s_server -dtls1_2`` on localhost and pushes bytes through
:class:`SClientTransport` — no controller involved.  Skipped (not failed) when
no openssl binary is available on the test host.  The server uses a throwaway
self-signed certificate; the client presents another one, and neither side
verifies (mirroring the fuzzing posture where trust is configured out of band).
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time

import pytest

from capwap_discovery_fuzzer.session.transport import CISCO_DTLS_PREFIX, SClientTransport

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None,
                                reason="openssl not available")


def _openssl() -> str:
    return shutil.which("openssl")  # type: ignore[return-value]


def _self_signed(tmp_path, cn: str) -> tuple[str, str]:
    cert = str(tmp_path / f"{cn}.pem")
    key = str(tmp_path / f"{cn}.key")
    subprocess.run(
        [_openssl(), "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "2", "-subj", f"/CN={cn}"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


@pytest.fixture()
def s_server(tmp_path):
    port_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    port_probe.bind(("127.0.0.1", 0))
    port = port_probe.getsockname()[1]
    port_probe.close()
    cert, key = _self_signed(tmp_path, "srv")
    proc = subprocess.Popen(
        [_openssl(), "s_server", "-dtls1_2", "-quiet", "-port", str(port),
         "-cert", cert, "-key", key],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    time.sleep(0.8)
    yield port
    proc.kill()


def test_connect_send_close(s_server, tmp_path):
    cert, key = _self_signed(tmp_path, "cli")
    t = SClientTransport(("127.0.0.1", s_server), cert_path=cert, key_path=key,
                         openssl_bin=_openssl(), handshake_settle=0.3)
    t.connect(timeout=15.0)
    assert t.is_alive
    # s_server sends nothing on its own; simulate the server flight arriving
    # (wait_handshake blocks on inbound before the settle window)
    winger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    winger.sendto(b"flight", ("127.0.0.1", t._wsock.getsockname()[1]))
    t.wait_handshake(timeout=10.0)
    t.send(bytes(range(48)))          # must not raise
    time.sleep(0.3)
    t.close()
    assert not t.is_alive


def test_connect_timeout_on_closed_port():
    port_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    port_probe.bind(("127.0.0.1", 0))
    port = port_probe.getsockname()[1]
    port_probe.close()
    t = SClientTransport(("127.0.0.1", port), cert_path="", key_path="",
                         openssl_bin=_openssl())
    with pytest.raises(Exception):
        t.connect(timeout=3.0)
    t.close()


def test_prefix_constant():
    assert CISCO_DTLS_PREFIX == b"\x01\x00\x00\x00"


def test_close_is_idempotent():
    t = SClientTransport(("127.0.0.1", 5246), cert_path="", key_path="")
    t.close()  # never connected — must not raise
    t.close()
