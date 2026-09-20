"""DTLS transport for CAPWAP control-channel fuzzing.

Cisco frames every CAPWAP-over-DTLS datagram with a 4-byte prefix
(``01 00 00 00``) before the DTLS records; stock ``openssl s_client`` neither
emits nor expects it, so the shipped transport inserts a local UDP proxy that
adds the prefix on the way out and strips it on the way back (live-verified
across the 2026-09-18/20 rounds; ~20 successful sessions).

Why a subprocess instead of a Python DTLS stack: CPython's ``ssl`` module has
no DTLS support, and the controller's HelloVerifyRequest/cookie exchange plus
client-cert renegotiation are exactly what the OpenSSL code paths already
handle.  The :class:`DTLSTransport` interface exists so a native
implementation can replace this one without touching the state machine.

Lifecycle rules (learned the hard way — see the E7 notes):

* **exit must kill** the ``s_client`` child.  An orphaned client keeps its DTLS
  session alive and its retransmits get proxied into the *next* fuzzing
  session, replacing it mid-flight ("Unable to fetch wtp session" →
  ``Max Retransmission`` teardown);
* a proxy thread forwards between the local loopback socket and the WLC; it
  owns no state beyond the client's observed address;
* ``is_alive`` combines process liveness with a write probe — after a fatal
  DTLS alert OpenSSL keeps accepting stdin while transmitting nothing, so
  "write succeeded" alone proves nothing.
"""

from __future__ import annotations

import secrets
import select
import socket
import subprocess
import threading
import time

#: Cisco's 4-byte CAPWAP-over-DTLS datagram prefix.
CISCO_DTLS_PREFIX = bytes.fromhex("01000000")

#: Default loopback proxy port (life44 used 9446 for control, 9447 for data).
DEFAULT_PROXY_PORT = 9446


class TransportError(RuntimeError):
    """Transport-level failure (process died, socket error, timeout)."""


class DTLSTransport:
    """Interface the session state machine codes against."""

    def connect(self, timeout: float = 25.0) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def send(self, data: bytes) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def recv(self, timeout: float = 3.0) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    @property
    def is_alive(self) -> bool:  # pragma: no cover - interface
        raise NotImplementedError


class SClientTransport(DTLSTransport):
    """DTLS transport driven by one ``openssl s_client -dtls1_2`` subprocess.

    Parameters mirror the live-verified invocation (life44)::

        openssl s_client -dtls1_2 -quiet -ign_eof -mtu 512 \
            -connect 127.0.0.1:<proxy_port> -cert <cert> -key <key>

    ``ac_addr`` is the controller ``(ip, 5246)``; the proxy binds an ephemeral
    loopback port unless ``proxy_port`` is given.
    """

    def __init__(self, ac_addr: tuple[str, int], cert_path: str, key_path: str,
                 proxy_port: int | None = None, openssl_bin: str = "openssl",
                 mtu: int = 512):
        self.ac_addr = ac_addr
        self.cert_path = cert_path
        self.key_path = key_path
        self.openssl_bin = openssl_bin
        self.mtu = mtu
        self.proxy_port = proxy_port  # None → ephemeral
        self._proxy: socket.socket | None = None
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._client_addr: tuple[str, int] | None = None
        self._buffer = bytearray()
        self._buf_lock = threading.Lock()
        self._stopped = False
        self.handshake_seconds: float | None = None

    # ------------------------------------------------------------------ setup

    def connect(self, timeout: float = 25.0) -> None:
        if self._proc is not None:
            raise TransportError("already connected")
        self._proxy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._proxy.bind(("127.0.0.1", self.proxy_port or 0))
        self.proxy_port = self._proxy.getsockname()[1]
        self._proxy.settimeout(0.2)

        args = [
            self.openssl_bin, "s_client", "-dtls1_2", "-quiet", "-ign_eof",
            "-mtu", str(self.mtu), "-connect", f"127.0.0.1:{self.proxy_port}",
            "-cert", self.cert_path, "-key", self.key_path,
        ]
        self._client_addr: tuple[str, int] | None = None
        t0 = time.time()
        self._thread = threading.Thread(target=self._proxy_loop, daemon=True)
        self._thread.start()
        try:
            self._proc = subprocess.Popen(
                args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, bufsize=0)
        except OSError as exc:
            self.close()
            raise TransportError(f"failed to start {self.openssl_bin}: {exc}") from exc

        # wait for the proxy to observe the first datagram from s_client, i.e.
        # the ClientHello — after that the handshake is in the controller's
        # hands; give it the remaining budget.
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._client_addr is not None:
                time.sleep(1.0)  # generous slice for HVR/cookie/cert flight
                self.handshake_seconds = time.time() - t0
                return
            if self._proc.poll() is not None:
                self.close()
                raise TransportError(
                    f"s_client exited rc={self._proc.returncode} during handshake")
            time.sleep(0.1)
        self.close()
        raise TransportError(f"handshake timed out after {timeout}s")

    # ------------------------------------------------------------- proxy loop

    def _proxy_loop(self) -> None:
        """Forward loopback<->WLC; adds/strips the Cisco datagram prefix."""
        wsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        wsock.bind(("0.0.0.0", 0))
        try:
            while not self._stopped:
                r, _, _ = select.select([self._proxy, wsock], [], [], 0.2)
                for s in r:
                    try:
                        data, addr = s.recvfrom(65535)
                    except OSError:
                        continue
                    if s is self._proxy:
                        self._client_addr = addr
                        wsock.sendto(CISCO_DTLS_PREFIX + data, self.ac_addr)
                    else:
                        payload = (data[4:] if data[:4] == CISCO_DTLS_PREFIX else data)
                        if self._client_addr is not None:
                            self._proxy.sendto(payload, self._client_addr)
                            with self._buf_lock:
                                self._buffer.extend(payload)
        except OSError:
            pass  # sockets closed during shutdown
        finally:
            wsock.close()

    # ------------------------------------------------------------------- I/O

    def send(self, data: bytes) -> None:
        if self._proc is None or self._proc.poll() is not None:
            raise TransportError("s_client not running")
        assert self._proc.stdin is not None
        try:
            self._proc.stdin.write(data)
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise TransportError(f"s_client stdin write failed: {exc}") from exc

    def recv(self, timeout: float = 3.0) -> bytes:
        """Return **new** decrypted bytes since the last call, or ``b""``."""
        deadline = time.time() + timeout
        start = 0
        with self._buf_lock:
            start = len(self._buffer)
        while time.time() < deadline:
            with self._buf_lock:
                if len(self._buffer) > start:
                    out = bytes(self._buffer[start:])
                    return out
            if self._proc is not None and self._proc.poll() is not None:
                return b""
            time.sleep(0.1)
        return b""

    @property
    def is_alive(self) -> bool:
        """Process liveness only; a dead session keeps stdin writable."""
        return self._proc is not None and self._proc.poll() is None

    # ---------------------------------------------------------------- cleanup

    def close(self) -> None:
        self._stopped = True
        if self._proc is not None and self._proc.poll() is None:
            try:
                self._proc.kill()
            except OSError:
                pass
        if self._proc is not None and self._proc.stdin is not None:
            try:
                self._proc.stdin.close()
            except OSError:
                pass
        self._proc = None
        if self._proxy is not None:
            try:
                self._proxy.close()
            except OSError:
                pass
            self._proxy = None


def random_session_id() -> bytes:
    """Fresh 16-byte Session ID (RFC 5415 §4.6.37) for a new session."""
    return secrets.token_bytes(16)
