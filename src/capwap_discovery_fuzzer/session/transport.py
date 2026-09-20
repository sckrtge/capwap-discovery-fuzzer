"""DTLS transport for CAPWAP control-channel fuzzing.

Cisco frames every CAPWAP-over-DTLS datagram with a 4-byte prefix
(``01 00 00 00``) before the DTLS records; stock ``openssl s_client`` neither
emits nor expects it, so the shipped transport inserts a local UDP proxy that
adds the prefix on the way out and strips it on the way back (live-verified
across the 2026-09-18/20 rounds; ~20 successful sessions).

Why a subprocess instead of a Python DTLS stack: CPython's ``ssl`` module has
no DTLS support, and the controller's HelloVerifyRequest/cookie exchange plus
client-certificate handling are exactly what the OpenSSL code paths already
deal with.  The :class:`DTLSTransport` interface exists so a native
implementation can replace this one without touching the state machine.

Lifecycle rules (learned the hard way — see the E7 notes):

* **exit must kill** the ``s_client`` child.  An orphaned client keeps its DTLS
  session alive and its retransmits get proxied into the *next* fuzzing
  session, replacing it mid-flight ("Unable to fetch wtp session" →
  ``Max Retransmission`` teardown);
* a proxy thread forwards between the local loopback socket and the WLC; the
  WLC-facing socket is also the Discovery-prelude sender — the prelude must
  share the DTLS session's 5-tuple;
* connect/wait_handshake are two phases: application data sent before the
  server's flight has arrived is rejected with an epoch-1 alert (verified
  live 2026-09-20);
* ``is_alive`` covers process liveness only — after a fatal DTLS alert OpenSSL
  keeps accepting stdin while transmitting nothing.
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

    def connect(self, timeout: float = 25.0) -> None:  # pragma: no cover
        raise NotImplementedError

    def wait_handshake(self, timeout: float = 25.0) -> None:  # pragma: no cover
        raise NotImplementedError

    def send(self, data: bytes) -> None:  # pragma: no cover
        raise NotImplementedError

    def recv(self, timeout: float = 3.0) -> bytes:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover
        raise NotImplementedError

    @property
    def is_alive(self) -> bool:  # pragma: no cover
        raise NotImplementedError


class SClientTransport(DTLSTransport):
    """DTLS transport driven by one ``openssl s_client -dtls1_2`` subprocess.

    Parameters mirror the live-verified invocation (life44)::

        openssl s_client -dtls1_2 -quiet -ign_eof -mtu 512 \
            -connect 127.0.0.1:<proxy_port> -cert <cert> -key <key>

    ``ac_addr`` is the controller ``(ip, 5246)``; the proxy binds an ephemeral
    loopback port unless ``proxy_port`` is given.  ``prelude`` (a Discovery
    Request) is sent from the WLC-facing socket before the handshake so the
    controller sees the discovery on the same 5-tuple.
    """

    def __init__(self, ac_addr: tuple[str, int], cert_path: str, key_path: str,
                 proxy_port: int | None = None, openssl_bin: str = "openssl",
                 mtu: int = 512, prelude: bytes = b"",
                 handshake_settle: float = 2.5, wlc_port: int = 0):
        self.ac_addr = ac_addr
        self.cert_path = cert_path
        self.key_path = key_path
        self.openssl_bin = openssl_bin
        self.mtu = mtu
        self.prelude = prelude
        self.proxy_port = proxy_port  # None → ephemeral
        self.handshake_settle = handshake_settle
        self.wlc_port = wlc_port      # fixed source port for the 5-tuple
        self._proxy: socket.socket | None = None
        self._wsock: socket.socket | None = None
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._client_addr: tuple[str, int] | None = None
        self._inbound_seen = threading.Event()
        self._wire_bytes = 0          # encrypted bytes seen on the wire
        self._buffer = bytearray()
        self._buf_lock = threading.Lock()
        self._stopped = False
        self.handshake_seconds: float | None = None

    def connect(self, timeout: float = 25.0) -> None:
        """Start proxy + s_client; returns once the ClientHello is observed.

        Call :meth:`wait_handshake` before sending application data.
        """
        if self._proc is not None:
            raise TransportError("already connected")
        self._proxy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._proxy.bind(("127.0.0.1", self.proxy_port or 0))
        self.proxy_port = self._proxy.getsockname()[1]
        self._proxy.settimeout(0.2)
        # the WLC-facing socket doubles as the discovery-prelude sender: the
        # prelude MUST share the DTLS session's 5-tuple, and its response MUST
        # be consumed here — the documented flow (e2_join_chain) waits for the
        # reply before starting the DTLS client; otherwise the stale reply is
        # forwarded to s_client as bogus record data
        self._wsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._wsock.bind(("0.0.0.0", self.wlc_port))
        if self.prelude:
            self._wsock.settimeout(3.0)
            try:
                self._wsock.sendto(self.prelude, self.ac_addr)
                self._wsock.recvfrom(4096)          # Discovery Response — discard
            except socket.timeout:
                self.close()
                raise TransportError("no Discovery Response (controller down?)")
            except OSError:
                pass
            finally:
                self._wsock.settimeout(0.2)

        # NOTE: no -ign_eof — on close() we end stdin so OpenSSL sends a
        # close_notify, releasing the session on the controller.  Without it,
        # killed clients leave the per-AP-MAC session occupied and every
        # OTHER new handshake is dropped (single session per AP MAC).
        args = [
            self.openssl_bin, "s_client", "-dtls1_2", "-quiet",
            "-mtu", str(self.mtu), "-connect", f"127.0.0.1:{self.proxy_port}",
            "-cert", self.cert_path, "-key", self.key_path,
        ]
        t0 = time.time()
        self._thread = threading.Thread(target=self._proxy_loop, daemon=True)
        self._thread.start()
        try:
            self._proc = subprocess.Popen(
                args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, bufsize=0)
        except OSError as exc:
            self.close()
            raise TransportError(f"failed to start {self.openssl_bin}: {exc}") from exc

        # openssl prints DECRYPTED application data on stdout — that is what
        # the oracle parses; the proxy only ever sees encrypted wire bytes.
        def _stdout_reader() -> None:
            stream = self._proc.stdout if self._proc else None
            if stream is None:
                return
            while not self._stopped:
                b = stream.read(1)
                if not b:
                    break
                with self._buf_lock:
                    self._buffer.extend(b)

        threading.Thread(target=_stdout_reader, daemon=True).start()

        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._client_addr is not None:
                self.handshake_seconds = time.time() - t0
                return
            if self._proc.poll() is not None:
                self.close()
                raise TransportError(
                    f"s_client exited rc={self._proc.returncode} during handshake")
            time.sleep(0.1)
        self.close()
        raise TransportError(f"handshake timed out after {timeout}s")

    def wait_handshake(self, timeout: float = 25.0) -> None:
        """Block until the server's flight is complete, then settle.

        The first inbound datagram may be only the HelloVerifyRequest; the
        flight is considered complete once no new wire bytes arrive for
        ``quiet_window`` seconds.  Sending app data before the handshake
        finishes makes the controller answer with an epoch-1 alert.
        """
        deadline = time.time() + timeout
        if not self._inbound_seen.wait(min(timeout, 10.0)):
            self.close()
            raise TransportError("no server flight observed")
        quiet = self.handshake_settle
        last = -1
        while time.time() < deadline:
            n = self._wire_bytes
            if n == last:
                time.sleep(self.handshake_settle)
                return
            last = n
            time.sleep(quiet)
        self.close()
        raise TransportError(f"handshake flight timed out after {timeout}s")

    def _proxy_loop(self) -> None:
        """Forward loopback<->WLC; adds/strips the Cisco datagram prefix."""
        wsock = self._wsock
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
                        # flight detection only — decrypted payload reaches the
                        # buffer via the stdout reader thread, not from here
                        self._wire_bytes += len(payload)
                        self._inbound_seen.set()
                        if self._client_addr is not None:
                            self._proxy.sendto(payload, self._client_addr)
        except OSError:
            pass  # sockets closed during shutdown
        finally:
            wsock.close()

    def send(self, data: bytes) -> None:
        if self._proc is None or self._proc.poll() is not None:
            raise TransportError("s_client not running")
        assert self._proc.stdin is not None
        try:
            self._proc.stdin.write(data)
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise TransportError(f"s_client stdin write failed: {exc}") from exc

    def snapshot(self) -> int:
        """Current inbound-buffer position, for use with :meth:`recv_since`."""
        with self._buf_lock:
            return len(self._buffer)

    def recv_since(self, mark: int, timeout: float = 3.0) -> bytes:
        """Return inbound bytes accumulated after ``mark``, waiting up to timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._buf_lock:
                if len(self._buffer) > mark:
                    return bytes(self._buffer[mark:])
            if self._proc is not None and self._proc.poll() is not None:
                return b""
            time.sleep(0.1)
        return b""

    def recv(self, timeout: float = 3.0) -> bytes:
        """Return **new** decrypted bytes since the last call, or ``b""``."""
        deadline = time.time() + timeout
        with self._buf_lock:
            start = len(self._buffer)
        while time.time() < deadline:
            with self._buf_lock:
                if len(self._buffer) > start:
                    return bytes(self._buffer[start:])
            if self._proc is not None and self._proc.poll() is not None:
                return b""
            time.sleep(0.1)
        return b""

    @property
    def is_alive(self) -> bool:
        """Process liveness only; a dead session keeps stdin writable."""
        return self._proc is not None and self._proc.poll() is None

    def close(self) -> None:
        self._stopped = True
        if self._proc is not None and self._proc.poll() is None:
            # orderly close first: stdin EOF makes OpenSSL emit close_notify,
            # which frees the controller session for the next round
            try:
                self._proc.stdin.close()
            except OSError:
                pass
            deadline = time.time() + 2.0
            while self._proc.poll() is None and time.time() < deadline:
                time.sleep(0.1)
        if self._proc is not None and self._proc.poll() is None:
            try:
                self._proc.kill()
            except OSError:
                pass
        self._proc = None
        if self._proxy is not None:
            try:
                self._proxy.close()
            except OSError:
                pass
            self._proxy = None
        if self._wsock is not None:
            try:
                self._wsock.close()
            except OSError:
                pass
            self._wsock = None


def random_session_id() -> bytes:
    """Fresh 16-byte Session ID (RFC 5415 §4.6.37) for a new session."""
    return secrets.token_bytes(16)
