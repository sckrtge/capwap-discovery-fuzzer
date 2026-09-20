"""Continuous responder for AC-initiated requests on a live session.

Why this exists (the E7 lesson): the controller starts pushing Configuration
Update Requests ~8 s into Run and retransmits every 4 s; after 6 misses it
tears the session down ("Max Retransmission to AP").  A fuzz driver that only
parses inbound traffic inside its own wait windows answers too late — and once
the controller gives up, the DTLS session is dead even though ``openssl
s_client`` still accepts stdin writes (it received the fatal alert and transmits
nothing; the write "succeeding" is an illusion).

The responder therefore runs its own tight loop and answers every pending
Configuration Update Request with a Configuration Update Response carrying
Result Code success plus the request's vendor payloads echoed back (live-
verified: session lifetime 26 s → 225 s+, all pushes accepted).
"""

from __future__ import annotations

import threading
import time

from capwap_discovery_fuzzer.session import builders
from capwap_discovery_fuzzer.session.builders import (
    MSG_CONFIG_UPDATE_REQUEST,
    RESULT_CODE_SUCCESS,
    parse_control_messages,
)


class Responder:
    """Drain inbound decrypted bytes and answer AC requests on a transport.

    ``transport`` needs ``recv``/``send``; ``identity`` is the same
    :class:`ApIdentity` the Join Request used.  ``round_hook`` (optional)
    receives every parsed message dict — handy for logging oracles.
    """

    def __init__(self, transport, identity, round_hook=None,
                 poll_interval: float = 0.3, result_code: int = RESULT_CODE_SUCCESS):
        self.transport = transport
        self.identity = identity
        self.round_hook = round_hook
        self.poll_interval = poll_interval
        self.result_code = result_code
        self.seq = 200                      # our own seq space for responses
        self.answered: list[int] = []       # msg types answered
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    # ------------------------------------------------------------------ loop

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:  # noqa: BLE001 - a responder must never die loudly
                pass
            self._stop.wait(self.poll_interval)

    def poll_once(self) -> int:
        """Parse new inbound bytes, answer requests; returns answers sent."""
        inbound = self.transport.recv(timeout=0.0)
        answers = 0
        for msg in parse_control_messages(inbound):
            if self.round_hook is not None:
                self.round_hook(msg)
            msg_type = msg["msg_type"]
            if msg_type % 2 == 1:  # AC-initiated request (odd type)
                echo = [(t, v) for t, _l, v in msg["elements"] if t == 37]
                frame = builders.build_config_update_response(
                    self.identity, seq_num=msg["seq"],
                    result_code=self.result_code, echo_elements=tuple(echo))
                self.transport.send(frame)
                self.answered.append(msg_type)
                answers += 1
        return answers
