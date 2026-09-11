"""Field-lock mode: confine mutation to explicitly mutable byte spans.

Why this exists
---------------
The C9800 WLC silently drops a Discovery Request whose framing does not match
its expectation, so a large share of mutated packets never reaches the element
parser and cannot tell us anything about it. Locked mode confines every
mutation to byte spans that are safe to change, so a run with the framing
tokens frozen cannot be dropped for structural reasons and the replies that do
arrive can be attributed to element-content parsing.

v1 mutation mode
----------------
Equal-length random overwrite inside one mutable span. Packet length, element
count and order, every element's declared Length, and (unless explicitly
released) the CAPWAP and Control header fields are preserved. Length-changing,
insert, drop, reorder and element-Type modes are deliberately left out so that
one variable changes at a time.

Element TLV headers (Type/Length of each element) are always protected in v1:
releasing them would change element semantics or declared lengths, which the
structure-preservation constraint forbids until a dedicated mode exists. The
8-byte CAPWAP base header is likewise always preserved, because rewriting Hlen
or M changes where the Control Header and elements are parsed from — the packet
would stop being parseable rather than mis-parse in an interesting way. The
``capwap-header`` token therefore governs the optional-field region that follows
the base header (the Radio MAC field of a Cisco seed), which can be released
safely because it does not move any offset.

Tokens (``--lock-fields``) select the PROTECTED regions:

  ``capwap-header``      CAPWAP header region (Hlen bytes, including the
                         optional Radio MAC field of a Cisco seed)
  ``msgtype``            Control Header MsgType
  ``msgelemslen``        Control Header MsgElemsLen
  ``cisco-fingerprint``  value bytes of the Cisco identity elements
                         (Types 20/38/39/45/28 and both Type 37 VSPs)
  ``all``                all of the above (conservative set)

Note the asymmetry: a token freezes a region, so omitting ``cisco-fingerprint``
releases the identity bytes too (including the VSP vendor ID). That is
intentional — it is what the fingerprint-ablation step measures — but it is not
the conservative default.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass

#: Element types that make up the Cisco AP identity in a Discovery Request.
CISCO_FINGERPRINT_TYPES = frozenset({20, 38, 39, 45, 28, 37})

#: Regions a caller can freeze. ``all`` expands to exactly this tuple.
LOCK_TOKENS = ("capwap-header", "msgtype", "msgelemslen", "cisco-fingerprint")

#: Upper bound on bytes rewritten per round. Keeping the edit local leaves the
#: rest of the element parseable, which is what makes a reply attributable to
#: the parser rather than to wholesale garbage.
MAX_MUTATION_BYTES = 32


@dataclass(frozen=True)
class Span:
    """A half-open byte range ``[start, end)`` with an attribution label."""

    start: int
    end: int
    label: str

    def __len__(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class Element:
    type: int
    header_start: int
    value_start: int
    value_end: int


@dataclass(frozen=True)
class Layout:
    header_end: int
    ctrl_off: int
    elements: tuple[Element, ...]


def parse_lock_fields(value: str | None) -> set[str] | None:
    """Turn a ``--lock-fields`` value into a validated token set.

    Returns ``None`` when locked mode is off (no value given), which is the
    default and leaves the original mutation pools untouched. Raises
    ``ValueError`` for an empty or unknown token list so the CLI can reject it.
    """
    if value is None:
        return None
    tokens = {t.strip().lower() for t in value.split(",") if t.strip()}
    if not tokens:
        raise ValueError("--lock-fields was given but contains no token")
    if "all" in tokens:
        tokens = set(LOCK_TOKENS)
    unknown = tokens - set(LOCK_TOKENS)
    if unknown:
        raise ValueError(
            f"unknown --lock-fields token(s): {', '.join(sorted(unknown))}; "
            f"supported: {', '.join(LOCK_TOKENS)}, all"
        )
    return tokens


def parse_layout(raw: bytes) -> Layout:
    """Locate the header, Control Header and element TLVs in a CAPWAP payload.

    Offsets come from the wire bytes rather than from a Scapy round-trip, so
    they stay correct for a pcap-derived seed whose serialisation is not
    byte-identical to the capture.
    """
    if len(raw) < 16:
        raise ValueError(f"payload too short for a CAPWAP header: {len(raw)} bytes")

    # Hlen is a 5-bit field at bit offset 8 of the first word (RFC 5415) and
    # counts the whole header, optional fields included, in 4-byte words.
    w0 = struct.unpack_from(">I", raw, 0)[0]
    header_end = ((w0 >> 19) & 0x1F) * 4
    if header_end < 8 or header_end > len(raw):
        header_end = 8
    ctrl_off = header_end

    elements: list[Element] = []
    off = ctrl_off + 8  # 8-byte Control Header: MsgType(4) SeqNum(1) Len(2) Flags(1)
    while off + 4 <= len(raw):
        etype, elen = struct.unpack_from(">HH", raw, off)
        value_start = off + 4
        value_end = value_start + elen
        if value_end > len(raw):
            break  # declared length runs past the payload; stop rather than guess
        elements.append(Element(etype, off, value_start, value_end))
        off = value_end

    return Layout(header_end=header_end, ctrl_off=ctrl_off, elements=tuple(elements))


def protected_spans(raw: bytes, freeze: set[str]) -> list[Span]:
    """Byte ranges that must stay identical to the seed for *freeze*."""
    layout = parse_layout(raw)
    spans: list[Span] = []

    if "capwap-header" in freeze:
        spans.append(Span(0, layout.header_end, "capwap-header"))
    if "msgtype" in freeze:
        spans.append(Span(layout.ctrl_off, layout.ctrl_off + 4, "msgtype"))
    if "msgelemslen" in freeze:
        spans.append(Span(layout.ctrl_off + 5, layout.ctrl_off + 7, "msgelemslen"))
    if "cisco-fingerprint" in freeze:
        for elem in layout.elements:
            if elem.type in CISCO_FINGERPRINT_TYPES and len_elem(elem) > 0:
                spans.append(Span(elem.value_start, elem.value_end,
                                  f"fingerprint-type{elem.type}"))
    return spans


def len_elem(elem: Element) -> int:
    return elem.value_end - elem.value_start


def _overlaps(span: Span, spans: list[Span]) -> bool:
    return any(s.start < span.end and span.start < s.end for s in spans)


def mutable_spans(raw: bytes, freeze: set[str]) -> list[Span]:
    """Byte ranges the v1 mutator may rewrite, given the frozen regions.

    Element values are always candidates; the CAPWAP optional-field region and
    the Control Header fields are candidates only when their token is absent, so
    a caller that freezes the framing cannot be surprised by a rewritten
    MsgType. The 8-byte base header is never mutable in v1 (see module docstring).
    """
    layout = parse_layout(raw)
    frozen = protected_spans(raw, freeze)

    candidates: list[Span] = []
    for elem in layout.elements:
        if len_elem(elem) > 0:
            candidates.append(Span(elem.value_start, elem.value_end,
                                   f"value-type{elem.type}"))
    if "capwap-header" not in freeze and layout.header_end > 8:
        candidates.append(Span(8, layout.header_end, "capwap-optional-fields"))
    if "msgtype" not in freeze:
        candidates.append(Span(layout.ctrl_off, layout.ctrl_off + 4, "msgtype"))
    if "msgelemslen" not in freeze:
        candidates.append(Span(layout.ctrl_off + 5, layout.ctrl_off + 7, "msgelemslen"))

    return [c for c in candidates if not _overlaps(c, frozen)]


def mutate_span_equal_length(raw: bytes, span: Span, rng: random.Random) -> bytes:
    """Equal-length overwrite of up to MAX_MUTATION_BYTES inside one named span.

    Split out from :func:`mutate_equal_length` so a caller that has already
    chosen the span (the adaptive scheduler in F) can mutate exactly that one.
    """
    count = rng.randint(1, min(len(span), MAX_MUTATION_BYTES))
    start = rng.randint(span.start, span.end - count)
    out = bytearray(raw)
    for i in range(start, start + count):
        out[i] = rng.getrandbits(8)
    return bytes(out)


def mutate_equal_length(raw: bytes, spans: list[Span], rng: random.Random) -> tuple[bytes, str]:
    """Overwrite up to ``MAX_MUTATION_BYTES`` random bytes inside one span.

    Returns the mutated payload and a method-chain label naming the span, so
    ``summary.json`` can attribute replies to a specific element. With no
    mutable span the seed is returned unchanged and labelled ``none``; the
    caller logs that case rather than silently sending an unmutated packet.
    """
    if not spans:
        return bytes(raw), "locked_equal_length_value:none"

    span = rng.choice(spans)
    return mutate_span_equal_length(raw, span, rng), f"locked_equal_length_value:{span.label}"
