import logging
from scapy.packet import Packet
from scapy.layers.inet import IP
from scapy.packet import Raw
import random

log = logging.getLogger(__name__)

def random_bytes(length: int, b: bytes | None = None, rng: random.Random | None = None) -> bytes:
    """
    Generate bytes of "length" length,
    or generate bytes with "b" repeated "length" times
    """
    rng = rng or random
    if b is None:
        return rng.getrandbits(length * 8).to_bytes(length, "big")
    return b * length

def mutate_bytes(data: bytes, rng: random.Random | None = None) -> bytes:
    rng = rng or random
    if not data:
        return bytes([rng.randrange(256)])

    b = bytearray(data)
    op = rng.choice(("insert", "delete", "flip_bit"))

    if op == "insert":
        pos = rng.randrange(len(b) + 1)
        b.insert(pos, rng.randrange(256))

    elif op == "delete":
        if len(b) > 1:
            pos = rng.randrange(len(b))
            del b[pos]

    elif op == "flip_bit":
        bit = rng.randrange(len(b) * 8)
        byte_idx = bit // 8
        bit_offset = bit % 8
        b[byte_idx] ^= (1 << bit_offset)

    return bytes(b)

def split_bytes(raw: bytes, offset: int, length: int | None = None):
    """
    split [offset: offset + length]
    """
    if length is None:
        return raw
    if offset + length > len(raw):
        raise ValueError("buffer underflow")
    return raw[offset: offset + length]