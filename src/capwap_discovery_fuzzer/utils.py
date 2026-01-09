import random
import logging
from scapy.packet import Packet
from scapy.layers.inet import IP
from scapy.packet import Raw

log = logging.getLogger(__name__)

def random_bytes(length: int, b: bytes | None = None):
    """
    Generate bytes of "length" length,
    or generate bytes with "b" repeated "length" times
    """
    if b is None:
        return random.getrandbits(length * 8).to_bytes(length, "big")
    return b * length

def hexdump(data: bytes, width: int = 16) -> str:
    """
    print hex
    """
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)

def mutate_bytes(data: bytes) -> bytes:
    if not data:
        return bytes([random.randrange(256)])

    b = bytearray(data)
    op = random.choice(("insert", "delete", "flip_bit"))

    if op == "insert":
        pos = random.randrange(len(b) + 1)
        b.insert(pos, random.randrange(256))

    elif op == "delete":
        if len(b) > 1:
            pos = random.randrange(len(b))
            del b[pos]

    elif op == "flip_bit":
        bit = random.randrange(len(b) * 8)
        byte_idx = bit // 8
        bit_offset = bit % 8
        b[byte_idx] ^= (1 << bit_offset)

    return bytes(b)

def split_bytes(raw:bytes, offset:int, length:int | None = None):
    """
    split [offset: offset + length]
    """
    if length is None:
        return raw
    if offset + length > len(raw):
        raise ValueError("buffer underflow")
    return raw[offset: offset+length]