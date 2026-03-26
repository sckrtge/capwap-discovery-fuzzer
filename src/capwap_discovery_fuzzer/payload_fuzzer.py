from capwap_discovery_fuzzer.request_creater import *
from scapy.packet import Packet
from scapy.layers.inet import IP, UDP
import random

class Payload_Fuzzer:
    def __init__(self, base_pkt: Packet):
        self.base = base_pkt

    def _clone(self) -> Packet:
        p = self.base.copy()
        if IP in p:
            p[IP].len = None
        if UDP in p:
            p[UDP].len = None
            p[UDP].chksum = None
        return p

    # --------------------- 原有 CAPWAP fuzz 方法 ---------------------
    def fuzz_capwap_header(self) -> Packet:
        p = self._clone()
        hdr = p.getlayer("CAPWAP Header")
        if hdr is None:
            raise ValueError("CAPWAP header invalid!")
        hdr.version = random.randint(0, 3)
        hdr.Hlen = random.randint(0, 31)
        hdr.FragmentOffset = random.randint(0, 0x1FFF)
        return p

    def fuzz_control_header(self) -> Packet:
        p = self._clone()
        ctrl = p.getlayer("Control Header")
        if ctrl is None:
            raise ValueError("Control header invalid!")
        ctrl.SeqNum = random.randint(0, 255)
        ctrl.MsgElemsLen = random.choice([0, 1, 0xFFFF])
        return p

    def _iter_message_elements(self, pkt: Packet) -> list[Packet]:
        elems = []
        i = 0
        while True:
            elem = pkt.getlayer(MessageElement, i)
            if elem is None:
                break
            elems.append(elem)
            i += 1
        return elems

    def fuzz_any_msg_type(self) -> Packet:
        p = self._clone()
        elems = self._iter_message_elements(p)
        if not elems:
            return p
        target = random.choice(elems)
        target.Type = random.randint(0, 512)
        return p

    def fuzz_any_msg_length(self) -> Packet:
        p = self._clone()
        elems = self._iter_message_elements(p)
        if not elems:
            return p
        target = random.choice(elems)
        target.Length = random.randint(0, 512)
        return p

    def fuzz_any_msg_value(self) -> Packet:
        p = self._clone()
        elems = self._iter_message_elements(p)
        if not elems:
            return p
        target = random.choice(elems)
        new_len = random.randint(0, 256)
        target.Value = bytes(random.getrandbits(8) for _ in range(new_len))
        target.Length = new_len
        return p

    def fuzz_specific_msg(self, msg_type: int) -> Packet:
        p = self._clone()
        elems = self._iter_message_elements(p)
        for elem in elems:
            if elem.Type == msg_type:
                new_len = random.randint(0, 256)
                elem.Value = bytes(random.getrandbits(8) for _ in range(new_len))
                elem.Length = new_len
                break
        return p

    def fuzz_duplicate_msg(self) -> Packet:
        p = self._clone()
        elems = self._iter_message_elements(p)
        if not elems:
            return p
        target = random.choice(elems)
        dup = target.copy()
        target.add_payload(dup)
        return p

    def fuzz_drop_last_msg(self) -> Packet:
        p = self._clone()
        elems = self._iter_message_elements(p)
        if len(elems) < 2:
            return p
        elems[-2].remove_payload()
        return p

    def fuzz_shuffle_msgs(self) -> Packet:
        p = self._clone()
        elems = self._iter_message_elements(p)
        if len(elems) < 2:
            return p
        first = elems[0]
        parent = p
        while parent.payload is not first:
            parent = parent.payload
        random.shuffle(elems)
        new_chain = elems[0]
        cur = new_chain
        for e in elems[1:]:
            cur.add_payload(e)
            cur = e
        parent.remove_payload()
        parent.add_payload(new_chain)
        return p

    def fuzz_capwap_flags(self) -> Packet:
        p = self._clone()
        hdr = p.getlayer("CAPWAP Header")
        if hdr is None:
            raise ValueError("CAPWAP header invalid!")
        strategy = random.choice(["random", "invalid_combo", "boundary"])
        if strategy == "random":
            hdr.T = random.randint(0, 1)
            hdr.F = random.randint(0, 1)
            hdr.L = random.randint(0, 1)
            hdr.W = random.randint(0, 1)
            hdr.M = random.randint(0, 1)
            hdr.K = random.randint(0, 1)
            hdr.Flags = random.randint(0, 7)
        elif strategy == "invalid_combo":
            hdr.F = 0
            hdr.L = 1
            hdr.Flags = random.choice([1, 2, 3, 4, 5, 6, 7])
            hdr.T = random.randint(0, 1)
            hdr.W = random.randint(0, 1)
            hdr.M = random.randint(0, 1)
            hdr.K = random.randint(0, 1)
        elif strategy == "boundary":
            hdr.T = hdr.F = hdr.L = hdr.W = hdr.M = hdr.K = 1
            hdr.Flags = 7
        return p

    # --------------------- 暴力字符串级 fuzz 方法 ---------------------
    def brutal_random_bytes(self, pkt: Packet) -> Packet:
        p = self._clone()
        raw = bytearray(bytes(p))
        for _ in range(random.randint(1, max(1, len(raw)//10))):
            idx = random.randint(0, len(raw)-1)
            raw[idx] = random.getrandbits(8)
        return IP(raw) if raw[:1][0] >> 4 == 4 else p.__class__(raw)

    def brutal_insert_random_bytes(self, pkt: Packet) -> Packet:
        p = self._clone()
        raw = bytearray(bytes(p))
        for _ in range(random.randint(1, 5)):
            idx = random.randint(0, len(raw))
            raw[idx:idx] = bytes([random.getrandbits(8) for _ in range(random.randint(1,5))])
        return IP(raw) if raw[:1][0] >> 4 == 4 else p.__class__(raw)

    def brutal_delete_random_bytes(self, pkt: Packet) -> Packet:
        p = self._clone()
        raw = bytearray(bytes(p))
        for _ in range(random.randint(1, 5)):
            if len(raw) == 0:
                break
            idx = random.randint(0, len(raw)-1)
            del raw[idx]
        return IP(raw) if raw[:1][0] >> 4 == 4 and len(raw)>0 else p.__class__(raw)

    def brutal_shuffle_bytes(self, pkt: Packet) -> Packet:
        p = self._clone()
        raw = bytearray(bytes(p))
        random.shuffle(raw)
        return IP(raw) if raw[:1][0] >> 4 == 4 else p.__class__(raw)

    def brutal_duplicate_segments(self, pkt: Packet) -> Packet:
        p = self._clone()
        raw = bytearray(bytes(p))
        if len(raw) < 2:
            return p
        start = random.randint(0, len(raw)//2)
        end = random.randint(start+1, len(raw))
        segment = raw[start:end]
        idx = random.randint(0, len(raw))
        raw[idx:idx] = segment
        return IP(raw) if raw[:1][0] >> 4 == 4 else p.__class__(raw)

    def brutal_reverse_segment(self, pkt: Packet) -> Packet:
        p = self._clone()
        raw = bytearray(bytes(p))
        if len(raw) < 2:
            return p
        start = random.randint(0, len(raw)-2)
        end = random.randint(start+1, len(raw))
        raw[start:end] = reversed(raw[start:end])
        return IP(raw) if raw[:1][0] >> 4 == 4 else p.__class__(raw)