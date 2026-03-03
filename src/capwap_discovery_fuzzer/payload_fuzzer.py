from capwap_discovery_fuzzer.payload_creater import *
from scapy.packet import Packet
from scapy.layers.inet import IP, UDP

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