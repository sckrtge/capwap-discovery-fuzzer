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

    def fuzz_any_tlv_length(self) -> Packet:
        """
        随机选择一个 TLV，破坏其 Length 字段
        """
        p = self._clone()

        elems = self._iter_message_elements(p)
        if not elems:
            return p

        target = random.choice(elems)
        target.Length = random.randint(0, 512)

        return p

    def fuzz_any_tlv_value(self) -> Packet:
        """
        随机选择一个 TLV，破坏其 Value 内容，并同步 Length
        """
        p = self._clone()

        elems = self._iter_message_elements(p)
        if not elems:
            return p

        target = random.choice(elems)
        new_len = random.randint(0, 256)
        target.Value = bytes(random.getrandbits(8) for _ in range(new_len))
        target.Length = new_len

        return p

    def fuzz_specific_tlv(self, tlv_type: int) -> Packet:
        """
        定向 fuzz 指定 Type 的 TLV
        """
        p = self._clone()

        elems = self._iter_message_elements(p)
        for elem in elems:
            if elem.Type == tlv_type:
                new_len = random.randint(0, 256)
                elem.Value = bytes(random.getrandbits(8) for _ in range(new_len))
                elem.Length = new_len
                break

        return p

    def fuzz_duplicate_tlv(self) -> Packet:
        """
        复制一个 TLV，并插入到 TLV 链中（制造重复 TLV）
        """
        p = self._clone()

        elems = self._iter_message_elements(p)
        if not elems:
            return p

        target = random.choice(elems)
        dup = target.copy()
        target.add_payload(dup)

        return p

    def fuzz_drop_last_tlv(self) -> Packet:
        """
        删除最后一个 TLV
        """
        p = self._clone()

        elems = self._iter_message_elements(p)
        if len(elems) < 2:
            return p

        # 删除最后一个 TLV
        elems[-2].remove_payload()

        return p
    def fuzz_shuffle_tlvs(self) -> Packet:
        """
        打乱 Message Element 的顺序
        """
        p = self._clone()

        elems = self._iter_message_elements(p)
        if len(elems) < 2:
            return p

        # 找到 TLV 起始前的层（Control Header）
        first = elems[0]
        parent = p
        while parent.payload is not first:
            parent = parent.payload

        # 打乱 TLV 顺序
        random.shuffle(elems)

        # 重新构建 TLV 链
        new_chain = elems[0]
        cur = new_chain
        for e in elems[1:]:
            cur.add_payload(e)
            cur = e

        # 接回报文
        parent.remove_payload()
        parent.add_payload(new_chain)

        return p