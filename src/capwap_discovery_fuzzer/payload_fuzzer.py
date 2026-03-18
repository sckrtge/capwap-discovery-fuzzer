from capwap_discovery_fuzzer.request_creater import *
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
        """
        专门模糊测试 CAPWAP 头部的所有标志位字段
        包括：T, F, L, W, M, K, Flags
        测试各种组合：随机值、边界值、非法组合
        """
        p = self._clone()
        hdr = p.getlayer("CAPWAP Header")
        if hdr is None:
            raise ValueError("CAPWAP header invalid!")
        
        # 随机选择测试策略：完全随机或生成特定无效组合
        strategy = random.choice(["random", "invalid_combo", "boundary"])
        
        if strategy == "random":
            # 完全随机设置所有标志位
            hdr.T = random.randint(0, 1)  # 载荷类型标志
            hdr.F = random.randint(0, 1)  # 分片标志
            hdr.L = random.randint(0, 1)  # 最后分片标志
            hdr.W = random.randint(0, 1)  # 无线专有信息标志
            hdr.M = random.randint(0, 1)  # Radio MAC标志
            hdr.K = random.randint(0, 1)  # 保活标志
            hdr.Flags = random.randint(0, 7)  # 保留标志位 (3位)
            
        elif strategy == "invalid_combo":
            # 生成特定的无效组合
            # 1. F=0 但 L=1（无效：L仅在F=1时有效）
            hdr.F = 0
            hdr.L = 1
            # 2. 设置保留标志位为非零值
            hdr.Flags = random.choice([1, 2, 3, 4, 5, 6, 7])
            # 3. 随机设置其他标志位
            hdr.T = random.randint(0, 1)
            hdr.W = random.randint(0, 1)
            hdr.M = random.randint(0, 1)
            hdr.K = random.randint(0, 1)
            
        elif strategy == "boundary":
            # 边界值测试
            # 将所有标志位设置为最大值（1位标志设为1，3位标志设为7）
            hdr.T = 1
            hdr.F = 1
            hdr.L = 1
            hdr.W = 1
            hdr.M = 1
            hdr.K = 1
            hdr.Flags = 7  # 二进制111
        
        # 额外测试：当标志位设置但无相应数据的情况
        # （这需要更复杂的处理，因为涉及可选字段的存在性）
        # 这里可以添加逻辑测试 W=1/M=1 但无相应数据字段的情况
        
        return p