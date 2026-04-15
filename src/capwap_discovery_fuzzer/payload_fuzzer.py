from capwap_discovery_fuzzer.request_creater import *
from scapy.packet import Packet
from scapy.layers.inet import IP, UDP
import random


class Payload_Fuzzer:
    def __init__(self, base_pkt: Packet):
        self.base = base_pkt

    def _clone(self, pkt: Packet | None = None) -> Packet:
        """
        Clone the given packet (or self.base if None), clearing IP/UDP length
        and checksum fields so Scapy recalculates them on send.
        克隆数据包（若未指定则克隆 base），清除 IP/UDP 长度和校验和以便 Scapy 重新计算。
        """
        src = pkt if pkt is not None else self.base
        p = src.copy()
        if IP in p:
            p[IP].len = None
        if UDP in p:
            p[UDP].len = None
            p[UDP].chksum = None
        return p

    def _iter_message_elements(self, pkt: Packet) -> list[Packet]:
        """
        Walk the packet layer chain and collect all MessageElement layers.
        遍历报文层链，收集所有 MessageElement 层，返回列表。
        """
        elems = []
        i = 0
        while True:
            elem = pkt.getlayer(MessageElement, i)
            if elem is None:
                break
            elems.append(elem)
            i += 1
        return elems

    # =====================================================================
    # Structured ("safe") fuzz methods — operate on named Scapy fields
    # 结构化（"安全"）变异方法 —— 针对具名 Scapy 字段进行变异
    # =====================================================================

    def fuzz_capwap_header(self, pkt: Packet | None = None) -> Packet:
        """
        Randomise version, Hlen and FragmentOffset fields in the CAPWAP Header.
        These fields control basic framing; invalid values may confuse AC parsers.

        随机化 CAPWAP Header 中的 version、Hlen、FragmentOffset 字段。
        这些字段控制基本帧格式，非法值可能使 AC 解析器产生混淆。
        """
        p = self._clone(pkt)
        hdr = p.getlayer("CAPWAP Header")
        if hdr is None:
            raise ValueError("CAPWAP header invalid!")
        hdr.version = random.randint(0, 3)
        hdr.Hlen = random.randint(0, 31)
        hdr.FragmentOffset = random.randint(0, 0x1FFF)
        return p

    def fuzz_capwap_wbid(self, pkt: Packet | None = None) -> Packet:
        """
        Randomise the WBID (Wireless Binding ID) field in the CAPWAP Header.
        RFC 5415 defines WBID=1 for 802.11; values like 0, 2, 31 are invalid
        and test how the AC handles unknown wireless binding types.

        随机化 CAPWAP Header 中的 WBID（无线绑定标识）字段。
        RFC 5415 规定 WBID=1 代表 802.11；0、2、31 等为无效值，
        用于测试 AC 对未知无线绑定类型的处理能力。
        """
        p = self._clone(pkt)
        hdr = p.getlayer("CAPWAP Header")
        if hdr is None:
            raise ValueError("CAPWAP header invalid!")
        hdr.WBID = random.choice([0, 2, 3, 15, 31, random.randint(0, 31)])
        return p

    def fuzz_capwap_flags(self, pkt: Packet | None = None) -> Packet:
        """
        Mutate the single-bit flag fields (T/F/L/W/M/K) and the 3-bit Flags
        field in the CAPWAP Header using one of three strategies:
          - random:        all flags set to independent random values
          - invalid_combo: F=0 with L=1 (Last Fragment without Fragment flag)
          - all_set:       every flag set to its maximum value

        使用三种策略之一变异 CAPWAP Header 的单比特标志位（T/F/L/W/M/K）和
        3-bit Flags 字段：
          - random:        所有标志位独立随机赋值
          - invalid_combo: F=0 且 L=1（无分片标志但置 Last Fragment），非法组合
          - all_set:       所有标志位置最大值
        """
        p = self._clone(pkt)
        hdr = p.getlayer("CAPWAP Header")
        if hdr is None:
            raise ValueError("CAPWAP header invalid!")
        strategy = random.choice(["random", "invalid_combo", "all_set"])
        if strategy == "random":
            hdr.T = random.randint(0, 1)
            hdr.F = random.randint(0, 1)
            hdr.L = random.randint(0, 1)
            hdr.W = random.randint(0, 1)
            hdr.M = random.randint(0, 1)
            hdr.K = random.randint(0, 1)
            hdr.Flags = random.randint(0, 7)
        elif strategy == "invalid_combo":
            # F=0 (not a fragment) but L=1 (last fragment) — contradictory
            # F=0（非分片包）却置 L=1（最后一片）—— 矛盾组合
            hdr.F = 0
            hdr.L = 1
            hdr.T = random.randint(0, 1)
            hdr.W = random.randint(0, 1)
            hdr.M = random.randint(0, 1)
            hdr.K = random.randint(0, 1)
            hdr.Flags = random.randint(0, 7)
        elif strategy == "all_set":
            hdr.T = hdr.F = hdr.L = hdr.W = hdr.M = hdr.K = 1
            hdr.Flags = 7
        return p

    def fuzz_capwap_fragment(self, pkt: Packet | None = None) -> Packet:
        """
        Set the Fragment flag (F=1) and randomise FragmentID and FragmentOffset
        to simulate a malformed or unexpected fragment packet.
        The AC should either reassemble or reject the fragment gracefully.

        置分片标志 F=1，并随机化 FragmentID 和 FragmentOffset，
        模拟畸形或非预期的分片报文。
        AC 应能正确拒绝或处理此类分片。
        """
        p = self._clone(pkt)
        hdr = p.getlayer("CAPWAP Header")
        if hdr is None:
            raise ValueError("CAPWAP header invalid!")
        hdr.F = 1
        hdr.L = random.randint(0, 1)
        hdr.FragmentID = random.randint(0, 0xFFFF)
        hdr.FragmentOffset = random.randint(0, 0x1FFF)
        return p

    def fuzz_ctrl_msgtype(self, pkt: Packet | None = None) -> Packet:
        """
        Mutate the MsgType field in the Control Header.
        MsgType=1 is the valid Discovery Request; this method replaces it with
        an invalid or boundary value drawn from a curated set, testing whether
        the AC rejects unexpected message types cleanly.

        变异 Control Header 的 MsgType 字段。
        合法的 Discovery Request 使用 MsgType=1；本方法将其替换为
        精心挑选的无效值或边界值，测试 AC 对非预期消息类型的拒绝行为。
        """
        p = self._clone(pkt)
        ctrl = p.getlayer("Control Header")
        if ctrl is None:
            raise ValueError("Control header invalid!")
        invalid_types = [0, 2, 3, 0xFF, 0x1000, 0xFFFF, random.randint(4, 0xFFFE)]
        ctrl.MsgType = random.choice(invalid_types)
        return p

    def fuzz_ctrl_seqnum(self, pkt: Packet | None = None) -> Packet:
        """
        Randomise the SeqNum field in the Control Header.
        Some AC implementations track sequence numbers; boundary values (0, 255)
        and wraparound behaviour may expose edge cases.

        随机化 Control Header 的 SeqNum 字段。
        部分 AC 实现会追踪序列号；边界值（0、255）及回绕行为可能暴露边界问题。
        """
        p = self._clone(pkt)
        ctrl = p.getlayer("Control Header")
        if ctrl is None:
            raise ValueError("Control header invalid!")
        ctrl.SeqNum = random.choice([0, 1, 127, 128, 255, random.randint(0, 255)])
        return p

    def fuzz_ctrl_msgelemslen(self, pkt: Packet | None = None) -> Packet:
        """
        Corrupt the MsgElemsLen field in the Control Header.
        This field declares the total length of the message elements section;
        setting it to 0, 1 or 0xFFFF causes a length/content mismatch that
        tests the AC's boundary checking.

        篡改 Control Header 的 MsgElemsLen 字段。
        该字段声明消息元素区域的总长度；置为 0、1 或 0xFFFF 会造成
        长度与实际内容不一致，测试 AC 的边界检查能力。
        """
        p = self._clone(pkt)
        ctrl = p.getlayer("Control Header")
        if ctrl is None:
            raise ValueError("Control header invalid!")
        ctrl.MsgElemsLen = random.choice([0, 1, 0xFFFF, random.randint(2, 0xFFFE)])
        return p

    def fuzz_ctrl_flags(self, pkt: Packet | None = None) -> Packet:
        """
        Randomise the Flags field in the Control Header.
        RFC 5415 specifies this field must be zero; non-zero values are
        reserved/undefined and should be ignored or rejected by the AC.

        随机化 Control Header 的 Flags 字段。
        RFC 5415 规定该字段必须为零；非零值属于保留/未定义行为，
        AC 应忽略或拒绝处理。
        """
        p = self._clone(pkt)
        ctrl = p.getlayer("Control Header")
        if ctrl is None:
            raise ValueError("Control header invalid!")
        ctrl.Flags = random.randint(1, 0xFF)
        return p

    def fuzz_elem_type(self, pkt: Packet | None = None) -> Packet:
        """
        Replace the Type field of a randomly chosen MessageElement with an
        arbitrary value in [0, 512].  Unknown element types test the AC's
        unknown-TLV handling (skip-unknown vs. reject).

        将随机选中的 MessageElement 的 Type 字段替换为 [0, 512] 中的任意值。
        未知元素类型用于测试 AC 对未知 TLV 的处理策略（跳过还是拒绝）。
        """
        p = self._clone(pkt)
        elems = self._iter_message_elements(p)
        if not elems:
            return p
        target = random.choice(elems)
        target.Type = random.randint(0, 512)
        return p

    def fuzz_elem_length(self, pkt: Packet | None = None) -> Packet:
        """
        Replace the Length field of a randomly chosen MessageElement with a
        random value in [0, 512] without changing its Value bytes, creating a
        length/content mismatch.

        将随机选中的 MessageElement 的 Length 字段替换为 [0, 512] 中的随机值，
        同时保持 Value 字节不变，制造长度与内容不一致的畸形报文。
        """
        p = self._clone(pkt)
        elems = self._iter_message_elements(p)
        if not elems:
            return p
        target = random.choice(elems)
        target.Length = random.randint(0, 512)
        return p

    def fuzz_elem_length_zero(self, pkt: Packet | None = None) -> Packet:
        """
        Set the Length field of a randomly chosen MessageElement to 0 while
        leaving its Value bytes intact.  A zero-length element with non-empty
        value bytes is a targeted boundary case that some parsers handle poorly.

        将随机选中的 MessageElement 的 Length 字段置为 0，同时保留 Value 字节。
        长度为零但内容非空是一个定向边界用例，部分解析器对此处理不当。
        """
        p = self._clone(pkt)
        elems = self._iter_message_elements(p)
        if not elems:
            return p
        target = random.choice(elems)
        target.Length = 0
        return p

    def fuzz_elem_length_overflow(self, pkt: Packet | None = None) -> Packet:
        """
        Set the Length field of a randomly chosen MessageElement to 0xFFFF,
        far exceeding the actual Value size.  This tests whether the AC performs
        bounds checking before reading element data (potential out-of-bounds read).

        将随机选中的 MessageElement 的 Length 字段置为 0xFFFF，
        远超实际 Value 大小，测试 AC 在读取元素数据前是否做边界检查
        （潜在越界读场景）。
        """
        p = self._clone(pkt)
        elems = self._iter_message_elements(p)
        if not elems:
            return p
        target = random.choice(elems)
        target.Length = 0xFFFF
        return p

    def fuzz_elem_value(self, pkt: Packet | None = None) -> Packet:
        """
        Replace the Value (and matching Length) of a randomly chosen
        MessageElement with random bytes of random length [0, 256].
        This corrupts element content while keeping the TLV structure intact.

        将随机选中的 MessageElement 的 Value 替换为长度随机（[0, 256]）的随机字节，
        并同步更新 Length 字段。在保持 TLV 结构的前提下破坏元素内容。
        """
        p = self._clone(pkt)
        elems = self._iter_message_elements(p)
        if not elems:
            return p
        target = random.choice(elems)
        new_len = random.randint(0, 256)
        target.Value = bytes(random.getrandbits(8) for _ in range(new_len))
        target.Length = new_len
        return p

    def fuzz_elem_value_by_type(self, msg_type: int, pkt: Packet | None = None) -> Packet:
        """
        Find the first MessageElement whose Type matches msg_type and replace
        its Value with random bytes.  Used to target mandatory elements such as
        WTP Board Data (38) and WTP Descriptor (39).

        查找 Type 匹配 msg_type 的第一个 MessageElement，将其 Value 替换为
        随机字节。用于定向变异必要元素，如 WTP Board Data（38）、
        WTP Descriptor（39）。
        """
        p = self._clone(pkt)
        elems = self._iter_message_elements(p)
        for elem in elems:
            if elem.Type == msg_type:
                new_len = random.randint(0, 256)
                elem.Value = bytes(random.getrandbits(8) for _ in range(new_len))
                elem.Length = new_len
                break
        return p

    def fuzz_elem_insert_unknown(self, pkt: Packet | None = None) -> Packet:
        """
        Insert a new MessageElement with an unknown Type (drawn from the
        reserved/vendor range: 0x8000–0xFFFF) at a random position in the
        element list.  Tests the AC's skip-unknown-TLV behaviour.

        在元素列表的随机位置插入一个 Type 为未知值（保留/厂商范围：
        0x8000–0xFFFF）的 MessageElement，测试 AC 跳过未知 TLV 的能力。
        """
        p = self._clone(pkt)
        elems = self._iter_message_elements(p)
        unknown_type = random.randint(0x8000, 0xFFFF)
        data_len = random.randint(0, 32)
        unknown_elem = MessageElement(
            Type=unknown_type,
            Length=data_len,
            Value=bytes(random.getrandbits(8) for _ in range(data_len))
        )
        if not elems:
            # No existing elements: just append after Control Header
            # 无现有元素：直接追加在 Control Header 之后
            ctrl = p.getlayer("Control Header")
            if ctrl:
                ctrl.add_payload(unknown_elem)
            return p
        insert_before = random.choice(elems)
        # Walk the layer chain to find the parent of insert_before
        # 遍历层链，找到 insert_before 的父层
        cur = p
        while cur.payload is not None and cur.payload is not insert_before:
            cur = cur.payload
        unknown_elem.add_payload(insert_before)
        cur.remove_payload()
        cur.add_payload(unknown_elem)
        return p

    def fuzz_elem_drop(self, pkt: Packet | None = None) -> Packet:
        """
        Remove a randomly chosen MessageElement from the element chain.
        If the dropped element happens to be mandatory (e.g. Type 20/38/39),
        this tests AC behaviour when required TLVs are absent.

        从元素链中随机删除一个 MessageElement。
        若被删除的恰好是必要元素（如 Type 20/38/39），
        则可测试 AC 在缺少必要 TLV 时的行为。
        """
        p = self._clone(pkt)
        elems = self._iter_message_elements(p)
        if len(elems) < 2:
            return p
        target = random.choice(elems)
        # Find the layer immediately before target and re-link around it
        # 找到 target 的前一层，绕过 target 重新链接
        cur = p
        while cur.payload is not None and cur.payload is not target:
            cur = cur.payload
        if cur.payload is target:
            cur.remove_payload()
            if target.payload:
                cur.add_payload(target.payload)
        return p

    def fuzz_elem_drop_required(self, pkt: Packet | None = None) -> Packet:
        """
        Intentionally remove one of the mandatory MessageElement types
        (Discovery Type=20, WTP Board Data=38, WTP Descriptor=39) chosen at
        random.  This is a targeted test for missing-required-element handling.

        有意删除必要 MessageElement 类型（Discovery Type=20、WTP Board Data=38、
        WTP Descriptor=39）中随机选中的一个，定向测试 AC 缺少必要元素时的处理逻辑。
        """
        REQUIRED_TYPES = [20, 38, 39]
        p = self._clone(pkt)
        elems = self._iter_message_elements(p)
        candidates = [e for e in elems if e.Type in REQUIRED_TYPES]
        if not candidates:
            return p
        target = random.choice(candidates)
        cur = p
        while cur.payload is not None and cur.payload is not target:
            cur = cur.payload
        if cur.payload is target:
            cur.remove_payload()
            if target.payload:
                cur.add_payload(target.payload)
        return p

    def fuzz_elem_duplicate(self, pkt: Packet | None = None) -> Packet:
        """
        Duplicate a randomly chosen MessageElement and append the copy
        immediately after the original.  Duplicate TLVs are forbidden by
        RFC 5415 and may expose double-processing or confusion bugs.

        复制随机选中的 MessageElement 并将副本追加在原元素之后。
        RFC 5415 禁止重复 TLV，此操作可能暴露重复处理或解析混淆 bug。
        """
        p = self._clone(pkt)
        elems = self._iter_message_elements(p)
        if not elems:
            return p
        target = random.choice(elems)
        dup = target.copy()
        target.add_payload(dup)
        return p

    def fuzz_elem_order_shuffle(self, pkt: Packet | None = None) -> Packet:
        """
        Randomly reorder all MessageElements in the element chain.
        RFC 5415 does not mandate element ordering; however, some AC
        implementations assume a fixed order and may misparse shuffled packets.

        随机打乱元素链中所有 MessageElement 的顺序。
        RFC 5415 不强制规定元素顺序，但部分 AC 实现假设固定顺序，
        乱序报文可能导致解析错误。
        """
        p = self._clone(pkt)
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

    # =====================================================================
    # Byte-level ("brutal") fuzz methods — operate on raw bytes
    # 字节级（"暴力"）变异方法 —— 直接操作原始字节
    # =====================================================================

    def _pkt_to_raw(self, pkt: Packet) -> bytearray:
        """
        Serialise a Scapy packet to a mutable bytearray.
        将 Scapy 数据包序列化为可变 bytearray。
        """
        return bytearray(bytes(pkt))

    def _raw_to_pkt(self, raw: bytearray, original: Packet) -> Packet:
        """
        Deserialise raw bytes back to a Scapy packet.  Falls back to the
        original packet on empty input.
        将原始字节反序列化为 Scapy 数据包；输入为空时回退到原始包。
        """
        if len(raw) == 0:
            return original
        return IP(bytes(raw)) if raw[0] >> 4 == 4 else original.__class__(bytes(raw))

    def brutal_random_bytes(self, pkt: Packet) -> Packet:
        """
        Overwrite up to ~10% of bytes at random positions with random values.
        Simulates bit-error-style corruption scattered across the entire packet.

        在随机位置覆写最多约 10% 的字节为随机值。
        模拟分散在整个报文中的位错误式随机损坏。
        """
        raw = self._pkt_to_raw(pkt)
        for _ in range(random.randint(1, max(1, len(raw) // 10))):
            idx = random.randint(0, len(raw) - 1)
            raw[idx] = random.getrandbits(8)
        return self._raw_to_pkt(raw, pkt)

    def brutal_insert_random_bytes(self, pkt: Packet) -> Packet:
        """
        Insert 1–5 bursts of 1–5 random bytes at random positions.
        Increases packet size and shifts all subsequent field offsets,
        invalidating any length-based parsing.

        在随机位置插入 1–5 段、每段 1–5 字节的随机内容。
        增大报文长度并偏移后续所有字段的偏移量，
        使基于长度的解析失效。
        """
        raw = self._pkt_to_raw(pkt)
        for _ in range(random.randint(1, 5)):
            idx = random.randint(0, len(raw))
            raw[idx:idx] = bytes([random.getrandbits(8) for _ in range(random.randint(1, 5))])
        return self._raw_to_pkt(raw, pkt)

    def brutal_delete_random_bytes(self, pkt: Packet) -> Packet:
        """
        Delete 1–5 individual bytes at random positions.
        Shrinks the packet and shifts field offsets, causing misalignment
        in fixed-offset parsers.

        在随机位置删除 1–5 个字节。
        缩短报文并偏移字段偏移量，导致固定偏移解析器对齐错误。
        """
        raw = self._pkt_to_raw(pkt)
        for _ in range(random.randint(1, 5)):
            if len(raw) == 0:
                break
            idx = random.randint(0, len(raw) - 1)
            del raw[idx]
        return self._raw_to_pkt(raw, pkt)

    def brutal_shuffle_bytes(self, pkt: Packet) -> Packet:
        """
        Randomly shuffle ALL bytes in the packet.
        Produces maximally chaotic input; useful as a sanity check for
        crash-on-garbage robustness.

        将报文中所有字节完全随机乱序。
        产生最大程度的混乱输入，可用作 AC 处理垃圾数据时健壮性的极端测试。
        """
        raw = self._pkt_to_raw(pkt)
        random.shuffle(raw)
        return self._raw_to_pkt(raw, pkt)

    def brutal_duplicate_segment(self, pkt: Packet) -> Packet:
        """
        Copy a random contiguous segment of bytes and insert the copy at a
        random offset.  Increases packet size and may create phantom TLVs or
        corrupt length fields depending on where the segment lands.

        复制一段连续字节区间，并将副本插入到随机偏移处。
        增大报文尺寸，根据插入位置不同，可能产生幽灵 TLV 或破坏长度字段。
        """
        raw = self._pkt_to_raw(pkt)
        if len(raw) < 2:
            return pkt
        start = random.randint(0, len(raw) // 2)
        end = random.randint(start + 1, len(raw))
        segment = raw[start:end]
        idx = random.randint(0, len(raw))
        raw[idx:idx] = segment
        return self._raw_to_pkt(raw, pkt)

    def brutal_reverse_segment(self, pkt: Packet) -> Packet:
        """
        Reverse the byte order of a random contiguous segment.
        Inverts multi-byte field values (e.g. big-endian integers) within the
        chosen range without altering the overall packet length.

        将随机连续字节区间内的字节顺序反转。
        在不改变报文总长度的前提下，颠倒区间内多字节字段的字节序
        （如大端整数）。
        """
        raw = self._pkt_to_raw(pkt)
        if len(raw) < 2:
            return pkt
        start = random.randint(0, len(raw) - 2)
        end = random.randint(start + 1, len(raw))
        raw[start:end] = reversed(raw[start:end])
        return self._raw_to_pkt(raw, pkt)

    def brutal_bitflip(self, pkt: Packet) -> Packet:
        """
        Flip individual bits at 1–8 random byte positions using XOR with a
        random single-bit mask.  Finer-grained than whole-byte overwrite;
        closely resembles real transmission-error patterns.

        对 1–8 个随机字节位置用随机单比特掩码执行 XOR 位翻转。
        比整字节覆写更细粒度，更接近真实传输错误的表现形式。
        """
        raw = self._pkt_to_raw(pkt)
        if len(raw) == 0:
            return pkt
        for _ in range(random.randint(1, 8)):
            idx = random.randint(0, len(raw) - 1)
            bit = 1 << random.randint(0, 7)
            raw[idx] ^= bit
        return self._raw_to_pkt(raw, pkt)

    def brutal_zero_segment(self, pkt: Packet) -> Packet:
        """
        Fill a random contiguous segment with 0x00 bytes.
        Simulates memory-zeroing or field-omission scenarios without changing
        packet length.

        将随机连续字节区间全部填充为 0x00。
        在不改变报文长度的前提下，模拟内存清零或字段缺失场景。
        """
        raw = self._pkt_to_raw(pkt)
        if len(raw) < 2:
            return pkt
        start = random.randint(0, len(raw) - 1)
        end = random.randint(start + 1, len(raw))
        for i in range(start, end):
            raw[i] = 0x00
        return self._raw_to_pkt(raw, pkt)

    def brutal_fill_segment(self, pkt: Packet) -> Packet:
        """
        Fill a random contiguous segment with a single repeated byte value
        (e.g. 0xFF or 0xAA).  Tests boundary/sentinel-value handling without
        changing packet length.

        将随机连续字节区间全部填充为同一字节值（如 0xFF 或 0xAA）。
        在不改变报文长度的前提下，测试边界值/哨兵值的处理能力。
        """
        raw = self._pkt_to_raw(pkt)
        if len(raw) < 2:
            return pkt
        fill_byte = random.choice([0xFF, 0xAA, 0x55, 0x01, random.getrandbits(8)])
        start = random.randint(0, len(raw) - 1)
        end = random.randint(start + 1, len(raw))
        for i in range(start, end):
            raw[i] = fill_byte
        return self._raw_to_pkt(raw, pkt)

    def brutal_truncate(self, pkt: Packet) -> Packet:
        """
        Truncate the packet at a random offset, discarding all subsequent bytes.
        Tests the AC's handling of incomplete/short packets that arrive with
        fewer bytes than their length fields declare.

        从随机偏移处截断报文，丢弃其后的所有字节。
        测试 AC 处理不完整/过短报文的能力——实际字节数少于长度字段声明的值。
        """
        raw = self._pkt_to_raw(pkt)
        if len(raw) < 2:
            return pkt
        cut = random.randint(1, len(raw) - 1)
        return self._raw_to_pkt(raw[:cut], pkt)
