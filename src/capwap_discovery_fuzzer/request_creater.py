from scapy.all import *
from capwap_discovery_fuzzer.utils import *
import logging
from typing import Optional

class CAPWAP_Header(Packet):
    name = "CAPWAP Header"
    fields_desc = [
        BitField("version", 0, 4),
        BitField("type", 0, 4),
        BitField("Hlen", 0, 5),
        BitField("Rid", 0, 5),
        BitField("WBID", 0, 5),
        BitField("T", 0, 1),
        BitField("F", 0, 1),
        BitField("L", 0, 1),
        BitField("W", 0, 1),
        BitField("M", 0, 1),
        BitField("K", 0, 1),
        BitField("Flags", 0, 3),
        BitField("FragmentID", 0, 16),
        BitField("FragmentOffset", 0, 13),
        BitField("Rsvd", 0, 3),
    ]

class Control_Header(Packet):
    name = "Control Header"
    fields_desc = [
        BitField("MsgType", 0, 32),
        BitField("SeqNum", 0, 8),
        BitField("MsgElemsLen", 0, 16),
        BitField("Flags", 0, 8),
    ]

# ----------------- Request Classes -----------------
class MessageElement(Packet):
    name = "Message Element"
    fields_desc = [
        BitField("Type", 0, 16),
        BitField("Length", 0, 16),
        StrField("Value", b"")
    ]

class MessageElement_Valid(Packet):
    name = "Message Element Valid"
    fields_desc = [
        BitField("Type", 0, 16),
        BitField("Length", 0, 16),
        StrLenField("Value", b"", length_from=lambda pkt: pkt.Length)
    ]

# ----------------- Existing Sub-Element Classes -----------------
class WTPBoardData(Packet):
    name = "WTP Board Data"
    fields_desc = [
        BitField("VendorID", 0, 32),
    ]

class BoardDataSubElement(Packet):
    name = "Board Data Sub-Element"
    fields_desc = [
        BitField("Type", 0, 16),
        BitField("Length", 0, 16),
        StrField("Value", b"")
    ]

class WTPDescriptor(Packet):
    name = "WTP Descriptor"
    fields_desc = [
        BitField("MaxRadio", 0, 8),
        BitField("Radioinuse", 0, 8),
        BitField("NumEncrypt", 0, 8),
    ]

class EncryptionSubElement(Packet):
    name = "Encryption Sub-Element"
    fields_desc = [
        BitField("Resvd", 0, 3),
        BitField("WBID", 0, 5),
        BitField("EncryptionCapabilities", 0, 16)
    ]

class DescriptorSubElement(Packet):
    name = "Descriptor Sub-Element"
    fields_desc = [
        BitField("VendorIdentifier", 0, 32),
        BitField("Type", 0, 16),
        BitField("Length", 0, 16),
        StrField("Data", b"")
    ]

# ----------------- Payload Creator -----------------
class Payload_Creator:
    """
    CAPWAP Discovery Request payload generator with controllable RNG.
    """
    def __init__(self, rng: Optional[random.Random] = None):
        self.rng = rng or random.Random()

    def create_capwap_header(self, valid: bool = True):
        return CAPWAP_Header(version=0, type=0, Hlen=2, Rid=0, WBID=1,
                             T=0, F=0, L=0, W=0, M=0, K=0, Flags=0,
                             FragmentID=0, FragmentOffset=0, Rsvd=0)

    def create_control_header(self, length: int, valid: bool = True):
        return Control_Header(MsgType=1, SeqNum=0, MsgElemsLen=length, Flags=0)

    def create_board_data(self, type: int):
        length = 4 if type in (0,1,4) else 0
        value = random_bytes(length, b'\x00', rng=self.rng)
        return BoardDataSubElement(Type=type, Length=length, Value=value)

    def create_descriptor_sub_element(self, type: int):
        return DescriptorSubElement(
            VendorIdentifier=0,
            Type=type,
            Length=4,
            Data=random_bytes(4, b'\x00', rng=self.rng)
        )

    def create_message_element(self, type: Optional[int] = None, valid: bool = False):
        VALID_TYPE = (20, 38, 39, 41, 44, 52, 37)
        rng = self.rng
        if type is None:
            type = rng.choice(VALID_TYPE) if valid else rng.randint(0, 0xFFFF)
        length = rng.randint(1,50)
        value = random_bytes(length, rng=rng)

        if valid:
            if type == 20: length, value = 1, b"\x02"
            elif type == 38:
                value = WTPBoardData(VendorID=1)/self.create_board_data(0)/self.create_board_data(1)
                length = len(value)
            elif type == 39:
                value = WTPDescriptor(MaxRadio=1, Radioinuse=0, NumEncrypt=1)/EncryptionSubElement(Resvd=0, WBID=1, EncryptionCapabilities=0)
                for i in range(3):
                    value = value/self.create_descriptor_sub_element(i)
                length = len(value)
            elif type in (41,44):
                length = 1
                value = random_bytes(length, b"\x00", rng=rng)
            elif type == 52:
                length = rng.randint(1,50)
                value = random_bytes(length, b"\x00", rng=rng)
            elif type == 37:
                length = rng.randint(7,50)
                value = random_bytes(length, b"\x00", rng=rng)
        return MessageElement(Type=type, Length=length, Value=value)

    def create_discovery_request(self, valid: bool = False):
        capwap_header = self.create_capwap_header(valid=valid)
        elements = []
        if valid:
            for t in (20,38,39,41,44):
                elements.append(self.create_message_element(type=t, valid=True))
        else:
            for _ in range(self.rng.randint(1,5)):
                elements.append(self.create_message_element(valid=False))
        message_elements = elements[0]
        for elem in elements[1:]:
            message_elements = message_elements/elem
        control_header = self.create_control_header(len(message_elements)+3, valid=valid)
        return capwap_header/control_header/message_elements

def parse_discovery_request(raw: bytes) -> Packet:
    bind_layers(CAPWAP_Header, Control_Header)
    bind_layers(Control_Header, MessageElement_Valid)
    bind_layers(MessageElement_Valid, MessageElement_Valid)
    try:
        pkt = CAPWAP_Header(raw)
        return pkt
    finally:
        split_layers(CAPWAP_Header, Control_Header)
        split_layers(Control_Header, MessageElement_Valid)
        split_layers(MessageElement_Valid, MessageElement_Valid)