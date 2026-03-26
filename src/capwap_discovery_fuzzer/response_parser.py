# response_parser.py
from scapy.all import *
from typing import Dict, Any, Optional
from .errors import *
from .request_creater import CAPWAP_Header, Control_Header  # 从 request_creater 导入

class ResponseType:
    VALID = "valid"
    ERROR = "error"
    NO_RESPONSE = "timeout"
    UNKNOWN = "unknown"

    @staticmethod
    def all_types():
        return [ResponseType.VALID, ResponseType.ERROR, ResponseType.NO_RESPONSE, ResponseType.UNKNOWN]

# --------------------- Scapy 层定义 ---------------------
class Response_MessageElement_Valid(Packet):
    name = "Message Element"
    fields_desc = [
        BitField("Type", 0, 16),
        BitField("Length", 0, 16),
        StrLenField("Value", b"", length_from=lambda pkt: pkt.Length)
    ]

# --------------------- ResponseParser ---------------------
class ResponseParser:
    """Parse and classify CAPWAP Discovery Responses."""

    def __init__(self):
        self.stats = {rtype: 0 for rtype in ResponseType.all_types()}
        self.total_responses = 0
        self._bind_layers()

    def _bind_layers(self):
        bind_layers(CAPWAP_Header, Control_Header)
        bind_layers(Control_Header, Response_MessageElement_Valid)
        bind_layers(Response_MessageElement_Valid, Response_MessageElement_Valid)

    def _unbind_layers(self):
        split_layers(CAPWAP_Header, Control_Header)
        split_layers(Control_Header, Response_MessageElement_Valid)
        split_layers(Response_MessageElement_Valid, Response_MessageElement_Valid)

    # 递归解析 Scapy 对象 -> 字典
    def scapy_to_dict(self, pkt) -> dict:
        if not pkt:
            return None
        d = {"layer": pkt.name, "fields": dict(pkt.fields)}
        if pkt.payload and not isinstance(pkt.payload, NoPayload):
            d["payload"] = self.scapy_to_dict(pkt.payload)
        return d

    # 递归收集所有 Message Element Type
    def _collect_types(self, pkt_elem) -> set:
        types = set()
        while pkt_elem:
            if isinstance(pkt_elem, Response_MessageElement_Valid):
                types.add(pkt_elem.Type)
            pkt_elem = pkt_elem.payload if hasattr(pkt_elem, "payload") else None
        return types

    def parse_response(self, raw_data: bytes, request_info: Optional[Dict] = None) -> Dict[str, Any]:
        request_info = request_info or {}
        if not raw_data:
            raise NoResponseError("No response received", request_info.get("ac_ip"), request_info.get("ac_port"))

        result: Dict[str, Any] = {
            "scapy_pkt": None,        # 字典化的完整包
            "scapy_pkt_obj": None,    # Scapy 对象
            "hex_dump": raw_data.hex(),
            "request_info": request_info,
            "response_type": ResponseType.UNKNOWN,
            "error_type": None
        }

        try:
            self._bind_layers()

            # 去掉 IP/UDP 首部
            if raw_data[:20] and raw_data[0] >> 4 == 4:
                ip_len = (raw_data[0] & 0x0F) * 4
                raw_data = raw_data[ip_len + 8:]  # UDP header固定8字节

            pkt = CAPWAP_Header(raw_data)

            # 完整 Scapy 对象
            result["scapy_pkt_obj"] = pkt
            result["scapy_pkt"] = self.scapy_to_dict(pkt)

            # 基本检查
            if not pkt.haslayer(CAPWAP_Header):
                raise MissingCapwapHeaderError("CAPWAP header missing", raw_data)
            if not pkt.haslayer(Control_Header):
                raise MissingControlHeaderError("Control header missing", raw_data)
            if pkt[Control_Header].MsgType != 2:
                raise UnexpectedMsgTypeError(f"Unexpected MsgType {pkt[Control_Header].MsgType}", raw_data)

            # 必要元素检查：Type 必须都出现 1,4,10
            elem = pkt[Control_Header].payload
            present_types = self._collect_types(elem)
            required_types = {1, 4, 10}
            if not required_types.issubset(present_types):
                raise MissingRequiredElementError(
                    f"Required message elements missing. Present: {present_types}, Required: {required_types}",
                    raw_data
                )

            result["response_type"] = ResponseType.VALID
            self.stats[ResponseType.VALID] += 1

        except CAPWAPFuzzerError as e:
            result["response_type"] = ResponseType.ERROR
            result["error_type"] = type(e).__name__
        except Exception:
            result["response_type"] = ResponseType.ERROR
            result["error_type"] = "UnknownError"
        finally:
            self._unbind_layers()
            self.total_responses += 1
            return result