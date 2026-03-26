from scapy.all import *
from typing import Dict, Any, Optional
from .errors import *
from .request_creater import CAPWAP_Header, Control_Header  # 直接导入，不重复定义

class ResponseType:
    VALID = "valid"
    ERROR = "error"
    NO_RESPONSE = "timeout"
    UNKNOWN = "unknown"

    @staticmethod
    def all_types():
        return [ResponseType.VALID, ResponseType.ERROR, ResponseType.NO_RESPONSE, ResponseType.UNKNOWN]

# --------------------- Response_MessageElement_Valid ---------------------
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

    def scapy_to_dict(self, pkt) -> dict:
        if not pkt:
            return None
        d = {"layer": pkt.name, "fields": dict(pkt.fields)}
        if pkt.payload and not isinstance(pkt.payload, NoPayload):
            d["payload"] = self.scapy_to_dict(pkt.payload)
        return d

    def _parse_elements(self, pkt) -> Optional[Packet]:
        elements_pkt = None
        current = pkt.payload if pkt.payload else None
        last_elem = None
        while current and isinstance(current, Response_MessageElement_Valid):
            if elements_pkt is None:
                elements_pkt = current
                last_elem = current
            else:
                last_elem = last_elem / current
            current = current.payload
        return elements_pkt

    def parse_response(self, raw_data: bytes, request_info: Optional[Dict] = None) -> Dict[str, Any]:
        request_info = request_info or {}
        if not raw_data:
            raise NoResponseError("No response received", request_info.get("ac_ip"), request_info.get("ac_port"))

        result: Dict[str, Any] = {
            "capwap_header": {},
            "control_header": {},
            "scapy_pkt": None,
            "scapy_pkt_obj": None,
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
            result["capwap_header"] = pkt[CAPWAP_Header].fields if pkt.haslayer(CAPWAP_Header) else {}
            result["control_header"] = pkt[Control_Header].fields if pkt.haslayer(Control_Header) else {}

            elements_pkt = self._parse_elements(pkt)
            full_pkt = pkt
            if elements_pkt:
                full_pkt = pkt / elements_pkt

            result["scapy_pkt_obj"] = full_pkt
            result["scapy_pkt"] = self.scapy_to_dict(full_pkt)

            # 分类逻辑
            if not result["capwap_header"]:
                raise MissingCapwapHeaderError("CAPWAP header missing", raw_data)
            if not result["control_header"]:
                raise MissingControlHeaderError("Control header missing", raw_data)
            if result["control_header"].get("MsgType") != 2:
                raise UnexpectedMsgTypeError(f"Unexpected MsgType {result['control_header'].get('MsgType')}", raw_data)

            # 必要元素检查：Type 必须包含 1, 4, 10
            required_types = {1, 4, 10}
            present_types = set()
            elem = elements_pkt
            while elem:
                present_types.add(elem.Type)
                elem = elem.payload if isinstance(elem.payload, Response_MessageElement_Valid) else None
            if not required_types.intersection(present_types):
                raise MissingRequiredElementError("Required message elements missing (need 1,4,10)", raw_data)

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