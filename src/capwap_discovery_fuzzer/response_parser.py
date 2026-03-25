from scapy.all import *
from scapy.all import bind_layers, split_layers, Packet
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from .request_creater import CAPWAP_Header, Control_Header, MessageElement_Valid
from .errors import *

class ResponseType:
    VALID = "valid"
    ERROR = "error"
    NO_RESPONSE = "timeout"
    UNKNOWN = "unknown"

    @staticmethod
    def all_types():
        return [ResponseType.VALID, ResponseType.ERROR, ResponseType.NO_RESPONSE, ResponseType.UNKNOWN]

class ResponseParser:
    """Parse and classify CAPWAP Discovery Responses."""

    def __init__(self):
        self.stats = {rtype: 0 for rtype in ResponseType.all_types()}
        self.total_responses = 0
        self._bind_layers()

    def _bind_layers(self):
        bind_layers(CAPWAP_Header, Control_Header)
        bind_layers(Control_Header, MessageElement_Valid)
        bind_layers(MessageElement_Valid, MessageElement_Valid)

    def _unbind_layers(self):
        split_layers(CAPWAP_Header, Control_Header)
        split_layers(Control_Header, MessageElement_Valid)
        split_layers(MessageElement_Valid, MessageElement_Valid)

    def parse_response(self, raw_data: bytes, request_info: Optional[Dict] = None) -> Dict[str, Any]:
        request_info = request_info or {}
        if not raw_data:
            raise NoResponseError("No response received", request_info.get("ac_ip"), request_info.get("ac_port"))

        result: Dict[str, Any] = {
            "capwap_header": {},
            "control_header": {},
            "message_elements": [],
            "hex_dump": raw_data.hex(),
            "request_info": request_info,
            "response_type": ResponseType.UNKNOWN,
            "error_type": None
        }

        try:
            self._bind_layers()
            # 去掉 IP/UDP 首部
            if raw_data[:20] and raw_data[0] >> 4 == 4:
                # 简单剥离 IPv4 + UDP
                ip_len = (raw_data[0] & 0x0F) * 4
                raw_data = raw_data[ip_len+8:]  # UDP header固定8字节

            pkt = CAPWAP_Header(raw_data)
            result["capwap_header"] = pkt[CAPWAP_Header].fields if pkt.haslayer(CAPWAP_Header) else {}
            result["control_header"] = pkt[Control_Header].fields if pkt.haslayer(Control_Header) else {}
            elements = []
            current = pkt
            while current:
                if isinstance(current, MessageElement_Valid):
                    elem = current
                    elements.append({
                        "Type": elem.Type,
                        "Length": elem.Length,
                        "Value": elem.Value.hex() if isinstance(elem.Value, bytes) else elem.Value,
                        "RawValue": elem.Value
                    })
                    current = elem.payload
                else:
                    break
            result["message_elements"] = elements

            # 分类逻辑
            if not result["capwap_header"]:
                raise MissingCapwapHeaderError("CAPWAP header missing", raw_data)
            if not result["control_header"]:
                raise MissingControlHeaderError("Control header missing", raw_data)
            if result["control_header"].get("MsgType") != 2:
                raise UnexpectedMsgTypeError(f"Unexpected MsgType {result['control_header'].get('MsgType')}", raw_data)
            required_types = {1, 4}
            present_types = {e["Type"] for e in elements}
            if not required_types.issubset(present_types):
                raise MissingRequiredElementError("Required message elements missing", raw_data)

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