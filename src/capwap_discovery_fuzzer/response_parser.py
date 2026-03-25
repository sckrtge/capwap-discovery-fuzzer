from scapy.all import *
from scapy.all import bind_layers, split_layers, Packet
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import json

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

    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = Path(log_dir) if log_dir else Path("./capwap_response_logs")
        self.log_dir.mkdir(exist_ok=True)
        self.stats = {rtype: 0 for rtype in ResponseType.all_types()}
        self.total_responses = 0
        self._setup_logging()
        self._bind_layers()

    def _bind_layers(self):
        bind_layers(CAPWAP_Header, Control_Header)
        bind_layers(Control_Header, MessageElement_Valid)
        bind_layers(MessageElement_Valid, MessageElement_Valid)

    def _unbind_layers(self):
        split_layers(CAPWAP_Header, Control_Header)
        split_layers(Control_Header, MessageElement_Valid)
        split_layers(MessageElement_Valid, MessageElement_Valid)

    def _setup_logging(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self.log_dir / f"response_parser_{timestamp}.log"
        self.parser_logger = logging.getLogger("response_parser")
        self.parser_logger.setLevel(logging.INFO)
        if not self.parser_logger.handlers:
            file_handler = logging.FileHandler(str(log_file))
            file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
            self.parser_logger.addHandler(file_handler)

    def parse_response(self, raw_data: bytes, request_info: Optional[Dict] = None) -> Dict[str, Any]:
        request_info = request_info or {}
        if not raw_data:
            raise NoResponseError("No response received", request_info.get("ac_ip"), request_info.get("ac_port"))
        try:
            self._bind_layers()
            pkt = CAPWAP_Header(raw_data)
            capwap_header = self._extract_capwap_header(pkt)
            control_header = self._extract_control_header(pkt)
            message_elements = self._extract_message_elements(pkt)
            error_type = None

            # 分类逻辑
            if not capwap_header:
                error_type = "MissingCapwapHeaderError"
                raise MissingCapwapHeaderError("CAPWAP header missing", raw_data)
            if not control_header:
                error_type = "MissingControlHeaderError"
                raise MissingControlHeaderError("Control header missing", raw_data)
            if control_header.get("MsgType") != 2:
                error_type = "UnexpectedMsgTypeError"
                raise UnexpectedMsgTypeError(f"Unexpected MsgType {control_header.get('MsgType')}", raw_data)
            required_types = {1, 4}
            present_types = {e["Type"] for e in message_elements}
            if not required_types.issubset(present_types):
                error_type = "MissingRequiredElementError"
                raise MissingRequiredElementError("Required message elements missing", raw_data)
            if not any(e["Type"] == 38 for e in message_elements):
                error_type = "InvalidRadioInfoError"
                raise InvalidRadioInfoError("Missing WTP Radio Info", raw_data)

            self.stats[ResponseType.VALID] += 1
            self.total_responses += 1
            result = {
                "response_type": ResponseType.VALID,
                "capwap_header": capwap_header,
                "control_header": control_header,
                "message_elements": message_elements,
                "raw_length": len(raw_data),
                "request_info": request_info,
                "hex_dump": raw_data.hex(),
                "error_type": None
            }
            self._log_result(result)
            return result

        except CAPWAPFuzzerError as e:
            self.stats[ResponseType.ERROR] += 1
            self.total_responses += 1
            result = {
                "response_type": ResponseType.ERROR,
                "capwap_header": {},
                "control_header": {},
                "message_elements": [],
                "raw_length": len(raw_data),
                "request_info": request_info,
                "hex_dump": raw_data.hex(),
                "error_type": type(e).__name__,
                "error": str(e)
            }
            self._log_result(result)
            return result

        finally:
            self._unbind_layers()

    def _extract_capwap_header(self, pkt: Packet) -> Dict[str, Any]:
        return pkt[CAPWAP_Header].fields if pkt.haslayer(CAPWAP_Header) else {}

    def _extract_control_header(self, pkt: Packet) -> Dict[str, Any]:
        return pkt[Control_Header].fields if pkt.haslayer(Control_Header) else {}

    def _extract_message_elements(self, pkt: Packet) -> list:
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
        return elements

    def _log_result(self, result: Dict[str, Any]):
        try:
            self.parser_logger.info(f"Response parsed: {json.dumps(result, indent=2, default=str)}")
            filename = self.log_dir / f"response_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
            with open(filename, "w") as f:
                json.dump(result, f, indent=2, default=str)
        except Exception as e:
            self.parser_logger.error(f"Failed to write response log: {e}")