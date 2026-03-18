"""Response parser for CAPWAP Discovery Responses."""

from scapy.all import *
from scapy.all import bind_layers, split_layers, Packet, UDP, Raw, hexdump
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import json

from .request_creater import (
    CAPWAP_Header,
    Control_Header,
    MessageElement_Valid,
)
from .errors import InvalidResponseError, NoResponseError

# Define response types
class ResponseType:
    VALID = "valid"           # Properly formatted CAPWAP Discovery Response
    ERROR = "error"           # Response received but malformed or error indication
    NO_RESPONSE = "timeout"   # No response received (timeout)
    UNKNOWN = "unknown"       # Cannot classify

    @staticmethod
    def all_types():
        return [ResponseType.VALID, ResponseType.ERROR, ResponseType.NO_RESPONSE, ResponseType.UNKNOWN]


class ResponseParser:
    """Parse and classify CAPWAP Discovery Responses."""

    def __init__(self, log_dir: Optional[Path] = None):
        """
        Initialize the response parser.

        Args:
            log_dir: Directory to store response logs. If None, logs to ./capwap_response_logs
        """
        if log_dir is None:
            self.log_dir = Path("./capwap_response_logs")
        else:
            self.log_dir = Path(log_dir)

        self.log_dir.mkdir(exist_ok=True)

        # Statistics
        self.stats = {rtype: 0 for rtype in ResponseType.all_types()}
        self.total_responses = 0

        # Setup logging for parser
        self.setup_logging()

        # Bind layers for parsing
        self._bind_layers()

    def _bind_layers(self):
        """Bind CAPWAP protocol layers for parsing."""
        bind_layers(CAPWAP_Header, Control_Header)
        bind_layers(Control_Header, MessageElement_Valid)
        bind_layers(MessageElement_Valid, MessageElement_Valid)

    def _unbind_layers(self):
        """Unbind layers to avoid conflicts."""
        split_layers(CAPWAP_Header, Control_Header)
        split_layers(Control_Header, MessageElement_Valid)
        split_layers(MessageElement_Valid, MessageElement_Valid)

    def setup_logging(self):
        """Setup logging for response parser."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self.log_dir / f"response_parser_{timestamp}.log"

        # Create a separate logger for response parsing
        self.parser_logger = logging.getLogger("response_parser")
        self.parser_logger.setLevel(logging.INFO)

        # Avoid duplicate handlers
        if not self.parser_logger.handlers:
            file_handler = logging.FileHandler(str(log_file))
            file_handler.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
            )
            self.parser_logger.addHandler(file_handler)

    def parse_response(self, raw_data: bytes, request_info: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Parse raw CAPWAP response data.

        Args:
            raw_data: Raw bytes of the response
            request_info: Optional dictionary with info about the request (e.g., fuzzing method)

        Returns:
            Dictionary with parsed response details and classification
        """
        if raw_data is None or len(raw_data) == 0:
            return self._create_no_response_result(request_info)

        try:
            # Parse the response using CAPWAP layers
            self._bind_layers()
            pkt = CAPWAP_Header(raw_data)

            # Extract headers
            capwap_header = self._extract_capwap_header(pkt)
            control_header = self._extract_control_header(pkt)
            message_elements = self._extract_message_elements(pkt)

            # Classify the response
            response_type = self._classify_response(capwap_header, control_header, message_elements)

            # Create result dictionary
            result = {
                "timestamp": datetime.now().isoformat(),
                "response_type": response_type,
                "capwap_header": capwap_header,
                "control_header": control_header,
                "message_elements": message_elements,
                "raw_length": len(raw_data),
                "request_info": request_info or {},
                "hex_dump": raw_data.hex(),
            }

            # Update statistics
            self.stats[response_type] += 1
            self.total_responses += 1

            # Log the result
            self._log_result(result)

            return result

        except Exception as e:
            # If parsing fails, treat as error response
            self.parser_logger.error(f"Failed to parse response: {e}")
            return self._create_error_result(e, raw_data, request_info)
        finally:
            self._unbind_layers()

    def _extract_capwap_header(self, pkt: Packet) -> Dict[str, Any]:
        """Extract CAPWAP header fields."""
        if pkt.haslayer(CAPWAP_Header):
            capwap = pkt[CAPWAP_Header]
            return {
                "version": capwap.version,
                "type": capwap.type,
                "Hlen": capwap.Hlen,
                "Rid": capwap.Rid,
                "WBID": capwap.WBID,
                "T": capwap.T,
                "F": capwap.F,
                "L": capwap.L,
                "W": capwap.W,
                "M": capwap.M,
                "K": capwap.K,
                "Flags": capwap.Flags,
                "FragmentID": capwap.FragmentID,
                "FragmentOffset": capwap.FragmentOffset,
                "Rsvd": capwap.Rsvd,
            }
        return {}

    def _extract_control_header(self, pkt: Packet) -> Dict[str, Any]:
        """Extract Control header fields."""
        if pkt.haslayer(Control_Header):
            ctrl = pkt[Control_Header]
            return {
                "MsgType": ctrl.MsgType,
                "SeqNum": ctrl.SeqNum,
                "MsgElemsLen": ctrl.MsgElemsLen,
                "Flags": ctrl.Flags,
            }
        return {}

    def _extract_message_elements(self, pkt: Packet) -> list:
        """Extract all Message Elements."""
        elements = []
        current = pkt

        # Navigate through MessageElement layers
        while current.haslayer(MessageElement_Valid):
            elem = current[MessageElement_Valid]
            element_data = {
                "Type": elem.Type,
                "Length": elem.Length,
                "Value": elem.Value.hex() if isinstance(elem.Value, bytes) else elem.Value,
                "RawValue": elem.Value,
            }
            elements.append(element_data)

            # Move to next layer
            current = elem.payload

            # If next layer is not MessageElement, break
            if not isinstance(current, MessageElement_Valid):
                break

        return elements

    def _classify_response(
        self,
        capwap_header: Dict[str, Any],
        control_header: Dict[str, Any],
        message_elements: list
    ) -> str:
        """
        Classify the response based on parsed headers and elements.

        Classification rules:
        - VALID: MsgType == 2 (Discovery Response) and basic structure is correct
        - ERROR: Response received but MsgType != 2 or malformed structure
        - UNKNOWN: Cannot determine
        """
        if not control_header:
            return ResponseType.ERROR

        msg_type = control_header.get("MsgType")

        # CAPWAP Discovery Response has MsgType = 2
        if msg_type == 2:
            # Additional checks could be added here (e.g., required message elements)
            return ResponseType.VALID
        else:
            # Other message types or malformed responses
            return ResponseType.ERROR

    def _create_no_response_result(self, request_info: Optional[Dict]) -> Dict[str, Any]:
        """Create result dictionary for no response (timeout)."""
        result = {
            "timestamp": datetime.now().isoformat(),
            "response_type": ResponseType.NO_RESPONSE,
            "capwap_header": {},
            "control_header": {},
            "message_elements": [],
            "raw_length": 0,
            "request_info": request_info or {},
            "hex_dump": "",
            "error": "No response received (timeout)",
        }

        self.stats[ResponseType.NO_RESPONSE] += 1
        self.total_responses += 1
        self._log_result(result)

        return result

    def _create_error_result(self, error: Exception, raw_data: bytes, request_info: Optional[Dict]) -> Dict[str, Any]:
        """Create result dictionary for parsing error."""
        result = {
            "timestamp": datetime.now().isoformat(),
            "response_type": ResponseType.ERROR,
            "capwap_header": {},
            "control_header": {},
            "message_elements": [],
            "raw_length": len(raw_data) if raw_data else 0,
            "request_info": request_info or {},
            "hex_dump": raw_data.hex() if raw_data else "",
            "error": str(error),
            "error_type": type(error).__name__,
        }

        self.stats[ResponseType.ERROR] += 1
        self.total_responses += 1
        self._log_result(result)

        return result

    def _log_result(self, result: Dict[str, Any]):
        """Log parsed response result to file."""
        try:
            # Create a separate log entry for each response
            log_entry = {
                "timestamp": result["timestamp"],
                "response_type": result["response_type"],
                "raw_length": result["raw_length"],
                "request_info": result.get("request_info", {}),
            }

            # Add error info if present
            if "error" in result:
                log_entry["error"] = result["error"]

            # Log to file
            self.parser_logger.info(f"Response parsed: {json.dumps(log_entry)}")

            # Also write detailed result to separate JSON file
            self._write_detailed_result(result)

        except Exception as e:
            # Fallback to simple logging if JSON serialization fails
            self.parser_logger.error(f"Failed to log result: {e}")

    def _write_detailed_result(self, result: Dict[str, Any]):
        """Write detailed response result to JSON file."""
        try:
            # Create a timestamped filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            filename = self.log_dir / f"response_{timestamp}_{result['response_type']}.json"

            # Write JSON with indentation
            with open(filename, 'w') as f:
                json.dump(result, f, indent=2, default=str)

        except Exception as e:
            self.parser_logger.error(f"Failed to write detailed result: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get current parsing statistics."""
        stats_summary = {
            "total_responses": self.total_responses,
            "by_type": self.stats.copy(),
        }

        # Calculate percentages
        if self.total_responses > 0:
            for rtype in ResponseType.all_types():
                count = self.stats[rtype]
                percentage = (count / self.total_responses) * 100
                stats_summary["by_type"][rtype] = {
                    "count": count,
                    "percentage": round(percentage, 2)
                }

        return stats_summary

    def print_statistics(self):
        """Print statistics to console and log."""
        stats = self.get_statistics()

        self.parser_logger.info("=== Response Parser Statistics ===")
        self.parser_logger.info(f"Total responses processed: {stats['total_responses']}")

        for rtype in ResponseType.all_types():
            if rtype in stats['by_type']:
                rtype_stats = stats['by_type'][rtype]
                if isinstance(rtype_stats, dict):
                    self.parser_logger.info(
                        f"  {rtype}: {rtype_stats['count']} ({rtype_stats['percentage']}%)"
                    )
                else:
                    self.parser_logger.info(f"  {rtype}: {rtype_stats}")

    def reset_statistics(self):
        """Reset parser statistics."""
        self.stats = {rtype: 0 for rtype in ResponseType.all_types()}
        self.total_responses = 0


def parse_and_classify_response(
    raw_data: bytes,
    request_info: Optional[Dict] = None,
    log_dir: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Convenience function to parse and classify a single response.

    Args:
        raw_data: Raw bytes of the response
        request_info: Optional request context
        log_dir: Directory for logs

    Returns:
        Parsed response dictionary
    """
    parser = ResponseParser(log_dir)
    return parser.parse_response(raw_data, request_info)


if __name__ == "__main__":
    # Test the parser with sample data
    import sys
    if len(sys.argv) > 1:
        # Read raw data from file
        with open(sys.argv[1], 'rb') as f:
            raw_data = f.read()

        result = parse_and_classify_response(raw_data)
        print(json.dumps(result, indent=2, default=str))
    else:
        print("Usage: python response_parser.py <raw_response_file>")