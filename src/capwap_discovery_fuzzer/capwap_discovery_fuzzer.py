"""Main module."""
import socket
from scapy.all import *
import capwap_discovery_fuzzer.errors as errors
from capwap_discovery_fuzzer.utils import *
import random
import time
import json
from pathlib import Path
from capwap_discovery_fuzzer.request_creater import *
from capwap_discovery_fuzzer.payload_fuzzer import *

from scapy.config import conf
from functools import partial

MUTATUION_COUNT = 10

class CAPWAPDiscoveryFuzzer:
    def __init__(
        self,
        ac_ip: str | None,
        ac_port: int = 5246,
        timeout: float = 3.0,
        seed: int | None = None,
        broadcast: bool = False,
        iface: str | None = None,
    ):
        self.ac_ip = ac_ip
        self.ac_port = ac_port
        self.timeout = timeout
        self.broadcast = broadcast
        self.iface = iface

        self.sock = None
        self.sequence = 0
        self._rng = random.Random()
        self.seed = seed

        if seed is not None:
            self._rng.seed(seed)

    def load_request_from_pcap(self, pcap_path: str) -> bytes:
        """
        Load and extract a CAPWAP Discovery Request from a pcap file.
        """
        pkts = rdpcap(pcap_path)
        for pkt in pkts:
            if not pkt.haslayer("UDP"):
                continue

            udp = pkt["UDP"]
            if udp.dport != 5246:
                continue

            payload = udp.payload
            return payload

        raise ValueError("No CAPWAP Discovery Request found in pcap!")

    def is_discovery_response(self, discovery_response) -> bool:
        """
        only determine whether any response is received.
        """
        if discovery_response is None:
            logging.info(f"Discovery Response Timeout")
            return False
        logging.info(f"Discovery Response:\n{hexdump(bytes(discovery_response))}")
        return True
    
    def send_discovery_request(self, discovery_request):
        conf.verb = 0
        sport = random.randint(20000,60000)
        pkt = IP(dst=self.ac_ip) / UDP(sport=sport, dport=self.ac_port) / discovery_request # type: ignore
        logging.info(f"Send Discovery Request:\n{pkt.show(dump=True)}\n")
        # logging.info(f"Send Discovery Request:\n{hexdump(bytes(pkt))}\n")
        resp = sr1(pkt, timeout=self.timeout)
        # time.sleep(1)
        return resp
    
    def fuzzing(
        self,
        pcap_path: str | None,
    ) -> dict[str, int]:

        status = {
            'timeout': 0,
            'valid': 0,
            'total': 0
        }

        creator = Payload_Creator()

        if pcap_path is not None:
            base_pkt = parse_discovery_request(
                bytes(self.load_request_from_pcap(pcap_path))
            )
            logging.info(
                f"PCAP Discovery Request:\n{base_pkt.show(dump=True)}"
            )
        else:
            base_pkt = creator.create_discovery_request(valid=True)

        fuzzer = Payload_Fuzzer(base_pkt)

        fuzz_methods = [
            fuzzer.fuzz_capwap_header,
            fuzzer.fuzz_control_header,
            fuzzer.fuzz_any_msg_length,
            fuzzer.fuzz_any_msg_value,
            lambda: fuzzer.fuzz_specific_msg(38),
            lambda: fuzzer.fuzz_specific_msg(39),
            fuzzer.fuzz_duplicate_msg,
            fuzzer.fuzz_drop_last_msg,
            fuzzer.fuzz_shuffle_msgs
        ]

        for _ in range(MUTATUION_COUNT):
            mutate = random.choice(fuzz_methods)
            logging.info(f"[FUZZ] Selected method: {mutate.__name__}")
            send_pkt = mutate()
            resp = self.send_discovery_request(send_pkt)

            if self.is_discovery_response(resp):
                status['valid'] += 1
            else:
                status['timeout'] += 1

            status['total'] += 1

        return status
# """Main module."""
# import socket
# from capwap_discovery_fuzzer.response_parser import ResponseParser, parse_and_classify_response
# from typing import Optional, Dict
# from scapy.all import *
# import capwap_discovery_fuzzer.errors as errors
# from capwap_discovery_fuzzer.utils import *
# import random
# import time
# import json
# from pathlib import Path
# from capwap_discovery_fuzzer.request_creater import *
# from capwap_discovery_fuzzer.payload_fuzzer import *
# from capwap_discovery_fuzzer.response_parser import ResponseParser, parse_and_classify_response
# from scapy.config import conf
# from functools import partial

# MUTATUION_COUNT = 10

# class CAPWAPDiscoveryFuzzer:
#     def __init__(
#         self,
#         ac_ip: str | None,
#         ac_port: int = 5246,
#         timeout: float = 3.0,
#         seed: int | None = None,
#         broadcast: bool = False,
#         iface: str | None = None,
#     ):
#         self.ac_ip = ac_ip
#         self.ac_port = ac_port
#         self.timeout = timeout
#         self.broadcast = broadcast
#         self.iface = iface

#         self.sock = None
#         self.sequence = 0
#         self._rng = random.Random()
#         self.seed = seed

#         if seed is not None:
#             self._rng.seed(seed)

#         self.response_parser = ResponseParser()

#     def load_request_from_pcap(self, pcap_path: str) -> bytes:
#         """
#         Load and extract a CAPWAP Discovery Request from a pcap file.
#         """
#         pkts = rdpcap(pcap_path)
#         for pkt in pkts:
#             if not pkt.haslayer("UDP"):
#                 continue

#             udp = pkt["UDP"]
#             if udp.dport != 5246:
#                 continue

#             payload = udp.payload
#             return payload

#         raise ValueError("No CAPWAP Discovery Request found in pcap!")

#     def classify_discovery_response(self, discovery_response, request_info: Optional[Dict] = None) -> str:
#         """
#         Parse and classify a CAPWAP discovery response.

#         Args:
#             discovery_response: Scapy packet (IP/UDP) or None
#             request_info: Optional dictionary with request context (e.g., fuzzing method)

#         Returns:
#             Response classification: "valid", "error", or "timeout"
#         """
#         if discovery_response is None:
#             logging.info("Discovery Response Timeout")
#             # Log no response via parser
#             self.response_parser.parse_response(b"", request_info)
#             return "timeout"

#         # Extract CAPWAP payload from IP/UDP response
#         raw_data = self._extract_capwap_payload(discovery_response)
#         if raw_data is None:
#             logging.warning("Could not extract CAPWAP payload from response")
#             raw_data = bytes(discovery_response)

#         logging.info(f"Discovery Response:\n{hexdump(raw_data)}")

#         # Parse and classify the response
#         parsed_result = self.response_parser.parse_response(raw_data, request_info)

#         # Return the classification from the parser
#         return parsed_result.get("response_type", "error")

#     def _extract_capwap_payload(self, packet) -> Optional[bytes]:
#         """
#         Extract CAPWAP payload from IP/UDP packet.

#         Args:
#             packet: Scapy packet (likely IP/UDP)

#         Returns:
#             CAPWAP payload bytes or None if not found
#         """
#         try:
#             # Check for UDP layer
#             if packet.haslayer(UDP):
#                 udp = packet[UDP]
#                 # CAPWAP payload is after UDP header
#                 # Note: scapy may already have parsed it as raw layer
#                 if udp.payload:
#                     # If payload is Raw, get its bytes
#                     if isinstance(udp.payload, Raw):
#                         return bytes(udp.payload)
#                     # Otherwise, try to get the bytes of the payload
#                     return bytes(udp.payload)
#         except Exception as e:
#             logging.warning(f"Failed to extract CAPWAP payload: {e}")

#         return None
    
#     def send_discovery_request(self, discovery_request):
#         conf.verb = 0
#         sport = random.randint(20000,60000)

#         # Determine destination IP based on mode
#         if self.broadcast:
#             dst_ip = "255.255.255.255"
#         else:
#             if not self.ac_ip:
#                 raise ValueError("AC IP address must be specified for unicast mode")
#             dst_ip = self.ac_ip

#         pkt = IP(dst=dst_ip) / UDP(sport=sport, dport=self.ac_port) / discovery_request # type: ignore
#         logging.info(f"Send Discovery Request:\n{pkt.show(dump=True)}\n")
#         # logging.info(f"Send Discovery Request:\n{hexdump(bytes(pkt))}\n")
#         resp = sr1(pkt, timeout=self.timeout)
#         # time.sleep(1)
#         return resp
    
#     def fuzzing(
#         self,
#         pcap_path: str | None,
#         max_methods_per_iteration: int = 3,
#         allow_multiple_methods: bool = True,
#         single_method_prob: float = 0.3,
#     ) -> dict[str, int]:
#         """
#         Main fuzzing loop with support for multiple method selection.
        
#         Args:
#             pcap_path: Path to PCAP file containing base request
#             max_methods_per_iteration: Maximum number of fuzzing methods to apply per iteration
#             allow_multiple_methods: Whether to allow multiple methods per iteration
#             single_method_prob: Probability of using single method even when multiple are allowed
            
#         Returns:
#             Dictionary with fuzzing statistics
#         """

#         status = {
#             'timeout': 0,
#             'valid': 0,
#             'error': 0,
#             'total': 0,
#             'method_combinations': {},  # Track effectiveness of different method combinations
#             'single_methods': {},       # Track effectiveness of individual methods
#         }

#         creator = Payload_Creator()

#         if pcap_path is not None:
#             base_pkt = parse_discovery_request(
#                 bytes(self.load_request_from_pcap(pcap_path))
#             )
#             logging.info(
#                 f"PCAP Discovery Request:\n{base_pkt.show(dump=True)}"
#             )
#         else:
#             base_pkt = creator.create_discovery_request(valid=True)

#         fuzzer = Payload_Fuzzer(base_pkt)

#         # Create a list of available fuzzing methods with their names
#         # Check if fuzz_capwap_flags method exists
#         available_methods = []
        
#         # Basic methods
#         basic_methods = [
#             ('fuzz_capwap_header', fuzzer.fuzz_capwap_header),
#             ('fuzz_control_header', fuzzer.fuzz_control_header),
#             ('fuzz_any_msg_type', fuzzer.fuzz_any_msg_type),
#             ('fuzz_any_msg_length', fuzzer.fuzz_any_msg_length),
#             ('fuzz_any_msg_value', fuzzer.fuzz_any_msg_value),
#             ('fuzz_specific_msg_38', partial(fuzzer.fuzz_specific_msg, 38)),
#             ('fuzz_specific_msg_39', partial(fuzzer.fuzz_specific_msg, 39)),
#             ('fuzz_duplicate_msg', fuzzer.fuzz_duplicate_msg),
#             ('fuzz_drop_last_msg', fuzzer.fuzz_drop_last_msg),
#             ('fuzz_shuffle_msgs', fuzzer.fuzz_shuffle_msgs),
#         ]
        
#         # Add fuzz_capwap_flags if it exists
#         if hasattr(fuzzer, 'fuzz_capwap_flags'):
#             basic_methods.append(('fuzz_capwap_flags', fuzzer.fuzz_capwap_flags))
        
#         available_methods = basic_methods
        
#         logging.info(f"Starting fuzzing with {MUTATUION_COUNT} iterations")
#         logging.info(f"Available methods: {[name for name, _ in available_methods]}")

#         for i in range(MUTATUION_COUNT):
#             logging.info(f"\n[Iteration {i+1}/{MUTATUION_COUNT}]")
            
#             # Determine if we use single or multiple methods
#             use_single_method = False
            
#             if not allow_multiple_methods:
#                 use_single_method = True
#             elif random.random() < single_method_prob:
#                 use_single_method = True
            
#             if use_single_method:
#                 # Single method selection
#                 method_name, method_func = random.choice(available_methods)
#                 logging.info(f"[FUZZ] Selected single method: {method_name}")
                
#                 try:
#                     send_pkt = method_func()
#                 except Exception as e:
#                     logging.error(f"[FUZZ] Failed to apply {method_name}: {e}")
#                     status['timeout'] += 1
#                     status['total'] += 1
#                     continue
                
#                 # Track individual method statistics
#                 if method_name not in status['single_methods']:
#                     status['single_methods'][method_name] = {'valid': 0, 'timeout': 0}
                
#                 method_key = method_name
#             else:
#                 # Multiple method selection
#                 # Randomly select 1 to max_methods_per_iteration methods
#                 num_methods = random.randint(1, min(max_methods_per_iteration, len(available_methods)))
#                 selected_methods = random.sample(available_methods, num_methods)
                
#                 method_names = [name for name, _ in selected_methods]
#                 logging.info(f"[FUZZ] Selected {num_methods} method(s): {method_names}")
                
#                 # Apply methods in chain
#                 current_pkt = base_pkt.copy()
#                 for method_name, method_func in selected_methods:
#                     try:
#                         # Create a new fuzzer for the current packet state
#                         temp_fuzzer = Payload_Fuzzer(current_pkt)
                        
#                         # Get the corresponding method from the new fuzzer
#                         # For partial functions (like fuzz_specific_msg), we need to handle specially
#                         if method_name.startswith('fuzz_specific_msg'):
#                             # Extract the type from the partial function
#                             # This is a bit hacky but works for our use case
#                             if method_name == 'fuzz_specific_msg_38':
#                                 current_pkt = temp_fuzzer.fuzz_specific_msg(38)
#                             elif method_name == 'fuzz_specific_msg_39':
#                                 current_pkt = temp_fuzzer.fuzz_specific_msg(39)
#                             else:
#                                 # For other specific messages, use the original function
#                                 current_pkt = method_func()
#                         else:
#                             # Get the method by name from the temp_fuzzer
#                             if hasattr(temp_fuzzer, method_name):
#                                 temp_method = getattr(temp_fuzzer, method_name)
#                                 current_pkt = temp_method()
#                             else:
#                                 # Fallback to original method
#                                 current_pkt = method_func()
#                     except Exception as e:
#                         logging.warning(f"[CHAIN] Failed to apply {method_name}: {e}")
#                         # Continue with the next method
                
#                 send_pkt = current_pkt
#                 method_key = "|".join(method_names)  # Create a combination key
            
#             # Build request info for response parsing
#             request_info = {
#                 "iteration": i + 1,
#                 "method_key": method_key,
#                 "use_single_method": use_single_method,
#                 "total_iterations": MUTATUION_COUNT,
#             }

#             # Send the fuzzed packet
#             resp = self.send_discovery_request(send_pkt)

#             # Check response
#             response_type = self.classify_discovery_response(resp, request_info)

#             # Update main statistics
#             if response_type == 'valid':
#                 status['valid'] += 1
#             elif response_type == 'error':
#                 status['error'] += 1
#             else:  # timeout
#                 status['timeout'] += 1

#             # Update method-specific statistics
#             if use_single_method:
#                 # Initialize if not present
#                 if method_key not in status['single_methods']:
#                     status['single_methods'][method_key] = {'valid': 0, 'error': 0, 'timeout': 0}
#                 # Increment the appropriate counter
#                 status['single_methods'][method_key][response_type] += 1
#             else:
#                 # Initialize if not present
#                 if method_key not in status['method_combinations']:
#                     status['method_combinations'][method_key] = {'valid': 0, 'error': 0, 'timeout': 0}
#                 # Increment the appropriate counter
#                 status['method_combinations'][method_key][response_type] += 1

#             status['total'] += 1
            
#             # Log progress periodically
#             if (i + 1) % 10 == 0:
#                 valid_rate = (status['valid'] / status['total']) * 100 if status['total'] > 0 else 0
#                 logging.info(f"[PROGRESS] {i+1}/{MUTATUION_COUNT} iterations completed. "
#                             f"Valid: {status['valid']}/{status['total']} ({valid_rate:.2f}%)")

#         # Final statistics
#         if status['total'] > 0:
#             valid_rate = (status['valid'] / status['total']) * 100
#             logging.info(f"\n[FINAL RESULTS]")
#             logging.info(f"Total iterations: {status['total']}")
#             logging.info(f"Valid responses: {status['valid']} ({valid_rate:.2f}%)")
#             logging.info(f"Error responses: {status['error']}")
#             logging.info(f"Timeouts: {status['timeout']}")
            
#             # Log individual method statistics
#             if status['single_methods']:
#                 logging.info("\n[INDIVIDUAL METHOD STATISTICS]")
#                 for method_name, counts in status['single_methods'].items():
#                     total = counts['valid'] + counts['error'] + counts['timeout']
#                     if total > 0:
#                         valid_rate = (counts['valid'] / total) * 100
#                         logging.info(f"  {method_name}: {counts['valid']}/{total} valid ({valid_rate:.2f}%), errors: {counts['error']}, timeouts: {counts['timeout']}")
            
#             # Log combination statistics
#             if status['method_combinations']:
#                 logging.info("\n[METHOD COMBINATION STATISTICS]")
#                 for combo_key, counts in status['method_combinations'].items():
#                     total = counts['valid'] + counts['error'] + counts['timeout']
#                     if total > 0:
#                         valid_rate = (counts['valid'] / total) * 100
#                         logging.info(f"  {combo_key}: {counts['valid']}/{total} valid ({valid_rate:.2f}%), errors: {counts['error']}, timeouts: {counts['timeout']}")

#         return status
