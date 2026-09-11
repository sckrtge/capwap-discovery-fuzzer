"""Regression tests for capwap-discovery-fuzzer bug fixes.

Covers the defects verified on 2026-09-10:
- message-element iteration (Scapy getlayer nb starts at 1; name-based
  matching misses MessageElement_Valid) — previously every fuzz_elem_*
  method was a silent no-op
- fuzz_elem_duplicate splicing (add_payload would drop the rest of the chain)
- --seed reproducibility of mutated bytes (mutations previously used the
  unseeded global random module)
- load_request_from_pcap returns a clonable Packet (previously bytes, which
  crashed base_pkt.copy()) and the loaded packet is element-fuzzable
- ResponseParser must not strip a bogus "IP header" from CAPWAP version=4
  responses
- /proc/<pid>/stat parsing with spaces in the process name
"""

import random
from pathlib import Path

import pytest
from scapy.packet import Packet

from capwap_discovery_fuzzer.capwap_discovery_fuzzer import CAPWAPDiscoveryFuzzer
from capwap_discovery_fuzzer.payload_fuzzer import Payload_Fuzzer
from capwap_discovery_fuzzer.request_creater import (
    CAPWAP_Header,
    Control_Header,
    MessageElement,
    Payload_Creator,
)
from capwap_discovery_fuzzer.response_parser import ResponseParser
from capwap_discovery_fuzzer.vendors.cisco.creator import CiscoPayloadCreator
from capwap_discovery_fuzzer.vendors.opencapwap.fuzzer import _parse_stat_cpu_times

def _locate_pcap() -> Path:
    here = Path(__file__).resolve().parent
    for base in (here.parent, Path.cwd(), Path.cwd().parent):
        candidate = base / "pcaps" / "sample_discovery_request.pcap"
        if candidate.exists():
            return candidate
    pytest.skip("pcaps/sample_discovery_request.pcap not found")


_PCAP = _locate_pcap()

ELEM_METHODS = [
    "fuzz_elem_type",
    "fuzz_elem_length",
    "fuzz_elem_length_zero",
    "fuzz_elem_length_overflow",
    "fuzz_elem_value",
    "fuzz_elem_drop",
    "fuzz_elem_drop_required",
    "fuzz_elem_duplicate",
    "fuzz_elem_insert_unknown",
]


@pytest.fixture
def generic_base():
    return Payload_Creator(rng=random.Random(1)).create_discovery_request(valid=True)


@pytest.fixture
def cisco_base():
    return CiscoPayloadCreator(rng=random.Random(2)).create_discovery_request(valid=True)


# ---------------------------------------------------------------- elements

def test_iter_message_elements_generic(generic_base):
    assert len(Payload_Fuzzer(generic_base)._iter_message_elements(generic_base)) == 5


def test_iter_message_elements_cisco(cisco_base):
    assert len(Payload_Fuzzer(cisco_base)._iter_message_elements(cisco_base)) == 11


@pytest.mark.parametrize("method_name", ELEM_METHODS)
def test_elem_methods_mutate_packet(generic_base, method_name):
    f = Payload_Fuzzer(generic_base, rng=random.Random(42))
    before = bytes(generic_base)
    after = bytes(getattr(f, method_name)(generic_base))
    assert after != before, f"{method_name} did not change the packet"


@pytest.mark.parametrize("msg_type", [38, 39])
def test_elem_value_by_type_mutates(generic_base, msg_type):
    f = Payload_Fuzzer(generic_base, rng=random.Random(7))
    assert bytes(f.fuzz_elem_value_by_type(msg_type, generic_base)) != bytes(generic_base)


def test_elem_duplicate_preserves_rest_of_chain(generic_base):
    f = Payload_Fuzzer(generic_base, rng=random.Random(3))
    out = f.fuzz_elem_duplicate(generic_base)
    assert len(f._iter_message_elements(out)) == 6


def test_elem_order_shuffle_mutates_packet(generic_base):
    # shuffle can legitimately yield the identity permutation for a single
    # seed, so require a change across several seeds
    for seed in range(10):
        f = Payload_Fuzzer(generic_base, rng=random.Random(seed))
        if bytes(f.fuzz_elem_order_shuffle(generic_base)) != bytes(generic_base):
            return
    pytest.fail("fuzz_elem_order_shuffle produced no change for seeds 0-9")


def test_elem_methods_work_on_cisco_base(cisco_base):
    f = Payload_Fuzzer(cisco_base, rng=random.Random(5))
    out = f.fuzz_elem_value_by_type(38, cisco_base)
    assert bytes(out) != bytes(cisco_base)


# ---------------------------------------------------------------- seed

def _simulate_round(seed: int) -> str:
    rng = random.Random(seed)
    base = Payload_Creator(rng=rng).create_discovery_request(valid=True)
    f = Payload_Fuzzer(base, rng=rng)
    pool = [f.fuzz_capwap_header, f.fuzz_elem_value, f.fuzz_elem_duplicate, f.fuzz_elem_drop]
    chosen = rng.choices(pool, k=2)
    pkt = base.copy()
    for m in chosen:
        pkt = m(pkt)
    return bytes(pkt).hex()


def test_same_seed_reproduces_mutated_bytes():
    assert _simulate_round(123) == _simulate_round(123)


def test_different_seed_produces_different_bytes():
    assert _simulate_round(123) != _simulate_round(999)


# ---------------------------------------------------------------- pcap

def test_load_request_from_pcap_returns_clonable_packet():
    pkt = CAPWAPDiscoveryFuzzer.load_request_from_pcap(str(_PCAP))
    assert isinstance(pkt, Packet)
    assert pkt.copy() is not None  # fuzzing() clones the base packet each round


def test_pcap_loaded_packet_is_element_fuzzable():
    pkt = CAPWAPDiscoveryFuzzer.load_request_from_pcap(str(_PCAP))
    f = Payload_Fuzzer(pkt, rng=random.Random(5))
    assert len(f._iter_message_elements(pkt)) >= 1
    assert bytes(f.fuzz_elem_type(pkt)) != bytes(pkt)


# ---------------------------------------------------------------- response parser

def _build_response(version: int) -> bytes:
    elems = (
        MessageElement(Type=1, Length=2, Value=b"\x00\x01")
        / MessageElement(Type=4, Length=2, Value=b"ac")
        / MessageElement(Type=10, Length=6, Value=b"\x0a\x00\x00\x01\x00\x05")
    )
    ctrl = Control_Header(MsgType=2, SeqNum=1, MsgElemsLen=len(bytes(elems)) + 3, Flags=0)
    hdr = CAPWAP_Header(version=version, Hlen=2, WBID=1)
    return bytes(hdr / ctrl / elems)


@pytest.mark.parametrize("version", [0, 4])
def test_response_parser_accepts_any_capwap_version(version):
    result = ResponseParser().parse_response(_build_response(version))
    assert result["response_type"] == "valid"
    assert result["error_type"] is None


# ---------------------------------------------------------------- proc stat

def test_parse_stat_cpu_times_with_spaced_comm():
    line = "1234 (my fancy proc) S 1 0 0 0 -1 4194624 10 20 30 40 777 888 0 0"
    assert _parse_stat_cpu_times(line) == (777, 888)


def test_parse_stat_cpu_times_malformed_returns_none():
    assert _parse_stat_cpu_times("garbage") is None
