"""Seed identity parameterisation tests (E/3a + the ablation switches for E/3b).

The central guarantee: the parameterised creator must still emit the exact bytes
the captured Cisco AP does when no override is given, so lock-mode and baseline
sessions remain comparable with everything recorded so far.
"""

import hashlib
import random
import struct

import pytest
from typer.testing import CliRunner

from tests.cli_helpers import flat, invoke_cli
from capwap_discovery_fuzzer import conformance as cf
from capwap_discovery_fuzzer.cli import app
from capwap_discovery_fuzzer.vendors.cisco.creator import (
    ApIdentity,
    CiscoPayloadCreator,
    DISCOVERY_REQUEST,
)
from capwap_discovery_fuzzer.vendors.cisco.elements import (
    BOARD_SUBELEM_BASE_MAC,
    BOARD_SUBELEM_MODEL,
    BOARD_SUBELEM_SERIAL,
    make_board_data,
    make_descriptor,
)

#: sha256 of the seed produced by the pre-parameterisation code (captured from
#: the remote working tree before this change), 252 bytes.
CAPTURED_SEED_SHA256 = "57db1af3551c05b3eda694fb0216219eb5310335ae5869e461c54fffa45a93bc"


def seed(identity=None) -> bytes:
    return bytes(CiscoPayloadCreator(rng=random.Random(1), identity=identity)
                 .create_discovery_request(valid=True))


def elements(raw: bytes):
    from capwap_discovery_fuzzer.lock_fuzzer import parse_layout
    layout = parse_layout(raw)
    return [(e.type, raw[e.value_start:e.value_end]) for e in layout.elements]


# ------------------------------------------------------- default byte-identity

def test_default_identity_reproduces_the_captured_seed():
    raw = seed()
    assert len(raw) == 252
    assert hashlib.sha256(raw).hexdigest() == CAPTURED_SEED_SHA256


def test_builders_reproduce_the_captured_element_values():
    assert make_board_data() == bytes.fromhex(
        "004096000000000a43393130354158492d48"
        "0001000b46474c323731384c505159"
        "00020002ffff"
        "0003000e4c696e7578205265766973696f6e"
        "0004000610a82901d6b0"
    )
    assert make_descriptor() == bytes.fromhex(
        "0202000100409600000000040100000000"
        "40960000010004110e004f004096000002000401010204"
    )


# --------------------------------------------------------- identity overrides

def test_ap_name_lands_in_element_45_and_the_rad_name_vsp():
    raw = seed(ApIdentity(ap_name=b"AP-TEST-1"))
    by_type = {}
    for etype, value in elements(raw):
        by_type.setdefault(etype, []).append(value)

    assert by_type[45] == [b"AP-TEST-1"]
    assert by_type[37][1] == bytes.fromhex("004096000005") + b"AP-TEST-1"


def test_model_serial_and_base_mac_land_in_board_data():
    ident = ApIdentity(model=b"MODEL-X", serial=b"SER-42",
                       base_mac=bytes.fromhex("aabbccddeeff"))
    board = dict((t, v) for t, v in elements(seed(ident)))[38]

    assert struct.pack(">HH", BOARD_SUBELEM_MODEL, len(b"MODEL-X")) + b"MODEL-X" in board
    assert struct.pack(">HH", BOARD_SUBELEM_SERIAL, len(b"SER-42")) + b"SER-42" in board
    assert struct.pack(">HH", BOARD_SUBELEM_BASE_MAC, 6) + bytes.fromhex("aabbccddeeff") in board


def test_ap_mac_lands_in_the_capwap_optional_field():
    raw = seed(ApIdentity(ap_mac=bytes.fromhex("001122334455")))
    # bytes 8..15 are the optional field: length byte, 6-byte MAC, pad
    assert raw[8] == 6
    assert raw[9:15] == bytes.fromhex("001122334455")


def test_radio_ids_control_the_type_1048_elements():
    raw = seed(ApIdentity(radios=((1, 0x01), (2, 0x02))))
    radios = [v for t, v in elements(raw) if t == 1048]

    assert len(radios) == 2
    assert [v[0] for v in radios] == [1, 2]
    # RFC 5416 §6.25 requires Radio ID 1..31 — this variant is conformant there.
    report = cf.check_message(raw)
    assert not any("Radio ID" in v for v in report.violations)


def test_num_encrypt_override_satisfies_the_descriptor_rule():
    baseline = cf.check_message(seed())
    assert any("Num Encrypt 0 outside 1..255" in v for v in baseline.violations)

    fixed = cf.check_message(seed(ApIdentity(num_encrypt=1)))
    assert not any("Num Encrypt" in v for v in fixed.violations)


def test_msg_type_1_produces_a_conformant_discovery_request():
    """§5.1 (Discovery Request) has the same MUST set as §5.3, so the body is reusable."""
    ident = ApIdentity(msg_type=DISCOVERY_REQUEST, radios=((1, 0x01), (2, 0x02)), num_encrypt=1)
    report = cf.check_message(seed(ident))

    assert report.msg_type == cf.MSG_DISCOVERY_REQUEST
    assert report.msg_name == "Discovery Request"
    assert report.conformant, report.violations


# ------------------------------------------------------------ ablation switch

def test_omit_element_drops_it_and_keeps_msg_elems_len_consistent():
    ident = ApIdentity(omit_elements=frozenset({45, cf.ELEM_WTP_BOARD_DATA}))
    raw = seed(ident)
    present = [t for t, _ in elements(raw)]

    assert 45 not in present
    assert cf.ELEM_WTP_BOARD_DATA not in present
    # MsgElemsLen (§4.5.1.1) stays len(elements) + 3.
    layout_len = len(raw) - 16 - 8
    assert struct.unpack_from(">H", raw, 16 + 5)[0] == layout_len + 3


def test_omitting_a_mandatory_element_is_reported_as_a_violation():
    """The ablation's signal: the checker, not the AC, tells us what we removed."""
    report = cf.check_message(seed(ApIdentity(omit_elements=frozenset({38}))))

    assert any("missing mandatory WTP Board Data" in v for v in report.violations)


def test_omitting_every_element_is_rejected():
    all_types = {t for t, _ in elements(seed())}
    with pytest.raises(ValueError):
        seed(ApIdentity(omit_elements=frozenset(all_types)))


# --------------------------------------------------------------- CLI plumbing

def test_cli_rejects_identity_options_for_other_vendors():
    result = invoke_cli(app, ["--ac-ip", "127.0.0.1", "--vendor", "generic", "--ap-name", "X"])
    assert result.exit_code != 0
    assert "only apply to --vendor cisco" in flat(result.output)


def test_cli_rejects_a_bad_mac():
    result = invoke_cli(app, ["--ac-ip", "127.0.0.1", "--vendor", "cisco", "--ap-mac", "zzzz"])
    assert result.exit_code != 0
    assert "--ap-mac must be hex" in flat(result.output)


def test_cli_rejects_a_short_mac():
    result = invoke_cli(app, ["--ac-ip", "127.0.0.1", "--vendor", "cisco", "--ap-mac", "aabb"])
    assert result.exit_code != 0
    assert "must be 6 bytes" in flat(result.output)


def test_cli_builds_and_records_the_seed_identity(tmp_path, monkeypatch):
    """End-to-end: the overrides reach the creator and session.json."""
    import json

    import socket
    import threading

    from typer.testing import CliRunner as Runner

    monkeypatch.chdir(tmp_path)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    stop = threading.Event()

    def serve():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                _, peer = sock.recvfrom(65535)
            except OSError:
                continue
            sock.sendto(b"\x00" * 8, peer)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        result = Runner().invoke(app, [
            "--ac-ip", "127.0.0.1", "--ac-port", str(port), "--vendor", "cisco",
            "--rounds", "2", "--sleep", "0", "--lock-fields", "all",
            "--ap-name", "AP-LAB-9", "--ap-radio-ids", "1,2", "--num-encrypt", "1",
            "--omit-element", "28",
        ])
    finally:
        stop.set()
        thread.join(timeout=2)
        sock.close()

    assert result.exit_code == 0, result.output
    session = json.loads(next(tmp_path.glob("capwap_log/*/session.json")).read_text())
    ident = session["seed_identity"]
    assert ident["ap_name"] == "AP-LAB-9"
    assert ident["radios"] == [[1, 1], [2, 2]]
    assert ident["num_encrypt"] == 1
    assert ident["omit_elements"] == [28]
    assert ident["msg_type"] == 19

    # the recorded request really carries the overrides
    record = json.loads(next(tmp_path.glob("capwap_log/*/records.jsonl")).read_text().splitlines()[0])
    raw = bytes.fromhex(record["request_hex"])
    types = [t for t, _ in elements(raw)]
    assert 28 not in types
    assert b"AP-LAB-9" in raw
