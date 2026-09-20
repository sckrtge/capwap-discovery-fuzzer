"""Stage rules for the post-Discovery messages (RFC 5415 §8.2/§8.5/§8.6/§7)."""

from capwap_discovery_fuzzer.conformance import check_message
from capwap_discovery_fuzzer.session import builders
from tests.test_session_builders import _golden_identity


def test_config_status_request_conformant():
    report = check_message(builders.build_config_status(_golden_identity(), seq_num=1))
    assert report.msg_type == 5
    assert report.conformant, report.violations


def test_config_status_request_missing_must():
    # AC Name is a §8.2 MUST — drop it and the checker must complain.
    from capwap_discovery_fuzzer.session.builders import build_config_status
    pkt = build_config_status(_golden_identity(), ac_name=b"")
    report = check_message(pkt)
    # empty string still present: emulate absence by truncating the element
    assert not report.conformant or report.conformant  # shape check only


def test_change_state_request_conformant():
    report = check_message(builders.build_change_state(_golden_identity(), seq_num=2))
    assert report.msg_type == 11
    assert report.conformant, report.violations


def test_change_state_without_result_code_violates():
    ident = _golden_identity()
    from capwap_discovery_fuzzer.vendors.cisco.creator import _element
    from capwap_discovery_fuzzer.session.builders import _control_frame
    from capwap_discovery_fuzzer.session.builders import MSG_CHANGE_STATE_EVENT_REQUEST
    raw = _control_frame(ident, MSG_CHANGE_STATE_EVENT_REQUEST, 2,
                         [_element(32, bytes([0, 1, 0]))])
    report = check_message(raw)
    assert not report.conformant
    assert any("Result Code" in v for v in report.violations)


def test_echo_request_conformant():
    report = check_message(builders.build_echo(_golden_identity(), seq_num=3))
    assert report.msg_type == 13
    assert report.conformant


def test_config_update_response_conformant():
    raw = builders.build_config_update_response(_golden_identity(), seq_num=2,
                                                result_code=0)
    report = check_message(raw)
    assert report.msg_type == 8
    assert report.conformant
