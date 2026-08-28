"""Tests for the server's capture-status reporting and CLI.

Request handling itself is exercised against a running server; what is unit
tested here is the logic that decides what the UI is told, including the
deliberate acceptance of capture states nobody has defined yet.
"""

from pathlib import Path

import pytest

from netmon import server
from netmon.server import (
    CAPTURE_STATE_DETAILS,
    CAPTURE_STATE_ERROR,
    CAPTURE_STATE_MOCK,
    DEFAULT_BIND_HOST,
    DEFAULT_HOST_IP,
    DEFAULT_PORT,
    build_parser,
    capture_status_for,
    resolve_capture_status,
)

INVENTED_STATE = "adapter_on_fire"


@pytest.mark.parametrize("state", sorted(CAPTURE_STATE_DETAILS))
def test_known_states_keep_their_own_sentence(state: str) -> None:
    status = capture_status_for(state)

    assert status.state == state
    assert status.detail == CAPTURE_STATE_DETAILS[state]
    assert status.as_dict() == {"state": state, "detail": status.detail}


def test_missing_npcap_points_the_operator_at_npcap_com() -> None:
    assert "npcap.com" in capture_status_for("npcap_missing").detail


def test_unknown_states_are_accepted_and_described() -> None:
    status = capture_status_for(INVENTED_STATE)

    assert status.state == INVENTED_STATE
    assert INVENTED_STATE in status.detail


def test_mock_traffic_is_reported_as_such() -> None:
    assert resolve_capture_status(mock=True, forced=None).state == CAPTURE_STATE_MOCK


def test_a_forced_state_wins_over_the_mock_flag() -> None:
    status = resolve_capture_status(mock=True, forced=INVENTED_STATE)

    assert status.state == INVENTED_STATE


def test_running_without_any_source_is_reported_as_an_error() -> None:
    status = resolve_capture_status(mock=False, forced=None)

    assert status.state == CAPTURE_STATE_ERROR
    assert "--mock" in status.detail


def test_web_directory_is_resolved_from_the_package_not_the_cwd() -> None:
    package_root = Path(server.__file__).resolve().parent

    assert server.WEB_DIRECTORY.is_absolute()
    assert server.WEB_DIRECTORY == package_root.parent / "web"


def test_cli_defaults_match_the_documented_ones() -> None:
    args = build_parser().parse_args([])

    assert args.port == DEFAULT_PORT
    assert args.host == DEFAULT_BIND_HOST
    assert args.host_ip == DEFAULT_HOST_IP
    assert args.mock is False
    assert args.capture_status is None


def test_cli_accepts_an_invented_capture_state() -> None:
    args = build_parser().parse_args(["--capture-status", INVENTED_STATE])

    assert args.capture_status == INVENTED_STATE
