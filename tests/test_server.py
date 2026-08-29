"""Tests for the rates endpoint: its payload, capture status, and filtering.

The endpoint's contract - what is served, what is filtered out, and what an
unusable subnet gets back - is asserted end to end against a handler running on
a loopback port, fed by a fake-clocked window so nothing sleeps and no reading
depends on real time.

The record endpoint has its own module, as does the command line; the harness
all three share lives in ``conftest``.
"""

import urllib.request
from http import HTTPStatus
from pathlib import Path

import pytest

from netmon import server
from netmon.capture import (
    CAPTURE_STATE_CAPTURE_DIED,
    CAPTURE_STATE_DROPPING_PACKETS,
    CAPTURE_STATE_NOT_RUNNING,
    CAPTURE_STATE_OK,
    CaptureStatus,
)
from netmon.mock_source import MockSource
from netmon.rate_window import RateWindow
from netmon.server import (
    CAPTURE_STATE_DETAILS,
    CAPTURE_STATE_MOCK,
    DEFAULT_HOST_IP,
    DEFAULT_SUBNET,
    JSON_CONTENT_TYPE,
    NO_STORE,
    UNKNOWN_CAPTURE_DETAIL,
    capture_status_for,
    capture_status_reader,
    devices_in_subnet,
    parse_subnet,
)

from .conftest import (
    BUCKET_MS,
    DEFAULT_SUBNET_IPS,
    INVALID_SUBNETS,
    INVENTED_STATE,
    MALFORMED_IP,
    PACKETS_PER_BUCKET,
    RECORDING_KEYS,
    REQUEST_TIMEOUT_S,
    SECOND_SUBNET,
    SECOND_SUBNET_IPS,
    WINDOW_BUCKETS,
    FakeClock,
    Response,
    fetch_rates,
    populated_window,
    serving,
)

PAYLOAD_KEYS = {
    "host_ip",
    "subnet",
    "capture",
    "recording",
    "bucket_ms",
    "buckets",
    "now_ms",
    "devices",
}
CAPTURE_KEYS = {"state", "detail"}

INDEX_PATH = "/"
HTML_CONTENT_TYPE = "text/html"
PAGE_TITLE_MARKUP = "<title>Subnet Traffic</title>"


class ChangingStatus:
    """A reader whose answer differs every time it is called.

    Stands in for a capture whose health changes while the server is up, which
    a status resolved once at startup could never report.
    """

    def __init__(self, *states: str) -> None:
        self._states = list(states)
        self.calls = 0

    def __call__(self) -> CaptureStatus:
        state = self._states[min(self.calls, len(self._states) - 1)]
        self.calls += 1
        return capture_status_for(state)


def fetch_index(base_url: str) -> tuple[int, str, str]:
    """GET the served page, returning its status, content type, and markup."""
    url = f"{base_url}{INDEX_PATH}"
    with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT_S) as answer:
        return (
            answer.status,
            answer.headers.get("Content-Type", ""),
            answer.read().decode("utf-8"),
        )


def served_ips(response: Response) -> list[str]:
    return [device["ip"] for device in response.body["devices"]]


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


@pytest.mark.parametrize(
    "state",
    [
        CAPTURE_STATE_CAPTURE_DIED,
        CAPTURE_STATE_NOT_RUNNING,
        CAPTURE_STATE_DROPPING_PACKETS,
    ],
)
def test_the_states_only_a_running_capture_produces_can_be_reviewed(
    state: str,
) -> None:
    """--capture-status exists to see banners this machine cannot produce."""
    status = capture_status_for(state)

    assert status.state == state
    assert status.detail != UNKNOWN_CAPTURE_DETAIL.format(state=state)


def test_without_a_forced_state_the_sources_own_reader_is_used() -> None:
    live = ChangingStatus(CAPTURE_STATE_OK)

    assert capture_status_reader(live, None) is live


@pytest.mark.parametrize(
    "forced", [INVENTED_STATE, CAPTURE_STATE_CAPTURE_DIED, CAPTURE_STATE_NOT_RUNNING]
)
def test_a_forced_state_overrides_whatever_the_source_reports(forced: str) -> None:
    live = ChangingStatus(CAPTURE_STATE_OK)

    reader = capture_status_reader(live, forced)

    assert reader().state == forced
    assert live.calls == 0


def test_the_mock_source_supplies_the_mock_state(clock: FakeClock) -> None:
    window = RateWindow(bucket_ms=BUCKET_MS, buckets=WINDOW_BUCKETS, clock=clock)

    reader = capture_status_reader(MockSource(window).status, None)

    assert reader().state == CAPTURE_STATE_MOCK


def test_web_directory_is_resolved_from_the_package_not_the_cwd() -> None:
    package_root = Path(server.__file__).resolve().parent

    assert server.WEB_DIRECTORY.is_absolute()
    assert server.WEB_DIRECTORY == package_root.parent / "web"


def test_the_root_path_serves_the_page_itself(clock: FakeClock) -> None:
    """The UI is reachable at ``/`` with ``index.html`` as the index."""
    with serving(populated_window(clock)) as base_url:
        status, content_type, markup = fetch_index(base_url)

    assert status == HTTPStatus.OK
    assert content_type.startswith(HTML_CONTENT_TYPE)
    assert PAGE_TITLE_MARKUP in markup


@pytest.mark.parametrize(
    "written,normalized",
    [
        (DEFAULT_SUBNET, DEFAULT_SUBNET),
        ("10.11.12.0/255.255.255.0", SECOND_SUBNET),
        ("192.168.2.5", "192.168.2.5/32"),
        (f"  {SECOND_SUBNET}  ", SECOND_SUBNET),
    ],
)
def test_a_valid_subnet_is_normalized(written: str, normalized: str) -> None:
    assert str(parse_subnet(written)) == normalized


@pytest.mark.parametrize("written", INVALID_SUBNETS)
def test_an_unusable_subnet_is_rejected_with_advice(written: str) -> None:
    with pytest.raises(ValueError) as error_info:
        parse_subnet(written)

    assert "CIDR" in str(error_info.value)


def test_filtering_keeps_members_in_order_and_drops_the_unparseable() -> None:
    devices = [{"ip": ip} for ip in (*DEFAULT_SUBNET_IPS, MALFORMED_IP)]

    kept = devices_in_subnet(devices, parse_subnet(DEFAULT_SUBNET))

    assert [device["ip"] for device in kept] == list(DEFAULT_SUBNET_IPS)


def test_filtering_ignores_addresses_of_another_family() -> None:
    devices = [{"ip": "fe80::1"}, {"ip": DEFAULT_SUBNET_IPS[0]}]

    kept = devices_in_subnet(devices, parse_subnet(DEFAULT_SUBNET))

    assert [device["ip"] for device in kept] == [DEFAULT_SUBNET_IPS[0]]


def test_omitting_the_parameter_serves_the_default_subnet(clock: FakeClock) -> None:
    with serving(populated_window(clock)) as base_url:
        response = fetch_rates(base_url)

    assert response.status == HTTPStatus.OK
    assert response.content_type == JSON_CONTENT_TYPE
    assert response.cache_control == NO_STORE
    assert response.body["subnet"] == DEFAULT_SUBNET
    assert response.body["host_ip"] == DEFAULT_HOST_IP
    assert served_ips(response) == list(DEFAULT_SUBNET_IPS)
    assert all(
        len(device["pps"]) == response.body["buckets"]
        for device in response.body["devices"]
    )


def test_the_payload_carries_exactly_the_documented_keys(clock: FakeClock) -> None:
    with serving(populated_window(clock)) as base_url:
        response = fetch_rates(base_url)

    assert set(response.body) == PAYLOAD_KEYS
    assert set(response.body["capture"]) == CAPTURE_KEYS
    assert set(response.body["recording"]) == RECORDING_KEYS


def test_the_capture_status_is_read_again_for_every_poll(clock: FakeClock) -> None:
    """The regression guard for a status frozen at startup.

    A capture that dies at minute nine has to be reported at minute nine: the
    page draws a dead capture as every device falling quiet, which is exactly
    the picture that is supposed to mean a device went quiet.
    """
    live = ChangingStatus(CAPTURE_STATE_OK, CAPTURE_STATE_CAPTURE_DIED)

    with serving(populated_window(clock), read_capture_status=live) as base_url:
        first = fetch_rates(base_url)
        second = fetch_rates(base_url)

    assert first.body["capture"]["state"] == CAPTURE_STATE_OK
    assert second.body["capture"]["state"] == CAPTURE_STATE_CAPTURE_DIED
    assert live.calls == 2


@pytest.mark.parametrize(
    "state", [CAPTURE_STATE_OK, CAPTURE_STATE_CAPTURE_DIED, INVENTED_STATE]
)
def test_the_capture_object_is_always_emitted(clock: FakeClock, state: str) -> None:
    """A payload with no capture object is rendered as healthy by the page."""
    with serving(
        populated_window(clock), read_capture_status=ChangingStatus(state)
    ) as base_url:
        response = fetch_rates(base_url)

    assert response.body["capture"] == capture_status_for(state).as_dict()


def test_a_requested_subnet_overrides_the_default(clock: FakeClock) -> None:
    with serving(populated_window(clock)) as base_url:
        response = fetch_rates(base_url, SECOND_SUBNET)

    assert response.body["subnet"] == SECOND_SUBNET
    assert served_ips(response) == list(SECOND_SUBNET_IPS)


def test_the_default_subnet_comes_from_the_command_line(clock: FakeClock) -> None:
    with serving(populated_window(clock), default_subnet=SECOND_SUBNET) as base_url:
        response = fetch_rates(base_url)

    assert response.body["subnet"] == SECOND_SUBNET
    assert served_ips(response) == list(SECOND_SUBNET_IPS)


@pytest.mark.parametrize(
    "subnet,expected",
    [
        ("10.11.0.0/16", list(SECOND_SUBNET_IPS)),
        ("0.0.0.0/0", [*SECOND_SUBNET_IPS, *DEFAULT_SUBNET_IPS]),
        ("192.168.2.8/30", ["192.168.2.10"]),
        ("172.16.0.0/12", []),
    ],
)
def test_any_prefix_length_is_honoured(
    clock: FakeClock, subnet: str, expected: list[str]
) -> None:
    with serving(populated_window(clock)) as base_url:
        response = fetch_rates(base_url, subnet)

    assert served_ips(response) == expected


def test_the_echoed_subnet_is_the_normalized_one(clock: FakeClock) -> None:
    with serving(populated_window(clock)) as base_url:
        response = fetch_rates(base_url, "10.11.12.0/255.255.255.0")

    assert response.body["subnet"] == SECOND_SUBNET


def test_a_hidden_device_comes_back_with_its_history(clock: FakeClock) -> None:
    """Filtering narrows the view; it must never discard what was recorded."""
    with serving(populated_window(clock)) as base_url:
        before = fetch_rates(base_url)
        hidden = fetch_rates(base_url, SECOND_SUBNET)
        after = fetch_rates(base_url)

    assert not set(served_ips(hidden)) & set(DEFAULT_SUBNET_IPS)
    assert before.body["devices"] == after.body["devices"]
    assert after.body["devices"][0]["total_packets"] == PACKETS_PER_BUCKET


@pytest.mark.parametrize("subnet", INVALID_SUBNETS)
def test_an_unusable_subnet_is_answered_with_a_readable_error(
    clock: FakeClock, subnet: str
) -> None:
    with serving(populated_window(clock)) as base_url:
        response = fetch_rates(base_url, subnet)

    assert response.status == HTTPStatus.BAD_REQUEST
    assert response.content_type == JSON_CONTENT_TYPE
    assert "devices" not in response.body
    assert response.body["error"].endswith(".")
    assert "CIDR" in response.body["error"]


def test_two_pages_can_watch_different_subnets_at_once(clock: FakeClock) -> None:
    """The subnet is a parameter of the read, never remembered by the server."""
    with serving(populated_window(clock)) as base_url:
        fetch_rates(base_url, SECOND_SUBNET)
        follow_up = fetch_rates(base_url)

    assert follow_up.body["subnet"] == DEFAULT_SUBNET
    assert served_ips(follow_up) == list(DEFAULT_SUBNET_IPS)
