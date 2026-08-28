"""Tests for the rates endpoint, its subnet filtering, and the CLI.

The endpoint's contract - what is served, what is filtered out, and what an
unusable subnet gets back - is asserted end to end against a handler running on
a loopback port, fed by a fake-clocked window so nothing sleeps and no reading
depends on real time.
"""

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from email.message import Message
from functools import partial
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest

from netmon import server
from netmon.rate_window import RateWindow
from netmon.server import (
    CAPTURE_STATE_DETAILS,
    CAPTURE_STATE_ERROR,
    CAPTURE_STATE_MOCK,
    DEFAULT_BIND_HOST,
    DEFAULT_HOST_IP,
    DEFAULT_PORT,
    DEFAULT_SUBNET,
    JSON_CONTENT_TYPE,
    NO_STORE,
    RATES_PATH,
    SUBNET_PARAM,
    RatesRequestHandler,
    build_parser,
    capture_status_for,
    devices_in_subnet,
    parse_subnet,
    resolve_capture_status,
)

from .conftest import FakeClock

INVENTED_STATE = "adapter_on_fire"

BUCKET_MS = 250
BUCKET_S = BUCKET_MS / 1000
WINDOW_BUCKETS = 8
PACKETS_PER_BUCKET = 3

INDEX_PATH = "/"
HTML_CONTENT_TYPE = "text/html"
PAGE_TITLE_MARKUP = "<title>Subnet Traffic</title>"

LOOPBACK = "127.0.0.1"
EPHEMERAL_PORT = 0
REQUEST_TIMEOUT_S = 5.0
SHUTDOWN_TIMEOUT_S = 5.0

DEFAULT_SUBNET_IPS = ("192.168.2.2", "192.168.2.10")
SECOND_SUBNET_IPS = ("10.11.12.2", "10.11.12.3")
SECOND_SUBNET = "10.11.12.0/24"
MALFORMED_IP = "not-an-ip"

INVALID_SUBNETS = [
    "nonsense",
    "192.168.2.0/33",
    "192.168.2.1/24",
    "",
    "192.168.2.0/",
    "1.2.3.4.5/24",
]


@dataclass(frozen=True)
class Response:
    """One HTTP answer, decoded."""

    status: int
    content_type: str | None
    cache_control: str | None
    body: dict[str, Any]


def populated_window(clock: FakeClock) -> RateWindow:
    """A window holding one completed bucket of traffic from both subnets."""
    window = RateWindow(bucket_ms=BUCKET_MS, buckets=WINDOW_BUCKETS, clock=clock)
    for ip in (*DEFAULT_SUBNET_IPS, *SECOND_SUBNET_IPS, MALFORMED_IP):
        window.record(ip, PACKETS_PER_BUCKET)
    clock.advance(BUCKET_S)
    return window


@contextmanager
def serving(window: RateWindow, default_subnet: str = DEFAULT_SUBNET) -> Iterator[str]:
    """Run the handler on a loopback port and yield its base URL."""
    handler = partial(
        RatesRequestHandler,
        window=window,
        host_ip=DEFAULT_HOST_IP,
        capture=capture_status_for(CAPTURE_STATE_MOCK),
        default_subnet=parse_subnet(default_subnet),
    )
    httpd = ThreadingHTTPServer((LOOPBACK, EPHEMERAL_PORT), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{LOOPBACK}:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(SHUTDOWN_TIMEOUT_S)


def fetch_rates(base_url: str, subnet: str | None = None) -> Response:
    """GET the rates endpoint, optionally asking for a particular subnet."""
    url = f"{base_url}{RATES_PATH}"
    if subnet is not None:
        url = f"{url}?{SUBNET_PARAM}={quote(subnet, safe='')}"
    try:
        with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT_S) as answer:
            return _decode(answer.status, answer.headers, answer.read())
    except urllib.error.HTTPError as error:
        with error:
            return _decode(error.status, error.headers, error.read())


def _decode(status: int, headers: Message, body: bytes) -> Response:
    return Response(
        status=status,
        content_type=headers.get("Content-Type"),
        cache_control=headers.get("Cache-Control"),
        body=json.loads(body),
    )


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


def test_cli_defaults_match_the_documented_ones() -> None:
    args = build_parser().parse_args([])

    assert args.port == DEFAULT_PORT
    assert args.host == DEFAULT_BIND_HOST
    assert args.host_ip == DEFAULT_HOST_IP
    assert args.subnet == DEFAULT_SUBNET
    assert args.mock is False
    assert args.capture_status is None


def test_cli_accepts_an_invented_capture_state() -> None:
    args = build_parser().parse_args(["--capture-status", INVENTED_STATE])

    assert args.capture_status == INVENTED_STATE


def test_an_unusable_default_subnet_fails_at_startup(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        server.main(["--subnet", "nonsense"])

    assert exit_info.value.code != 0
    assert "CIDR" in capsys.readouterr().err
