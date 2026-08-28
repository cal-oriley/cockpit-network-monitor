"""Tests for the rates endpoint, its subnet filtering, and the CLI.

The endpoint's contract - what is served, what is filtered out, and what an
unusable subnet gets back - is asserted end to end against a handler running on
a loopback port, fed by a fake-clocked window so nothing sleeps and no reading
depends on real time.
"""

import json
import socket
import subprocess
import sys
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
from urllib.parse import quote, urlsplit

import pytest

from netmon import server
from netmon.capture import (
    CAPTURE_STATE_CAPTURE_DIED,
    CAPTURE_STATE_DROPPING_PACKETS,
    CAPTURE_STATE_NOT_RUNNING,
    CAPTURE_STATE_OK,
    CaptureSource,
    CaptureStatus,
)
from netmon.mock_source import MockSource
from netmon.rate_window import RateWindow
from netmon.server import (
    BIND_ADVICE,
    CAPTURE_STATE_DETAILS,
    CAPTURE_STATE_ERROR,
    CAPTURE_STATE_MOCK,
    DEFAULT_BIND_HOST,
    DEFAULT_HOST_IP,
    DEFAULT_PORT,
    DEFAULT_SUBNET,
    EXCLUSIVE_PORTS_AVAILABLE,
    JSON_CONTENT_TYPE,
    NO_STORE,
    RATES_PATH,
    SUBNET_PARAM,
    UNKNOWN_CAPTURE_DETAIL,
    CaptureStatusReader,
    ExclusivePortHTTPServer,
    RatesRequestHandler,
    build_parser,
    build_source,
    capture_status_for,
    capture_status_reader,
    devices_in_subnet,
    parse_subnet,
)

from .conftest import FakeClock

INVENTED_STATE = "adapter_on_fire"
IFACE = "\\Device\\NPF_{11111111-1111-1111-1111-111111111111}"

BUCKET_MS = 250
BUCKET_S = BUCKET_MS / 1000
WINDOW_BUCKETS = 8
PACKETS_PER_BUCKET = 3

PAYLOAD_KEYS = {
    "host_ip",
    "subnet",
    "capture",
    "bucket_ms",
    "buckets",
    "now_ms",
    "devices",
}
CAPTURE_KEYS = {"state", "detail"}

REPO_ROOT = Path(__file__).resolve().parents[1]

INDEX_PATH = "/"
HTML_CONTENT_TYPE = "text/html"
PAGE_TITLE_MARKUP = "<title>Subnet Traffic</title>"

LOOPBACK = "127.0.0.1"
EPHEMERAL_PORT = 0
REQUEST_TIMEOUT_S = 5.0
SHUTDOWN_TIMEOUT_S = 5.0

RESTART_CYCLES = 3
SERVER_MODULE = "netmon.server"
# Only ever waited out by a server that wrongly stays up, since a refused start
# returns at once.
STARTUP_TIMEOUT_S = 20.0
# Stock ``ThreadingHTTPServer`` stands in for a server left over from an older
# build, which is how the port came to be occupied in the first place.
INCUMBENT_SERVERS = [ThreadingHTTPServer, ExclusivePortHTTPServer]
SHARED_PORTS_REASON = (
    "Only Windows lets a second socket bind a port already in LISTEN, so only "
    "there can a server be started that receives nothing."
)

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


class StubHTTPServer:
    """Stands in for ``ThreadingHTTPServer`` so ``main`` can be run in-process.

    ``serve_forever`` raises the interrupt a Ctrl+C would, which is also how
    the shutdown path gets exercised without a real socket or a real wait.
    """

    def __init__(self, address: tuple[str, int], handler: Any) -> None:
        self.address = address
        self.handler = handler
        self.daemon_threads = False
        self.closed = False

    def serve_forever(self) -> None:
        raise KeyboardInterrupt

    def server_close(self) -> None:
        self.closed = True


class RecordingSource:
    """Records how the server built it, and never opens a capture."""

    def __init__(self, window: RateWindow, host_ip: str, iface: str | None) -> None:
        self.window = window
        self.host_ip = host_ip
        self.iface = iface
        self.state = CAPTURE_STATE_OK
        self.started = False
        self.stopped = False

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True

    def status(self) -> CaptureStatus:
        return capture_status_for(self.state)


def run_main(
    monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> tuple[int, StubHTTPServer]:
    """Run ``main`` against a stub server, returning its code and that stub."""
    built: list[StubHTTPServer] = []

    def build(address: tuple[str, int], handler: Any) -> StubHTTPServer:
        stub = StubHTTPServer(address, handler)
        built.append(stub)
        return stub

    monkeypatch.setattr(server, "ExclusivePortHTTPServer", build)
    code = server.main(argv)
    return code, built[0]


def recording_sources(monkeypatch: pytest.MonkeyPatch) -> list[RecordingSource]:
    """Replace the real capture source with recorders, returning the list."""
    created: list[RecordingSource] = []

    def build(window: RateWindow, host_ip: str, iface: str | None) -> RecordingSource:
        source = RecordingSource(window, host_ip, iface)
        created.append(source)
        return source

    monkeypatch.setattr(server, "CaptureSource", build)
    return created


def populated_window(clock: FakeClock) -> RateWindow:
    """A window holding one completed bucket of traffic from both subnets."""
    window = RateWindow(bucket_ms=BUCKET_MS, buckets=WINDOW_BUCKETS, clock=clock)
    for ip in (*DEFAULT_SUBNET_IPS, *SECOND_SUBNET_IPS, MALFORMED_IP):
        window.record(ip, PACKETS_PER_BUCKET)
    clock.advance(BUCKET_S)
    return window


@contextmanager
def serving(
    window: RateWindow,
    default_subnet: str = DEFAULT_SUBNET,
    read_capture_status: CaptureStatusReader | None = None,
    port: int = EPHEMERAL_PORT,
    server_class: type[ThreadingHTTPServer] = ThreadingHTTPServer,
) -> Iterator[str]:
    """Run the handler on a loopback port and yield its base URL."""
    handler = partial(
        RatesRequestHandler,
        window=window,
        host_ip=DEFAULT_HOST_IP,
        read_capture_status=read_capture_status
        or partial(capture_status_for, CAPTURE_STATE_MOCK),
        default_subnet=parse_subnet(default_subnet),
    )
    httpd = server_class((LOOPBACK, port), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{LOOPBACK}:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(SHUTDOWN_TIMEOUT_S)


def port_of(base_url: str) -> int:
    """The port a ``serving`` base URL was handed."""
    port = urlsplit(base_url).port
    assert port is not None
    return port


def free_loopback_port() -> int:
    """A loopback port nothing holds, released before it is returned."""
    with socket.socket() as probe:
        probe.bind((LOOPBACK, EPHEMERAL_PORT))
        return probe.getsockname()[1]


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


def test_cli_defaults_match_the_documented_ones() -> None:
    args = build_parser().parse_args([])

    assert args.port == DEFAULT_PORT
    assert args.host == DEFAULT_BIND_HOST
    assert args.host_ip == DEFAULT_HOST_IP
    assert args.subnet == DEFAULT_SUBNET
    assert args.iface is None
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


@pytest.mark.skipif(not EXCLUSIVE_PORTS_AVAILABLE, reason=SHARED_PORTS_REASON)
@pytest.mark.parametrize("incumbent", INCUMBENT_SERVERS)
def test_a_port_already_being_served_is_refused_at_startup(
    clock: FakeClock, incumbent: type[ThreadingHTTPServer]
) -> None:
    """The regression guard for a second server that receives nothing.

    Windows hands a port already in LISTEN to a second socket, so the server
    just started sits idle while the one already there answers every poll -
    which the page cannot tell apart from working software serving the wrong
    data. Starting has to fail instead, name the address, and exit non-zero.

    Run as its own process because that is what the failure looks like: a
    server that gets this wrong does not return at all, it serves nobody
    forever, so the timeout is the assertion that it exited.
    """
    with serving(
        populated_window(clock), port=free_loopback_port(), server_class=incumbent
    ) as base_url:
        port = port_of(base_url)
        rival = subprocess.run(
            [
                sys.executable,
                "-m",
                SERVER_MODULE,
                "--mock",
                "--host",
                LOOPBACK,
                "--port",
                str(port),
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            timeout=STARTUP_TIMEOUT_S,
        )

    assert rival.returncode != 0
    assert f"{LOOPBACK}:{port}" in rival.stderr
    assert BIND_ADVICE in rival.stderr


def test_a_port_just_released_can_be_served_again_at_once(clock: FakeClock) -> None:
    """Refusing to share a port must not also refuse a restart.

    Stop and start again on the same port is the every-few-minutes loop of
    working on this program, so a bind that had to wait out the sockets the
    previous run left behind would cost more than the hijack it prevents.
    """
    port = free_loopback_port()

    for _ in range(RESTART_CYCLES):
        with serving(
            populated_window(clock), port=port, server_class=ExclusivePortHTTPServer
        ) as base_url:
            assert fetch_rates(base_url).status == HTTPStatus.OK


def test_the_mock_flag_selects_synthetic_traffic(clock: FakeClock) -> None:
    window = RateWindow(bucket_ms=BUCKET_MS, buckets=WINDOW_BUCKETS, clock=clock)

    source = build_source(
        window, mock=True, host_ip=DEFAULT_HOST_IP, iface=None
    )

    assert isinstance(source, MockSource)
    assert source.status().state == CAPTURE_STATE_MOCK


def test_without_the_mock_flag_a_real_capture_source_is_built(
    clock: FakeClock,
) -> None:
    window = RateWindow(bucket_ms=BUCKET_MS, buckets=WINDOW_BUCKETS, clock=clock)

    source = build_source(
        window, mock=False, host_ip=DEFAULT_HOST_IP, iface=None
    )

    assert isinstance(source, CaptureSource)
    assert source.status().state == CAPTURE_STATE_NOT_RUNNING
    assert source.running is False


def test_the_mock_path_never_reaches_scapy() -> None:
    """``--mock`` has to keep working on a machine with no scapy installed."""
    probe = (
        "import sys;"
        "from netmon.rate_window import RateWindow;"
        "from netmon.server import build_source;"
        "build_source(RateWindow(), mock=True,"
        f" host_ip={DEFAULT_HOST_IP!r}, iface=None);"
        "print(any(m == 'scapy' or m.startswith('scapy.') for m in sys.modules))"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=True,
    )

    assert result.stdout.strip() == "False"


def test_the_handler_is_given_the_sources_own_live_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Binding the method, not its answer, is what keeps the status live."""
    sources = recording_sources(monkeypatch)

    code, stub = run_main(monkeypatch, [])
    reader = stub.handler.keywords["read_capture_status"]
    sources[0].state = CAPTURE_STATE_CAPTURE_DIED

    assert code == 0
    assert reader().state == CAPTURE_STATE_CAPTURE_DIED


@pytest.mark.parametrize("argv,expected", [([], None), (["--iface", IFACE], IFACE)])
def test_the_interface_flag_reaches_the_capture_source(
    monkeypatch: pytest.MonkeyPatch, argv: list[str], expected: str | None
) -> None:
    sources = recording_sources(monkeypatch)

    server_code, _ = run_main(monkeypatch, argv)

    assert server_code == 0
    assert sources[0].iface == expected
    assert sources[0].host_ip == DEFAULT_HOST_IP


def test_a_forced_state_still_wins_once_the_server_is_wired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources = recording_sources(monkeypatch)

    _, stub = run_main(monkeypatch, ["--capture-status", INVENTED_STATE])
    reader = stub.handler.keywords["read_capture_status"]

    assert reader().state == INVENTED_STATE
    assert sources[0].started is True


def test_an_interrupted_run_shuts_the_source_down_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ctrl+C must leave neither a traceback nor a capture still running."""
    sources = recording_sources(monkeypatch)

    code, stub = run_main(monkeypatch, [])

    assert code == 0
    assert sources[0].started is True
    assert sources[0].stopped is True
    assert stub.closed is True


def test_an_interrupt_while_the_capture_opens_still_stops_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opening a capture waits on confirmation, so Ctrl+C can land there."""

    def interrupted_start(self: RecordingSource) -> None:
        self.started = True
        raise KeyboardInterrupt

    sources = recording_sources(monkeypatch)
    monkeypatch.setattr(RecordingSource, "start", interrupted_start)

    code, stub = run_main(monkeypatch, [])

    assert code == 0
    assert sources[0].stopped is True
    assert stub.closed is True
