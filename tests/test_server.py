"""Tests for the rates endpoint, its subnet filtering, and the CLI.

The endpoint's contract - what is served, what is filtered out, and what an
unusable subnet gets back - is asserted end to end against a handler running on
a loopback port, fed by a fake-clocked window so nothing sleeps and no reading
depends on real time.
"""

import csv
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
from netmon.recorder import IDLE_STATUS, Recorder, RecordingStatus
from netmon.server import (
    BIND_ADVICE,
    CAPTURE_STATE_DETAILS,
    CAPTURE_STATE_ERROR,
    CAPTURE_STATE_MOCK,
    DEFAULT_BIND_HOST,
    DEFAULT_HOST_IP,
    DEFAULT_PORT,
    DEFAULT_RECORDINGS_DIR,
    DEFAULT_SUBNET,
    EXCLUSIVE_PORTS_AVAILABLE,
    JSON_CONTENT_TYPE,
    MAX_BODY_BYTES,
    NO_STORE,
    RATES_PATH,
    RECORD_PATH,
    START_ACTION,
    STOP_ACTION,
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
    "recording",
    "bucket_ms",
    "buckets",
    "now_ms",
    "devices",
}
CAPTURE_KEYS = {"state", "detail"}
RECORDING_KEYS = {"active", "file", "subnet", "rows", "started_ms", "detail"}

# Nothing in these tests starts a recording unless it is handed a recorder of
# its own, so this directory is never created.
UNUSED_RECORDINGS_DIR = Path("recordings-no-test-writes-here")
# Far longer than any test: a recorder under test is ticked by the assertions,
# never by its own thread.
IDLE_TICK_MS = 60 * 60 * 1000
UNKNOWN_ACTION = "pause"
MALFORMED_BODIES = [b"", b"not json at all", b"[1, 2, 3]", b'"start"', b"{"]

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


class StubRecorder:
    """Stands in for the recorder so ``main``'s wiring can be observed."""

    def __init__(
        self, window: RateWindow, recordings_dir: Path, filter_devices: Any
    ) -> None:
        self.window = window
        self.recordings_dir = recordings_dir
        self.filter_devices = filter_devices
        self.stopped = False

    def status(self) -> RecordingStatus:
        return IDLE_STATUS

    def stop(self) -> RecordingStatus:
        self.stopped = True
        return IDLE_STATUS


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


def stub_recorders(monkeypatch: pytest.MonkeyPatch) -> list[StubRecorder]:
    """Replace the CSV recorder with stubs, returning the list."""
    created: list[StubRecorder] = []

    def build(**kwargs: Any) -> StubRecorder:
        stub = StubRecorder(**kwargs)
        created.append(stub)
        return stub

    monkeypatch.setattr(server, "Recorder", build)
    return created


def recorder_for(window: RateWindow, recordings_dir: Path) -> Recorder:
    """A recorder wired exactly as the server wires its own."""
    return Recorder(
        window, recordings_dir, devices_in_subnet, tick_ms=IDLE_TICK_MS
    )


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
    recorder: Recorder | None = None,
) -> Iterator[str]:
    """Run the handler on a loopback port and yield its base URL."""
    recorder = recorder or recorder_for(window, UNUSED_RECORDINGS_DIR)
    handler = partial(
        RatesRequestHandler,
        window=window,
        host_ip=DEFAULT_HOST_IP,
        read_capture_status=read_capture_status
        or partial(capture_status_for, CAPTURE_STATE_MOCK),
        default_subnet=parse_subnet(default_subnet),
        recorder=recorder,
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
        recorder.stop()


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


def post_record(
    base_url: str, payload: Any = None, raw: bytes | None = None
) -> Response:
    """POST the record endpoint, decoding whatever it answers."""
    body = raw if raw is not None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}{RECORD_PATH}",
        data=body,
        method="POST",
        headers={"Content-Type": JSON_CONTENT_TYPE},
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_S) as answer:
            return _decode(answer.status, answer.headers, answer.read())
    except urllib.error.HTTPError as error:
        with error:
            return _decode(error.status, error.headers, error.read())


def post_status(base_url: str, path: str) -> int:
    """The status of a POST whose body is not expected to be JSON."""
    request = urllib.request.Request(
        f"{base_url}{path}", data=b"{}", method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_S) as answer:
            return answer.status
    except urllib.error.HTTPError as error:
        with error:
            return error.status


def start_body(subnet: str = DEFAULT_SUBNET) -> dict[str, str]:
    return {"action": START_ACTION, "subnet": subnet}


STOP_BODY = {"action": STOP_ACTION}


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


def recorded_ips(path: Path) -> set[str]:
    """The addresses a recording actually holds rows for."""
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    return {row[2] for row in rows[1:]}


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


def test_recording_is_reported_on_every_poll_even_when_idle(
    clock: FakeClock,
) -> None:
    """A missing object would read as "not recording" when something broke."""
    with serving(populated_window(clock)) as base_url:
        first = fetch_rates(base_url)
        second = fetch_rates(base_url)

    assert first.body["recording"] == IDLE_STATUS.as_dict()
    assert second.body["recording"] == IDLE_STATUS.as_dict()
    assert first.body["recording"]["rows"] == 0


def test_starting_a_recording_answers_with_the_recording_object(
    clock: FakeClock, tmp_path: Path
) -> None:
    window = populated_window(clock)
    recorder = recorder_for(window, tmp_path)

    with serving(window, recorder=recorder) as base_url:
        answer = post_record(base_url, start_body())
        polled = fetch_rates(base_url)

    assert answer.status == HTTPStatus.OK
    assert answer.content_type == JSON_CONTENT_TYPE
    assert set(answer.body) == RECORDING_KEYS
    assert answer.body["active"] is True
    assert answer.body["subnet"] == DEFAULT_SUBNET
    assert answer.body["rows"] == 0
    assert answer.body["detail"] is None
    assert Path(answer.body["file"]).parent == tmp_path
    assert polled.body["recording"] == answer.body


def test_a_recording_ignores_the_subnet_the_page_moves_on_to(
    clock: FakeClock, tmp_path: Path
) -> None:
    """The file keeps its own subnet; the payload reports both, so the page
    can say they differ."""
    window = populated_window(clock)
    recorder = recorder_for(window, tmp_path)

    with serving(window, recorder=recorder) as base_url:
        started = post_record(base_url, start_body())
        clock.advance(BUCKET_S)
        recorder.tick()
        elsewhere = fetch_rates(base_url, SECOND_SUBNET)
        post_record(base_url, STOP_BODY)

    assert elsewhere.body["subnet"] == SECOND_SUBNET
    assert elsewhere.body["recording"]["subnet"] == DEFAULT_SUBNET
    assert recorded_ips(Path(started.body["file"])) == set(DEFAULT_SUBNET_IPS)


def test_a_second_start_is_refused_with_the_recording_already_running(
    clock: FakeClock, tmp_path: Path
) -> None:
    """The loser of a two-tab race re-syncs rather than opening a new file."""
    window = populated_window(clock)
    recorder = recorder_for(window, tmp_path)

    with serving(window, recorder=recorder) as base_url:
        first = post_record(base_url, start_body())
        second = post_record(base_url, start_body(SECOND_SUBNET))
        post_record(base_url, STOP_BODY)

    assert second.status == HTTPStatus.CONFLICT
    assert second.body == first.body
    assert second.body["subnet"] == DEFAULT_SUBNET
    assert len(list(tmp_path.iterdir())) == 1


def test_stopping_answers_with_the_final_tally(
    clock: FakeClock, tmp_path: Path
) -> None:
    window = populated_window(clock)
    recorder = recorder_for(window, tmp_path)

    with serving(window, recorder=recorder) as base_url:
        started = post_record(base_url, start_body())
        clock.advance(BUCKET_S)
        recorder.tick()
        stopped = post_record(base_url, STOP_BODY)
        after = fetch_rates(base_url)

    assert stopped.status == HTTPStatus.OK
    assert stopped.body["active"] is False
    assert stopped.body["file"] == started.body["file"]
    assert stopped.body["rows"] == len(DEFAULT_SUBNET_IPS)
    assert after.body["recording"] == IDLE_STATUS.as_dict()


@pytest.mark.parametrize("repeats", [1, 2])
def test_a_stop_with_nothing_recording_is_not_an_error(
    clock: FakeClock, repeats: int
) -> None:
    """The desired end state already holds; a second click is not a fault."""
    with serving(populated_window(clock)) as base_url:
        answers = [post_record(base_url, STOP_BODY) for _ in range(repeats)]

    assert [answer.status for answer in answers] == [HTTPStatus.OK] * repeats
    assert all(answer.body == IDLE_STATUS.as_dict() for answer in answers)


@pytest.mark.parametrize("body", [{"action": UNKNOWN_ACTION}, {}, {"subnet": "x"}])
def test_an_action_the_server_does_not_know_is_rejected(
    clock: FakeClock, body: dict[str, str]
) -> None:
    with serving(populated_window(clock)) as base_url:
        response = post_record(base_url, body)

    assert response.status == HTTPStatus.BAD_REQUEST
    assert response.content_type == JSON_CONTENT_TYPE
    assert response.body["error"].endswith(".")
    assert START_ACTION in response.body["error"]


@pytest.mark.parametrize("raw", MALFORMED_BODIES)
def test_a_body_that_is_not_a_json_object_is_rejected(
    clock: FakeClock, raw: bytes
) -> None:
    with serving(populated_window(clock)) as base_url:
        response = post_record(base_url, raw=raw)

    assert response.status == HTTPStatus.BAD_REQUEST
    assert response.body["error"].endswith(".")
    assert "devices" not in response.body


def test_a_body_larger_than_a_record_request_is_refused(clock: FakeClock) -> None:
    oversized = b'{"action": "start", "subnet": "' + b"9" * MAX_BODY_BYTES + b'"}'

    with serving(populated_window(clock)) as base_url:
        response = post_record(base_url, raw=oversized)

    assert response.status == HTTPStatus.BAD_REQUEST
    assert response.body["error"].endswith(".")


@pytest.mark.parametrize("subnet", INVALID_SUBNETS)
def test_a_recording_of_an_unusable_subnet_is_refused(
    clock: FakeClock, subnet: str, tmp_path: Path
) -> None:
    """Validated exactly as the query parameter is, and never opens a file."""
    window = populated_window(clock)
    recorder = recorder_for(window, tmp_path)

    with serving(window, recorder=recorder) as base_url:
        response = post_record(base_url, start_body(subnet))

    assert response.status == HTTPStatus.BAD_REQUEST
    assert "CIDR" in response.body["error"]
    assert not list(tmp_path.iterdir())


def test_a_recording_that_cannot_be_opened_answers_500_naming_the_path(
    clock: FakeClock, tmp_path: Path
) -> None:
    """The one failure the operator can act on has to say where it happened."""
    blocked = tmp_path / "in-the-way"
    blocked.write_text("not a directory", encoding="utf-8")
    window = populated_window(clock)

    with serving(
        window, recorder=recorder_for(window, blocked / "recordings")
    ) as base_url:
        response = post_record(base_url, start_body())
        polled = fetch_rates(base_url)

    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    assert str(blocked) in response.body["error"]
    assert polled.body["recording"] == IDLE_STATUS.as_dict()


def test_a_post_to_any_other_path_is_not_found(clock: FakeClock) -> None:
    with serving(populated_window(clock)) as base_url:
        assert post_status(base_url, RATES_PATH) == HTTPStatus.NOT_FOUND


def test_cli_defaults_match_the_documented_ones() -> None:
    args = build_parser().parse_args([])

    assert args.port == DEFAULT_PORT
    assert args.host == DEFAULT_BIND_HOST
    assert args.host_ip == DEFAULT_HOST_IP
    assert args.subnet == DEFAULT_SUBNET
    assert args.iface is None
    assert args.mock is False
    assert args.capture_status is None
    assert args.recordings_dir == DEFAULT_RECORDINGS_DIR


def test_the_default_recordings_directory_sits_beside_the_program() -> None:
    package_root = Path(server.__file__).resolve().parent

    assert DEFAULT_RECORDINGS_DIR == package_root.parent / "recordings"


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


def test_the_recordings_directory_comes_from_the_command_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    recording_sources(monkeypatch)
    recorders = stub_recorders(monkeypatch)

    code, stub = run_main(monkeypatch, ["--recordings-dir", str(tmp_path)])

    assert code == 0
    assert recorders[0].recordings_dir == tmp_path
    # The endpoint's own filter, not a second implementation of it.
    assert recorders[0].filter_devices is devices_in_subnet
    assert stub.handler.keywords["recorder"] is recorders[0]


def test_an_interrupted_run_closes_the_recording_as_well(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ctrl+C has to leave a flushed, closed CSV, not a half-written one."""
    recording_sources(monkeypatch)
    recorders = stub_recorders(monkeypatch)

    code, _ = run_main(monkeypatch, [])

    assert code == 0
    assert recorders[0].stopped is True


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
