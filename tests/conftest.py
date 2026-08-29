"""Shared fixtures, and the harness the HTTP tests drive the server through.

Everything time-dependent in ``netmon`` takes an injectable clock, so the
tests advance time by hand rather than sleeping.

The endpoints are asserted end to end rather than by calling the handler
directly: ``serving`` runs a real handler on a loopback port, fed by a
fake-clocked window so nothing sleeps and no reading depends on real time,
and the request helpers decode whatever comes back. The rates endpoint, the
record endpoint and the CLI have a test module each, and all three reach the
server through here.
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
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest

from netmon.rate_window import RateWindow
from netmon.recorder import Recorder
from netmon.server import (
    CAPTURE_STATE_MOCK,
    DEFAULT_HOST_IP,
    DEFAULT_SUBNET,
    JSON_CONTENT_TYPE,
    RATES_PATH,
    RECORD_PATH,
    SUBNET_PARAM,
    CaptureStatusReader,
    RatesRequestHandler,
    capture_status_for,
    devices_in_subnet,
    parse_subnet,
)

MS_PER_SECOND = 1000

BUCKET_MS = 250
BUCKET_S = BUCKET_MS / MS_PER_SECOND
WINDOW_BUCKETS = 8
PACKETS_PER_BUCKET = 3

INVENTED_STATE = "adapter_on_fire"

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

RECORDING_KEYS = {"active", "file", "subnet", "rows", "started_ms", "detail"}

# Nothing in these tests starts a recording unless it is handed a recorder of
# its own, so this directory is never created.
UNUSED_RECORDINGS_DIR = Path("recordings-no-test-writes-here")
# Far longer than any test: a recorder under test is ticked by the assertions,
# never by its own thread.
IDLE_TICK_MS = 60 * 60 * 1000

LOOPBACK = "127.0.0.1"
EPHEMERAL_PORT = 0
REQUEST_TIMEOUT_S = 5.0
SHUTDOWN_TIMEOUT_S = 5.0


class FakeClock:
    """Deterministic stand-in for ``time.monotonic``, in seconds."""

    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def advance_ms(self, milliseconds: float) -> None:
        self.now += milliseconds / MS_PER_SECOND


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@dataclass(frozen=True)
class Response:
    """One HTTP answer, decoded."""

    status: int
    content_type: str | None
    cache_control: str | None
    body: dict[str, Any]


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


def _decode(status: int, headers: Message, body: bytes) -> Response:
    return Response(
        status=status,
        content_type=headers.get("Content-Type"),
        cache_control=headers.get("Cache-Control"),
        body=json.loads(body),
    )
