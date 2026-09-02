"""Tests for the command line, the wiring it produces, and binding a port.

``main`` is run in-process against a stub server whose ``serve_forever``
raises the interrupt a Ctrl+C would, so startup and shutdown are both
exercised without a real socket or a real wait. What the flags reach is
asserted on the objects ``main`` actually built rather than on their
behaviour, since the capture source is the one thing these tests must not
open. The binding rules need real sockets and get them.
"""

import socket
import subprocess
import sys
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from netmon import server
from netmon.capture import (
    CAPTURE_STATE_CAPTURE_DIED,
    CAPTURE_STATE_NOT_RUNNING,
    CAPTURE_STATE_OK,
    CaptureSource,
    CaptureStatus,
)
from netmon.mock_source import MockSource
from netmon.rate_window import RateWindow
from netmon.recorder import IDLE_STATUS, RecordingStatus
from netmon.server import (
    BIND_ADVICE,
    CAPTURE_STATE_MOCK,
    DEFAULT_BIND_HOST,
    DEFAULT_HOST_IP,
    DEFAULT_PORT,
    DEFAULT_RECORDINGS_DIR,
    DEFAULT_SUBNET,
    EXCLUSIVE_PORTS_AVAILABLE,
    ExclusivePortHTTPServer,
    browse_url,
    build_parser,
    build_source,
    capture_status_for,
    devices_in_subnet,
)

from .conftest import (
    BUCKET_MS,
    EPHEMERAL_PORT,
    INVENTED_STATE,
    LOOPBACK,
    WINDOW_BUCKETS,
    FakeClock,
    fetch_rates,
    populated_window,
    serving,
)

IFACE = "\\Device\\NPF_{11111111-1111-1111-1111-111111111111}"

REPO_ROOT = Path(__file__).resolve().parents[1]

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


@pytest.mark.parametrize(
    "host,port,url",
    [
        ("0.0.0.0", 8765, "http://localhost:8765/"),
        ("::", 8765, "http://localhost:8765/"),
        ("127.0.0.1", 8765, "http://127.0.0.1:8765/"),
        ("192.168.2.1", 8080, "http://192.168.2.1:8080/"),
        ("::1", 8765, "http://[::1]:8765/"),
        ("[::1]", 8765, "http://[::1]:8765/"),
    ],
)
def test_browse_url_is_a_destination_the_browser_can_open(
    host: str, port: int, url: str
) -> None:
    assert browse_url(host, port) == url


def test_startup_banner_names_localhost_not_the_bind_all_address(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    recording_sources(monkeypatch)

    run_main(monkeypatch, ["--port", "8765"])
    out = capsys.readouterr().out

    assert "http://localhost:8765/" in out
    assert "http://0.0.0.0:" not in out


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
