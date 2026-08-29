"""HTTP server for the network monitor: static UI plus ``GET /api/rates``.

ponytail: the whole web stack is the standard library's
:class:`~http.server.ThreadingHTTPServer`. Ceiling - request/response only, so
no server push (SSE or WebSocket), no async, and one thread per connection,
which a 2 Hz poll from a handful of browser tabs does not strain. Upgrade path
- if push updates are ever wanted, drop in FastAPI + uvicorn behind the same
``/api/rates`` shape.
"""

import argparse
import ipaddress
import json
import socket
import sys
from collections.abc import Callable, Iterable, Sequence
from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .capture import (
    CAPTURE_STATE_CAPTURE_DIED,
    CAPTURE_STATE_DROPPING_PACKETS,
    CAPTURE_STATE_ERROR,
    CAPTURE_STATE_INTERFACE_MISSING,
    CAPTURE_STATE_NEEDS_ELEVATION,
    CAPTURE_STATE_NOT_RUNNING,
    CAPTURE_STATE_NPCAP_MISSING,
    CAPTURE_STATE_OK,
    CAPTURE_STATE_UNSUPPORTED_PLATFORM,
    CaptureSource,
    CaptureStatus,
)
from .mock_source import CAPTURE_STATE_MOCK, MOCK_DETAIL, MockSource
from .rate_window import RateWindow
from .recorder import (
    AlreadyRecordingError,
    IPNetwork,
    Recorder,
    RecordingStartError,
)

DEFAULT_PORT = 8080
DEFAULT_BIND_HOST = "0.0.0.0"
DEFAULT_HOST_IP = "192.168.2.1"
DEFAULT_SUBNET = "192.168.2.0/24"

RATES_PATH = "/api/rates"
RECORD_PATH = "/api/record"
SUBNET_PARAM = "subnet"
JSON_CONTENT_TYPE = "application/json"
NO_STORE = "no-store"

ACTION_KEY = "action"
# The body names its subnet field after the query parameter it mirrors: a
# subnet is validated the same way whichever way it arrives.
SUBNET_KEY = SUBNET_PARAM
START_ACTION = "start"
STOP_ACTION = "stop"
CONTENT_LENGTH_HEADER = "Content-Length"
# A record request is two short fields. Anything larger is not one, and the
# body is read into memory before it can be judged.
MAX_BODY_BYTES = 64 * 1024

SUBNET_ADVICE = f"Enter a subnet in CIDR form, such as {DEFAULT_SUBNET}."
BIND_ADVICE = "Another server may already be running on this port."

MISSING_LENGTH_ERROR = "The request needs a Content-Length header."
BODY_TOO_LARGE_ERROR = "The request body is larger than {limit:,} bytes."
INVALID_JSON_ERROR = "The request body is not valid JSON: {error}."
NOT_AN_OBJECT_ERROR = "The request body must be a JSON object."
UNKNOWN_ACTION_ERROR = (
    "Unknown action {action!r}. Use {start!r} to begin a recording or "
    "{stop!r} to end one."
)

# Windows and Unix disagree about what SO_REUSEADDR permits, and the difference
# is the whole reason this is not just the stock server. On Unix it only lets a
# port lingering in TIME_WAIT be rebound; a live listener still cannot be
# hijacked, so it is genuinely wanted there and a restart is never blocked. On
# Windows it also lets a second socket bind a port that is already in LISTEN,
# and which of the two processes then receives a given connection is undefined:
# a stale server goes on answering while the one just started receives nothing.
# SO_EXCLUSIVEADDRUSE, which exists only on Windows, is the documented way to
# refuse that bind, and it does not stand in the way of an immediate restart.
EXCLUSIVE_PORTS_AVAILABLE = hasattr(socket, "SO_EXCLUSIVEADDRUSE")

# Both sources satisfy this, which is what lets the handler ask for the current
# capture health while it builds each response instead of being handed a value
# that was true only at startup.
CaptureStatusReader = Callable[[], CaptureStatus]
PacketSource = CaptureSource | MockSource

# Resolved from the package location so the server works from any working
# directory - it is routinely launched from somewhere other than the repo root.
WEB_DIRECTORY = Path(__file__).resolve().parent.parent / "web"
DEFAULT_RECORDINGS_DIR = Path(__file__).resolve().parent.parent / "recordings"

# Sentences for a state named on the command line, where none of the context a
# real capture reports - the address, the platform, the driver's own message -
# is available. The live sources word their own details from what they observed.
CAPTURE_STATE_DETAILS: dict[str, str] = {
    CAPTURE_STATE_OK: "Capturing live traffic.",
    CAPTURE_STATE_MOCK: MOCK_DETAIL,
    CAPTURE_STATE_NEEDS_ELEVATION: (
        "Packet capture needs Administrator rights; restart this program as an "
        "administrator."
    ),
    CAPTURE_STATE_NPCAP_MISSING: (
        "Npcap is not installed. Install it from npcap.com, then restart this "
        "program to capture live traffic."
    ),
    CAPTURE_STATE_INTERFACE_MISSING: (
        "No network interface for the vehicle subnet was found; check that the "
        "tether is connected and the adapter still holds its static address."
    ),
    CAPTURE_STATE_UNSUPPORTED_PLATFORM: (
        "Packet capture is only available on Windows in this release."
    ),
    CAPTURE_STATE_NOT_RUNNING: (
        "Packet capture is not running; restart this program to see live "
        "traffic."
    ),
    CAPTURE_STATE_CAPTURE_DIED: (
        "Packet capture stopped unexpectedly after starting, so these rates "
        "are no longer live; restart this program."
    ),
    CAPTURE_STATE_DROPPING_PACKETS: (
        "Packets are reaching the capture driver faster than they can be "
        "counted, so every rate shown here is undercounted."
    ),
    CAPTURE_STATE_ERROR: "Packet capture failed.",
}

UNKNOWN_CAPTURE_DETAIL = "Packet capture reported an unrecognised state: {state}."


def capture_status_for(state: str) -> CaptureStatus:
    """Pair a capture state with its human-readable sentence.

    Unrecognised states are accepted rather than rejected: the UI treats the
    state list as open and falls through to its warning banner, which is what
    lets a later phase introduce failure states without touching the frontend.
    """
    detail = CAPTURE_STATE_DETAILS.get(state) or UNKNOWN_CAPTURE_DETAIL.format(
        state=state
    )
    return CaptureStatus(state=state, detail=detail)


def capture_status_reader(
    live: CaptureStatusReader, forced: str | None
) -> CaptureStatusReader:
    """Choose what the handler asks for the capture status.

    Normally that is the source's own live reader, so a capture that dies at
    minute nine is reported at minute nine. An explicit ``--capture-status``
    wins, since its whole purpose is reviewing a state the machine at hand
    cannot actually produce; it is supplied as a constant reader so both paths
    go through the same mechanism.
    """
    if forced is None:
        return live
    return partial(capture_status_for, forced)


def build_source(
    window: RateWindow, mock: bool, host_ip: str, iface: str | None
) -> PacketSource:
    """The packet source the flags ask for.

    A :class:`CaptureSource` is constructed only when one is actually wanted,
    so ``--mock`` still runs on a machine with no scapy installed.
    """
    if mock:
        return MockSource(window)
    return CaptureSource(window, host_ip, iface)


def parse_subnet(value: str) -> IPNetwork:
    """Validate a CIDR string and return the network it names.

    The ``ValueError`` message is written to be read by the operator: it is
    shown verbatim beside the page's subnet field and on the command line.
    """
    cidr = value.strip()
    if not cidr:
        raise ValueError(f"No subnet given. {SUBNET_ADVICE}")
    try:
        return ipaddress.ip_network(cidr)
    except ValueError as error:
        raise ValueError(f"{error}. {SUBNET_ADVICE}") from error


def devices_in_subnet(
    devices: Iterable[dict[str, Any]], network: IPNetwork
) -> list[dict[str, Any]]:
    """Keep the devices whose address is a member of ``network``, in order.

    An address that will not parse is dropped rather than raised on: the
    aggregator stores whatever the packet source hands it, and one malformed
    key must not be able to break every poll.
    """
    members: list[dict[str, Any]] = []
    for device in devices:
        try:
            address = ipaddress.ip_address(str(device["ip"]))
        except ValueError:
            continue
        if address in network:
            members.append(device)
    return members


class RatesRequestHandler(SimpleHTTPRequestHandler):
    """Serves the ``web/`` directory, intercepting the rates endpoint."""

    def __init__(
        self,
        *args: Any,
        window: RateWindow,
        host_ip: str,
        read_capture_status: CaptureStatusReader,
        default_subnet: IPNetwork,
        recorder: Recorder,
        **kwargs: Any,
    ) -> None:
        self._window = window
        self._host_ip = host_ip
        self._read_capture_status = read_capture_status
        self._default_subnet = default_subnet
        self._recorder = recorder
        # The base class handles the whole request from within __init__, so
        # everything the handler needs must already be attached.
        super().__init__(*args, directory=str(WEB_DIRECTORY), **kwargs)

    def do_GET(self) -> None:
        if urlsplit(self.path).path == RATES_PATH:
            self._send_rates()
            return
        super().do_GET()

    def do_POST(self) -> None:
        if urlsplit(self.path).path == RECORD_PATH:
            self._handle_record()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def log_message(self, format: str, *args: Any) -> None:
        """Stay quiet: a 2 Hz poll would otherwise flood the console."""

    def _send_rates(self) -> None:
        """Answer one poll, narrowed to the subnet it asked for.

        The requested subnet is a parameter of the read and is never retained,
        so two pages can watch different subnets against one process. The
        capture status is read here too, for the same reason in reverse: a
        status resolved once at startup could never report a capture that died
        afterwards, and the page renders a dead capture as every device going
        quiet.
        """
        requested = parse_qs(
            urlsplit(self.path).query, keep_blank_values=True
        ).get(SUBNET_PARAM)
        if requested is None:
            network = self._default_subnet
        else:
            try:
                network = parse_subnet(requested[-1])
            except ValueError as error:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return

        snapshot = self._window.snapshot()
        snapshot["devices"] = devices_in_subnet(snapshot["devices"], network)
        self._send_json(
            HTTPStatus.OK,
            {
                "host_ip": self._host_ip,
                "subnet": str(network),
                "capture": self._read_capture_status().as_dict(),
                # Always present, even idle: a missing object would read as
                # "not recording" at exactly the moment something went wrong.
                "recording": self._recorder.status().as_dict(),
                **snapshot,
            },
        )

    def _handle_record(self) -> None:
        """Start or stop the recording.

        The handler never writes a row itself. It only flips the recorder,
        which owns the file and the thread that fills it, so a slow disk cannot
        stall the poll on the other end of this server.
        """
        try:
            body = self._read_json_body()
        except ValueError as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return

        action = body.get(ACTION_KEY)
        if action == STOP_ACTION:
            self._send_json(HTTPStatus.OK, self._recorder.stop().as_dict())
            return
        if action != START_ACTION:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "error": UNKNOWN_ACTION_ERROR.format(
                        action=action, start=START_ACTION, stop=STOP_ACTION
                    )
                },
            )
            return

        requested = body.get(SUBNET_KEY)
        try:
            network = parse_subnet("" if requested is None else str(requested))
        except ValueError as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return

        try:
            status = self._recorder.start(network)
        except AlreadyRecordingError:
            # The current recording, not an argument about it: two tabs are
            # possible, and the loser should re-sync rather than quietly
            # destroying the other's file by opening a new one.
            self._send_json(HTTPStatus.CONFLICT, self._recorder.status().as_dict())
            return
        except RecordingStartError as error:
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(error)}
            )
            return
        self._send_json(HTTPStatus.OK, status.as_dict())

    def _read_json_body(self) -> dict[str, Any]:
        """Decode the request body, or raise ``ValueError`` with a sentence.

        Everything here is a trust boundary: the length is declared by the
        caller, the bytes are whatever they sent, and both are believed only as
        far as they can be checked.
        """
        try:
            length = int(self.headers.get(CONTENT_LENGTH_HEADER, 0))
        except ValueError as error:
            raise ValueError(MISSING_LENGTH_ERROR) from error
        if length > MAX_BODY_BYTES:
            # The unread remainder would otherwise be parsed as the next
            # request on this connection.
            self.close_connection = True
            raise ValueError(BODY_TOO_LARGE_ERROR.format(limit=MAX_BODY_BYTES))

        raw = self.rfile.read(max(0, length))
        try:
            body = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ValueError(INVALID_JSON_ERROR.format(error=error)) from error
        if not isinstance(body, dict):
            raise ValueError(NOT_AN_OBJECT_ERROR)
        return body

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        """Write ``payload`` as an uncacheable JSON response."""
        body = json.dumps(payload).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", JSON_CONTENT_TYPE)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", NO_STORE)
            self.end_headers()
            self.wfile.write(body)
        except ConnectionError:
            # A poll abandoned by the browser is routine, not a server fault.
            self.close_connection = True


class ExclusivePortHTTPServer(ThreadingHTTPServer):
    """A server that refuses to share its port with one already serving it.

    Starting a second server on a busy port has to fail loudly: a server that
    binds but is never handed a connection looks exactly like working software
    serving stale data, which is far more expensive to diagnose than a refused
    start. See ``EXCLUSIVE_PORTS_AVAILABLE`` for why the option differs by
    platform.
    """

    allow_reuse_address = not EXCLUSIVE_PORTS_AVAILABLE

    def server_bind(self) -> None:
        if EXCLUSIVE_PORTS_AVAILABLE:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def build_parser() -> argparse.ArgumentParser:
    """Command-line interface for ``python -m netmon.server``."""
    parser = argparse.ArgumentParser(
        prog="python -m netmon.server",
        description="Serve the subnet traffic monitor UI and its rates API.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"TCP port to listen on (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_BIND_HOST,
        help=f"Address to bind to (default: {DEFAULT_BIND_HOST})",
    )
    parser.add_argument(
        "--host-ip",
        default=DEFAULT_HOST_IP,
        help=(
            "Address reported to the UI as this machine's own "
            f"(default: {DEFAULT_HOST_IP})"
        ),
    )
    parser.add_argument(
        "--subnet",
        default=DEFAULT_SUBNET,
        help=(
            "Subnet watched when the page asks for no particular one "
            f"(default: {DEFAULT_SUBNET})"
        ),
    )
    parser.add_argument(
        "--iface",
        default=None,
        help=(
            "Capture interface to listen on, overriding the adapter derived "
            "from --host-ip (default: derived)"
        ),
    )
    parser.add_argument(
        "--recordings-dir",
        type=Path,
        default=DEFAULT_RECORDINGS_DIR,
        help=(
            "Directory CSV recordings are written to, created if missing "
            f"(default: {DEFAULT_RECORDINGS_DIR})"
        ),
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Feed the aggregator synthetic traffic instead of real packets",
    )
    parser.add_argument(
        "--capture-status",
        metavar="STATE",
        default=None,
        help=(
            "Force the reported capture.state so the UI's banner can be "
            "reviewed. Any string is accepted, including states the UI has "
            "never seen. Known states: "
            + ", ".join(sorted(CAPTURE_STATE_DETAILS))
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the server until interrupted."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        default_subnet = parse_subnet(args.subnet)
    except ValueError as error:
        parser.error(str(error))

    window = RateWindow()
    source = build_source(
        window, mock=args.mock, host_ip=args.host_ip, iface=args.iface
    )
    read_capture_status = capture_status_reader(source.status, args.capture_status)
    recorder = Recorder(
        window=window,
        recordings_dir=args.recordings_dir,
        filter_devices=devices_in_subnet,
    )

    handler = partial(
        RatesRequestHandler,
        window=window,
        host_ip=args.host_ip,
        read_capture_status=read_capture_status,
        default_subnet=default_subnet,
        recorder=recorder,
    )
    try:
        server = ExclusivePortHTTPServer((args.host, args.port), handler)
    except OSError as error:
        print(
            f"Cannot bind {args.host}:{args.port}: {error}\n{BIND_ADVICE}",
            file=sys.stderr,
        )
        return 1
    server.daemon_threads = True

    if not WEB_DIRECTORY.is_dir():
        print(
            f"Warning: {WEB_DIRECTORY} does not exist; only {RATES_PATH} will "
            "respond.",
            file=sys.stderr,
        )
    try:
        # Started before the banner is printed so the state it names is the one
        # the source actually reached, not the one it held before opening.
        source.start()
        print(
            f"Serving on http://{args.host}:{args.port}/ "
            f"(capture: {read_capture_status().state}, subnet: {default_subnet})",
            flush=True,
        )
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        # The recording first, so a Ctrl+C leaves a flushed, closed CSV rather
        # than one still waiting on the capture to wind down.
        recorder.stop()
        source.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
