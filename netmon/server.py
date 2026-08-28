"""HTTP server for the network monitor: static UI plus ``GET /api/rates``.

ponytail: the whole web stack is the standard library's
:class:`~http.server.ThreadingHTTPServer`. Ceiling - request/response only, so
no server push (SSE or WebSocket), no async, and one thread per connection,
which a 2 Hz poll from a handful of browser tabs does not strain. Upgrade path
- if push updates are ever wanted, drop in FastAPI + uvicorn behind the same
``/api/rates`` shape.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .mock_source import MockSource
from .rate_window import RateWindow

DEFAULT_PORT = 8080
DEFAULT_BIND_HOST = "0.0.0.0"
DEFAULT_HOST_IP = "192.168.2.1"

RATES_PATH = "/api/rates"
JSON_CONTENT_TYPE = "application/json"
NO_STORE = "no-store"

# Resolved from the package location so the server works from any working
# directory - it is routinely launched from somewhere other than the repo root.
WEB_DIRECTORY = Path(__file__).resolve().parent.parent / "web"

CAPTURE_STATE_OK = "ok"
CAPTURE_STATE_MOCK = "mock"
CAPTURE_STATE_ERROR = "error"

CAPTURE_STATE_DETAILS: dict[str, str] = {
    CAPTURE_STATE_OK: "Capturing live traffic.",
    CAPTURE_STATE_MOCK: "Showing simulated traffic.",
    "needs_elevation": (
        "Packet capture needs Administrator rights; restart this program as an "
        "administrator."
    ),
    "npcap_missing": (
        "Npcap is not installed. Install it from npcap.com, then restart this "
        "program to capture live traffic."
    ),
    "interface_missing": (
        "No network interface for the vehicle subnet was found; check that the "
        "tether is connected and the adapter still holds its static address."
    ),
    "unsupported_platform": (
        "Packet capture is only available on Windows in this release."
    ),
    CAPTURE_STATE_ERROR: "Packet capture stopped unexpectedly.",
}

UNKNOWN_CAPTURE_DETAIL = "Packet capture reported an unrecognised state: {state}."
NO_SOURCE_DETAIL = (
    "No packet source is running; restart with --mock to see simulated traffic."
)


@dataclass(frozen=True)
class CaptureStatus:
    """What the UI is told about the health of the packet source."""

    state: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"state": self.state, "detail": self.detail}


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


def resolve_capture_status(mock: bool, forced: str | None) -> CaptureStatus:
    """Decide the reported capture status from the CLI flags.

    An explicit ``--capture-status`` always wins, since its whole purpose is
    reviewing a state the machine at hand cannot actually produce.
    """
    if forced is not None:
        return capture_status_for(forced)
    if mock:
        return capture_status_for(CAPTURE_STATE_MOCK)
    return CaptureStatus(state=CAPTURE_STATE_ERROR, detail=NO_SOURCE_DETAIL)


class RatesRequestHandler(SimpleHTTPRequestHandler):
    """Serves the ``web/`` directory, intercepting the rates endpoint."""

    def __init__(
        self,
        *args: Any,
        window: RateWindow,
        host_ip: str,
        capture: CaptureStatus,
        **kwargs: Any,
    ) -> None:
        self._window = window
        self._host_ip = host_ip
        self._capture = capture
        # The base class handles the whole request from within __init__, so
        # everything the handler needs must already be attached.
        super().__init__(*args, directory=str(WEB_DIRECTORY), **kwargs)

    def do_GET(self) -> None:
        if urlsplit(self.path).path == RATES_PATH:
            self._send_rates()
            return
        super().do_GET()

    def log_message(self, format: str, *args: Any) -> None:
        """Stay quiet: a 2 Hz poll would otherwise flood the console."""

    def _send_rates(self) -> None:
        payload: dict[str, object] = {
            "host_ip": self._host_ip,
            "capture": self._capture.as_dict(),
            **self._window.snapshot(),
        }
        body = json.dumps(payload).encode("utf-8")
        try:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", JSON_CONTENT_TYPE)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", NO_STORE)
            self.end_headers()
            self.wfile.write(body)
        except ConnectionError:
            # A poll abandoned by the browser is routine, not a server fault.
            self.close_connection = True


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
    args = build_parser().parse_args(argv)

    window = RateWindow()
    source = MockSource(window) if args.mock else None
    capture = resolve_capture_status(mock=args.mock, forced=args.capture_status)

    handler = partial(
        RatesRequestHandler,
        window=window,
        host_ip=args.host_ip,
        capture=capture,
    )
    try:
        server = ThreadingHTTPServer((args.host, args.port), handler)
    except OSError as error:
        print(f"Cannot bind {args.host}:{args.port}: {error}", file=sys.stderr)
        return 1
    server.daemon_threads = True

    if not WEB_DIRECTORY.is_dir():
        print(
            f"Warning: {WEB_DIRECTORY} does not exist; only {RATES_PATH} will "
            "respond.",
            file=sys.stderr,
        )
    print(f"Serving on http://{args.host}:{args.port}/ (capture: {capture.state})")

    if source is not None:
        source.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if source is not None:
            source.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
