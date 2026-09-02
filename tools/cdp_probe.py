"""Measure a page's real frame timing by attaching to a running Chromium.

The graphs scroll smoothly in a normal browser tab and step inside Cockpit's
iframe, which leaves two very different causes: either that frame is painting
far below 60 Hz (nothing drawn on its main thread can be smooth, and the fix
has to move off it), or it paints fine and the stepping comes from our own
geometry. Guessing between those two is what makes this loop expensive, so
this reads the answer out of the process that is actually misbehaving.

Chromium can only be attached to if it was started with a debugging port, and
that cannot be turned on afterwards, so Cockpit has to be relaunched::

    cd C:\\Users\\Callum\\git\\cockpit
    npx electron . --no-sandbox --remote-debugging-port=9222

Then, with the panel on screen::

    python tools/cdp_probe.py --url localhost:8765

ponytail: a hand-rolled WebSocket client rather than a dependency, because it
only ever speaks one request/response pair to a loopback port. It handles
exactly the framing CDP replies use - masked writes, unmasked reads, and
continuations - and would need replacing to do more than that.
"""

import argparse
import base64
import json
import os
import socket
import struct
import sys
import time
from typing import Any
from urllib.request import urlopen
from urllib.parse import urlsplit

DEFAULT_PORT = 9222
DEFAULT_SECONDS = 3.0
HTTP_TIMEOUT_S = 5.0
SOCKET_TIMEOUT_S = 30.0
READ_CHUNK_BYTES = 65536
NAVIGATE_SETTLE_S = 4.0

TEXT_FRAME = 0x1
CLOSE_FRAME = 0x8
FIN_BIT = 0x80
MASK_BIT = 0x80
LENGTH_16_BIT = 126
LENGTH_64_BIT = 127
MAX_SHORT_LENGTH = 125
MAX_16_BIT_LENGTH = 65535
MASK_BYTES = 4

# Measured in the page rather than out here: only the frame itself knows when
# its own callbacks ran. The guard timer matters - a fully throttled frame
# never calls requestAnimationFrame at all, and a probe that hung on that
# would hide the most interesting result it can report.
MEASURE_JS = """
(() => new Promise((resolve) => {
  const durationMs = %DURATION_MS%;
  const frames = [];
  const timers = [];
  const pollGaps = [];
  const pollLatencies = [];
  const bucketSteps = [];
  const start = performance.now();
  let lastFrame = start;
  let lastTimer = start;
  let lastPoll = null;
  let lastNowMs = null;
  let done = false;

  const ticker = setInterval(() => {
    const now = performance.now();
    timers.push(now - lastTimer);
    lastTimer = now;
  }, 16);

  /* The page's own polling, watched from the outside: how regularly it
     actually fires here, what the server costs it, and whether the payload's
     bucket clock advances one bucket at a time or in bursts. */
  const originalFetch = window.fetch;
  window.fetch = function (...args) {
    const began = performance.now();
    if (lastPoll !== null) pollGaps.push(began - lastPoll);
    lastPoll = began;
    const pending = originalFetch.apply(this, args);
    pending
      .then((response) => {
        pollLatencies.push(performance.now() - began);
        return response.clone().json();
      })
      .then((body) => {
        if (body && typeof body.now_ms === 'number') {
          if (lastNowMs !== null) bucketSteps.push(body.now_ms - lastNowMs);
          lastNowMs = body.now_ms;
        }
      })
      .catch(() => {});
    return pending;
  };

  const stat = (values) => {
    if (values.length === 0) return null;
    const sorted = [...values].sort((a, b) => a - b);
    const at = (q) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];
    const round = (value) => Math.round(value * 100) / 100;
    return {
      count: sorted.length,
      mean: round(values.reduce((a, b) => a + b, 0) / values.length),
      p50: round(at(0.5)),
      p95: round(at(0.95)),
      max: round(sorted[sorted.length - 1]),
    };
  };

  const finish = () => {
    if (done) return;
    done = true;
    clearInterval(ticker);
    clearTimeout(guard);
    window.fetch = originalFetch;
    const elapsed = performance.now() - start;
    resolve({
      url: location.href,
      elapsedMs: Math.round(elapsed),
      framesPerSecond: Math.round((frames.length / elapsed) * 1000 * 10) / 10,
      devicePixelRatio: window.devicePixelRatio,
      visibility: document.visibilityState,
      innerSize: [window.innerWidth, window.innerHeight],
      frameIntervalMs: stat(frames),
      timerIntervalMs: stat(timers),
      pollGapMs: stat(pollGaps),
      pollLatencyMs: stat(pollLatencies),
      bucketStepMs: stat(bucketSteps),
      canvases: [...document.querySelectorAll('canvas')].map((canvas) => ({
        cssSize: [canvas.clientWidth, canvas.clientHeight],
        bitmapSize: [canvas.width, canvas.height],
        animations: canvas.getAnimations().length,
      })),
    });
  };

  const guard = setTimeout(finish, durationMs * 2 + 500);
  const tick = (now) => {
    frames.push(now - lastFrame);
    lastFrame = now;
    if (now - start < durationMs) requestAnimationFrame(tick);
    else finish();
  };
  requestAnimationFrame(tick);
}))()
"""


def encode_frame(payload: bytes) -> bytes:
    """Frame ``payload`` as a masked client text frame."""
    header = bytearray([FIN_BIT | TEXT_FRAME])
    length = len(payload)
    if length <= MAX_SHORT_LENGTH:
        header.append(MASK_BIT | length)
    elif length <= MAX_16_BIT_LENGTH:
        header.append(MASK_BIT | LENGTH_16_BIT)
        header += struct.pack("!H", length)
    else:
        header.append(MASK_BIT | LENGTH_64_BIT)
        header += struct.pack("!Q", length)
    mask = os.urandom(MASK_BYTES)
    header += mask
    masked = bytes(byte ^ mask[index % MASK_BYTES] for index, byte in enumerate(payload))
    return bytes(header) + masked


def read_frame(read_exactly: Any) -> tuple[int, bytes]:
    """Read one whole message, following continuation frames.

    ``read_exactly(n)`` must return exactly ``n`` bytes or raise.
    """
    opcode = 0
    payload = bytearray()
    while True:
        first, second = read_exactly(2)
        if opcode == 0:
            opcode = first & 0x0F
        masked = bool(second & MASK_BIT)
        length = second & 0x7F
        if length == LENGTH_16_BIT:
            (length,) = struct.unpack("!H", read_exactly(2))
        elif length == LENGTH_64_BIT:
            (length,) = struct.unpack("!Q", read_exactly(8))
        mask = read_exactly(MASK_BYTES) if masked else b""
        chunk = read_exactly(length) if length else b""
        if masked:
            chunk = bytes(
                byte ^ mask[index % MASK_BYTES] for index, byte in enumerate(chunk)
            )
        payload += chunk
        if first & FIN_BIT:
            return opcode, bytes(payload)


def pick_target(targets: list[dict[str, Any]], url_fragment: str) -> dict[str, Any] | None:
    """The first attachable target whose URL contains ``url_fragment``."""
    for target in targets:
        if url_fragment not in target.get("url", ""):
            continue
        if target.get("webSocketDebuggerUrl"):
            return target
    return None


def list_targets(port: int) -> list[dict[str, Any]]:
    with urlopen(f"http://127.0.0.1:{port}/json/list", timeout=HTTP_TIMEOUT_S) as response:
        return json.loads(response.read().decode("utf-8"))


class CdpConnection:
    """One WebSocket to one debugger target."""

    def __init__(self, websocket_url: str) -> None:
        parsed = urlsplit(websocket_url)
        self._socket = socket.create_connection(
            (parsed.hostname, parsed.port or 80), timeout=SOCKET_TIMEOUT_S
        )
        self._buffer = bytearray()
        self._next_id = 0
        self._handshake(parsed.path or "/", parsed.hostname, parsed.port or 80)

    def _handshake(self, path: str, host: str, port: int) -> None:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self._socket.sendall(request.encode("ascii"))
        while b"\r\n\r\n" not in self._buffer:
            self._fill()
        head, _, rest = bytes(self._buffer).partition(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0].decode("latin-1")
        if "101" not in status:
            raise RuntimeError(f"debugger refused the upgrade: {status}")
        self._buffer = bytearray(rest)

    def _fill(self) -> None:
        chunk = self._socket.recv(READ_CHUNK_BYTES)
        if not chunk:
            raise RuntimeError("debugger closed the connection")
        self._buffer += chunk

    def _read_exactly(self, count: int) -> bytes:
        while len(self._buffer) < count:
            self._fill()
        taken = bytes(self._buffer[:count])
        del self._buffer[:count]
        return taken

    def call(self, method: str, **params: Any) -> dict[str, Any]:
        """Send one command and return its reply, skipping unrelated events."""
        self._next_id += 1
        message_id = self._next_id
        payload = json.dumps({"id": message_id, "method": method, "params": params})
        self._socket.sendall(encode_frame(payload.encode("utf-8")))
        while True:
            opcode, body = read_frame(self._read_exactly)
            if opcode == CLOSE_FRAME:
                raise RuntimeError("debugger closed the connection")
            message = json.loads(body.decode("utf-8"))
            if message.get("id") == message_id:
                return message

    def close(self) -> None:
        self._socket.close()


def measure(target: dict[str, Any], seconds: float) -> dict[str, Any]:
    connection = CdpConnection(target["webSocketDebuggerUrl"])
    try:
        reply = connection.call(
            "Runtime.evaluate",
            expression=MEASURE_JS.replace("%DURATION_MS%", str(int(seconds * 1000))),
            awaitPromise=True,
            returnByValue=True,
        )
    finally:
        connection.close()
    if "error" in reply:
        raise RuntimeError(reply["error"])
    result = reply.get("result", {})
    if "exceptionDetails" in result:
        raise RuntimeError(result["exceptionDetails"])
    return result.get("result", {}).get("value", {})


def send_to(target: dict[str, Any], method: str, **params: Any) -> None:
    connection = CdpConnection(target["webSocketDebuggerUrl"])
    try:
        connection.call(method, **params)
    finally:
        connection.close()


def navigate(target: dict[str, Any], url: str, port: int) -> dict[str, Any]:
    """Point a frame at ``url`` and return the target that ends up hosting it.

    A cross-origin navigation moves the frame into a different renderer, and
    with it a different debugger target, so the one handed in here is not the
    one to measure afterwards - it has to be looked up again.
    """
    send_to(target, "Page.navigate", url=url)
    time.sleep(NAVIGATE_SETTLE_S)
    landed = pick_target(list_targets(port), urlsplit(url).netloc)
    if landed is None:
        raise RuntimeError(f"nothing is hosting {url} after the navigation")
    return landed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--url",
        default="",
        help="substring of the target page's URL; omit to only list targets",
    )
    parser.add_argument("--seconds", type=float, default=DEFAULT_SECONDS)
    parser.add_argument(
        "--navigate",
        default="",
        help="point the matched frame at this URL first, then measure it there",
    )
    parser.add_argument(
        "--restore",
        action="store_true",
        help="send the frame back to its original URL once measured",
    )
    args = parser.parse_args(argv)

    try:
        targets = list_targets(args.port)
    except OSError as error:
        print(
            f"No debugger on port {args.port} ({error}). Relaunch Cockpit with"
            f" --remote-debugging-port={args.port}.",
            file=sys.stderr,
        )
        return 1

    for target in targets:
        print(f"[{target.get('type')}] {target.get('title')} - {target.get('url')}")
    if not args.url:
        return 0

    target = pick_target(targets, args.url)
    if target is None:
        print(f"No attachable target matched {args.url!r}.", file=sys.stderr)
        return 1

    origin_url = target.get("url", "")
    if args.navigate:
        print(f"\nPointing {origin_url} at {args.navigate}...")
        target = navigate(target, args.navigate, args.port)

    print(f"\nMeasuring {target.get('url')} for {args.seconds:g}s...")
    print(json.dumps(measure(target, args.seconds), indent=2))

    if args.navigate and args.restore and origin_url:
        print(f"\nRestoring {origin_url}...")
        navigate(target, origin_url, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
