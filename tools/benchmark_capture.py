"""Measure how much packet rate :mod:`netmon.capture` can sustain.

scapy builds a full structured object for every packet, which is roughly two
orders of magnitude more work per packet than a minimal decoder. A BlueROV2
pushing video and telemetry is plausibly well inside that budget, but only
plausibly - so this drives the real capture path with a known offered load and
records what actually arrives.

Three numbers are recorded together, because any one alone misleads. A healthy
packet rate beside a rising drop count is exactly the silent failure the
monitor exists to catch:

* **Sustained packets per second through the callback** - what reached
  :meth:`RateWindow.record`.
* **``ps_drop`` / ``ps_recv``**, sampled periodically rather than once at the
  end. The counters are cumulative, so a single reading hides where the ceiling
  was crossed. ``ps_recv`` is recorded beside our own counted total: the gap
  between them *is* the loss, and it is the more trustworthy figure because
  ``ps_drop`` semantics vary by platform.
* **CPU time of the capture thread**, read from the OS rather than inferred.

The generator's own send count is recorded too, so offered load is a
measurement rather than an assumption.

Lock contention may matter more than parsing cost, so the sweep repeats at
several retained-address counts with a 2 Hz poller running against a real
``/api/rates`` endpoint - see :func:`run_group`.

**What this does and does not bound.** Loopback packet sizes and datalink
differ from real Ethernet and drop accounting may behave differently from a
physical NIC, so the absolute numbers do not transfer. What transfers is the
userspace ceiling - driver to kernel filter to scapy dissection to our callback
to the aggregator - which is the question being asked.
"""

import argparse
import csv
import ctypes
import json
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
from functools import partial
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

# Run as a script, not a package module, so the repo root is put on the path
# explicitly rather than relying on the working directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netmon import capture  # noqa: E402
from netmon.rate_window import RateWindow  # noqa: E402
from netmon.recorder import Recorder  # noqa: E402
from netmon.server import (  # noqa: E402
    RatesRequestHandler,
    devices_in_subnet,
    parse_subnet,
)

WINDOWS_PLATFORM = "win32"

# One reading of the three counters, any of which may be unavailable.
Counters = tuple[int | None, int | None, float | None]

# The 0 pps step is the baseline that makes the CPU figure readable: it
# separates what the capture thread costs merely by waiting from what it costs
# per packet.
DEFAULT_RATES_PPS = (0, 500, 1000, 2500, 5000, 10000, 20000)
DEFAULT_STEP_SECONDS = 30.0
DEFAULT_PRELOAD_ADDRESSES = (0, 1000, 10000)

# Npcap's loopback device, which captures Windows loopback traffic. Named
# rather than derived: no adapter reports 127.0.0.1 in scapy's interface table,
# so CaptureSource's --iface override is the intended route here.
DEFAULT_IFACE = r"\Device\NPF_Loopback"
DEFAULT_TARGET_IP = "127.0.0.1"
DEFAULT_TARGET_PORT = 9999
DEFAULT_PAYLOAD_BYTES = 64
# Any free port. Windows lets a second socket share a bound port, so naming a
# fixed one risks polling somebody else's server without ever saying so - and
# nothing outside this process needs to reach the benchmark's endpoint.
DEFAULT_SERVER_PORT = 0
DEFAULT_SUBNET = "192.168.2.0/24"
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "benchmark-results"
# ``None`` keeps Npcap's own default kernel buffer, about 1 MB.
DEFAULT_KERNEL_BUFFER_MB: float | None = None
BYTES_PER_MB = 2**20

SERVER_BIND_HOST = "127.0.0.1"
SAMPLE_INTERVAL_S = 1.0
POLL_INTERVAL_S = 0.5
SETTLE_S = 2.0
CAPTURE_WARMUP_S = 1.0
HTTP_TIMEOUT_S = 10.0
BLAST_EXIT_MARGIN_S = 20.0
BLAST_KILL_TIMEOUT_S = 5.0

# A sleep shorter than this costs more in scheduling jitter than it saves, so
# the generator spins through the remainder instead.
MIN_SLEEP_S = 0.001
# Caps the catch-up burst after the scheduler oversleeps, so a late wakeup
# spreads over the next few milliseconds rather than firing as one spike.
MAX_SEND_BATCH = 256
# Printed by the generator once its sockets are up, so the parent can start
# measuring at the same moment the traffic does.
READY_LINE = "ready"

PRELOAD_FIRST_OCTET = 10
OCTET_RANGE = 256

FILETIME_TICKS_PER_SECOND = 10_000_000
THREAD_QUERY_LIMITED_INFORMATION = 0x0800

RESULT_FILENAME = "capture-benchmark-{stamp}"
STAMP_FORMAT = "%Y%m%dT%H%M%SZ"
NO_SAMPLES_ERROR = "fewer than two samples were taken"

HEADER_FORMAT = (
    "{preload:>8} {rate:>7} {sent:>9} {counted:>9} {counted_pps:>9} "
    "{recv:>9} {drop:>7} {ratio:>9} {cpu:>7} {poll:>9}"
)
HEADER_ROW = HEADER_FORMAT.format(
    preload="preload",
    rate="offered",
    sent="sent",
    counted="counted",
    counted_pps="pps",
    recv="ps_recv",
    drop="ps_drop",
    ratio="drop/recv",
    cpu="cores",
    poll="poll ms",
)


@dataclass(frozen=True)
class Sample:
    """One periodic reading of the cumulative counters.

    Every field is cumulative since the capture opened, so a step's figures are
    differences between its first and last sample rather than the raw values.
    """

    at_s: float
    counted: int
    received: int | None
    dropped: int | None
    cpu_s: float | None


@dataclass
class StepResult:
    """What one offered-load step measured.

    Every measured field defaults to absent, so a step that failed reports
    what it did observe rather than inventing zeroes for the rest.
    """

    preload_addresses: int
    offered_pps: int
    capture_state: str
    duration_s: float = 0.0
    sent: int | None = None
    sent_pps: float | None = None
    counted: int = 0
    counted_pps: float = 0.0
    loss_vs_sent: float | None = None
    ps_recv: int | None = None
    ps_drop: int | None = None
    drop_ratio: float | None = None
    peak_interval_drop_ratio: float | None = None
    recv_minus_counted: int | None = None
    capture_cpu_s: float | None = None
    capture_cpu_cores: float | None = None
    polls: int = 0
    poll_mean_ms: float | None = None
    poll_max_ms: float | None = None
    poll_failures: int = 0
    error: str | None = None


class CountingWindow(RateWindow):
    """A :class:`RateWindow` that counts the calls reaching :meth:`record`.

    Counting at the boundary is what makes "packets through the callback" a
    measurement rather than an inference from the payload. The added work is a
    single integer increment inside the measured path.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.recorded = 0

    def record(self, ip: str, packets: int = 1) -> None:
        self.recorded += packets
        super().record(ip, packets)


def packets_due(rate_pps: float, elapsed_s: float) -> int:
    """Packets that should have been sent by ``elapsed_s`` at ``rate_pps``.

    Pacing against a cumulative target rather than a per-tick quota is what
    keeps the generator from drifting: an oversleep is repaid on the next
    iteration instead of being lost.
    """
    if rate_pps <= 0.0 or elapsed_s <= 0.0:
        return 0
    return int(rate_pps * elapsed_s)


def next_send_delay(
    rate_pps: float, sent: int, elapsed_s: float, duration_s: float
) -> float:
    """Seconds to wait before the next packet is due.

    A zero rate means no packet is ever due, so the generator waits out the
    whole step in one sleep instead of spinning on a schedule with no entries.
    """
    if rate_pps <= 0.0:
        return max(0.0, duration_s - elapsed_s)
    return (sent + 1) / rate_pps - elapsed_s


def rate_per_second(count: int, seconds: float) -> float:
    """``count`` over ``seconds``, or 0.0 for a zero-length interval."""
    if seconds <= 0.0:
        return 0.0
    return count / seconds


def drop_ratio(received: int | None, dropped: int | None) -> float | None:
    """``dropped / received``, or ``None`` when the counters are unavailable.

    A zero receive count is not a drop-free capture, it is no evidence either
    way, so it reports 0.0 only when nothing was dropped from nothing.
    """
    if received is None or dropped is None:
        return None
    if received <= 0:
        return 0.0 if not dropped else 1.0
    return dropped / received


def loss_ratio(offered: int | None, counted: int) -> float | None:
    """Fraction of the offered packets that never reached the callback.

    Clamped at zero because the capture also sees traffic the generator did not
    send - the poller's own HTTP packets are addressed to the same loopback
    address - so a small surplus is expected rather than a fault.
    """
    if offered is None or offered <= 0:
        return None
    return max(0, offered - counted) / offered


def peak_interval_drop_ratio(samples: Sequence[Sample]) -> float | None:
    """Worst drop ratio over any single interval between samples.

    The cumulative counters average a spike away over a thirty-second step;
    the interval maximum is what says where the ceiling actually is.
    """
    ratios: list[float] = []
    for previous, current in zip(samples, samples[1:]):
        ratio = _interval_drop_ratio(previous, current)
        if ratio is not None:
            ratios.append(ratio)
    return max(ratios) if ratios else None


def _interval_drop_ratio(previous: Sample, current: Sample) -> float | None:
    """Drop ratio between two consecutive samples, or ``None`` if unknown."""
    if (
        previous.received is None
        or current.received is None
        or previous.dropped is None
        or current.dropped is None
    ):
        return None
    return drop_ratio(
        current.received - previous.received, current.dropped - previous.dropped
    )


def _delta(
    start: int | float | None, end: int | float | None
) -> int | float | None:
    """``end - start`` when both readings exist, else ``None``."""
    if start is None or end is None:
        return None
    return end - start


def summarize_step(
    preload_addresses: int,
    offered_pps: int,
    samples: Sequence[Sample],
    sent: int | None,
    poll_latencies_ms: Sequence[float],
    poll_failures: int,
    capture_state: str,
    error: str | None = None,
) -> StepResult:
    """Reduce a step's samples to the row that goes in the results table."""
    polling = {
        "polls": len(poll_latencies_ms),
        "poll_mean_ms": _rounded(_mean(poll_latencies_ms), 1),
        "poll_max_ms": _rounded(max(poll_latencies_ms, default=None), 1),
        "poll_failures": poll_failures,
    }
    if len(samples) < 2:
        return StepResult(
            preload_addresses=preload_addresses,
            offered_pps=offered_pps,
            capture_state=capture_state,
            sent=sent,
            error=error or NO_SAMPLES_ERROR,
            **polling,
        )

    first, last = samples[0], samples[-1]
    duration_s = last.at_s - first.at_s
    counted = last.counted - first.counted
    received = _delta(first.received, last.received)
    dropped = _delta(first.dropped, last.dropped)
    cpu_s = _delta(first.cpu_s, last.cpu_s)
    return StepResult(
        preload_addresses=preload_addresses,
        offered_pps=offered_pps,
        duration_s=round(duration_s, 3),
        sent=sent,
        sent_pps=None if sent is None else round(rate_per_second(sent, duration_s), 1),
        counted=counted,
        counted_pps=round(rate_per_second(counted, duration_s), 1),
        loss_vs_sent=_rounded(loss_ratio(sent, counted), 6),
        ps_recv=None if received is None else int(received),
        ps_drop=None if dropped is None else int(dropped),
        drop_ratio=_rounded(drop_ratio(received, dropped), 6),
        peak_interval_drop_ratio=_rounded(peak_interval_drop_ratio(samples), 6),
        recv_minus_counted=None if received is None else int(received) - counted,
        capture_cpu_s=_rounded(cpu_s, 3),
        capture_cpu_cores=_rounded(
            None if cpu_s is None else rate_per_second(cpu_s, duration_s), 3
        ),
        capture_state=capture_state,
        error=error,
        **polling,
    )


def _listed(values: Sequence[int]) -> str:
    """Default sequence as it appears in ``--help``."""
    return " ".join(str(value) for value in values)


def _mean(values: Sequence[float]) -> float | None:
    """Arithmetic mean, or ``None`` for an empty sequence."""
    return sum(values) / len(values) if values else None


def _rounded(value: float | None, places: int) -> float | None:
    """Round a reading that may be absent."""
    return None if value is None else round(value, places)


def preload_addresses(count: int) -> list[str]:
    """``count`` distinct addresses to fill the aggregator with.

    They stand in for retained history rather than for reachable hosts, so they
    only have to be distinct and parseable.
    """
    return [
        f"{PRELOAD_FIRST_OCTET}."
        f"{index // (OCTET_RANGE * OCTET_RANGE) % OCTET_RANGE}."
        f"{index // OCTET_RANGE % OCTET_RANGE}."
        f"{index % OCTET_RANGE}"
        for index in range(count)
    ]


class _FileTime(ctypes.Structure):
    """Windows ``FILETIME``: a 64-bit count of 100-nanosecond intervals."""

    _fields_ = [
        ("low_date_time", ctypes.c_uint32),
        ("high_date_time", ctypes.c_uint32),
    ]

    def seconds(self) -> float:
        ticks = (self.high_date_time << 32) | self.low_date_time
        return ticks / FILETIME_TICKS_PER_SECOND


def thread_cpu_seconds(native_id: int | None) -> float | None:
    """Kernel plus user CPU time consumed by one OS thread, in seconds.

    ``time.thread_time`` only reports the calling thread, and the capture
    thread is scapy's, so the figure is read from the OS by thread id. Returns
    ``None`` rather than raising if the thread has already exited.
    """
    if native_id is None or sys.platform != WINDOWS_PLATFORM:
        return None
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenThread.restype = ctypes.c_void_p
    kernel32.OpenThread.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    handle = kernel32.OpenThread(
        THREAD_QUERY_LIMITED_INFORMATION, False, native_id
    )
    if not handle:
        return None
    try:
        creation, exited, kernel, user = (_FileTime() for _ in range(4))
        ok = kernel32.GetThreadTimes(
            ctypes.c_void_p(handle),
            ctypes.byref(creation),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        )
        if not ok:
            return None
        return kernel.seconds() + user.seconds()
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def read_counters(source: capture.CaptureSource) -> Counters:
    """``(ps_recv, ps_drop, cpu_seconds)`` for a live capture.

    The drop counters are read by :mod:`netmon.capture`'s own reader rather
    than by a second implementation, so what is measured is what ships.

    ponytail: reaches past ``CaptureSource``'s public surface, which reports
    health but exposes neither the socket the counters live behind nor the
    thread whose CPU time is wanted. Ceiling - the sniffer attribute and the
    module-private reader are the benchmark's only internal dependencies, and
    a rename would break them silently, so both are treated as absent rather
    than fatal. Upgrade path - read them from ``CaptureStatus`` if drop counts
    and thread identity ever become part of it.
    """
    sniffer = getattr(source, "_sniffer", None)
    if sniffer is None:
        return None, None, None
    counts = capture._drop_counts(sniffer)
    received, dropped = counts if counts is not None else (None, None)
    thread = sniffer.thread
    cpu_s = thread_cpu_seconds(None if thread is None else thread.native_id)
    return received, dropped, cpu_s


class RatesPoller(threading.Thread):
    """Polls ``/api/rates`` at a fixed interval, timing each request.

    The latency it records is the signal that matters here: a poll that has to
    wait on the aggregator's lock is a poll that was stalling the capture
    callback for the same length of time.
    """

    def __init__(self, url: str, interval_s: float = POLL_INTERVAL_S) -> None:
        super().__init__(name="benchmark-rates-poller", daemon=True)
        self._url = url
        self._interval_s = interval_s
        self._stopping = threading.Event()
        self._lock = threading.Lock()
        self._latencies_ms: list[float] = []
        self._failures = 0

    def run(self) -> None:
        while not self._stopping.is_set():
            started = time.perf_counter()
            try:
                with urlopen(self._url, timeout=HTTP_TIMEOUT_S) as response:
                    response.read()
            except (URLError, OSError):
                with self._lock:
                    self._failures += 1
            else:
                elapsed_ms = (time.perf_counter() - started) * 1000.0
                with self._lock:
                    self._latencies_ms.append(elapsed_ms)
            self._stopping.wait(self._interval_s)

    def take(self) -> tuple[list[float], int]:
        """Latencies and failures since the last call, clearing both."""
        with self._lock:
            latencies, failures = self._latencies_ms, self._failures
            self._latencies_ms, self._failures = [], 0
        return latencies, failures

    def stop(self) -> None:
        self._stopping.set()
        self.join(HTTP_TIMEOUT_S)


def run_blaster(
    script: Path, rate_pps: int, args: argparse.Namespace
) -> subprocess.Popen[str]:
    """Start the UDP generator in its own process and wait for it to be ready.

    A separate process is the point: a generator sharing this interpreter would
    contend with the capture thread for the GIL and its CPU cost would land in
    the same process being measured. It costs an interpreter startup, though,
    which is why the parent waits for the ready line before starting its own
    clock - otherwise the measurement window is offset from the traffic by a
    few hundred milliseconds and the offered load looks partly lost.
    """
    command = [sys.executable, str(script), "blast", "--rate", str(rate_pps)]
    for name in ("duration", "target_ip", "target_port", "payload_bytes"):
        command += [f"--{name.replace('_', '-')}", str(getattr(args, name))]
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    assert process.stdout is not None
    if process.stdout.readline().strip() != READY_LINE:
        raise RuntimeError("generator never reported that it was ready")
    return process


def collect_blaster_result(
    process: subprocess.Popen[str], timeout_s: float
) -> tuple[int | None, str | None]:
    """``(packets sent, error)`` once the generator has exited.

    The count is the generator's own tally, which makes offered load a
    measurement rather than the number that was asked for.
    """
    try:
        stdout, stderr = process.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=BLAST_KILL_TIMEOUT_S)
        return None, "generator did not exit; killed"
    if process.returncode != 0:
        return None, f"generator exited {process.returncode}: {stderr.strip()}"
    try:
        return int(json.loads(stdout)["sent"]), None
    except (ValueError, KeyError) as error:
        return None, f"unreadable generator output: {error}"


def run_step(
    source: capture.CaptureSource,
    window: CountingWindow,
    poller: RatesPoller,
    script: Path,
    rate_pps: int,
    preload: int,
    args: argparse.Namespace,
) -> StepResult:
    """Drive one offered-load step and return its measured row."""
    poller.take()
    process = run_blaster(script, rate_pps, args)
    samples: list[Sample] = []
    started = time.perf_counter()
    deadline = started + args.duration
    while True:
        now = time.perf_counter()
        received, dropped, cpu_s = read_counters(source)
        samples.append(
            Sample(
                at_s=now - started,
                counted=window.recorded,
                received=received,
                dropped=dropped,
                cpu_s=cpu_s,
            )
        )
        if now >= deadline:
            break
        time.sleep(min(SAMPLE_INTERVAL_S, max(0.0, deadline - now)))

    sent, error = collect_blaster_result(
        process, args.duration + BLAST_EXIT_MARGIN_S
    )
    latencies, failures = poller.take()
    return summarize_step(
        preload_addresses=preload,
        offered_pps=rate_pps,
        samples=samples,
        sent=sent,
        poll_latencies_ms=latencies,
        poll_failures=failures,
        capture_state=source.status().state,
        error=error,
    )


def _failed_step(
    preload: int, rate_pps: int, capture_state: str, error: str
) -> StepResult:
    """A step that produced no measurement, recorded rather than dropped."""
    return StepResult(
        preload_addresses=preload,
        offered_pps=rate_pps,
        capture_state=capture_state,
        error=error,
    )


def buffered_sniffer_factory(size_bytes: int) -> capture.SnifferFactory:
    """A sniffer factory that requests a larger kernel capture buffer.

    Npcap's default buffer is about 1 MB, which the sweep showed absorbing only
    a few seconds of backlog once the capture saturates. ``pcap_setbuff``
    resizes it after activation - the one knob that turns "drops after N
    seconds of deficit" into "drops after M times N seconds".

    ponytail: reaches into the sniffer's private socket chain, the same way
    :func:`read_counters` does. Ceiling - the ``pcap_fd.pcap`` attribute path
    is private scapy API. Upgrade path - use whatever ``netmon.capture`` grows
    for buffer sizing if it grows one.
    """

    def factory(
        iface: str,
        bpf_filter: str,
        on_packet: Callable[[Any], None],
        on_started: Callable[[], None],
    ) -> capture.Sniffer:
        from scapy.libs.winpcapy import pcap_setbuff

        sniffer = capture._PcapSniffer(iface, bpf_filter, on_packet, on_started)
        if pcap_setbuff(sniffer._socket.pcap_fd.pcap, size_bytes) != 0:
            raise RuntimeError(f"pcap_setbuff({size_bytes}) was refused")
        return sniffer

    return factory


def run_group(
    preload: int, args: argparse.Namespace, script: Path
) -> list[StepResult]:
    """Run every offered-load step against one retained-address count.

    :meth:`RateWindow.snapshot` is O(devices x buckets) and holds the lock
    :meth:`RateWindow.record` needs, so every poll stalls the capture callback
    for as long as it takes to walk the history. Comparing groups is what says
    whether that, rather than scapy's parsing, is the binding constraint.

    The capture, the aggregator and the HTTP server are rebuilt per group so
    the drop counters start from zero and the retained-address count is the
    only variable between them.
    """
    window = CountingWindow()
    for address in preload_addresses(preload):
        window.record(address)

    factory = None
    if args.kernel_buffer_mb is not None:
        factory = buffered_sniffer_factory(int(args.kernel_buffer_mb * BYTES_PER_MB))
    source = capture.CaptureSource(
        window, args.target_ip, iface=args.iface, sniffer_factory=factory
    )
    server = ThreadingHTTPServer(
        (SERVER_BIND_HOST, args.server_port),
        partial(
            RatesRequestHandler,
            window=window,
            host_ip=args.target_ip,
            read_capture_status=source.status,
            default_subnet=parse_subnet(args.subnet),
            # Never started, so nothing is ever written; the handler requires
            # one regardless.
            recorder=Recorder(
                window=window,
                recordings_dir=args.output_dir,
                filter_devices=devices_in_subnet,
            ),
        ),
    )
    server.daemon_threads = True
    server_thread = threading.Thread(
        target=server.serve_forever, name="benchmark-http", daemon=True
    )
    poller = RatesPoller(
        f"http://{SERVER_BIND_HOST}:{server.server_address[1]}/api/rates"
    )

    results: list[StepResult] = []
    try:
        server_thread.start()
        poller.start()
        source.start()
        status = source.status()
        if status.state != capture.CAPTURE_STATE_OK:
            print(f"  capture unhealthy: {status.state} - {status.detail}")
            return [
                _failed_step(preload, rate, status.state, status.detail)
                for rate in args.rates
            ]
        time.sleep(CAPTURE_WARMUP_S)

        for rate in args.rates:
            try:
                result = run_step(
                    source, window, poller, script, rate, preload, args
                )
            except Exception as error:
                # One bad step is a gap in the curve, not a reason to abandon
                # the ten minutes of sweep still to come.
                result = _failed_step(
                    preload,
                    rate,
                    source.status().state,
                    f"{type(error).__name__}: {error}",
                )
            results.append(result)
            print(format_row(result), flush=True)
            time.sleep(SETTLE_S)
    finally:
        poller.stop()
        source.stop()
        server.shutdown()
        server.server_close()
        server_thread.join(HTTP_TIMEOUT_S)
    return results


def format_row(result: StepResult) -> str:
    """One results row, sized to line up under :data:`HEADER_ROW`."""
    return HEADER_FORMAT.format(
        preload=result.preload_addresses,
        rate=result.offered_pps,
        sent=_cell(result.sent),
        counted=result.counted,
        counted_pps=_cell(result.counted_pps),
        recv=_cell(result.ps_recv),
        drop=_cell(result.ps_drop),
        ratio=_cell(result.drop_ratio),
        cpu=_cell(result.capture_cpu_cores),
        poll=_cell(result.poll_max_ms),
    ) + (f"  {result.error}" if result.error else "")


def _cell(value: object) -> str:
    """Render a possibly-absent reading for the console table."""
    return "-" if value is None else str(value)


def write_results(
    results: Sequence[StepResult], args: argparse.Namespace, directory: Path
) -> tuple[Path, Path]:
    """Write the run as JSON and CSV, and return both paths."""
    directory.mkdir(parents=True, exist_ok=True)
    stem = RESULT_FILENAME.format(
        stamp=datetime.now(timezone.utc).strftime(STAMP_FORMAT)
    )
    json_path = directory / f"{stem}.json"
    csv_path = directory / f"{stem}.csv"

    json_path.write_text(
        json.dumps(
            {
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "python": sys.version,
                "platform": sys.platform,
                "settings": {
                    "iface": args.iface,
                    "target": f"{args.target_ip}:{args.target_port}",
                    "payload_bytes": args.payload_bytes,
                    "duration_s": args.duration,
                    "rates_pps": list(args.rates),
                    "preload_addresses": list(args.preload),
                    "poll_interval_s": POLL_INTERVAL_S,
                    "kernel_buffer_mb": args.kernel_buffer_mb,
                },
                "steps": [asdict(result) for result in results],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=[field.name for field in fields(StepResult)]
        )
        writer.writeheader()
        writer.writerows(asdict(result) for result in results)
    return json_path, csv_path


def run_sweep(args: argparse.Namespace) -> int:
    """Run the whole matrix of retained-address counts and offered loads."""
    self_check()
    script = Path(__file__).resolve()
    total_s = len(args.rates) * len(args.preload) * (args.duration + SETTLE_S)
    print(
        f"Capturing {capture.filter_for(args.target_ip)!r} on {args.iface}\n"
        f"{len(args.preload)} x {len(args.rates)} steps of {args.duration:g}s "
        f"- roughly {total_s / 60:.0f} minutes\n"
    )
    print(HEADER_ROW, flush=True)

    results: list[StepResult] = []
    for preload in args.preload:
        results.extend(run_group(preload, args, script))

    json_path, csv_path = write_results(results, args, args.output_dir)
    print(f"\nWrote {json_path}\n      {csv_path}")
    return 1 if any(result.error for result in results) else 0


def run_blast(args: argparse.Namespace) -> int:
    """Send UDP at a paced rate and report how many packets actually left.

    The destination port is bound here and never read: an unbound port would
    make the kernel answer every packet with an ICMP unreachable, doubling the
    traffic the capture sees with packets the generator never counted.
    """
    payload = bytes(args.payload_bytes)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    try:
        sink.bind((args.target_ip, args.target_port))
        sender.connect((args.target_ip, args.target_port))
        print(READY_LINE, flush=True)
        started = time.perf_counter()
        while True:
            elapsed = time.perf_counter() - started
            if elapsed >= args.duration:
                break
            due = packets_due(args.rate, elapsed)
            if sent >= due:
                remaining = next_send_delay(
                    args.rate, sent, elapsed, args.duration
                )
                if remaining > MIN_SLEEP_S:
                    time.sleep(remaining)
                continue
            for _ in range(min(due - sent, MAX_SEND_BATCH)):
                sender.send(payload)
                sent += 1
    finally:
        sender.close()
        sink.close()
    print(
        json.dumps(
            {"sent": sent, "elapsed_s": round(time.perf_counter() - started, 3)}
        )
    )
    return 0


def self_check() -> None:
    """Exercise the harness's own arithmetic. Raises on a wrong answer.

    The measuring instrument gets its own check: a pacing or aggregation bug
    would show up as a plausible-looking curve rather than as a crash.
    """
    assert packets_due(1000, 0.5) == 500
    assert packets_due(1000, 0.0) == 0
    assert packets_due(0, 10.0) == 0
    assert packets_due(20000, 1.5) == 30000

    assert next_send_delay(1000, 0, 0.0, 30.0) == 0.001
    assert round(next_send_delay(1000, 500, 0.5, 30.0), 9) == 0.001
    # Behind schedule: the delay goes negative so the caller sends immediately.
    assert next_send_delay(1000, 100, 0.5, 30.0) < 0.0
    # An idle step has no schedule to follow, so it waits out the whole step.
    assert next_send_delay(0, 0, 2.0, 30.0) == 28.0
    assert next_send_delay(0, 0, 31.0, 30.0) == 0.0

    assert rate_per_second(300, 1.5) == 200.0
    assert rate_per_second(300, 0.0) == 0.0

    assert drop_ratio(1000, 10) == 0.01
    assert drop_ratio(0, 0) == 0.0
    assert drop_ratio(0, 5) == 1.0
    assert drop_ratio(None, 10) is None
    assert drop_ratio(1000, None) is None

    assert loss_ratio(1000, 900) == 0.1
    # The capture also sees the poller's own HTTP traffic, so a surplus is
    # expected and must not read as negative loss.
    assert loss_ratio(1000, 1200) == 0.0
    assert loss_ratio(0, 0) is None
    assert loss_ratio(None, 10) is None

    spiking = [
        Sample(at_s=0.0, counted=0, received=0, dropped=0, cpu_s=0.0),
        Sample(at_s=1.0, counted=100, received=100, dropped=0, cpu_s=0.1),
        Sample(at_s=2.0, counted=150, received=200, dropped=50, cpu_s=0.2),
    ]
    assert peak_interval_drop_ratio(spiking) == 0.5
    assert drop_ratio(200, 50) == 0.25, "cumulative ratio must hide the spike"
    assert peak_interval_drop_ratio(spiking[:1]) is None
    assert (
        peak_interval_drop_ratio(
            [
                Sample(at_s=0.0, counted=0, received=None, dropped=None, cpu_s=None),
                Sample(at_s=1.0, counted=10, received=None, dropped=None, cpu_s=None),
            ]
        )
        is None
    )

    summary = summarize_step(
        preload_addresses=1000,
        offered_pps=5000,
        samples=spiking,
        sent=10000,
        poll_latencies_ms=[10.0, 30.0],
        poll_failures=1,
        capture_state=capture.CAPTURE_STATE_OK,
    )
    assert summary.duration_s == 2.0
    assert summary.counted == 150
    assert summary.counted_pps == 75.0
    assert summary.loss_vs_sent == 0.985
    assert summary.ps_recv == 200
    assert summary.ps_drop == 50
    assert summary.drop_ratio == 0.25
    assert summary.peak_interval_drop_ratio == 0.5
    assert summary.recv_minus_counted == 50
    assert summary.capture_cpu_s == 0.2
    assert summary.capture_cpu_cores == 0.1
    assert summary.poll_mean_ms == 20.0
    assert summary.poll_max_ms == 30.0
    assert summary.poll_failures == 1
    assert summary.error is None

    empty = summarize_step(
        preload_addresses=0,
        offered_pps=500,
        samples=[],
        sent=None,
        poll_latencies_ms=[],
        poll_failures=0,
        capture_state=capture.CAPTURE_STATE_NOT_RUNNING,
    )
    assert empty.error is not None
    assert empty.counted == 0
    assert empty.poll_max_ms is None

    addresses = preload_addresses(1000)
    assert len(addresses) == len(set(addresses)) == 1000
    assert addresses[0] == "10.0.0.0"
    assert addresses[999] == "10.0.3.231"
    assert preload_addresses(0) == []


def run_self_check(args: argparse.Namespace) -> int:
    """Run :func:`self_check` from the command line."""
    self_check()
    print("self-check ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Command line for ``python tools/benchmark_capture.py``."""
    parser = argparse.ArgumentParser(
        prog="python tools/benchmark_capture.py",
        description=(
            "Measure the packet rate netmon's capture path sustains, using a "
            "UDP generator against the loopback adapter."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    sweep = commands.add_parser(
        "sweep", help="run the offered-load sweep and record the results"
    )
    sweep.add_argument(
        "--rates",
        type=int,
        nargs="+",
        default=list(DEFAULT_RATES_PPS),
        metavar="PPS",
        help=f"offered loads to step through (default: {_listed(DEFAULT_RATES_PPS)})",
    )
    sweep.add_argument(
        "--duration",
        type=float,
        default=DEFAULT_STEP_SECONDS,
        metavar="SECONDS",
        help=f"seconds per step (default: {DEFAULT_STEP_SECONDS:g})",
    )
    sweep.add_argument(
        "--preload",
        type=int,
        nargs="+",
        default=list(DEFAULT_PRELOAD_ADDRESSES),
        metavar="N",
        help="retained address counts to repeat the sweep at, which is what "
        f"exposes snapshot lock contention (default: {_listed(DEFAULT_PRELOAD_ADDRESSES)})",
    )
    sweep.add_argument(
        "--iface",
        default=DEFAULT_IFACE,
        help=f"capture interface (default: {DEFAULT_IFACE})",
    )
    sweep.add_argument(
        "--server-port",
        type=int,
        default=DEFAULT_SERVER_PORT,
        help="port for the polled /api/rates server, 0 for any free one "
        f"(default: {DEFAULT_SERVER_PORT})",
    )
    sweep.add_argument(
        "--subnet",
        default=DEFAULT_SUBNET,
        help="subnet the poller's response is narrowed to; the default excludes "
        "the preloaded addresses, so the measurement isolates lock contention "
        f"from response size (default: {DEFAULT_SUBNET})",
    )
    sweep.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"where the JSON and CSV results are written (default: {DEFAULT_OUTPUT_DIR})",
    )
    sweep.add_argument(
        "--kernel-buffer-mb",
        type=float,
        default=DEFAULT_KERNEL_BUFFER_MB,
        metavar="MB",
        help="kernel capture buffer size to request via pcap_setbuff; omit to "
        "keep Npcap's default of about 1 MB",
    )
    _add_traffic_arguments(sweep)
    sweep.set_defaults(handler=run_sweep)

    blast = commands.add_parser(
        "blast", help="generate UDP traffic; run as a subprocess by the sweep"
    )
    blast.add_argument("--rate", type=int, required=True, metavar="PPS")
    blast.add_argument("--duration", type=float, required=True, metavar="SECONDS")
    _add_traffic_arguments(blast)
    blast.set_defaults(handler=run_blast)

    check = commands.add_parser(
        "selfcheck", help="verify the harness's own arithmetic"
    )
    check.set_defaults(handler=run_self_check)

    return parser


def _add_traffic_arguments(parser: argparse.ArgumentParser) -> None:
    """Flags describing the generated traffic, shared by sweep and blast."""
    parser.add_argument(
        "--target-ip",
        default=DEFAULT_TARGET_IP,
        help="destination of the generated packets, which is also the address "
        f"the capture filters on (default: {DEFAULT_TARGET_IP})",
    )
    parser.add_argument(
        "--target-port",
        type=int,
        default=DEFAULT_TARGET_PORT,
        help=f"destination UDP port (default: {DEFAULT_TARGET_PORT})",
    )
    parser.add_argument(
        "--payload-bytes",
        type=int,
        default=DEFAULT_PAYLOAD_BYTES,
        help=f"UDP payload size (default: {DEFAULT_PAYLOAD_BYTES})",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args) or 0
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
