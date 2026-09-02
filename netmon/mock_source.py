"""Synthetic traffic generator that feeds a :class:`RateWindow`.

The profiles below are chosen to exercise every state the UI has to render -
steady, bursty, barely-there, dropping out, and arriving late - so the page can
be built and reviewed without packet capture, elevation, or a vehicle. They
span two subnets, because a filter with nothing outside the default subnet to
hide cannot be reviewed at all.
"""

import random
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .capture import CaptureStatus
from .rate_window import MS_PER_SECOND, RateWindow

Clock = Callable[[], float]

CAPTURE_STATE_MOCK = "mock"
MOCK_DETAIL = "Showing simulated traffic."

TELEMETRY_PPS = 30.0
TELEMETRY_JITTER = 0.08
VIDEO_PPS = 200.0
VIDEO_JITTER = 0.35
QUIET_PPS = 5.0
DROPOUT_PPS = 40.0
DROPOUT_JITTER = 0.1
DROPOUT_PERIOD_S = 15.0
DROPOUT_SILENCE_S = 4.0
LATE_PPS = 20.0
LATE_JITTER = 0.15
LATE_APPEARANCE_S = 8.0
SECONDARY_STEADY_PPS = 16.0
SECONDARY_STEADY_JITTER = 0.05
SECONDARY_BURSTY_PPS = 120.0
SECONDARY_BURSTY_JITTER = 0.6

STOP_TIMEOUT_S = 2.0
THREAD_NAME = "netmon-mock-source"


@dataclass(frozen=True)
class MockDevice:
    """Traffic profile for one synthetic device.

    ``jitter`` is a fraction of ``base_pps`` swung either way each bucket. A
    device with a ``silent_period_s`` cycle transmits for the first part of
    every cycle and falls silent for the last ``silent_duration_s`` of it.
    """

    ip: str
    base_pps: float
    jitter: float = 0.0
    appears_after_s: float = 0.0
    silent_period_s: float = 0.0
    silent_duration_s: float = 0.0

    def is_silent(self, elapsed_s: float) -> bool:
        """Whether this device is inside a scheduled dropout at ``elapsed_s``."""
        if self.silent_period_s <= 0.0 or self.silent_duration_s <= 0.0:
            return False
        phase = (elapsed_s - self.appears_after_s) % self.silent_period_s
        return phase >= self.silent_period_s - self.silent_duration_s

    def packets_for(
        self, elapsed_s: float, interval_s: float, rng: random.Random
    ) -> int:
        """Packets this device sends during one ``interval_s`` bucket."""
        if elapsed_s < self.appears_after_s or self.is_silent(elapsed_s):
            return 0
        rate = self.base_pps * (1.0 + self.jitter * rng.uniform(-1.0, 1.0))
        return _stochastic_round(max(0.0, rate) * interval_s, rng)


def _stochastic_round(value: float, rng: random.Random) -> int:
    """Round to an integer, treating the fraction as a probability.

    A 5 pps device owes 0.5 packets per 100 ms bucket; truncating would peg it
    at a flat 4 pps forever, so the fractional part decides a coin flip and the
    long-run average comes out right.
    """
    whole = int(value)
    return whole + (1 if rng.random() < value - whole else 0)


DEFAULT_MOCK_DEVICES: tuple[MockDevice, ...] = (
    # Steady telemetry: the baseline "healthy" trace.
    MockDevice(ip="192.168.2.2", base_pps=TELEMETRY_PPS, jitter=TELEMETRY_JITTER),
    # Video-ish: high rate with enough jitter to show a lively waveform.
    MockDevice(ip="192.168.2.3", base_pps=VIDEO_PPS, jitter=VIDEO_JITTER),
    # Barely-there device: exercises autoscaling on a near-flat trace.
    MockDevice(ip="192.168.2.4", base_pps=QUIET_PPS),
    # Dropout: flatlines for 4 s of every 15 s to demo the stale badge.
    MockDevice(
        ip="192.168.2.5",
        base_pps=DROPOUT_PPS,
        jitter=DROPOUT_JITTER,
        silent_period_s=DROPOUT_PERIOD_S,
        silent_duration_s=DROPOUT_SILENCE_S,
    ),
    # Late arrival: demos dynamic row insertion, and sorts after .5 numerically.
    MockDevice(
        ip="192.168.2.10",
        base_pps=LATE_PPS,
        jitter=LATE_JITTER,
        appears_after_s=LATE_APPEARANCE_S,
    ),
    # A second subnet, so the page's subnet control has somewhere to switch to
    # and the filter changes which rows are drawn rather than emptying the grid.
    MockDevice(
        ip="10.11.12.2",
        base_pps=SECONDARY_STEADY_PPS,
        jitter=SECONDARY_STEADY_JITTER,
    ),
    MockDevice(
        ip="10.11.12.3",
        base_pps=SECONDARY_BURSTY_PPS,
        jitter=SECONDARY_BURSTY_JITTER,
    ),
)


class MockSource:
    """Drives :meth:`RateWindow.record` for a set of synthetic devices.

    The schedule that decides when a device appears or drops out runs from
    construction, so a source can be ticked by hand - :meth:`tick` produces
    exactly one bucket's worth of traffic - without ever starting the thread.
    """

    def __init__(
        self,
        window: RateWindow,
        devices: Iterable[MockDevice] = DEFAULT_MOCK_DEVICES,
        tick_ms: int | None = None,
        clock: Clock = time.monotonic,
        rng: random.Random | None = None,
    ) -> None:
        self._window = window
        self._devices = tuple(devices)
        self._tick_ms = window.bucket_ms if tick_ms is None else tick_ms
        if self._tick_ms <= 0:
            raise ValueError("tick_ms must be positive")

        self._clock = clock
        self._rng = random.Random() if rng is None else rng
        self._started_at = clock()
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def devices(self) -> tuple[MockDevice, ...]:
        """The profiles this source generates traffic for."""
        return self._devices

    @property
    def running(self) -> bool:
        """Whether the generator thread is currently alive."""
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> CaptureStatus:
        """Say that this traffic is simulated, however the thread is faring.

        Synthetic traffic has no health to report: the state names where the
        rates came from, so the page can tag them as invented rather than
        warning about a capture that was never meant to exist.
        """
        return CaptureStatus(CAPTURE_STATE_MOCK, MOCK_DETAIL)

    def tick(self) -> None:
        """Record one bucket's worth of traffic for every device."""
        elapsed_s = self._clock() - self._started_at
        interval_s = self._tick_ms / MS_PER_SECOND
        for device in self._devices:
            packets = device.packets_for(elapsed_s, interval_s, self._rng)
            if packets:
                self._window.record(device.ip, packets)

    def start(self) -> None:
        """Begin generating traffic on a daemon thread."""
        if self._thread is not None:
            raise RuntimeError("mock source is already running")
        self._stopping.clear()
        self._thread = threading.Thread(
            target=self._run, name=THREAD_NAME, daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = STOP_TIMEOUT_S) -> None:
        """Ask the thread to finish and wait for it. A no-op if not started."""
        thread = self._thread
        if thread is None:
            return
        self._stopping.set()
        thread.join(timeout)
        self._thread = None

    def _run(self) -> None:
        """Tick on a fixed schedule until stopped, without accumulating drift."""
        interval_s = self._tick_ms / MS_PER_SECOND
        next_deadline = self._clock()
        while not self._stopping.is_set():
            self.tick()
            next_deadline += interval_s
            if self._stopping.wait(max(0.0, next_deadline - self._clock())):
                break
