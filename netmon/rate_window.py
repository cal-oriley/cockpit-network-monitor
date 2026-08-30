"""Thread-safe rolling window of per-IP packet rates.

This module is the seam between the data source and everything above it: a
packet-capture thread has nothing to say to the aggregator beyond "this IP
sent a packet", which is exactly what :meth:`RateWindow.record` accepts.

The window knows nothing about subnets. It keeps every address it has ever
seen, and narrowing the view to one subnet is the server's job, so an address
hidden by a subnet change comes back with its history intact.

Time handling
-------------
The injectable ``clock`` is a *monotonic seconds* source, while the payload
handed to the UI speaks *milliseconds*. Buckets are addressed by **tick**, an
integer count of ``bucket_ms`` intervals elapsed since the window was created.

Only *completed* ticks are reported. The tick in progress keeps accumulating
in a spare ring slot and is published on the next snapshot, so the newest
value the UI draws is never a half-filled bucket that would read as a dip.
``now_ms`` is therefore the boundary between the newest completed bucket and
the one in progress: the wall-clock time captured at construction, advanced by
whole ticks. Driving it from the monotonic clock keeps the axis immune to
system-clock adjustments while still reading as a familiar Unix millisecond
timestamp. ``idle_ms``, in contrast, is measured against the unquantised
current time, because the UI compares it against a plain 2-second threshold.
"""

import ipaddress
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

MS_PER_SECOND = 1000
DEFAULT_BUCKET_MS = 100
DEFAULT_BUCKETS = 100
PPS_DECIMAL_PLACES = 2

Clock = Callable[[], float]


@dataclass
class _DeviceState:
    """Per-IP ring of packet counts, one slot per tick."""

    counts: list[int]
    head_tick: int
    last_packet_at: float
    total_packets: int = 0


def _ip_sort_key(ip: str) -> tuple[int, int, str]:
    """Order addresses numerically, so ``192.168.2.10`` follows ``.9``.

    Anything unparseable sorts after the real addresses by string, so a
    malformed key can never crash a poll.
    """
    try:
        return (0, int(ipaddress.ip_address(ip)), "")
    except ValueError:
        return (1, 0, ip)


class RateWindow:
    """Rolling packet-rate window shared by a producer and HTTP threads.

    Counters are advanced lazily from ``clock()`` on both :meth:`record` and
    :meth:`snapshot`, so an idle process needs no timer thread; ticks skipped
    over are zero-filled as they are passed.
    """

    def __init__(
        self,
        bucket_ms: int = DEFAULT_BUCKET_MS,
        buckets: int = DEFAULT_BUCKETS,
        clock: Clock = time.monotonic,
    ) -> None:
        if bucket_ms <= 0:
            raise ValueError("bucket_ms must be positive")
        if buckets <= 0:
            raise ValueError("buckets must be positive")

        self._bucket_ms = bucket_ms
        self._buckets = buckets
        self._clock = clock
        self._lock = threading.Lock()
        self._devices: dict[str, _DeviceState] = {}
        # One slot beyond the reported window holds the tick in progress, so
        # the oldest completed bucket is not overwritten before it is read.
        self._ring_size = buckets + 1
        self._clock_epoch = clock()
        self._wall_epoch_ms = int(time.time() * MS_PER_SECOND)

    @property
    def bucket_ms(self) -> int:
        """Width of a single bucket, in milliseconds."""
        return self._bucket_ms

    @property
    def buckets(self) -> int:
        """Number of completed buckets reported per device."""
        return self._buckets

    def record(self, ip: str, packets: int = 1) -> None:
        """Attribute ``packets`` arriving from ``ip`` to the current bucket.

        The first call for an address adds it to the window; it then stays for
        the lifetime of the process, reporting zeros once it goes quiet.
        """
        if not ip:
            raise ValueError("ip must be a non-empty string")
        if packets < 1:
            raise ValueError("packets must be at least 1")

        with self._lock:
            now = self._clock()
            tick = self._tick(now)
            device = self._devices.get(ip)
            if device is None:
                device = _DeviceState(
                    counts=[0] * self._ring_size,
                    head_tick=tick,
                    last_packet_at=now,
                )
                self._devices[ip] = device
            else:
                self._advance(device, tick)
            device.counts[tick % self._ring_size] += packets
            device.total_packets += packets
            device.last_packet_at = now

    def snapshot(self) -> dict[str, Any]:
        """Return the current window as the ``/api/rates`` payload body.

        **Every** device's ring is advanced to the current tick, not only those
        that recorded recently, so a silent device keeps returning a
        full-length array that scrolls and fills with zeros from the right.
        Advancing only inside :meth:`record` would freeze an idle device's
        array at whatever it held when its last packet arrived, and a stalled
        graph reads as a dead monitor rather than a dropout.

        The caller adds the fields the aggregator cannot know: ``host_ip``,
        ``subnet``, and the capture status.
        """
        with self._lock:
            now = self._clock()
            tick = self._tick(now)
            devices = [
                self._device_payload(ip, self._devices[ip], tick, now)
                for ip in sorted(self._devices, key=_ip_sort_key)
            ]
            return {
                "bucket_ms": self._bucket_ms,
                "buckets": self._buckets,
                "now_ms": self._wall_epoch_ms + tick * self._bucket_ms,
                "devices": devices,
            }

    def _tick(self, now: float) -> int:
        """Convert a clock reading into an absolute bucket index."""
        elapsed_ms = (now - self._clock_epoch) * MS_PER_SECOND
        return int(elapsed_ms // self._bucket_ms)

    def _advance(self, device: _DeviceState, tick: int) -> None:
        """Zero-fill every slot between the device's head tick and ``tick``."""
        steps = min(tick - device.head_tick, self._ring_size)
        for offset in range(1, steps + 1):
            device.counts[(device.head_tick + offset) % self._ring_size] = 0
        if tick > device.head_tick:
            device.head_tick = tick

    def _device_payload(
        self, ip: str, device: _DeviceState, tick: int, now: float
    ) -> dict[str, Any]:
        """Render one device, oldest completed bucket first.

        The ring is advanced to ``tick`` first, whether or not this device has
        recorded anything since it was last read, which is what keeps a silent
        device's trace marching leftward along the baseline.
        """
        self._advance(device, tick)
        seconds_per_bucket = self._bucket_ms / MS_PER_SECOND
        pps = [
            round(
                device.counts[(tick - age) % self._ring_size] / seconds_per_bucket,
                PPS_DECIMAL_PLACES,
            )
            for age in range(self._buckets, 0, -1)
        ]
        return {
            "ip": ip,
            "pps": pps,
            "current_pps": pps[-1],
            "peak_pps": max(pps),
            "total_packets": device.total_packets,
            # Rounded, not truncated: floating-point seconds otherwise land a
            # millisecond short of every round number.
            "idle_ms": max(0, round((now - device.last_packet_at) * MS_PER_SECOND)),
        }
