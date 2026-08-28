"""Contract tests for the rolling packet-rate window.

These assert the shape and semantics the HTTP payload promises - fixed-length
bucket arrays, lazy expiry, numeric ordering - rather than how the ring buffer
happens to be laid out inside.
"""

import threading

import pytest

from netmon.rate_window import RateWindow

from .conftest import FakeClock

BUCKET_MS = 250
SMALL_BUCKETS = 4
SCROLL_BUCKETS = 6
BUCKET_S = BUCKET_MS / 1000
# The ring keeps one slot beyond the reported window for the tick in progress,
# so a value only comes back around into the read window after more than
# ``buckets + 1`` silent ticks - and lands off the one slot the read skips.
WRAPAROUND_SILENT_BUCKETS = SCROLL_BUCKETS + 3
DEVICE_IP = "192.168.2.2"
OTHER_DEVICE_IP = "192.168.2.3"


def make_window(clock: FakeClock, buckets: int = SMALL_BUCKETS) -> RateWindow:
    return RateWindow(bucket_ms=BUCKET_MS, buckets=buckets, clock=clock)


def only_device(window: RateWindow) -> dict:
    devices = window.snapshot()["devices"]
    assert len(devices) == 1
    return devices[0]


def pps_of(window: RateWindow, ip: str) -> list[float]:
    devices = window.snapshot()["devices"]
    matches = [device for device in devices if device["ip"] == ip]
    assert matches, f"{ip} is not in the window"
    return matches[0]["pps"]


def test_geometry_is_reported_and_starts_empty(clock: FakeClock) -> None:
    snapshot = make_window(clock).snapshot()

    assert snapshot["bucket_ms"] == BUCKET_MS
    assert snapshot["buckets"] == SMALL_BUCKETS
    assert snapshot["devices"] == []


@pytest.mark.parametrize("buckets", [1, 4, 40])
def test_constructor_geometry_is_exposed(clock: FakeClock, buckets: int) -> None:
    window = make_window(clock, buckets=buckets)

    assert window.bucket_ms == BUCKET_MS
    assert window.buckets == buckets


@pytest.mark.parametrize("bucket_ms,buckets", [(0, 4), (-1, 4), (250, 0), (250, -3)])
def test_constructor_rejects_impossible_geometry(bucket_ms: int, buckets: int) -> None:
    with pytest.raises(ValueError):
        RateWindow(bucket_ms=bucket_ms, buckets=buckets)


def test_first_packet_inserts_the_device(clock: FakeClock) -> None:
    window = make_window(clock)

    assert window.snapshot()["devices"] == []
    window.record(DEVICE_IP)

    assert only_device(window)["ip"] == DEVICE_IP


@pytest.mark.parametrize("elapsed_s", [0.0, 0.1, BUCKET_S, 1.0, 3600.0])
def test_pps_is_always_exactly_buckets_long(
    clock: FakeClock, elapsed_s: float
) -> None:
    window = make_window(clock, buckets=40)
    window.record(DEVICE_IP, 7)
    clock.advance(elapsed_s)

    device = only_device(window)

    assert len(device["pps"]) == 40
    assert device["current_pps"] == device["pps"][-1]


def test_rate_is_packet_count_over_bucket_seconds(clock: FakeClock) -> None:
    window = make_window(clock)
    window.record(DEVICE_IP, 5)
    clock.advance(BUCKET_S)

    device = only_device(window)

    assert device["current_pps"] == pytest.approx(5 / BUCKET_S)
    assert device["pps"] == [0.0, 0.0, 0.0, 20.0]


def test_bucket_in_progress_is_withheld_until_it_completes(
    clock: FakeClock,
) -> None:
    window = make_window(clock)
    window.record(DEVICE_IP, 5)

    assert only_device(window)["pps"] == [0.0] * SMALL_BUCKETS

    clock.advance(BUCKET_S)

    assert only_device(window)["pps"][-1] == 20.0


def test_successive_buckets_roll_over_oldest_first(clock: FakeClock) -> None:
    window = make_window(clock)
    window.record(DEVICE_IP, 1)
    clock.advance(BUCKET_S)
    window.record(DEVICE_IP, 2)
    clock.advance(BUCKET_S)

    assert only_device(window)["pps"] == [0.0, 0.0, 4.0, 8.0]


def test_skipped_buckets_are_zero_filled(clock: FakeClock) -> None:
    window = make_window(clock)
    window.record(DEVICE_IP, 1)
    clock.advance(3 * BUCKET_S)
    window.record(DEVICE_IP, 4)
    clock.advance(BUCKET_S)

    assert only_device(window)["pps"] == [4.0, 0.0, 0.0, 16.0]


def test_counts_expire_once_the_window_passes_them(clock: FakeClock) -> None:
    window = make_window(clock)
    window.record(DEVICE_IP, 8)
    clock.advance((SMALL_BUCKETS + 1) * BUCKET_S)

    device = only_device(window)

    assert device["pps"] == [0.0] * SMALL_BUCKETS
    assert device["current_pps"] == 0.0
    assert device["peak_pps"] == 0.0


def test_quiet_device_stays_in_the_list_reporting_zeros(clock: FakeClock) -> None:
    window = make_window(clock)
    window.record(DEVICE_IP)
    clock.advance(3600.0)

    device = only_device(window)

    assert device["ip"] == DEVICE_IP
    assert device["pps"] == [0.0] * SMALL_BUCKETS
    assert device["total_packets"] == 1


def test_a_silent_window_scrolls_left_by_the_buckets_that_passed(
    clock: FakeClock,
) -> None:
    """Wall-clock time, not traffic, is what moves a device's window along."""
    window = make_window(clock, buckets=SCROLL_BUCKETS)
    for packets in (1, 2, 3):
        window.record(DEVICE_IP, packets)
        clock.advance(BUCKET_S)
    before = pps_of(window, DEVICE_IP)

    shift = 2
    clock.advance(shift * BUCKET_S)
    after = pps_of(window, DEVICE_IP)

    assert len(after) == len(before)
    assert after == before[shift:] + [0.0] * shift


def test_every_device_scrolls_not_only_the_ones_recording(
    clock: FakeClock,
) -> None:
    window = make_window(clock, buckets=SCROLL_BUCKETS)
    for ip in (DEVICE_IP, OTHER_DEVICE_IP):
        window.record(ip, 4)
    clock.advance(BUCKET_S)
    before = pps_of(window, DEVICE_IP)

    shift = 3
    for _ in range(shift):
        window.record(OTHER_DEVICE_IP, 4)
        clock.advance(BUCKET_S)

    assert pps_of(window, DEVICE_IP) == before[shift:] + [0.0] * shift
    assert pps_of(window, OTHER_DEVICE_IP)[-1] == 16.0


def test_a_device_silent_for_a_whole_window_reports_zeros_not_a_stale_array(
    clock: FakeClock,
) -> None:
    window = make_window(clock, buckets=SCROLL_BUCKETS)
    window.record(DEVICE_IP, 9)
    clock.advance(BUCKET_S)
    assert only_device(window)["peak_pps"] == 36.0

    clock.advance(SCROLL_BUCKETS * BUCKET_S)
    device = only_device(window)

    assert device["pps"] == [0.0] * SCROLL_BUCKETS
    assert device["current_pps"] == 0.0
    assert device["peak_pps"] == 0.0
    assert device["total_packets"] == 9


def test_an_old_burst_never_wraps_back_into_view_while_a_device_is_silent(
    clock: FakeClock,
) -> None:
    """Silence long enough to wrap the ring must still read as zeros.

    The ring is only as long as the window plus the tick in progress, so its
    slots are reused. Stay quiet for longer than that and the slot holding the
    burst is addressed again from the far side of the wrap - which is where a
    ring advanced only by ``record`` hands the UI a value from a minute ago as
    if it had just arrived.
    """
    window = make_window(clock, buckets=SCROLL_BUCKETS)
    window.record(DEVICE_IP, 9)
    clock.advance(BUCKET_S)
    assert max(pps_of(window, DEVICE_IP)) == 36.0

    clock.advance(WRAPAROUND_SILENT_BUCKETS * BUCKET_S)
    pps = pps_of(window, DEVICE_IP)

    assert len(pps) == SCROLL_BUCKETS
    assert pps == [0.0] * SCROLL_BUCKETS


def test_a_device_quiet_since_its_first_packet_still_moves_with_the_clock(
    clock: FakeClock,
) -> None:
    """A device seen once at startup and never again must not freeze."""
    window = make_window(clock, buckets=SCROLL_BUCKETS)
    window.record(DEVICE_IP)
    clock.advance(3600.0)
    first = window.snapshot()

    clock.advance(2 * BUCKET_S)
    second = window.snapshot()

    assert second["now_ms"] == first["now_ms"] + 2 * BUCKET_MS
    for snapshot in (first, second):
        assert snapshot["devices"][0]["pps"] == [0.0] * SCROLL_BUCKETS


def test_peak_is_the_maximum_across_the_window(clock: FakeClock) -> None:
    window = make_window(clock)
    for packets in (1, 9, 2):
        window.record(DEVICE_IP, packets)
        clock.advance(BUCKET_S)

    assert only_device(window)["peak_pps"] == 36.0


def test_peak_falls_away_with_the_bucket_that_set_it(clock: FakeClock) -> None:
    window = make_window(clock)
    window.record(DEVICE_IP, 9)
    clock.advance(BUCKET_S)
    assert only_device(window)["peak_pps"] == 36.0

    window.record(DEVICE_IP, 1)
    clock.advance(SMALL_BUCKETS * BUCKET_S)

    assert only_device(window)["peak_pps"] == 4.0


def test_idle_ms_grows_while_the_device_is_quiet(clock: FakeClock) -> None:
    window = make_window(clock)
    window.record(DEVICE_IP)

    assert only_device(window)["idle_ms"] == 0

    clock.advance(0.6)
    assert only_device(window)["idle_ms"] == 600

    clock.advance(1.4)
    assert only_device(window)["idle_ms"] == 2000

    window.record(DEVICE_IP)
    assert only_device(window)["idle_ms"] == 0


def test_total_packets_accumulates_beyond_the_window(clock: FakeClock) -> None:
    window = make_window(clock)
    for _ in range(10):
        window.record(DEVICE_IP, 3)
        clock.advance(BUCKET_S)

    assert only_device(window)["total_packets"] == 30


def test_devices_are_sorted_numerically_not_lexically(clock: FakeClock) -> None:
    window = make_window(clock)
    for ip in ("192.168.2.10", "192.168.2.2", "192.168.2.9", "192.168.2.100"):
        window.record(ip)

    order = [device["ip"] for device in window.snapshot()["devices"]]

    assert order == [
        "192.168.2.2",
        "192.168.2.9",
        "192.168.2.10",
        "192.168.2.100",
    ]


def test_device_order_is_stable_across_polls(clock: FakeClock) -> None:
    window = make_window(clock)
    for ip in ("192.168.2.10", "192.168.2.2"):
        window.record(ip)
    first = [device["ip"] for device in window.snapshot()["devices"]]

    clock.advance(BUCKET_S)
    window.record("192.168.2.2")
    clock.advance(BUCKET_S)

    second = [device["ip"] for device in window.snapshot()["devices"]]

    assert first == second


def test_unparseable_address_sorts_last_without_failing(clock: FakeClock) -> None:
    window = make_window(clock)
    window.record("not-an-ip")
    window.record("192.168.2.2")

    order = [device["ip"] for device in window.snapshot()["devices"]]

    assert order == ["192.168.2.2", "not-an-ip"]


def test_now_ms_advances_one_bucket_per_tick(clock: FakeClock) -> None:
    window = make_window(clock)
    start_ms = window.snapshot()["now_ms"]

    clock.advance(BUCKET_S / 2)
    assert window.snapshot()["now_ms"] == start_ms

    clock.advance(3 * BUCKET_S)
    assert window.snapshot()["now_ms"] == start_ms + 3 * BUCKET_MS


@pytest.mark.parametrize("ip,packets", [("", 1), ("192.168.2.2", 0), ("x", -1)])
def test_record_rejects_meaningless_input(
    clock: FakeClock, ip: str, packets: int
) -> None:
    window = make_window(clock)

    with pytest.raises(ValueError):
        window.record(ip, packets)


def test_concurrent_records_and_snapshots_lose_nothing() -> None:
    """The producer thread and HTTP handler threads share one window."""
    window = RateWindow(bucket_ms=BUCKET_MS, buckets=40)
    producers = 8
    per_producer = 500
    ips = ["192.168.2.2", "192.168.2.3", "192.168.2.4"]
    stop_reading = threading.Event()
    failures: list[BaseException] = []

    def produce(index: int) -> None:
        try:
            for count in range(per_producer):
                window.record(ips[(index + count) % len(ips)])
        except BaseException as error:  # pragma: no cover - failure path
            failures.append(error)

    def read() -> None:
        try:
            while not stop_reading.is_set():
                snapshot = window.snapshot()
                for device in snapshot["devices"]:
                    assert len(device["pps"]) == snapshot["buckets"]
        except BaseException as error:  # pragma: no cover - failure path
            failures.append(error)

    reader = threading.Thread(target=read)
    reader.start()
    writers = [threading.Thread(target=produce, args=(i,)) for i in range(producers)]
    for writer in writers:
        writer.start()
    for writer in writers:
        writer.join()
    stop_reading.set()
    reader.join()

    assert failures == []
    recorded = sum(
        device["total_packets"] for device in window.snapshot()["devices"]
    )
    assert recorded == producers * per_producer
