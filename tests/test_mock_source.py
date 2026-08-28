"""Tests for the synthetic traffic generator.

The generator's job is to put the aggregator - and therefore the UI - through
every state it has to render, so these tests drive its schedule with a fake
clock and assert the behaviours the prototype depends on.
"""

import random
import threading
import time

import pytest

from netmon.mock_source import (
    DEFAULT_MOCK_DEVICES,
    DROPOUT_PERIOD_S,
    DROPOUT_SILENCE_S,
    LATE_APPEARANCE_S,
    THREAD_NAME,
    MockDevice,
    MockSource,
)
from netmon.rate_window import RateWindow

from .conftest import FakeClock

SEED = 20260828
BUCKET_MS = 250
BUCKET_S = BUCKET_MS / 1000
WINDOW_BUCKETS = 40

LATE_DEVICE_IP = "192.168.2.10"
DROPOUT_DEVICE_IP = "192.168.2.5"
QUIET_DEVICE_IP = "192.168.2.4"
TELEMETRY_DEVICE_IP = "192.168.2.2"

# A rate that divides evenly into a bucket, so no coin flip is involved.
EXACT_PPS = 8.0
THREAD_TEST_TICK_MS = 5
THREAD_TEST_PPS = 1_000.0
THREAD_TEST_DEADLINE_S = 2.0


def build_source(
    clock: FakeClock,
    devices: tuple[MockDevice, ...] = DEFAULT_MOCK_DEVICES,
    bucket_ms: int = BUCKET_MS,
) -> tuple[RateWindow, MockSource]:
    window = RateWindow(bucket_ms=bucket_ms, buckets=WINDOW_BUCKETS, clock=clock)
    source = MockSource(
        window, devices=devices, clock=clock, rng=random.Random(SEED)
    )
    return window, source


def run_ticks(clock: FakeClock, source: MockSource, seconds: float) -> None:
    """Tick once per bucket across ``seconds`` of simulated time."""
    for _ in range(round(seconds / BUCKET_S)):
        source.tick()
        clock.advance(BUCKET_S)


def device_named(window: RateWindow, ip: str) -> dict:
    matches = [d for d in window.snapshot()["devices"] if d["ip"] == ip]
    assert matches, f"{ip} is not in the window"
    return matches[0]


def addresses(window: RateWindow) -> list[str]:
    return [device["ip"] for device in window.snapshot()["devices"]]


def test_default_profiles_cover_five_distinct_devices() -> None:
    ips = [device.ip for device in DEFAULT_MOCK_DEVICES]

    assert len(ips) == 5
    assert len(set(ips)) == 5


def test_late_device_appears_only_after_its_delay(clock: FakeClock) -> None:
    window, source = build_source(clock)

    run_ticks(clock, source, LATE_APPEARANCE_S)
    assert LATE_DEVICE_IP not in addresses(window)

    run_ticks(clock, source, 2.0)
    assert LATE_DEVICE_IP in addresses(window)


def test_other_devices_are_present_from_the_first_tick(clock: FakeClock) -> None:
    window, source = build_source(clock)

    source.tick()

    assert set(addresses(window)) == {
        TELEMETRY_DEVICE_IP,
        "192.168.2.3",
        QUIET_DEVICE_IP,
        DROPOUT_DEVICE_IP,
    }


@pytest.mark.parametrize(
    "elapsed_s,silent",
    [(0.0, False), (10.9, False), (11.0, True), (14.9, True), (15.0, False), (26.0, True)],
)
def test_dropout_schedule_silences_the_tail_of_each_cycle(
    elapsed_s: float, silent: bool
) -> None:
    device = MockDevice(
        ip=DROPOUT_DEVICE_IP,
        base_pps=40.0,
        silent_period_s=DROPOUT_PERIOD_S,
        silent_duration_s=DROPOUT_SILENCE_S,
    )

    assert device.is_silent(elapsed_s) is silent
    assert (device.packets_for(elapsed_s, BUCKET_S, random.Random(SEED)) == 0) is silent


def test_devices_without_a_dropout_schedule_never_go_silent() -> None:
    device = MockDevice(ip=QUIET_DEVICE_IP, base_pps=5.0)

    assert device.is_silent(0.0) is False
    assert device.is_silent(12.0) is False


def test_dropout_device_flatlines_for_its_silent_seconds(clock: FakeClock) -> None:
    window, source = build_source(clock)

    run_ticks(clock, source, DROPOUT_PERIOD_S)
    pps = device_named(window, DROPOUT_DEVICE_IP)["pps"]

    silent_buckets = round(DROPOUT_SILENCE_S / BUCKET_S)
    assert pps[-silent_buckets:] == [0.0] * silent_buckets
    assert any(rate > 0.0 for rate in pps[:-silent_buckets])


def test_dropout_device_recovers_on_the_next_cycle(clock: FakeClock) -> None:
    window, source = build_source(clock)

    run_ticks(clock, source, DROPOUT_PERIOD_S + 2.0)

    assert device_named(window, DROPOUT_DEVICE_IP)["current_pps"] > 0.0


def test_a_bucket_aligned_rate_is_reproduced_exactly(clock: FakeClock) -> None:
    device = MockDevice(ip=TELEMETRY_DEVICE_IP, base_pps=EXACT_PPS)
    window, source = build_source(clock, devices=(device,))

    source.tick()
    clock.advance(BUCKET_S)

    assert device_named(window, TELEMETRY_DEVICE_IP)["current_pps"] == EXACT_PPS


def test_tick_interval_comes_from_the_window_bucket(clock: FakeClock) -> None:
    """A wider bucket must mean more packets per tick, not the same number."""
    device = MockDevice(ip=TELEMETRY_DEVICE_IP, base_pps=EXACT_PPS)
    window, source = build_source(clock, devices=(device,), bucket_ms=2 * BUCKET_MS)

    source.tick()
    clock.advance(2 * BUCKET_S)

    assert device_named(window, TELEMETRY_DEVICE_IP)["total_packets"] == 4


@pytest.mark.parametrize(
    "ip,expected_pps",
    [(QUIET_DEVICE_IP, 5.0), (TELEMETRY_DEVICE_IP, 30.0)],
)
def test_long_run_rate_tracks_the_profile(
    clock: FakeClock, ip: str, expected_pps: float
) -> None:
    """Fractional per-bucket rates must not be truncated away."""
    duration_s = 40.0
    window, source = build_source(clock)

    run_ticks(clock, source, duration_s)
    total = device_named(window, ip)["total_packets"]

    assert total == pytest.approx(expected_pps * duration_s, rel=0.15)


def test_tick_ms_must_be_positive(clock: FakeClock) -> None:
    window = RateWindow(bucket_ms=BUCKET_MS, buckets=WINDOW_BUCKETS, clock=clock)

    with pytest.raises(ValueError):
        MockSource(window, tick_ms=0, clock=clock)


def test_stopping_a_source_that_never_started_is_harmless(clock: FakeClock) -> None:
    _, source = build_source(clock)

    source.stop()

    assert source.running is False


def test_starting_twice_is_rejected(clock: FakeClock) -> None:
    _, source = build_source(clock, devices=())
    source.start()
    try:
        with pytest.raises(RuntimeError):
            source.start()
    finally:
        source.stop()


def test_generator_thread_feeds_the_window_and_stops_cleanly() -> None:
    """The one place a real thread and a real clock are exercised."""
    window = RateWindow(bucket_ms=BUCKET_MS, buckets=WINDOW_BUCKETS)
    device = MockDevice(ip=TELEMETRY_DEVICE_IP, base_pps=THREAD_TEST_PPS)
    source = MockSource(window, devices=(device,), tick_ms=THREAD_TEST_TICK_MS)

    source.start()
    try:
        assert source.running is True
        worker = next(t for t in threading.enumerate() if t.name == THREAD_NAME)
        assert worker.daemon is True

        deadline = time.monotonic() + THREAD_TEST_DEADLINE_S
        while not window.snapshot()["devices"] and time.monotonic() < deadline:
            time.sleep(0.01)
        assert device_named(window, TELEMETRY_DEVICE_IP)["total_packets"] > 0
    finally:
        source.stop()

    assert source.running is False
    assert worker.is_alive() is False
