"""Tests for the CSV recorder.

Bucket accounting gets the most attention, because it is the part that can go
wrong quietly: a duplicated row, a missing one, or a file that is short because
the writer fell behind all look like ordinary data afterwards. The fake clock
drives every one of these, so a tick that is early, late, or later than the
whole window is a deterministic thing to assert rather than a race to provoke.

Recorders come from the ``build`` fixture, which stops each one at the end of
the test, and every file written here lives in a pytest ``tmp_path``.
"""

import csv
import io
import ipaddress
import threading
import time
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path

import pytest

from netmon import recorder as recorder_module
from netmon.rate_window import Clock, RateWindow
from netmon.recorder import (
    CSV_HEADER,
    IDLE_STATUS,
    THREAD_NAME,
    AlreadyRecordingError,
    IPNetwork,
    Recorder,
    RecordingStartError,
    buckets_since,
    iso_timestamp,
    open_recording,
    recording_filename,
    unique_recording_path,
)
from netmon.server import devices_in_subnet

from .conftest import FakeClock

BUCKET_MS = 250
BUCKET_S = BUCKET_MS / 1000
WINDOW_BUCKETS = 8
WINDOW_S = WINDOW_BUCKETS * BUCKET_S
PACKETS_PER_BUCKET = 3
BUCKET_PPS = PACKETS_PER_BUCKET / BUCKET_S

SUBNET = ipaddress.ip_network("192.168.2.0/24")
SECOND_SUBNET = ipaddress.ip_network("10.11.12.0/24")
SUBNET_IPS = ("192.168.2.2", "192.168.2.3")
OUTSIDE_IP = "10.11.12.2"

# Far longer than any test, so the recorder's own thread never fires while a
# test is driving tick() by hand.
IDLE_TICK_MS = 60 * 60 * 1000

DISK_FULL = "No space left on device"

THREAD_TEST_BUCKET_MS = 20
THREAD_TEST_DEADLINE_S = 3.0
THREAD_TEST_POLL_S = 0.01

RecorderFactory = Callable[..., tuple[RateWindow, Recorder]]


class FailingFile(io.StringIO):
    """A file whose writes fail the way a full disk does."""

    def write(self, data: str) -> int:
        raise OSError(DISK_FULL)


@pytest.fixture
def build(clock: FakeClock, tmp_path: Path) -> Iterator[RecorderFactory]:
    """Build recorders, stopping each of them when the test ends."""
    created: list[Recorder] = []

    def make(
        buckets: int = WINDOW_BUCKETS,
        bucket_ms: int = BUCKET_MS,
        tick_ms: int = IDLE_TICK_MS,
        recordings_dir: Path | None = None,
        source_clock: Clock | None = None,
    ) -> tuple[RateWindow, Recorder]:
        ticker = clock if source_clock is None else source_clock
        window = RateWindow(bucket_ms=bucket_ms, buckets=buckets, clock=ticker)
        recorder = Recorder(
            window,
            tmp_path if recordings_dir is None else recordings_dir,
            devices_in_subnet,
            tick_ms=tick_ms,
            clock=ticker,
        )
        created.append(recorder)
        return window, recorder

    yield make
    for recorder in created:
        recorder.stop()


def feed(window: RateWindow, *ips: str) -> None:
    """Put one bucket's worth of traffic into the window for each address."""
    for ip in ips:
        window.record(ip, PACKETS_PER_BUCKET)


def advance(clock: FakeClock, buckets: int = 1) -> None:
    clock.advance(buckets * BUCKET_S)


def recorded_path(recorder: Recorder) -> Path:
    file = recorder.status().file
    assert file is not None
    return Path(file)


def read_csv(path: Path) -> list[list[str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.reader(handle))


def data_rows(path: Path) -> list[list[str]]:
    """Every row of the recording below its header."""
    rows = read_csv(path)
    assert rows[0] == list(CSV_HEADER)
    return rows[1:]


def epochs(rows: list[list[str]]) -> list[int]:
    """The distinct bucket ends in ``rows``, in the order they appear."""
    seen: list[int] = []
    for row in rows:
        stamp = int(row[1])
        if stamp not in seen:
            seen.append(stamp)
    return seen


def start_recording(
    recorder: Recorder, network: IPNetwork = SUBNET
) -> tuple[Path, int]:
    status = recorder.start(network)
    assert status.started_ms is not None
    return Path(str(status.file)), status.started_ms


def test_an_idle_recorder_reports_the_documented_idle_shape(
    build: RecorderFactory,
) -> None:
    _, recorder = build()

    assert recorder.status() == IDLE_STATUS
    assert recorder.status().as_dict() == {
        "active": False,
        "file": None,
        "subnet": None,
        "rows": 0,
        "started_ms": None,
        "detail": None,
    }
    assert recorder.running is False


def test_starting_reports_the_file_and_the_subnet_it_is_fixed_to(
    build: RecorderFactory, tmp_path: Path
) -> None:
    window, recorder = build()
    feed(window, *SUBNET_IPS)

    status = recorder.start(SUBNET)

    assert status.active is True
    assert status.subnet == str(SUBNET)
    assert status.rows == 0
    assert status.detail is None
    assert status.started_ms == window.snapshot()["now_ms"]
    assert Path(str(status.file)).parent == tmp_path
    assert recorder.status() == status


def test_nothing_is_written_until_a_bucket_completes(
    build: RecorderFactory,
) -> None:
    window, recorder = build()
    feed(window, *SUBNET_IPS)
    path, _ = start_recording(recorder)

    recorder.tick()

    assert read_csv(path) == [list(CSV_HEADER)]


def test_a_bucket_is_written_once_however_often_the_recorder_ticks(
    build: RecorderFactory, clock: FakeClock
) -> None:
    """The guard against duplicate rows: ticks are idempotent between buckets."""
    window, recorder = build()
    feed(window, *SUBNET_IPS)
    path, _ = start_recording(recorder)

    advance(clock)
    for _ in range(4):
        recorder.tick()

    rows = data_rows(path)
    assert len(rows) == len(SUBNET_IPS)
    assert len(epochs(rows)) == 1


def test_every_bucket_completed_since_the_last_tick_is_written(
    build: RecorderFactory, clock: FakeClock
) -> None:
    """A late tick catches up rather than writing only the newest bucket."""
    window, recorder = build()
    late_buckets = 5
    path, started_ms = start_recording(recorder)

    for _ in range(late_buckets):
        feed(window, *SUBNET_IPS)
        advance(clock)
    recorder.tick()

    rows = data_rows(path)
    assert len(rows) == late_buckets * len(SUBNET_IPS)
    assert epochs(rows) == [
        started_ms + step * BUCKET_MS for step in range(1, late_buckets + 1)
    ]
    assert recorder.status().detail is None


def test_bucket_ends_are_contiguous_across_many_uneven_ticks(
    build: RecorderFactory, clock: FakeClock
) -> None:
    """No gaps and no repeats when ticks land at irregular intervals."""
    window, recorder = build()
    path, started_ms = start_recording(recorder)

    written = 0
    for step in (1, 3, 1, 2, 4, 1):
        for _ in range(step):
            feed(window, *SUBNET_IPS)
            advance(clock)
        written += step
        recorder.tick()

    stamps = epochs(data_rows(path))
    assert stamps == [started_ms + step * BUCKET_MS for step in range(1, written + 1)]
    assert recorder.status().rows == written * len(SUBNET_IPS)


def test_falling_behind_the_whole_window_is_reported_not_hidden(
    build: RecorderFactory, clock: FakeClock
) -> None:
    """The documented ceiling: buckets that scrolled out are gone, and said so.

    A short file that says nothing is the failure worth preventing here - the
    gap has to be visible while the recording is still running.
    """
    window, recorder = build()
    starved_buckets = WINDOW_BUCKETS + 4
    path, started_ms = start_recording(recorder)

    for _ in range(starved_buckets):
        feed(window, *SUBNET_IPS)
        advance(clock)
    recorder.tick()

    stamps = epochs(data_rows(path))
    lost = starved_buckets - WINDOW_BUCKETS
    assert len(stamps) == WINDOW_BUCKETS
    assert stamps[0] == started_ms + (lost + 1) * BUCKET_MS
    detail = recorder.status().detail
    assert detail is not None
    assert str(lost) in detail
    assert f"{WINDOW_S:g}" in detail
    assert recorder.status().active is True


def test_a_reported_gap_survives_the_ticks_that_follow_it(
    build: RecorderFactory, clock: FakeClock
) -> None:
    """A recording with a hole in it keeps saying so, not just once."""
    window, recorder = build()
    start_recording(recorder)

    for _ in range(WINDOW_BUCKETS + 2):
        feed(window, *SUBNET_IPS)
        advance(clock)
    recorder.tick()
    feed(window, *SUBNET_IPS)
    advance(clock)
    recorder.tick()

    assert recorder.status().detail is not None


@pytest.mark.parametrize(
    "last_end_ms,now_ms,expected_ends,expected_lost",
    [
        (1_000, 1_000, [], 0),
        (1_000, 1_250, [1_250], 0),
        (1_000, 1_750, [1_250, 1_500, 1_750], 0),
        # Exactly a windowful behind: the oldest bucket wanted is the oldest
        # one still held, so nothing has been lost yet.
        (1_000, 1_000 + WINDOW_BUCKETS * BUCKET_MS, None, 0),
        (1_000, 1_000 + (WINDOW_BUCKETS + 3) * BUCKET_MS, None, 3),
    ],
)
def test_bucket_accounting_names_what_is_writable_and_what_is_lost(
    last_end_ms: int,
    now_ms: int,
    expected_ends: list[int] | None,
    expected_lost: int,
) -> None:
    ends, lost = buckets_since(last_end_ms, now_ms, BUCKET_MS, WINDOW_BUCKETS)

    assert lost == expected_lost
    if expected_ends is not None:
        assert ends == expected_ends
    else:
        assert len(ends) == WINDOW_BUCKETS
        assert ends[-1] == now_ms
    # Nothing may be silently unaccounted for: every bucket that elapsed was
    # either written or counted as lost.
    assert len(ends) + lost == (now_ms - last_end_ms) // BUCKET_MS


def test_a_device_outside_the_recorded_subnet_never_appears(
    build: RecorderFactory, clock: FakeClock
) -> None:
    window, recorder = build()
    path, _ = start_recording(recorder)

    for _ in range(3):
        feed(window, *SUBNET_IPS, OUTSIDE_IP)
        advance(clock)
    recorder.tick()

    assert {row[2] for row in data_rows(path)} == set(SUBNET_IPS)


def test_the_recording_keeps_its_own_subnet_whatever_is_being_viewed(
    build: RecorderFactory, clock: FakeClock
) -> None:
    """Looking somewhere else must not change what is being written."""
    window, recorder = build()
    path, _ = start_recording(recorder, SECOND_SUBNET)

    for _ in range(2):
        feed(window, *SUBNET_IPS, OUTSIDE_IP)
        advance(clock)
    recorder.tick()
    # What a poll asking for the other subnet reads, which the file ignores.
    devices_in_subnet(window.snapshot()["devices"], SUBNET)
    feed(window, *SUBNET_IPS, OUTSIDE_IP)
    advance(clock)
    recorder.tick()

    assert {row[2] for row in data_rows(path)} == {OUTSIDE_IP}
    assert recorder.status().subnet == str(SECOND_SUBNET)


def test_a_silent_device_records_zeros_rather_than_a_gap(
    build: RecorderFactory, clock: FakeClock
) -> None:
    quiet_ip, busy_ip = SUBNET_IPS
    window, recorder = build()
    feed(window, quiet_ip, busy_ip)
    advance(clock)
    path, _ = start_recording(recorder)

    for _ in range(3):
        feed(window, busy_ip)
        advance(clock)
    recorder.tick()

    quiet = [row for row in data_rows(path) if row[2] == quiet_ip]
    assert len(quiet) == 3
    assert {row[3] for row in quiet} == {"0.0"}


def test_each_bucket_carries_the_rate_that_bucket_held(
    build: RecorderFactory, clock: FakeClock
) -> None:
    ip = SUBNET_IPS[0]
    window, recorder = build()
    feed(window, ip)
    advance(clock)
    path, _ = start_recording(recorder)

    feed(window, ip)
    advance(clock, 2)
    recorder.tick()

    assert [row[3] for row in data_rows(path)] == [str(BUCKET_PPS), "0.0"]


def test_the_header_is_written_once_and_the_file_parses_as_csv(
    build: RecorderFactory, clock: FakeClock
) -> None:
    window, recorder = build()
    path, _ = start_recording(recorder)

    for _ in range(3):
        feed(window, *SUBNET_IPS)
        advance(clock)
        recorder.tick()

    rows = read_csv(path)
    assert rows[0] == list(CSV_HEADER)
    assert all(row != list(CSV_HEADER) for row in rows[1:])
    assert all(len(row) == len(CSV_HEADER) for row in rows)


def test_timestamps_are_bucket_ends_spaced_by_one_bucket(
    build: RecorderFactory, clock: FakeClock
) -> None:
    """The two timestamp columns must name the same instant as each other."""
    window, recorder = build()
    path, _ = start_recording(recorder)

    for _ in range(4):
        feed(window, SUBNET_IPS[0])
        advance(clock)
    recorder.tick()

    rows = data_rows(path)
    stamps = [int(row[1]) for row in rows]
    assert [b - a for a, b in zip(stamps, stamps[1:])] == [BUCKET_MS] * 3
    for row in rows:
        moment = datetime.fromisoformat(row[0])
        assert round(moment.timestamp() * 1000) == int(row[1])
        assert moment.utcoffset() is not None


@pytest.mark.parametrize(
    "epoch_ms", [1_787_935_496_750, 1_787_935_496_001, 1_787_935_496_000]
)
def test_an_iso_timestamp_keeps_its_milliseconds_and_its_offset(
    epoch_ms: int,
) -> None:
    written = iso_timestamp(epoch_ms)

    assert round(datetime.fromisoformat(written).timestamp() * 1000) == epoch_ms
    assert datetime.fromisoformat(written).utcoffset() is not None


@pytest.mark.parametrize(
    "subnet,expected",
    [
        ("192.168.2.0/24", "netmon-20260828-123456-192.168.2.0-24.csv"),
        ("fe80::/64", "netmon-20260828-123456-fe80---64.csv"),
    ],
)
def test_a_filename_says_when_and_of_what_without_illegal_characters(
    subnet: str, expected: str
) -> None:
    started_ms = int(datetime(2026, 8, 28, 12, 34, 56, 750_000).timestamp() * 1000)

    filename = recording_filename(started_ms, subnet)

    assert filename == expected
    assert not set(filename) & {"/", ":"}


def test_a_name_already_taken_is_numbered_rather_than_reused(
    tmp_path: Path,
) -> None:
    filename = "netmon-20260828-123456-192.168.2.0-24.csv"
    (tmp_path / filename).write_text("first", encoding="utf-8")

    second = unique_recording_path(tmp_path, filename)
    second.write_text("second", encoding="utf-8")
    third = unique_recording_path(tmp_path, filename)

    assert second.name == "netmon-20260828-123456-192.168.2.0-24-2.csv"
    assert third.name == "netmon-20260828-123456-192.168.2.0-24-3.csv"
    assert (tmp_path / filename).read_text(encoding="utf-8") == "first"


def test_an_existing_file_is_appended_to_rather_than_truncated(
    tmp_path: Path,
) -> None:
    """Never destroy data because a name repeated - and never re-head a file."""
    path = tmp_path / "existing.csv"
    path.write_text("timestamp_iso,epoch_ms,ip,pps\nkeep,1,2,3\n", encoding="utf-8")

    file = open_recording(path)
    csv.writer(file).writerow(("added", 4, 5, 6))
    file.close()

    assert read_csv(path) == [
        list(CSV_HEADER),
        ["keep", "1", "2", "3"],
        ["added", "4", "5", "6"],
    ]


def test_a_new_file_is_given_its_header(tmp_path: Path) -> None:
    path = tmp_path / "fresh.csv"

    open_recording(path).close()

    assert read_csv(path) == [list(CSV_HEADER)]


def test_recording_begins_where_record_was_pressed(
    build: RecorderFactory, clock: FakeClock
) -> None:
    """History already in the window is not retroactively written."""
    window, recorder = build()
    for _ in range(4):
        feed(window, *SUBNET_IPS)
        advance(clock)

    path, started_ms = start_recording(recorder)
    feed(window, *SUBNET_IPS)
    advance(clock)
    recorder.tick()

    assert epochs(data_rows(path)) == [started_ms + BUCKET_MS]


def test_a_second_start_is_refused_and_leaves_the_first_alone(
    build: RecorderFactory, clock: FakeClock, tmp_path: Path
) -> None:
    window, recorder = build()
    path, _ = start_recording(recorder)
    feed(window, *SUBNET_IPS)
    advance(clock)
    recorder.tick()
    written = read_csv(path)

    with pytest.raises(AlreadyRecordingError):
        recorder.start(SECOND_SUBNET)

    assert recorder.status().subnet == str(SUBNET)
    assert recorded_path(recorder) == path
    assert read_csv(path) == written
    assert list(tmp_path.iterdir()) == [path]


def test_starting_again_opens_a_new_file_and_never_reopens_the_old_one(
    build: RecorderFactory, clock: FakeClock
) -> None:
    window, recorder = build()
    first, _ = start_recording(recorder)
    feed(window, *SUBNET_IPS)
    advance(clock)
    recorder.tick()
    recorder.stop()
    first_content = read_csv(first)

    advance(clock, 4)
    second, _ = start_recording(recorder)
    feed(window, *SUBNET_IPS)
    advance(clock)
    recorder.tick()
    recorder.stop()

    assert second != first
    assert read_csv(first) == first_content
    assert len(data_rows(second)) == len(SUBNET_IPS)


def test_stopping_hands_back_the_final_tally_and_closes_the_file(
    build: RecorderFactory, clock: FakeClock
) -> None:
    window, recorder = build()
    path, started_ms = start_recording(recorder)
    for _ in range(3):
        feed(window, *SUBNET_IPS)
        advance(clock)
    recorder.tick()

    final = recorder.stop()

    assert final.active is False
    assert final.rows == 3 * len(SUBNET_IPS)
    assert final.file == str(path)
    assert final.started_ms == started_ms
    assert len(data_rows(path)) == final.rows
    assert recorder.status() == IDLE_STATUS
    assert recorder.running is False


def test_a_stopped_recording_is_not_written_to_again(
    build: RecorderFactory, clock: FakeClock
) -> None:
    window, recorder = build()
    path, _ = start_recording(recorder)
    recorder.stop()

    feed(window, *SUBNET_IPS)
    advance(clock)
    recorder.tick()

    assert data_rows(path) == []


@pytest.mark.parametrize("stops", [1, 2, 3])
def test_stopping_when_nothing_is_recording_is_harmless(
    build: RecorderFactory, tmp_path: Path, stops: int
) -> None:
    _, recorder = build()

    for _ in range(stops):
        assert recorder.stop() == IDLE_STATUS

    assert recorder.running is False
    assert not list(tmp_path.iterdir())


def test_a_directory_that_cannot_be_created_answers_at_the_start(
    build: RecorderFactory, tmp_path: Path
) -> None:
    """A disk failure has to reach the request that caused it."""
    blocked = tmp_path / "in-the-way"
    blocked.write_text("not a directory", encoding="utf-8")
    _, recorder = build(recordings_dir=blocked / "recordings")

    with pytest.raises(RecordingStartError) as error_info:
        recorder.start(SUBNET)

    assert str(blocked) in str(error_info.value)
    assert recorder.status() == IDLE_STATUS
    assert recorder.running is False


def test_a_write_failure_stops_the_recording_and_names_the_path(
    build: RecorderFactory, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dead writer must never leave the page saying it is still recording."""
    window, recorder = build()
    monkeypatch.setattr(recorder_module, "open_recording", lambda path: FailingFile())
    path, _ = start_recording(recorder)
    feed(window, *SUBNET_IPS)
    advance(clock)

    recorder.tick()

    status = recorder.status()
    assert status.active is False
    assert status.detail is not None
    assert str(path) in status.detail
    assert DISK_FULL in status.detail
    assert recorder.stop().detail == status.detail


def test_a_failed_recording_can_be_started_again(
    build: RecorderFactory, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    window, recorder = build()
    monkeypatch.setattr(recorder_module, "open_recording", lambda path: FailingFile())
    start_recording(recorder)
    feed(window, *SUBNET_IPS)
    advance(clock)
    recorder.tick()

    monkeypatch.setattr(recorder_module, "open_recording", open_recording)
    status = recorder.start(SUBNET)

    assert status.active is True
    assert status.detail is None


def test_tick_ms_must_be_positive(clock: FakeClock, tmp_path: Path) -> None:
    window = RateWindow(bucket_ms=BUCKET_MS, buckets=WINDOW_BUCKETS, clock=clock)

    with pytest.raises(ValueError):
        Recorder(window, tmp_path, devices_in_subnet, tick_ms=0)


def test_the_writing_thread_records_and_shuts_down_cleanly(
    build: RecorderFactory,
) -> None:
    """The one place a real thread, a real clock and a real file all meet."""
    window, recorder = build(
        bucket_ms=THREAD_TEST_BUCKET_MS,
        tick_ms=THREAD_TEST_BUCKET_MS,
        source_clock=time.monotonic,
    )
    window.record(SUBNET_IPS[0], PACKETS_PER_BUCKET)

    path, _ = start_recording(recorder)
    try:
        assert recorder.running is True
        # Exactly one: a recording that leaked its thread would show up here as
        # a second one that nothing can ever stop.
        workers = [t for t in threading.enumerate() if t.name == THREAD_NAME]
        assert len(workers) == 1
        assert workers[0].daemon is True

        deadline = time.monotonic() + THREAD_TEST_DEADLINE_S
        while recorder.status().rows == 0 and time.monotonic() < deadline:
            window.record(SUBNET_IPS[0])
            time.sleep(THREAD_TEST_POLL_S)
        # Flushed every tick, so the rows are readable before the file closes.
        assert len(data_rows(path)) == recorder.status().rows > 0
    finally:
        final = recorder.stop()

    assert recorder.running is False
    assert workers[0].is_alive() is False
    assert len(data_rows(path)) == final.rows
