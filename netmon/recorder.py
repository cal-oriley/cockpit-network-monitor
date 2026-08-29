"""CSV recording of per-device rates, written by the recorder's own thread.

The rolling window forgets everything older than ten seconds, so recording is
the only way anything is kept. What gets written is fixed when the recording
starts - the subnet chosen then, not whatever the page is looking at later - so
one file holds one set of devices and means one thing for its whole length.

Why the writing has a thread of its own
---------------------------------------
The obvious implementation appends a row whenever a poll arrives, and it is
wrong twice over. Polls are not guaranteed: closing, backgrounding or
disconnecting the browser stops them, and a recording that quietly stops
collecting is only discovered afterwards, from a file that is too short. Poll
timing also does not align with buckets: a 500 ms poll against 250 ms buckets
sees two new buckets most times, but three, one, or the same one twice under
jitter, a slow request or a retry - so rows would duplicate or vanish according
to network timing.

So the recorder ticks at bucket resolution on a daemon thread, remembers the
end of the last bucket it wrote, and writes every bucket completed since. The
aggregator zero-fills buckets nobody recorded into, so a silent device writes
zeros rather than leaving a hole - the same reasoning that makes its graph
scroll instead of freeze.

The subnet filter is not implemented here. The endpoint's own helper is handed
in at construction, because a recording that disagreed with the page about what
belongs to a subnet would be a miserable bug to find.
"""

import csv
import ipaddress
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

from .rate_window import MS_PER_SECOND, RateWindow

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# The endpoint's subnet filter, injected rather than imported: the server
# already owns it, and importing it here would close a cycle.
DeviceFilter = Callable[[Iterable[dict[str, Any]], IPNetwork], list[dict[str, Any]]]
Clock = Callable[[], float]

CSV_HEADER = ("timestamp_iso", "epoch_ms", "ip", "pps")
CSV_SUFFIX = ".csv"
FILENAME_STEM_TEMPLATE = "netmon-{stamp}-{subnet}"
FILENAME_STAMP_FORMAT = "%Y%m%d-%H%M%S"
# A CIDR carries "/" always and ":" whenever it is IPv6, and Windows will not
# have either in a filename.
FILENAME_ILLEGAL_CHARACTERS = ("/", ":")
FILENAME_REPLACEMENT = "-"
FIRST_COLLISION_ORDINAL = 2

MICROSECONDS_PER_MS = 1000
THREAD_NAME = "netmon-recorder"
STOP_TIMEOUT_S = 2.0

ALREADY_RECORDING = "A recording is already running; stop it before starting another."
OPEN_FAILED_DETAIL = "Cannot write the recording to {path} ({error})."
WRITE_FAILED_DETAIL = "Recording stopped: {path} could not be written ({error})."
LOST_BUCKETS_DETAIL = (
    "The recorder fell more than {window_s:g} seconds behind, so {lost:,} "
    "{noun} left the window before {they} could be written and this recording "
    "has gaps."
)
LOST_BUCKET_NOUNS = ("bucket", "buckets")
LOST_BUCKET_PRONOUNS = ("it", "they")


class AlreadyRecordingError(RuntimeError):
    """A recording was asked for while one was already running."""


class RecordingStartError(RuntimeError):
    """The recording file could not be created. Its message names the path."""


@dataclass(frozen=True)
class RecordingStatus:
    """What the page is told about the recording, on every poll.

    Idle is ``active`` false with every descriptive field null and ``rows``
    zero - a count of nothing is nothing, and a null there would make the page
    guard arithmetic it should not have to. ``detail`` outlives the recording
    it describes, so a recording that ended in a disk failure can still say so
    once it is no longer running.
    """

    active: bool = False
    file: str | None = None
    subnet: str | None = None
    rows: int = 0
    started_ms: int | None = None
    detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "active": self.active,
            "file": self.file,
            "subnet": self.subnet,
            "rows": self.rows,
            "started_ms": self.started_ms,
            "detail": self.detail,
        }


IDLE_STATUS = RecordingStatus()


@dataclass
class _Session:
    """One recording: its open file, its thread, and its bucket accounting.

    The stop signal belongs to the session rather than the recorder, so a
    thread can only ever be stopped by the recording that owns it. A single
    shared flag could be cleared by the next ``start`` before the previous
    thread had noticed it was set, leaving that thread ticking for the life of
    the process.
    """

    path: Path
    network: IPNetwork
    file: TextIO
    # csv exposes no public type for its writer.
    writer: Any
    started_ms: int
    last_end_ms: int
    window_s: float
    stopping: threading.Event
    rows: int = 0
    lost_buckets: int = 0


def iso_timestamp(epoch_ms: int) -> str:
    """``epoch_ms`` as local time with its offset, to the millisecond.

    Built from whole seconds and a millisecond remainder rather than from a
    float, so a bucket end never lands a microsecond short of the millisecond
    it is supposed to be.
    """
    seconds, milliseconds = divmod(epoch_ms, MS_PER_SECOND)
    moment = datetime.fromtimestamp(seconds).astimezone()
    return moment.replace(microsecond=milliseconds * MICROSECONDS_PER_MS).isoformat(
        timespec="milliseconds"
    )


def recording_filename(started_ms: int, subnet: str) -> str:
    """Timestamped, self-describing name for a recording of ``subnet``.

    A directory listing should say when a recording was taken and of what
    without anything being opened.
    """
    stamp = datetime.fromtimestamp(started_ms // MS_PER_SECOND).strftime(
        FILENAME_STAMP_FORMAT
    )
    for character in FILENAME_ILLEGAL_CHARACTERS:
        subnet = subnet.replace(character, FILENAME_REPLACEMENT)
    return FILENAME_STEM_TEMPLATE.format(stamp=stamp, subnet=subnet) + CSV_SUFFIX


def unique_recording_path(directory: Path, filename: str) -> Path:
    """``filename`` in ``directory``, numbered if that name is already taken.

    The stamp is only accurate to the second, so stopping and starting again
    within the same second would otherwise name the file that is already
    there - and appending to it would leave one file holding two recordings.
    """
    candidate = directory / filename
    stem = candidate.stem
    ordinal = FIRST_COLLISION_ORDINAL
    while candidate.exists():
        candidate = directory / f"{stem}-{ordinal}{CSV_SUFFIX}"
        ordinal += 1
    return candidate


def open_recording(path: Path) -> TextIO:
    """Open ``path`` for appending, writing the header only if it is new.

    Append rather than truncate: names are chosen not to collide, but losing
    somebody's data because one repeated is not a failure mode worth having.
    An existing file already has its header, so a second one would land in the
    middle of the table and stop the file parsing as one.
    """
    existing = path.exists() and path.stat().st_size > 0
    file = path.open("a", newline="", encoding="utf-8")
    if not existing:
        csv.writer(file).writerow(CSV_HEADER)
        file.flush()
    return file


def buckets_since(
    last_end_ms: int, now_ms: int, bucket_ms: int, buckets: int
) -> tuple[list[int], int]:
    """Bucket ends still writable after ``last_end_ms``, and how many are lost.

    Buckets are identified by the instant they end, which is what makes this
    accounting resistant to a tick that is early, late, or repeated: a bucket
    written once is behind ``last_end_ms`` forever after, and one that has not
    been written yet is still ahead of it however many ticks have gone by.

    ponytail: only buckets still inside the aggregator's window can be
    written. Ceiling - a thread starved for longer than the window
    (``buckets`` x ``bucket_ms``) loses the buckets that scrolled out of it,
    counted here and reported through the recording's ``detail`` rather than
    left to look like a short file. Upgrade path - a queue fed from
    ``RateWindow.record``, which would decouple writing from the window's
    lifetime entirely.
    """
    oldest_available_ms = now_ms - (buckets - 1) * bucket_ms
    first_wanted_ms = last_end_ms + bucket_ms
    lost = max(0, (oldest_available_ms - first_wanted_ms) // bucket_ms)
    first_ms = max(first_wanted_ms, oldest_available_ms)
    return list(range(first_ms, now_ms + 1, bucket_ms)), lost


class Recorder:
    """Appends every completed bucket to a CSV, on a thread of its own.

    :meth:`start`, :meth:`stop` and :attr:`running` mirror the packet sources,
    so the server shuts a recording down in the same ``finally`` that stops the
    capture. :meth:`stop` never raises and is safe when nothing is recording;
    :meth:`status` is answered from a value the writing thread swaps in, so a
    poll never waits on the disk.
    """

    def __init__(
        self,
        window: RateWindow,
        recordings_dir: Path,
        filter_devices: DeviceFilter,
        tick_ms: int | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        self._window = window
        self._recordings_dir = Path(recordings_dir)
        self._filter_devices = filter_devices
        self._tick_ms = window.bucket_ms if tick_ms is None else tick_ms
        if self._tick_ms <= 0:
            raise ValueError("tick_ms must be positive")

        self._clock = clock
        # Serializes the session transitions - start, stop, and the tick that
        # writes - so a file is never written after it has been closed.
        self._control = threading.Lock()
        self._thread: threading.Thread | None = None
        self._session: _Session | None = None
        self._status = IDLE_STATUS

    @property
    def running(self) -> bool:
        """Whether the writing thread is currently alive."""
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> RecordingStatus:
        """The current recording state. Cheap: this answers every poll."""
        return self._status

    def start(self, network: IPNetwork) -> RecordingStatus:
        """Open a new file and begin recording ``network``.

        The file is opened here rather than on the thread so that a full disk
        or a refused permission answers the request that caused it, instead of
        surfacing later as a button still claiming to record.

        Recording begins now: the baseline comes from a snapshot taken here, so
        the file starts where the operator pressed record rather than
        retroactively holding the ten seconds of history they did not ask for.
        """
        with self._control:
            if self._session is not None:
                raise AlreadyRecordingError(ALREADY_RECORDING)

            snapshot = self._window.snapshot()
            started_ms = int(snapshot["now_ms"])
            path = self._recordings_dir / recording_filename(started_ms, str(network))
            try:
                self._recordings_dir.mkdir(parents=True, exist_ok=True)
                path = unique_recording_path(self._recordings_dir, path.name)
                file = open_recording(path)
            except OSError as error:
                raise RecordingStartError(
                    OPEN_FAILED_DETAIL.format(path=path, error=error)
                ) from error

            session = _Session(
                path=path,
                network=network,
                file=file,
                writer=csv.writer(file),
                started_ms=started_ms,
                last_end_ms=started_ms,
                window_s=snapshot["buckets"] * snapshot["bucket_ms"] / MS_PER_SECOND,
                stopping=threading.Event(),
            )
            self._session = session
            self._status = _status_for(session, active=True)
            self._thread = threading.Thread(
                target=self._run, args=(session,), name=THREAD_NAME, daemon=True
            )
            self._thread.start()
            return self._status

    def stop(self) -> RecordingStatus:
        """End the recording and close its file. Never raises.

        Returns the finished recording - ``active`` false, but still carrying
        the file and the row count, so the page can say how much was written.
        Subsequent polls see the idle status. Stopping when nothing is
        recording is the desired end state already holding, not an error.
        """
        session = self._session
        if session is not None:
            session.stopping.set()
        # Joined before the lock is taken, because the thread it is waiting for
        # takes that same lock to write.
        self._join_thread()

        with self._control:
            if session is None or self._session is not session:
                # Nothing was recording, or a start raced this stop and won -
                # either way there is no file here that is ours to close.
                return self._status
            self._session = None
            _close(session)
            final = _status_for(session, active=False)
            self._status = RecordingStatus(detail=final.detail)
            return final

    def tick(self) -> None:
        """Write every bucket that has completed since the last tick.

        Never raises: this runs on the writing thread, where an escaping
        exception would end the recording silently and leave the page still
        showing that it is recording.
        """
        with self._control:
            session = self._session
            if session is None:
                return

            snapshot = self._window.snapshot()
            now_ms = int(snapshot["now_ms"])
            bucket_ms = int(snapshot["bucket_ms"])
            ends_ms, lost = buckets_since(
                session.last_end_ms, now_ms, bucket_ms, int(snapshot["buckets"])
            )
            devices = self._filter_devices(snapshot["devices"], session.network)
            rows = _rows_for(devices, ends_ms, now_ms, bucket_ms)

            try:
                session.writer.writerows(rows)
                # Every tick, so a kill loses at most one bucket rather than
                # whatever the operating system was still holding.
                session.file.flush()
            except OSError as error:
                self._fail(session, error)
                return

            session.rows += len(rows)
            session.lost_buckets += lost
            session.last_end_ms = max(session.last_end_ms, now_ms)
            self._status = _status_for(session, active=True)

    def _run(self, session: _Session) -> None:
        """Tick at bucket resolution until stopped, without accumulating drift.

        The wait comes first: no bucket has completed at the instant recording
        starts, so there would be nothing for an immediate tick to write.
        """
        interval_s = self._tick_ms / MS_PER_SECOND
        next_deadline = self._clock() + interval_s
        while not session.stopping.wait(max(0.0, next_deadline - self._clock())):
            self.tick()
            next_deadline += interval_s

    def _join_thread(self) -> None:
        """Wait for the writing thread to finish, unless we are it."""
        thread = self._thread
        if thread is None or thread is threading.current_thread():
            return
        thread.join(STOP_TIMEOUT_S)
        if not thread.is_alive():
            self._thread = None

    def _fail(self, session: _Session, error: OSError) -> None:
        """Abandon a recording whose file will not take any more rows.

        Carrying on would leave the page reporting a recording that is no
        longer being written, which is the one thing worse than stopping: the
        sentence names the path, because that is what the operator can act on.
        """
        self._session = None
        session.stopping.set()
        _close(session)
        self._status = RecordingStatus(
            detail=WRITE_FAILED_DETAIL.format(path=session.path, error=error)
        )


def _rows_for(
    devices: list[dict[str, Any]], ends_ms: list[int], now_ms: int, bucket_ms: int
) -> list[tuple[str, int, str, float]]:
    """One row per device per bucket, oldest bucket first.

    Each bucket end names a position in every device's array: the newest
    completed bucket ends at ``now_ms`` and sits last, and each earlier one
    steps back a slot.
    """
    rows: list[tuple[str, int, str, float]] = []
    for end_ms in ends_ms:
        index = -1 - (now_ms - end_ms) // bucket_ms
        timestamp = iso_timestamp(end_ms)
        for device in devices:
            rows.append((timestamp, end_ms, str(device["ip"]), device["pps"][index]))
    return rows


def _status_for(session: _Session, active: bool) -> RecordingStatus:
    """Render a session as the object the page is handed."""
    return RecordingStatus(
        active=active,
        file=str(session.path),
        subnet=str(session.network),
        rows=session.rows,
        started_ms=session.started_ms,
        detail=_detail_for(session),
    )


def _detail_for(session: _Session) -> str | None:
    """The sentence a recording with a problem shows, or ``None``."""
    if not session.lost_buckets:
        return None
    plural = session.lost_buckets != 1
    return LOST_BUCKETS_DETAIL.format(
        window_s=session.window_s,
        lost=session.lost_buckets,
        noun=LOST_BUCKET_NOUNS[plural],
        they=LOST_BUCKET_PRONOUNS[plural],
    )


def _close(session: _Session) -> None:
    """Flush and close a recording's file, whatever state it is in."""
    try:
        session.file.close()
    except OSError:
        # The rows already flushed are on disk; a close that fails has nothing
        # left to report and must not turn a Ctrl+C into a traceback.
        pass
