"""Tests for ``POST /api/record`` and the recording the poll reports.

Recording is server-side, so the endpoint is the whole of the page's control
over it: start, stop, the refusal a second start gets, and the sentences a
bad request comes back with. The poll's own ``recording`` object is asserted
here too, since it is the other half of the same contract - what the page is
told between one press of the button and the next.
"""

import csv
from http import HTTPStatus
from pathlib import Path

import pytest

from netmon.recorder import IDLE_STATUS
from netmon.server import (
    DEFAULT_SUBNET,
    JSON_CONTENT_TYPE,
    MAX_BODY_BYTES,
    RATES_PATH,
    START_ACTION,
    STOP_ACTION,
)

from .conftest import (
    BUCKET_S,
    DEFAULT_SUBNET_IPS,
    INVALID_SUBNETS,
    RECORDING_KEYS,
    SECOND_SUBNET,
    FakeClock,
    fetch_rates,
    populated_window,
    post_record,
    post_status,
    recorder_for,
    serving,
)

UNKNOWN_ACTION = "pause"
MALFORMED_BODIES = [b"", b"not json at all", b"[1, 2, 3]", b'"start"', b"{"]

STOP_BODY = {"action": STOP_ACTION}


def start_body(subnet: str = DEFAULT_SUBNET) -> dict[str, str]:
    return {"action": START_ACTION, "subnet": subnet}


def recorded_ips(path: Path) -> set[str]:
    """The addresses a recording actually holds rows for."""
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    return {row[2] for row in rows[1:]}


def test_recording_is_reported_on_every_poll_even_when_idle(
    clock: FakeClock,
) -> None:
    """A missing object would read as "not recording" when something broke."""
    with serving(populated_window(clock)) as base_url:
        first = fetch_rates(base_url)
        second = fetch_rates(base_url)

    assert first.body["recording"] == IDLE_STATUS.as_dict()
    assert second.body["recording"] == IDLE_STATUS.as_dict()
    assert first.body["recording"]["rows"] == 0


def test_starting_a_recording_answers_with_the_recording_object(
    clock: FakeClock, tmp_path: Path
) -> None:
    window = populated_window(clock)
    recorder = recorder_for(window, tmp_path)

    with serving(window, recorder=recorder) as base_url:
        answer = post_record(base_url, start_body())
        polled = fetch_rates(base_url)

    assert answer.status == HTTPStatus.OK
    assert answer.content_type == JSON_CONTENT_TYPE
    assert set(answer.body) == RECORDING_KEYS
    assert answer.body["active"] is True
    assert answer.body["subnet"] == DEFAULT_SUBNET
    assert answer.body["rows"] == 0
    assert answer.body["detail"] is None
    assert Path(answer.body["file"]).parent == tmp_path
    assert polled.body["recording"] == answer.body


def test_a_recording_ignores_the_subnet_the_page_moves_on_to(
    clock: FakeClock, tmp_path: Path
) -> None:
    """The file keeps its own subnet; the payload reports both, so the page
    can say they differ."""
    window = populated_window(clock)
    recorder = recorder_for(window, tmp_path)

    with serving(window, recorder=recorder) as base_url:
        started = post_record(base_url, start_body())
        clock.advance(BUCKET_S)
        recorder.tick()
        elsewhere = fetch_rates(base_url, SECOND_SUBNET)
        post_record(base_url, STOP_BODY)

    assert elsewhere.body["subnet"] == SECOND_SUBNET
    assert elsewhere.body["recording"]["subnet"] == DEFAULT_SUBNET
    assert recorded_ips(Path(started.body["file"])) == set(DEFAULT_SUBNET_IPS)


def test_a_second_start_is_refused_with_the_recording_already_running(
    clock: FakeClock, tmp_path: Path
) -> None:
    """The loser of a two-tab race re-syncs rather than opening a new file."""
    window = populated_window(clock)
    recorder = recorder_for(window, tmp_path)

    with serving(window, recorder=recorder) as base_url:
        first = post_record(base_url, start_body())
        second = post_record(base_url, start_body(SECOND_SUBNET))
        post_record(base_url, STOP_BODY)

    assert second.status == HTTPStatus.CONFLICT
    assert second.body == first.body
    assert second.body["subnet"] == DEFAULT_SUBNET
    assert len(list(tmp_path.iterdir())) == 1


def test_stopping_answers_with_the_final_tally(
    clock: FakeClock, tmp_path: Path
) -> None:
    window = populated_window(clock)
    recorder = recorder_for(window, tmp_path)

    with serving(window, recorder=recorder) as base_url:
        started = post_record(base_url, start_body())
        clock.advance(BUCKET_S)
        recorder.tick()
        stopped = post_record(base_url, STOP_BODY)
        after = fetch_rates(base_url)

    assert stopped.status == HTTPStatus.OK
    assert stopped.body["active"] is False
    assert stopped.body["file"] == started.body["file"]
    assert stopped.body["rows"] == len(DEFAULT_SUBNET_IPS)
    assert after.body["recording"] == IDLE_STATUS.as_dict()


@pytest.mark.parametrize("repeats", [1, 2])
def test_a_stop_with_nothing_recording_is_not_an_error(
    clock: FakeClock, repeats: int
) -> None:
    """The desired end state already holds; a second click is not a fault."""
    with serving(populated_window(clock)) as base_url:
        answers = [post_record(base_url, STOP_BODY) for _ in range(repeats)]

    assert [answer.status for answer in answers] == [HTTPStatus.OK] * repeats
    assert all(answer.body == IDLE_STATUS.as_dict() for answer in answers)


@pytest.mark.parametrize("body", [{"action": UNKNOWN_ACTION}, {}, {"subnet": "x"}])
def test_an_action_the_server_does_not_know_is_rejected(
    clock: FakeClock, body: dict[str, str]
) -> None:
    with serving(populated_window(clock)) as base_url:
        response = post_record(base_url, body)

    assert response.status == HTTPStatus.BAD_REQUEST
    assert response.content_type == JSON_CONTENT_TYPE
    assert response.body["error"].endswith(".")
    assert START_ACTION in response.body["error"]


@pytest.mark.parametrize("raw", MALFORMED_BODIES)
def test_a_body_that_is_not_a_json_object_is_rejected(
    clock: FakeClock, raw: bytes
) -> None:
    with serving(populated_window(clock)) as base_url:
        response = post_record(base_url, raw=raw)

    assert response.status == HTTPStatus.BAD_REQUEST
    assert response.body["error"].endswith(".")
    assert "devices" not in response.body


def test_a_body_larger_than_a_record_request_is_refused(clock: FakeClock) -> None:
    oversized = b'{"action": "start", "subnet": "' + b"9" * MAX_BODY_BYTES + b'"}'

    with serving(populated_window(clock)) as base_url:
        response = post_record(base_url, raw=oversized)

    assert response.status == HTTPStatus.BAD_REQUEST
    assert response.body["error"].endswith(".")


@pytest.mark.parametrize("subnet", INVALID_SUBNETS)
def test_a_recording_of_an_unusable_subnet_is_refused(
    clock: FakeClock, subnet: str, tmp_path: Path
) -> None:
    """Validated exactly as the query parameter is, and never opens a file."""
    window = populated_window(clock)
    recorder = recorder_for(window, tmp_path)

    with serving(window, recorder=recorder) as base_url:
        response = post_record(base_url, start_body(subnet))

    assert response.status == HTTPStatus.BAD_REQUEST
    assert "CIDR" in response.body["error"]
    assert not list(tmp_path.iterdir())


def test_a_recording_that_cannot_be_opened_answers_500_naming_the_path(
    clock: FakeClock, tmp_path: Path
) -> None:
    """The one failure the operator can act on has to say where it happened."""
    blocked = tmp_path / "in-the-way"
    blocked.write_text("not a directory", encoding="utf-8")
    window = populated_window(clock)

    with serving(
        window, recorder=recorder_for(window, blocked / "recordings")
    ) as base_url:
        response = post_record(base_url, start_body())
        polled = fetch_rates(base_url)

    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    assert str(blocked) in response.body["error"]
    assert polled.body["recording"] == IDLE_STATUS.as_dict()


def test_a_post_to_any_other_path_is_not_found(clock: FakeClock) -> None:
    with serving(populated_window(clock)) as base_url:
        assert post_status(base_url, RATES_PATH) == HTTPStatus.NOT_FOUND
