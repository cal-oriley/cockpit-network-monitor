"""Tests for ``POST /api/record`` and the recording the poll reports.

Recording is server-side, so the endpoint is the whole of the page's control
over it: start, stop, the refusal a second start gets, and the sentences a
bad request comes back with. The poll's own ``recording`` object is asserted
here too, since it is the other half of the same contract - what the page is
told between one press of the button and the next.
"""

import csv
import http.client
import json
from http import HTTPStatus
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from netmon.recorder import IDLE_STATUS
from netmon.server import (
    BODY_TOO_LARGE_ERROR,
    CONNECTION_CLOSE,
    CONTENT_LENGTH_HEADER,
    DEFAULT_SUBNET,
    JSON_CONTENT_TYPE,
    MAX_BODY_BYTES,
    MAX_DRAIN_BYTES,
    MISSING_LENGTH_ERROR,
    RATES_PATH,
    RECORD_PATH,
    START_ACTION,
    STOP_ACTION,
)

from .conftest import (
    BUCKET_S,
    DEFAULT_SUBNET_IPS,
    INVALID_SUBNETS,
    RECORDING_KEYS,
    REQUEST_TIMEOUT_S,
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

# A byte count is a non-negative run of decimal digits and nothing else. The
# superscript is the awkward one: it passes ``str.isdigit`` while ``int``
# refuses it, so a laxer check would answer with Python's own complaint.
NOT_A_LENGTH = ["as many as it takes", "-1", "\u00b2", "0x40", ""]
# Far enough past the drain cap that no amount of headroom could cover it.
ABSURD_LENGTH_MULTIPLE = 8

TOO_LARGE_ERROR = BODY_TOO_LARGE_ERROR.format(limit=MAX_BODY_BYTES)

STOP_BODY = {"action": STOP_ACTION}


def refused_without_a_body(
    base_url: str, declared: str
) -> tuple[int, str | None, dict[str, Any]]:
    """POST a ``Content-Length`` the server refuses, sending no body at all.

    Withholding the body is what makes the refusal observable: a server that
    waited for bytes it had already decided not to use would sit there until
    the socket timed out instead of answering. Yields the status, the
    ``Connection`` header, and the decoded payload.
    """
    url = urlsplit(base_url)
    connection = http.client.HTTPConnection(
        url.hostname, url.port, timeout=REQUEST_TIMEOUT_S
    )
    try:
        connection.putrequest("POST", RECORD_PATH)
        connection.putheader("Content-Type", JSON_CONTENT_TYPE)
        connection.putheader(CONTENT_LENGTH_HEADER, declared)
        connection.endheaders()
        answer = connection.getresponse()
        return (
            answer.status,
            answer.getheader("Connection"),
            json.loads(answer.read()),
        )
    finally:
        connection.close()


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
    """The refusal has to reach a caller still mid-send, which is the whole
    point of wording it: this body is over the limit but within the drain cap,
    so it is read out of the socket before the answer is written."""
    oversized = b'{"action": "start", "subnet": "' + b"9" * MAX_BODY_BYTES + b'"}'

    with serving(populated_window(clock)) as base_url:
        response = post_record(base_url, raw=oversized)

    assert response.status == HTTPStatus.BAD_REQUEST
    assert response.body["error"] == TOO_LARGE_ERROR


def test_a_body_far_past_the_drain_cap_is_refused_unread(clock: FakeClock) -> None:
    """Answered, not indulged: a body this size is never read, and the caller
    is told the connection ends with the refusal rather than continuing."""
    absurd = MAX_DRAIN_BYTES * ABSURD_LENGTH_MULTIPLE

    with serving(populated_window(clock)) as base_url:
        status, connection, body = refused_without_a_body(base_url, str(absurd))

    assert status == HTTPStatus.BAD_REQUEST
    assert body["error"] == TOO_LARGE_ERROR
    assert connection == CONNECTION_CLOSE


@pytest.mark.parametrize("declared", NOT_A_LENGTH)
def test_a_body_of_undeclared_length_is_refused_with_the_connection(
    clock: FakeClock, declared: str
) -> None:
    """With no byte count there is no reading the body out and no telling it
    from whatever follows, so this connection cannot carry another request."""
    with serving(populated_window(clock)) as base_url:
        status, connection, body = refused_without_a_body(base_url, declared)

    assert status == HTTPStatus.BAD_REQUEST
    assert body["error"] == MISSING_LENGTH_ERROR
    assert connection == CONNECTION_CLOSE


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
