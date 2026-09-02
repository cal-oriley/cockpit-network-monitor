"""The probe's WebSocket framing, which nothing else would catch if it broke.

A wrong length prefix or a mask applied the wrong way round does not fail
loudly - it hangs waiting for bytes that never come, against a browser that
has to be relaunched to try again. So the framing is exercised here instead,
with no browser and no socket.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from cdp_probe import encode_frame, pick_target, read_frame  # noqa: E402

CLOSE_FRAME = 0x8
TEXT_FRAME = 0x1
FIN_BIT = 0x80


def reader_over(data: bytes):
    """A ``read_exactly`` that serves ``data`` and refuses to over-read."""
    position = 0

    def read_exactly(count: int) -> bytes:
        nonlocal position
        end = position + count
        if end > len(data):
            raise AssertionError("read past the end of the frame")
        chunk = data[position:end]
        position = end
        return chunk

    return read_exactly


@pytest.mark.parametrize("length", [0, 1, 125, 126, 127, 65535, 65536])
def test_frame_survives_a_round_trip_at_every_length_boundary(length: int) -> None:
    payload = bytes(index % 251 for index in range(length))
    opcode, decoded = read_frame(reader_over(encode_frame(payload)))
    assert opcode == TEXT_FRAME
    assert decoded == payload


def test_payload_is_masked_on_the_wire() -> None:
    """An unmasked client frame is a protocol error the browser drops."""
    payload = b"x" * 64
    frame = encode_frame(payload)
    assert frame[1] & 0x80, "mask bit must be set"
    assert payload not in frame


def test_continuation_frames_are_joined() -> None:
    first = bytes([TEXT_FRAME, 2]) + b"ab"
    last = bytes([FIN_BIT, 2]) + b"cd"
    opcode, decoded = read_frame(reader_over(first + last))
    assert opcode == TEXT_FRAME
    assert decoded == b"abcd"


def test_close_frame_keeps_its_opcode() -> None:
    opcode, _ = read_frame(reader_over(bytes([FIN_BIT | CLOSE_FRAME, 0])))
    assert opcode == CLOSE_FRAME


def test_target_is_matched_by_url_fragment() -> None:
    targets = [
        {"url": "file:///app/index.html", "webSocketDebuggerUrl": "ws://x/parent"},
        {"url": "http://localhost:8765/?panel=1", "webSocketDebuggerUrl": "ws://x/panel"},
    ]
    assert pick_target(targets, "localhost:8765")["webSocketDebuggerUrl"] == "ws://x/panel"


def test_target_without_a_debugger_url_is_not_attachable() -> None:
    targets = [{"url": "http://localhost:8765/"}]
    assert pick_target(targets, "localhost:8765") is None


def test_no_match_is_reported_rather_than_guessed() -> None:
    targets = [{"url": "file:///app/index.html", "webSocketDebuggerUrl": "ws://x/parent"}]
    assert pick_target(targets, "localhost:8765") is None
