"""Shared test fixtures.

Everything time-dependent in ``netmon`` takes an injectable clock, so the
tests advance time by hand rather than sleeping.
"""

import pytest

MS_PER_SECOND = 1000


class FakeClock:
    """Deterministic stand-in for ``time.monotonic``, in seconds."""

    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def advance_ms(self, milliseconds: float) -> None:
        self.now += milliseconds / MS_PER_SECOND


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()
