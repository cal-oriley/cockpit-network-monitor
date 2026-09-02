"""The graph slide clock is JS; this runs its self-check when node is present."""

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CHECK = REPO / "tests" / "test_slide.mjs"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_slide_clock() -> None:
    completed = subprocess.run(
        ["node", str(CHECK)],
        cwd=REPO,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
