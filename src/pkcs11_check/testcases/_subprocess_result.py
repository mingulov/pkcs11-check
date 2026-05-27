"""Shared subprocess result assertions for crash-survival tests."""

from __future__ import annotations

import pytest


def assert_subprocess_completed(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
) -> None:
    """Fail if a crash-survival subprocess crashed or failed internally."""
    if rc < 0:
        pytest.fail(
            f"{context}: module crashed with signal {-rc}\n"
            f"stdout: {stdout[:500]}\nstderr: {stderr[:500]}"
        )
    if rc > 0:
        pytest.fail(
            f"{context}: subprocess failed with exit code {rc}\n"
            f"stdout: {stdout[:500]}\nstderr: {stderr[:500]}"
        )
