"""Shared subprocess result assertions for crash-survival tests."""

from __future__ import annotations

import pytest

from pkcs11_check.testcases._subprocess_trace import (
    RV_TRACE_MARKER,
    record_subprocess_rv_trace,
)


def _format_subprocess_stream(text: str, *, limit: int = 500) -> str:
    """Return a short subprocess stream excerpt while preserving RV trace markers."""
    excerpt = text[:limit]
    marker_lines = [line for line in text.splitlines() if line.startswith(RV_TRACE_MARKER)]
    for line in marker_lines:
        if line not in excerpt:
            excerpt += f"\n{line}"
    return excerpt


def assert_subprocess_completed(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
) -> None:
    """Fail if a crash-survival subprocess crashed or failed internally."""
    record_subprocess_rv_trace(stdout, stderr)
    if rc < 0:
        pytest.fail(
            f"{context}: module crashed with signal {-rc}\n"
            f"stdout: {_format_subprocess_stream(stdout)}\n"
            f"stderr: {_format_subprocess_stream(stderr)}"
        )
    if rc > 0:
        pytest.fail(
            f"{context}: subprocess failed with exit code {rc}\n"
            f"stdout: {_format_subprocess_stream(stdout)}\n"
            f"stderr: {_format_subprocess_stream(stderr)}"
        )
