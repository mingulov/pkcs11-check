"""Shared subprocess result assertions for crash-survival tests."""

from __future__ import annotations

import re

import pytest

from pkcs11_check.classification import Classification, classify, fail_as, record
from pkcs11_check.core.crash_codes import crash_detail_name, is_crash_returncode
from pkcs11_check.core.process_observation import termination_from_returncode
from pkcs11_check.core.subprocess_trace import (
    RV_TRACE_MARKER,
    record_subprocess_rv_trace,
)
from pkcs11_check.testcases._probes._emit import HARNESS_ERROR_MARKER
from pkcs11_check.testcases._subprocess_preamble import SUBPROCESS_TIMEOUT_MARKER

_MISSING_FUNCTION_ERROR = re.compile(
    r"AttributeError: C_[A-Za-z0-9_]+ not available in this module"
)


def _format_subprocess_stream(text: str, *, limit: int = 500, tail: int = 800) -> str:
    """Return a short subprocess stream excerpt while preserving RV trace markers.

    Keeps the tail as well as the head. A Python traceback carries its exception type and
    message on the LAST line, so a head-only excerpt of a failing child reports the
    traceback header and silently drops the actual error -- the defect that made GH #9
    impossible to diagnose from harness output alone.
    """
    if len(text) <= limit + tail:
        excerpt = text
    else:
        omitted = len(text) - limit - tail
        excerpt = f"{text[:limit]}\n... [{omitted} chars omitted] ...\n{text[-tail:]}"
    marker_lines = [line for line in text.splitlines() if line.startswith(RV_TRACE_MARKER)]
    for line in marker_lines:
        if line not in excerpt:
            excerpt += f"\n{line}"
    return excerpt


def _harness_error_line(stdout: str, stderr: str) -> str | None:
    """Return the harness-error detail the child reported, or None if it reported none."""
    for stream in (stdout, stderr):
        for line in stream.splitlines():
            if line.startswith(HARNESS_ERROR_MARKER):
                return line.removeprefix(HARNESS_ERROR_MARKER).strip()
    return None


def _is_dispatcher_capability_error(stderr: str) -> bool:
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    return bool(lines and _MISSING_FUNCTION_ERROR.fullmatch(lines[-1]))


def _report_harness_error(detail: str, *, rc: int, stdout: str, context: str) -> None:
    """Record a harness defect against the harness, never against the module.

    Exit 0 means the probe delivered its measurement and only cleanup broke: record the
    defect (never silent, and it rides to report.jsonl) and let the caller go on to read
    the verdict the module legitimately produced. A non-zero exit means the harness died
    before delivering anything, so there is no verdict to keep and the test fails.
    """
    summary = (
        f"{context}: pkcs11-check itself failed, NOT the module under test -- {detail}\n"
        f"stdout: {_format_subprocess_stream(stdout)}"
    )
    if rc == 0:
        record(
            Classification(
                reason="harness_error",
                outcome="fail",
                severity="HIGH",
                label=context,
                summary=summary,
            )
        )
        return
    fail_as("harness_error", label=context, summary=summary)


def assert_subprocess_completed(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
) -> None:
    """Fail if a crash-survival subprocess crashed or failed internally."""
    record_subprocess_rv_trace(stdout, stderr)
    if SUBPROCESS_TIMEOUT_MARKER in stderr:
        # The module hung on the probe input (subprocess timed out without
        # returning). A conformant module must reject an impossible input, not
        # hang on it -- classify as a crash-class finding, never a record-less
        # runtime-gate leak. (Checked first: the sentinel rc is incidental.)
        classify(
            "crash",
            label=context,
            detail={"termination": termination_from_returncode(rc, timed_out=True, stderr=stderr)},
            summary=(
                f"{context}: module hung -- subprocess timed out without returning "
                f"on the probe input (must reject impossible inputs, not hang)\n"
                f"stdout: {_format_subprocess_stream(stdout)}\n"
                f"stderr: {_format_subprocess_stream(stderr)}"
            ),
        )
        return
    if is_crash_returncode(rc):
        crash_name = f"signal {-rc}" if rc < 0 else f"Windows exception {crash_detail_name(rc)}"
        classify(
            "crash",
            label=context,
            detail={"termination": termination_from_returncode(rc, stderr=stderr)},
            summary=(
                f"{context}: module crashed with {crash_name}\n"
                f"stdout: {_format_subprocess_stream(stdout)}\n"
                f"stderr: {_format_subprocess_stream(stderr)}"
            ),
        )
        return
    if (harness_error := _harness_error_line(stdout, stderr)) is not None:
        _report_harness_error(harness_error, rc=rc, stdout=stdout, context=context)
        return
    if rc > 0:
        # A child that exited cleanly (non-zero, not a signal) only because it
        # called a PKCS#11 function the module does not implement is a capability
        # gap, not a crash/finding: the dispatcher raises
        # AttributeError("<C_Fn> not available in this module"). Skip rather than
        # fail. Real abnormal exits (e.g. an empty-output exit-5 over-read) carry
        # no such marker and still fail.
        if rc == 1 and _is_dispatcher_capability_error(stderr):
            pytest.skip(
                f"{context}: a PKCS#11 function used by this probe is not "
                "implemented by the module (absent from the function list)"
            )
        classify(
            "crash",
            label=context,
            detail={"termination": termination_from_returncode(rc, stderr=stderr)},
            summary=(
                f"{context}: subprocess failed with exit code {rc}\n"
                f"stdout: {_format_subprocess_stream(stdout)}\n"
                f"stderr: {_format_subprocess_stream(stderr)}"
            ),
        )
