"""Shared subprocess result assertions for crash-survival tests."""

from __future__ import annotations

import re

import pytest

from pkcs11_check.classification import Classification, classify, fail_as, record
from pkcs11_check.core.crash_codes import crash_detail_name
from pkcs11_check.core.process_observation import termination_from_returncode
from pkcs11_check.core.subprocess_trace import (
    RV_TRACE_MARKER,
    record_subprocess_rv_trace,
)
from pkcs11_check.testcases._probes._emit import HARNESS_ERROR_MARKER
from pkcs11_check.testcases._subprocess_preamble import SUBPROCESS_TIMEOUT_MARKER

# The two process-level dispositions ``assert_subprocess_completed`` can record for a
# non-zero exit. Callers that defer a process disposition until provider evidence has had
# its turn must check for BOTH: they describe how the child ENDED, not what the module
# did, so a real provider finding parsed from the same output always outranks them.
PROCESS_DISPOSITION_REASONS = frozenset({"harness_error", "probe_incomplete"})

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


def _report_harness_error(
    detail: str,
    *,
    rc: int,
    stdout: str,
    stderr: str,
    context: str,
    classification_detail: dict[str, object] | None = None,
) -> bool:
    """Record a defect the harness ANNOUNCED about itself, never against the module.

    Only ever called for an explicit ``HARNESS_ERROR:`` marker: the child said, in its own
    words, that pkcs11-check's code broke. That is the one claim strong enough to earn a
    `harness_error` reason, because that reason removes the record from the provider's
    fail total, severity sections, and cross-provider correlation.

    Exit 0 means the probe delivered its measurement and only cleanup broke: record the
    defect (never silent, and it rides to report.jsonl) and let the caller go on to read
    the verdict the module legitimately produced. The return value tells callers that
    this explicit harness marker was handled. A non-zero exit means the harness did not
    complete a supported process protocol, so the test fails.
    """
    summary = (
        f"{context}: pkcs11-check itself failed, NOT the module under test -- {detail}\n"
        f"stdout: {_format_subprocess_stream(stdout)}\n"
        f"stderr: {_format_subprocess_stream(stderr)}"
    )
    if rc == 0:
        record(
            Classification(
                reason="harness_error",
                outcome="fail",
                severity="HIGH",
                label=context,
                summary=summary,
                detail=classification_detail,
            )
        )
        return True
    fail_as("harness_error", label=context, summary=summary, detail=classification_detail)
    return False


def _report_probe_incomplete(
    detail: str,
    *,
    stdout: str,
    stderr: str,
    context: str,
    classification_detail: dict[str, object] | None = None,
) -> None:
    """Fail with attribution UNRESOLVED when a child exits without a known protocol.

    This is the inference path, and it must not assert a conclusion. A non-zero exit that
    matches no supported protocol tells us only that the measurement is missing -- not
    whose fault that is. The child's own traceback frequently contains a module
    observation: a probe that detects a provider defect and raises a bare ``AssertionError``
    lands here, byte-identical in shape to a real harness bug.

    Blaming the harness here is the expensive direction. ``harness_error`` is in
    ``HARNESS_REASONS``, so it is stripped from the provider's fail total, severity
    sections and cross-provider correlation -- a module that wrote past a caller-declared
    output length reached the rendered report as "a defect in this tool, not in the module
    under test", excluded from every provider count. ``probe_incomplete`` keeps the record
    in the provider's counts, states only what is known, and points the reader at the
    captured streams, which is where the answer actually is.
    """
    summary = (
        f"{context}: probe child exited without completing a recognized protocol -- "
        f"{detail}. Attribution unresolved: the captured streams below may contain a "
        f"module observation (a probe that detected a provider defect and raised rather "
        f"than emitting a marker looks identical here) or a genuine pkcs11-check defect.\n"
        f"stdout: {_format_subprocess_stream(stdout)}\n"
        f"stderr: {_format_subprocess_stream(stderr)}"
    )
    fail_as("probe_incomplete", label=context, summary=summary, detail=classification_detail)


def assert_subprocess_completed(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
    already_attributed: bool = False,
) -> tuple[dict[str, object], bool]:
    """Fail if a crash-survival subprocess crashed or failed internally.

    On a non-terminating path, return the normalized process termination and whether an
    explicit HARNESS_ERROR marker was handled. Callers that know their own output
    protocol can use the latter to continue reading a valid measurement after cleanup.

    Pass ``already_attributed=True`` when the caller has POSITIVELY identified why the
    child exited non-zero (e.g. it parsed a malformed marker and recorded its own
    ``harness_error``). The unresolved-attribution fallback is then suppressed so the
    caller's own, better-informed record stands alone. Crash, hang, and explicit
    ``HARNESS_ERROR:`` dispositions are unaffected -- a crash still outranks everything,
    which is why callers invoke this before acting on their own protocol findings.
    """
    record_subprocess_rv_trace(stdout, stderr)
    timed_out = SUBPROCESS_TIMEOUT_MARKER in stderr
    termination = termination_from_returncode(rc, timed_out=timed_out, stderr=stderr)
    termination_kind = termination["kind"]
    if termination_kind in {"signal", "exception", "timeout", "abrupt_exit"}:
        # The module hung on the probe input (subprocess timed out without
        # returning). A conformant module must reject an impossible input, not
        # hang on it -- classify as a crash-class finding, never a record-less
        # runtime-gate leak. (Checked first: the sentinel rc is incidental.)
        if termination_kind == "timeout":
            summary = (
                f"{context}: module hung -- subprocess timed out without returning "
                f"on the probe input (must reject impossible inputs, not hang)\n"
                f"stdout: {_format_subprocess_stream(stdout)}\n"
                f"stderr: {_format_subprocess_stream(stderr)}"
            )
        elif termination_kind == "signal":
            crash_name = f"signal {-rc}" if rc < 0 else "signal"
            summary = (
                f"{context}: module crashed with {crash_name}\n"
                f"stdout: {_format_subprocess_stream(stdout)}\n"
                f"stderr: {_format_subprocess_stream(stderr)}"
            )
        elif termination_kind == "abrupt_exit":
            # The child never reached its own exit path -- CPython finalization did not
            # run, so the module called exit()/_exit() from inside the PKCS#11 call.
            # (Observed: SoftHSM2 C_Digest -> ByteString -> SecureAllocator::allocate
            # throws std::bad_alloc -> its own catch(...) calls FatalException(), which
            # wipes secure memory and exit(5)s the CALLING APPLICATION.) A library that
            # terminates its host instead of returning a CK_RV is a crash finding.
            summary = (
                f"{context}: module terminated the calling process with exit code {rc} "
                f"from inside the PKCS#11 call -- it never returned a CK_RV, and the "
                f"child never reached its own exit path\n"
                f"stdout: {_format_subprocess_stream(stdout)}\n"
                f"stderr: {_format_subprocess_stream(stderr)}"
            )
        else:
            windows_status = termination.get("windows_status")
            crash_code = windows_status if isinstance(windows_status, int) else rc
            summary = (
                f"{context}: module crashed with Windows exception "
                f"{crash_detail_name(crash_code)}\n"
                f"stdout: {_format_subprocess_stream(stdout)}\n"
                f"stderr: {_format_subprocess_stream(stderr)}"
            )
        classify(
            "crash",
            label=context,
            detail={"termination": termination},
            summary=summary,
        )
        return termination, False
    if (harness_error := _harness_error_line(stdout, stderr)) is not None:
        explicit_harness = _report_harness_error(
            harness_error,
            rc=rc,
            stdout=stdout,
            stderr=stderr,
            context=context,
            classification_detail={"termination": termination},
        )
        return termination, explicit_harness
    if rc != 0:
        # A child that exited cleanly (non-zero, not a signal) only because it
        # called a PKCS#11 function the module does not implement is a capability
        # gap, not a crash/finding: the dispatcher raises
        # AttributeError("<C_Fn> not available in this module"). Skip rather than
        # fail.
        if rc == 1 and _is_dispatcher_capability_error(stderr):
            pytest.skip(
                f"{context}: a PKCS#11 function used by this probe is not "
                "implemented by the module (absent from the function list)"
            )
        if already_attributed:
            # The caller knows why this child died and has recorded it. Adding an
            # "attribution unresolved" record on top would be false and duplicative.
            return termination, False
        # Anything else is an exit we do not recognize. We know the measurement is
        # missing; we do NOT know whose fault that is, and we must not guess. The child
        # reached its own exit path (otherwise termination_kind would be "abrupt_exit"
        # above), so this is a Python-level death -- which is just as often a probe that
        # detected a provider defect and raised a bare AssertionError as it is a real
        # harness bug. Blaming the harness here removes a genuine provider finding from
        # the provider's counts; see _report_probe_incomplete.
        _report_probe_incomplete(
            f"subprocess exited with code {rc}",
            stdout=stdout,
            stderr=stderr,
            context=context,
            classification_detail={
                "probe_incomplete": True,
                "termination": termination,
            },
        )
        return termination, False
    return termination, False
