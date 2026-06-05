"""Regression tests for the timeout-as-passed downgrade (review finding R3).

When a file times out, the runner deselects the completed/culprit tests and
retries the rest. If the timeout cannot be attributed to a single test (no
culprit, or the culprit passes in isolation) and the retry then passes, the unit
was recorded as ``passed`` and the timeout vanished from the summary. The
``_ensure_timeout_recorded`` helper preserves an unattributed file-level timeout
so a green retry never hides a real hang; the summary must keep it.
"""

from __future__ import annotations

from pkcs11_check.core.file_runner import (
    FileRunResult,
    FileRunState,
    _build_isolated_json_payload,
    _ensure_timeout_recorded,
)


def test_ensure_timeout_recorded_injects_when_absent() -> None:
    detail = _ensure_timeout_recorded(None, "test_slow.py")
    assert detail["counts"]["timeout"] == 1
    assert any(
        t.get("outcome") == "timeout" and t.get("nodeid") == "test_slow.py" for t in detail["tests"]
    )


def test_ensure_timeout_recorded_is_idempotent_when_already_counted() -> None:
    # A confirmed culprit already contributed a timeout; do not double-count.
    existing = {
        "counts": {"timeout": 1, "passed": 2},
        "tests": [{"nodeid": "test_slow.py::test_c", "outcome": "timeout"}],
    }
    detail = _ensure_timeout_recorded(existing, "test_slow.py")
    assert detail["counts"]["timeout"] == 1
    assert sum(1 for t in detail["tests"] if t.get("outcome") == "timeout") == 1


def test_passing_retry_does_not_hide_timeout_in_summary() -> None:
    # The unit's FileRunResult is "passed" (the retry overwrote the timeout
    # result), but its per-unit detail carries an unattributed file-level
    # timeout. The aggregated summary must still report the timeout.
    state = FileRunState(
        units=["test_slow.py"],
        fingerprint="fp",
        results=[
            FileRunResult(
                target="test_slow.py",
                status="passed",
                returncode=0,
                duration_s=1.0,
            )
        ],
    )
    details = {"test_slow.py": _ensure_timeout_recorded(None, "test_slow.py")}

    payload = _build_isolated_json_payload(state, per_unit_details=details)

    assert payload["summary"]["timeout"] >= 1, payload["summary"]
