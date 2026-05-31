"""Regression checks for crash-reporting policy in provider tests."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from pkcs11_check.testcases.ckr.test_ckr_null_params import _check_null_result

ROOT = Path(__file__).resolve().parents[1]
TESTCASE_ROOT = ROOT / "src/pkcs11_check/testcases"

_CRASH_TERMS = ("crash", "crashed", "segfault", "signal")
_NON_CRASH_PHRASES = (
    "not a crash",
    "without crash",
    "does not crash",
    "doesn't crash",
    "protocol kdf",
)

# A crash under DOCUMENTED MISUSE is not a provider conformance finding, so the
# spec permits it and xfail/skip is allowed -- but ONLY when the message
# explicitly justifies it as spec-permitted undefined behavior. Today the sole
# case is multi-threaded access after a single-threaded ``C_Initialize(NULL)``,
# which PKCS#11 v3.2 Sec.5.4 leaves undefined (see test_threading.py's UB probe
# and docs/module-issues.md). This exemption is justification-gated on purpose:
# a *real* provider crash is a finding and never carries such wording, so the
# guard stays strict for everything else and cannot be used to silently bury a
# genuine crash.
_PERMITTED_UB_MARKERS = (
    "undefined behavior per pkcs#11",
    "documented misuse",
)


def _is_spec_permitted_ub(strings: list[str]) -> bool:
    text = " ".join(value.lower() for value in strings)
    return any(marker in text for marker in _PERMITTED_UB_MARKERS)


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{func.value.id}.{func.attr}"
    return ""


def _literal_strings(node: ast.AST) -> list[str]:
    return [
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    ]


def _reports_crash(strings: list[str]) -> bool:
    text = " ".join(value.lower() for value in strings)
    if any(phrase in text for phrase in _NON_CRASH_PHRASES):
        return False
    return any(term in text for term in _CRASH_TERMS)


def test_provider_crashes_are_not_xfailed() -> None:
    offenders: list[str] = []
    for path in TESTCASE_ROOT.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _call_name(node) != "pytest.xfail":
                continue
            strings = _literal_strings(node)
            if _reports_crash(strings) and not _is_spec_permitted_ub(strings):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    assert offenders == []


def test_provider_crashes_are_not_skipped() -> None:
    offenders: list[str] = []
    for path in TESTCASE_ROOT.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _call_name(node) != "pytest.skip":
                continue
            strings = _literal_strings(node)
            if _reports_crash(strings) and not _is_spec_permitted_ub(strings):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    assert offenders == []


def test_null_param_subprocess_signal_is_failure() -> None:
    with pytest.raises(pytest.fail.Exception, match="C_GetInfo.*signal 11"):
        _check_null_result("C_GetInfo", -11, "", "segfault")


def test_ub_exemption_is_narrow() -> None:
    """The documented-misuse exemption must NOT excuse an ordinary crash report.

    A real provider crash (a finding) carries no spec-permitted-UB justification,
    so it is still an offender; only a message that explicitly states the crash
    is spec-permitted undefined behavior is exempt.
    """
    # A genuine crash report -> reported as crash, NOT exempt.
    real_crash = ["C_GenerateKey segfault (signal 11)"]
    assert _reports_crash(real_crash)
    assert not _is_spec_permitted_ub(real_crash)

    # The documented-misuse probe -> still reads as a crash, but is exempt.
    ub_probe = [
        "module SIGSEGV (signal 11) under NULL-init concurrency -- "
        "undefined behavior per PKCS#11 Sec.5.4, not a conformance bug"
    ]
    assert _reports_crash(ub_probe)
    assert _is_spec_permitted_ub(ub_probe)
