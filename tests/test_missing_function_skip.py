"""M-37: pin the live-hook missing-function -> skip conversion.

The function dispatcher raises ``AttributeError("<C_Fn> not available in this
module")`` (raw/api.py) when a test calls a function the loaded module does not
implement -- routine on minimal modules. The makereport hook converts that one
shape into a skip; only the subprocess stderr layer had coverage, so a
regression here would misclassify minimal-module capability gaps as hard
errors while the suite stays green.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from pkcs11_check._plugin_report_attach import _convert_missing_function_to_skip

_MISSING_MESSAGE = "C_EncryptMessage not available in this module"


def _report(*, when: str = "call", outcome: str = "failed") -> Any:
    return SimpleNamespace(
        when=when,
        outcome=outcome,
        fspath="/x/test_minimal.py",
        location=("/x/test_minimal.py", 41, "test_minimal"),
        longrepr=None,
    )


def _call(exc_type: type[BaseException], message: str) -> Any:
    return SimpleNamespace(
        excinfo=SimpleNamespace(type=exc_type, value=exc_type(message)),
    )


def test_missing_function_failure_converts_to_skip() -> None:
    """The dispatcher's exact AttributeError shape becomes a skip, not an error."""
    report = _report()
    call = _call(AttributeError, _MISSING_MESSAGE)

    _convert_missing_function_to_skip(report, call)

    assert report.outcome == "skipped"
    assert report.longrepr == ("/x/test_minimal.py", 42, f"Skipped: {_MISSING_MESSAGE}")


def test_missing_function_setup_failure_converts_to_skip() -> None:
    report = _report(when="setup")
    call = _call(AttributeError, _MISSING_MESSAGE)

    _convert_missing_function_to_skip(report, call)

    assert report.outcome == "skipped"


def test_other_attribute_error_is_untouched() -> None:
    """A nearby-but-different AttributeError must stay a hard failure."""
    report = _report()
    call = _call(AttributeError, "C_EncryptMessage blew up")

    _convert_missing_function_to_skip(report, call)

    assert report.outcome == "failed"
    assert report.longrepr is None


def test_non_attribute_error_is_untouched() -> None:
    report = _report()
    call = _call(ValueError, _MISSING_MESSAGE)

    _convert_missing_function_to_skip(report, call)

    assert report.outcome == "failed"
    assert report.longrepr is None


def test_passed_report_is_untouched() -> None:
    report = _report(outcome="passed")
    call = _call(AttributeError, _MISSING_MESSAGE)

    _convert_missing_function_to_skip(report, call)

    assert report.outcome == "passed"


def test_teardown_report_is_untouched() -> None:
    report = _report(when="teardown")
    call = _call(AttributeError, _MISSING_MESSAGE)

    _convert_missing_function_to_skip(report, call)

    assert report.outcome == "failed"


def test_missing_excinfo_is_untouched() -> None:
    report = _report()
    call = SimpleNamespace(excinfo=None)

    _convert_missing_function_to_skip(report, call)

    assert report.outcome == "failed"
