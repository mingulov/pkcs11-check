"""Regression tests for the subprocess session preamble (PIN-leak + escaping)."""

from __future__ import annotations

from typing import Any
from unittest import mock

from pkcs11_check.testcases import _subprocess_preamble
from pkcs11_check.testcases._subprocess_preamble import (
    _P11CHECK_PIN_ENV,
    run_with_coverage,
    subprocess_session_preamble,
)


def test_pin_not_interpolated_into_script() -> None:
    """M1: the PIN must never appear in the generated script text/argv.

    The PIN is passed to the child via an environment variable, so the
    plaintext PIN must not be present anywhere in the script source string.
    """
    pin = "s3cr3t-PIN-DO-NOT-LEAK"
    script = subprocess_session_preamble("/path/to/module.so", pin=pin)
    assert pin not in script
    # Login must still happen -- via an env-var read, not a literal.
    assert _P11CHECK_PIN_ENV in script
    assert "login_user(" in script


def test_no_pin_means_no_login_and_no_env_read() -> None:
    """When pin is None, no login line is emitted at all."""
    script = subprocess_session_preamble("/path/to/module.so", pin=None)
    assert "login_user(" not in script


def test_slot_label_with_quotes_does_not_break_script() -> None:
    """M1: a slot label containing quotes/backslashes/newlines must be safe.

    The generated script must remain syntactically valid Python and must not
    permit injection via the label.
    """
    # NOTE: the os.system(...) text below is INERT test data -- a hostile label
    # payload used to assert that the preamble does NOT emit it as executable
    # code. Nothing here ever runs a shell.
    malicious = 'foo"; import os; os.system("rm -rf /")\n#'
    script = subprocess_session_preamble("/path/to/module.so", slot_label=malicious)
    # Must still parse as valid Python (no broken string / injected statement).
    compile(script, "<preamble>", "exec")
    # The injected os.system call must not appear as executable code.
    assert 'os.system("rm -rf /")' not in script


def test_module_path_with_quotes_does_not_break_script() -> None:
    """A module path containing a quote must not break the generated source."""
    path = '/weird"path/module.so'
    script = subprocess_session_preamble(path, pin=None)
    compile(script, "<preamble>", "exec")


def test_run_with_coverage_places_pin_in_env_not_argv() -> None:
    """M1: run_with_coverage must inject the PIN into the child env, not argv."""
    pin = "another-secret-pin"
    captured: dict[str, Any] = {}

    class _Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def _fake_run(args: list[str], **kwargs: Any) -> _Result:
        captured["args"] = args
        captured["env"] = kwargs.get("env")
        return _Result()

    with mock.patch.object(_subprocess_preamble.subprocess, "run", _fake_run):
        run_with_coverage("print('hi')", pin=pin)

    # PIN must not appear in the argv at all.
    assert all(pin not in arg for arg in captured["args"])
    # PIN must be present in the child environment under the agreed key.
    assert captured["env"][_P11CHECK_PIN_ENV] == pin


def test_run_with_coverage_no_pin_does_not_set_env_key() -> None:
    """Without a PIN, the env var must not be present in the child env."""
    captured: dict[str, Any] = {}

    class _Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def _fake_run(args: list[str], **kwargs: Any) -> _Result:
        captured["env"] = kwargs.get("env")
        return _Result()

    with mock.patch.object(_subprocess_preamble.subprocess, "run", _fake_run):
        run_with_coverage("print('hi')")

    assert _P11CHECK_PIN_ENV not in captured["env"]
