"""Regression guards for nested security-probe timeout ordering."""

from __future__ import annotations

import ast
import inspect
import time
from types import ModuleType

import pytest

from pkcs11_check import classification
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import (
    SUBPROCESS_TIMEOUT_MARKER,
    SUBPROCESS_TIMEOUT_RC,
)
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed
from pkcs11_check.testcases.security import (
    test_digest_length_truncation,
    test_field_size_boundary,
    test_output_length_truncation,
    test_random_length_truncation,
)

_AFFECTED_MODULES = (
    test_output_length_truncation,
    test_random_length_truncation,
    test_digest_length_truncation,
    test_field_size_boundary,
)


def _declared_probe_timeouts(module: ModuleType) -> list[int]:
    """Return the statically declared timeout of every run_probe call in a module."""
    tree = ast.parse(inspect.getsource(module))
    integer_constants = {
        target.id: value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance((target := node.targets[0]), ast.Name)
        and isinstance((value := node.value), ast.Constant)
        and isinstance(value.value, int)
    }
    timeouts: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id != "run_probe":
            continue
        timeout = next((kw.value for kw in node.keywords if kw.arg == "timeout"), None)
        if isinstance(timeout, ast.Constant) and isinstance(timeout.value, int):
            timeouts.append(timeout.value)
        elif isinstance(timeout, ast.Name) and timeout.id in integer_constants:
            timeouts.append(integer_constants[timeout.id])
        else:
            raise AssertionError(f"{module.__name__} has a run_probe call without a fixed timeout")
    return timeouts


@pytest.mark.parametrize(
    "module", _AFFECTED_MODULES, ids=lambda module: module.__name__.rsplit(".", 1)[-1]
)
def test_outer_watchdog_exceeds_every_inner_probe_timeout(module: ModuleType) -> None:
    """The pytest watchdog must leave time for every inner probe to report its timeout."""
    inner_timeouts = _declared_probe_timeouts(module)
    timeout_marks = [mark for mark in module.pytestmark if mark.name == "timeout"]

    assert inner_timeouts
    assert max(inner_timeouts) == 180
    assert len(timeout_marks) == 1
    assert timeout_marks[0].args == (240,)
    assert timeout_marks[0].args[0] > max(inner_timeouts)


@pytest.mark.timeout(3)
def test_inner_probe_timeout_is_classified_before_outer_watchdog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hanging probe emits its sentinel and a crash finding before the unit watchdog."""
    monkeypatch.setenv("PKCS11_CHECK_UNIT_CHILD", "1")
    classification.clear()
    started = time.monotonic()
    try:
        result = run_probe(
            "_echo",
            {"module_path": "/nonexistent.so", "sleep": 5},
            timeout=1,
        )

        assert result.returncode == SUBPROCESS_TIMEOUT_RC
        assert SUBPROCESS_TIMEOUT_MARKER in result.stderr
        with pytest.raises(pytest.fail.Exception, match="module hung"):
            assert_subprocess_completed(
                result.returncode,
                result.stdout,
                result.stderr,
                context="nested timeout ordering regression",
            )
        records = classification.get_records()
        assert [(record.reason, record.outcome) for record in records] == [("crash", "fail")]
        assert time.monotonic() - started < 3
    finally:
        classification.clear()
