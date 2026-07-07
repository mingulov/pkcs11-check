"""Guard: fork-based subprocess-safety tests must skip where ``os.fork`` is absent.

``os.fork()`` is POSIX-only. On Windows/Wine, ``os.fork`` does not exist, so a probe that
calls it raises ``AttributeError`` and the probe subprocess exits with code 1. The isolated
runner then records that as a *crash finding* against the module, even though the module
never ran the scenario - a false positive (observed on the ``softhsm2-wine`` pool target).
Any parent test that launches a fork-using probe must therefore carry a skipif guard
(``@requires_fork``) so it skips cleanly on a no-fork platform instead of manufacturing a
fake crash.

Since the fork logic now lives in ``_probes/subprocess_safety.py`` (dispatched on
``extra["probe"]``), this AST guard: (1) discovers which probe dispatch keys have handlers
that call ``os.fork``, then (2) fails on any parent test in ``test_subprocess_safety.py``
that references such a key (i.e. launches a fork-using probe) without the guard. It mirrors
``tests/test_security_64bit_value_gating.py`` and catches the gap once on a POSIX dev box
rather than as a flood of false crashes under Wine.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases"
_PARENT = _SRC / "test_subprocess_safety.py"
_PROBE = _SRC / "_probes/subprocess_safety.py"


def _calls_os_fork(func: ast.FunctionDef) -> bool:
    """True if the function body calls ``os.fork(...)``."""
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "fork"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
        ):
            return True
    return False


def _fork_probe_keys() -> set[str]:
    """Dispatch keys in the probe whose handler calls ``os.fork``."""
    tree = ast.parse(_PROBE.read_text())
    fork_funcs = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and _calls_os_fork(node)
    }
    keys: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "_PROBES" for t in node.targets):
            continue
        if isinstance(node.value, ast.Dict):
            for key, value in zip(node.value.keys, node.value.values, strict=False):
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and isinstance(value, ast.Name)
                    and value.id in fork_funcs
                ):
                    keys.add(key.value)
    return keys


def _references_fork_probe(func: ast.FunctionDef, fork_keys: set[str]) -> bool:
    """True if the test body references a fork-using probe dispatch key."""
    return any(
        isinstance(node, ast.Constant) and node.value in fork_keys for node in ast.walk(func)
    )


def _is_fork_guarded(decorators: list[ast.expr]) -> bool:
    """True if any decorator is the requires_fork marker or an os.fork skipif."""
    for dec in decorators:
        src = ast.unparse(dec)
        if "requires_fork" in src or ("skipif" in src and "fork" in src):
            return True
    return False


def test_fork_based_tests_skip_without_os_fork() -> None:
    fork_keys = _fork_probe_keys()
    # Guard against a vacuous pass: the probe must actually host fork handlers.
    assert fork_keys, "expected the subprocess_safety probe to expose fork-using handlers"

    tree = ast.parse(_PARENT.read_text())
    offenders: list[str] = []

    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        cls_guarded = _is_fork_guarded(cls.decorator_list)
        for func in cls.body:
            if (
                isinstance(func, ast.FunctionDef)
                and func.name.startswith("test_")
                and _references_fork_probe(func, fork_keys)
                and not (cls_guarded or _is_fork_guarded(func.decorator_list))
            ):
                offenders.append(f"{cls.name}.{func.name}")

    for func in tree.body:  # defensive: module-level test functions
        if (
            isinstance(func, ast.FunctionDef)
            and func.name.startswith("test_")
            and _references_fork_probe(func, fork_keys)
            and not _is_fork_guarded(func.decorator_list)
        ):
            offenders.append(func.name)

    assert not offenders, (
        "fork-based subprocess-safety tests missing an os.fork skipif guard "
        f"(decorate with @requires_fork): {offenders}"
    )
