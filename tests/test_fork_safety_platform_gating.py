"""Guard: fork-based subprocess-safety tests must skip where ``os.fork`` is absent.

``os.fork()`` is POSIX-only. On Windows/Wine, ``os.fork`` does not exist, so a child
script that calls it raises ``AttributeError`` and the child exits with code 1. The
isolated runner then records that as a *crash finding* against the module, even though
the module never ran the scenario - a false positive (observed on the ``softhsm2-wine``
pool target). Any test whose child script uses ``os.fork`` must therefore carry a
skipif guard (``@requires_fork``) so it skips cleanly on a no-fork platform instead of
manufacturing a fake crash.

This is an AST guard (mirrors ``tests/test_security_64bit_value_gating.py``): it fails
on any fork-based test that lacks the guard, catching the gap once on a POSIX dev box
rather than as a flood of false crashes under Wine.
"""

from __future__ import annotations

import ast
from pathlib import Path

_FILE = Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases/test_subprocess_safety.py"


def _uses_fork(func: ast.FunctionDef) -> bool:
    """True if the function body (incl. embedded child-script strings) uses os.fork."""
    return any(
        isinstance(node, ast.Constant) and isinstance(node.value, str) and "os.fork(" in node.value
        for node in ast.walk(func)
    )


def _is_fork_guarded(decorators: list[ast.expr]) -> bool:
    """True if any decorator is the requires_fork marker or an os.fork skipif."""
    for dec in decorators:
        src = ast.unparse(dec)
        if "requires_fork" in src or ("skipif" in src and "fork" in src):
            return True
    return False


def test_fork_based_tests_skip_without_os_fork() -> None:
    tree = ast.parse(_FILE.read_text())
    offenders: list[str] = []

    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        cls_guarded = _is_fork_guarded(cls.decorator_list)
        for func in cls.body:
            if (
                isinstance(func, ast.FunctionDef)
                and func.name.startswith("test_")
                and _uses_fork(func)
                and not (cls_guarded or _is_fork_guarded(func.decorator_list))
            ):
                offenders.append(f"{cls.name}.{func.name}")

    for func in tree.body:  # defensive: module-level test functions
        if (
            isinstance(func, ast.FunctionDef)
            and func.name.startswith("test_")
            and _uses_fork(func)
            and not _is_fork_guarded(func.decorator_list)
        ):
            offenders.append(func.name)

    assert not offenders, (
        "fork-based subprocess-safety tests missing an os.fork skipif guard "
        f"(decorate with @requires_fork): {offenders}"
    )
