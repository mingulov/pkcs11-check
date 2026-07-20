"""Static gate: at most ONE set_mechanism() call per function in testcases/.

The hollow-coverage claim (set_mechanism's operation + expect_success) is a
scalar: a second call in the same test silently overwrites the first, losing
a declaration. Dual-op roundtrip tests declare exactly one op (C_Sign) by
design — see the 2026-07-18 batch design spec.
"""

from __future__ import annotations

import ast
import pathlib

_TESTCASES = pathlib.Path(__file__).resolve().parent.parent / "src/pkcs11_check/testcases"


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def test_at_most_one_set_mechanism_call_per_function() -> None:
    offenders: list[str] = []
    for path in sorted(_TESTCASES.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            count = sum(
                1
                for sub in ast.walk(node)
                if isinstance(sub, ast.Call) and _call_name(sub) == "set_mechanism"
            )
            if count > 1:
                offenders.append(f"{path.relative_to(_TESTCASES)}::{node.name} ({count} calls)")
    assert not offenders, (
        "set_mechanism called more than once in a single function (the claim is a "
        "scalar; the second call silently drops the first): " + ", ".join(offenders)
    )
