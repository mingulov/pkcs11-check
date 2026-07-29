"""Guard: test cases must not assert on wall-clock elapsed time.

A hard-coded budget ("1000 cycles must finish in 30s") benchmarks the HOST but fails
the PROVIDER. Real numbers from the win-ctr lane: a 2-vCPU Windows container driving
BouncyHsm over loopback RPC needs 87s for the 1000 encrypt/decrypt cycles that were
budgeted at 30s, and 11s for the 1000 C_GenerateRandom calls budgeted at 10s. Both are
legitimate throughput for that deployment; both were recorded as provider failures.
Slow-but-correct hardware -- smartcards, embedded HSMs, emulators, remote daemons --
trips such thresholds the same way, which is exactly the "false finding against a
conformant provider" the classification rules call out as the real danger.

Hang detection belongs to the runner's per-unit ``--timeout``: stronger (it catches any
hang, not only one that pushes an aggregate past a constant) and free of the hardware
assumption.

Timing may still be MEASURED and compared relatively -- the padding-oracle probes
compare valid-vs-invalid decrypt means against each other, which is host-independent.
What is banned is comparing elapsed time to a hard-coded constant.
"""

from __future__ import annotations

import ast
from pathlib import Path

TESTCASES = Path(__file__).resolve().parent.parent / "src" / "pkcs11_check" / "testcases"

# Names that hold a duration in seconds. An assert comparing one of these to a literal
# is a wall-clock budget.
_DURATION_NAMES = {"elapsed", "duration", "took", "runtime", "wall", "seconds"}


def _is_duration_name(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        return node.id.lower() in _DURATION_NAMES
    if isinstance(node, ast.Attribute):
        return node.attr.lower() in _DURATION_NAMES
    return False


def _find_wallclock_asserts(tree: ast.AST) -> list[int]:
    hits: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assert):
            continue
        test = node.test
        if not isinstance(test, ast.Compare):
            continue
        if not any(isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)) for op in test.ops):
            continue
        operands = [test.left, *test.comparators]
        has_duration = any(_is_duration_name(operand) for operand in operands)
        has_constant = any(
            isinstance(operand, ast.Constant) and isinstance(operand.value, (int, float))
            for operand in operands
        )
        if has_duration and has_constant:
            hits.append(node.lineno)
    return hits


def test_no_hardcoded_wallclock_budgets_in_testcases() -> None:
    offenders: list[str] = []
    for path in sorted(TESTCASES.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for lineno in _find_wallclock_asserts(tree):
            offenders.append(f"{path.relative_to(TESTCASES.parent.parent.parent)}:{lineno}")

    assert not offenders, (
        "wall-clock budget asserted against a hard-coded constant:\n  "
        + "\n  ".join(offenders)
        + "\n\nThese fail slow-but-correct hosts (see this module's docstring). Assert on "
        "correctness and let the runner's --timeout catch genuine hangs, or compare two "
        "measured durations against each other rather than against a constant."
    )


def test_guard_detects_a_wallclock_budget() -> None:
    """The guard must actually fire -- otherwise it is a no-op that always passes."""
    tree = ast.parse("def f():\n    assert elapsed < 30, 'too slow'\n")
    assert _find_wallclock_asserts(tree) == [2]


def test_guard_ignores_relative_duration_comparisons() -> None:
    """Comparing two measured durations is host-independent and stays allowed."""
    tree = ast.parse("def f():\n    assert elapsed < baseline * 3\n")
    assert _find_wallclock_asserts(tree) == []
