"""Regression checks for crash-reporting policy in provider tests."""

from __future__ import annotations

import ast
from pathlib import Path

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
            if _reports_crash(_literal_strings(node)):
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
            if _reports_crash(_literal_strings(node)):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    assert offenders == []
