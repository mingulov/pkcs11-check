"""Hygiene checks for provider-neutral runtime finding messages."""

from __future__ import annotations

import ast
from pathlib import Path

_PROVIDER_TOKENS = ("NSS", "NSS-PQC", "softoken")
_TESTCASE_ROOT = Path("src/pkcs11_check/testcases")


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{func.value.id}.{func.attr}"
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _literal_strings(node: ast.AST) -> list[str]:
    strings: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            strings.append(child.value)
    return strings


def _assigned_name(node: ast.AST) -> str:
    if isinstance(node, ast.Assign):
        return ",".join(target.id for target in node.targets if isinstance(target, ast.Name))
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id
    return ""


def test_runtime_findings_use_provider_neutral_wording() -> None:
    """Runtime findings should not misattribute behavior to a specific provider."""
    offenders: list[str] = []
    for path in sorted(_TESTCASE_ROOT.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _call_name(node) in {
                "pytest.xfail",
                "pytest.fail",
                "note",
            }:
                strings = _literal_strings(node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)) and any(
                part in _assigned_name(node) for part in ("XFAIL", "FAIL_MSG")
            ):
                strings = _literal_strings(node)
            else:
                continue

            for text in strings:
                if any(token in text for token in _PROVIDER_TOKENS):
                    offenders.append(f"{path}:{node.lineno}: {text}")

    assert offenders == []
