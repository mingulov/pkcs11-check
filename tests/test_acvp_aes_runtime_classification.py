"""Hygiene checks for ACVP AES runtime-result classification."""

from __future__ import annotations

import ast
from pathlib import Path

_ACVP_AES_ROOT = Path("src/pkcs11_check/testcases/acvp/aes")


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


def test_advertised_acvp_aes_runtime_rejections_are_not_skips() -> None:
    """After has_mechanism passes, runtime mechanism rejection is a finding."""
    offenders: list[str] = []
    for path in sorted(_ACVP_AES_ROOT.rglob("*.py")):
        source = path.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _call_name(node) != "pytest.skip":
                continue
            strings = _literal_strings(node)
            if any("not supported:" in text or "module errors" in text for text in strings):
                offenders.append(f"{path}:{node.lineno}: {strings!r}")

    assert offenders == []
