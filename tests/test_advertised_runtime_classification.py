"""Hygiene checks for advertised mechanism runtime classification."""

from __future__ import annotations

import ast
from pathlib import Path

_LEGACY_CIPHER_FILES = (
    Path("src/pkcs11_check/testcases/test_aria.py"),
    Path("src/pkcs11_check/testcases/test_blowfish.py"),
    Path("src/pkcs11_check/testcases/test_camellia.py"),
    Path("src/pkcs11_check/testcases/test_twofish.py"),
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


def test_advertised_legacy_cipher_runtime_rejections_are_not_skips() -> None:
    """Advertised-but-rejected mechanisms should remain visible as xfails."""
    offenders: list[str] = []
    for path in _LEGACY_CIPHER_FILES:
        source = path.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _call_name(node) != "pytest.skip":
                continue
            if any("Mechanism advertised but rejected at use" in s for s in _literal_strings(node)):
                offenders.append(f"{path}:{node.lineno}")

    assert offenders == []
