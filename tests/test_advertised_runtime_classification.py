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

_RUNTIME_SKIP_PATTERNS = {
    Path("src/pkcs11_check/testcases/test_ecdh_extended.py"): (
        "Cofactor ECDH cannot derive AES key",
        "EC_MONTGOMERY_KEY_PAIR_GEN not operational",
    ),
    Path("src/pkcs11_check/testcases/test_extended_mechanisms.py"): (
        "mechanism rejected by module",
    ),
    Path("src/pkcs11_check/testcases/test_mech_message.py"): ("CKR_MECHANISM_INVALID for CKM_",),
    Path("src/pkcs11_check/testcases/test_kdf.py"): ("HKDF derivation not operational",),
    Path("src/pkcs11_check/testcases/test_otp.py"): (
        "keygen rejected",
        "not operational",
        "CKM_KIP_DERIVE rejected",
    ),
}


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


def test_advertised_runtime_rejections_are_not_skipped() -> None:
    """Runtime rejection after capability checks should be xfail/fail evidence."""
    offenders: list[str] = []
    for path, skip_patterns in _RUNTIME_SKIP_PATTERNS.items():
        source = path.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _call_name(node) != "pytest.skip":
                continue
            strings = _literal_strings(node)
            if any(pattern in value for pattern in skip_patterns for value in strings):
                offenders.append(f"{path}:{node.lineno}")

    assert offenders == []
