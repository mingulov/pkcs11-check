"""Hygiene checks for ACVP AES runtime-result classification."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKM_AES_CFB128, CKR_DEVICE_ERROR, CKR_GENERAL_ERROR
from pkcs11_check.testcases.acvp.aes import base_cts, base_runner_simple

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


class _AesSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "AES_CFB128"


def _raise_general_error(*_args: Any, **_kwargs: Any) -> bytes:
    raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))


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


def test_advertised_acvp_aes_simple_general_error_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Generic runtime rejection after advertised AES support is an xfail finding."""
    monkeypatch.setattr(base_runner_simple, "_import_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(base_runner_simple, "encrypt_single", _raise_general_error)
    monkeypatch.setattr(base_runner_simple, "destroy_quietly", lambda *_args: None)

    vec = {
        "key": b"0" * 16,
        "iv": b"1" * 16,
        "pt": b"2" * 16,
        "ct_expected": b"3" * 16,
    }

    with pytest.raises(pytest.xfail.Exception, match="advertised but encrypt is not operational"):
        base_runner_simple.run_simple_encrypt_test(
            _AesSession(),
            "cfb128-general-error",
            vec,
            "AES_CFB128",
            CKM_AES_CFB128,
        )


def test_advertised_acvp_aes_mct_general_error_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MCT runtime rejection is classified like simple encrypt/decrypt rejection."""
    monkeypatch.setattr(base_runner_simple, "_import_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(base_runner_simple, "encrypt_single", _raise_general_error)
    monkeypatch.setattr(base_runner_simple, "destroy_quietly", lambda *_args: None)

    vec = {
        "blocks": [
            {
                "block_index": 0,
                "key": b"0" * 16,
                "iv": b"1" * 16,
                "pt": b"2" * 16,
                "ct_expected": b"3" * 16,
            }
        ],
    }

    with pytest.raises(
        pytest.xfail.Exception,
        match="advertised but MCT encrypt is not operational",
    ):
        base_runner_simple.run_multiblock_encrypt_test(
            _AesSession(),
            "cfb128-mct-general-error",
            vec,
            "AES_CFB128",
            CKM_AES_CFB128,
        )


def test_advertised_aes_cts_device_error_is_xfail() -> None:
    """CKR_DEVICE_ERROR from advertised CTS is a provider finding, not a raw failure."""
    exc = CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    with pytest.raises(pytest.xfail.Exception, match="CKM_AES_CTS advertised"):
        base_cts._handle_cts_error(_AesSession(), exc, "CBC-CS1-AES-enc-tc285", "encrypt")
