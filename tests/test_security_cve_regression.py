"""Regression tests for security CVE testcase behavior."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.testcases.security import test_cve_regression


class _EncryptStateRaw:
    def __init__(self) -> None:
        self.active = False
        self.abort_count = 0

    def C_EncryptFinal(self, *_args: Any) -> int:  # noqa: N802 - raw PKCS#11 API shape
        self.active = False
        self.abort_count += 1
        return 0


def _session(raw: Any) -> SimpleNamespace:
    return SimpleNamespace(raw=raw, sh=1)


def test_aes_ecb_boundary_lengths_aborts_after_rejected_invalid_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _EncryptStateRaw()

    def _encrypt_single(_raw: Any, _sh: int, _key: int, _mech: int, data: bytes) -> bytes:
        if raw.active:
            raise AssertionError("Unexpected CK_RV CKR_OPERATION_ACTIVE")
        if len(data) % 16 != 0 or len(data) == 0:
            raw.active = True
            raise AssertionError("Unexpected CK_RV CKR_DATA_LEN_RANGE")
        return data

    monkeypatch.setattr(test_cve_regression, "gen_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_cve_regression, "encrypt_single", _encrypt_single)
    monkeypatch.setattr(test_cve_regression, "decrypt_single", lambda *_args: _args[4])
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_args: None)

    test_cve_regression.TestBoundaryLengthCrypto().test_aes_ecb_boundary_lengths(
        _session(raw)
    )

    assert raw.abort_count >= 4


def test_aes_ecb_boundary_lengths_fails_when_nonaligned_input_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _EncryptStateRaw()

    def _encrypt_single(_raw: Any, _sh: int, _key: int, _mech: int, data: bytes) -> bytes:
        if len(data) % 16 == 0 and len(data) > 0:
            return data
        if len(data) == 1:
            return b"accepted"
        raise AssertionError("Unexpected CK_RV CKR_DATA_LEN_RANGE")

    monkeypatch.setattr(test_cve_regression, "gen_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_cve_regression, "encrypt_single", _encrypt_single)
    monkeypatch.setattr(test_cve_regression, "decrypt_single", lambda *_args: _args[4])
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="accepted non-block-aligned"):
        test_cve_regression.TestBoundaryLengthCrypto().test_aes_ecb_boundary_lengths(
            _session(raw)
        )
