# tests/test_capability_for.py
"""Unit tests for capability_for: the CK_MECHANISM_INFO -> verdict classifier."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_SIGN,
    CKM_AES_ECB,
    CKM_RSA_PKCS,
    CKR_FUNCTION_FAILED,
)
from pkcs11_check.testcases import _capability
from pkcs11_check.testcases._capability import Capability, capability_for


@pytest.fixture(autouse=True)
def _clear_cache() -> Any:
    _capability.reset_capability_cache()
    yield
    _capability.reset_capability_cache()


def _rs(names: set[str]) -> Any:
    return SimpleNamespace(raw=object(), slot_id=0, has_mechanism=lambda n: n in names)


def _patch_info(monkeypatch: pytest.MonkeyPatch, info: dict[str, int]) -> None:
    monkeypatch.setattr(_capability, "get_mechanism_info", lambda *_a, **_k: dict(info))


def test_not_advertised_when_name_absent() -> None:
    rs = _rs(set())
    assert capability_for(rs, CKM_RSA_PKCS, key_size=2048) is Capability.NOT_ADVERTISED


def test_rsa_in_range_bits(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = _rs({"CKM_RSA_PKCS", "RSA_PKCS"})
    _patch_info(monkeypatch, {"min_key_size": 2048, "max_key_size": 4096, "flags": int(CKF_SIGN)})
    result = capability_for(rs, CKM_RSA_PKCS, key_size=3072, operation=CKF_SIGN)
    assert result is Capability.IN_RANGE


def test_rsa_out_of_range_below_min(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = _rs({"CKM_RSA_PKCS", "RSA_PKCS"})
    _patch_info(monkeypatch, {"min_key_size": 2048, "max_key_size": 4096, "flags": int(CKF_SIGN)})
    assert capability_for(rs, CKM_RSA_PKCS, key_size=1024) is Capability.OUT_OF_RANGE


def test_aes_in_range_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = _rs({"CKM_AES_ECB", "AES_ECB"})
    _patch_info(monkeypatch, {"min_key_size": 16, "max_key_size": 32, "flags": int(CKF_DECRYPT)})
    assert capability_for(rs, CKM_AES_ECB, key_size=16) is Capability.IN_RANGE


def test_aes_out_of_range_short_key(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = _rs({"CKM_AES_ECB", "AES_ECB"})
    _patch_info(monkeypatch, {"min_key_size": 16, "max_key_size": 32, "flags": int(CKF_DECRYPT)})
    assert capability_for(rs, CKM_AES_ECB, key_size=8) is Capability.OUT_OF_RANGE


def test_flag_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = _rs({"CKM_RSA_PKCS", "RSA_PKCS"})
    _patch_info(monkeypatch, {"min_key_size": 2048, "max_key_size": 4096, "flags": int(CKF_SIGN)})
    # Mechanism advertises SIGN but not DECRYPT.
    assert capability_for(rs, CKM_RSA_PKCS, operation=CKF_DECRYPT) is Capability.FLAG_UNSET


def test_no_size_semantics_when_min_max_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = _rs({"CKM_AES_ECB", "AES_ECB"})
    _patch_info(monkeypatch, {"min_key_size": 0, "max_key_size": 0, "flags": int(CKF_DECRYPT)})
    result = capability_for(rs, CKM_AES_ECB, key_size=9999, operation=CKF_DECRYPT)
    assert result is Capability.IN_RANGE


def test_info_error_is_in_range_never_gates_out(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = _rs({"CKM_RSA_PKCS", "RSA_PKCS"})

    def _boom(*_a: Any, **_k: Any) -> dict[str, int]:
        raise CkrAssertionError("Unexpected CK_RV CKR_FUNCTION_FAILED", int(CKR_FUNCTION_FAILED))

    monkeypatch.setattr(_capability, "get_mechanism_info", _boom)
    assert capability_for(rs, CKM_RSA_PKCS, key_size=2048) is Capability.IN_RANGE
