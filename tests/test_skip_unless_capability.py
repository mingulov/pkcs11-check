# tests/test_skip_unless_capability.py
"""skip_unless_capability gate + in-range not-operational routing."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import XFailed  # type: ignore[attr-defined]

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKF_SIGN,
    CKM_RSA_PKCS,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_SIZE_RANGE,
)
from pkcs11_check.testcases import _capability
from pkcs11_check.testcases import conftest as ct


@pytest.fixture(autouse=True)
def _clear_cache() -> Any:
    _capability.reset_capability_cache()
    yield
    _capability.reset_capability_cache()


def _rs(names: set[str]) -> Any:
    return SimpleNamespace(raw=object(), slot_id=0, has_mechanism=lambda n: n in names)


def test_in_range_does_not_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = _rs({"CKM_RSA_PKCS", "RSA_PKCS"})
    monkeypatch.setattr(
        _capability,
        "get_mechanism_info",
        lambda *_a, **_k: {"min_key_size": 2048, "max_key_size": 4096, "flags": int(CKF_SIGN)},
    )
    # Should NOT raise Skipped.
    ct.skip_unless_capability(rs, CKM_RSA_PKCS, key_size=3072, operation=CKF_SIGN)


def test_out_of_range_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = _rs({"CKM_RSA_PKCS", "RSA_PKCS"})
    monkeypatch.setattr(
        _capability,
        "get_mechanism_info",
        lambda *_a, **_k: {"min_key_size": 2048, "max_key_size": 4096, "flags": int(CKF_SIGN)},
    )
    with pytest.raises(pytest.skip.Exception):
        ct.skip_unless_capability(rs, CKM_RSA_PKCS, key_size=1024, operation=CKF_SIGN)


def test_in_range_fns_routes_to_xfail() -> None:
    exc = CkrAssertionError(
        "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED", int(CKR_FUNCTION_NOT_SUPPORTED)
    )
    with pytest.raises(XFailed):
        ct.route_in_range_not_operational(
            exc, label="RSA_PKCS:sign", mechanism="RSA_PKCS", key_size=3072, operation="C_Sign"
        )


def test_in_range_key_size_range_routes_to_xfail() -> None:
    exc = CkrAssertionError("Unexpected CK_RV CKR_KEY_SIZE_RANGE", int(CKR_KEY_SIZE_RANGE))
    with pytest.raises(XFailed):
        ct.route_in_range_not_operational(
            exc, label="RSA_PKCS:sign", mechanism="RSA_PKCS", key_size=3072, operation="C_Sign"
        )


def test_device_error_is_not_routed_stays_finding() -> None:
    exc = CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))
    with pytest.raises(CkrAssertionError):
        ct.route_in_range_not_operational(
            exc, label="RSA_PKCS:sign", mechanism="RSA_PKCS", key_size=3072, operation="C_Sign"
        )
