"""Regression tests for C_GetObjectSize runtime classification."""

from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CK_UNAVAILABLE_INFORMATION, CKR_FUNCTION_FAILED
from pkcs11_check.testcases import test_object_size


def test_safe_get_size_propagates_python_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def _local_bug(*_args: object) -> int:
        raise ValueError("local object-size bug")

    monkeypatch.setattr(test_object_size, "get_object_size", _local_bug)

    with pytest.raises(ValueError, match="local object-size bug"):
        test_object_size._safe_get_size(object(), 1, 2)


def test_safe_get_size_xfails_generic_runtime_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _runtime_reject(*_args: object) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_FAILED",
            int(CKR_FUNCTION_FAILED),
        )

    monkeypatch.setattr(test_object_size, "get_object_size", _runtime_reject)

    with pytest.raises(pytest.xfail.Exception, match="C_GetObjectSize rejected"):
        test_object_size._safe_get_size(object(), 1, 2)


@pytest.mark.parametrize("reported_size", [0, CK_UNAVAILABLE_INFORMATION])
def test_safe_get_size_keeps_unavailable_sentinel_as_none(
    monkeypatch: pytest.MonkeyPatch,
    reported_size: int,
) -> None:
    monkeypatch.setattr(test_object_size, "get_object_size", lambda *_args: reported_size)

    assert test_object_size._safe_get_size(object(), 1, 2) is None
