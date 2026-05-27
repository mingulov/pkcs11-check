"""Regression tests for mechanism-driven derive runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKM_EXTRACT_KEY_FROM_KEY,
    CKM_HKDF_DERIVE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import test_mech_derive
from pkcs11_check.testcases.mechanism_catalog import MechEntry


def _entry(mech_id: int, name: str) -> MechEntry:
    return MechEntry(
        mech_id=mech_id,
        mech_name=name,
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=object(),
    )


def _session() -> Any:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
    )


def test_extract_key_from_key_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _derive_reject(*_args: Any, **_kwargs: Any) -> None:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT",
            int(CKR_TEMPLATE_INCONSISTENT),
        )

    monkeypatch.setattr(test_mech_derive, "_derive_extract", _derive_reject)

    with pytest.raises(
        pytest.xfail.Exception,
        match="CKM_EXTRACT_KEY_FROM_KEY: advertised derive path is not operational",
    ):
        test_mech_derive.TestMechDerive().test_derive_produces_key(
            _session(),
            _entry(int(CKM_EXTRACT_KEY_FROM_KEY), "CKM_EXTRACT_KEY_FROM_KEY"),
        )


def test_hkdf_base_keygen_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _derive_reject(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("HKDF base key gen failed: CKR_MECHANISM_INVALID")

    monkeypatch.setattr(test_mech_derive, "_derive_hkdf", _derive_reject)

    with pytest.raises(
        pytest.xfail.Exception,
        match="CKM_HKDF_DERIVE: advertised derive path is not operational",
    ):
        test_mech_derive.TestMechDerive().test_derive_produces_key(
            _session(),
            _entry(int(CKM_HKDF_DERIVE), "CKM_HKDF_DERIVE"),
        )
