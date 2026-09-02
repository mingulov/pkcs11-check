"""Regression tests for HKDF extended runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKK_HKDF, CKR_ATTRIBUTE_VALUE_INVALID
from pkcs11_check.testcases import test_hkdf_extended


def test_hkdf_keygen_value_readback_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """Generated HKDF key value readback rejects should stay visible as xfail evidence."""

    def _read_attributes(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
            int(CKR_ATTRIBUTE_VALUE_INVALID),
        )

    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "HKDF_KEY_GEN",
    )
    monkeypatch.setattr(test_hkdf_extended, "_gen_hkdf_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_hkdf_extended, "read_attributes", _read_attributes)
    monkeypatch.setattr(test_hkdf_extended, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="CKA_VALUE readback rejected"):
        test_hkdf_extended.TestHKDFKeyGen().test_hkdf_key_gen_basic(rs, CKK_HKDF)
