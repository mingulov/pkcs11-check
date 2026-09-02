"""Regression tests for miscellaneous KDF runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_ATTRIBUTE_VALUE_INVALID
from pkcs11_check.testcases import test_misc_kdf


def test_extract_key_from_key_attribute_value_invalid_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "EXTRACT_KEY_FROM_KEY",
    )
    monkeypatch.setattr(test_misc_kdf, "_import_generic_secret", lambda *_args: 10)
    monkeypatch.setattr(test_misc_kdf, "destroy_quietly", lambda *_args: None)

    def _derive_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
            int(CKR_ATTRIBUTE_VALUE_INVALID),
        )

    monkeypatch.setattr(test_misc_kdf, "_derive_generic_secret", _derive_reject)
    monkeypatch.setattr(
        test_misc_kdf,
        "read_attributes",
        lambda *_args, **_kwargs: pytest.fail("read should not run after derive reject"),
    )

    with pytest.raises(pytest.xfail.Exception, match="CKM_EXTRACT_KEY_FROM_KEY derive failed"):
        test_misc_kdf.TestExtractKeyFromKey().test_extract_from_offset_zero(rs)
