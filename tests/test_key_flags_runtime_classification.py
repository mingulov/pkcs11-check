"""Regression tests for key-flag setup/runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases import test_key_flags


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def test_key_flags_aes_keygen_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _keygen_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
            int(CKR_FUNCTION_NOT_SUPPORTED),
        )

    monkeypatch.setattr(test_key_flags, "gen_aes_key", _keygen_reject)
    monkeypatch.setattr(test_key_flags, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_key_flags.TestNeverExtractable().test_generated_non_extractable_is_never_extractable(
            _session()
        )


def test_imported_key_missing_local_readback_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_key_flags, "import_secret_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_key_flags, "read_attributes", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(test_key_flags, "_read_bool_attr_safe", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_key_flags, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        test_key_flags, "skip_unless_create_object_supported", lambda *_args, **_kwargs: None
    )

    with pytest.raises(pytest.xfail.Exception, match="CKA_LOCAL"):
        test_key_flags.TestLocalFlag().test_imported_key_is_not_local(_session())
