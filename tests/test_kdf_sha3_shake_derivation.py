"""Regression tests for SHA3/SHAKE key-derivation parameter templates."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKM_SHA3_224_KEY_DERIVE,
    CKM_SHAKE_128_KEY_DERIVE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import test_kdf


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


def test_sha3_224_key_derive_uses_no_params_and_digest_output_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    def _derive_key(*_args: Any, **kwargs: Any) -> int:
        calls.append(kwargs)
        assert kwargs["mech_param"] is None
        assert kwargs["attrs"][int(CKA_VALUE_LEN)] == 28
        return 2

    monkeypatch.setattr(test_kdf, "_import_generic_secret", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_kdf, "derive_key", _derive_key)
    monkeypatch.setattr(test_kdf, "read_attributes", lambda *_args: {CKA_VALUE: b"x" * 28})
    monkeypatch.setattr(test_kdf, "destroy_quietly", lambda *_args: None)

    test_kdf.TestSHA3ShakeKeyDerive().test_derive_produces_key(
        _session(),
        "SHA3_224_KEY_DERIVE",
        int(CKM_SHA3_224_KEY_DERIVE),
    )

    assert len(calls) == 1


def test_shake_key_derive_uses_no_string_data_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    params: list[Any] = []

    def _derive_key(*_args: Any, **kwargs: Any) -> int:
        params.append(kwargs["mech_param"])
        return len(params) + 1

    monkeypatch.setattr(test_kdf, "_import_generic_secret", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_kdf, "derive_key", _derive_key)
    monkeypatch.setattr(test_kdf, "read_attributes", lambda *_args: {CKA_VALUE: b"x" * 16})
    monkeypatch.setattr(test_kdf, "destroy_quietly", lambda *_args: None)

    test_kdf.TestSHA3ShakeKeyDerive().test_derive_deterministic(
        _session(),
        "SHAKE_128_KEY_DERIVE",
        int(CKM_SHAKE_128_KEY_DERIVE),
    )

    assert params == [None, None]


def test_sha3_key_derive_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _derive_key(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT",
            int(CKR_TEMPLATE_INCONSISTENT),
        )

    monkeypatch.setattr(test_kdf, "_import_generic_secret", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_kdf, "derive_key", _derive_key)
    monkeypatch.setattr(test_kdf, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="SHA3_224_KEY_DERIVE derivation"):
        test_kdf.TestSHA3ShakeKeyDerive().test_derive_produces_key(
            _session(),
            "SHA3_224_KEY_DERIVE",
            int(CKM_SHA3_224_KEY_DERIVE),
        )
