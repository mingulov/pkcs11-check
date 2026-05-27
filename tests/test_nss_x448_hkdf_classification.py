"""Regression tests for NSS X448/HKDF runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DOMAIN_PARAMS_INVALID, CKR_MECHANISM_INVALID
from pkcs11_check.testcases import test_ecdh_extended, test_mech_lifecycle


def _session(raw: object | None = None) -> SimpleNamespace:
    return SimpleNamespace(raw=raw or object(), sh=1, has_mechanism=lambda _name: True)


def test_x448_domain_params_invalid_is_unsupported_curve_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _reject_x448(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_DOMAIN_PARAMS_INVALID",
            int(CKR_DOMAIN_PARAMS_INVALID),
        )

    monkeypatch.setattr(test_ecdh_extended, "_gen_montgomery", _reject_x448)

    with pytest.raises(pytest.skip.Exception, match="X448 keygen not supported"):
        test_ecdh_extended.TestECMontgomeryKeyPairGen().test_x448_keygen(_session())


def test_hkdf_lifecycle_keygen_mechanism_invalid_is_xfail() -> None:
    class _Raw:
        def C_GenerateKey(self, *_args: Any) -> int:  # noqa: N802
            return int(CKR_MECHANISM_INVALID)

    with pytest.raises(pytest.xfail.Exception, match="HKDF base key generation rejected"):
        test_mech_lifecycle.TestHKDFDerivedKeyUse().test_hkdf_to_aes_encrypt(_session(_Raw()))
