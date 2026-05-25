"""Regression tests for ECDSA prehash runtime-result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKM_ECDSA_SHA224, CKR_DEVICE_ERROR
from pkcs11_check.testcases import test_ecdsa_extended


def _session(*mechanisms: str) -> SimpleNamespace:
    advertised = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in advertised,
    )


def test_tampered_ecdsa_non_clean_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _verify_reject(*_args: Any, **_kwargs: Any) -> bool:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(test_ecdsa_extended, "gen_ec_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(test_ecdsa_extended, "sign_single", lambda *_args, **_kwargs: b"sig")
    monkeypatch.setattr(test_ecdsa_extended, "verify_single", _verify_reject)
    monkeypatch.setattr(test_ecdsa_extended, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="invalid signature rejected"):
        test_ecdsa_extended.TestECDSAPrehash().test_tampered_data_fails(
            _session("ECDSA_SHA224"),
            "ECDSA_SHA224",
            CKM_ECDSA_SHA224,
        )
