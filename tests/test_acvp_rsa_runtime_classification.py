"""Regression tests for ACVP RSA setup/result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKM_SHA1_RSA_PKCS,
    CKM_SHA1_RSA_PKCS_PSS,
    CKM_SHA_1,
    CKR_ATTRIBUTE_VALUE_INVALID,
)
from pkcs11_check.testcases.acvp import test_acvp_rsa


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


def _pkcs15_vec(*, expected_pass: bool = True) -> dict[str, Any]:
    return {
        "mech_name": "SHA1_RSA_PKCS",
        "mech_int": int(CKM_SHA1_RSA_PKCS),
        "expected_pass": expected_pass,
        "n": b"\x01",
        "e": b"\x01",
        "message": b"message",
        "signature": b"signature",
    }


def _pss_vec(*, expected_pass: bool = True) -> dict[str, Any]:
    return {
        "mech_name": "SHA1_RSA_PKCS_PSS",
        "mech_int": int(CKM_SHA1_RSA_PKCS_PSS),
        "hash_mech": int(CKM_SHA_1),
        "mgf": 1,
        "salt_len": 20,
        "expected_pass": expected_pass,
        "n": b"\x01",
        "e": b"\x01",
        "message": b"message",
        "signature": b"signature",
    }


def _attribute_value_invalid(*_args: Any, **_kwargs: Any) -> int:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
        int(CKR_ATTRIBUTE_VALUE_INVALID),
    )


def test_acvp_rsa_pkcs15_public_import_reject_is_setup_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_acvp_rsa, "import_rsa_public_key", _attribute_value_invalid)

    with pytest.raises(pytest.skip.Exception, match="RSA public key import failed"):
        test_acvp_rsa.TestRsaSigVer().test_rsa_pkcs15_verify(
            _session(),
            "SigVer-pkcs15-ver-SHA-1-tc181_0",
            _pkcs15_vec(),
        )


def test_acvp_rsa_pss_public_import_reject_is_setup_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_acvp_rsa, "import_rsa_public_key", _attribute_value_invalid)

    with pytest.raises(pytest.skip.Exception, match="RSA public key import failed"):
        test_acvp_rsa.TestRsaSigVer().test_rsa_pss_verify(
            _session(),
            "SigVer-pss-ver-SHA-1-tc181_0",
            _pss_vec(),
        )


def test_acvp_rsa_verify_attribute_value_invalid_is_not_setup_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_acvp_rsa, "import_rsa_public_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_acvp_rsa, "verify_single", _attribute_value_invalid)
    monkeypatch.setattr(test_acvp_rsa, "destroy_quietly", lambda *_args: None)

    with pytest.raises(CkrAssertionError):
        test_acvp_rsa.TestRsaSigVer().test_rsa_pkcs15_verify(
            _session(),
            "SigVer-pkcs15-ver-SHA-1-tc181_0",
            _pkcs15_vec(expected_pass=False),
        )
