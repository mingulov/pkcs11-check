"""Regression tests for generic Wycheproof mechanism guards."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.config import P11TestConfig
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
)
from pkcs11_check.testcases.wycheproof import test_wycheproof as wy


class _NoMechanismSession:
    raw = object()
    sh = 1

    def __init__(self) -> None:
        self.checked: list[str] = []

    def has_mechanism(self, name: str) -> bool:
        self.checked.append(name)
        return False


def _fail_if_called(*_args: Any, **_kwargs: Any) -> int:
    raise AssertionError("PKCS#11 operation reached before mechanism guard")


_STUB_CFG = P11TestConfig(module=Path("/stub.so"), key_inject="off")


@pytest.mark.parametrize(
    ("case_factory", "method_name", "vector_factory", "expected_mechanism", "needs_cfg"),
    [
        (wy.TestAESGCMWycheproof, "test_aes_gcm", wy._load_aes_gcm_vectors, "AES_GCM", True),
        (
            wy.TestHMACSHA256Wycheproof,
            "test_hmac_sha256",
            wy._load_hmac_sha256_vectors,
            "SHA256_HMAC",
            True,
        ),
        (
            wy.TestECDSAP256Wycheproof,
            "test_ecdsa_p256_sha256_verify",
            wy._load_ecdsa_p256_vectors,
            "ECDSA",
            False,
        ),
        (
            wy.TestECDSAP384Wycheproof,
            "test_ecdsa_p384_sha384_verify",
            wy._load_ecdsa_p384_vectors,
            "ECDSA",
            False,
        ),
        (
            wy.TestAESCBCPKCS5Wycheproof,
            "test_aes_cbc_pkcs5",
            wy._load_aes_cbc_pkcs5_vectors,
            "AES_CBC_PAD",
            True,
        ),
        (
            wy.TestRSASigWycheproof,
            "test_rsa_sig_2048_sha256",
            wy._load_rsa_sig_vectors,
            "SHA256_RSA_PKCS",
            False,
        ),
    ],
)
def test_generic_wycheproof_skips_when_mechanism_missing(
    monkeypatch: pytest.MonkeyPatch,
    case_factory: Callable[[], object],
    method_name: str,
    vector_factory: Callable[[], list[dict[str, Any]]],
    expected_mechanism: str,
    needs_cfg: bool,
) -> None:
    """Missing mechanisms are capability skips, not failed vector tests."""
    monkeypatch.setattr(wy, "provision_secret_key", _fail_if_called)
    monkeypatch.setattr(wy, "import_ec_public_key_negotiated", _fail_if_called)
    monkeypatch.setattr(wy, "import_rsa_public_key_negotiated", _fail_if_called)

    session = _NoMechanismSession()
    method = getattr(case_factory(), method_name)

    with pytest.raises(pytest.skip.Exception, match="not supported"):
        if needs_cfg:
            method(session, _STUB_CFG, vector_factory()[0])
        else:
            method(session, vector_factory()[0])

    assert session.checked == [expected_mechanism]


class _EcdsaSession(_NoMechanismSession):
    def has_mechanism(self, name: str) -> bool:
        self.checked.append(name)
        return name == "ECDSA"


def test_generic_ecdsa_p384_broad_import_reject_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Batch 3b (A13): a broad P-384 import reject -> xfail (advertised but not operational).

    Reconciles the prior ``..._skips_unsupported_curve_import`` pin: ECDSA is
    advertised, so a broad import-failure CKR is no longer a capability skip.
    """

    def reject_curve(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected CKR_OK",
            int(CKR_ATTRIBUTE_VALUE_INVALID),
        )

    monkeypatch.setattr(wy, "import_ec_public_key_negotiated", reject_curve)
    monkeypatch.setattr(
        wy.pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}")
    )

    session = _EcdsaSession()
    vec = wy._load_ecdsa_p384_vectors()[0]

    with pytest.raises(pytest.xfail.Exception, match="ECDSA:key-import"):
        wy.TestECDSAP384Wycheproof().test_ecdsa_p384_sha384_verify(session, vec)

    assert session.checked == ["ECDSA"]


def test_generic_ecdsa_p384_curve_unsupported_still_skips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Batch 3b (A13): a curve-absence import CKR keeps the genuine-absence skip."""

    def reject_curve(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_CURVE_NOT_SUPPORTED; expected CKR_OK",
            int(CKR_CURVE_NOT_SUPPORTED),
        )

    monkeypatch.setattr(wy, "import_ec_public_key_negotiated", reject_curve)

    session = _EcdsaSession()
    vec = wy._load_ecdsa_p384_vectors()[0]

    with pytest.raises(pytest.skip.Exception, match="Cannot import EC public key on this module"):
        wy.TestECDSAP384Wycheproof().test_ecdsa_p384_sha384_verify(session, vec)

    assert session.checked == ["ECDSA"]


@pytest.mark.parametrize(
    ("rv", "operation"),
    [
        (CKR_GENERAL_ERROR, "AES-GCM decrypt"),
        (CKR_GENERAL_ERROR, "AES-CBC-PAD decrypt"),
        (CKR_GENERAL_ERROR, "HMAC-SHA256 sign"),
        (CKR_ARGUMENTS_BAD, "RSA PKCS#1 verify"),
        (CKR_DEVICE_ERROR, "RSA PKCS#1 verify"),
    ],
)
def test_generic_wycheproof_valid_runtime_rejects_are_xfail(
    rv: int,
    operation: str,
) -> None:
    """Advertised generic Wycheproof operation rejects are findings."""
    exc = CkrAssertionError("Unexpected CK_RV", int(rv))

    with pytest.raises(pytest.xfail.Exception, match=operation):
        wy._xfail_if_generic_runtime_reject(exc, "tc1-valid", operation)


def test_generic_hmac_key_import_reject_is_xfail() -> None:
    """Advertised HMAC key import rejection is setup evidence, not a raw failure."""
    exc = CkrAssertionError("Unexpected CK_RV", int(CKR_KEY_SIZE_RANGE))

    with pytest.raises(pytest.xfail.Exception, match="HMAC-SHA256 key import"):
        wy._xfail_if_generic_runtime_reject(exc, "tc163-valid", "HMAC-SHA256 key import")
