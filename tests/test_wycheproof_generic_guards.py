"""Regression tests for generic Wycheproof mechanism guards."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

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


@pytest.mark.parametrize(
    ("case_factory", "method_name", "vector_factory", "expected_mechanism"),
    [
        (wy.TestAESGCMWycheproof, "test_aes_gcm", wy._load_aes_gcm_vectors, "AES_GCM"),
        (
            wy.TestHMACSHA256Wycheproof,
            "test_hmac_sha256",
            wy._load_hmac_sha256_vectors,
            "SHA256_HMAC",
        ),
        (
            wy.TestECDSAP256Wycheproof,
            "test_ecdsa_p256_sha256_verify",
            wy._load_ecdsa_p256_vectors,
            "ECDSA",
        ),
        (
            wy.TestECDSAP384Wycheproof,
            "test_ecdsa_p384_sha384_verify",
            wy._load_ecdsa_p384_vectors,
            "ECDSA",
        ),
        (
            wy.TestAESCBCPKCS5Wycheproof,
            "test_aes_cbc_pkcs5",
            wy._load_aes_cbc_pkcs5_vectors,
            "AES_CBC_PAD",
        ),
        (
            wy.TestRSASigWycheproof,
            "test_rsa_sig_2048_sha256",
            wy._load_rsa_sig_vectors,
            "SHA256_RSA_PKCS",
        ),
    ],
)
def test_generic_wycheproof_skips_when_mechanism_missing(
    monkeypatch: pytest.MonkeyPatch,
    case_factory: Callable[[], object],
    method_name: str,
    vector_factory: Callable[[], list[dict[str, Any]]],
    expected_mechanism: str,
) -> None:
    """Missing mechanisms are capability skips, not failed vector tests."""
    monkeypatch.setattr(wy, "import_secret_key", _fail_if_called)
    monkeypatch.setattr(wy, "import_ec_public_key", _fail_if_called)
    monkeypatch.setattr(wy, "import_rsa_public_key", _fail_if_called)

    session = _NoMechanismSession()
    method = getattr(case_factory(), method_name)

    with pytest.raises(pytest.skip.Exception, match="not supported"):
        method(session, vector_factory()[0])

    assert session.checked == [expected_mechanism]


def test_generic_ecdsa_p384_skips_unsupported_curve_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P-384 import rejection is an unsupported-curve skip, not a vector failure."""

    class _EcdsaSession(_NoMechanismSession):
        def has_mechanism(self, name: str) -> bool:
            self.checked.append(name)
            return name == "ECDSA"

    def reject_curve(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected CKR_OK")

    monkeypatch.setattr(wy, "import_ec_public_key", reject_curve)

    session = _EcdsaSession()
    vec = wy._load_ecdsa_p384_vectors()[0]

    with pytest.raises(pytest.skip.Exception, match="Cannot import EC public key"):
        wy.TestECDSAP384Wycheproof().test_ecdsa_p384_sha384_verify(session, vec)

    assert session.checked == ["ECDSA"]
