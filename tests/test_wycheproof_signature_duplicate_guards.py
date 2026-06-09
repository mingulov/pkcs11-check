"""Regression tests for Wycheproof signature vector duplicate guards."""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check.testcases.wycheproof import test_wycheproof_dsa as dsa
from pkcs11_check.testcases.wycheproof import test_wycheproof_ecdsa as ecdsa
from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa as rsa
from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_pss as rsa_pss


class _SignatureSession:
    raw = object()
    sh = 1

    def has_mechanism(self, _name: str) -> bool:
        return True


def _fail_if_called(*_args: Any, **_kwargs: Any) -> int:
    raise AssertionError("PKCS#11 import reached for duplicate signature vector")


def _find_ecdsa(vec_id: str) -> dict[str, Any]:
    return next(vec for candidate_id, vec in ecdsa._ALL_ECDSA if candidate_id == vec_id)


def _find_dsa(vec_id: str) -> dict[str, Any]:
    return next(vec for candidate_id, vec in dsa._ALL_DSA_VECTORS if candidate_id == vec_id)


def _find_rsa(vec_id: str) -> dict[str, Any]:
    return next(vec for candidate_id, vec in rsa._ALL_RSA_VECTORS if candidate_id == vec_id)


def _find_rsa_pss(vec_id: str) -> dict[str, Any]:
    return next(vec for candidate_id, vec in rsa_pss._ALL_PSS_VECTORS if candidate_id == vec_id)


def test_duplicate_ecdsa_p1363_vector_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """DER and P1363 ECDSA vectors that decode to the same raw sig run once."""
    monkeypatch.setattr(ecdsa, "import_ec_public_key_negotiated", _fail_if_called)
    vec_id = "ecdsa_brainpoolP224r1_sha224_p1363_test.json:tc183-valid"

    with pytest.raises(pytest.skip.Exception, match="Duplicate PKCS#11 ECDSA operation input"):
        ecdsa.test_ecdsa_wycheproof(_SignatureSession(), vec_id, _find_ecdsa(vec_id))


def test_ecdsa_bitcoin_policy_duplicate_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bitcoin low-S policy invalids are not PKCS#11 ECDSA raw-signature failures."""
    monkeypatch.setattr(ecdsa, "import_ec_public_key_negotiated", _fail_if_called)
    vec_id = "ecdsa_secp256k1_sha256_bitcoin_test.json:tc1-invalid"

    with pytest.raises(pytest.skip.Exception, match="Duplicate PKCS#11 ECDSA operation input"):
        ecdsa.test_ecdsa_wycheproof(_SignatureSession(), vec_id, _find_ecdsa(vec_id))


def test_ecdsa_short_p1363_signature_size_vector_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PKCS#11 v3.2 permits shorter ECDSA verify signatures than fixed P1363."""
    monkeypatch.setattr(ecdsa, "import_ec_public_key_negotiated", _fail_if_called)
    vec_id = "ecdsa_secp256r1_sha512_p1363_test.json:tc191-invalid"

    with pytest.raises(pytest.skip.Exception, match="short ECDSA signature"):
        ecdsa.test_ecdsa_wycheproof(_SignatureSession(), vec_id, _find_ecdsa(vec_id))


def test_ecdsa_p521_shake256_loader_hash_matches_valid_vector() -> None:
    """The loader's SHAKE256 length must match Wycheproof P-521 signatures."""
    vec_id = "ecdsa_secp521r1_shake256_test.json:tc1-valid"
    vec = _find_ecdsa(vec_id)
    group = vec["_group"]
    public_key = serialization.load_der_public_key(bytes.fromhex(group["publicKeyDer"]))

    try:
        public_key.verify(
            bytes.fromhex(vec["sig"]),
            bytes.fromhex(vec["msg"]),
            ec.ECDSA(hashes.SHAKE256(len(vec["_hash_fn"](b"").digest()))),
        )
    except InvalidSignature:
        pytest.fail("loader SHAKE256 length does not verify the valid Wycheproof vector")


def test_duplicate_dsa_p1363_vector_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """DER and P1363 DSA vectors that decode to the same raw sig run once."""
    monkeypatch.setattr(dsa, "import_dsa_public_key", _fail_if_called)
    vec_id = "dsa_2048_224_sha224_p1363_test.json:tc3-invalid"

    with pytest.raises(pytest.skip.Exception, match="Duplicate PKCS#11 DSA operation input"):
        dsa.test_dsa(_SignatureSession(), vec_id, _find_dsa(vec_id))


def test_dsa_der_metadata_duplicate_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid DER-only DSA encodings are not PKCS#11 raw-signature failures."""
    monkeypatch.setattr(dsa, "import_dsa_public_key", _fail_if_called)
    vec_id = "dsa_2048_224_sha224_test.json:tc3-invalid"

    with pytest.raises(pytest.skip.Exception, match="Duplicate PKCS#11 DSA operation input"):
        dsa.test_dsa(_SignatureSession(), vec_id, _find_dsa(vec_id))


def test_duplicate_rsa_pss_params_vector_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """RSA-PSS params and non-params files can encode the same PKCS#11 operation."""
    monkeypatch.setattr(rsa_pss, "import_rsa_public_key", _fail_if_called)
    vec_id = "rsa_pss_2048_sha1_mgf1_20_test.json:tc1-valid"

    with pytest.raises(pytest.skip.Exception, match="Duplicate PKCS#11 RSA-PSS operation input"):
        rsa_pss.test_rsa_pss(_SignatureSession(), vec_id, _find_rsa_pss(vec_id))


def test_duplicate_rsa_pkcs1_signature_vector_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RSA PKCS#1 sig-gen and sig-ver files can duplicate the same verify input."""
    monkeypatch.setattr(rsa, "import_rsa_public_key", _fail_if_called)
    vec_id = "rsa_signature_2048_sha256_test.json:tc1-valid"

    with pytest.raises(pytest.skip.Exception, match="Duplicate PKCS#11 RSA operation input"):
        rsa.test_rsa_wycheproof(_SignatureSession(), vec_id, _find_rsa(vec_id))
