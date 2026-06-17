"""Regression tests for ACVP KeyGen duplicate guards."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.acvp import (
    test_acvp_ecdsa,
    test_acvp_eddsa,
    test_acvp_mldsa,
    test_acvp_mlkem,
    test_acvp_rsa_keygen,
)


class _KeygenSession:
    raw = object()
    sh = 1
    slot_id = 0

    def has_mechanism(self, _name: str) -> bool:
        return True


@pytest.fixture(autouse=True)
def _advertise_keygen_in_range(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the new ACVP key-size gate in range for the duplicate-skip path.

    The duplicate guard must fire (the second same-size/curve vector is skipped)
    regardless of the advertised range, so the size gate is made to pass through
    with a wide [192, 16384] range covering every RSA modulus and EC field size
    these vectors use; the stub C_GetMechanismInfo would otherwise short-circuit.
    """

    def _fake(_raw: object, _slot: int, _mech: int) -> dict[str, int]:
        return {"min_key_size": 192, "max_key_size": 16384, "flags": 0}

    monkeypatch.setattr("pkcs11_check.raw.recipes.get_mechanism_info", _fake)


def _fail_if_called(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
    raise AssertionError("PKCS#11 key generation reached for duplicate ACVP KeyGen vector")


def _find(vectors: list[tuple[str, dict[str, Any]]], vec_id: str) -> dict[str, Any]:
    return next(vec for candidate_id, vec in vectors if candidate_id == vec_id)


def test_duplicate_rsa_keygen_vector_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """ACVP RSA KeyGen seeds are not PKCS#11 inputs; repeated sizes run once."""
    monkeypatch.setattr(test_acvp_rsa_keygen, "gen_rsa_keypair", _fail_if_called)
    vec_id = "FIPS186-4-2048-tc2"

    with pytest.raises(pytest.skip.Exception, match="Duplicate ACVP RSA KeyGen input"):
        test_acvp_rsa_keygen.TestRsaKeyGen().test_rsa_keygen_basic(
            _KeygenSession(),
            vec_id,
            _find(test_acvp_rsa_keygen._RSA_KEYGEN_VECTORS, vec_id),
        )


def test_duplicate_ecdsa_keygen_vector_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """ACVP ECDSA KeyGen seeds are not PKCS#11 inputs; repeated curves run once."""
    monkeypatch.setattr(test_acvp_ecdsa, "gen_ec_keypair", _fail_if_called)
    vec_id = "ECDSA-KeyGen-P-256-tc8"

    with pytest.raises(pytest.skip.Exception, match="Duplicate ACVP ECDSA KeyGen input"):
        test_acvp_ecdsa.TestEcdsaKeyGen().test_ecdsa_keygen(
            _KeygenSession(),
            vec_id,
            _find(test_acvp_ecdsa._ECDSA_KEYGEN_VECTORS, vec_id),
        )


def test_duplicate_eddsa_keygen_vector_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """ACVP EdDSA KeyGen seeds are not PKCS#11 inputs; repeated curves run once."""
    monkeypatch.setattr(test_acvp_eddsa, "gen_keypair", _fail_if_called)
    vec_id = "EDDSA-KeyGen-ED-25519-tc2"

    with pytest.raises(pytest.skip.Exception, match="Duplicate ACVP EdDSA KeyGen input"):
        test_acvp_eddsa.TestEdDsaKeyGen().test_eddsa_keygen(
            _KeygenSession(),
            vec_id,
            _find(test_acvp_eddsa._KEYGEN_VECTORS, vec_id),
        )


def test_duplicate_mldsa_keygen_vector_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """ACVP ML-DSA KeyGen seeds are not PKCS#11 inputs; repeated sets run once."""
    monkeypatch.setattr(test_acvp_mldsa, "gen_keypair", _fail_if_called)
    vec_id = "ML-DSA-keyGen-ML-DSA-44-tc2"

    with pytest.raises(pytest.skip.Exception, match="Duplicate ACVP ML-DSA KeyGen input"):
        test_acvp_mldsa.TestMlDsaKeyGen().test_mldsa_keygen(
            _KeygenSession(),
            vec_id,
            _find(test_acvp_mldsa._KEYGEN_VECTORS, vec_id),
        )


def test_duplicate_mlkem_keygen_vector_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """ACVP ML-KEM KeyGen seeds are not PKCS#11 inputs; repeated sets run once."""
    monkeypatch.setattr(test_acvp_mlkem, "gen_keypair", _fail_if_called)
    vec_id = "ML-KEM-keyGen-ML-KEM-512-tc2"

    with pytest.raises(pytest.skip.Exception, match="Duplicate ACVP ML-KEM KeyGen input"):
        test_acvp_mlkem.TestMlKemKeyGen().test_mlkem_keygen(
            _KeygenSession(),
            vec_id,
            _find(test_acvp_mlkem._KEYGEN_VECTORS, vec_id),
        )
