"""Regression tests for RSA-PSS invalid-vector acceptance classification.

Wycheproof PSS "invalid" vectors split into two very different acceptance
classes (tpm2 fresh run 2026-06-09):

- ``s_len changed to N`` (flag ``ModifiedSignature``): a GENUINE signature
  produced with the private key, just with a different salt length than the
  declared ``sLen`` parameter. A verifier that recovers the salt from the
  signature (RFC 8017 verification with auto salt) accepts it. Not forgeable
  without the private key -> honest policy deviation -> xfail (recorded).
- everything else (e.g. ``all bits in m_hash flipped``): acceptance means the
  padding/hash check was bypassed -> Type-A crypto break -> fail.

The discriminator is a reference RSA-PSS verification with auto salt length
(public-key math, no provider involved): only the first class passes it.

Also covers CKR_OPERATION_ACTIVE collateral classification: a provider that
leaks a stale verify operation after a reject (spec violation, reported as a
FAIL by test_operation_termination.py) poisons the NEXT vector's C_VerifyInit;
that collateral is a clean non-signature-evaluating reject -> xfail, never a
hard fail attributed to the innocent vector.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_OPERATION_ACTIVE
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_pss as pss
from pkcs11_check.testcases.wycheproof._key_decoders import pkcs11_bigint_from_hex

_NO_VECTORS = "Wycheproof vectors not available (run `pkcs11-check fetch-data wycheproof`)"

_RESALTED_VEC_ID = "rsa_pss_2048_sha256_mgf1_32_params_test.json:tc67-invalid"
_GARBAGE_VEC_ID = "rsa_pss_2048_sha256_mgf1_32_params_test.json:tc66-invalid"


class _PssSession:
    raw = object()
    sh = 1

    def has_mechanism(self, _name: str) -> bool:
        return True


def _vec(vec_id: str) -> dict[str, Any]:
    hit = next((v for cid, v in pss._ALL_PSS_VECTORS if cid == vec_id), None)
    if hit is None:
        pytest.skip(_NO_VECTORS)
    return hit


def _wire_verify(monkeypatch: pytest.MonkeyPatch, outcome: Any) -> None:
    def _verify(*_a: Any, **_k: Any) -> bool:
        if isinstance(outcome, BaseException):
            raise outcome
        return bool(outcome)

    monkeypatch.setattr(pss, "import_rsa_public_key_negotiated", lambda *_a, **_k: 1)
    monkeypatch.setattr(pss, "verify_single", _verify)
    monkeypatch.setattr(pss, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(pss, "generate_random", lambda *_a, **_k: b"")
    monkeypatch.setattr(pss, "_UNSUPPORTED_RSA_KEY_SIZES", set())


def _reference_args(vec: dict[str, Any]) -> tuple[bytes, bytes, bytes, bytes, str, str]:
    pk = vec["_group"]["publicKey"]
    return (
        pkcs11_bigint_from_hex(pk["modulus"]),
        pkcs11_bigint_from_hex(pk["publicExponent"]),
        bytes.fromhex(vec["msg"]),
        bytes.fromhex(vec["sig"]),
        vec["_sha"],
        vec["_mgf_sha"],
    )


def test_auto_salt_reference_confirms_resalted_vector() -> None:
    """The s_len-variant vector IS a genuine signature under auto-salt PSS."""
    vec = _vec(_RESALTED_VEC_ID)
    assert vec.get("comment", "").startswith("s_len changed")
    assert pss._pss_valid_under_auto_salt(*_reference_args(vec)) is True


def test_auto_salt_reference_rejects_garbage_vector() -> None:
    """The m_hash-flip vector is NOT a genuine signature under any salt."""
    vec = _vec(_GARBAGE_VEC_ID)
    assert "m_hash" in vec.get("comment", "")
    assert pss._pss_valid_under_auto_salt(*_reference_args(vec)) is False


def test_accepted_resalted_signature_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Accepting a re-salted genuine signature is a recorded deviation (xfail)."""
    vec = _vec(_RESALTED_VEC_ID)
    _wire_verify(monkeypatch, True)
    with pytest.raises(pytest.xfail.Exception, match="salt length"):
        pss.test_rsa_pss(_PssSession(), _RESALTED_VEC_ID, vec)


def test_accepted_garbage_signature_still_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Accepting a non-genuine invalid signature stays a hard Type-A fail."""
    vec = _vec(_GARBAGE_VEC_ID)
    _wire_verify(monkeypatch, True)
    with pytest.raises(pytest.fail.Exception, match="accepted by module"):
        pss.test_rsa_pss(_PssSession(), _GARBAGE_VEC_ID, vec)


def test_operation_active_on_invalid_vector_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stale-op collateral on an invalid vector is xfail, not a hard fail."""
    vec = _vec(_GARBAGE_VEC_ID)
    _wire_verify(
        monkeypatch,
        CkrAssertionError("Unexpected CK_RV CKR_OPERATION_ACTIVE", int(CKR_OPERATION_ACTIVE)),
    )
    with pytest.raises(pytest.xfail.Exception, match="CKR_OPERATION_ACTIVE"):
        pss.test_rsa_pss(_PssSession(), _GARBAGE_VEC_ID, vec)


def test_operation_active_is_non_clean_signature_reject() -> None:
    """Shared policy: CKR_OPERATION_ACTIVE classifies as non-clean xfail."""
    exc = CkrAssertionError("Unexpected CK_RV CKR_OPERATION_ACTIVE", int(CKR_OPERATION_ACTIVE))
    with pytest.raises(pytest.xfail.Exception, match="CKR_OPERATION_ACTIVE"):
        signature_rejected_or_xfail(exc, "tc-invalid")
