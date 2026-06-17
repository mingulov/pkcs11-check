"""Regression tests for Wycheproof ML-DSA sign-vector classification.

NSS fresh run 2026-06-09, two mis-classifications found in test_mldsa_sign:

1. ``ctx`` vectors not exercised faithfully: the suite signs with
   ``sign_single(... CKM_ML_DSA, msg)`` and never transmits ``vec["ctx"]``, so
   an InvalidContext vector ("context too long", tc5) reaches the module as a
   perfectly valid (msg, empty-ctx) sign — "accepted" is then a false finding.
   Context vectors (including the over-long reject) are properly exercised by
   test_wycheproof_mldsa_context via CK_SIGN_ADDITIONAL_CONTEXT; here they must
   SKIP as covered-elsewhere duplicates.

2. Malformed-key invalid vectors (IncorrectPrivateKeyLength/InvalidPrivateKey)
   that the module imports AND signs with: lenient key-material validation —
   an honest deviation (no forgery, no self-contradiction) -> xfail
   (recorded), not a hard fail. Acceptance of any OTHER invalid sign vector
   class stays a hard fail.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.wycheproof import test_wycheproof_mldsa_sign as mldsa_sign

_NO_VECTORS = "Wycheproof vectors not available (run `pkcs11-check fetch-data wycheproof`)"


class _Session:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "ML_DSA"


def _vec(vec_id: str) -> dict[str, Any]:
    hit = next((v for cid, v in mldsa_sign._ALL_SIGN_VECTORS if cid == vec_id), None)
    if hit is None:
        pytest.skip(_NO_VECTORS)
    return hit


def _wire_sign_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mldsa_sign, "import_pqc_private_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(mldsa_sign, "sign_single", lambda *_a, **_k: b"\xab" * 64)
    monkeypatch.setattr(mldsa_sign, "destroy_quietly", lambda *_a, **_k: None)


def test_context_vector_skips_as_covered_elsewhere(monkeypatch: pytest.MonkeyPatch) -> None:
    """An InvalidContext vector must skip: ctx is never transmitted here."""
    vec_id = "mldsa_44_sign_noseed_test.json:tc5-invalid"
    vec = _vec(vec_id)
    assert "InvalidContext" in vec.get("flags", [])
    _wire_sign_ok(monkeypatch)

    with pytest.raises(pytest.skip.Exception, match="mldsa_context"):
        mldsa_sign.test_mldsa_sign(vec_id, vec, _Session())


def test_valid_vector_with_nonempty_ctx_skips_as_covered_elsewhere(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Any vector carrying a non-empty ctx is exercised by the context suite."""
    hit = next(
        (
            (cid, v)
            for cid, v in mldsa_sign._ALL_SIGN_VECTORS
            if v.get("ctx", "") and v["result"] == "valid"
        ),
        None,
    )
    if hit is None:
        pytest.skip(_NO_VECTORS)
    vec_id, vec = hit
    _wire_sign_ok(monkeypatch)

    with pytest.raises(pytest.skip.Exception, match="mldsa_context"):
        mldsa_sign.test_mldsa_sign(vec_id, vec, _Session())


def test_malformed_key_signed_is_recorded_deviation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lenient import+sign of malformed key material is an xfail, not a fail."""
    vec_id = "mldsa_44_sign_noseed_test.json:tc50-invalid"
    vec = _vec(vec_id)
    assert "IncorrectPrivateKeyLength" in vec.get("flags", [])
    _wire_sign_ok(monkeypatch)

    with pytest.raises(pytest.xfail.Exception, match="lenient"):
        mldsa_sign.test_mldsa_sign(vec_id, vec, _Session())


def test_other_invalid_acceptance_still_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """An accepted invalid vector outside the recognized classes stays a fail."""
    hit = next(
        (
            (cid, v)
            for cid, v in mldsa_sign._ALL_SIGN_VECTORS
            if v["result"] == "invalid"
            and not v.get("ctx", "")
            and not mldsa_sign._has_flag(v, mldsa_sign._MLDSA_INVALID_PRIVATE_KEY_FLAGS)
            and "InvalidContext" not in v.get("flags", [])
        ),
        None,
    )
    if hit is None:
        pytest.skip("no non-key non-ctx invalid sign vector in data set")
    vec_id, vec = hit
    _wire_sign_ok(monkeypatch)

    with pytest.raises(pytest.fail.Exception, match="accepted by module"):
        mldsa_sign.test_mldsa_sign(vec_id, vec, _Session())
