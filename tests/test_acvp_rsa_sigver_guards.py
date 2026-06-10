"""Regression tests for ACVP RSA SigVer valid-vector reject classification.

tpm2 fresh run 2026-06-09: ALL 27 valid SHA-1 PKCS#1 v1.5 SigVer vectors are
rejected (every invalid one correctly rejected too) — the module never
verifies any valid SHA-1 signature with an imported public key. A reject of
EVERY valid vector of a (mechanism, key-size) class is "advertised but not
operational" (classification model: xfail), not 27 per-vector findings. A
module that verifies the canonical known-valid vector but rejects another
valid vector keeps the hard fail (real selective mis-verification).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases._operability import reset_operability_cache
from pkcs11_check.testcases.acvp import test_acvp_rsa as acvp_rsa


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    reset_operability_cache()


_NO_VECTORS = "ACVP vectors not available (run `pkcs11-check fetch-data acvp`)"


class _Session:
    raw = object()
    sh = 1

    def has_mechanism(self, _name: str) -> bool:
        return True


def _valid_vectors(mech_name: str) -> list[tuple[str, dict[str, Any]]]:
    hits = [
        (vid, v)
        for vid, v in acvp_rsa._PKCS15_VER
        if v["mech_name"] == mech_name and v["expected_pass"]
    ]
    if len(hits) < 2:
        pytest.skip(_NO_VECTORS)
    return hits


def _wire(monkeypatch: pytest.MonkeyPatch, verify_fn: Any) -> None:
    monkeypatch.setattr(acvp_rsa, "import_rsa_public_key_negotiated", lambda *_a, **_k: 1)
    monkeypatch.setattr(acvp_rsa, "verify_single", verify_fn)
    monkeypatch.setattr(acvp_rsa, "destroy_quietly", lambda *_a, **_k: None)


def test_valid_reject_with_nonoperational_class_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rejecting a valid vector when the canonical valid vector also rejects = xfail."""
    vecs = _valid_vectors("SHA1_RSA_PKCS")
    vec_id, vec = vecs[1]
    _wire(monkeypatch, lambda *_a, **_k: False)

    with pytest.raises(pytest.xfail.Exception, match="not operational"):
        acvp_rsa.TestRsaSigVer().test_rsa_pkcs15_verify(_Session(), vec_id, vec)


def test_valid_reject_with_operational_class_still_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Selective mis-verification (canonical verifies, this vector not) stays a fail."""
    vecs = _valid_vectors("SHA1_RSA_PKCS")
    # Tested vector must differ from the canonical (first same-size valid vector).
    canonical_id, canonical = next(
        (vid, v) for vid, v in vecs if len(v["n"]) == len(vecs[1][1]["n"])
    )
    vec_id, vec = next(
        (vid, v) for vid, v in vecs if vid != canonical_id and len(v["n"]) == len(canonical["n"])
    )

    def _verify(_raw: Any, _sh: Any, _key: Any, _mech: Any, message: bytes, *_a: Any) -> bool:
        return message == canonical["message"]

    _wire(monkeypatch, _verify)

    with pytest.raises(pytest.fail.Exception, match="rejected VALID"):
        acvp_rsa.TestRsaSigVer().test_rsa_pkcs15_verify(_Session(), vec_id, vec)


def test_invalid_acceptance_still_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Accepting an invalid signature stays a hard fail regardless of the probe."""
    hit = next(
        ((vid, v) for vid, v in acvp_rsa._PKCS15_VER if not v["expected_pass"]),
        None,
    )
    if hit is None:
        pytest.skip(_NO_VECTORS)
    vec_id, vec = hit
    _wire(monkeypatch, lambda *_a, **_k: True)

    with pytest.raises(pytest.fail.Exception, match="ACCEPTED INVALID"):
        acvp_rsa.TestRsaSigVer().test_rsa_pkcs15_verify(_Session(), vec_id, vec)


def test_valid_reject_with_inconclusive_probe_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid-vector reject when probe is INCONCLUSIVE xfails with the inconclusive message."""
    vecs = _valid_vectors("SHA1_RSA_PKCS")
    vec_id, vec = vecs[1]

    # Make import fail so the probe returns INCONCLUSIVE, but the test-level import
    # succeeds (first call = test path, second call = probe path).
    import_calls: list[int] = [0]

    def _import(*_a: Any, **_k: Any) -> int:
        import_calls[0] += 1
        if import_calls[0] > 1:
            # probe's import attempt -- raise a CKR error to make it INCONCLUSIVE
            from pkcs11_check.raw.rv import CkrAssertionError
            from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR

            raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))
        return 1

    monkeypatch.setattr(acvp_rsa, "import_rsa_public_key_negotiated", _import)
    monkeypatch.setattr(acvp_rsa, "verify_single", lambda *_a, **_k: False)
    monkeypatch.setattr(acvp_rsa, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.xfail.Exception, match="inconclusive"):
        acvp_rsa.TestRsaSigVer().test_rsa_pkcs15_verify(_Session(), vec_id, vec)
