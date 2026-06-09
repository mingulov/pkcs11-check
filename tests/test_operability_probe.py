"""Meta-tests for the effect-based mechanism operability probe (triage H2).

The probe replaces per-CKR xfail allowlists in KAT runners: a mechanism is
classified by what it DID with one canonical known-answer operation, not by
which error code a vector run happened to return.

- canonical OK + correct output  -> OPERATIONAL: vector failures stay findings
  (only spec-legal parameter-shape rejects remain xfail)
- canonical clean CKR error      -> NOT_OPERATIONAL: advertised but not
  operational, vector clean errors xfail regardless of CKR (bouncyhsm CCM
  GENERAL_ERROR == kryoptic PARAM_INVALID; no provider identity, no allowlist)
- canonical OK + wrong output    -> WRONG_OUTPUT: crypto break; never masks a
  vector failure
- canonical setup failed         -> INCONCLUSIVE: no mechanism evidence (e.g.
  the key import path is broken, see triage H6) -> legacy param-shape rules
"""

from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases._operability import (
    Operability,
    OperabilityResult,
    classify_kat_clean_error,
    probe_operability,
    reset_operability_cache,
)


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    reset_operability_cache()


def _ckr(rv: int) -> CkrAssertionError:
    return CkrAssertionError(f"Unexpected CK_RV; rv={rv}", int(rv))


OPERATIONAL = OperabilityResult(Operability.OPERATIONAL, "canonical OK")
NOT_OPERATIONAL = OperabilityResult(Operability.NOT_OPERATIONAL, "canonical CKR_GENERAL_ERROR")
WRONG_OUTPUT = OperabilityResult(Operability.WRONG_OUTPUT, "canonical ct mismatch")
INCONCLUSIVE = OperabilityResult(Operability.INCONCLUSIVE, "canonical key import failed")


def test_probe_runs_once_per_key() -> None:
    calls = 0

    def probe() -> OperabilityResult:
        nonlocal calls
        calls += 1
        return OPERATIONAL

    assert probe_operability("AES_CCM:encrypt", probe) is OPERATIONAL
    assert probe_operability("AES_CCM:encrypt", probe) is OPERATIONAL
    assert calls == 1


def test_probe_keys_are_independent() -> None:
    assert probe_operability("a", lambda: OPERATIONAL).status is Operability.OPERATIONAL
    assert probe_operability("b", lambda: NOT_OPERATIONAL).status is Operability.NOT_OPERATIONAL


def test_not_operational_xfails_any_clean_ckr() -> None:
    """bouncyhsm CCM: every vector returns GENERAL_ERROR and the canonical does
    too -> xfail without any CKR allowlist."""
    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        classify_kat_clean_error(
            _ckr(CKR_GENERAL_ERROR), result=NOT_OPERATIONAL, label="AES_CCM encrypt"
        )


def test_operational_param_shape_reject_is_xfail() -> None:
    """kryoptic CCM: canonical works, 7-byte-nonce vector cleanly rejected ->
    recorded deviation, not a hard fail."""
    with pytest.raises(pytest.xfail.Exception, match="cleanly rejected"):
        classify_kat_clean_error(
            _ckr(CKR_MECHANISM_PARAM_INVALID), result=OPERATIONAL, label="AES_CCM encrypt"
        )


def test_operational_clean_reject_is_recorded_deviation() -> None:
    """Per the classification model, a clean error on a positive op is an
    honest deviation (xfail) even when the canonical works — only wrong
    output, crashes and self-contradictions fail. (wolfpkcs11 rejects
    unaligned CTS input with ENCRYPTED_DATA_INVALID while aligned works.)"""
    with pytest.raises(pytest.xfail.Exception, match="cleanly rejected"):
        classify_kat_clean_error(
            _ckr(CKR_GENERAL_ERROR), result=OPERATIONAL, label="AES_CCM encrypt"
        )


def test_wrong_output_never_masks_vector_failures() -> None:
    """Canonical produced WRONG ciphertext: a crypto break. Vector errors must
    stay findings; nothing gets xfailed."""
    exc = _ckr(CKR_MECHANISM_PARAM_INVALID)
    with pytest.raises(CkrAssertionError):
        classify_kat_clean_error(exc, result=WRONG_OUTPUT, label="AES_GCM encrypt")


def test_inconclusive_keeps_legacy_param_shape_rules() -> None:
    """Setup failure (e.g. broken import path, H6) is not mechanism evidence:
    param-shape rejects stay xfail, other CKRs stay findings."""
    with pytest.raises(pytest.xfail.Exception):
        classify_kat_clean_error(
            _ckr(CKR_MECHANISM_PARAM_INVALID), result=INCONCLUSIVE, label="AES_CCM encrypt"
        )
    with pytest.raises(CkrAssertionError):
        classify_kat_clean_error(
            _ckr(CKR_ENCRYPTED_DATA_INVALID), result=INCONCLUSIVE, label="AES_CCM encrypt"
        )


def test_param_shape_reject_set_is_request_shape_only() -> None:
    """PARAM_SHAPE_REJECTS must contain only request-shape codes (the module
    refused the call shape), never data-verdict or generic-failure codes that
    could mask a crypto break on an operational mechanism."""
    from pkcs11_check.raw.types_std import (
        CKR_ARGUMENTS_BAD,
        CKR_DEVICE_ERROR,
        CKR_ENCRYPTED_DATA_INVALID,
        CKR_FUNCTION_FAILED,
        CKR_MECHANISM_INVALID,
    )
    from pkcs11_check.testcases._operability import PARAM_SHAPE_REJECTS

    assert CKR_MECHANISM_INVALID in PARAM_SHAPE_REJECTS
    assert CKR_MECHANISM_PARAM_INVALID in PARAM_SHAPE_REJECTS
    assert CKR_ARGUMENTS_BAD in PARAM_SHAPE_REJECTS
    for forbidden in (
        CKR_ENCRYPTED_DATA_INVALID,
        CKR_GENERAL_ERROR,
        CKR_DEVICE_ERROR,
        CKR_FUNCTION_FAILED,
    ):
        assert forbidden not in PARAM_SHAPE_REJECTS


def test_non_ckr_assertion_errors_are_reraised() -> None:
    """A plain AssertionError (harness/ctypes bug) must never be read as
    'not operational'."""
    exc = AssertionError("packing bug")
    with pytest.raises(AssertionError) as ei:
        classify_kat_clean_error(exc, result=NOT_OPERATIONAL, label="AES_CCM encrypt")
    assert ei.value is exc


def test_oaep_combo_probe_classifies_by_canonical_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H3: opencryptoki rejects valid SHA-512/224 OAEP vectors with
    ENCRYPTED_DATA_INVALID. The combo probe decrypts a cryptography-made
    canonical ciphertext: clean reject -> NOT_OPERATIONAL; round-trip ->
    OPERATIONAL (so the vector rejection stays a finding)."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    from pkcs11_check.raw.types_std import CKG_MGF1_SHA256, CKM_SHA256
    from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_oaep as oaep

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = priv.public_key().public_numbers()
    modulus = nums.n.to_bytes(256, "big")
    pub_exp = nums.e.to_bytes(3, "big")

    class _Rs:
        raw = object()
        sh = 1

    def _reject(*_a: object, **_k: object) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID", int(CKR_ENCRYPTED_DATA_INVALID)
        )

    monkeypatch.setattr(oaep, "decrypt_single", _reject)
    res = oaep._oaep_combo_probe(
        _Rs(),
        7,
        modulus=modulus,
        pub_exponent=pub_exp,
        sha="SHA-256",
        mgf_sha="SHA-256",
        hash_mech=int(CKM_SHA256),
        mgf=int(CKG_MGF1_SHA256),
    )
    assert res.status is Operability.NOT_OPERATIONAL

    def _roundtrip(
        _raw: object, _sh: int, _key: int, _mech: object, ct: bytes, **_k: object
    ) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        return priv.decrypt(
            ct,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

    monkeypatch.setattr(oaep, "decrypt_single", _roundtrip)
    res = oaep._oaep_combo_probe(
        _Rs(),
        7,
        modulus=modulus,
        pub_exponent=pub_exp,
        sha="SHA-256",
        mgf_sha="SHA-256",
        hash_mech=int(CKM_SHA256),
        mgf=int(CKG_MGF1_SHA256),
    )
    assert res.status is Operability.OPERATIONAL
