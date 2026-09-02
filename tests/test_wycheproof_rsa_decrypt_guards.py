"""Behavioral guards for Wycheproof RSA decrypt / RSA-OAEP invalid-vector rejection.

Phase-2 V2/Task 2k (investigate): both RSA PKCS#1 v1.5 decrypt and RSA-OAEP
already decrypt the supplied ciphertext and fail on accept of an invalid
(Bleichenbacher/Manger oracle surface) vector. These guards lock in that
accept->fail behavior behaviorally, not just by source-string hygiene.

A12 (import-skip-audit.md) guards (added in the A12 fix commit): the
not-advertised gate skips; advertised + broad-CKR exhaustion -> xfail; non-CKR
propagates; cached key-size early-exit xfails (not skips).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases.wycheproof import (
    test_wycheproof_rsa_decrypt as rsa_dec,
)
from pkcs11_check.testcases.wycheproof import (
    test_wycheproof_rsa_oaep as rsa_oaep,
)

# ---------------------------------------------------------------------------
# Shared CKR fixtures (A12 meta-tests)
# ---------------------------------------------------------------------------

_ATTR_INVALID = CkrAssertionError(
    "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID", int(CKR_ATTRIBUTE_VALUE_INVALID)
)
_KEY_SIZE_RANGE = CkrAssertionError("Unexpected CK_RV CKR_KEY_SIZE_RANGE", int(CKR_KEY_SIZE_RANGE))
_TEMPLATE_INCONS = CkrAssertionError(
    "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT", int(CKR_TEMPLATE_INCONSISTENT)
)
_NON_CKR_WITH_CKR_TEXT = AssertionError("ctypes mismatch after CKR_ENCRYPTED_DATA_INVALID")


def _handle(*_args: Any, **_kwargs: Any) -> int:
    return 1


def _raiser(exc: BaseException) -> Any:
    def _raise(*_a: Any, **_kw: Any) -> Any:
        raise exc

    return _raise


class _RsaPkcsSession:
    """Session stub that advertises RSA_PKCS (for A12 decrypt test tests)."""

    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "RSA_PKCS"

    def has_mechanism_flag(self, mech: str | int, _flag: int) -> bool:
        return mech == "RSA_PKCS"


class _RsaOaepSession:
    """Session stub that advertises RSA_PKCS_OAEP (for OAEP tests)."""

    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "RSA_PKCS_OAEP"

    def has_mechanism_flag(self, mech: str | int, _flag: int) -> bool:
        return mech == "RSA_PKCS_OAEP"


class _RsaNoneSession:
    """Session stub that advertises NEITHER RSA_PKCS nor RSA_PKCS_OAEP."""

    raw = object()
    sh = 1

    def has_mechanism(self, _name: str) -> bool:
        return False

    def has_mechanism_flag(self, _mech: str | int, _flag: int) -> bool:
        return False


def _first_invalid_pkcs1() -> tuple[str, dict[str, Any]]:
    hit = next(
        ((vid, v) for vid, v in rsa_dec._ALL_DECRYPT_VECTORS if v["result"] == "invalid"), None
    )
    if hit is None:
        pytest.skip("Wycheproof RSA decrypt vectors not available (run `fetch-data wycheproof`)")
    return hit


def _first_valid_pkcs1() -> tuple[str, dict[str, Any]]:
    hit = next(
        (
            (vid, v)
            for vid, v in rsa_dec._ALL_DECRYPT_VECTORS
            if v["result"] == "valid" and v["_group"].get("privateKey", {}).get("modulus")
        ),
        None,
    )
    if hit is None:
        pytest.skip("Wycheproof RSA decrypt vectors not available (run `fetch-data wycheproof`)")
    return hit


# ===========================================================================
# A12 Gate: not-advertised -> skip (new gate must exist)
# ===========================================================================


def test_a12_gate_not_advertised_skips() -> None:
    """A12: RSA_PKCS not advertised -> test skips via the new has_mechanism gate.

    Hard-pin: the gate must exist. If the test proceeds instead of skipping,
    the gate is absent -- regression.
    """
    vec_id, vec = _first_valid_pkcs1()
    with pytest.raises(pytest.skip.Exception, match="RSA_PKCS not supported"):
        rsa_dec.test_rsa_pkcs1_decrypt(_RsaNoneSession(), None, vec_id, vec)


# ===========================================================================
# A12 Import helper: broad CKR -> xfail, non-CKR propagates
# ===========================================================================


def test_a12_import_helper_xfails_on_broad_ckr() -> None:
    """A12: the import helper xfails 'advertised but not operational' on broad CKR.

    Hard-pin: an unexpected skip escaping instead of an xfail is a regression.
    """
    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            rsa_dec._skip_or_xfail_rsa_pkcs1_private_import_reject(_ATTR_INVALID, 2048)
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_a12_import_helper_xfail_carries_probe_key() -> None:
    """A12: the xfail wording carries the RSA_PKCS:key-import probe key."""
    try:
        with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS:key-import"):
            rsa_dec._skip_or_xfail_rsa_pkcs1_private_import_reject(_TEMPLATE_INCONS, 3072)
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_a12_import_helper_propagates_non_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A12 negative pin: a non-CKR AssertionError from the negotiated importer propagates.

    Driven through the real test function so the helper's terminal ``raise`` runs
    inside an active ``except`` block (the established convention -- mirrors A11).
    """
    rsa_dec._UNSUPPORTED_RSA_KEY_SIZES.clear()
    vec_id, vec = _first_valid_pkcs1()
    monkeypatch.setattr(rsa_dec, "provision_rsa_private_key", _raiser(_NON_CKR_WITH_CKR_TEXT))

    try:
        with pytest.raises(AssertionError, match="ctypes mismatch"):
            rsa_dec.test_rsa_pkcs1_decrypt(_RsaPkcsSession(), None, vec_id, vec)
    finally:
        rsa_dec._UNSUPPORTED_RSA_KEY_SIZES.clear()


# ===========================================================================
# A12 Real function: advertised + broad CKR -> xfail; non-CKR propagates
# ===========================================================================


def test_a12_real_function_xfails_on_broad_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A12: the real test_rsa_pkcs1_decrypt xfails when negotiated import is rejected.

    Hard-pin: an unexpected skip escaping instead of an xfail is a regression.
    """
    rsa_dec._UNSUPPORTED_RSA_KEY_SIZES.clear()
    vec_id, vec = _first_valid_pkcs1()
    monkeypatch.setattr(rsa_dec, "provision_rsa_private_key", _raiser(_KEY_SIZE_RANGE))
    monkeypatch.setattr(
        rsa_dec.pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}")
    )

    try:
        with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS:key-import"):
            rsa_dec.test_rsa_pkcs1_decrypt(_RsaPkcsSession(), None, vec_id, vec)
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")
    finally:
        rsa_dec._UNSUPPORTED_RSA_KEY_SIZES.clear()


def test_a12_real_function_propagates_non_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A12 negative pin: a non-CKR AssertionError from the negotiated importer propagates."""
    rsa_dec._UNSUPPORTED_RSA_KEY_SIZES.clear()
    vec_id, vec = _first_valid_pkcs1()
    monkeypatch.setattr(rsa_dec, "provision_rsa_private_key", _raiser(_NON_CKR_WITH_CKR_TEXT))

    try:
        with pytest.raises(AssertionError, match="ctypes mismatch"):
            rsa_dec.test_rsa_pkcs1_decrypt(_RsaPkcsSession(), None, vec_id, vec)
    finally:
        rsa_dec._UNSUPPORTED_RSA_KEY_SIZES.clear()


# ===========================================================================
# A12 Cached key-size: early exit must xfail, not skip
# ===========================================================================


def test_a12_cached_keysize_early_exit_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A12: the cached unsupported-key-size early exit xfails (was skip before fix).

    A broad import reject populates _UNSUPPORTED_RSA_KEY_SIZES; the next vector
    of that size short-circuits. That early-exit must carry the same
    advertised-but-not-operational xfail, not a capability skip.
    """
    vec_id, vec = _first_valid_pkcs1()
    modulus = rsa_dec.pkcs11_bigint_from_hex(vec["_group"]["privateKey"]["modulus"])
    key_bits = len(modulus) * 8
    rsa_dec._UNSUPPORTED_RSA_KEY_SIZES.clear()
    rsa_dec._UNSUPPORTED_RSA_KEY_SIZES.add(key_bits)
    monkeypatch.setattr(
        rsa_dec.pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}")
    )

    try:
        with pytest.raises(pytest.xfail.Exception, match="not operational \\(cached\\)"):
            rsa_dec.test_rsa_pkcs1_decrypt(_RsaPkcsSession(), None, vec_id, vec)
    finally:
        rsa_dec._UNSUPPORTED_RSA_KEY_SIZES.clear()


# ===========================================================================
# Original guards (Bleichenbacher/Manger oracle surface) -- retargeted to
# import_rsa_private_key_negotiated (A12 swap) and _RsaPkcsSession
# ===========================================================================


def test_rsa_pkcs1_invalid_padding_bypass_returns_real_msg_is_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The REAL Bleichenbacher-class break: a module that returns the actual
    target message for an invalid-padding ciphertext bypassed the padding
    check -> fail. (Each invalid Wycheproof vector carries the target msg.)"""
    vec_id, vec = _first_invalid_pkcs1()
    monkeypatch.setattr(rsa_dec, "provision_rsa_private_key", _handle)
    monkeypatch.setattr(rsa_dec, "decrypt_single", lambda *_a, **_k: bytes.fromhex(vec["msg"]))
    monkeypatch.setattr(rsa_dec, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="recovered the target message"):
        rsa_dec.test_rsa_pkcs1_decrypt(_RsaPkcsSession(), None, vec_id, vec)


def test_rsa_pkcs1_invalid_synthetic_plaintext_is_secure_not_a_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Returning a SYNTHETIC plaintext (!= target msg) for invalid padding is the
    recommended anti-Bleichenbacher mitigation (RFC 8017 §7.2.2 / Marvin 2023),
    NOT a finding. Every real provider (softhsm2/kryoptic/NSS) does this; the old
    'any decrypt-success -> fail' guard wrongly penalized the secure behavior."""
    vec_id, vec = _first_invalid_pkcs1()
    synthetic = b"\x00" + b"\xa5" * 31  # != bytes.fromhex(vec["msg"])
    assert synthetic != bytes.fromhex(vec["msg"])
    monkeypatch.setattr(rsa_dec, "provision_rsa_private_key", _handle)
    monkeypatch.setattr(rsa_dec, "decrypt_single", lambda *_a, **_k: synthetic)
    monkeypatch.setattr(rsa_dec, "destroy_quietly", lambda *_a: None)

    # No exception: secure non-rejection is accepted.
    rsa_dec.test_rsa_pkcs1_decrypt(_RsaPkcsSession(), None, vec_id, vec)


def test_rsa_pkcs1_invalid_clean_rejection_is_secure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A constant-time clean rejection of invalid padding is also acceptable."""
    vec_id, vec = _first_invalid_pkcs1()
    monkeypatch.setattr(rsa_dec, "provision_rsa_private_key", _handle)

    def _reject(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID", int(CKR_ENCRYPTED_DATA_INVALID)
        )

    monkeypatch.setattr(rsa_dec, "decrypt_single", _reject)
    monkeypatch.setattr(rsa_dec, "destroy_quietly", lambda *_a: None)

    rsa_dec.test_rsa_pkcs1_decrypt(_RsaPkcsSession(), None, vec_id, vec)  # no exception


def _first_invalid_oaep() -> tuple[str, dict[str, Any]]:
    hit = next(
        ((vid, v) for vid, v in rsa_oaep._ALL_OAEP_VECTORS if v["result"] == "invalid"), None
    )
    if hit is None:
        pytest.skip(
            "Wycheproof RSA-OAEP vectors not available (run `pkcs11-check fetch-data wycheproof`)"
        )
    return hit


def _run_negative_reject(
    module: Any,
    session: Any,
    vec_id: str,
    vec: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    exc: BaseException,
) -> None:
    monkeypatch.setattr(module, "provision_rsa_private_key", _handle)
    monkeypatch.setattr(module, "decrypt_single", _raiser(exc))
    monkeypatch.setattr(module, "destroy_quietly", lambda *_a: None)
    if module is rsa_dec:
        module.test_rsa_pkcs1_decrypt(session, None, vec_id, vec)
    else:
        module.test_rsa_oaep(session, None, vec_id, vec)


@pytest.mark.parametrize(
    ("module", "session", "vector"),
    [
        (rsa_dec, _RsaPkcsSession(), _first_invalid_pkcs1),
        (rsa_oaep, _RsaOaepSession(), _first_invalid_oaep),
    ],
    ids=["pkcs1", "oaep"],
)
@pytest.mark.parametrize("rv", [CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE])
def test_rsa_negative_expected_rejects_are_accepted(
    module: Any,
    session: Any,
    vector: Any,
    rv: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Padding-invalid vectors accept both PKCS#11 encrypted-data rejects."""
    vec_id, vec = vector()
    _run_negative_reject(
        module,
        session,
        vec_id,
        vec,
        monkeypatch,
        CkrAssertionError(f"Unexpected CK_RV {int(rv):#x}", int(rv)),
    )


@pytest.mark.parametrize(
    ("module", "session", "vector"),
    [
        (rsa_dec, _RsaPkcsSession(), _first_invalid_pkcs1),
        (rsa_oaep, _RsaOaepSession(), _first_invalid_oaep),
    ],
    ids=["pkcs1", "oaep"],
)
@pytest.mark.parametrize("rv", [CKR_DEVICE_ERROR, CKR_GENERAL_ERROR, CKR_VENDOR_DEFINED + 1])
def test_rsa_negative_unexpected_clean_rejects_are_visible_xfails(
    module: Any,
    session: Any,
    vector: Any,
    rv: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A clean but non-spec reject is visible as nonspec_reject, not a pass."""
    vec_id, vec = vector()
    with pytest.raises(pytest.xfail.Exception, match="expected"):
        _run_negative_reject(
            module,
            session,
            vec_id,
            vec,
            monkeypatch,
            CkrAssertionError(f"Unexpected CK_RV {int(rv):#x}", int(rv)),
        )


@pytest.mark.parametrize(
    ("module", "session", "vector"),
    [
        (rsa_dec, _RsaPkcsSession(), _first_invalid_pkcs1),
        (rsa_oaep, _RsaOaepSession(), _first_invalid_oaep),
    ],
    ids=["pkcs1", "oaep"],
)
def test_rsa_negative_undefined_ckr_is_hard_failure(
    module: Any,
    session: Any,
    vector: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A return value outside the CK_RV enum is a provider contract failure."""
    vec_id, vec = vector()
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        _run_negative_reject(
            module,
            session,
            vec_id,
            vec,
            monkeypatch,
            CkrAssertionError("Unexpected CK_RV 0x7fffffff", 0x7FFFFFFF),
        )


@pytest.mark.parametrize(
    ("module", "session", "vector"),
    [
        (rsa_dec, _RsaPkcsSession(), _first_invalid_pkcs1),
        (rsa_oaep, _RsaOaepSession(), _first_invalid_oaep),
    ],
    ids=["pkcs1", "oaep"],
)
def test_rsa_negative_non_ckr_is_hard_failure(
    module: Any,
    session: Any,
    vector: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Python/FFI assertion cannot be downgraded by negative-vector routing."""
    vec_id, vec = vector()
    with pytest.raises(AssertionError, match="ctypes mismatch"):
        _run_negative_reject(
            module,
            session,
            vec_id,
            vec,
            monkeypatch,
            _NON_CKR_WITH_CKR_TEXT,
        )


def test_rsa_oaep_acceptable_wrong_plaintext_is_wrong_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An OAEP vector marked acceptable still has an exact expected plaintext."""
    vec_id, vec = next(
        ((vid, v) for vid, v in rsa_oaep._ALL_OAEP_VECTORS if v["result"] == "acceptable"),
        (None, None),
    )
    if vec_id is None or vec is None:
        pytest.skip("Wycheproof RSA-OAEP acceptable vectors not available")
    expected = bytes.fromhex(vec["msg"])
    wrong = b"\x00" * len(expected)
    assert wrong != expected
    monkeypatch.setattr(rsa_oaep, "provision_rsa_private_key", _handle)
    monkeypatch.setattr(rsa_oaep, "decrypt_single", lambda *_a, **_k: wrong)
    monkeypatch.setattr(rsa_oaep, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="output does not match"):
        rsa_oaep.test_rsa_oaep(_RsaOaepSession(), None, vec_id, vec)


def test_rsa_oaep_invalid_ciphertext_decrypt_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid RSA-OAEP ciphertext that decrypts must fail (Manger oracle break)."""
    hit = next(
        ((vid, v) for vid, v in rsa_oaep._ALL_OAEP_VECTORS if v["result"] == "invalid"), None
    )
    if hit is None:
        pytest.skip(
            "Wycheproof RSA-OAEP vectors not available (run `pkcs11-check fetch-data wycheproof`)"
        )
    vec_id, vec = hit
    monkeypatch.setattr(rsa_oaep, "provision_rsa_private_key", _handle)
    monkeypatch.setattr(rsa_oaep, "decrypt_single", lambda *_a, **_k: b"\x00recovered")
    monkeypatch.setattr(rsa_oaep, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid ciphertext"):
        rsa_oaep.test_rsa_oaep(_RsaOaepSession(), None, vec_id, vec)
