"""Meta-tests: invalid-vector rejections on NOT_OPERATIONAL mechanisms xfail.

bouncyhsm CCM records thousands of invalid-vector "passes" while its decrypt
refuses every valid vector; those rejections are vacuous (the input was never
evaluated -- the module refuses everything). Counting them as pass asserts
conformance that was never tested (gap-analysis leak 1, Denis-endorsed
downgrade). The downgrade must fire ONLY on a NOT_OPERATIONAL canonical probe
verdict; OPERATIONAL rejections stay genuine passes and INCONCLUSIVE (staging
failure, no mechanism evidence) keeps legacy pass.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_GENERAL_ERROR,
    CKR_SIGNATURE_INVALID,
)
from pkcs11_check.testcases._operability import reset_operability_cache
from pkcs11_check.testcases.acvp import test_acvp_rsa as rsa
from pkcs11_check.testcases.acvp.aes import base_runner_aead as aead
from pkcs11_check.testcases.acvp.aes import test_wrap as wrap
from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_pss as pss


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    reset_operability_cache()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(), sh=1, has_mechanism=lambda name: True, has_mechanism_flag=lambda _m, _f: True
    )


def _vec_invalid_gcm() -> dict[str, Any]:
    return {
        "tag_len_bits": 128,
        "iv": b"\x00" * 12,
        "aad": b"",
        "ct": b"\x00" * 16,
        "tag": b"\x00" * 16,
        "key": b"\x00" * 16,
        "pt_expected": b"",
        "test_passed": False,
    }


# --- GCM (base_runner_aead) -------------------------------------------------


def _wire_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both the vector decrypt and the canonical probe refuse -> NOT_OPERATIONAL.

    The reject code must be in ``_GCM_DATA_REJECTS`` so the vector enters the
    invalid-tag reject branch (the path Task 8 downgrades); the same clean
    rejection makes the canonical probe NOT_OPERATIONAL.
    """

    def refuse(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID", int(CKR_ENCRYPTED_DATA_INVALID)
        )

    monkeypatch.setattr(aead, "_import_aes_key", lambda *a, **k: 7)
    monkeypatch.setattr(aead, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(aead, "decrypt_single", refuse)


def test_gcm_invalid_reject_on_dead_mech_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire_not_operational(monkeypatch)  # canonical probe also refuses -> NOT_OPERATIONAL
    with pytest.raises(pytest.xfail.Exception, match="vacuous reject"):
        aead.run_gcm_decrypt_test(_rs(), "tc-inv", _vec_invalid_gcm())


def test_gcm_invalid_reject_on_live_mech_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """OPERATIONAL mechanism rejecting an invalid tag stays a genuine pass.

    Discriminates probe vs. vector by ciphertext equality: the canonical probe
    uses ``_probe_expected_ct`` output; the test vector uses a different ct+tag
    blob (all-zeros).  ``encrypt_single`` is not patched because
    ``_canonical_aead_probe`` in the decrypt direction never calls it.
    """
    probe_ct = aead._probe_expected_ct("AES_GCM")

    def reject_vector_return_probe(
        _raw: Any, _sh: int, _key: int, _mech: Any, _ct: bytes, **_kw: Any
    ) -> bytes:
        if _ct == probe_ct:
            # canonical probe ciphertext -> OPERATIONAL
            return aead.PROBE_PT
        # vector ciphertext (all-zeros ct+tag) -> reject
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID", int(CKR_ENCRYPTED_DATA_INVALID)
        )

    monkeypatch.setattr(aead, "_import_aes_key", lambda *a, **k: 7)
    monkeypatch.setattr(aead, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(aead, "decrypt_single", reject_vector_return_probe)
    # returns normally (no xfail) = PASS
    aead.run_gcm_decrypt_test(_rs(), "tc-inv", _vec_invalid_gcm())


# --- CCM (base_runner_aead) -------------------------------------------------


def _vec_invalid_ccm() -> dict[str, Any]:
    """Minimal invalid CCM decrypt vector (test_passed=False, tag_len=16)."""
    return {
        "nonce": b"\x00" * 13,
        "aad": None,
        # 1-byte ciphertext + 16-byte tag = 17 bytes total
        "ct": b"\x00" * 17,
        "key": b"\x00" * 16,
        "pt_expected": b"",
        "test_passed": False,
        "tag_len": 16,
    }


def test_ccm_invalid_reject_on_dead_mech_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """AES-CCM invalid-tag reject on a NOT_OPERATIONAL mech -> vacuous xfail.

    ``CKR_DEVICE_ERROR`` is in ``_CCM_DATA_REJECTS`` but NOT in ``_GCM_DATA_REJECTS``,
    pinning the guard-set difference between the two sibling sites.
    """

    def refuse(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(aead, "_import_aes_key", lambda *a, **k: 7)
    monkeypatch.setattr(aead, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(aead, "decrypt_single", refuse)
    with pytest.raises(pytest.xfail.Exception, match="vacuous reject"):
        aead.run_ccm_decrypt_test(_rs(), "tc-inv", _vec_invalid_ccm())


# --- wrap (test_wrap) -------------------------------------------------------


def _vec_invalid_kw() -> dict[str, Any]:
    return {
        "key": b"\x00" * 16,
        "ct": b"\x00" * 24,
        "pt_expected": b"",
        "test_passed": False,
    }


def test_kw_invalid_reject_on_dead_mech_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """AES-KW invalid-ciphertext reject on a NOT_OPERATIONAL mech -> vacuous xfail."""

    def refuse(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(wrap, "_import_aes_key", lambda *a, **k: 7)
    monkeypatch.setattr(wrap, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(wrap, "decrypt_single", refuse)
    with pytest.raises(pytest.xfail.Exception, match="vacuous reject"):
        wrap.test_acvp_aes_kw_unwrap(_rs(), "tc-inv", _vec_invalid_kw())


def _vec_invalid_kwp() -> dict[str, Any]:
    """Minimal invalid KWP decrypt vector (test_passed=False)."""
    return {
        "key": b"\x00" * 16,
        "ct": b"\x00" * 24,
        "pt_expected": b"",
        "test_passed": False,
    }


def test_kwp_invalid_reject_on_dead_mech_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """AES-KWP invalid-ciphertext reject on a NOT_OPERATIONAL mech -> vacuous xfail.

    Probes the ``AES_KEY_WRAP_KWP:decrypt`` probe key (``_wrap_operability``
    dispatches on the mechanism name).
    """

    def refuse(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(wrap, "_import_aes_key", lambda *a, **k: 7)
    monkeypatch.setattr(wrap, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(wrap, "decrypt_single", refuse)
    with pytest.raises(pytest.xfail.Exception, match="vacuous reject"):
        wrap.test_acvp_aes_kwp_unwrap(_rs(), "tc-inv", _vec_invalid_kwp())


# --- wycheproof CCM: INCONCLUSIVE must NOT xfail -----------------------------


def test_wycheproof_ccm_inconclusive_does_not_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid CCM vector + import-stage probe failure (INCONCLUSIVE) -> legacy pass.

    The canonical probe cannot import its key, so there is no mechanism
    evidence; the downgrade must not fire. The vector reject returns normally.
    If the guard regressed (downgrade firing on INCONCLUSIVE), the resulting
    XFailed propagates as this meta-test's own xfail outcome and CI stays green
    without this hard-fail wrapper.
    """
    from pkcs11_check.testcases.wycheproof import test_wycheproof_aes as wp

    def import_refuses(*_a: Any, **_k: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    def decrypt_refuses(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID", int(CKR_ENCRYPTED_DATA_INVALID)
        )

    # The vector path imports via import_secret_key_negotiated and succeeds (so
    # we reach the decrypt reject), but the CANONICAL probe imports via
    # base_runner_aead._import_aes_key and fails -> INCONCLUSIVE.
    monkeypatch.setattr(wp, "import_secret_key_negotiated", lambda *a, **k: 7)
    monkeypatch.setattr(wp, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(wp, "decrypt_single", decrypt_refuses)
    monkeypatch.setattr(aead, "_import_aes_key", import_refuses)

    vec_data = {
        "key": "00" * 16,
        "iv": "00" * 12,
        "aad": "",
        "msg": "",
        "ct": "00" * 16,
        "tag": "00" * 16,
        "result": "invalid",
    }
    # Hard-fail on downgrade leak: if xfail_vacuous_reject fires on INCONCLUSIVE
    # the XFailed exception would silently become this test's own xfail outcome.
    try:
        wp.test_aes_ccm(_rs(), "tc-inv", vec_data)
    except pytest.xfail.Exception as exc:
        pytest.fail(f"vacuous downgrade fired on INCONCLUSIVE probe: {exc}")


# --- wycheproof CCM: FIRING direction (NOT_OPERATIONAL must xfail) -----------


def test_wycheproof_ccm_not_operational_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid CCM vector + NOT_OPERATIONAL probe -> vacuous-reject xfail.

    ``decrypt_single`` refuses everywhere (both the vector decrypt and the
    canonical probe), so the probe verdict is NOT_OPERATIONAL.  Driving
    ``test_aes_ccm`` with an invalid vector must fire the downgrade.
    This test detects deleted wiring that the INCONCLUSIVE counterpart cannot
    (an INCONCLUSIVE probe never fires the downgrade).
    """
    from pkcs11_check.testcases.wycheproof import test_wycheproof_aes as wp

    def refuse_decrypt(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID", int(CKR_ENCRYPTED_DATA_INVALID)
        )

    # Vector path key import succeeds; canonical probe key import also succeeds
    # (both use _import_aes_key when patched here).  All decrypt_single calls
    # raise -> probe verdict = NOT_OPERATIONAL -> downgrade fires.
    monkeypatch.setattr(wp, "import_secret_key_negotiated", lambda *a, **k: 7)
    monkeypatch.setattr(wp, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(wp, "decrypt_single", refuse_decrypt)
    monkeypatch.setattr(aead, "_import_aes_key", lambda *a, **k: 7)
    monkeypatch.setattr(aead, "decrypt_single", refuse_decrypt)
    monkeypatch.setattr(aead, "destroy_quietly", lambda *a, **k: None)

    vec_data = {
        "key": "00" * 16,
        "iv": "00" * 12,
        "aad": "",
        "msg": "",
        "ct": "00" * 16,
        "tag": "00" * 16,
        "result": "invalid",
    }
    with pytest.raises(pytest.xfail.Exception, match="vacuous reject"):
        wp.test_aes_ccm(_rs(), "tc-inv", vec_data)


# --- ACVP SigVer (test_acvp_rsa.test_rsa_pkcs15_verify) ---------------------
#
# An invalid SigVer vector "rejected" by a mechanism whose canonical SigVer
# probe is NOT_OPERATIONAL never evaluated the signature -- the downgrade fires.
# A probe that is INCONCLUSIVE (canonical public-key import refused, no
# mechanism evidence) must leave the legacy pass untouched.  Both directions
# drive the real ``test_rsa_pkcs15_verify`` method so deleting the wiring fails
# the firing test.

_SIGVER_VECTOR_SIG = b"\xaa" * 8  # the under-test vector signature (distinct)
_SIGVER_CANON_SIG = b"\xbb" * 8  # the canonical probe vector signature


def _invalid_sigver_vec() -> dict[str, Any]:
    """A SigVer vector with expected_pass=False (the under-test invalid vector)."""
    return {
        "mech_name": "SHA1_RSA_PKCS",
        "mech_int": 6,
        "expected_pass": False,
        "n": b"\x01" * 256,  # 256 bytes = 2048 bits
        "e": b"\x01\x00\x01",
        "message": b"m",
        "signature": _SIGVER_VECTOR_SIG,
    }


def _canonical_sigver_pkcs15_ver() -> list[tuple[str, dict[str, Any]]]:
    """A single canonical valid vector for the probe to find (2048-bit SHA-1)."""
    return [
        (
            "canon",
            {
                "mech_name": "SHA1_RSA_PKCS",
                "mech_int": 6,
                "expected_pass": True,
                "n": b"\x01" * 256,
                "e": b"\x01\x00\x01",
                "message": b"m",
                "signature": _SIGVER_CANON_SIG,
            },
        )
    ]


def test_sigver_invalid_reject_on_dead_mech_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid SigVer vector rejected + NOT_OPERATIONAL probe -> vacuous xfail.

    The vector-under-test verify cleanly rejects (CKR_SIGNATURE_INVALID, so
    ``signature_rejected_or_xfail`` returns False = ``verified``), and the
    canonical probe verify ALSO refuses -> NOT_OPERATIONAL.  Mutation-resistant:
    deleting the ``xfail_vacuous_reject`` call lets the function return = pass.
    """

    def verify_dispatch(
        _raw: Any, _sh: int, _key: int, _mech: int, _msg: bytes, sig: bytes, **_kw: Any
    ) -> bool:
        if sig == _SIGVER_CANON_SIG:  # canonical probe verify -> NOT_OPERATIONAL
            raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))
        # under-test invalid vector -> clean signature reject
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SIGNATURE_INVALID", int(CKR_SIGNATURE_INVALID)
        )

    monkeypatch.setattr(rsa, "import_rsa_public_key_negotiated", lambda *a, **k: 7)
    monkeypatch.setattr(rsa, "verify_single", verify_dispatch)
    monkeypatch.setattr(rsa, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(rsa, "_PKCS15_VER", _canonical_sigver_pkcs15_ver())
    rs = SimpleNamespace(
        raw=object(), sh=1, has_mechanism=lambda name: True, has_mechanism_flag=lambda _m, _f: True
    )
    with pytest.raises(pytest.xfail.Exception, match="vacuous reject"):
        rsa.TestRsaSigVer().test_rsa_pkcs15_verify(rs, "tc-inv", _invalid_sigver_vec())


def test_sigver_invalid_reject_on_inconclusive_probe_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid SigVer vector rejected + INCONCLUSIVE probe -> legacy pass (no xfail).

    Probe staging (per the plan) = canonical public-key import refusal, so there
    is no mechanism evidence; the downgrade must NOT fire.  The under-test vector
    import succeeds (1st call) but the probe's canonical-vector import refuses
    (2nd call) -> INCONCLUSIVE.  The vector reject returns normally.
    Hard-fail wrapper: if the guard regressed and xfail_vacuous_reject fired on
    INCONCLUSIVE the resulting XFailed would silently become this meta-test's own
    xfail outcome, keeping CI green while the regression went undetected.
    """
    import_calls = {"n": 0}

    def import_dispatch(_rs: Any, *, n: bytes, e: bytes, attrs: Any) -> int:
        import_calls["n"] += 1
        if import_calls["n"] == 1:  # under-test vector import succeeds
            return 7
        # canonical probe import refuses -> staging failure -> INCONCLUSIVE
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    def verify_reject(
        _raw: Any, _sh: int, _key: int, _mech: int, _msg: bytes, _sig: bytes, **_kw: Any
    ) -> bool:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SIGNATURE_INVALID", int(CKR_SIGNATURE_INVALID)
        )

    monkeypatch.setattr(rsa, "import_rsa_public_key_negotiated", import_dispatch)
    monkeypatch.setattr(rsa, "verify_single", verify_reject)
    monkeypatch.setattr(rsa, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(rsa, "_PKCS15_VER", _canonical_sigver_pkcs15_ver())
    rs = SimpleNamespace(
        raw=object(), sh=1, has_mechanism=lambda name: True, has_mechanism_flag=lambda _m, _f: True
    )
    # Hard-fail on downgrade leak so CI cannot silently swallow a regression.
    try:
        rsa.TestRsaSigVer().test_rsa_pkcs15_verify(rs, "tc-inv", _invalid_sigver_vec())
    except pytest.xfail.Exception as exc:
        pytest.fail(f"vacuous downgrade fired on INCONCLUSIVE probe: {exc}")


# --- wycheproof RSA-PSS (test_wycheproof_rsa_pss.test_rsa_pss) ---------------
#
# An invalid PSS vector cleanly refused by a NOT_OPERATIONAL combo never
# evaluated the signature -> vacuous xfail.  An INCONCLUSIVE combo (keypair
# staging refused) keeps the legacy pass.  Staging = ``gen_rsa_keypair``
# refusal in the probe.


def _pss_vec_invalid() -> dict[str, Any]:
    """A minimal wycheproof PSS test entry with result=invalid (SHA-1, 2048-bit)."""
    from pkcs11_check.raw.types_std import CKG_MGF1_SHA1, CKM_SHA1_RSA_PKCS_PSS, CKM_SHA_1

    n_hex = "01" * 256  # 2048-bit modulus
    return {
        "msg": "00",
        "sig": "00" * 8,
        "result": "invalid",
        "_mechanism": CKM_SHA1_RSA_PKCS_PSS,
        "_sLen": 20,
        "_hash_mech": CKM_SHA_1,
        "_mgf": CKG_MGF1_SHA1,
        "_sha": "SHA-1",
        "_mgf_sha": "SHA-1",
        "_group": {"publicKey": {"modulus": n_hex, "publicExponent": "010001"}},
    }


def test_pss_invalid_reject_on_dead_combo_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid PSS vector cleanly refused + NOT_OPERATIONAL combo -> vacuous xfail.

    The vector verify refuses with CKR_SIGNATURE_INVALID (clean signature
    reject; ``signature_rejected_or_xfail`` returns False), and the canonical
    combo sign also refuses -> NOT_OPERATIONAL.  Mutation-resistant: deleting
    the ``xfail_vacuous_reject`` lets the function ``return`` = pass.
    """

    def refuse_combo_sign(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    def reject_vector_verify(*_a: Any, **_k: Any) -> bool:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SIGNATURE_INVALID", int(CKR_SIGNATURE_INVALID)
        )

    monkeypatch.setattr(pss, "import_rsa_public_key_negotiated", lambda *a, **k: 7)
    monkeypatch.setattr(pss, "verify_single", reject_vector_verify)
    monkeypatch.setattr(pss, "gen_rsa_keypair", lambda *a, **k: (7, 8))
    monkeypatch.setattr(pss, "sign_single", refuse_combo_sign)
    monkeypatch.setattr(pss, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(pss, "mech_pss", lambda *a, **k: object())
    rs = SimpleNamespace(
        raw=object(), sh=1, has_mechanism=lambda name: True, has_mechanism_flag=lambda _m, _f: True
    )
    with pytest.raises(pytest.xfail.Exception, match="vacuous reject"):
        pss.test_rsa_pss(rs, "tc-inv", _pss_vec_invalid())


def test_pss_invalid_reject_on_inconclusive_combo_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid PSS vector cleanly refused + INCONCLUSIVE combo -> legacy pass.

    The probe's RSA-2048 keypair generation refuses (staging), so there is no
    PSS-combo evidence; the downgrade must NOT fire.  The vector reject returns
    normally.
    Hard-fail wrapper: if the guard regressed and xfail_vacuous_reject fired on
    INCONCLUSIVE the resulting XFailed would silently become this meta-test's own
    xfail outcome, keeping CI green while the regression went undetected.
    """

    def refuse_keygen(*_a: Any, **_k: Any) -> tuple[int, int]:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    def reject_vector_verify(*_a: Any, **_k: Any) -> bool:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SIGNATURE_INVALID", int(CKR_SIGNATURE_INVALID)
        )

    monkeypatch.setattr(pss, "import_rsa_public_key_negotiated", lambda *a, **k: 7)
    monkeypatch.setattr(pss, "verify_single", reject_vector_verify)
    monkeypatch.setattr(pss, "gen_rsa_keypair", refuse_keygen)
    monkeypatch.setattr(pss, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(pss, "mech_pss", lambda *a, **k: object())
    rs = SimpleNamespace(
        raw=object(), sh=1, has_mechanism=lambda name: True, has_mechanism_flag=lambda _m, _f: True
    )
    # Hard-fail on downgrade leak so CI cannot silently swallow a regression.
    try:
        pss.test_rsa_pss(rs, "tc-inv", _pss_vec_invalid())
    except pytest.xfail.Exception as exc:
        pytest.fail(f"vacuous downgrade fired on INCONCLUSIVE probe: {exc}")


def test_pss_invalid_verify_false_on_dead_combo_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid PSS vector returns verify-False + NOT_OPERATIONAL combo -> xfail.

    Pins the SECOND PSS wiring site: the hoisted ``if result == 'invalid'``
    classification block's terminal ``return`` (verify_single returns False
    rather than raising).  The combo probe sign refuses -> NOT_OPERATIONAL ->
    the downgrade fires.  Mutation-resistant for the hoisted-block site
    independently of the except-handler site.
    """

    def refuse_combo_sign(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    # verify_single returns False for the under-test vector (no raise) so the
    # hoisted invalid block is reached; the combo probe also calls verify_single
    # but only after sign_single, which refuses first.
    monkeypatch.setattr(pss, "import_rsa_public_key_negotiated", lambda *a, **k: 7)
    monkeypatch.setattr(pss, "verify_single", lambda *a, **k: False)
    monkeypatch.setattr(pss, "gen_rsa_keypair", lambda *a, **k: (7, 8))
    monkeypatch.setattr(pss, "sign_single", refuse_combo_sign)
    monkeypatch.setattr(pss, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(pss, "mech_pss", lambda *a, **k: object())
    rs = SimpleNamespace(
        raw=object(), sh=1, has_mechanism=lambda name: True, has_mechanism_flag=lambda _m, _f: True
    )
    with pytest.raises(pytest.xfail.Exception, match="vacuous reject"):
        pss.test_rsa_pss(rs, "tc-inv", _pss_vec_invalid())


def _pss_vec_acceptable() -> dict[str, Any]:
    """A minimal wycheproof PSS test entry with result=acceptable (SHA-1, 2048-bit).

    "acceptable" vectors are technically valid signatures (the module should
    not reject them) whose parameters are non-standard (e.g. sLen=0); a clean
    exception-path rejection is a legitimate honest deviation, NOT a vacuous
    reject that warrants xfailing.  The downgrade must only fire on result==invalid.
    """
    from pkcs11_check.raw.types_std import CKG_MGF1_SHA1, CKM_SHA1_RSA_PKCS_PSS, CKM_SHA_1

    n_hex = "01" * 256  # 2048-bit modulus
    return {
        "msg": "00",
        "sig": "00" * 8,
        "result": "acceptable",
        "_mechanism": CKM_SHA1_RSA_PKCS_PSS,
        "_sLen": 0,
        "_hash_mech": CKM_SHA_1,
        "_mgf": CKG_MGF1_SHA1,
        "_sha": "SHA-1",
        "_mgf_sha": "SHA-1",
        "_group": {"publicKey": {"modulus": n_hex, "publicExponent": "010001"}},
    }


def test_pss_acceptable_reject_on_dead_combo_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Acceptable PSS vector cleanly refused + NOT_OPERATIONAL combo -> legacy pass (no xfail).

    RED test for Fix 3: the except-handler's xfail_vacuous_reject must only fire
    when ``result == 'invalid'``.  An "acceptable" vector rejected during verify
    (a legitimate honest deviation -- the module refused a technically-valid but
    non-standard parameter set) must NOT be labelled "invalid-PSS reject"; it
    should return normally from the except branch regardless of the combo probe
    verdict.
    """

    def refuse_combo_sign(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    def reject_vector_verify(*_a: Any, **_k: Any) -> bool:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_SIGNATURE_INVALID", int(CKR_SIGNATURE_INVALID)
        )

    monkeypatch.setattr(pss, "import_rsa_public_key_negotiated", lambda *a, **k: 7)
    monkeypatch.setattr(pss, "verify_single", reject_vector_verify)
    monkeypatch.setattr(pss, "gen_rsa_keypair", lambda *a, **k: (7, 8))
    monkeypatch.setattr(pss, "sign_single", refuse_combo_sign)
    monkeypatch.setattr(pss, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(pss, "mech_pss", lambda *a, **k: object())
    rs = SimpleNamespace(
        raw=object(), sh=1, has_mechanism=lambda name: True, has_mechanism_flag=lambda _m, _f: True
    )
    # Must return normally (no xfail) -- acceptable-vector rejection is a genuine
    # honest deviation regardless of the combo probe verdict.
    try:
        pss.test_rsa_pss(rs, "tc-inv", _pss_vec_acceptable())
    except pytest.xfail.Exception as exc:
        pytest.fail(f"vacuous downgrade fired on acceptable-result vector: {exc}")
