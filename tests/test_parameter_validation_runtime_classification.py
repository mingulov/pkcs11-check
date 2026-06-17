"""Runtime classification meta-tests for weak/invalid mechanism-parameter probes.

Each probe in security/test_parameter_validation.py is reclassified from a
compliance.note() (silent-pass on acceptance) to the Type-A crypto-correctness
rule: accepting the insecure/invalid parameter -> fail; an expected reject ->
pass; another clean reject code -> xfail. These offline meta-tests drive each
probe with fake recipes and assert all three branches.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.security import test_parameter_validation as pv


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: True)


def _raise(rv: int):  # type: ignore[no-untyped-def]
    def _f(*_a: object, **_k: object) -> int:
        raise CkrAssertionError(f"rv={rv}", int(rv))

    return _f


_EXPECTED = int(CKR_MECHANISM_PARAM_INVALID)
_OTHER = int(CKR_DEVICE_ERROR)


# --- GCM weak tag ---------------------------------------------------------


def _run_gcm_tag(monkeypatch: pytest.MonkeyPatch, *, accepted: bool, rv: int = 0) -> None:
    monkeypatch.setattr(pv, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(pv, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(pv, "encrypt_single", (lambda *_a, **_k: b"x") if accepted else _raise(rv))
    pv.TestGcmTagSize().test_gcm_weak_tag_size(_session(), 32)


def test_gcm_tag_accept_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed):
        _run_gcm_tag(monkeypatch, accepted=True)


def test_gcm_tag_expected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_gcm_tag(monkeypatch, accepted=False, rv=_EXPECTED)


def test_gcm_tag_other_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_gcm_tag(monkeypatch, accepted=False, rv=_OTHER)


# --- GCM weak IV ----------------------------------------------------------


def _run_gcm_iv(monkeypatch: pytest.MonkeyPatch, *, accepted: bool, rv: int = 0) -> None:
    monkeypatch.setattr(pv, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(pv, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(pv, "encrypt_single", (lambda *_a, **_k: b"x") if accepted else _raise(rv))
    pv.TestGcmIvWeakness().test_gcm_weak_iv(_session(), b"\x00" * 4)


def test_gcm_iv_accept_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed):
        _run_gcm_iv(monkeypatch, accepted=True)


def test_gcm_iv_expected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_gcm_iv(monkeypatch, accepted=False, rv=_EXPECTED)


def test_gcm_iv_other_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_gcm_iv(monkeypatch, accepted=False, rv=_OTHER)


# --- GCM IV reuse ---------------------------------------------------------


def _run_gcm_reuse(monkeypatch: pytest.MonkeyPatch, *, second_accepted: bool, rv: int = 0) -> None:
    monkeypatch.setattr(pv, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(pv, "destroy_quietly", lambda *_a, **_k: None)
    calls = {"n": 0}

    def _enc(*_a: object, **_k: object) -> bytes:
        calls["n"] += 1
        if calls["n"] == 1:
            return b"ct1"
        if second_accepted:
            return b"ct2"
        raise CkrAssertionError(f"rv={rv}", int(rv))

    monkeypatch.setattr(pv, "encrypt_single", _enc)
    pv.TestGcmIvReuse().test_gcm_iv_reuse_same_key(_session())


def test_gcm_reuse_accept_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed):
        _run_gcm_reuse(monkeypatch, second_accepted=True)


def test_gcm_reuse_expected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_gcm_reuse(monkeypatch, second_accepted=False, rv=_EXPECTED)


def test_gcm_reuse_other_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_gcm_reuse(monkeypatch, second_accepted=False, rv=_OTHER)


# --- PSS zero salt --------------------------------------------------------


def _run_pss(
    monkeypatch: pytest.MonkeyPatch, *, accepted: bool, rv: int = 0, verifies: bool = True
) -> None:
    monkeypatch.setattr(pv, "gen_rsa_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(pv, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(pv, "sign_single", (lambda *_a, **_k: b"sig") if accepted else _raise(rv))
    monkeypatch.setattr(pv, "verify_single", lambda *_a, **_k: verifies)
    pv.TestPssSaltLength().test_pss_zero_salt_length(_session(), 0)


# sLen=0 is a VALID deterministic PSS variant (RFC 8017 §9.1 / FIPS 186-5):
# accepting it and producing a verifiable signature is CORRECT (pass); declining
# it cleanly is a policy choice (xfail); accepting it but producing a signature
# that does NOT verify is a real break (fail).
def test_pss_sln0_accepted_and_verifies_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_pss(monkeypatch, accepted=True, verifies=True)


def test_pss_sln0_accepted_but_invalid_signature_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed):
        _run_pss(monkeypatch, accepted=True, verifies=False)


def test_pss_sln0_clean_decline_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_pss(monkeypatch, accepted=False, rv=_EXPECTED)


def test_pss_sln0_nonclean_decline_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(CkrAssertionError):
        _run_pss(monkeypatch, accepted=False, rv=_OTHER)


# --- XTS identical halves -------------------------------------------------


def _run_xts(
    monkeypatch: pytest.MonkeyPatch, *, import_ok: bool, encrypt_accepted: bool, rv: int = 0
) -> None:
    monkeypatch.setattr(pv, "destroy_quietly", lambda *_a, **_k: None)
    if import_ok:
        monkeypatch.setattr(pv, "import_secret_key", lambda *_a, **_k: 1)
    else:
        monkeypatch.setattr(pv, "import_secret_key", _raise(rv))
    monkeypatch.setattr(
        pv, "encrypt_single", (lambda *_a, **_k: b"x") if encrypt_accepted else _raise(rv)
    )
    pv.TestXtsKeyValidation().test_xts_identical_keys(_session())


def test_xts_accept_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed):
        _run_xts(monkeypatch, import_ok=True, encrypt_accepted=True)


def test_xts_reject_at_encrypt_expected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_xts(
        monkeypatch, import_ok=True, encrypt_accepted=False, rv=int(CKR_ATTRIBUTE_VALUE_INVALID)
    )


def test_xts_reject_at_encrypt_other_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_xts(monkeypatch, import_ok=True, encrypt_accepted=False, rv=_OTHER)


# --- RSA weak exponent ----------------------------------------------------


def _run_rsa_exp(monkeypatch: pytest.MonkeyPatch, *, accepted: bool, rv: int = 0) -> None:
    monkeypatch.setattr(pv, "destroy_quietly", lambda *_a, **_k: None)
    if accepted:
        monkeypatch.setattr(pv, "gen_rsa_keypair", lambda *_a, **_k: (1, 2))
    else:
        monkeypatch.setattr(pv, "gen_rsa_keypair", _raise(rv))
    pv.TestRsaExponent().test_rsa_weak_public_exponent(_session(), 0)


def test_rsa_exp_accept_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed):
        _run_rsa_exp(monkeypatch, accepted=True)


def test_rsa_exp_expected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_rsa_exp(monkeypatch, accepted=False, rv=int(CKR_ATTRIBUTE_VALUE_INVALID))


def test_rsa_exp_other_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_rsa_exp(monkeypatch, accepted=False, rv=_OTHER)


# --- EC point validation (ECDH derive) ------------------------------------


def _run_ecdh(monkeypatch: pytest.MonkeyPatch, *, accepted: bool, rv: int = 0) -> None:
    monkeypatch.setattr(pv, "gen_ec_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(pv, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        pv,
        "read_attributes",
        lambda *_a, **_k: {pv.CKA_EC_POINT: b"\x04" + b"\x01" * 64},
    )
    monkeypatch.setattr(pv, "decode_ec_point", lambda data: b"\x04" + b"\x01" * 64)
    monkeypatch.setattr(pv, "derive_key", (lambda *_a, **_k: 9) if accepted else _raise(rv))
    pv.TestEcPointValidation().test_ecdh_invalid_point(_session(), "off_curve")


def test_ecdh_accept_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed):
        _run_ecdh(monkeypatch, accepted=True)


def test_ecdh_expected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_ecdh(monkeypatch, accepted=False, rv=int(CKR_ATTRIBUTE_VALUE_INVALID))


def test_ecdh_other_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_ecdh(monkeypatch, accepted=False, rv=_OTHER)
