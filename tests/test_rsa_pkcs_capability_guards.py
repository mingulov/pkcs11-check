"""Regression tests for GH #7: CKM_RSA_PKCS encrypt/decrypt capability guards.

Two security tests reached ``encrypt_single(..., CKM_RSA_PKCS, ...)`` with no
capability guard, so a module that legitimately does not offer PKCS#1 v1.5
*encryption* failed them instead of skipping.

The guard is on the **operation flag**, not on mere mechanism presence:
``CKM_RSA_PKCS`` covers signature and encryption, and the two are separately
gated -- v1.5 signature is FIPS-approved while v1.5 encryption is not, so a
FIPS-strict module advertises ``CKM_RSA_PKCS`` for signing only. A bare
``has_mechanism("RSA_PKCS")`` check would therefore still run these tests on such
a module. Conversely a module that DOES advertise ``CKF_ENCRYPT``/``CKF_DECRYPT``
and then refuses the operation must still be a finding, never a skip -- so the
positive-path tests below assert the guard falls through.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_ENCRYPT,
    CKR_KEY_HANDLE_INVALID,
    CKR_MECHANISM_INVALID,
)
from pkcs11_check.testcases import test_encrypt, test_key_sizes
from pkcs11_check.testcases.security import test_cve_regression, test_padding_oracle
from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_decrypt


class _GuardFellThroughError(Exception):
    """Raised by a stubbed keypair generator to prove the guard fell through."""


def _session(*, flags: set[int]) -> SimpleNamespace:
    """Fake raw session advertising CKM_RSA_PKCS with exactly *flags* set."""
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
        has_mechanism_flag=lambda _mech, flag: int(flag) in flags,
    )


def test_rsa_encrypt_boundary_skips_without_ckf_encrypt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Signature-only CKM_RSA_PKCS must skip, not fail (the GH #7 report)."""

    def _unexpected_keygen(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("RSA keypair generation should have been capability-guarded")

    monkeypatch.setattr(test_cve_regression, "_gen_cve_rsa_keypair_or_xfail", _unexpected_keygen)
    rs = _session(flags=set())  # mechanism advertised, but not for encryption

    with pytest.raises(pytest.skip.Exception, match="CKF_ENCRYPT"):
        test_cve_regression.TestBoundaryLengthCrypto().test_rsa_encrypt_boundary(rs)


def test_rsa_encrypt_boundary_runs_when_ckf_encrypt_advertised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An advertised CKF_ENCRYPT must NOT be skipped -- a later refusal is a finding."""

    def _reached(*_args: object, **_kwargs: object) -> object:
        raise _GuardFellThroughError

    monkeypatch.setattr(test_cve_regression, "_gen_cve_rsa_keypair_or_xfail", _reached)
    rs = _session(flags={int(CKF_ENCRYPT)})

    with pytest.raises(_GuardFellThroughError):
        test_cve_regression.TestBoundaryLengthCrypto().test_rsa_encrypt_boundary(rs)


def test_rsa_timing_sanity_skips_without_ckf_encrypt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The timing probe encrypts first, so it needs CKF_ENCRYPT too."""

    def _unexpected_keygen(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("RSA keypair generation should have been capability-guarded")

    monkeypatch.setattr(test_padding_oracle, "gen_rsa_keypair_or_xfail", _unexpected_keygen)
    rs = _session(flags={int(CKF_DECRYPT)})  # decrypt only -- cannot build the probe

    with pytest.raises(pytest.skip.Exception, match="CKF_ENCRYPT"):
        test_padding_oracle.TestTimingBasic().test_rsa_decrypt_timing_sanity(rs)


def test_rsa_timing_sanity_skips_without_ckf_decrypt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Encrypt-only CKM_RSA_PKCS cannot be timed for a decryption oracle."""

    def _unexpected_keygen(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("RSA keypair generation should have been capability-guarded")

    monkeypatch.setattr(test_padding_oracle, "gen_rsa_keypair_or_xfail", _unexpected_keygen)
    rs = _session(flags={int(CKF_ENCRYPT)})

    with pytest.raises(pytest.skip.Exception, match="CKF_DECRYPT"):
        test_padding_oracle.TestTimingBasic().test_rsa_decrypt_timing_sanity(rs)


def test_rsa_timing_sanity_runs_with_both_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both flags advertised -> the guard falls through and the test really runs."""

    def _reached(*_args: object, **_kwargs: object) -> object:
        raise _GuardFellThroughError

    monkeypatch.setattr(test_padding_oracle, "gen_rsa_keypair_or_xfail", _reached)
    rs = _session(flags={int(CKF_ENCRYPT), int(CKF_DECRYPT)})

    with pytest.raises(_GuardFellThroughError):
        test_padding_oracle.TestTimingBasic().test_rsa_decrypt_timing_sanity(rs)


# --- advertised-but-not-operational: xfail, never a hard fail ---------------------------
# The flag guard only skips a module that never CLAIMED the capability. A module that DOES
# advertise CKF_ENCRYPT/CKF_DECRYPT and then refuses is a positive op returning a clean
# error -- "advertised but not operational" -- which the classification model records as an
# xfail finding (reason=not_operational), not a failure. Both are recorded findings; the
# distinction that matters is not accusing a module that made no such claim.


def _ckr_mechanism_invalid(*_args: object, **_kwargs: object) -> object:
    raise CkrAssertionError("Unexpected CK_RV CKR_MECHANISM_INVALID", int(CKR_MECHANISM_INVALID))


def test_rsa_encrypt_boundary_xfails_when_advertised_but_not_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Advertised CKF_ENCRYPT + CKR_MECHANISM_INVALID -> not_operational xfail."""
    monkeypatch.setattr(
        test_cve_regression, "_gen_cve_rsa_keypair_or_xfail", lambda *_a, **_k: (1, 2)
    )
    monkeypatch.setattr(test_cve_regression, "encrypt_single", _ckr_mechanism_invalid)
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_a, **_k: None)
    rs = _session(flags={int(CKF_ENCRYPT)})

    with pytest.raises(pytest.xfail.Exception):
        test_cve_regression.TestBoundaryLengthCrypto().test_rsa_encrypt_boundary(rs)


def test_rsa_timing_sanity_xfails_when_advertised_but_not_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The timing probe's setup encrypt must xfail, not fail, on a clean refusal."""
    monkeypatch.setattr(test_padding_oracle, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(test_padding_oracle, "encrypt_single", _ckr_mechanism_invalid)
    monkeypatch.setattr(test_padding_oracle, "destroy_quietly", lambda *_a, **_k: None)
    rs = _session(flags={int(CKF_ENCRYPT), int(CKF_DECRYPT)})

    with pytest.raises(pytest.xfail.Exception):
        test_padding_oracle.TestTimingBasic().test_rsa_decrypt_timing_sanity(rs)


# --- GH #7 class sweep: same guard at the remaining RSA cipher sites --------------------
# The class defect (RSA cipher op with no operation-flag guard) also lived in the
# conformance roundtrips, the key-size OAEP roundtrip, and the Wycheproof PKCS#1
# decrypt gate. The guards must skip only non-claiming modules; genuine crypto
# findings (broken OAEP randomization, unknown CKRs on advertised ops) must
# survive as hard failures.


def test_encrypt_rsa_pkcs_roundtrip_skips_without_ckf_decrypt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Encrypt-only CKM_RSA_PKCS cannot round-trip -- skip, not xfail."""

    def _unexpected_keygen(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("keypair generation should have been capability-guarded")

    monkeypatch.setattr(test_encrypt, "gen_rsa_keypair_or_xfail", _unexpected_keygen)
    rs = _session(flags={int(CKF_ENCRYPT)})

    with pytest.raises(pytest.skip.Exception, match="CKF_DECRYPT"):
        test_encrypt.TestRSAEncryption().test_rsa_pkcs_roundtrip(rs)


def test_encrypt_rsa_pkcs_roundtrip_skips_without_ckf_encrypt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Signature-only CKM_RSA_PKCS (the craton-hsm/nethsm posture) must skip."""

    def _unexpected_keygen(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("keypair generation should have been capability-guarded")

    monkeypatch.setattr(test_encrypt, "gen_rsa_keypair_or_xfail", _unexpected_keygen)
    rs = _session(flags={int(CKF_DECRYPT)})

    with pytest.raises(pytest.skip.Exception, match="CKF_ENCRYPT"):
        test_encrypt.TestRSAEncryption().test_rsa_pkcs_roundtrip(rs)


def test_encrypt_rsa_pkcs_roundtrip_runs_with_both_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both flags advertised -> the roundtrip really runs."""

    def _reached(*_args: object, **_kwargs: object) -> object:
        raise _GuardFellThroughError

    monkeypatch.setattr(test_encrypt, "gen_rsa_keypair_or_xfail", _reached)
    rs = _session(flags={int(CKF_ENCRYPT), int(CKF_DECRYPT)})

    with pytest.raises(_GuardFellThroughError):
        test_encrypt.TestRSAEncryption().test_rsa_pkcs_roundtrip(rs)


def test_encrypt_rsa_oaep_roundtrip_skips_without_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A module not offering OAEP encryption must skip the OAEP roundtrip."""

    def _unexpected_keygen(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("keypair generation should have been capability-guarded")

    monkeypatch.setattr(test_encrypt, "gen_rsa_keypair_or_xfail", _unexpected_keygen)
    rs = _session(flags=set())

    with pytest.raises(pytest.skip.Exception, match="CKF_ENCRYPT"):
        test_encrypt.TestRSAEncryption().test_rsa_oaep_roundtrip(rs)


def test_encrypt_rsa_oaep_roundtrip_xfails_when_advertised_but_not_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Advertised OAEP + clean runtime refusal -> not_operational xfail."""
    monkeypatch.setattr(test_encrypt, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(test_encrypt, "encrypt_single", _ckr_mechanism_invalid)
    monkeypatch.setattr(test_encrypt, "destroy_quietly", lambda *_a, **_k: None)
    rs = _session(flags={int(CKF_ENCRYPT), int(CKF_DECRYPT)})

    with pytest.raises(pytest.xfail.Exception):
        test_encrypt.TestRSAEncryption().test_rsa_oaep_roundtrip(rs)


def test_encrypt_rsa_ciphertext_random_break_stays_a_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Identical OAEP ciphertexts (real case: pkcs11-mock) must NOT become xfail."""
    monkeypatch.setattr(test_encrypt, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(test_encrypt, "encrypt_single", lambda *_a, **_k: b"same-ct")
    monkeypatch.setattr(test_encrypt, "destroy_quietly", lambda *_a, **_k: None)
    rs = _session(flags={int(CKF_ENCRYPT)})

    with pytest.raises(AssertionError):
        test_encrypt.TestRSAEncryption().test_rsa_ciphertext_is_random(rs)


def test_key_sizes_oaep_roundtrip_skips_without_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OAEP advertised without cipher flags -> skip at every key size."""

    def _unexpected_keygen(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("keypair generation should have been capability-guarded")

    monkeypatch.setattr(test_key_sizes, "gen_rsa_keypair_or_xfail", _unexpected_keygen)
    rs = _session(flags=set())

    with pytest.raises(pytest.skip.Exception, match="CKF_ENCRYPT"):
        test_key_sizes.TestRSAKeySizes().test_rsa_oaep_roundtrip(rs, 2048)


def test_key_sizes_oaep_unknown_ckr_stays_a_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKR_KEY_HANDLE_INVALID on an advertised OAEP op (real case: craton-hsm)
    is not in the not-operational tuple and must stay a hard failure."""

    def _key_handle_invalid(*_args: object, **_kwargs: object) -> object:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_KEY_HANDLE_INVALID", int(CKR_KEY_HANDLE_INVALID)
        )

    monkeypatch.setattr(test_key_sizes, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(test_key_sizes, "encrypt_single", _key_handle_invalid)
    monkeypatch.setattr(test_key_sizes, "destroy_quietly", lambda *_a, **_k: None)
    rs = _session(flags={int(CKF_ENCRYPT), int(CKF_DECRYPT)})

    with pytest.raises(CkrAssertionError):
        test_key_sizes.TestRSAKeySizes().test_rsa_oaep_roundtrip(rs, 2048)


def test_wycheproof_rsa_decrypt_skips_without_ckf_decrypt() -> None:
    """Sign-only CKM_RSA_PKCS must not accumulate per-vector decrypt findings.

    The guard must fire before the vector dict is even touched (vec={} here)."""
    rs = _session(flags=set())

    with pytest.raises(pytest.skip.Exception, match="CKF_DECRYPT"):
        test_wycheproof_rsa_decrypt.test_rsa_pkcs1_decrypt(rs, object(), "unit", {})
