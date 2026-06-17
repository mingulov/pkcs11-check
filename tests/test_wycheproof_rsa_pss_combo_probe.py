"""Regression tests for PC-3 remainder: tpm2 SHA-1 RSA-PSS "valid sig
rejected" must classify as ``xfail`` (advertised but not operational)
when the provider cannot itself produce a verifying signature for the
same (mech, hash, mgf, sLen) combo.

A `verified=False` return from ``C_Verify`` carries no exception, so
the existing ``xfail_if_known_ckr`` path does not apply. The
``_pss_combo_operability`` self-roundtrip probe answers the only
question that distinguishes "real provider bug" from "advertised but
not operational" in this shape: can the provider sign+verify a fresh
message with the same PSS params? If not, the combo is xfail; if yes,
the rejection of the known-valid vector is a real ``fail``.

The probe's three-state internals (keygen staging -> INCONCLUSIVE; sign/
verify refusal or verify-False -> NOT_OPERATIONAL; roundtrip -> OPERATIONAL;
plain AssertionError propagates uncached) are covered in
test_pss_combo_probe_three_state.py; this file pins the end-to-end consumer.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.testcases._operability import reset_operability_cache
from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_pss as twrp


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    reset_operability_cache()


def test_rsa_pss_valid_rejected_xfails_when_combo_not_operational(monkeypatch: Any) -> None:
    """End-to-end: valid-vector rejected + roundtrip-fails => xfail, not fail."""
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _n: True)
    monkeypatch.setattr(twrp, "import_rsa_public_key_negotiated", lambda *_a, **_kw: 99)
    # The wycheproof verify of the test vector -> False (provider rejects).
    # The probe verify -> False (provider can't verify its own sig either).
    monkeypatch.setattr(twrp, "verify_single", lambda *_a, **_kw: False)
    monkeypatch.setattr(twrp, "gen_rsa_keypair", lambda *_a, **_kw: (10, 11))
    monkeypatch.setattr(twrp, "sign_single", lambda *_a, **_kw: b"sig")
    monkeypatch.setattr(twrp, "destroy_quietly", lambda *_a, **_kw: None)
    monkeypatch.setattr(twrp, "generate_random", lambda *_a, **_kw: b"\x00" * 64)

    vec = {
        "msg": "00",
        "sig": "00",
        "result": "valid",
        "_mechanism": 0x0D,  # CKM_RSA_PKCS_PSS
        "_hash_mech": 0x0220,  # CKM_SHA_1
        "_mgf": 1,  # CKG_MGF1_SHA1
        "_sLen": 20,
        "_group": {"publicKey": {"modulus": "00" * 256, "publicExponent": "010001"}},
    }
    with pytest.raises(pytest.xfail.Exception):
        twrp.test_rsa_pss(rs, "rsa_pss_2048_sha1_mgf1_20_params:tc1-valid", vec)


def test_rsa_pss_valid_rejected_fails_when_combo_operational(monkeypatch: Any) -> None:
    """End-to-end: valid-vector rejected + roundtrip-succeeds => real fail."""
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _n: True)
    monkeypatch.setattr(twrp, "import_rsa_public_key_negotiated", lambda *_a, **_kw: 99)
    # Drive vector-verify = False but probe-verify = True (operational).
    verify_results = iter([False, True])
    monkeypatch.setattr(twrp, "verify_single", lambda *_a, **_kw: next(verify_results))
    monkeypatch.setattr(twrp, "gen_rsa_keypair", lambda *_a, **_kw: (10, 11))
    monkeypatch.setattr(twrp, "sign_single", lambda *_a, **_kw: b"sig")
    monkeypatch.setattr(twrp, "destroy_quietly", lambda *_a, **_kw: None)
    monkeypatch.setattr(twrp, "generate_random", lambda *_a, **_kw: b"\x00" * 64)

    vec = {
        "msg": "00",
        "sig": "00",
        "result": "valid",
        "_mechanism": 0x0D,
        "_hash_mech": 0x0250,
        "_mgf": 2,
        "_sLen": 32,
        "_group": {"publicKey": {"modulus": "00" * 256, "publicExponent": "010001"}},
    }
    with pytest.raises(pytest.fail.Exception):
        twrp.test_rsa_pss(rs, "rsa_pss_2048_sha256_mgf1_32_params:tc1-valid", vec)


def test_plain_assertion_from_probe_propagates_not_xfail(monkeypatch: Any) -> None:
    """Fix 1 regression: plain AssertionError from the probe must propagate out
    of the consumer test as AssertionError — never become an xfail, even when
    the message contains a CKR name that the broad except/substring-match path
    would otherwise misroute.

    Root cause: if the probe call sits inside the ``try:`` whose ``except
    AssertionError`` handler calls ``_xfail_if_rsa_pss_runtime_reject``, a
    plain AssertionError from the probe goes through the substring-match
    fallback in ``xfail_if_known_ckr``.  When the message happens to contain a
    CKR name that is in ``_RSA_PSS_RUNTIME_REJECT_CKRS`` (e.g.
    "CKR_FUNCTION_FAILED"), it is silently misattributed as an xfail (harness
    bug hidden as "advertised but not operational").

    The fix hoists the probe call OUT of the ``try:`` so the broad handler
    never sees it.
    """
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _n: True)
    monkeypatch.setattr(twrp, "import_rsa_public_key_negotiated", lambda *_a, **_kw: 99)
    # The wycheproof verify of the test vector -> False (triggers probe path).
    monkeypatch.setattr(twrp, "verify_single", lambda *_a, **_kw: False)
    # gen_rsa_keypair raises a plain AssertionError whose message contains a
    # CKR name from _RSA_PSS_RUNTIME_REJECT_CKRS (simulates a harness assert
    # that happens to mention a CKR constant in its message).  The substring-
    # match fallback in xfail_if_known_ckr would fire on this, converting the
    # harness bug into an xfail — the test pins that this must NOT happen.
    monkeypatch.setattr(
        twrp,
        "gen_rsa_keypair",
        lambda *_a, **_kw: (_ for _ in ()).throw(
            AssertionError("harness internal: CKR_FUNCTION_FAILED not expected here")
        ),
    )
    monkeypatch.setattr(twrp, "sign_single", lambda *_a, **_kw: b"sig")
    monkeypatch.setattr(twrp, "destroy_quietly", lambda *_a, **_kw: None)
    monkeypatch.setattr(twrp, "generate_random", lambda *_a, **_kw: b"\x00" * 64)

    vec = {
        "msg": "00",
        "sig": "00",
        "result": "valid",
        "_mechanism": 0x0D,
        "_hash_mech": 0x0220,
        "_mgf": 1,
        "_sLen": 20,
        "_group": {"publicKey": {"modulus": "00" * 256, "publicExponent": "010001"}},
    }
    # Must propagate as plain AssertionError.  With the probe inside the try:,
    # the "CKR_FUNCTION_FAILED" substring match fires and pytest.xfail() is
    # raised instead — that is the bug this test pins against.
    with pytest.raises(AssertionError, match="CKR_FUNCTION_FAILED not expected here"):
        twrp.test_rsa_pss(rs, "rsa_pss_2048_sha1_mgf1_20_probe_bug:tc1-valid", vec)
