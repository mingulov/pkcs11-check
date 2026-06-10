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
from pkcs11_check.raw.types_std import CKR_ENCRYPTED_DATA_INVALID, CKR_GENERAL_ERROR
from pkcs11_check.testcases._operability import reset_operability_cache
from pkcs11_check.testcases.acvp.aes import base_runner_aead as aead
from pkcs11_check.testcases.acvp.aes import test_wrap as wrap


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    reset_operability_cache()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: True)


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
    """OPERATIONAL mechanism rejecting an invalid tag stays a genuine pass."""
    calls = {"n": 0}

    def reject_vector_only(
        _raw: Any, _sh: int, _key: int, _mech: Any, _ct: bytes, **_kw: Any
    ) -> bytes:
        calls["n"] += 1
        if calls["n"] == 1:  # the vector under test
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID", int(CKR_ENCRYPTED_DATA_INVALID)
            )
        return aead.PROBE_PT  # the canonical probe decrypt succeeds -> OPERATIONAL

    monkeypatch.setattr(aead, "_import_aes_key", lambda *a, **k: 7)
    monkeypatch.setattr(aead, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(aead, "decrypt_single", reject_vector_only)
    monkeypatch.setattr(aead, "encrypt_single", lambda *a, **k: aead.PROBE_PT)
    monkeypatch.setattr(aead, "_probe_expected_ct", lambda mech_name: aead.PROBE_PT)
    # returns normally (no xfail) = PASS
    aead.run_gcm_decrypt_test(_rs(), "tc-inv", _vec_invalid_gcm())


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


# --- wycheproof CCM: INCONCLUSIVE must NOT xfail -----------------------------


def test_wycheproof_ccm_inconclusive_does_not_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid CCM vector + import-stage probe failure (INCONCLUSIVE) -> legacy pass.

    The canonical probe cannot import its key, so there is no mechanism
    evidence; the downgrade must not fire. The vector reject returns normally.
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
    # returns normally (no xfail) = legacy pass on INCONCLUSIVE
    wp.test_aes_ccm(_rs(), "tc-inv", vec_data)
