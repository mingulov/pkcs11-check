"""Meta-tests: AEAD KAT runners classify clean errors via the operability probe.

Replaces the narrow {MECHANISM_INVALID, MECHANISM_PARAM_INVALID} xfail
allowlists (triage H2): the canonical known-answer probe's EFFECT decides.

Provider shapes covered (all via fakes, no module needed):
- bouncyhsm:  every CCM call returns CKR_GENERAL_ERROR, canonical included
              -> whole class xfails ("advertised but not operational")
- kryoptic:   canonical CCM (13B nonce) works; a 7B-nonce vector is cleanly
              rejected -> xfail ("parameter shape"), NOT a hard fail
- healthy module failing one valid vector -> stays a finding (re-raised)
- broken import path (triage H6) -> INCONCLUSIVE -> legacy param-shape rules
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases._operability import reset_operability_cache
from pkcs11_check.testcases.acvp.aes import base_runner_aead as runner


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    reset_operability_cache()


class _AeadSession:
    raw = object()
    sh = 1

    @staticmethod
    def has_mechanism(name: str) -> bool:
        return name in ("AES_CCM", "AES_GCM")


def _ckm_ccm_vec(nonce_len: int = 13) -> dict[str, Any]:
    return {
        "key": bytes(16),
        "nonce": bytes(nonce_len),
        "pt": bytes(8),
        "aad": b"",
        "ct_expected": bytes(24),
        "tag_len": 16,
    }


def _expected_canonical_ccm_ct() -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM

    return AESCCM(runner.PROBE_KEY, tag_length=16).encrypt(
        runner.PROBE_CCM_NONCE, runner.PROBE_PT, None
    )


def test_ccm_wholly_non_operational_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """bouncyhsm shape: vector AND canonical return CKR_GENERAL_ERROR."""
    monkeypatch.setattr(runner, "import_secret_key", lambda *a, **k: 7)
    monkeypatch.setattr(runner, "destroy_quietly", lambda *a, **k: None)

    def _general_error(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(runner, "encrypt_single", _general_error)

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        runner.run_ccm_encrypt_test(_AeadSession(), "tc1", _ckm_ccm_vec())


def test_ccm_param_shape_reject_on_operational_mech_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """kryoptic shape: canonical 13B-nonce CCM works; 7B-nonce vector rejected."""
    monkeypatch.setattr(runner, "import_secret_key", lambda *a, **k: 7)
    monkeypatch.setattr(runner, "destroy_quietly", lambda *a, **k: None)
    canonical_ct = _expected_canonical_ccm_ct()

    def _encrypt(_raw: Any, _sh: int, _key: int, _mech: Any, pt: bytes, **_k: Any) -> bytes:
        if pt == runner.PROBE_PT:
            return canonical_ct
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID", int(CKR_MECHANISM_PARAM_INVALID)
        )

    monkeypatch.setattr(runner, "encrypt_single", _encrypt)

    with pytest.raises(pytest.xfail.Exception, match="parameter shape"):
        runner.run_ccm_encrypt_test(_AeadSession(), "tc7b", _ckm_ccm_vec(nonce_len=7))


def test_ccm_vector_error_on_operational_mech_stays_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Canonical works; a valid vector erroring with GENERAL_ERROR is a finding."""
    monkeypatch.setattr(runner, "import_secret_key", lambda *a, **k: 7)
    monkeypatch.setattr(runner, "destroy_quietly", lambda *a, **k: None)
    canonical_ct = _expected_canonical_ccm_ct()

    def _encrypt(_raw: Any, _sh: int, _key: int, _mech: Any, pt: bytes, **_k: Any) -> bytes:
        if pt == runner.PROBE_PT:
            return canonical_ct
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(runner, "encrypt_single", _encrypt)

    with pytest.raises(CkrAssertionError):
        runner.run_ccm_encrypt_test(_AeadSession(), "tc1", _ckm_ccm_vec())


def test_ccm_broken_import_path_is_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    """H6 shape: canonical key import fails -> no mechanism evidence -> the
    legacy param-shape rules apply (param reject xfails, generic error stays)."""

    def _no_import(*_a: Any, **_k: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_ARGUMENTS_BAD", int(CKR_ARGUMENTS_BAD))

    monkeypatch.setattr(runner, "import_secret_key", _no_import)
    monkeypatch.setattr(runner, "destroy_quietly", lambda *a, **k: None)

    # The vector op itself cannot run either (import fails first), so the
    # import failure surfaces as the vector error -> ARGUMENTS_BAD is in the
    # param-shape set -> xfail rather than mass hard-fail.
    with pytest.raises(pytest.xfail.Exception):
        runner.run_ccm_encrypt_test(_AeadSession(), "tc1", _ckm_ccm_vec())


def test_gcm_decrypt_valid_tag_rejection_with_dead_mechanism_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid-tag GCM vector rejected as ENCRYPTED_DATA_INVALID is only a
    tag-auth FINDING when canonical decrypt works; with a dead decrypt path it
    is 'advertised but not operational'."""
    from pkcs11_check.raw.types_std import CKR_ENCRYPTED_DATA_INVALID

    monkeypatch.setattr(runner, "import_secret_key", lambda *a, **k: 7)
    monkeypatch.setattr(runner, "destroy_quietly", lambda *a, **k: None)

    def _decrypt(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID", int(CKR_ENCRYPTED_DATA_INVALID)
        )

    monkeypatch.setattr(runner, "decrypt_single", _decrypt)

    vec = {
        "key": bytes(16),
        "iv": bytes(12),
        "ct": bytes(16),
        "tag": bytes(16),
        "aad": b"",
        "pt_expected": bytes(16),
        "test_passed": True,
        "tag_len_bits": 128,
    }
    with pytest.raises(pytest.xfail.Exception, match="not operational"):
        runner.run_gcm_decrypt_test(_AeadSession(), "tc-valid", vec)


def test_gcm_decrypt_invalid_tag_rejection_still_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rejecting an INVALID-tag vector is the expected pass and must not probe."""
    from pkcs11_check.raw.types_std import CKR_ENCRYPTED_DATA_INVALID

    monkeypatch.setattr(runner, "import_secret_key", lambda *a, **k: 7)
    monkeypatch.setattr(runner, "destroy_quietly", lambda *a, **k: None)

    def _decrypt(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID", int(CKR_ENCRYPTED_DATA_INVALID)
        )

    monkeypatch.setattr(runner, "decrypt_single", _decrypt)

    vec = {
        "key": bytes(16),
        "iv": bytes(12),
        "ct": bytes(16),
        "tag": bytes(16),
        "aad": b"",
        "pt_expected": bytes(16),
        "test_passed": False,
        "tag_len_bits": 128,
    }
    # No exception: expected rejection of an invalid tag.
    runner.run_gcm_decrypt_test(_AeadSession(), "tc-invalid", vec)
