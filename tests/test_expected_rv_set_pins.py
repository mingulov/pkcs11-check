"""Expected-RV set pins: the "never widen" gate for the M-15 slice (H-4 starter).

``_VERIFY_MISMATCH_RVS`` and ``_DECRYPT_GARBAGE_RVS`` in
``testcases/test_errors.py`` previously passed generic codes
(``CKR_GENERAL_ERROR``, ``CKR_DEVICE_ERROR``, ``CKR_DATA_LEN_RANGE``) as
spec-correct for conditions whose spec code is exact. They are narrowed to
the spec codes; anything else is a recorded ``nonspec_reject`` xfail, never
a silent pass. These pins fail if anyone re-widens the sets.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_GENERAL_ERROR,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
)
from pkcs11_check.testcases import test_errors


def test_verify_mismatch_set_is_pinned_to_spec_codes() -> None:
    """M-15: cross-mechanism verify mismatch expects only the signature codes."""
    assert test_errors._VERIFY_MISMATCH_RVS == {
        CKR_SIGNATURE_INVALID,
        CKR_SIGNATURE_LEN_RANGE,
    }


def test_decrypt_garbage_set_is_pinned_to_spec_codes() -> None:
    """M-15: RSA garbage decrypt expects only the encrypted-data codes."""
    assert test_errors._DECRYPT_GARBAGE_RVS == {
        CKR_ENCRYPTED_DATA_INVALID,
        CKR_ENCRYPTED_DATA_LEN_RANGE,
    }


def _wrong_mech_session(verify_rv: int) -> Any:
    raw = SimpleNamespace(
        C_VerifyInit=lambda *_a, **_k: int(CKR_OK),
        C_Verify=lambda *_a, **_k: int(verify_rv),
    )
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda name: True)


def _run_wrong_mech_verify(monkeypatch: pytest.MonkeyPatch, verify_rv: int) -> None:
    monkeypatch.setattr(test_errors, "skip_unless_mechanism", lambda *_a, **_k: None)
    monkeypatch.setattr(test_errors, "_gen_rsa_keypair_or_xfail", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(test_errors, "sign_single", lambda *_a, **_k: b"\x00" * 256)
    monkeypatch.setattr(test_errors, "destroy_quietly", lambda *_a, **_k: None)
    test_errors.TestInvalidOperations().test_verify_with_wrong_mechanism(
        _wrong_mech_session(verify_rv)
    )


@pytest.mark.parametrize("rv", [int(CKR_GENERAL_ERROR), int(CKR_DEVICE_ERROR)])
def test_verify_mismatch_generic_error_xfails_not_passes(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    """A module reporting crypto failure as a generic error is a noted deviation."""
    with pytest.raises(pytest.xfail.Exception):
        _run_wrong_mech_verify(monkeypatch, rv)


def test_verify_mismatch_len_range_still_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The spec length variant stays in the expected set."""
    _run_wrong_mech_verify(monkeypatch, int(CKR_SIGNATURE_LEN_RANGE))


def test_decrypt_init_data_len_range_xfails_not_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """M-15: CKR_DATA_LEN_RANGE at C_DecryptInit is a noted deviation, not a pass."""
    monkeypatch.setattr(test_errors, "gen_rsa_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(test_errors, "destroy_quietly", lambda *_a, **_k: None)
    raw = SimpleNamespace(C_DecryptInit=lambda *_a, **_k: int(CKR_DATA_LEN_RANGE))
    rs = SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda name: True)
    with pytest.raises(pytest.xfail.Exception):
        test_errors.TestInvalidOperations().test_decrypt_garbage(rs)
