"""Runtime classification meta-test for test_errors wrong-mechanism verify (crypto).

A signature produced under SHA256-RSA verified under SHA384-RSA that returns
CKR_OK accepts a signature over the wrong message digest -- a crypto-correctness
break. The probe must classify CKR_OK as fail, the expected reject as pass, and
another clean reject as xfail (replacing the prior silent `if rv == CKR_OK: pass`).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_FAILED,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
)
from pkcs11_check.testcases import test_errors


def _session(verify_rv: int) -> SimpleNamespace:
    raw = SimpleNamespace(
        C_VerifyInit=lambda *_a, **_k: int(CKR_OK),
        C_Verify=lambda *_a, **_k: int(verify_rv),
    )
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda name: True)


def _run(monkeypatch: pytest.MonkeyPatch, verify_rv: int) -> None:
    monkeypatch.setattr(test_errors, "skip_unless_mechanism", lambda *_a, **_k: None)
    monkeypatch.setattr(test_errors, "_gen_rsa_keypair_or_xfail", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(test_errors, "sign_single", lambda *_a, **_k: b"\x00" * 256)
    monkeypatch.setattr(test_errors, "destroy_quietly", lambda *_a, **_k: None)
    test_errors.TestInvalidOperations().test_verify_with_wrong_mechanism(_session(verify_rv))


def test_wrong_mech_verify_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed):
        _run(monkeypatch, int(CKR_OK))


def test_wrong_mech_verify_expected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, int(CKR_SIGNATURE_INVALID))


def test_wrong_mech_verify_other_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    # CKR_FUNCTION_FAILED is in _VERIFY_MISMATCH_RVS? No -- it is not, so it is a
    # clean non-expected reject -> xfail.
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, int(CKR_FUNCTION_FAILED))
