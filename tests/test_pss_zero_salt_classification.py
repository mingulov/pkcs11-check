"""Classification meta-tests for the RSA-PSS sLen=0 probe.

sLen=0 PSS is a STANDARDIZED deterministic variant (RFC 8017 §9.1 / FIPS 186-5)
that produces correct, verifiable, non-forgeable signatures -- accepting it is
NOT a crypto-correctness break. The probe therefore:
  - clean sign-reject  -> xfail (module/policy declines deterministic PSS)
  - sign + verify OK   -> pass  (correct support of a valid variant)
  - sign accepted but the produced signature does NOT verify -> fail (real break)
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_MECHANISM_PARAM_INVALID
from pkcs11_check.testcases.security import test_parameter_validation as pv


class _Rs:
    raw = object()
    sh = 1

    @staticmethod
    def has_mechanism(_name: str) -> bool:
        return True


def _wire(monkeypatch: pytest.MonkeyPatch, *, sign: Any, verify: Any) -> None:
    monkeypatch.setattr(pv, "gen_rsa_keypair", lambda *a, **k: (11, 22))
    monkeypatch.setattr(pv, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(pv, "sign_single", sign)
    monkeypatch.setattr(pv, "verify_single", verify)


def _run() -> None:
    pv.TestPssSaltLength().test_pss_zero_salt_length(_Rs(), 0)


def test_sln0_accepted_and_verifies_is_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """A module that signs sLen=0 and the signature verifies is CORRECT."""
    _wire(monkeypatch, sign=lambda *a, **k: b"sig", verify=lambda *a, **k: True)
    _run()  # no exception


def test_sln0_clean_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """Declining deterministic PSS (clean reject) is a policy deviation, not a finding."""

    def _reject(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID", int(CKR_MECHANISM_PARAM_INVALID)
        )

    _wire(monkeypatch, sign=_reject, verify=lambda *a, **k: True)
    with pytest.raises(pytest.xfail.Exception):
        _run()


def test_sln0_accepted_but_signature_invalid_is_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """Accepting sLen=0 but producing a signature that does NOT verify is a real break."""
    _wire(monkeypatch, sign=lambda *a, **k: b"sig", verify=lambda *a, **k: False)
    with pytest.raises(pytest.fail.Exception, match="does not verify"):
        _run()


def test_sln0_non_clean_sign_reject_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-clean sign reject (e.g. CKR_DEVICE_ERROR) is not a known PSS decline."""

    def _reject(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    _wire(monkeypatch, sign=_reject, verify=lambda *a, **k: True)
    with pytest.raises(CkrAssertionError):
        _run()
