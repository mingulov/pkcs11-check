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
from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.security import test_parameter_validation as pv


class _Rs:
    raw = object()
    sh = 1

    @staticmethod
    def has_mechanism(_name: str) -> bool:
        return True


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sign: Any,
    verify: Any,
    local_result: bool | BaseException = True,
) -> None:
    monkeypatch.setattr(pv, "gen_rsa_keypair", lambda *a, **k: (11, 22))
    monkeypatch.setattr(pv, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(pv, "sign_single", sign)
    monkeypatch.setattr(pv, "verify_single", verify)
    monkeypatch.setattr(
        pv,
        "read_rsa_public_key_or_xfail",
        lambda *_a, **_k: object(),
        raising=False,
    )

    def _local(*_args: Any, **_kwargs: Any) -> bool:
        if isinstance(local_result, BaseException):
            raise local_result
        return local_result

    monkeypatch.setattr(pv, "rsa_pss_local", _local, raising=False)


def _run() -> None:
    pv.TestPssSaltLength().test_pss_zero_salt_length(_Rs(), 0)


def test_sln0_accepted_and_verifies_is_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """A module that signs sLen=0 and the signature verifies is CORRECT."""
    _wire(monkeypatch, sign=lambda *a, **k: b"sig", verify=lambda *a, **k: True)
    _run()  # no exception


def test_sln0_module_self_verify_cannot_mask_wrong_salt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _wire(
        monkeypatch,
        sign=lambda *a, **k: b"sig",
        verify=lambda *a, **k: True,
        local_result=False,
    )
    with pytest.raises(pytest.fail.Exception, match="local cross-verify"):
        _run()


def test_sln0_local_verifier_failure_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(
        monkeypatch,
        sign=lambda *a, **k: b"sig",
        verify=lambda *a, **k: True,
        local_result=RuntimeError("local verifier bug"),
    )
    with pytest.raises(RuntimeError, match="local verifier bug"):
        _run()


def test_sln0_public_key_export_failure_is_visible(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, sign=lambda *a, **k: b"sig", verify=lambda *a, **k: True)
    monkeypatch.setattr(
        pv,
        "read_rsa_public_key_or_xfail",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("public export bug")),
    )
    with pytest.raises(RuntimeError, match="public export bug"):
        _run()


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


def test_sln0_advertised_sign_function_failed_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _reject(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_FUNCTION_FAILED", int(CKR_FUNCTION_FAILED))

    _wire(monkeypatch, sign=_reject, verify=lambda *a, **k: True)
    with pytest.raises(pytest.xfail.Exception, match="CKR_FUNCTION_FAILED"):
        _run()


def test_sln0_advertised_verify_function_not_supported_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _reject(*_a: Any, **_k: Any) -> bool:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED", int(CKR_FUNCTION_NOT_SUPPORTED)
        )

    _wire(monkeypatch, sign=lambda *a, **k: b"sig", verify=_reject)
    with pytest.raises(pytest.xfail.Exception, match="verify is not operational"):
        _run()
