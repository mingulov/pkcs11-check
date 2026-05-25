"""Regression tests for ACVP SLH-DSA runtime-result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR
from pkcs11_check.testcases.acvp import test_acvp_slhdsa


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SLH_DSA")


def _device_error(*_args: Any, **_kwargs: Any) -> int:
    raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))


def test_slhdsa_valid_sigver_runtime_reject_has_valid_signature_xfail_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec = {
        "param_set": 1,
        "param_name": "SLH-DSA-SHA2-128f",
        "pk": b"public",
        "msg": b"message",
        "sig": b"signature",
        "expected_pass": True,
    }
    monkeypatch.setattr(test_acvp_slhdsa, "import_pqc_public_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_acvp_slhdsa, "verify_single", _device_error)
    monkeypatch.setattr(test_acvp_slhdsa, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="valid SLH-DSA signature"):
        test_acvp_slhdsa.test_slhdsa_sigver(
            _session(),
            "sigVer-SLH-DSA-SHA2-128f-tc2",
            vec,
        )


def test_slhdsa_siggen_runtime_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    vec = {
        "param_set": 1,
        "param_name": "SLH-DSA-SHA2-128f",
        "sk": b"private",
        "msg": b"message",
    }
    monkeypatch.setattr(test_acvp_slhdsa, "import_pqc_private_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_acvp_slhdsa, "sign_single", _device_error)
    monkeypatch.setattr(test_acvp_slhdsa, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="SLH-DSA.*operation"):
        test_acvp_slhdsa.test_slhdsa_siggen(
            _session(),
            "sigGen-SLH-DSA-SHA2-128f-tc1",
            vec,
        )
