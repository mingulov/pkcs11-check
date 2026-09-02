"""Regression tests for Wycheproof ML-DSA context handling."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKP_ML_DSA_44, CKR_GENERAL_ERROR, CKR_SIGNATURE_INVALID
from pkcs11_check.testcases.wycheproof import (
    test_wycheproof_mldsa,
)
from pkcs11_check.testcases.wycheproof import (
    test_wycheproof_mldsa_context as mldsa_context,
)


def test_mldsa_verify_passes_non_empty_context(monkeypatch: Any) -> None:
    seen: dict[str, object | None] = {}
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)
    vec = {
        "_group": {"publicKey": "01" * 1312},
        "_param_set": 44,
        "_file": "mldsa_44_verify_test.json",
        "msg": "6d657373616765",
        "ctx": "646f6d61696e",
        "sig": "02" * 2420,
        "result": "valid",
        "flags": ["ValidSignature"],
    }

    monkeypatch.setattr(test_wycheproof_mldsa, "import_pqc_public_key", lambda *_a, **_kw: 10)
    monkeypatch.setattr(test_wycheproof_mldsa, "destroy_quietly", lambda *_a, **_kw: None)

    def _verify(*_args: Any, mech_param: object | None = None, **_kwargs: Any) -> bool:
        seen["verify_param"] = mech_param
        return True

    monkeypatch.setattr(test_wycheproof_mldsa, "verify_single", _verify)

    test_wycheproof_mldsa.test_mldsa_verify(
        rs,
        "mldsa_44_verify_test.json:tc3-valid",
        vec,
    )

    assert seen["verify_param"] is not None


def test_mldsa_verify_omits_empty_context(monkeypatch: Any) -> None:
    seen: dict[str, object | None] = {}
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)
    vec = {
        "_group": {"publicKey": "01" * 1312},
        "_param_set": 44,
        "_file": "mldsa_44_verify_test.json",
        "msg": "6d657373616765",
        "ctx": "",
        "sig": "02" * 2420,
        "result": "valid",
        "flags": ["ValidSignature"],
    }

    monkeypatch.setattr(test_wycheproof_mldsa, "import_pqc_public_key", lambda *_a, **_kw: 10)
    monkeypatch.setattr(test_wycheproof_mldsa, "destroy_quietly", lambda *_a, **_kw: None)

    def _verify(*_args: Any, mech_param: object | None = None, **_kwargs: Any) -> bool:
        seen["verify_param"] = mech_param
        return True

    monkeypatch.setattr(test_wycheproof_mldsa, "verify_single", _verify)

    test_wycheproof_mldsa.test_mldsa_verify(
        rs,
        "mldsa_44_verify_test.json:tc1-valid",
        vec,
    )

    assert seen["verify_param"] is None


def _context_vector() -> dict[str, Any]:
    return {
        "_private_key": "01",
        "_public_key": "02",
        "_param_set": CKP_ML_DSA_44,
        "msg": "6d7367",
        "ctx": "646f6d61696e",
        "sig": "03",
        "flags": [],
    }


def test_mldsa_cross_context_unexpected_ckr_is_visible(monkeypatch: Any) -> None:
    """A non-signature CKR must not be treated as a successful mismatch reject."""
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)
    monkeypatch.setattr(mldsa_context, "_import_keys", lambda *_a, **_k: (10, 11))
    monkeypatch.setattr(mldsa_context, "_context_signing_operational", lambda *_a: True)
    monkeypatch.setattr(mldsa_context, "destroy_quietly", lambda *_a, **_k: None)
    calls = 0

    def _verify(*_args: Any, **_kwargs: Any) -> bool:
        nonlocal calls
        calls += 1
        if calls == 1:
            return True
        raise CkrAssertionError("unexpected cross-context CKR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(mldsa_context, "verify_single", _verify)

    with pytest.raises(pytest.xfail.Exception):
        mldsa_context.test_mldsa_context("synthetic:tc1", _context_vector(), rs)


def test_mldsa_cross_context_signature_reject_is_accepted(monkeypatch: Any) -> None:
    """The canonical signature-invalid CKR is the only clean mismatch reject."""
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)
    monkeypatch.setattr(mldsa_context, "_import_keys", lambda *_a, **_k: (10, 11))
    monkeypatch.setattr(mldsa_context, "_context_signing_operational", lambda *_a: True)
    monkeypatch.setattr(mldsa_context, "destroy_quietly", lambda *_a, **_k: None)
    calls = 0

    def _verify(*_args: Any, **_kwargs: Any) -> bool:
        nonlocal calls
        calls += 1
        if calls == 1:
            return True
        raise CkrAssertionError("signature mismatch", int(CKR_SIGNATURE_INVALID))

    monkeypatch.setattr(mldsa_context, "verify_single", _verify)

    mldsa_context.test_mldsa_context("synthetic:tc1", _context_vector(), rs)
