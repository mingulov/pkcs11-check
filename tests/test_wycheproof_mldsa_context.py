"""Regression tests for Wycheproof ML-DSA context handling."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from pkcs11_check.testcases.wycheproof import test_wycheproof_mldsa


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
