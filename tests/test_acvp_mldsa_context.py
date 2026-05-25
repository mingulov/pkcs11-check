"""Regression tests for ACVP ML-DSA context handling."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from pkcs11_check.raw.types_std import CKP_ML_DSA_44
from pkcs11_check.testcases.acvp import test_acvp_mldsa


def test_mldsa_siggen_roundtrip_verify_reuses_non_empty_context(
    monkeypatch: Any,
) -> None:
    seen: dict[str, object | None] = {}
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)
    vec = {
        "pre_hash": "pure",
        "context": b"domain-separation",
        "sk": b"private-key",
        "pk": b"public-key",
        "msg": b"message",
        "parameter_set": int(CKP_ML_DSA_44),
        "param_set": "ML-DSA-44",
    }

    monkeypatch.setattr(test_acvp_mldsa, "import_pqc_private_key", lambda *_a, **_kw: 10)
    monkeypatch.setattr(test_acvp_mldsa, "import_pqc_public_key", lambda *_a, **_kw: 11)
    monkeypatch.setattr(test_acvp_mldsa, "destroy_quietly", lambda *_a, **_kw: None)

    def _sign(*_args: Any, mech_param: object | None = None, **_kwargs: Any) -> bytes:
        seen["sign_param"] = mech_param
        return b"signature"

    def _verify(*_args: Any, mech_param: object | None = None, **_kwargs: Any) -> bool:
        seen["verify_param"] = mech_param
        return True

    monkeypatch.setattr(test_acvp_mldsa, "sign_single", _sign)
    monkeypatch.setattr(test_acvp_mldsa, "verify_single", _verify)

    test_acvp_mldsa.TestMlDsaSigGen().test_mldsa_siggen(rs, "ML-DSA-sigGen-context", vec)

    assert seen["sign_param"] is not None
    assert seen["verify_param"] is seen["sign_param"]
