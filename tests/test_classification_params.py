"""classify() carries a structured ``params`` map (curve/key-size/hash) to the record."""

from __future__ import annotations

import pytest

from pkcs11_check import classification as C


def test_classify_records_params() -> None:
    C.clear()
    with pytest.raises(BaseException):  # noqa: B017,PT011 - classify() raises the pytest outcome
        C.classify(
            "not_operational",
            mechanism="CKM_ECDSA",
            operation="C_Verify",
            params={"curve": "brainpoolP224r1"},
        )
    recs = C.serialize(C.get_records())
    assert recs[0]["params"] == {"curve": "brainpoolP224r1"}


def test_params_default_none() -> None:
    C.clear()
    with pytest.raises(BaseException):  # noqa: B017,PT011
        C.classify("wrong_result", kind="crypto", mechanism="CKM_RSA_PKCS", operation="C_Decrypt")
    recs = C.serialize(C.get_records())
    assert recs[0]["params"] is None


def test_active_params_inherited_by_classify() -> None:
    C.clear()
    C.set_params({"curve": "secp256k1"})
    with pytest.raises(BaseException):  # noqa: B017,PT011
        C.classify("not_operational", mechanism="CKM_ECDSA", operation="C_Verify")
    assert C.serialize(C.get_records())[0]["params"] == {"curve": "secp256k1"}


def test_explicit_params_override_active() -> None:
    C.clear()
    C.set_params({"curve": "secp256k1"})
    with pytest.raises(BaseException):  # noqa: B017,PT011
        C.classify("wrong_result", kind="crypto", params={"curve": "p256"})
    assert C.serialize(C.get_records())[0]["params"] == {"curve": "p256"}


def test_clear_resets_active_params() -> None:
    C.set_params({"curve": "x"})
    C.clear()
    with pytest.raises(BaseException):  # noqa: B017,PT011
        C.classify("wrong_result", kind="crypto")
    assert C.serialize(C.get_records())[0]["params"] is None


def test_set_params_normalizes_curve_aliases() -> None:
    # cross-family curve forms must canonicalize so the report's per-curve buckets
    # don't fragment (P-256 vs secp256r1, brainpoolP vs brainpoolp, ED-25519 vs ed25519)
    cases = [
        ("P-256", "secp256r1"),
        ("P-256K", "secp256k1"),
        ("P-384", "secp384r1"),
        ("ED-25519", "ed25519"),
        ("ED-448", "ed448"),
        ("brainpoolP224r1", "brainpoolp224r1"),
        ("secp256r1", "secp256r1"),
        ("ed25519", "ed25519"),
    ]
    for raw, canon in cases:
        C.clear()
        C.set_params({"curve": raw})
        with pytest.raises(BaseException):  # noqa: B017,PT011
            C.classify("not_operational", mechanism="CKM_ECDSA")
        assert C.serialize(C.get_records())[0]["params"] == {"curve": canon}, raw
