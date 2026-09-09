"""test_ec_curves uses skip_unless_capability for CKM_ECDSA sign."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKA_KEY_TYPE, CKF_SIGN
from pkcs11_check.testcases import test_ec_curves as mod


@pytest.fixture(autouse=True)
def _clear_classifications() -> None:
    C.clear()
    yield
    C.clear()


def test_ecdsa_gate_uses_skip_unless_capability_with_ckf_sign(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Any, ...]] = []

    def _skip_unless(rs: Any, mechanism: int, **kw: Any) -> None:
        calls.append((mechanism, kw))
        pytest.skip("gated")

    monkeypatch.setattr(mod, "skip_unless_capability", _skip_unless)
    rs = SimpleNamespace(raw=object(), sh=1, slot_id=0, has_mechanism=lambda _n: True)

    with pytest.raises(pytest.skip.Exception):
        mod.TestECDSACrossVerify().test_ecdsa_sign_p11_verify_crypto(
            rs, "secp256r1", 32, ec.SECP256R1(), hashes.SHA256()
        )
    assert calls and calls[0][1].get("operation") == CKF_SIGN


def test_ec_key_type_collects_both_missing_fields_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(mod, "_try_gen_ec", lambda *_a: (11, 12))
    monkeypatch.setattr(mod, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(mod, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    mod.TestECKeygen().test_ec_key_type(
        SimpleNamespace(raw=object(), sh=1), "secp256r1", 32, None, None
    )

    assert destroyed == [11, 12]
    assert [rec.detail["attribute"]["id"] for rec in C.get_records() if rec.detail] == [
        int(CKA_KEY_TYPE),
        int(CKA_KEY_TYPE),
    ]


def test_missing_public_key_type_does_not_hide_private_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mod, "_try_gen_ec", lambda *_a: (13, 14))

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, int]:
        return {} if handle == 13 else {CKA_KEY_TYPE: 0xDEADBEEF}

    monkeypatch.setattr(mod, "read_attributes", _read)
    monkeypatch.setattr(mod, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="CKA_KEY_TYPE"):
        mod.TestECKeygen().test_ec_key_type(
            SimpleNamespace(raw=object(), sh=1), "secp256r1", 32, None, None
        )

    assert [rec.reason for rec in C.get_records()] == [
        "honest_deviation",
        "self_contradiction",
    ]


def test_crossverify_reads_provider_point_with_explicit_curve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    curve = ec.SECP256R1()
    private_key = ec.generate_private_key(curve)
    calls: list[ec.EllipticCurve] = []

    def _read_key(_rs: Any, _handle: int, selected: ec.EllipticCurve, **_kw: Any):
        calls.append(selected)
        return private_key.public_key()

    def _sign(*_args: Any, **_kwargs: Any) -> bytes:
        der = private_key.sign(b"ECDSA secp256r1 cross-verify", ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    monkeypatch.setattr(mod, "skip_unless_capability", lambda *_a, **_k: None)
    monkeypatch.setattr(mod, "_try_gen_ec", lambda *_a: (15, 16))
    monkeypatch.setattr(mod, "sign_single", _sign)
    monkeypatch.setattr(mod, "read_ec_public_key_or_xfail", _read_key, raising=False)
    monkeypatch.setattr(mod, "destroy_quietly", lambda *_a: None)

    mod.TestECDSACrossVerify().test_ecdsa_sign_p11_verify_crypto(
        SimpleNamespace(raw=object(), sh=1),
        "secp256r1",
        32,
        curve,
        hashes.SHA256(),
    )

    assert calls == [curve]
