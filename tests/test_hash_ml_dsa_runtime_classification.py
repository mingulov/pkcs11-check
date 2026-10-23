"""Regression tests for advertised Hash-ML-DSA runtime rejects."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKM_SHA256, CKR_DATA_LEN_RANGE, CKR_GENERAL_ERROR
from pkcs11_check.testcases import test_hash_ml_dsa


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in {"HASH_ML_DSA", "ML_DSA_KEY_PAIR_GEN"},
    )


@pytest.mark.parametrize("rv", [CKR_DATA_LEN_RANGE, CKR_GENERAL_ERROR])
def test_hash_ml_dsa_sign_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
) -> None:
    monkeypatch.setattr(test_hash_ml_dsa, "_generate_ml_dsa_keypair", lambda _rs: (10, 11))
    monkeypatch.setattr(test_hash_ml_dsa, "destroy_quietly", lambda *_args: None)

    def _sign_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(f"Unexpected CK_RV {rv!r}", int(rv))

    monkeypatch.setattr(test_hash_ml_dsa, "sign_single", _sign_reject)
    monkeypatch.setattr(
        test_hash_ml_dsa,
        "verify_single",
        lambda *_args, **_kwargs: pytest.fail("verify should not run after sign reject"),
    )

    with pytest.raises(pytest.xfail.Exception, match="CKM_HASH_ML_DSA sign not operational"):
        # test_sign_verify_roundtrip is parametrized over (hash_name, hash_mech) since the
        # multi-hash HASH_ML_DSA change; pass one valid pair. The sign-reject path is
        # hash-independent, so SHA-256 exercises it. The xfail message gained a "(hash_name)"
        # suffix but the substring match above still holds.
        test_hash_ml_dsa.TestHashMLDSAGeneric().test_sign_verify_roundtrip(
            _session(), "SHA-256", CKM_SHA256
        )


def test_keygen_capability_is_checked_by_actual_name(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[bytes] = []
    monkeypatch.setattr(test_hash_ml_dsa, "_generate_ml_dsa_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(test_hash_ml_dsa, "destroy_quietly", lambda *_a, **_k: None)

    def _sign(*args: Any, **_kwargs: Any) -> bytes:
        seen.append(args[4])
        return b"sig"

    monkeypatch.setattr(test_hash_ml_dsa, "sign_single", _sign)
    monkeypatch.setattr(test_hash_ml_dsa, "verify_single", lambda *_a, **_k: True)

    session = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in {"HASH_ML_DSA", "ML_DSA_KEY_PAIR_GEN"},
    )
    test_hash_ml_dsa.TestHashMLDSAGeneric().test_sign_verify_roundtrip(
        session, "SHA-256", CKM_SHA256
    )
    assert len(seen) == 1
    assert len(seen[0]) == 32
