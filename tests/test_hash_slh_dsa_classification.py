"""Classification meta-tests for test_hash_slh_dsa sign leg (Phase 5 P1b).

The HASH_SLH_DSA produce-leg guards used to ``pytest.xfail`` on *any*
AssertionError, hiding a non-CKR failure. They now xfail only on a known clean
reject CKR (mirroring test_hash_ml_dsa); a non-CKR error propagates.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases import test_hash_slh_dsa as ths


class _RawSession:
    raw = object()
    sh = 1
    slot_id = 0

    @staticmethod
    def has_mechanism(_n: str) -> bool:
        return True


def _patch(monkeypatch: pytest.MonkeyPatch, *, sign_exc: BaseException) -> None:
    monkeypatch.setattr(ths, "_generate_slh_dsa_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(ths, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(ths, "mech_hash_sign_context", lambda *_a, **_k: None)

    def _raise(*_a: Any, **_k: Any) -> bytes:
        raise sign_exc

    monkeypatch.setattr(ths, "sign_single", _raise)


def test_sign_clean_ckr_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    exc = CkrAssertionError("CKR_FUNCTION_NOT_SUPPORTED", int(CKR_FUNCTION_NOT_SUPPORTED))
    _patch(monkeypatch, sign_exc=exc)
    with pytest.raises(XFailed):
        ths.TestHashSLHDSAGeneric().test_sign_verify_roundtrip(_RawSession())


def test_sign_non_ckr_error_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, sign_exc=AssertionError("python decoder bug, no CKR"))
    with pytest.raises(AssertionError, match="decoder bug") as ei:
        ths.TestHashSLHDSAGeneric().test_sign_verify_roundtrip(_RawSession())
    assert not isinstance(ei.value, XFailed)


def test_keygen_capability_is_checked_by_actual_name(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[bytes] = []
    monkeypatch.setattr(ths, "_generate_slh_dsa_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(ths, "destroy_quietly", lambda *_a, **_k: None)

    def _sign(*args: Any, **_kwargs: Any) -> bytes:
        seen.append(args[4])
        return b"sig"

    monkeypatch.setattr(ths, "sign_single", _sign)
    monkeypatch.setattr(ths, "verify_single", lambda *_a, **_k: True)

    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in {"HASH_SLH_DSA", "SLH_DSA_KEY_PAIR_GEN"},
    )
    ths.TestHashSLHDSAGeneric().test_sign_verify_roundtrip(rs)
    assert len(seen) == 1
    assert len(seen[0]) == 32
