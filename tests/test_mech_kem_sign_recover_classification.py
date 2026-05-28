"""Classification meta-tests for test_mech_kem / test_mech_sign_recover (Phase 5 P1b).

The produce-leg (encapsulate / sign-recover) now xfails only on a known clean
"advertised but not operational" reject CKR; a non-CKR error propagates. The
dependent roundtrip that follows remains a hard failure (self-contradiction).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases import test_mech_kem as tmk
from pkcs11_check.testcases import test_mech_sign_recover as tmsr


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, slot_id=0, has_mechanism=lambda _n: True)


def test_kem_encapsulate_clean_ckr_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tmk, "_ml_kem_keypair", lambda _rs: (1, 2))
    monkeypatch.setattr(tmk, "destroy_quietly", lambda *_a, **_k: None)

    def _raise(*_a: Any, **_k: Any) -> tuple[int, bytes]:
        raise CkrAssertionError("CKR_FUNCTION_NOT_SUPPORTED", int(CKR_FUNCTION_NOT_SUPPORTED))

    monkeypatch.setattr(tmk, "encapsulate_key", _raise)
    with pytest.raises(XFailed):
        tmk.TestMechKEM().test_ml_kem_roundtrip(_session())


def test_kem_encapsulate_non_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tmk, "_ml_kem_keypair", lambda _rs: (1, 2))
    monkeypatch.setattr(tmk, "destroy_quietly", lambda *_a, **_k: None)

    def _raise(*_a: Any, **_k: Any) -> tuple[int, bytes]:
        raise AssertionError("python bug, no CKR")

    monkeypatch.setattr(tmk, "encapsulate_key", _raise)
    with pytest.raises(AssertionError, match="python bug") as ei:
        tmk.TestMechKEM().test_ml_kem_roundtrip(_session())
    assert not isinstance(ei.value, XFailed)


def test_sign_recover_clean_ckr_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tmsr, "_rsa_x509_keypair", lambda _rs: (1, 2))
    monkeypatch.setattr(tmsr, "destroy_quietly", lambda *_a, **_k: None)

    def _raise(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError("CKR_FUNCTION_NOT_SUPPORTED", int(CKR_FUNCTION_NOT_SUPPORTED))

    monkeypatch.setattr(tmsr, "sign_recover_single", _raise)
    with pytest.raises(XFailed):
        tmsr.TestSignRecover().test_rsa_x509_sign_recover_roundtrip(_session())


def test_sign_recover_non_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tmsr, "_rsa_x509_keypair", lambda _rs: (1, 2))
    monkeypatch.setattr(tmsr, "destroy_quietly", lambda *_a, **_k: None)

    def _raise(*_a: Any, **_k: Any) -> bytes:
        raise AssertionError("python bug, no CKR")

    monkeypatch.setattr(tmsr, "sign_recover_single", _raise)
    with pytest.raises(AssertionError, match="python bug") as ei:
        tmsr.TestSignRecover().test_rsa_x509_sign_recover_roundtrip(_session())
    assert not isinstance(ei.value, XFailed)
