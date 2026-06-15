"""Runtime classification meta-tests for test_verify_signature reject guards (Phase 4 N2).

The wrong-signature and wrong-key verify guards check that verification rejects.
Converted from a flat ``assert rv in {set}`` to a 3-way ``classify_negative_rv``:

- ``CKR_OK`` (a forged/mismatched signature verified) -> ``fail`` (crypto break),
- a spec-acceptable reject code -> ``pass``,
- any other clean reject code -> ``xfail``.

(For wrong-key, the CKR_OK init-time silent-acceptance is handled above as a
documented CRITICAL xfail; this guard covers the reject path.)
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
)
from pkcs11_check.testcases import test_verify_signature as tvs


def _session(*, init_rv: int = 0, verify_rv: int = 0) -> SimpleNamespace:
    raw = SimpleNamespace(
        C_VerifySignatureInit=lambda *_a, **_k: int(init_rv),
        C_VerifySignature=lambda *_a, **_k: int(verify_rv),
    )
    return SimpleNamespace(
        raw=raw, sh=1, has_mechanism=lambda n: True, has_mechanism_flag=lambda _m, _f: True
    )


# --- wrong-signature guard (verify-time) ---------------------------------


def _run_wrong_sig(monkeypatch: pytest.MonkeyPatch, verify_rv: int) -> None:
    monkeypatch.setattr(tvs, "gen_rsa_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(tvs, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        tvs.TestVerifySignatureRoundtrip, "_skip_unless_available", staticmethod(lambda _rs: None)
    )
    tvs.TestVerifySignatureRoundtrip().test_verify_signature_wrong_sig(
        _session(init_rv=int(CKR_OK), verify_rv=verify_rv)
    )


def test_wrong_sig_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_wrong_sig(monkeypatch, int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_wrong_sig_spec_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_wrong_sig(monkeypatch, int(CKR_SIGNATURE_INVALID))


def test_wrong_sig_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_wrong_sig(monkeypatch, int(CKR_GENERAL_ERROR))


# --- wrong-key guard (init-time reject path) -----------------------------


def _run_wrong_key(monkeypatch: pytest.MonkeyPatch, init_rv: int) -> None:
    monkeypatch.setattr(tvs, "gen_rsa_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(tvs, "sign_single", lambda *_a, **_k: b"\x01" * 256)
    monkeypatch.setattr(tvs, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        tvs.TestVerifySignatureRoundtrip, "_skip_unless_available", staticmethod(lambda _rs: None)
    )
    tvs.TestVerifySignatureRoundtrip().test_verify_signature_wrong_key(_session(init_rv=init_rv))


def test_wrong_key_spec_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_wrong_key(monkeypatch, int(CKR_KEY_HANDLE_INVALID))


def test_wrong_key_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_wrong_key(monkeypatch, int(CKR_GENERAL_ERROR))
