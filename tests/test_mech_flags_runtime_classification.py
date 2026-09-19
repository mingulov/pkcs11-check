"""Runtime classification meta-tests for test_mech_flags flag probes (F-009).

The minimal probe (handle 0, NULL params) cannot carry a FAIL
self-contradiction alone: a lie-RV (CKR_MECHANISM_INVALID /
CKR_FUNCTION_NOT_SUPPORTED) must be strengthened with a valid-key retry:

- retry with a valid key + recipe params also returns a lie-RV -> ``fail``
  (strong operational evidence, summary cites the valid key);
- retry succeeds -> ``pass`` (flag claim holds; the minimal rejection was a
  degenerate-input artifact);
- retry returns another reject -> ``xfail`` (inconclusive, both kept);
- no valid key provisionable (unregistered mechanism, domain params,
  keygen rejected) -> ``xfail`` retaining the minimal rejection.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKF_ENCRYPT,
    CKM_AES_ECB,
    CKR_FUNCTION_FAILED,
    CKR_KEY_HANDLE_INVALID,
    CKR_MECHANISM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases import test_mech_flags as tmf


def _entry(config: Any) -> SimpleNamespace:
    return SimpleNamespace(
        mech_name="AES_ECB",
        mech_id=int(CKM_AES_ECB),
        flags=int(CKF_ENCRYPT),
        min_key_size=128,
        max_key_size=256,
        config=config,
    )


def _run_encrypt(
    monkeypatch: pytest.MonkeyPatch,
    *,
    minimal_rv: int | None,
    retry_rv: int | None = None,
    config: Any = SimpleNamespace(),
    provision_keys: tuple[int, int | None] = (11, None),
) -> None:
    scripted = [minimal_rv] if retry_rv is None else [minimal_rv, retry_rv]
    queue = [int(v) for v in scripted if v is not None]

    def _init(*args: Any, **kwargs: Any) -> int:
        return queue.pop(0)

    raw = SimpleNamespace(
        C_EncryptInit=_init,
        C_EncryptFinal=lambda *_a, **_k: int(CKR_OK),
    )
    if minimal_rv is None:
        raw = SimpleNamespace(C_EncryptFinal=lambda *_a, **_k: int(CKR_OK))
    monkeypatch.setattr(
        tmf, "generate_key_for_encrypt", lambda *_a, **_k: provision_keys, raising=False
    )
    monkeypatch.setattr(tmf, "make_mech_param_or_skip", lambda *_a, **_k: None, raising=False)
    monkeypatch.setattr(tmf, "destroy_quietly", lambda *_a, **_k: None, raising=False)
    tmf.TestMechFlagBehavioralConformance().test_encrypt_flag_callable(
        SimpleNamespace(raw=raw, sh=1), _entry(config)
    )


def test_minimal_lie_retry_lie_fails_with_valid_key_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F-009: lie-RV on the valid-key retry is strong -> fail citing the key."""
    with pytest.raises(Failed, match="valid key") as ei:
        _run_encrypt(
            monkeypatch,
            minimal_rv=int(CKR_MECHANISM_INVALID),
            retry_rv=int(CKR_MECHANISM_INVALID),
        )
    assert not isinstance(ei.value, XFailed)


def test_minimal_lie_retry_ok_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-009: retry success proves the flag honest -> pass."""
    _run_encrypt(
        monkeypatch,
        minimal_rv=int(CKR_MECHANISM_INVALID),
        retry_rv=int(CKR_OK),
    )


def test_minimal_lie_unprovisionable_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-009: no registry config -> cannot strengthen -> xfail, never fail."""
    with pytest.raises(pytest.xfail.Exception):
        _run_encrypt(
            monkeypatch,
            minimal_rv=int(CKR_MECHANISM_INVALID),
            config=None,
        )


def test_minimal_lie_retry_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-009: inconclusive retry -> xfail retaining both observations."""
    with pytest.raises(pytest.xfail.Exception):
        _run_encrypt(
            monkeypatch,
            minimal_rv=int(CKR_MECHANISM_INVALID),
            retry_rv=int(CKR_FUNCTION_FAILED),
        )


def test_minimal_key_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-lie minimal rejection still passes (mech accepted, key irrelevant)."""
    _run_encrypt(monkeypatch, minimal_rv=int(CKR_KEY_HANDLE_INVALID))


def test_minimal_missing_fn_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.skip.Exception):
        _run_encrypt(monkeypatch, minimal_rv=None)
