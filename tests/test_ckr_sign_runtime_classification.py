"""Runtime classification meta-tests for ckr/test_ckr_sign Type-A reclassification.

Accepting an AES key under an RSA signing mechanism is key-type confusion (a
crypto-correctness break). The test must classify CKR_OK as fail via the 3-way
assert_ckr instead of a compliance.note(), pass on the expected reject, and
xfail on another clean reject.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_OK,
)
from pkcs11_check.testcases.ckr import test_ckr_sign


def _session(sign_init_rv: int) -> SimpleNamespace:
    raw = SimpleNamespace(C_SignInit=lambda *_a, **_k: int(sign_init_rv))
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda name: True)


def _run(monkeypatch: pytest.MonkeyPatch, sign_init_rv: int) -> None:
    monkeypatch.setattr(test_ckr_sign, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ckr_sign, "destroy_quietly", lambda *_a, **_k: None)
    test_ckr_sign.TestSignInitErrors().test_key_type_inconsistent(
        _session(sign_init_rv), ckr_strict=False
    )


def test_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed):
        _run(monkeypatch, int(CKR_OK))


def test_expected_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, int(CKR_KEY_TYPE_INCONSISTENT))


def test_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, int(CKR_DEVICE_ERROR))
