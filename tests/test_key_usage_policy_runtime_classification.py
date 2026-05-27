"""Runtime classification meta-tests for test_key_usage_policy (Phase 4 N2).

Key-usage-policy guards check that a usage-restricted key rejects the forbidden
function. Converted from a flat ``assert rv in _KEY_POLICY_CKRS`` to a 3-way
``classify_negative_rv``:

- ``CKR_OK`` (the module ran the forbidden function) -> ``fail``,
- ``CKR_KEY_FUNCTION_NOT_PERMITTED`` (spec) -> ``pass``,
- any other clean reject code -> ``xfail`` (honest non-spec deviation).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKR_DEVICE_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_OK,
)
from pkcs11_check.testcases import test_key_usage_policy as tkup


def _session(encrypt_init_rv: int) -> SimpleNamespace:
    def _encrypt_init(*_a: object, **_k: object) -> int:
        return int(encrypt_init_rv)

    raw = SimpleNamespace(C_EncryptInit=_encrypt_init)
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda n: True)


def _run(monkeypatch: pytest.MonkeyPatch, encrypt_init_rv: int) -> None:
    monkeypatch.setattr(tkup, "require_operational_aes_keygen", lambda *_a: None)
    monkeypatch.setattr(tkup, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(tkup, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tkup, "read_attributes", lambda *_a, **_k: {CKA_DECRYPT: True})
    tkup.TestAESKeyUsagePolicy().test_decrypt_only_key_cannot_encrypt(_session(encrypt_init_rv))


def test_forbidden_op_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_spec_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, int(CKR_KEY_FUNCTION_NOT_PERMITTED))


def test_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, int(CKR_DEVICE_ERROR))
