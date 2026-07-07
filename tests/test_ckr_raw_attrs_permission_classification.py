"""Runtime classification meta-tests for ckr/test_ckr_raw_attrs permission flags (policy).

CKA_ENCRYPT=False / CKA_DECRYPT=False enforcement, exercised in a subprocess.
The outer test parses the subprocess output and applies a policy claim/effect-check:
claimed = the key reads back the permission flag as False; violated = the
corresponding C_*Init still returned CKR_OK -> fail; not claimed -> xfail.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.testcases.ckr import test_ckr_raw_attrs as tra


def _cfg() -> Any:
    return type("Cfg", (), {"module": "x", "pin": None})()


def _patch_run(monkeypatch: pytest.MonkeyPatch, out: str) -> None:
    def fake_run_probe(probe: str, params: Any, **_kwargs: Any) -> SimpleNamespace:
        assert probe == "ckr_raw_attrs"
        assert params["probe"] in ("encrypt", "sign", "decrypt")
        return SimpleNamespace(returncode=0, stdout=out, stderr="")

    monkeypatch.setattr(tra, "run_probe", fake_run_probe)
    monkeypatch.setattr(tra, "assert_ckr_subprocess_ok", lambda *_a, **_k: None)


_ENC_OK = "CLAIM:0\nCKR:0x00000000\nOK"
_ENC_CLAIMED_REJECTED = "CLAIM:0\nCKR:0x00000068\nOK"  # KEY_FUNCTION_NOT_PERMITTED
_ENC_NOT_CLAIMED = "CLAIM:1\nCKR:0x00000000\nOK"


def test_encrypt_claimed_violated_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _ENC_OK)
    with pytest.raises(Failed) as ei:
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())
    assert not isinstance(ei.value, XFailed)


def test_encrypt_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _ENC_NOT_CLAIMED)
    with pytest.raises(pytest.xfail.Exception):
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())


def test_encrypt_claimed_enforced_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _ENC_CLAIMED_REJECTED)
    tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())


def test_decrypt_claimed_violated_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _ENC_OK)
    with pytest.raises(Failed) as ei:
        tra.TestKeyFunctionNotPermitted().test_decrypt_not_permitted(_cfg())
    assert not isinstance(ei.value, XFailed)


def test_decrypt_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _ENC_NOT_CLAIMED)
    with pytest.raises(pytest.xfail.Exception):
        tra.TestKeyFunctionNotPermitted().test_decrypt_not_permitted(_cfg())


def test_decrypt_claimed_enforced_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _ENC_CLAIMED_REJECTED)
    tra.TestKeyFunctionNotPermitted().test_decrypt_not_permitted(_cfg())


def test_sign_claimed_violated_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _ENC_OK)
    with pytest.raises(Failed) as ei:
        tra.TestKeyFunctionNotPermitted().test_sign_not_permitted(_cfg())
    assert not isinstance(ei.value, XFailed)


def test_sign_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _ENC_NOT_CLAIMED)
    with pytest.raises(pytest.xfail.Exception):
        tra.TestKeyFunctionNotPermitted().test_sign_not_permitted(_cfg())


def test_sign_claimed_enforced_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _ENC_CLAIMED_REJECTED)
    tra.TestKeyFunctionNotPermitted().test_sign_not_permitted(_cfg())
