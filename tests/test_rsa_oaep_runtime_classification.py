"""Regression tests for RSA-OAEP runtime-result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_ARGUMENTS_BAD
from pkcs11_check.testcases import test_rsa_oaep


def test_oaep_hash_combo_runtime_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """Advertised RSA-OAEP hash/MGF parameter rejects are visible xfail findings."""

    def _reject_oaep_params(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_ARGUMENTS_BAD", int(CKR_ARGUMENTS_BAD))

    monkeypatch.setattr(test_rsa_oaep, "gen_rsa_keypair_or_xfail", lambda *_args, **_kwargs: (1, 2))
    monkeypatch.setattr(test_rsa_oaep, "encrypt_single", _reject_oaep_params)
    monkeypatch.setattr(test_rsa_oaep, "destroy_quietly", lambda *_args: None)

    rs = SimpleNamespace(raw=object(), sh=1)

    with pytest.raises(pytest.xfail.Exception, match="advertised RSA-OAEP parameters"):
        test_rsa_oaep.TestRSAOAEPHashCombos().test_oaep_sha384_roundtrip(rs)
