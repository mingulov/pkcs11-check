"""Regression tests for classic DH runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKA_VALUE, CKR_DEVICE_ERROR
from pkcs11_check.testcases import test_dh_key_agreement as dh


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in {"DH_PKCS_KEY_PAIR_GEN", "DH_PKCS_DERIVE"},
    )


def test_dh_derive_clean_runtime_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    keypairs = iter([(11, 21), (12, 22)])
    public_values = {
        11: b"\x02",
        12: b"\x03",
    }

    def _derive_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_args, **_kwargs: next(keypairs))
    monkeypatch.setattr(
        dh,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {CKA_VALUE: public_values[handle]},
    )
    monkeypatch.setattr(dh, "derive_key", _derive_reject)
    monkeypatch.setattr(dh, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="DH derive advertised"):
        dh.TestDHKeyAgreement().test_dh_derive_shared_secret(_session())
