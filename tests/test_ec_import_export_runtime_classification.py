"""Regression tests for EC import/export runtime-result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKR_ATTRIBUTE_VALUE_INVALID,
)
from pkcs11_check.testcases import test_ec_import_export


def _session(*mechanisms: str) -> SimpleNamespace:
    advertised = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in advertised,
    )


def test_ec_public_import_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    def _import_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
            int(CKR_ATTRIBUTE_VALUE_INVALID),
        )

    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(
        test_ec_import_export,
        "read_attributes",
        lambda *_args: {
            CKA_EC_POINT: b"\x04\x02\x04\x00",
            CKA_EC_PARAMS: b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        },
    )
    monkeypatch.setattr(test_ec_import_export, "sign_single", lambda *_args: b"sig")
    monkeypatch.setattr(test_ec_import_export, "import_ec_public_key", _import_reject)
    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="EC public key import not operational"):
        test_ec_import_export.TestECPublicKeyImport().test_generate_export_import_verify(
            _session("ECDSA"),
            "secp256r1",
        )
