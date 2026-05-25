"""Regression tests for ACVP EdDSA key-verification result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_TEMPLATE_INCONSISTENT
from pkcs11_check.testcases.acvp import test_acvp_eddsa


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


def test_eddsa_keyver_valid_key_import_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _reject_valid_key(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT",
            int(CKR_TEMPLATE_INCONSISTENT),
        )

    vec = {
        "ec_params": b"params",
        "ec_point": b"point",
        "curve": "ED-25519",
        "expected_pass": True,
    }
    monkeypatch.setattr(test_acvp_eddsa, "import_ec_public_key", _reject_valid_key)

    with pytest.raises(pytest.xfail.Exception, match="valid EdDSA key import rejected"):
        test_acvp_eddsa.TestEdDsaKeyVer().test_eddsa_keyver(
            _session(),
            SimpleNamespace(),
            "EDDSA-KeyVer-valid",
            vec,
        )


def test_eddsa_keyver_invalid_key_acceptance_stays_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec = {
        "ec_params": b"params",
        "ec_point": b"point",
        "curve": "ED-25519",
        "expected_pass": False,
    }
    monkeypatch.setattr(test_acvp_eddsa, "import_ec_public_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_acvp_eddsa, "verify_single", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(test_acvp_eddsa, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="ACCEPTED an INVALID EdDSA key"):
        test_acvp_eddsa.TestEdDsaKeyVer().test_eddsa_keyver(
            _session(),
            SimpleNamespace(),
            "EDDSA-KeyVer-invalid",
            vec,
        )
