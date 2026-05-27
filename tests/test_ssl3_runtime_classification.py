"""Regression tests for SSL3 runtime reject classification."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.types_std import CKR_ATTRIBUTE_VALUE_INVALID
from pkcs11_check.testcases import test_ssl3


def test_ssl3_premaster_attribute_value_invalid_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = SimpleNamespace(
        raw=SimpleNamespace(
            C_GenerateKey=lambda *_args: int(CKR_ATTRIBUTE_VALUE_INVALID),
        ),
        sh=1,
        has_mechanism=lambda name: name == "SSL3_PRE_MASTER_KEY_GEN",
    )
    monkeypatch.setattr(test_ssl3, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="CKM_SSL3_PRE_MASTER_KEY_GEN"):
        test_ssl3.TestSSL3PreMasterKeyGen().test_generate_pre_master_key(rs)
