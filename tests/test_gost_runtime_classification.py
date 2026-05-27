"""Regression tests for GOST runtime reject classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_TEMPLATE_INCONSISTENT
from pkcs11_check.testcases import test_gost


def test_gost_hmac_key_template_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "GOSTR3411_HMAC",
    )

    def _import_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT",
            int(CKR_TEMPLATE_INCONSISTENT),
        )

    monkeypatch.setattr(test_gost, "import_secret_key", _import_reject)
    monkeypatch.setattr(test_gost, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="CKM_GOSTR3411_HMAC"):
        test_gost.TestGOSTR3411Digest().test_hmac_sign_verify(rs)
