"""Regression tests for BLAKE2 runtime reject classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_ARGUMENTS_BAD
from pkcs11_check.testcases import test_blake2


def test_blake2_empty_digest_arguments_bad_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "BLAKE2B_256",
    )

    def _digest_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_ARGUMENTS_BAD", int(CKR_ARGUMENTS_BAD))

    monkeypatch.setattr(test_blake2, "digest_single", _digest_reject)

    with pytest.raises(pytest.xfail.Exception, match="CKM_BLAKE2B_256 empty digest"):
        test_blake2.TestBlake2bProperties().test_empty_data(rs)
