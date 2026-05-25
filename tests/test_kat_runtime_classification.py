"""Regression tests for standalone KAT runtime-result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_ARGUMENTS_BAD
from pkcs11_check.testcases import test_kat


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


def test_sha_kat_empty_digest_runtime_reject_is_visible_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _digest_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_ARGUMENTS_BAD", int(CKR_ARGUMENTS_BAD))

    monkeypatch.setattr(test_kat, "digest_single", _digest_reject)

    with pytest.raises(pytest.xfail.Exception, match="SHA256 KAT digest rejected"):
        test_kat.TestSHA256KAT().test_sha256_kat(
            _session(),
            {
                "msg": "",
                "digest": "e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855",
            },
        )


def test_sha_kat_missing_digest_mechanism_is_counted_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_kat,
        "digest_single",
        lambda *_args, **_kwargs: pytest.fail("digest should not be called"),
    )
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: False)

    with pytest.raises(pytest.skip.Exception, match="CKM_SHA256 not supported"):
        test_kat.TestSHA256KAT().test_sha256_kat(
            rs,
            {
                "msg": "",
                "digest": "e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855",
            },
        )
