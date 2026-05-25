"""Regression tests for access-control capability guards."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.testcases import test_access_control


def test_secret_key_access_control_skips_when_aes_keygen_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Secret-key access-control tests require AES key generation capability."""

    def _unexpected_keygen(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("AES keygen should have been capability-guarded")

    monkeypatch.setattr(test_access_control, "gen_aes_key", _unexpected_keygen)
    rs = SimpleNamespace(has_mechanism=lambda _name: False)

    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN not supported"):
        test_access_control.TestPrivateAttribute().test_private_key_default_is_private(rs)
