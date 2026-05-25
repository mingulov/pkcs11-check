"""Regression tests for general encrypt/decrypt capability guards."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.testcases import test_encrypt


def test_aes_encrypt_tests_skip_when_aes_keygen_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """General AES encrypt tests require AES key generation capability."""

    def _unexpected_keygen(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("AES keygen should have been capability-guarded")

    monkeypatch.setattr(test_encrypt, "gen_aes_key", _unexpected_keygen)
    rs = SimpleNamespace(has_mechanism=lambda _name: False)

    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN not supported"):
        test_encrypt.TestAESEncryption().test_aes_generate_key(rs)
