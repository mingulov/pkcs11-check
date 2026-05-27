"""Regression tests for general encrypt/decrypt capability guards."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED
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


def test_aes_encrypt_tests_xfail_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Advertised-but-nonoperational AES key generation is an xfail finding."""

    def _rejected_keygen(*_args: object, **_kwargs: object) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
            int(CKR_FUNCTION_NOT_SUPPORTED),
        )

    monkeypatch.setattr(raw_recipes, "gen_aes_key", _rejected_keygen)
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_encrypt.TestAESEncryption().test_aes_generate_key(rs)


def test_aes_roundtrip_uses_operational_aes128_setup_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Roundtrip smoke coverage should not require AES-256 setup keys."""

    def _gen_aes128_key(*_args: Any, bits: int = 256, **_kwargs: Any) -> int:
        if len(_args) >= 3:
            bits = int(_args[2])
        if bits != 128:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
                int(CKR_FUNCTION_NOT_SUPPORTED),
            )
        return 1

    monkeypatch.setattr(test_encrypt, "_require_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_encrypt, "gen_aes_key", _gen_aes128_key)
    monkeypatch.setattr(test_encrypt, "generate_random", lambda *_args, **_kwargs: b"\x00" * 16)
    monkeypatch.setattr(test_encrypt, "encrypt_single", lambda *_args, **_kwargs: b"ciphertext")
    monkeypatch.setattr(
        test_encrypt,
        "decrypt_single",
        lambda *_args, **_kwargs: b"hello pkcs11!!\x02\x02",
    )
    monkeypatch.setattr(test_encrypt, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)

    test_encrypt.TestAESEncryption().test_aes_cbc_roundtrip(rs)


def test_aes_key_size_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit AES key-size probes keep advertised runtime rejects as xfail findings."""

    def _rejected_keygen(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
            int(CKR_FUNCTION_NOT_SUPPORTED),
        )

    monkeypatch.setattr(test_encrypt, "_require_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_encrypt, "gen_aes_key", _rejected_keygen)
    monkeypatch.setattr(test_encrypt, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)

    with pytest.raises(pytest.xfail.Exception, match="AES-256 key generation"):
        test_encrypt.TestAESEncryption().test_aes_key_sizes(rs, 256)
