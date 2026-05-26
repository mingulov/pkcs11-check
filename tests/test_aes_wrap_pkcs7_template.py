"""Regression tests for AES-KEY-WRAP-PKCS7 unwrap templates."""

from __future__ import annotations

import os
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKA_VALUE, CKA_VALUE_LEN
from pkcs11_check.testcases import test_aes_modes


def test_aes_key_wrap_pkcs7_unwrap_template_omits_value_len(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_bytes = b"\x42" * 24
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "AES_KEY_WRAP_PKCS7",
    )
    monkeypatch.setattr(os, "urandom", lambda length: key_bytes[:length])
    monkeypatch.setattr(test_aes_modes, "gen_aes_key", lambda *_args, **_kwargs: 10)
    monkeypatch.setattr(test_aes_modes, "import_secret_key", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(test_aes_modes, "wrap_key", lambda *_args, **_kwargs: b"wrapped-key")
    monkeypatch.setattr(test_aes_modes, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        test_aes_modes,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_VALUE: key_bytes},
    )

    def _unwrap_check_attrs(*_args: Any, **kwargs: Any) -> int:
        attrs = kwargs["attrs"]
        assert CKA_VALUE_LEN not in attrs
        return 12

    monkeypatch.setattr(test_aes_modes, "unwrap_key_for_mechanism_roundtrip", _unwrap_check_attrs)

    test_aes_modes.TestAESKeyWrapPKCS7().test_aes_key_wrap_pkcs7_roundtrip(
        rs, SimpleNamespace(module="/tmp/vendor-pkcs11.so")
    )
