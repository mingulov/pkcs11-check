"""Regression tests for KMAC parameterized signing semantics."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from pkcs11_check.raw.types_std import CKM
from pkcs11_check.testcases import test_extended_mechanisms as tem


def test_kmac_product_tests_cover_variable_mac_lengths() -> None:
    text = Path(tem.__file__).read_text(encoding="utf-8")

    assert "test_kmac_128_short_output_roundtrip" in text
    assert "test_kmac_256_short_output_roundtrip" in text
    assert "self._run_roundtrip(rs, \"KMAC_128\", 16)" in text
    assert "self._run_roundtrip(rs, \"KMAC_256\", 32)" in text


def test_kmac_roundtrip_rejects_tampered_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verify_calls: list[tuple[bytes, bytes]] = []

    runner = tem.TestKMAC()
    monkeypatch.setattr(runner, "_mechanism_or_skip", lambda name: CKM(0x80010001, name))
    monkeypatch.setattr(tem, "import_secret_key", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(tem, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tem, "sign_single", lambda *_args, **_kwargs: b"s" * 32)

    def _verify_single(
        _raw: object,
        _session: int,
        _key: int,
        _mechanism: object,
        data: bytes,
        signature: bytes,
        **_kwargs: object,
    ) -> bool:
        verify_calls.append((data, signature))
        return data == b"pkcs11-check KMAC parameterized signing" and signature == b"s" * 32

    monkeypatch.setattr(tem, "verify_single", _verify_single)

    runner._run_roundtrip(
        SimpleNamespace(raw=object(), sh=7, has_mechanism=lambda name: name == "KMAC_128"),
        "KMAC_128",
        32,
    )

    assert (
        b"pkcs11-check KMAC parameterized signing!",
        b"s" * 32,
    ) in verify_calls
