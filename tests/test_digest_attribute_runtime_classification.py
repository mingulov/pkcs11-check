"""Regression tests for C_DigestKey attribute-readback evidence."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.types_std import CKA_VALUE
from pkcs11_check.testcases import test_digest as digest
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE
from tests._attribute_access_guard import analyze_file


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in {"SHA256", "AES_KEY_GEN"},
    )


def test_missing_digest_key_value_is_visible_and_keeps_digest_result_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An omitted oracle is reported while the productive DigestKey call is retained."""
    calls: list[str] = []

    def fake_digest(*_args: Any, **_kwargs: Any) -> bytes:
        calls.append("digest")
        return b"d" * 32

    def fake_destroy(*_args: Any, **_kwargs: Any) -> None:
        calls.append("destroy")

    monkeypatch.setattr(digest, "_gen_extractable_aes_key_or_xfail", lambda *_args: 7)
    monkeypatch.setattr(digest, "_digest_key_or_skip_or_xfail", fake_digest)
    monkeypatch.setattr(digest, "read_attributes", lambda *_args: {})
    monkeypatch.setattr(digest, "destroy_quietly", fake_destroy)

    digest.TestDigestKey().test_digest_key_matches_hashlib(_session())

    assert calls == ["digest", "destroy"]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].outcome == "xfail"
    assert records[0].operation == "C_GetAttributeValue"
    # F6: the key's CKA_VALUE was produced by C_GenerateKey(CKM_AES_KEY_GEN), not by
    # the CKM_SHA256 digest mechanism this readback feeds into as a KAT reference.
    assert records[0].mechanism is None
    assert "producer_operation=C_GenerateKey" in records[0].label
    assert "producer_mechanism=CKM_AES_KEY_GEN" in records[0].label
    assert records[0].detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}
    assert MISSING_ATTRIBUTE is not False


@pytest.mark.parametrize("value", [False, 0, None], ids=["false", "zero", "none"])
def test_non_bytes_digest_key_value_is_metadata_failure_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    """A non-bytes readback is a metadata failure at C_GetAttributeValue."""
    calls: list[str] = []
    monkeypatch.setattr(digest, "_gen_extractable_aes_key_or_xfail", lambda *_args: 8)
    monkeypatch.setattr(
        digest,
        "_digest_key_or_skip_or_xfail",
        lambda *_args: b"d" * 32,
    )
    monkeypatch.setattr(digest, "read_attributes", lambda *_args: {CKA_VALUE: value})
    monkeypatch.setattr(digest, "destroy_quietly", lambda *_args: calls.append("destroy"))

    with pytest.raises(pytest.fail.Exception):
        digest.TestDigestKey().test_digest_key_matches_hashlib(_session())

    assert calls == ["destroy"]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.outcome == "fail"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_SHA256"
    assert record.detail is not None
    assert record.detail["attribute"]["expected"] == "bytes"
    assert record.detail["attribute"]["actual"] == repr(value)


@pytest.mark.parametrize("value", [b"", b"short", b"x" * 15, b"x" * 17])
def test_wrong_length_digest_key_value_is_generated_key_failure_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
    value: bytes,
) -> None:
    """Well-typed but wrong-sized CKA_VALUE contradicts AES key generation."""
    calls: list[str] = []
    monkeypatch.setattr(digest, "_gen_extractable_aes_key_or_xfail", lambda *_args: 9)
    monkeypatch.setattr(
        digest,
        "_digest_key_or_skip_or_xfail",
        lambda *_args: b"d" * 32,
    )
    monkeypatch.setattr(digest, "read_attributes", lambda *_args: {CKA_VALUE: value})

    def fake_destroy(*_args: Any, **_kwargs: Any) -> None:
        calls.append("destroy")

    monkeypatch.setattr(digest, "destroy_quietly", fake_destroy)

    with pytest.raises(pytest.fail.Exception):
        digest.TestDigestKey().test_digest_key_matches_hashlib(_session())

    assert calls == ["destroy"]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.outcome == "fail"
    assert record.kind == "crypto"
    assert record.operation == "C_GenerateKey"
    assert record.mechanism == "CKM_AES_KEY_GEN"
    assert record.detail is not None
    assert record.detail["attribute"]["expected"] == "16-byte bytes (CKA_VALUE_LEN)"
    assert record.detail["attribute"]["actual"] == repr(value)


def test_digest_attribute_access_slice_is_analyzer_clean() -> None:
    """The digest migration must stay covered by the path-sensitive guard."""
    source = Path(__file__).parents[1] / "src" / "pkcs11_check" / "testcases" / "test_digest.py"
    assert analyze_file(source) == []
