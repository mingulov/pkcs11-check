"""Regression tests for destroyed-handle runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKR_MECHANISM_INVALID, CKR_OK
from pkcs11_check.testcases.security import test_handle_reuse


def _session(*mechanisms: str, raw: Any | None = None) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=raw if raw is not None else SimpleNamespace(C_DestroyObject=lambda *_a: CKR_OK),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def test_get_attribute_after_destroy_success_is_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_handle_reuse,
        "gen_aes_key_or_xfail",
        lambda *_a, **_k: 7,
        raising=False,
    )
    monkeypatch.setattr(test_handle_reuse, "gen_aes_key", lambda *_a, **_k: 7, raising=False)
    monkeypatch.setattr(test_handle_reuse, "read_attributes", lambda *_a, **_k: {})

    with pytest.raises(pytest.fail.Exception, match="succeeded"):
        test_handle_reuse.TestHandleReuseAfterDestroy().test_get_attribute_after_destroy(
            _session("AES_KEY_GEN")
        )


def test_get_attribute_after_destroy_python_bug_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _bug(*_args: Any, **_kwargs: Any) -> dict[Any, Any]:
        raise RuntimeError("readback bug")

    monkeypatch.setattr(
        test_handle_reuse,
        "gen_aes_key_or_xfail",
        lambda *_a, **_k: 7,
        raising=False,
    )
    monkeypatch.setattr(test_handle_reuse, "gen_aes_key", lambda *_a, **_k: 7, raising=False)
    monkeypatch.setattr(test_handle_reuse, "read_attributes", _bug)

    with pytest.raises(RuntimeError, match="readback bug"):
        test_handle_reuse.TestHandleReuseAfterDestroy().test_get_attribute_after_destroy(
            _session("AES_KEY_GEN")
        )


def test_missing_aes_keygen_is_skip_not_setup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_handle_reuse,
        "gen_aes_key",
        lambda *_a, **_k: pytest.fail("AES setup should have been skipped"),
        raising=False,
    )

    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN not supported"):
        test_handle_reuse.TestHandleReuseAfterDestroy().test_double_destroy(_session())


def test_encrypt_after_destroy_unexpected_ckr_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Phase 3 Type-C: a non-handle clean reject on a destroyed handle is now a
    # noted deviation (xfail), not a hard fail.
    raw = SimpleNamespace(
        C_DestroyObject=lambda *_a: CKR_OK,
        C_EncryptInit=lambda *_a: CKR_MECHANISM_INVALID,
    )
    monkeypatch.setattr(
        test_handle_reuse,
        "gen_aes_key_or_xfail",
        lambda *_a, **_k: 7,
        raising=False,
    )
    monkeypatch.setattr(test_handle_reuse, "gen_aes_key", lambda *_a, **_k: 7, raising=False)

    with pytest.raises(pytest.xfail.Exception, match="use-after-destroy"):
        test_handle_reuse.TestHandleReuseAfterDestroy().test_encrypt_after_destroy(
            _session("AES_KEY_GEN", "AES_ECB", raw=raw)
        )


def test_encrypt_after_destroy_success_is_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Phase 3 Type-C: the op succeeding on a destroyed handle is a genuine fail.
    from _pytest.outcomes import Failed, XFailed

    raw = SimpleNamespace(
        C_DestroyObject=lambda *_a: CKR_OK,
        C_EncryptInit=lambda *_a: CKR_OK,
    )
    monkeypatch.setattr(
        test_handle_reuse,
        "gen_aes_key_or_xfail",
        lambda *_a, **_k: 7,
        raising=False,
    )
    monkeypatch.setattr(test_handle_reuse, "gen_aes_key", lambda *_a, **_k: 7, raising=False)

    with pytest.raises(Failed, match="use-after-destroy") as ei:
        test_handle_reuse.TestHandleReuseAfterDestroy().test_encrypt_after_destroy(
            _session("AES_KEY_GEN", "AES_ECB", raw=raw)
        )
    assert not isinstance(ei.value, XFailed)


def test_double_destroy_unexpected_ckr_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def _destroy(*_args: Any) -> int:
        nonlocal calls
        calls += 1
        return CKR_OK if calls == 1 else CKR_MECHANISM_INVALID

    raw = SimpleNamespace(C_DestroyObject=_destroy)
    monkeypatch.setattr(
        test_handle_reuse,
        "gen_aes_key_or_xfail",
        lambda *_a, **_k: 7,
        raising=False,
    )
    monkeypatch.setattr(test_handle_reuse, "gen_aes_key", lambda *_a, **_k: 7, raising=False)

    with pytest.raises(pytest.xfail.Exception, match="use-after-destroy"):
        test_handle_reuse.TestHandleReuseAfterDestroy().test_double_destroy(
            _session("AES_KEY_GEN", raw=raw)
        )
