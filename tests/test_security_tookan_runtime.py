"""Regression tests for Tookan security-vector runtime classification."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EXTRACTABLE,
    CKA_VALUE,
    CKR_DEVICE_ERROR,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_UNEXTRACTABLE,
)
from pkcs11_check.testcases.security import test_tookan


def _session(*mechanisms: str) -> SimpleNamespace:
    supported = set(mechanisms) or {"AES_KEY_WRAP", "AES_KEY_GEN"}
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name in supported)


def _run_key_type_confusion_until_wrap(
    monkeypatch: pytest.MonkeyPatch,
    wrap_exc: CkrAssertionError,
) -> None:
    monkeypatch.setattr(test_tookan, "gen_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_tookan, "destroy_quietly", lambda *_args: None)
    # The valid leg reads the target's CKA_VALUE before the wrap; these two
    # tests only exercise the wrap-reject path (skip / xfail before unwrap), so
    # a stub value is sufficient.
    monkeypatch.setattr(
        test_tookan,
        "read_attributes",
        lambda *_a, **_k: {CKA_VALUE: b"\x00" * 16},
    )
    monkeypatch.setattr(
        test_tookan,
        "wrap_key",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(wrap_exc),
    )

    test_tookan.TestKeyTypeConfusionOnUnwrap().test_unwrap_aes_as_des3_rejected(
        _session(), object()
    )


def test_key_type_confusion_skips_explicit_key_not_wrappable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(pytest.skip.Exception, match="cannot wrap AES-128 key"):
        _run_key_type_confusion_until_wrap(
            monkeypatch,
            CkrAssertionError(
                "Unexpected CK_RV CKR_KEY_NOT_WRAPPABLE",
                int(CKR_KEY_NOT_WRAPPABLE),
            ),
        )


def test_key_type_confusion_xfails_generic_wrap_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_tookan.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="key-type-confusion wrap rejected"):
        _run_key_type_confusion_until_wrap(
            monkeypatch,
            CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR)),
        )


# --- TestWrapExtraction::test_wrap_decrypt_extraction_attempt --------------
#
# Regression for the false positive where a module CORRECTLY refusing to wrap a
# non-extractable/sensitive key (CKR_KEY_UNEXTRACTABLE) surfaced as a hard fail
# because the wrap_key recipe re-raised the refusal.


def _run_wrap_extraction(
    monkeypatch: pytest.MonkeyPatch,
    *,
    wrap_exc: CkrAssertionError | None = None,
    recovered: bytes = b"",
    claimed_protected: bool = True,
) -> None:
    monkeypatch.setattr(test_tookan, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_tookan, "destroy_quietly", lambda *_a: None)

    def _wrap(*_a: object, **_k: object) -> bytes:
        if wrap_exc is not None:
            raise wrap_exc
        return b"\x00" * 24  # 16-byte AES key + 8-byte KWP prefix

    monkeypatch.setattr(test_tookan, "wrap_key", _wrap)
    monkeypatch.setattr(
        test_tookan,
        "read_attributes",
        lambda *_a, **_k: {CKA_EXTRACTABLE: not claimed_protected},
    )
    monkeypatch.setattr(test_tookan, "decrypt_single", lambda *_a, **_k: recovered)

    test_tookan.TestWrapExtraction().test_wrap_decrypt_extraction_attempt(_session())


def test_wrap_extraction_refused_unextractable_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    # Module refused to wrap the protected key -> attack blocked -> pass.
    monkeypatch.setattr(
        test_tookan.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )
    _run_wrap_extraction(
        monkeypatch,
        wrap_exc=CkrAssertionError(
            "Unexpected CK_RV CKR_KEY_UNEXTRACTABLE; expected one of: CKR_OK",
            int(CKR_KEY_UNEXTRACTABLE),
        ),
    )


def test_wrap_extraction_refused_not_wrappable_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_wrap_extraction(
        monkeypatch,
        wrap_exc=CkrAssertionError(
            "Unexpected CK_RV CKR_KEY_NOT_WRAPPABLE; expected one of: CKR_OK",
            int(CKR_KEY_NOT_WRAPPABLE),
        ),
    )


def test_wrap_extraction_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(XFailed, match="wrap rejected before the decrypt leg"):
        _run_wrap_extraction(
            monkeypatch,
            wrap_exc=CkrAssertionError(
                "Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK",
                int(CKR_DEVICE_ERROR),
            ),
        )


def test_wrap_extraction_leak_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    # Wrap succeeded AND the decrypt leg recovers >= key-length plaintext from a
    # key claimed non-extractable -> policy self-contradiction -> fail.
    with pytest.raises(Failed) as ei:
        _run_wrap_extraction(monkeypatch, recovered=b"\x11" * 16, claimed_protected=True)
    assert not isinstance(ei.value, XFailed)


def test_wrap_extraction_no_leak_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    # Wrap succeeded but the decrypt leg recovers nothing usable -> no extraction.
    _run_wrap_extraction(monkeypatch, recovered=b"", claimed_protected=True)
