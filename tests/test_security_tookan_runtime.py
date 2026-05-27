"""Regression tests for Tookan security-vector runtime classification."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_KEY_NOT_WRAPPABLE
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
