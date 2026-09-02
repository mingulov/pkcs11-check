"""X.509 lifecycle capability refusals stay visible and wrong readbacks stay hard."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_ID,
    CKA_TOKEN,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_FUNCTION_FAILED,
)
from pkcs11_check.testcases.x509 import test_lifecycle as lifecycle

_RS = SimpleNamespace(raw=object(), sh=1, slot_id=0)


def _common(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lifecycle, "destroy_quietly", lambda *_a, **_k: None)


def test_token_false_readback_is_not_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    _common(monkeypatch)
    monkeypatch.setattr(lifecycle, "import_cert_object", lambda *_a, **_k: 7)
    monkeypatch.setattr(lifecycle, "read_attributes", lambda *_a, **_k: {CKA_TOKEN: False})

    with pytest.raises(Failed):
        lifecycle.TestCertificateLifecycle().test_cert_token_persistence(_RS, b"der", "3.0")


def test_token_import_refusal_is_visible_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    _common(monkeypatch)
    error = CkrAssertionError("refused", int(CKR_FUNCTION_FAILED))
    monkeypatch.setattr(
        lifecycle,
        "import_cert_object",
        lambda *_a, **_k: (_ for _ in ()).throw(error),
    )

    with pytest.raises(XFailed):
        lifecycle.TestCertificateLifecycle().test_cert_token_persistence(_RS, b"der", "3.0")


def test_plain_import_assertion_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    _common(monkeypatch)
    monkeypatch.setattr(
        lifecycle,
        "import_cert_object",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("harness bug")),
    )

    with pytest.raises(AssertionError, match="harness bug"):
        lifecycle.TestCertificateLifecycle().test_cert_token_persistence(_RS, b"der", "3.0")


def test_nonmodifiable_success_is_forbidden(monkeypatch: pytest.MonkeyPatch) -> None:
    _common(monkeypatch)
    monkeypatch.setattr(lifecycle, "import_cert_object", lambda *_a, **_k: 7)
    monkeypatch.setattr(lifecycle, "set_attributes", lambda *_a, **_k: None)

    with pytest.raises(Failed):
        lifecycle.TestCertificateLifecycle().test_cert_modifiability(_RS, b"der", "3.0")


def test_nonmodifiable_exact_refusal_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _common(monkeypatch)
    monkeypatch.setattr(lifecycle, "import_cert_object", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        lifecycle,
        "set_attributes",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("read only", int(CKR_ATTRIBUTE_READ_ONLY))
        ),
    )

    lifecycle.TestCertificateLifecycle().test_cert_modifiability(_RS, b"der", "3.0")


def test_wrong_id_readback_is_not_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    _common(monkeypatch)
    monkeypatch.setattr(lifecycle, "import_cert_object", lambda *_a, **_k: 7)
    monkeypatch.setattr(lifecycle, "read_attributes", lambda *_a, **_k: {CKA_ID: b"wrong"})

    with pytest.raises(Failed):
        lifecycle.TestCertificateLifecycle().test_cert_id_assignment(_RS, b"der", "3.0")
