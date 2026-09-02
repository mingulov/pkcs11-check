"""Classification meta-tests for x509/test_identity sign leg (Phase 5 P1a).

After importing a cert + private key, a clean failure of the positive *sign*
leg is advertised-but-not-operational provider-incompleteness -> ``xfail``, not
a hard ``fail``. A successful sign passes.
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_FAILED
from pkcs11_check.testcases.x509 import test_identity as ti


class _RawSession:
    raw = object()
    sh = 1
    slot_id = 0


def _cases() -> list[dict[str, Any]]:
    return [
        {
            "id": "tc1",
            "peer_certificate": "certpem",
            "peer_certificate_key": "keypem",
        }
    ]


def _patch(monkeypatch: pytest.MonkeyPatch, *, sign_ok: bool) -> None:
    monkeypatch.setattr(ti, "pem_to_der", lambda _pem: b"der")
    monkeypatch.setattr(ti, "import_cert_object", lambda *_a, **_k: 5)
    monkeypatch.setattr(ti, "create_object", lambda *_a, **_k: 6)
    monkeypatch.setattr(ti, "destroy_quietly", lambda *_a, **_k: None)

    def _sign(*_a: Any, **_k: Any) -> bytes:
        if sign_ok:
            return b"sig"
        raise CkrAssertionError("Unexpected CK_RV CKR_FUNCTION_FAILED", int(CKR_FUNCTION_FAILED))

    monkeypatch.setattr(ti, "sign_single", _sign)


def _run(monkeypatch: pytest.MonkeyPatch, *, sign_ok: bool) -> None:
    _patch(monkeypatch, sign_ok=sign_ok)
    ti.test_limbo_identity_closeness(
        _RawSession(),
        True,  # cert_support
        _cases(),  # all_limbo_cases
        lambda c, limit=100: c,  # limbo_filter
        "v3.0",  # p11_interface_version
    )


def test_sign_leg_clean_failure_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(XFailed):
        _run(monkeypatch, sign_ok=False)


def test_sign_leg_success_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, sign_ok=True)


def test_sign_leg_does_not_swallow_harness_assertion(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, sign_ok=True)
    monkeypatch.setattr(
        ti, "sign_single", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("harness bug"))
    )

    with pytest.raises(AssertionError, match="harness bug"):
        ti.test_limbo_identity_closeness(
            _RawSession(),
            True,
            _cases(),
            lambda c, limit=100: c,
            "v3.0",
        )
