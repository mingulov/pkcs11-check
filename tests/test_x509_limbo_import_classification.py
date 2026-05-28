"""Classification meta-tests for x509/test_limbo_import (Phase 5 P1a).

A clean CKR rejection of a Limbo-*valid* cert on raw import is provider-
incompleteness (the module is stricter than required for mere storage) ->
``xfail``, not a hard ``fail``. A non-CKR error still propagates.
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_ATTRIBUTE_VALUE_INVALID
from pkcs11_check.testcases.x509 import test_limbo_import as tli


class _RawSession:
    raw = object()
    sh = 1
    slot_id = 0


def _run(monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> None:
    def _raise_import(*_a: Any, **_k: Any) -> tuple[int, list[int]]:
        raise exc

    monkeypatch.setattr(tli, "pem_to_der", lambda _pem: b"der")
    monkeypatch.setattr(tli, "import_cert_raw", _raise_import)
    monkeypatch.setattr(tli, "destroy_quietly", lambda *_a, **_k: None)
    tc = {"id": "tc-valid", "peer_certificate": "pem", "expected_result": "SUCCESS"}
    tli.TestLimboCertImport().test_import_peer_cert(tc, _RawSession(), object())


def test_valid_cert_clean_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    exc = CkrAssertionError("CKR_ATTRIBUTE_VALUE_INVALID", int(CKR_ATTRIBUTE_VALUE_INVALID))
    with pytest.raises(XFailed):
        _run(monkeypatch, exc)


def test_non_ckr_error_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="harness bug"):
        _run(monkeypatch, ValueError("harness bug"))
