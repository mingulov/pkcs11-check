"""Runtime classification meta-tests for ckr/test_ckr_raw_multipart (Phase 4 N2).

C_*Update/Final without the matching C_*Init must reject with
CKR_OPERATION_NOT_INITIALIZED. The probe runs in a subprocess; previously the
spec CKR was asserted *inside* the child script, so a non-spec clean reject
crashed the child (rc != 0) and was mislabeled as a "Crash". The negative
classification now happens in the parent via ``_classify_multipart_ckr`` over
the printed ``CKR:0x...`` line:

- ``CKR_OK`` (the multipart op ran without init) -> ``fail``,
- ``CKR_OPERATION_NOT_INITIALIZED`` (spec) -> ``pass``,
- any other clean reject code -> ``xfail``.
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_FAILED,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
)
from pkcs11_check.testcases.ckr import test_ckr_raw_multipart as trm


def _cfg() -> Any:
    return type("Cfg", (), {"module": "x", "pin": None})()


def _patch(monkeypatch: pytest.MonkeyPatch, rv: int) -> None:
    out = f"CKR:0x{int(rv):08x}\nOK"
    monkeypatch.setattr(trm, "_run_raw_test", lambda *_a, **_k: (0, out, ""))
    monkeypatch.setattr(trm, "assert_ckr_subprocess_ok", lambda *_a, **_k: None)


def test_multipart_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, int(CKR_OK))
    with pytest.raises(Failed) as ei:
        trm.TestMultipartNotInitialized().test_encrypt_update_no_init(_cfg())
    assert not isinstance(ei.value, XFailed)


def test_multipart_spec_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, int(CKR_OPERATION_NOT_INITIALIZED))
    trm.TestMultipartNotInitialized().test_encrypt_update_no_init(_cfg())


def test_multipart_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, int(CKR_FUNCTION_FAILED))
    with pytest.raises(pytest.xfail.Exception):
        trm.TestMultipartNotInitialized().test_encrypt_update_no_init(_cfg())
