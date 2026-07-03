"""Runtime classification meta-tests for test_initialize_args arg guards (Phase 4 N2).

C_Initialize arg-validation guards (non-NULL pReserved, partial mutex callbacks)
expect CKR_ARGUMENTS_BAD per spec Sec.5.4. Converted from a flat
``assert rv == CKR_ARGUMENTS_BAD`` to a 3-way classification:

- ``CKR_OK`` (module accepted the spec-violating arg) -> ``xfail`` (honest
  non-compliance, not security-impacting; symmetric with the pReserved sibling),
- ``CKR_ARGUMENTS_BAD`` (spec) -> ``pass``,
- any other clean reject code -> ``xfail``.

A real segfault on these probes still ``fail``s via the existing rc<0 guard.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_OK,
)
from pkcs11_check.testcases import test_initialize_args as tia


def _patch(monkeypatch: pytest.MonkeyPatch, rv: int) -> None:
    monkeypatch.setattr(tia, "_run_init_args_probe", lambda *_a, **_k: (0, str(int(rv)), ""))
    monkeypatch.setattr(tia, "_parse_rv", lambda stdout: int(stdout))


_CASES = ("test_init_reserved_non_null_rejected", "test_init_partial_callbacks_rejected")


@pytest.mark.parametrize("method", _CASES)
def test_accepted_xfails(monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    _patch(monkeypatch, int(CKR_OK))
    with pytest.raises(pytest.xfail.Exception):
        getattr(tia.TestInitArgsMatrix(), method)(_config())


@pytest.mark.parametrize("method", _CASES)
def test_spec_reject_passes(monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    _patch(monkeypatch, int(CKR_ARGUMENTS_BAD))
    getattr(tia.TestInitArgsMatrix(), method)(_config())


@pytest.mark.parametrize("method", _CASES)
def test_other_reject_xfails(monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    _patch(monkeypatch, int(CKR_FUNCTION_FAILED))
    with pytest.raises(pytest.xfail.Exception):
        getattr(tia.TestInitArgsMatrix(), method)(_config())


def _config() -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(module="x", slot=0, pin=None, token_label=None)
