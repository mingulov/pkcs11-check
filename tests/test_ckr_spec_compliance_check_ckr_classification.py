"""Runtime classification meta-tests for ckr/test_ckr_spec_compliance _check_ckr (Phase 4 N2).

_check_ckr previously emitted a compliance note() on any mismatch and never
failed -- a non-spec reject code was effectively a silent pass. It is now routed
through classify_negative_rv: the expected spec code -> pass, any other clean
reject -> xfail. CKR_OK is guarded at every call site (pytest.fail before the
_check_ckr call), so the accepted-when-must-reject case is already a fail.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
)
from pkcs11_check.testcases.ckr import test_ckr_spec_compliance as tcsc


def _session(create_rv: int) -> SimpleNamespace:
    def _create(*_a: object, **_k: object) -> int:
        return int(create_rv)

    raw = SimpleNamespace(
        C_CreateObject=_create,
        C_DestroyObject=lambda *_a, **_k: int(CKR_OK),
    )
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda n: True)


def _run(create_rv: int) -> None:
    tcsc.TestCKRTemplateCompliance().test_missing_class_returns_template_incomplete(
        _session(create_rv)
    )


def test_accepted_must_reject_fails() -> None:
    # CKR_OK (the module created an object with no CKA_CLASS) -> fail at the call site.
    with pytest.raises(Failed) as ei:
        _run(int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_expected_code_passes() -> None:
    _run(int(CKR_TEMPLATE_INCOMPLETE))


def test_other_reject_xfails() -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(int(CKR_DEVICE_ERROR))
