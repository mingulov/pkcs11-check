"""Runtime classification meta-tests for ckr/test_ckr_slot_token (Phase 4 N2).

C_GetMechanismInfo for a non-existent mechanism must reject. Converted from a
flat ``assert rv == CKR_MECHANISM_INVALID`` to a 3-way ``classify_negative_rv``:

- ``CKR_OK`` (the module returned info for a bogus mechanism) -> ``fail``,
- ``CKR_MECHANISM_INVALID`` (spec) -> ``pass``,
- any other clean reject code -> ``xfail``.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_FAILED,
    CKR_MECHANISM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases.ckr import test_ckr_slot_token as tst


def _session(rv: int) -> SimpleNamespace:
    raw = SimpleNamespace(C_GetMechanismInfo=lambda *_a, **_k: int(rv))
    return SimpleNamespace(raw=raw, sh=1, slot_id=0)


def _run(rv: int) -> None:
    tst.TestGetMechanismInfoErrors().test_mechanism_invalid(_session(rv))


def test_bogus_mech_info_returned_fails() -> None:
    with pytest.raises(Failed) as ei:
        _run(int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_spec_reject_passes() -> None:
    _run(int(CKR_MECHANISM_INVALID))


def test_other_reject_xfails() -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(int(CKR_FUNCTION_FAILED))
