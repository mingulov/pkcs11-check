"""Runtime classification meta-test for test_operation_state garbage-state guard (Phase 4 N2).

C_SetOperationState with a garbage blob must reject. Converted from a flat
``assert rv in {set}`` to a 3-way ``classify_negative_rv``:

- ``CKR_OK`` (the module accepted a garbage state blob) -> ``fail``,
- ``CKR_SAVED_STATE_INVALID`` (spec) -> ``pass``,
- any other clean reject code -> ``xfail``.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_OK,
    CKR_SAVED_STATE_INVALID,
)
from pkcs11_check.testcases import test_operation_state as tos


def _session(set_state_rv: int) -> SimpleNamespace:
    raw = SimpleNamespace(C_SetOperationState=lambda *_a, **_k: int(set_state_rv))
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda n: True)


def _run(set_state_rv: int) -> None:
    tos.TestGetOperationStateAPI().test_garbage_state_raises_saved_state_invalid(
        _session(set_state_rv)
    )


def test_garbage_accepted_fails() -> None:
    with pytest.raises(Failed) as ei:
        _run(int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_spec_reject_passes() -> None:
    _run(int(CKR_SAVED_STATE_INVALID))


def test_other_reject_xfails() -> None:
    # CKR_ARGUMENTS_BAD also triggers a note() above, then classifies as xfail.
    with pytest.raises(pytest.xfail.Exception):
        _run(int(CKR_ARGUMENTS_BAD))
