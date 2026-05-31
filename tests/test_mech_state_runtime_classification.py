"""Runtime classification meta-tests for test_mech_state negative state asserts (Phase 4 N2).

The operation-state guards (op-without-init, double-init) are negative
rejections. Converted from a flat ``assert rv in _NOT_INIT_RVCS`` (which failed
on every non-set code, including a clean but non-spec reject) to a 3-way
``classify_negative_rv``:

- ``CKR_OK`` (the module ran the op without init) -> ``fail``,
- the spec-preferred code -> ``pass``,
- any other clean reject code -> ``xfail``.

The deliberately strict cross-session guards (``_CROSS_SESSION_NOT_INIT_RVCS``)
are intentionally NOT converted: there ``CKR_FUNCTION_FAILED`` /
``CKR_GENERAL_ERROR`` indicate the crash-on-cross-session-probe pattern the test
guards against and must stay ``fail``.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
)
from pkcs11_check.testcases import test_mech_state as tms


class _FakeRaw:
    """Returns ``rv`` from every C_* entry point used by the state guards."""

    def __init__(self, rv: int) -> None:
        self._rv = rv

    def __getattr__(self, _name: str):  # type: ignore[no-untyped-def]
        return lambda *_a, **_k: self._rv


def _session(rv: int) -> SimpleNamespace:
    return SimpleNamespace(raw=_FakeRaw(rv), sh=1, has_mechanism=lambda name: True)


# --- op-without-init (_NOT_INIT_RVCS) ------------------------------------


def _run_no_init(rv: int) -> None:
    tms.TestEncryptState().test_encrypt_without_init(_session(rv))


def test_no_init_ckr_ok_fails() -> None:
    with pytest.raises(Failed) as ei:
        _run_no_init(CKR_OK)
    assert not isinstance(ei.value, XFailed)


def test_no_init_expected_passes() -> None:
    _run_no_init(CKR_OPERATION_NOT_INITIALIZED)


def test_no_init_other_reject_xfails() -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_no_init(CKR_DEVICE_ERROR)


# --- double-init (_ALREADY_ACTIVE_RVCS) ----------------------------------
#
# test_double_encrypt_init generates a key, inits once (CKR_OK), then inits
# again -- the second init's rv is the one classified. With a fake raw that
# returns the same rv everywhere, the first init must be CKR_OK for the test to
# reach the classification, so drive the double-init via test_double_digest_init
# which has no keygen and skips if the first init != CKR_OK. Instead use the
# encrypt path but stub keygen/destroy and force CKR_OK on the first init.


def _run_double_init(second_rv: int) -> SimpleNamespace:
    """Drive test_double_digest_init: first DigestInit must be CKR_OK, second is classified."""
    state = {"init_calls": 0}

    def _dispatch(name: str):  # type: ignore[no-untyped-def]
        def _call(*_a: object, **_k: object) -> int:
            if name == "C_DigestInit":
                state["init_calls"] += 1
                return CKR_OK if state["init_calls"] == 1 else second_rv
            return CKR_OK

        return _call

    class _Raw:
        def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
            return _dispatch(name)

    return SimpleNamespace(raw=_Raw(), sh=1, has_mechanism=lambda name: True)


def test_double_init_ckr_ok_fails() -> None:
    # Second init returning CKR_OK = module accepted a double-init -> fail.
    with pytest.raises(Failed) as ei:
        tms.TestDigestState().test_double_digest_init(_run_double_init(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_double_init_expected_passes() -> None:
    tms.TestDigestState().test_double_digest_init(_run_double_init(CKR_OPERATION_ACTIVE))


def test_double_init_other_reject_xfails() -> None:
    with pytest.raises(pytest.xfail.Exception):
        tms.TestDigestState().test_double_digest_init(_run_double_init(CKR_DEVICE_ERROR))
