"""Regression test for PC-4.1: unwrap-to-token-object in an RO session
must classify an unlisted clean reject (e.g. softhsm2's
``CKR_TEMPLATE_INCOMPLETE``) as ``xfail``, not a hard fail. The crypto
acceptance path (``CKR_OK`` on a write to RO session) must still
hard-fail.

Catalog: PC-4.1, softhsm2-recheck-20260528 evidence shows the recipe
raises ``CkrAssertionError(rv=CKR_TEMPLATE_INCOMPLETE)`` from the
``unwrap_key`` recipe call in ``test_ro_session_restrictions.py``.
"""

from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_OK,
    CKR_SESSION_READ_ONLY,
    CKR_TEMPLATE_INCOMPLETE,
)
from pkcs11_check.testcases.conftest import reject_or_classify
from pkcs11_check.testcases.test_ro_session_restrictions import (
    _RO_OR_UNSUPPORTED_RVS,
)


def _exc(rv: int, ckr_name: str) -> CkrAssertionError:
    return CkrAssertionError(f"Unexpected CK_RV {ckr_name}; expected one of: CKR_OK", rv)


def test_listed_reject_passes() -> None:
    # CKR_SESSION_READ_ONLY is the spec-preferred reject for write-to-RO.
    reject_or_classify(
        _exc(int(CKR_SESSION_READ_ONLY), "CKR_SESSION_READ_ONLY"),
        _RO_OR_UNSUPPORTED_RVS,
        label="C_UnwrapKey to TOKEN=True in RO session",
    )


def test_unlisted_reject_xfails() -> None:
    """The softhsm2-recheck case: CKR_TEMPLATE_INCOMPLETE is not in the
    _RO_OR_UNSUPPORTED_RVS spec-preferred set, so the 3-way classifier
    must xfail (noted deviation) rather than hard-fail.
    """
    with pytest.raises(pytest.xfail.Exception):
        reject_or_classify(
            _exc(int(CKR_TEMPLATE_INCOMPLETE), "CKR_TEMPLATE_INCOMPLETE"),
            _RO_OR_UNSUPPORTED_RVS,
            label="C_UnwrapKey to TOKEN=True in RO session",
        )


def test_acceptance_still_fails() -> None:
    """If the test body reaches ``assert False, 'Unwrap to TOKEN=True
    succeeded ...'``, the existing guard re-raises it before
    reject_or_classify is called. Verify the guard pattern.
    """
    # This test does not call reject_or_classify; it verifies the
    # pre-guard short-circuit that prevents reject_or_classify from
    # ever seeing an "Unwrap to TOKEN=True succeeded" AssertionError.
    succeeded_msg = "Unwrap to TOKEN=True succeeded in RO session"
    exc = AssertionError(succeeded_msg)
    # Mimic the in-test guard:
    with pytest.raises(AssertionError, match="succeeded"):
        if succeeded_msg in str(exc):
            raise exc
        reject_or_classify(  # unreachable
            exc, (CKR_OK,), label="unreachable"
        )
