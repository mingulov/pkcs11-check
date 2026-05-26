"""Runtime-reject policy for interop and cross-verification tests."""

from __future__ import annotations

from typing import NoReturn

from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR
from pkcs11_check.testcases.conftest import xfail_if_known_ckr

_INTEROP_OPERATION_REJECT_RVS = (CKR_GENERAL_ERROR,)


def xfail_if_interop_operation_reject(exc: AssertionError, label: str) -> NoReturn:
    """Classify explicit interop operation rejects as visible findings."""
    xfail_if_known_ckr(
        exc,
        _INTEROP_OPERATION_REJECT_RVS,
        f"{label}: advertised operation rejected during interop/crossverify",
    )
    raise exc
