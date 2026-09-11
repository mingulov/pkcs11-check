"""Regression tests for ACVP HMAC runtime-result classification."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKK_GENERIC_SECRET,
    CKK_SHA256_HMAC,
    CKM_SHA256_HMAC,
    CKR_GENERAL_ERROR,
)
from pkcs11_check.testcases.acvp import test_acvp_hmac as hmac

# Classification records are cleared automatically by tests/conftest.py's
# autouse `_isolate_meta_test_classifications` fixture, which also detaches the
# live report hook so this helper-level record does not rewrite this file's own
# meta-test result.


class _HmacSession:
    raw = object()
    sh = 1


def _hmac_vec() -> dict[str, Any]:
    return {
        "key_type": int(CKK_SHA256_HMAC),
        "mechanism": int(CKM_SHA256_HMAC),
        "mech_display": "SHA256_HMAC",
        "key": b"k",
        "msg": b"message",
    }


def test_advertised_hmac_runtime_general_error_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Generic runtime rejection after advertised HMAC support is an xfail finding.

    Pins the full classification record, not just the raised outcome type: a
    reason/kind/label swap that kept the same ``pytest.xfail.Exception`` type would
    otherwise pass silently.
    """

    def _sign_general_error(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(hmac, "import_secret_key_negotiated", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(hmac, "sign_single", _sign_general_error)
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="advertised but imported HMAC key"):
        hmac._sign_hmac_with_key_fallback(_HmacSession(), _hmac_vec())

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "not_operational"
    assert record.outcome == "xfail"
    assert record.severity == "LOW"
    assert record.kind == "crypto"
    assert record.label == "SHA256_HMAC:sign"
    assert record.summary.startswith(
        "SHA256_HMAC advertised but imported HMAC key was not accepted:"
    )
    # Both the typed HMAC key type and the GENERIC_SECRET fallback were tried and
    # both hit the same clean rejection -- the fallback loop itself is exercised,
    # not just its final outcome.
    assert f"key_type=0x{int(CKK_SHA256_HMAC):x}: Unexpected CK_RV CKR_GENERAL_ERROR" in (
        record.summary
    )
    assert f"key_type=0x{int(CKK_GENERIC_SECRET):x}: Unexpected CK_RV CKR_GENERAL_ERROR" in (
        record.summary
    )
    assert record.operation is None
    assert record.mechanism is None
    assert record.expected_ckr is None
    assert record.actual_ckr is None
    assert record.spec_ref == ""
    assert record.source is None
    assert record.vector_id is None
    assert record.params is None
    assert record.detail is None
