"""classify() carries a structured ``params`` map (curve/key-size/hash) to the record."""

from __future__ import annotations

import pytest

from pkcs11_check import classification as C


def test_classify_records_params() -> None:
    C.clear()
    with pytest.raises(BaseException):  # noqa: B017,PT011 - classify() raises the pytest outcome
        C.classify(
            "not_operational",
            mechanism="CKM_ECDSA",
            operation="C_Verify",
            params={"curve": "brainpoolP224r1"},
        )
    recs = C.serialize(C.get_records())
    assert recs[0]["params"] == {"curve": "brainpoolP224r1"}


def test_params_default_none() -> None:
    C.clear()
    with pytest.raises(BaseException):  # noqa: B017,PT011
        C.classify("wrong_result", kind="crypto", mechanism="CKM_RSA_PKCS", operation="C_Decrypt")
    recs = C.serialize(C.get_records())
    assert recs[0]["params"] is None
