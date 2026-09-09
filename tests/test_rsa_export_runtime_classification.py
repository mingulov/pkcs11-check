"""Runtime classification regressions for RSA provider attribute export."""

from __future__ import annotations

from collections.abc import Generator

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.types_std import CKA_MODULUS
from pkcs11_check.testcases import _rsa_export


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def test_missing_rsa_attribute_records_exact_read_context_without_ckr() -> None:
    with pytest.raises(pytest.xfail.Exception, match="missing RSA public attribute"):
        _rsa_export.rsa_public_key_from_attrs_or_xfail({}, label="exported RSA key")

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_GetAttributeValue"
    assert record.actual_ckr is None
    assert record.detail == {
        "attribute": {"name": "CKA_MODULUS", "id": int(CKA_MODULUS)},
    }
