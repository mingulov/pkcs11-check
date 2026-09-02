"""Regression tests for required ACVP RSA generated-key attributes."""

from __future__ import annotations

from collections.abc import Generator

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.classification import clear, get_records
from pkcs11_check.raw.types_std import CKA_MODULUS, CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT
from pkcs11_check.testcases.acvp.test_acvp_rsa_keygen import _require_rsa_keygen_attribute


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    clear()
    yield
    clear()


@pytest.mark.parametrize(
    ("attr_id", "name"),
    [
        (CKA_MODULUS_BITS, "CKA_MODULUS_BITS"),
        (CKA_MODULUS, "CKA_MODULUS"),
        (CKA_PUBLIC_EXPONENT, "CKA_PUBLIC_EXPONENT"),
    ],
)
def test_missing_rsa_keygen_attribute_is_a_metadata_failure(attr_id: int, name: str) -> None:
    """A successful attribute query must not silently omit a required RSA attribute."""
    with pytest.raises(Failed):
        _require_rsa_keygen_attribute({}, attr_id, "rsa-vector", name)

    record = get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.outcome == "fail"
    assert record.kind == "metadata"
    assert record.label == f"rsa-vector:{name}"
