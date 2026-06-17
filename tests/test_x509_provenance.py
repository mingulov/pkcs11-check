"""Regression: x509 limbo loader stamps _source and _vector_id on every testcase."""

from __future__ import annotations

import pytest

from pkcs11_check.testcases.x509.conftest import load_limbo_testcases


def test_limbo_cases_carry_source_and_vector_id() -> None:
    cases = load_limbo_testcases()
    if not cases:
        pytest.skip("x509-limbo data not present in this checkout")
    assert cases[0]["_source"] == "x509:limbo.json"
    assert cases[0]["_vector_id"].startswith("id=")
