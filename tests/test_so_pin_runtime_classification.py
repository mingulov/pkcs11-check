"""Regression tests for SO PIN setup classification."""

from __future__ import annotations

import pytest

from pkcs11_check.raw.types_std import CKR_PIN_INCORRECT
from pkcs11_check.testcases import test_access_levels, test_session_state_machine


@pytest.mark.parametrize(
    "module",
    [test_access_levels, test_session_state_machine],
)
def test_so_pin_incorrect_is_setup_skip(module: object) -> None:
    classifier = getattr(module, "_skip_if_so_pin_differs")

    with pytest.raises(pytest.skip.Exception, match="SO PIN differs from user PIN"):
        classifier(CKR_PIN_INCORRECT)
