"""The undeclared_capability reason: symmetric over-advertised partner of not_operational."""

from __future__ import annotations

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check import classification as C


def test_reason_maps_to_xfail_low() -> None:
    outcome, severity = C.derive_verdict("undeclared_capability", None)
    assert outcome == "xfail"
    assert severity == "LOW"


def test_xfail_as_accepts_it() -> None:
    with pytest.raises(XFailed):
        C.xfail_as("undeclared_capability", label="probe", summary="performed above advertised max")


def test_fail_as_rejects_it() -> None:
    with pytest.raises(ValueError):
        C.fail_as("undeclared_capability", label="probe", summary="should not be a fail reason")
