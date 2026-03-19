"""CKR error coverage test configuration.

Registers --ckr-strict flag for strict PKCS#11 spec CKR compliance mode.
"""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register CKR-specific command-line options."""
    group = parser.getgroup("ckr", "CKR spec compliance options")
    group.addoption(
        "--ckr-strict",
        action="store_true",
        default=False,
        help="Strict CKR compliance: spec deviations are test failures, not notes",
    )


@pytest.fixture
def ckr_strict(request: pytest.FixtureRequest) -> bool:
    """Whether to enforce exact spec CKR codes.

    When True: deviations from spec-mandated CKR codes are test failures.
    When False (default): deviations are logged as compliance notes.
    Both modes fail on errors outside the acceptable set.
    """
    return request.config.getoption("--ckr-strict")
