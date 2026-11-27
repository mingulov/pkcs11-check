"""CKR error coverage test configuration.

The --ckr-strict flag itself is registered by the always-loaded
pkcs11-check pytest plugin (so CLI runs may pass it for any
selection); this module only exposes it as a fixture.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def ckr_strict(request: pytest.FixtureRequest) -> bool:
    """Whether to enforce exact spec CKR codes.

    When True: deviations from spec-mandated CKR codes are test failures.
    When False (default): deviations are logged as compliance notes.
    Both modes fail on errors outside the acceptable set.
    """
    return bool(request.config.getoption("--ckr-strict"))
