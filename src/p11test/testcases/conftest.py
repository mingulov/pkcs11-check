"""Shared fixtures and configuration for p11test PKCS#11 test cases."""

from __future__ import annotations

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip all PKCS#11 testcases if no module is configured."""
    if config.getoption("p11_module", default=None) is None:
        skip = pytest.mark.skip(reason="No --p11-module specified")
        for item in items:
            item.add_marker(skip)
