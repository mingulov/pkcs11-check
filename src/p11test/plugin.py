"""pytest plugin entry point for p11test."""

from __future__ import annotations

from typing import Any

import pytest

# Re-export fixtures so pytest discovers them
from p11test.fixtures import (  # noqa: F401
    p11_config,
    p11_interface_version,
    p11_module,
    p11_session,
)
from p11test.markers import MARKER_DEFINITIONS, should_skip_for_version


def pytest_addoption(parser: Any) -> None:
    """Register p11test CLI options with pytest."""
    group = parser.getgroup("p11test", "PKCS#11 testing")
    group.addoption(
        "--p11-module",
        dest="p11_module",
        default=None,
        help="Path to PKCS#11 module (.so/.dll/.dylib)",
    )
    group.addoption(
        "--p11-interface",
        dest="p11_interface",
        default="auto",
        help="Force interface version: auto, 2.40, 3.0, 3.2",
    )
    group.addoption(
        "--p11-slot",
        dest="p11_slot",
        type=int,
        default=0,
        help="Slot index (default: 0)",
    )
    group.addoption(
        "--p11-pin",
        dest="p11_pin",
        default=None,
        help="PIN (prefer P11TEST_PIN env var)",
    )
    group.addoption(
        "--p11-destructive",
        dest="p11_destructive",
        action="store_true",
        default=False,
        help="Enable destructive tests",
    )
    group.addoption(
        "--p11-skip-unsupported",
        dest="p11_skip_unsupported",
        action="store_true",
        default=True,
        help="Auto-skip tests for unsupported mechanisms (default: on)",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Register p11test custom markers."""
    for marker in MARKER_DEFINITIONS:
        config.addinivalue_line("markers", f"{marker.name}: {marker.description}")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Auto-skip tests based on module availability, version, and destructive flag."""
    module_path = config.getoption("p11_module", default=None)

    # If no module specified, skip all tests in testcases/
    if module_path is None:
        for item in items:
            if "testcases" in str(item.fspath):
                item.add_marker(pytest.mark.skip(reason="No --p11-module specified"))
        return

    # Determine interface version (default to 2.40 for Phase 1)
    interface_version = "2.40"

    # Skip version-gated tests
    destructive_enabled = config.getoption("p11_destructive", default=False)
    for item in items:
        # Version markers
        for marker_name in ("requires_v30", "requires_v32"):
            if item.get_closest_marker(marker_name):
                if should_skip_for_version(marker_name, interface_version):
                    item.add_marker(
                        pytest.mark.skip(
                            reason=f"Requires {marker_name.replace('requires_', 'v')}, "
                            f"module has v{interface_version}"
                        )
                    )

        # Destructive marker
        if item.get_closest_marker("destructive") and not destructive_enabled:
            item.add_marker(
                pytest.mark.skip(reason="Destructive test (use --p11-destructive to enable)")
            )

    # Skip tests for unsupported mechanisms
    skip_unsupported = config.getoption("p11_skip_unsupported", default=True)
    if skip_unsupported and module_path is not None:
        try:
            from pathlib import Path

            from p11test.core.loader import load_module

            p11 = load_module(Path(module_path))
            slot = p11.get_slots(token_present=True)[0]
            available_mechanisms = {m.name for m in slot.get_mechanisms()}
        except Exception:
            available_mechanisms = None

        if available_mechanisms is not None:
            for item in items:
                marker = item.get_closest_marker("needs_mechanism")
                if marker and marker.args:
                    needed = marker.args[0]
                    if needed not in available_mechanisms:
                        item.add_marker(
                            pytest.mark.skip(reason=f"Mechanism {needed} not supported by module")
                        )
