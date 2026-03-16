"""pytest plugin entry point for p11test."""

from __future__ import annotations

from typing import Any

# Re-export fixtures so pytest discovers them
from p11test.fixtures import (  # noqa: F401
    p11_config,
    p11_interface_version,
    p11_module,
    p11_session,
)


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
