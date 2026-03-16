"""pytest fixtures for PKCS#11 testing."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from p11test.config import P11TestConfig
from p11test.core.loader import P11Module, load_module


@pytest.fixture(scope="session")
def p11_config(request: pytest.FixtureRequest) -> P11TestConfig:
    """Merged configuration from CLI options, env vars, and TOML."""
    module_path = request.config.getoption("p11_module")
    if module_path is None:
        pytest.skip("No --p11-module specified")
    return P11TestConfig(
        module=Path(module_path),
        interface=request.config.getoption("p11_interface"),
        slot=request.config.getoption("p11_slot"),
        destructive=request.config.getoption("p11_destructive"),
    )


@pytest.fixture(scope="session")
def p11_module(p11_config: P11TestConfig) -> P11Module:
    """Loaded and negotiated PKCS#11 module."""
    return load_module(p11_config.module, interface=p11_config.interface)


@pytest.fixture(scope="session")
def p11_interface_version(p11_module: P11Module) -> str:
    """Negotiated interface version string."""
    return p11_module.interface_version


@pytest.fixture
def p11_session(p11_module: P11Module, p11_config: P11TestConfig) -> Generator[Any, None, None]:
    """Open PKCS#11 session with login. Yields session, closes after test."""
    token = p11_module.get_token(p11_config.slot)
    pin = p11_config.pin.get_secret_value() if p11_config.pin else None
    with token.open(user_pin=pin) as session:
        yield session
