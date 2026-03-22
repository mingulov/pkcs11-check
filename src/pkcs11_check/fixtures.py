"""pytest fixtures for PKCS#11 testing."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from typing import Any

import pkcs11 as _p11
import pytest

from pkcs11_check.config import P11TestConfig
from pkcs11_check.core.loader import P11Module, load_module


@pytest.fixture(scope="session")
def p11_config(request: pytest.FixtureRequest) -> P11TestConfig:
    """Merged configuration from CLI options, env vars, and TOML."""
    module_path = request.config.getoption("p11_module")
    if module_path is None:
        pytest.skip("No --p11-module specified")
    pin_value = request.config.getoption("p11_pin")
    kwargs: dict[str, Any] = {
        "module": Path(module_path),
        "interface": request.config.getoption("p11_interface"),
        "slot": request.config.getoption("p11_slot"),
        "destructive": request.config.getoption("p11_destructive"),
    }
    if pin_value is not None:
        kwargs["pin"] = pin_value
    return P11TestConfig(**kwargs)


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
    """Open PKCS#11 session with login. Yields session, closes after test.

    After the test, we attempt to logout so the next test can login fresh.
    This avoids UserAlreadyLoggedIn / UserTypeInvalid cascading failures.
    """
    token = p11_module.get_token(p11_config.slot)
    pin = p11_config.pin.get_secret_value() if p11_config.pin else None
    session = token.open(rw=True)
    logged_in = False
    if pin is not None:
        try:
            session.login(_p11.UserType.USER, pin)
            logged_in = True
        except _p11.exceptions.UserAlreadyLoggedIn:
            logged_in = True  # Already logged in at token level -- reuse
    try:
        yield session
    finally:
        if logged_in:
            try:
                session.logout()
            except (
                _p11.exceptions.UserNotLoggedIn,
                _p11.exceptions.SessionClosed,
                _p11.exceptions.FunctionFailed,
            ):
                pass  # Logout may fail if session closed or not logged in
        session.close()
