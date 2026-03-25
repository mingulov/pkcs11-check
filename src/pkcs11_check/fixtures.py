"""pytest fixtures for PKCS#11 testing."""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pkcs11 as _p11
import pytest

from pkcs11_check.config import P11TestConfig
from pkcs11_check.core.loader import P11Module, load_module
from pkcs11_check.raw.api import RawPKCS11


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
            logged_in = True  # Already logged in at token level - reuse
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


@dataclass
class RawSession:
    """Raw PKCS#11 session for migrated tests.

    Mechanism list is cached lazily on first access -- raw package stays
    stateless, caching is fixture-owned and dies with the session.
    """

    raw: RawPKCS11
    sh: int
    slot_id: int
    _mechanisms: frozenset[str] | None = field(default=None, repr=False)

    @property
    def mechanisms(self) -> frozenset[str]:
        """Cached mechanism name set (both 'CKM_AES_ECB' and 'AES_ECB' forms)."""
        if self._mechanisms is None:
            from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
            from pkcs11_check.raw.recipes import get_mechanism_list

            mechs = get_mechanism_list(self.raw, self.slot_id)
            names: set[str] = set()
            for m in mechs:
                mname = MECHANISM_NAMES.get(m, "")
                if mname:
                    names.add(mname)
                    if mname.startswith("CKM_"):
                        names.add(mname[4:])
            self._mechanisms = frozenset(names)
        return self._mechanisms

    def has_mechanism(self, name: str) -> bool:
        """Check if a mechanism is supported by name (prefix-optional)."""
        return name in self.mechanisms


@pytest.fixture
def p11_raw_session(
    p11_module: P11Module,
    p11_config: P11TestConfig,
) -> Generator[RawSession, None, None]:
    """Open a raw PKCS#11 session bridged from the loaded module.

    Yields RawSession with raw, session_handle, slot_id, and cached
    mechanism discovery. Handles login/logout.

    Note: this opens a separate session from p11_session. Both can coexist
    because PKCS#11 login is per-token, and login_user() accepts
    CKR_USER_ALREADY_LOGGED_IN.
    """
    from pkcs11_check.raw.bootstrap import (
        close_session_quietly,
        get_slot_ids,
        login_user,
    )
    from pkcs11_check.raw.bootstrap import (
        open_session as raw_open_session,
    )
    from pkcs11_check.raw.bridge import raw_from_module
    from pkcs11_check.raw.types_std import (
        CKF_RW_SESSION,
        CKF_SERIAL_SESSION,
        CKU_USER,
    )

    raw = raw_from_module(p11_module)
    slots = get_slot_ids(raw)
    slot_idx = p11_config.slot if p11_config.slot is not None else 0
    slot_id = slots[slot_idx] if slot_idx < len(slots) else slots[0]

    flags = int(CKF_SERIAL_SESSION | CKF_RW_SESSION)
    sh = raw_open_session(raw, slot_id, flags)

    pin = p11_config.pin.get_secret_value() if p11_config.pin else None
    if pin is not None:
        login_user(raw, sh, int(CKU_USER), pin.encode("utf-8"))

    try:
        yield RawSession(raw, sh, slot_id)
    finally:
        if pin is not None:
            raw.C_Logout(sh)  # returns CKR int, never raises
        close_session_quietly(raw, sh)
