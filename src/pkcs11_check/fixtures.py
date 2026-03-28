"""pytest fixtures for PKCS#11 testing."""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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


def _open_raw_session(
    p11_module: P11Module,
    p11_config: P11TestConfig,
) -> tuple[RawPKCS11, int, int, bool]:
    """Open a raw PKCS#11 session and optionally login.

    Returns (raw, session_handle, slot_id, logged_in).
    Caller is responsible for logout and close.
    """
    from pkcs11_check.raw.bootstrap import get_slot_ids, login_user
    from pkcs11_check.raw.bootstrap import open_session as raw_open_session
    from pkcs11_check.raw.types_std import CKF_RW_SESSION, CKF_SERIAL_SESSION, CKU_USER

    raw = p11_module.raw
    slots = get_slot_ids(raw)
    slot_idx = p11_config.slot if p11_config.slot is not None else 0
    slot_id = slots[slot_idx] if slot_idx < len(slots) else slots[0]

    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
    sh = raw_open_session(raw, slot_id, flags)

    pin = p11_config.pin.get_secret_value() if p11_config.pin else None
    logged_in = False
    if pin is not None:
        login_user(raw, sh, CKU_USER, pin.encode("utf-8"))
        logged_in = True

    return raw, sh, slot_id, logged_in


@pytest.fixture
def p11_session(p11_module: P11Module, p11_config: P11TestConfig) -> Generator[Any, None, None]:
    """Open PKCS#11 session with login. Yields RawSession, closes after test.

    After the test, we attempt to logout so the next test can login fresh.
    This avoids UserAlreadyLoggedIn / UserTypeInvalid cascading failures.
    """
    from pkcs11_check.raw.bootstrap import close_session_quietly

    raw, sh, slot_id, logged_in = _open_raw_session(p11_module, p11_config)
    bootstrap_log = dict(raw.call_log)
    raw.reset_call_log()
    raw.reset_used_mechanisms()
    try:
        yield RawSession(raw, sh, slot_id, bootstrap_call_counts=bootstrap_log)
    finally:
        if logged_in:
            raw.C_Logout(sh)  # type: ignore[attr-defined]
        close_session_quietly(raw, sh)


def _build_ckm_alias_map() -> dict[int, list[str]]:
    """Build a reverse map from CKM int value to all CKM_* names for that value."""
    import importlib as _il
    from collections import defaultdict

    _ts = _il.import_module("pkcs11_check.raw.types_std")
    by_val: dict[int, list[str]] = defaultdict(list)
    for attr_name in dir(_ts):
        if attr_name.startswith("CKM_") and attr_name.isupper():
            val = getattr(_ts, attr_name)
            if isinstance(val, int):
                by_val[int(val)].append(attr_name)
    return {v: names for v, names in by_val.items() if len(names) > 1}


_CKM_ALIAS_MAP: dict[int, list[str]] | None = None


def _get_ckm_aliases(types_std_mod: Any, mech_int: int) -> list[str]:
    """Return alias CKM names for a mechanism value (empty if no aliases)."""
    global _CKM_ALIAS_MAP
    if _CKM_ALIAS_MAP is None:
        _CKM_ALIAS_MAP = _build_ckm_alias_map()
    return _CKM_ALIAS_MAP.get(mech_int, [])


@dataclass
class RawSession:
    """Raw PKCS#11 session.

    Exposes raw, sh (session handle), slot_id, and convenience wrappers
    for common operations. Mechanism list is cached lazily on first access.
    """

    raw: RawPKCS11
    sh: int
    slot_id: int
    _mechanisms: frozenset[str] | None = field(default=None, repr=False)
    bootstrap_call_counts: dict[str, int] = field(default_factory=dict, repr=False)

    @property
    def mechanisms(self) -> frozenset[str]:
        """Cached mechanism name set (both 'CKM_AES_ECB' and 'AES_ECB' forms).

        Includes alias names (e.g. 'EC_KEY_PAIR_GEN' for CKM_ECDSA_KEY_PAIR_GEN).
        """
        if self._mechanisms is None:
            import importlib as _importlib

            from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
            from pkcs11_check.raw.recipes import get_mechanism_list

            _ts = _importlib.import_module("pkcs11_check.raw.types_std")
            mechs = get_mechanism_list(self.raw, self.slot_id)
            names: set[str] = set()
            for m in mechs:
                mname = MECHANISM_NAMES.get(m, "")
                if mname:
                    names.add(mname)
                    if mname.startswith("CKM_"):
                        names.add(mname[4:])
                for alias in _get_ckm_aliases(_ts, int(m)):
                    names.add(alias)
                    if alias.startswith("CKM_"):
                        names.add(alias[4:])
            self._mechanisms = frozenset(names)
        return self._mechanisms

    def has_mechanism(self, name: str) -> bool:
        """Check if a mechanism is supported by name (prefix-optional)."""
        return name in self.mechanisms

    def generate_random(self, bits: int) -> bytes:
        """Generate random bytes via C_GenerateRandom.

        Args:
            bits: Number of bits to generate. Must be a multiple of 8.

        Returns:
            bytes of length bits // 8.
        """
        from pkcs11_check.raw.recipes import generate_random as _generate_random

        length = bits // 8
        return _generate_random(self.raw, self.sh, length)

    def seed_random(self, seed: bytes) -> None:
        """Seed the RNG via C_SeedRandom."""
        from pkcs11_check.raw.recipes import seed_random as _seed_random

        _seed_random(self.raw, self.sh, seed)


@pytest.fixture
def p11_raw_session(
    p11_module: P11Module,
    p11_config: P11TestConfig,
) -> Generator[RawSession, None, None]:
    """Open a raw PKCS#11 session.

    Yields RawSession with raw, session_handle, slot_id, and cached
    mechanism discovery. Handles login/logout.

    Note: this opens a separate session from p11_session. Both can coexist
    because PKCS#11 login is per-token, and login_user() accepts
    CKR_USER_ALREADY_LOGGED_IN.
    """
    from pkcs11_check.raw.bootstrap import close_session_quietly

    raw, sh, slot_id, logged_in = _open_raw_session(p11_module, p11_config)
    bootstrap_log = dict(raw.call_log)
    raw.reset_call_log()
    raw.reset_used_mechanisms()
    try:
        yield RawSession(raw, sh, slot_id, bootstrap_call_counts=bootstrap_log)
    finally:
        if logged_in:
            raw.C_Logout(sh)  # type: ignore[attr-defined]
        close_session_quietly(raw, sh)
