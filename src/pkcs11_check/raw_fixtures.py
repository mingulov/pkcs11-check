"""Raw PKCS#11 pytest fixtures -- uses pkcs11_check.raw, not the python-pkcs11 fork."""

from __future__ import annotations

from collections.abc import Generator
from ctypes import byref

import pytest

from pkcs11_check.config import P11TestConfig
from pkcs11_check.fixtures import resolve_cli_settings
from pkcs11_check.raw import RawPKCS11
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    get_slot_ids,
    login_user,
    logout_quietly,
    open_session,
    resolve_slot_id,
)
from pkcs11_check.raw.types_std import (
    CK_MECHANISM_TYPE,
    CK_ULONG,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKR_OK,
    CKU_USER,
)


def _merged_config(request: pytest.FixtureRequest) -> P11TestConfig:
    """Merged CLI > env > TOML settings shared with the runtime path (S3)."""
    from tomllib import TOMLDecodeError

    from pydantic import ValidationError

    module_path = request.config.getoption("p11_module")
    try:
        return resolve_cli_settings(module_path, request.config.getoption)
    except (ValidationError, TOMLDecodeError) as exc:
        raise pytest.UsageError(f"invalid pkcs11-check configuration: {exc}") from exc


@pytest.fixture(scope="session")
def raw_pkcs11(request: pytest.FixtureRequest) -> Generator[RawPKCS11]:
    """Load a PKCS#11 module via the raw layer and initialize it."""
    module_path = request.config.getoption("p11_module")
    if module_path is None:
        pytest.skip("No --p11-module specified")
    cfg = _merged_config(request)
    raw = RawPKCS11.from_lib(str(module_path), interface=cfg.interface or "auto")
    yield raw


@pytest.fixture(scope="session")
def raw_slot_id(raw_pkcs11: RawPKCS11, request: pytest.FixtureRequest) -> int:
    """Slot index into token-present slots (--p11-slot/P11TEST_SLOT/TOML)."""
    slots = get_slot_ids(raw_pkcs11)
    if not slots:
        pytest.skip("No slots with tokens found")
    cfg = _merged_config(request)
    try:
        return resolve_slot_id(slots, cfg.slot)
    except (IndexError, ValueError) as exc:
        raise pytest.UsageError(str(exc)) from exc


@pytest.fixture
def raw_session(
    raw_pkcs11: RawPKCS11,
    raw_slot_id: int,
    request: pytest.FixtureRequest,
) -> Generator[int]:
    """Open a raw PKCS#11 RW session with login. Yields session handle.

    Performs login/logout per test to avoid UserAlreadyLoggedIn cascading.
    The PIN resolves through the merged config, so env/TOML pins log in
    exactly like runtime sessions; an explicit empty PIN means no login.
    """
    cfg = _merged_config(request)
    pin_value: str | None = cfg.pin.get_secret_value() if cfg.pin else None
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
    sh = open_session(raw_pkcs11, raw_slot_id, flags)
    logged_in = False
    try:
        if pin_value is not None:
            login_user(raw_pkcs11, sh, CKU_USER, pin_value.encode("utf-8"))
            logged_in = True
        yield sh
    finally:
        if logged_in:
            logout_quietly(raw_pkcs11, sh)
        close_session_quietly(raw_pkcs11, sh)


# --- Mechanism availability helper ---

_raw_mechanism_cache: dict[tuple[int, int], frozenset[str]] = {}


def raw_has_mechanism(raw: RawPKCS11, slot_id: int, name: str) -> bool:
    """Check if a PKCS#11 slot supports a named mechanism (via raw layer).

    The mechanism list is cached per (raw-id, slot) pair.
    """
    key = (id(raw), slot_id)
    cached = _raw_mechanism_cache.get(key)
    if cached is None:
        count = CK_ULONG(0)
        rv = raw.C_GetMechanismList(slot_id, None, byref(count))
        if rv != CKR_OK:
            return False
        mechs = (CK_MECHANISM_TYPE * count.value)()
        rv = raw.C_GetMechanismList(slot_id, mechs, byref(count))
        if rv != CKR_OK:
            return False
        from pkcs11_check.raw import metadata_std

        mech_names: set[str] = set()
        for i in range(count.value):
            mech_val = mechs[i]
            sym = metadata_std.MECHANISM_NAMES.get(mech_val)
            if sym:
                # Strip CKM_ prefix for compatibility with has_mechanism("AES_CBC")
                short = sym[4:] if sym.startswith("CKM_") else sym
                mech_names.add(short)
                mech_names.add(sym)
        cached = frozenset(mech_names)
        _raw_mechanism_cache[key] = cached
    return name in cached
