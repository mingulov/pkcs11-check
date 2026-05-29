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
    kwargs: dict[str, Any] = {"module": Path(module_path)}
    interface = request.config.getoption("p11_interface")
    if interface is not None:
        kwargs["interface"] = interface
    slot = request.config.getoption("p11_slot")
    if slot is not None:
        kwargs["slot"] = slot
    destructive = request.config.getoption("p11_destructive")
    if destructive:
        kwargs["destructive"] = destructive
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
        try:
            login_user(raw, sh, CKU_USER, pin.encode("utf-8"))
            logged_in = True
        except Exception:
            from pkcs11_check.raw.bootstrap import close_session_quietly

            close_session_quietly(raw, sh)
            raise

    return raw, sh, slot_id, logged_in


@pytest.fixture
def p11_session(p11_module: P11Module, p11_config: P11TestConfig) -> Generator[Any]:
    """Open PKCS#11 session with login. Yields RawSession, closes after test.

    After the test, we attempt to logout so the next test can login fresh.
    This avoids UserAlreadyLoggedIn / UserTypeInvalid cascading failures.
    """
    from pkcs11_check.raw.bootstrap import close_session_quietly, logout_quietly

    raw, sh, slot_id, logged_in = _open_raw_session(p11_module, p11_config)
    bootstrap_log = dict(raw.call_log)
    raw.reset_call_log()
    raw.reset_used_mechanisms()
    try:
        yield RawSession(raw, sh, slot_id, bootstrap_call_counts=bootstrap_log)
    finally:
        if logged_in:
            logout_quietly(raw, sh)
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

# Module-level mechanism cache: populated after the first C_GetMechanismList call
# and reused by all subsequent RawSession instances in the same process.
# The mechanism list is a slot property that does not change between tests.
_MECHANISM_CACHE: frozenset[str] | None = None


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
        The result is stored in a module-level cache after the first call so that
        subsequent RawSession instances (one per test function) skip the
        C_GetMechanismList round-trips entirely.
        """
        global _MECHANISM_CACHE
        if self._mechanisms is None:
            if _MECHANISM_CACHE is not None:
                self._mechanisms = _MECHANISM_CACHE
            else:
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
                _MECHANISM_CACHE = self._mechanisms
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

    def seed_random(self, seed: bytes, *, extra_ok: tuple[int, ...] = ()) -> int:
        """Seed the RNG via C_SeedRandom.  Returns the raw CK_RV."""
        from pkcs11_check.raw.recipes import seed_random as _seed_random

        return _seed_random(self.raw, self.sh, seed, extra_ok=extra_ok)


@pytest.fixture
def p11_raw_session(
    p11_module: P11Module,
    p11_config: P11TestConfig,
) -> Generator[RawSession]:
    """Open a raw PKCS#11 session.

    Yields RawSession with raw, session_handle, slot_id, and cached
    mechanism discovery. Handles login/logout.

    Note: this opens a separate session from p11_session. Both can coexist
    because PKCS#11 login is per-token, and login_user() accepts
    CKR_USER_ALREADY_LOGGED_IN.
    """
    from pkcs11_check.raw.bootstrap import close_session_quietly, logout_quietly

    raw, sh, slot_id, logged_in = _open_raw_session(p11_module, p11_config)
    bootstrap_log = dict(raw.call_log)
    raw.reset_call_log()
    raw.reset_used_mechanisms()
    try:
        yield RawSession(raw, sh, slot_id, bootstrap_call_counts=bootstrap_log)
    finally:
        if logged_in:
            logout_quietly(raw, sh)
        close_session_quietly(raw, sh)


class _ModuleSessionHolder:
    """Holds a module-scoped PKCS#11 session with self-healing.

    The session is opened once per test module and reused across all tests
    in the module. Before each handout, the session is health-checked via
    C_GetSessionInfo. If a prior test closed the session or logged out the
    token, a fresh session is opened transparently for the next test.

    PKCS#11 spec note: C_*Init does NOT silently cancel a pending operation of
    the same class -- it returns CKR_OPERATION_ACTIVE. So a provider that fails
    to terminate an operation when the spec requires it (e.g. kryoptic /
    tpm2-pkcs11 leave a verify op active after C_Verify rejects a signature,
    violating "a call to C_Verify always terminates the active verification
    operation") would leave the shared session dirty. The single-shot recipes
    handle this reactively: ``_init_or_recover`` cancels the stale op and
    retries the init once if (and only if) a C_*Init returns
    CKR_OPERATION_ACTIVE, so one provider misbehavior cannot cascade onto
    sibling tests -- with zero extra round-trips on the clean path. Outright
    C_CloseSession / C_Logout / C_Finalize damage is detected by the health
    check below and triggers a reopen.
    """

    def __init__(self, p11_module: P11Module, p11_config: P11TestConfig) -> None:
        self._module = p11_module
        self._config = p11_config
        self._sh: int | None = None
        self._slot_id: int | None = None
        self._logged_in: bool = False
        self._bootstrap_log: dict[str, int] = {}
        self._reopen_count: int = 0

    @property
    def raw(self) -> RawPKCS11:
        return self._module.raw

    @property
    def reopen_count(self) -> int:
        """Number of times the session was re-opened due to damage."""
        return self._reopen_count

    def get_session(self) -> tuple[int, int, dict[str, int]]:
        """Return (sh, slot_id, bootstrap_log); reopen if damaged or if a prior test
        left an unclearable active operation (see recipes._init_or_recover)."""
        from pkcs11_check.raw.recipes import consume_session_reopen_request

        # Consume the reopen request FIRST (unconditionally) so it is always
        # cleared -- a short-circuit on the health check must not leave a stale
        # request that triggers a spurious reopen on a later handout.
        reopen_requested = consume_session_reopen_request()
        if reopen_requested or not self._is_healthy():
            self._reopen()
        assert self._sh is not None and self._slot_id is not None
        return self._sh, self._slot_id, dict(self._bootstrap_log)

    def _is_healthy(self) -> bool:
        if self._sh is None:
            return False
        import ctypes

        from pkcs11_check.raw.types_std import CK_SESSION_INFO, CKR_OK

        info = CK_SESSION_INFO()
        try:
            rv = self.raw.C_GetSessionInfo(self._sh, ctypes.byref(info))
        except (AttributeError, OSError, ctypes.ArgumentError):
            return False
        if rv != CKR_OK:
            return False
        if self._logged_in:
            # CKS_RO_PUBLIC_SESSION=0, CKS_RW_PUBLIC_SESSION=2 mean login was dropped.
            if int(info.state) in (0, 2):
                return False
        return True

    def _reopen(self) -> None:
        self._close()
        raw, sh, slot_id, logged_in = _open_raw_session(self._module, self._config)
        self._sh = sh
        self._slot_id = slot_id
        self._logged_in = logged_in
        self._bootstrap_log = dict(raw.call_log)
        self._reopen_count += 1

    def _close(self) -> None:
        if self._sh is None:
            return
        from pkcs11_check.raw.bootstrap import close_session_quietly, logout_quietly

        if self._logged_in:
            logout_quietly(self.raw, self._sh)
        close_session_quietly(self.raw, self._sh)
        self._sh = None
        self._logged_in = False

    def close(self) -> None:
        self._close()


@pytest.fixture(scope="module")
def _p11_module_session_holder(
    p11_module: P11Module,
    p11_config: P11TestConfig,
) -> Generator[_ModuleSessionHolder]:
    """Module-scoped holder; lifecycle bound to the test module."""
    holder = _ModuleSessionHolder(p11_module, p11_config)
    try:
        yield holder
    finally:
        holder.close()


@pytest.fixture
def p11_module_session(
    _p11_module_session_holder: _ModuleSessionHolder,
) -> Generator[RawSession]:
    """Module-scoped PKCS#11 session with per-test counter reset.

    Open + login happens ONCE per test module (file). All tests in the
    module share the same session handle and logged-in token state.
    Per-test call_log and used_mechanisms are reset so coverage tracking
    stays accurate.

    Before each test, the session is health-checked via C_GetSessionInfo.
    If a prior test closed the session or logged out the token, the next
    test transparently receives a fresh session+login.

    Use this for read-only verification tests (Wycheproof, ACVP vectors)
    where each test independently imports key material and runs one
    crypto operation. DO NOT use for tests that test session lifecycle,
    login/logout/PIN behavior, or require a freshly-opened session per
    invocation -- use ``p11_raw_session`` (function-scoped) for those.

    Performance: avoids the per-test C_OpenSession + C_Login overhead,
    which is ~47ms on OpenCryptoki SWToken (PBKDF2-based PIN derivation)
    and ~80ms on BouncyHSM (HTTP/TCP RPC). For a 28,915-test file this
    saves 23 minutes (OpenCryptoki) or 39 minutes (BouncyHSM) of pure
    login overhead.
    """
    holder = _p11_module_session_holder
    sh, slot_id, bootstrap_log = holder.get_session()
    raw = holder.raw
    raw.reset_call_log()
    raw.reset_used_mechanisms()
    yield RawSession(raw, sh, slot_id, bootstrap_call_counts=bootstrap_log)
