"""pytest fixtures for PKCS#11 testing."""

from __future__ import annotations

import os
import time
import warnings
from collections.abc import Generator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.config import P11TestConfig
from pkcs11_check.core.loader import P11Module, load_module
from pkcs11_check.raw.api import RawPKCS11

_RV_TRACE_TRUTHY = frozenset({"1", "true", "yes", "on"})
MODULE_SESSION_CALL_FAILED_ATTR = "_pkcs11_module_session_call_failed"


def _empty_module_session_health_metrics() -> dict[str, int | float]:
    return {"checks": 0, "duration_s": 0.0}


def _resolve_rv_trace(
    *,
    opt_trace: bool,
    opt_compact: int | None,
    env_trace: str | None,
    env_compact: str | None,
) -> tuple[bool, int | None]:
    """Resolve ``(enabled, maxlen)`` for the CK_RV trace from options + env.

    Options take precedence over env; a compact window size (``maxlen``) implies
    tracing is enabled. ``maxlen is None`` means full (unbounded) capture.
    """
    compact = opt_compact
    if compact is None and env_compact:
        try:
            compact = int(env_compact)
        except ValueError:
            compact = None
    compact_requested = compact is not None
    if compact is not None and compact <= 0:
        # A nonsensical window (<=0 would be a deque(maxlen) ValueError, or maxlen=0
        # silently records nothing) -> fall back to full capture, still enabled.
        compact = None
    env_on = (env_trace or "").strip().lower() in _RV_TRACE_TRUTHY
    enabled = bool(opt_trace) or env_on or compact_requested
    return enabled, compact


def _apply_rv_trace(raw: RawPKCS11, p11_config: P11TestConfig) -> None:
    """Arm (and per-test reset) the CK_RV trace on ``raw`` when configured on.

    Called at each session fixture's reset point, i.e. *after* bootstrap/login,
    so the PIN-bearing C_Login and session-open calls stay out of the test-body
    trace for successful fixture setup. It is also called before bootstrap so
    setup failures can carry the failing CK_RV; successful fixtures reset it
    again before yielding. ``enable_rv_trace`` doubles as the per-test reset.
    """
    if p11_config.rv_trace:
        raw.enable_rv_trace(maxlen=p11_config.rv_trace_compact)


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
    so_pin_value = request.config.getoption("p11_so_pin", default=None)
    if so_pin_value is not None:
        kwargs["so_pin"] = so_pin_value
    rv_trace_enabled, rv_trace_compact = _resolve_rv_trace(
        opt_trace=bool(request.config.getoption("p11_rv_trace", default=False)),
        opt_compact=request.config.getoption("p11_rv_trace_compact", default=None),
        env_trace=os.environ.get("PKCS11_CHECK_RV_TRACE"),
        env_compact=os.environ.get("PKCS11_CHECK_RV_TRACE_COMPACT"),
    )
    if rv_trace_enabled:
        kwargs["rv_trace"] = True
        kwargs["rv_trace_compact"] = rv_trace_compact
    key_inject = request.config.getoption("p11_key_inject", default="off")
    if key_inject != "off":
        kwargs["key_inject"] = key_inject
    wrap_key_source = request.config.getoption("p11_wrap_key_source", default="bootstrap")
    if wrap_key_source != "bootstrap":
        kwargs["wrap_key_source"] = wrap_key_source
    wrap_key_label = request.config.getoption("p11_wrap_key_label", default=None)
    if wrap_key_label is not None:
        kwargs["wrap_key_label"] = wrap_key_label
    wrap_key_handle = request.config.getoption("p11_wrap_key_handle", default=None)
    if wrap_key_handle is not None:
        kwargs["wrap_key_handle"] = wrap_key_handle
    wrap_key_value = request.config.getoption("p11_wrap_key_value", default=None)
    if wrap_key_value is not None:
        kwargs["wrap_key_value"] = wrap_key_value
    wrap_mech = request.config.getoption("p11_wrap_mech", default=None)
    if wrap_mech is not None:
        kwargs["wrap_mech"] = wrap_mech
    wrap_rsa_bits = request.config.getoption("p11_wrap_rsa_bits", default=2048)
    if wrap_rsa_bits != 2048:
        kwargs["wrap_rsa_bits"] = wrap_rsa_bits
    wrap_oaep_hash = request.config.getoption("p11_wrap_oaep_hash", default="auto")
    if wrap_oaep_hash != "auto":
        kwargs["wrap_oaep_hash"] = wrap_oaep_hash
    allow_external = request.config.getoption("p11_allow_external_provision", default=False)
    if allow_external:
        kwargs["allow_external_provision"] = True
    ext_cmd = request.config.getoption("p11_external_provision_cmd", default=None)
    if ext_cmd is not None:
        kwargs["external_provision_cmd"] = ext_cmd
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
    from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, resolve_slot_id
    from pkcs11_check.raw.bootstrap import open_session as raw_open_session
    from pkcs11_check.raw.types_std import CKF_RW_SESSION, CKF_SERIAL_SESSION, CKU_USER

    raw = p11_module.raw
    _apply_rv_trace(raw, p11_config)
    slots = get_slot_ids(raw)
    # config.slot is an index into the present-token slots (shared resolver: the probe harness
    # uses the same one, so parent and probe subprocess always pick the same slot).
    slot_id = resolve_slot_id(slots, p11_config.slot)

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


# --- provider/proxy restart recovery (proxy restart window) ------------------
# A proxied provider crash + restart is NOT instantaneous: a proxy/daemon
# restarts the provider and restores access over seconds, during which the
# surviving client module returns a "connection lost" CK_RV for every call.
# Recovery is a BOUNDED wait-and-reconnect loop -- reconnect (C_Finalize +
# C_Initialize), then re-open + re-login -- so the restart window does not
# cascade onto every remaining test in the file. The loop is bounded by a time
# AND an attempt budget, so a genuinely dead provider fails as a finding (never
# hangs). The triggering test still records its own (real) result; every
# reconnect is surfaced (warning + reinit_count). No CLI/env knob by design --
# tune the constants here if a deployment needs a different window.
_RECONNECT_TIMEOUT_S = 20.0  # total wall-clock budget for one session bootstrap
_RECONNECT_MAX_ATTEMPTS = 64  # hard backstop on reconnect attempts
_RECONNECT_INITIAL_DELAY_S = 0.1  # first backoff sleep
_RECONNECT_MAX_DELAY_S = 2.0  # backoff cap


def _restart_signature_rvs(
    *,
    include_ambiguous_general_error: bool = False,
) -> frozenset[int]:
    """CK_RVs that, *at session bootstrap*, mean "the connection/session is gone".

    Recovery triggers ONLY at the fixture open/login layer, where these codes
    cannot mean a legitimately-rejected operation. They must NEVER be treated as
    a restart signal inside a test-body assertion path -- e.g. CKR_DEVICE_ERROR
    is also a known legitimate provider return for a rejected signature, so misusing it there
    would mask real findings.
    """
    from pkcs11_check.raw.types_std import (
        CKR_CRYPTOKI_NOT_INITIALIZED,
        CKR_DEVICE_ERROR,
        CKR_DEVICE_REMOVED,
        CKR_GENERAL_ERROR,
        CKR_SESSION_CLOSED,
        CKR_SESSION_HANDLE_INVALID,
    )

    values = [
        CKR_CRYPTOKI_NOT_INITIALIZED,
        CKR_SESSION_HANDLE_INVALID,
        CKR_SESSION_CLOSED,
        CKR_DEVICE_ERROR,
        CKR_DEVICE_REMOVED,
    ]
    if include_ambiguous_general_error:
        # CKR_GENERAL_ERROR is too broad to mean "dead provider" in normal
        # operation or initial bootstrap. During a reopen after an already-held
        # session became unhealthy, it is an ambiguous bootstrap symptom worth
        # one bounded reconnect path before surfacing as a finding.
        values.append(CKR_GENERAL_ERROR)
    return frozenset(int(rv) for rv in values)


def _open_or_reinit(
    p11_module: P11Module,
    p11_config: P11TestConfig,
    *,
    recover_ambiguous_bootstrap_general_error: bool = False,
) -> tuple[RawPKCS11, int, int, bool]:
    """Open a session; bridge a provider/proxy restart with a bounded wait loop.

    A proxied provider crash + proxy restart leaves the surviving
    client module returning a restart-signature CK_RV (NOT_INITIALIZED, a stale
    SESSION_HANDLE_INVALID / SESSION_CLOSED, or a transport DEVICE_ERROR /
    DEVICE_REMOVED) -- or a transport ``OSError`` -- for the whole restart
    window. On the clean path the open succeeds once with zero added latency and
    no reinit. On a restart signature we reconnect (``reinitialize``) and retry
    the open, sleeping with capped exponential backoff between attempts until the
    provider returns or the time/attempt budget is exhausted (bounded -- never an
    infinite loop). Any *non*-restart CKR (e.g. a clean CKR_PIN_INCORRECT)
    propagates unchanged. The triggering test still records its own result; this
    only un-cascades the *subsequent* tests in the file.

    ``CKR_GENERAL_ERROR`` is included only when explicitly requested by a caller
    that is reopening after a previously healthy session became unusable. The
    same CKR during initial bootstrap still propagates immediately.
    """
    from pkcs11_check.raw.rv import CkrAssertionError

    restart_rvs = _restart_signature_rvs(
        include_ambiguous_general_error=recover_ambiguous_bootstrap_general_error
    )

    def _is_restart(exc: BaseException) -> bool:
        # A transport failure (OSError) or a bootstrap-layer "connection gone"
        # CK_RV. A RuntimeError from reinitialize() (C_Initialize still failing)
        # is handled as retryable by the loop below, not here.
        if isinstance(exc, OSError):
            return True
        return isinstance(exc, CkrAssertionError) and int(getattr(exc, "rv", -1)) in restart_rvs

    try:
        return _open_raw_session(p11_module, p11_config)
    except (CkrAssertionError, OSError) as exc:
        if not _is_restart(exc):
            raise
        last_exc: BaseException = exc

    deadline = time.monotonic() + _RECONNECT_TIMEOUT_S
    for attempt in range(1, _RECONNECT_MAX_ATTEMPTS + 1):
        try:
            p11_module.reinitialize()  # reconnect the client to the restarted proxy
            result = _open_raw_session(p11_module, p11_config)  # re-open + re-login
        except CkrAssertionError as exc:
            if not _is_restart(exc):
                raise  # a genuine non-restart CKR is a finding -- do not retry/mask
            last_exc = exc
        except (OSError, RuntimeError) as exc:
            # OSError = transport still down; RuntimeError = C_Initialize still
            # failing. Both are restart-window symptoms -> retry within budget.
            last_exc = exc
        else:
            warnings.warn(
                "PKCS#11 library reconnected after a likely provider/proxy restart "
                f"(reinit #{p11_module.reinit_count}, recovered on attempt {attempt})",
                stacklevel=2,
            )
            return result
        if attempt >= _RECONNECT_MAX_ATTEMPTS or time.monotonic() >= deadline:
            break
        delay = min(_RECONNECT_INITIAL_DELAY_S * 2 ** (attempt - 1), _RECONNECT_MAX_DELAY_S)
        time.sleep(delay)
    raise last_exc


@pytest.fixture
def p11_session(p11_module: P11Module, p11_config: P11TestConfig) -> Generator[Any]:
    """Open PKCS#11 session with login. Yields RawSession, closes after test.

    After the test, we attempt to logout so the next test can login fresh.
    This avoids UserAlreadyLoggedIn / UserTypeInvalid cascading failures.
    """
    from pkcs11_check.raw.bootstrap import close_session_quietly, logout_quietly
    from pkcs11_check.raw.recipes import consume_session_reopen_request

    raw, sh, slot_id, logged_in = _open_or_reinit(p11_module, p11_config)
    bootstrap_log = dict(raw.call_log)
    raw.reset_call_log()
    raw.reset_used_mechanisms()
    _apply_rv_trace(raw, p11_config)
    try:
        yield RawSession(raw, sh, slot_id, bootstrap_call_counts=bootstrap_log)
    finally:
        if logged_in:
            logout_quietly(raw, sh)
        close_session_quietly(raw, sh)
        # This is a fresh function-scoped session: a reopen request raised by a
        # recipe here refers to THIS (now-closed) session, not the shared one, so
        # discard it to keep it from leaking to a later module-scoped handout.
        consume_session_reopen_request()


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

# Per-(slot, mechanism) cache of C_GetMechanismInfo results, mirroring
# _MECHANISM_CACHE: module-level, populated once, reused across the per-test
# RawSession instances within a subprocess. Cold again in the next file's
# subprocess (per-file isolation), which is correct.
_MECH_INFO_CACHE: dict[tuple[int, int], dict[str, int]] = {}


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
    module_session_health_metrics: dict[str, int | float] = field(
        default_factory=_empty_module_session_health_metrics,
        repr=False,
    )

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

    def has_mechanism_flag(self, mechanism: str | int, flag: int) -> bool:
        """True if C_GetMechanismInfo reports *flag* set for *mechanism*.

        *mechanism* is a CKM int or a name (with or without the ``CKM_`` prefix).
        Returns ``False`` when the mechanism is not advertised, the name is
        unknown, or the requested flag is unset. An advertised mechanism whose
        info query fails remains a provider finding. Result is memoized in
        ``_MECH_INFO_CACHE``.
        """
        if isinstance(mechanism, str):
            if not self.has_mechanism(mechanism):
                return False
            from pkcs11_check.raw import types_std

            name = mechanism if mechanism.startswith("CKM_") else "CKM_" + mechanism
            mech_int_opt = getattr(types_std, name, None)
            if mech_int_opt is None:
                return False
            mech_int = int(mech_int_opt)
        else:
            mech_int = int(mechanism)

        key = (self.slot_id, mech_int)
        if key not in _MECH_INFO_CACHE:
            from pkcs11_check.raw.recipes import get_mechanism_info

            _MECH_INFO_CACHE[key] = get_mechanism_info(self.raw, self.slot_id, mech_int)

        return bool(_MECH_INFO_CACHE[key]["flags"] & flag)

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
    from pkcs11_check.raw.recipes import consume_session_reopen_request

    raw, sh, slot_id, logged_in = _open_or_reinit(p11_module, p11_config)
    bootstrap_log = dict(raw.call_log)
    raw.reset_call_log()
    raw.reset_used_mechanisms()
    _apply_rv_trace(raw, p11_config)
    try:
        yield RawSession(raw, sh, slot_id, bootstrap_call_counts=bootstrap_log)
    finally:
        if logged_in:
            logout_quietly(raw, sh)
        close_session_quietly(raw, sh)
        # Fresh function-scoped session: discard any reopen request a recipe
        # raised here so it cannot leak to a later shared-session handout.
        consume_session_reopen_request()


class _ModuleSessionHolder:
    """Holds a module-scoped PKCS#11 session with self-healing.

    The session is opened once per test module and reused across all tests
    in the module. Before each handout, the session is health-checked via
    C_GetSessionInfo. If a prior test closed the session or logged out the
    token, a fresh session is opened transparently for the next test.

    PKCS#11 spec note: C_*Init does NOT silently cancel a pending operation of
    the same class -- it returns CKR_OPERATION_ACTIVE. So a provider that fails
    to terminate an operation when the spec requires it (e.g. some modules
    leave a verify op active after C_Verify rejects a signature,
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
        self._health_check_required: bool = False
        self._health_check_count: int = 0
        self._health_check_duration_s: float = 0.0

    @property
    def raw(self) -> RawPKCS11:
        return self._module.raw

    @property
    def reopen_count(self) -> int:
        """Number of times the session was re-opened due to damage."""
        return self._reopen_count

    def require_health_check(self) -> None:
        """Force a health check before the next shared-session handout."""
        self._health_check_required = True

    def consume_health_metrics_delta(self) -> dict[str, int | float]:
        metrics = {
            "checks": self._health_check_count,
            "duration_s": self._health_check_duration_s,
        }
        self._health_check_count = 0
        self._health_check_duration_s = 0.0
        return metrics

    def get_session(self, *, skip_health_check: bool = False) -> tuple[int, int, dict[str, int]]:
        """Return (sh, slot_id, bootstrap_log); reopen if damaged or if a prior test
        left an unclearable active operation (see recipes._init_or_recover)."""
        from pkcs11_check.raw.recipes import consume_session_reopen_request

        # Consume the reopen request FIRST (unconditionally) so it is always
        # cleared -- a short-circuit on the health check must not leave a stale
        # request that triggers a spurious reopen on a later handout.
        reopen_requested = consume_session_reopen_request()
        if reopen_requested:
            self._reopen()
            self._health_check_required = False
        elif self._sh is None:
            self._reopen()
        elif self._health_check_required or not skip_health_check:
            if not self._is_healthy():
                self._reopen()
            self._health_check_required = False
        assert self._sh is not None and self._slot_id is not None
        return self._sh, self._slot_id, dict(self._bootstrap_log)

    def _is_healthy(self) -> bool:
        if self._sh is None:
            return False
        import ctypes

        from pkcs11_check.core.crash_codes import ctypes_access_violation_code
        from pkcs11_check.raw.types_std import CK_SESSION_INFO, CKR_OK

        info = CK_SESSION_INFO()
        start = time.monotonic()
        try:
            rv = self.raw.C_GetSessionInfo(self._sh, ctypes.byref(info))
        except (AttributeError, OSError, ctypes.ArgumentError) as exc:
            self._record_health_check(time.monotonic() - start)
            if ctypes_access_violation_code(exc) is not None:
                raise
            return False
        self._record_health_check(time.monotonic() - start)
        if rv != CKR_OK:
            return False
        if self._logged_in:
            # CKS_RO_PUBLIC_SESSION=0, CKS_RW_PUBLIC_SESSION=2 mean login was dropped.
            if int(info.state) in (0, 2):
                return False
        return True

    def _record_health_check(self, duration_s: float) -> None:
        self._health_check_count += 1
        self._health_check_duration_s += max(duration_s, 0.0)

    def _reopen(self) -> None:
        recover_general_error = self._sh is not None
        self._close()
        raw, sh, slot_id, logged_in = _open_or_reinit(
            self._module,
            self._config,
            recover_ambiguous_bootstrap_general_error=recover_general_error,
        )
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
    p11_config: P11TestConfig,
    request: pytest.FixtureRequest,
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
    which can be tens of milliseconds per login on modules with PBKDF2-based
    PIN derivation or RPC-backed transports. For a 28,915-test file that adds
    up to tens of minutes of pure login overhead.
    """
    holder = _p11_module_session_holder
    fast_reuse = request.node.get_closest_marker("module_session_fast") is not None
    sh, slot_id, bootstrap_log = holder.get_session(skip_health_check=fast_reuse)
    health_metrics = holder.consume_health_metrics_delta()
    raw = holder.raw
    raw.reset_call_log()
    raw.reset_used_mechanisms()
    _apply_rv_trace(raw, p11_config)
    try:
        yield RawSession(
            raw,
            sh,
            slot_id,
            bootstrap_call_counts=bootstrap_log,
            module_session_health_metrics=health_metrics,
        )
    finally:
        if fast_reuse and getattr(request.node, MODULE_SESSION_CALL_FAILED_ATTR, False):
            holder.require_health_check()
