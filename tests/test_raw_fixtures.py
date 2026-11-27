"""Meta-tests for raw migration infrastructure."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from pkcs11_check import raw_fixtures as rf
from pkcs11_check.fixtures import RawSession, p11_module_session, p11_raw_session
from pkcs11_check.raw.recipes import create_object, get_mechanism_list


def test_raw_pkcs11_fixture_passes_requested_interface() -> None:
    from pkcs11_check import raw_fixtures

    request = SimpleNamespace(
        config=SimpleNamespace(
            getoption=lambda name, default=None: {
                "p11_module": "/tmp/provider.so",
                "p11_interface": "3.1",
            }.get(name, default)
        )
    )
    raw = object()
    with patch.object(raw_fixtures.RawPKCS11, "from_lib", return_value=raw) as from_lib:
        fixture = raw_fixtures.raw_pkcs11.__wrapped__(request)
        assert next(fixture) is raw

    from_lib.assert_called_once_with("/tmp/provider.so", interface="3.1")


def _parity_request(options: dict[str, Any]) -> Any:
    values = {"p11_module": "/tmp/provider.so", **options}
    config = SimpleNamespace(getoption=lambda name, default=None: values.get(name, default))
    return SimpleNamespace(config=config)


def _isolate_settings_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Drop ambient pin/slot/interface layers; TOML reads from an empty dir."""
    monkeypatch.delenv("P11TEST_PIN", raising=False)
    monkeypatch.delenv("P11TEST_SLOT", raising=False)
    monkeypatch.delenv("P11TEST_INTERFACE", raising=False)
    monkeypatch.chdir(tmp_path)


def test_raw_session_logs_in_with_env_pin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """S3: P11TEST_PIN logs the raw session in (env parity with runtime)."""
    _isolate_settings_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_PIN", "envpin")
    logins: list[bytes] = []
    monkeypatch.setattr(rf, "open_session", lambda raw, slot, flags: 99)
    monkeypatch.setattr(rf, "login_user", lambda raw, sh, user, pin: logins.append(pin))
    monkeypatch.setattr(rf, "logout_quietly", lambda *a: None)
    monkeypatch.setattr(rf, "close_session_quietly", lambda *a: None)

    gen = rf.raw_session.__wrapped__(object(), 7, _parity_request({}))
    assert next(gen) == 99
    gen.close()

    assert logins == [b"envpin"]


def test_raw_session_explicit_empty_pin_does_not_log_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """S3/F13: explicit empty PIN means no login (force-no-login)."""
    _isolate_settings_env(monkeypatch, tmp_path)
    logins: list[bytes] = []
    monkeypatch.setattr(rf, "open_session", lambda raw, slot, flags: 99)
    monkeypatch.setattr(rf, "login_user", lambda raw, sh, user, pin: logins.append(pin))
    monkeypatch.setattr(rf, "logout_quietly", lambda *a: None)
    monkeypatch.setattr(rf, "close_session_quietly", lambda *a: None)

    gen = rf.raw_session.__wrapped__(object(), 7, _parity_request({"p11_pin": ""}))
    assert next(gen) == 99
    gen.close()

    assert logins == []


def test_raw_slot_id_resolves_index(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """S3: --p11-slot is an index into token-present slots (documented)."""
    _isolate_settings_env(monkeypatch, tmp_path)
    monkeypatch.setattr(rf, "get_slot_ids", lambda raw: [10, 20])

    assert rf.raw_slot_id.__wrapped__(object(), _parity_request({"p11_slot": 1})) == 20


def test_raw_slot_id_env_slot_honored(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """S3: P11TEST_SLOT selects the slot (env parity with runtime)."""
    _isolate_settings_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_SLOT", "1")
    monkeypatch.setattr(rf, "get_slot_ids", lambda raw: [10, 20])

    assert rf.raw_slot_id.__wrapped__(object(), _parity_request({})) == 20


def test_raw_slot_id_invalid_slot_is_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """S3: garbage slot config fails cleanly instead of opening a wrong slot."""
    _isolate_settings_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_SLOT", "abc")
    monkeypatch.setattr(rf, "get_slot_ids", lambda raw: [10, 20])

    with pytest.raises(pytest.UsageError):
        rf.raw_slot_id.__wrapped__(object(), _parity_request({}))


def test_raw_pkcs11_uses_env_interface(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """S3: P11TEST_INTERFACE selects the interface (env parity with runtime)."""
    _isolate_settings_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_INTERFACE", "3.0")
    captured: dict[str, Any] = {}

    def fake_from_lib(path: object, interface: object = None) -> object:
        captured["path"] = path
        captured["interface"] = interface
        return object()

    monkeypatch.setattr(rf, "RawPKCS11", SimpleNamespace(from_lib=fake_from_lib))

    gen = rf.raw_pkcs11.__wrapped__(_parity_request({}))
    next(gen)
    gen.close()

    assert captured == {"path": "/tmp/provider.so", "interface": "3.0"}


def test_raw_pkcs11_defaults_interface_to_auto(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """S3 control: no configured interface keeps the historical auto default."""
    _isolate_settings_env(monkeypatch, tmp_path)
    captured: dict[str, Any] = {}

    def fake_from_lib(path: object, interface: object = None) -> object:
        captured["interface"] = interface
        return object()

    monkeypatch.setattr(rf, "RawPKCS11", SimpleNamespace(from_lib=fake_from_lib))

    gen = rf.raw_pkcs11.__wrapped__(_parity_request({}))
    next(gen)
    gen.close()

    assert captured == {"interface": "auto"}


def test_raw_session_closes_session_on_login_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """F11: a failed login still closes the opened session (no leak)."""
    _isolate_settings_env(monkeypatch, tmp_path)
    closed: list[int] = []
    logouts: list[int] = []
    monkeypatch.setattr(rf, "open_session", lambda raw, slot, flags: 99)

    def _fail_login(raw: Any, sh: int, user: int, pin: bytes) -> None:
        raise RuntimeError("login failed")

    monkeypatch.setattr(rf, "login_user", _fail_login)
    monkeypatch.setattr(rf, "logout_quietly", lambda raw, sh: logouts.append(sh))
    monkeypatch.setattr(rf, "close_session_quietly", lambda raw, sh: closed.append(sh))

    gen = rf.raw_session.__wrapped__(object(), 7, _parity_request({"p11_pin": "badpin"}))
    with pytest.raises(RuntimeError, match="login failed"):
        next(gen)
    assert closed == [99]
    assert logouts == []


def test_create_object_importable() -> None:
    """create_object recipe exists and is importable."""
    assert callable(create_object)


def test_get_mechanism_list_importable() -> None:
    """get_mechanism_list recipe exists and is importable."""
    assert callable(get_mechanism_list)


def test_raw_session_importable() -> None:
    """RawSession dataclass exists and is importable."""
    assert RawSession is not None


def test_p11_raw_session_importable() -> None:
    """p11_raw_session fixture exists and is importable."""
    assert callable(p11_raw_session)


def test_p11_module_session_importable() -> None:
    """p11_module_session fixture exists and is importable."""
    assert callable(p11_module_session)


class _RawForModuleSession:
    def reset_call_log(self) -> None:
        pass

    def reset_used_mechanisms(self) -> None:
        pass


class _HolderForModuleSession:
    raw = _RawForModuleSession()

    def __init__(self) -> None:
        self.skip_health_args: list[bool] = []
        self.required_health_checks = 0
        self.health_metrics = {"checks": 1, "duration_s": 0.25}

    def get_session(self, *, skip_health_check: bool = False) -> tuple[int, int, dict[str, int]]:
        self.skip_health_args.append(skip_health_check)
        return 7, 0, {}

    def consume_health_metrics_delta(self) -> dict[str, float | int]:
        return dict(self.health_metrics)

    def require_health_check(self) -> None:
        self.required_health_checks += 1


class _NodeForModuleSession:
    def __init__(self, *, fast_marker: bool) -> None:
        self.fast_marker = fast_marker

    def get_closest_marker(self, name: str) -> object | None:
        if name == "module_session_fast" and self.fast_marker:
            return object()
        return None


def _run_wrapped_module_session(
    *,
    fast_marker: bool,
    call_failed: bool = False,
) -> _HolderForModuleSession:
    holder = _HolderForModuleSession()
    request = SimpleNamespace(node=_NodeForModuleSession(fast_marker=fast_marker))
    config = SimpleNamespace(rv_trace=False, rv_trace_compact=None)
    gen = p11_module_session.__wrapped__(holder, config, request)

    session = next(gen)
    assert session.sh == 7
    if call_failed:
        setattr(request.node, "_pkcs11_module_session_call_failed", True)
    with pytest.raises(StopIteration):
        next(gen)
    return holder


def test_p11_module_session_fast_marker_skips_health_check() -> None:
    holder = _run_wrapped_module_session(fast_marker=True)
    assert holder.skip_health_args == [True]
    assert holder.required_health_checks == 0


def test_p11_module_session_without_fast_marker_keeps_health_check() -> None:
    holder = _run_wrapped_module_session(fast_marker=False)
    assert holder.skip_health_args == [False]


def test_p11_module_session_exposes_health_metrics_on_raw_session() -> None:
    holder = _HolderForModuleSession()
    request = SimpleNamespace(node=_NodeForModuleSession(fast_marker=False))
    config = SimpleNamespace(rv_trace=False, rv_trace_compact=None)
    gen = p11_module_session.__wrapped__(holder, config, request)

    session = next(gen)

    assert session.module_session_health_metrics == {"checks": 1, "duration_s": 0.25}
    with pytest.raises(StopIteration):
        next(gen)


def test_p11_module_session_fast_marker_checks_after_call_failure() -> None:
    holder = _run_wrapped_module_session(fast_marker=True, call_failed=True)
    assert holder.required_health_checks == 1


def test_module_session_report_hook_marks_call_failures() -> None:
    from pkcs11_check.fixtures import MODULE_SESSION_CALL_FAILED_ATTR
    from pkcs11_check.plugin import _remember_module_session_call_outcome

    item = SimpleNamespace()
    _remember_module_session_call_outcome(item, SimpleNamespace(when="setup", outcome="failed"))
    assert not hasattr(item, MODULE_SESSION_CALL_FAILED_ATTR)

    _remember_module_session_call_outcome(item, SimpleNamespace(when="call", outcome="failed"))
    assert getattr(item, MODULE_SESSION_CALL_FAILED_ATTR) is True


def test_generate_random_rejects_non_multiple_of_8() -> None:
    """The bits contract is enforced, not silently truncated."""
    rs = RawSession(object(), 0, 0)
    with pytest.raises(ValueError, match="multiple of 8"):
        rs.generate_random(7)


def test_generate_random_returns_requested_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path returns exactly bits // 8 bytes."""
    monkeypatch.setattr("pkcs11_check.raw.recipes.generate_random", lambda _r, _s, n: b"\xab" * n)
    rs = RawSession(object(), 0, 0)
    assert rs.generate_random(128) == b"\xab" * 16


def test_generate_random_short_provider_read_is_wrong_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A short provider read fails at the source with a wrong_result verdict."""
    from pkcs11_check import classification as C  # noqa: N812 - existing classification convention

    monkeypatch.setattr("pkcs11_check.raw.recipes.generate_random", lambda _r, _s, _n: b"\xab" * 4)
    rs = RawSession(object(), 0, 0)
    C.clear()
    with pytest.raises(pytest.fail.Exception, match="C_GenerateRandom"):
        rs.generate_random(128)
    assert C.get_records()[-1].reason == "wrong_result"


def _reset_mechanism_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    import pkcs11_check.fixtures as fixtures_mod
    from pkcs11_check.raw.extensions import clear_extensions

    monkeypatch.setattr(fixtures_mod, "_MECHANISM_CACHE", None)
    monkeypatch.setattr(fixtures_mod, "_MECHANISM_ID_CACHE", None)
    monkeypatch.setattr(fixtures_mod, "_MECH_INFO_CACHE", {})
    clear_extensions("cli")


def test_vendor_mechanism_registration_advertises_in_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A registered vendor id advertises under both name forms (F3)."""
    from pkcs11_check.raw.extensions import clear_extensions, register_extension

    _reset_mechanism_caches(monkeypatch)
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.get_mechanism_list",
        lambda _raw, _slot: [0x8000F001],
    )
    register_extension(namespace="cli", mechanisms={0x8000F001: "CKM_FOO_KMAC"})
    try:
        rs = RawSession(object(), 0, 0)
        assert rs.has_mechanism("CKM_FOO_KMAC")
        assert rs.has_mechanism("FOO_KMAC")
    finally:
        clear_extensions("cli")


def test_unregistered_vendor_id_stays_unadvertised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An id known to no table never appears under a guessed name (F3)."""
    _reset_mechanism_caches(monkeypatch)
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.get_mechanism_list",
        lambda _raw, _slot: [0x8000F002],
    )

    rs = RawSession(object(), 0, 0)
    assert not rs.has_mechanism("CKM_FOO_KMAC")
    assert not rs.has_mechanism("FOO_KMAC")


def test_has_mechanism_flag_resolves_registered_vendor_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """has_mechanism_flag queries info by the registered vendor id (F3)."""
    from pkcs11_check.raw.extensions import clear_extensions, register_extension

    _reset_mechanism_caches(monkeypatch)
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.get_mechanism_list",
        lambda _raw, _slot: [0x8000F003],
    )
    seen: list[int] = []

    def _fake_info(_raw: object, _slot: int, mech: int) -> dict[str, int]:
        seen.append(mech)
        return {"flags": 0x100}

    monkeypatch.setattr("pkcs11_check.raw.recipes.get_mechanism_info", _fake_info)
    register_extension(namespace="cli", mechanisms={0x8000F003: "CKM_FOO_SIGN"})
    try:
        rs = RawSession(object(), 0, 0)
        assert rs.has_mechanism_flag("FOO_SIGN", 0x100) is True
        assert rs.has_mechanism_flag("FOO_SIGN", 0x200) is False
        assert seen == [0x8000F003]
    finally:
        clear_extensions("cli")
