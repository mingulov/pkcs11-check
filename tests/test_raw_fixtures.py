"""Meta-tests for raw migration infrastructure."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.fixtures import RawSession, p11_module_session, p11_raw_session
from pkcs11_check.raw.recipes import create_object, get_mechanism_list


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
