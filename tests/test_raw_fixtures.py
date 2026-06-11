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
