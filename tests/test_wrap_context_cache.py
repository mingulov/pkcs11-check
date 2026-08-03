"""Regression: wrap_context_for must build the WrapContext ONCE per session and cache it.

Rebuilding build_wrap_context on every provision bootstraps fresh key material + trial
round-trips per KAT vector, leaking objects (observed as CKR_HOST_MEMORY on one provider) and
running a keygen per vector. wrap_context_for caches by rs.sh (incl. a None no-path result).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.testcases import _provisioning


@pytest.fixture(autouse=True)
def _clear_caches() -> Any:
    _provisioning._WRAP_CONTEXT_CACHE.clear()
    _provisioning._WRAP_CONTEXT_COMPUTED.clear()
    yield
    _provisioning._WRAP_CONTEXT_CACHE.clear()
    _provisioning._WRAP_CONTEXT_COMPUTED.clear()


def _rs(sh: int) -> Any:
    return SimpleNamespace(raw=object(), sh=sh)


def test_built_once_per_session(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    sentinel = object()

    def fake_build(rs: Any, cfg: Any) -> Any:
        calls.append(rs.sh)
        return sentinel

    monkeypatch.setattr(_provisioning, "build_wrap_context", fake_build)
    rs = _rs(7)
    cfg = SimpleNamespace()

    a = _provisioning.wrap_context_for(rs, cfg)
    b = _provisioning.wrap_context_for(rs, cfg)
    c = _provisioning.wrap_context_for(rs, cfg)

    assert a is sentinel and b is sentinel and c is sentinel
    assert calls == [7], f"build_wrap_context must run once per session, ran {len(calls)}x"


def test_none_result_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def fake_build_none(rs: Any, cfg: Any) -> Any:
        calls.append(rs.sh)
        return None

    monkeypatch.setattr(_provisioning, "build_wrap_context", fake_build_none)
    rs = _rs(9)
    cfg = SimpleNamespace()

    assert _provisioning.wrap_context_for(rs, cfg) is None
    assert _provisioning.wrap_context_for(rs, cfg) is None
    assert calls == [9], "a legitimate None must be cached, not re-probed every provision"


def test_distinct_sessions_build_independently(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def fake_build(rs: Any, cfg: Any) -> Any:
        calls.append(rs.sh)
        return object()

    monkeypatch.setattr(_provisioning, "build_wrap_context", fake_build)
    cfg = SimpleNamespace()
    _provisioning.wrap_context_for(_rs(1), cfg)
    _provisioning.wrap_context_for(_rs(2), cfg)
    _provisioning.wrap_context_for(_rs(1), cfg)

    assert calls == [1, 2], "each distinct session builds once; same session reuses the cache"
