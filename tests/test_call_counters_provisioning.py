"""Area E (rc3): provisioning-bucket attribution pins.

The six ``provision_*`` bodies plus ``_open_or_reinit`` run under the
``session_provisioning`` region wherever the calling phase is; nested
``module_init`` still wins inside; independent capability gates outside
provision bodies stay window-attributed; totals are conserved (only the
split shifts).
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import pkcs11_check.fixtures as _fixtures
import pkcs11_check.testcases._provisioning as _prov
from pkcs11_check.core import call_counters
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKK_AES,
)

_PROVISION_FUNCS = (
    "provision_secret_key",
    "provision_rsa_private_key",
    "provision_ec_private_key",
    "provision_public_key",
    "provision_certificate",
    "provision_data",
)


@pytest.fixture(autouse=True)
def _clean_counters() -> Any:
    call_counters.reset_for_tests()
    _prov._PROFILE_CACHE.clear()
    _prov._WRAP_CONTEXT_CACHE.clear()
    _prov._WRAP_CONTEXT_COMPUTED.clear()
    yield
    call_counters.reset_for_tests()
    _prov._PROFILE_CACHE.clear()
    _prov._WRAP_CONTEXT_CACHE.clear()
    _prov._WRAP_CONTEXT_COMPUTED.clear()


def _buckets() -> dict[str, Any]:
    snap = call_counters.serialize_current()
    return snap["by_module"][""]["buckets"]


def _make_rs(sh: int) -> Any:
    return SimpleNamespace(raw=object(), sh=sh, slot_id=0)


def _make_cfg() -> Any:
    from pkcs11_check.config import P11TestConfig

    return P11TestConfig(module=Path("/stub.so"), key_inject="off")


def _recording_import(raw: Any, sh: int, key_type: Any, value: bytes, attrs: Any) -> int:
    call_counters.record_call("C_CreateObject")
    call_counters.record_return("C_CreateObject", 0)
    return 55


def _recording_destroy(raw: Any, sh: int, handle: int) -> None:
    call_counters.record_call("C_DestroyObject")
    call_counters.record_return("C_DestroyObject", 0)


def _stub_recipes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", _recording_import)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", _recording_destroy)


def _has_provisioning_region(source: str, func_name: str) -> bool:
    """Whether ``func_name`` carries a session_provisioning region decorator."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != func_name:
            continue
        for deco in node.decorator_list:
            if not isinstance(deco, ast.Call) or not deco.args:
                continue
            func = deco.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else (func.id if isinstance(func, ast.Name) else None)
            )
            first = deco.args[0]
            if (
                name == "counted_bucket"
                and isinstance(first, ast.Constant)
                and first.value == "session_provisioning"
            ):
                return True
    return False


@pytest.mark.parametrize("func_name", _PROVISION_FUNCS)
def test_provision_body_runs_under_provisioning_region(func_name: str) -> None:
    assert _prov.__file__ is not None
    source = Path(_prov.__file__).read_text(encoding="utf-8")
    assert _has_provisioning_region(source, func_name), (
        f"{func_name} must run its whole body under session_provisioning"
    )


def test_open_or_reinit_runs_under_provisioning_region() -> None:
    assert _fixtures.__file__ is not None
    source = Path(_fixtures.__file__).read_text(encoding="utf-8")
    assert _has_provisioning_region(source, "_open_or_reinit")


def test_provision_secret_key_create_path_moves_to_provisioning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_recipes(monkeypatch)
    rs = _make_rs(sh=200)
    cfg = _make_cfg()
    attrs = {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False, CKA_SENSITIVE: False}
    with call_counters.counted_bucket("test"):
        handle = _prov.provision_secret_key(rs, cfg, CKK_AES, bytes(range(32)), attrs, label="t")
    assert handle == 55
    buckets = _buckets()
    # Profile probe (import + destroy) plus the real import: 3 calls, all
    # provisioning. Totals conserved, only the split shifts.
    assert buckets["session_provisioning"]["calls"] == 3
    assert buckets["session_provisioning"]["by_fn"]["C_CreateObject"]["calls"] == 2
    assert buckets["session_provisioning"]["by_fn"]["C_DestroyObject"]["calls"] == 1
    assert buckets["test"] == {"calls": 0, "by_fn": {}}
    assert call_counters.serialize_current()["total_calls"] == 3


def test_open_or_reinit_retry_keeps_module_init_nested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def _flaky_open(module: Any, config: Any) -> tuple[Any, int, int, bool]:
        calls.append("open")
        if len(calls) == 1:
            raise OSError("transport still down")
        call_counters.record_call("C_OpenSession")
        call_counters.record_return("C_OpenSession", 0)
        return (object(), 7, 0, True)

    def _reinit() -> None:
        # Simulates P11Module.reinitialize's own module_init region.
        with call_counters.counted_bucket("module_init"):
            call_counters.record_call("C_Initialize")
            call_counters.record_return("C_Initialize", 0)

    monkeypatch.setattr(_fixtures, "_open_raw_session", _flaky_open)
    module = SimpleNamespace(reinit_count=0, reinitialize=_reinit)
    with call_counters.counted_bucket("test"):
        with pytest.warns(UserWarning, match="reconnected"):
            _fixtures._open_or_reinit(module, None)
    assert calls == ["open", "open"], "clean open failed, retry path ran"
    buckets = _buckets()
    assert buckets["session_provisioning"]["by_fn"]["C_OpenSession"]["calls"] == 1
    assert buckets["module_init"]["by_fn"]["C_Initialize"]["calls"] == 1
    assert buckets["test"] == {"calls": 0, "by_fn": {}}
    assert call_counters.serialize_current()["total_calls"] == 2


def test_capability_gate_outside_provision_stays_window_attributed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_recipes(monkeypatch)
    rs = _make_rs(sh=200)
    with call_counters.counted_bucket("test"):
        assert _prov.skip_unless_can_create(rs, "secret") is None
    buckets = _buckets()
    # An independent gate (not inside a provision body) keeps the
    # window/phase bucket; only provision-body traffic moves.
    assert buckets["test"]["by_fn"]["C_CreateObject"]["calls"] == 1
    assert buckets["test"]["by_fn"]["C_DestroyObject"]["calls"] == 1
    assert buckets["session_provisioning"] == {"calls": 0, "by_fn": {}}
