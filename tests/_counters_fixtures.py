"""Shared block/record builders for call-counter tests.

Canonical copies of the ``_fn_block`` / ``_module_block`` /
``_legacy_block`` / ``_session_record`` helpers previously duplicated
across the counter test files. Key order follows the durability
variant (``pid``, ``probes_lost``, ``isolation``); no test asserts on
record key order.
"""

from __future__ import annotations

from typing import Any


def _fn_block(calls: int, *, rv: int = 0, name: str = "CKR_OK") -> dict[str, Any]:
    return {"calls": calls, "by_rv": {str(rv): {"name": name, "count": calls}}}


def _module_block(module_buckets: dict[str, dict[str, Any]]) -> dict[str, Any]:
    by_module: dict[str, Any] = {}
    total = 0
    for module, buckets in module_buckets.items():
        calls = sum(block["calls"] for block in buckets.values())
        by_module[module] = {"calls": calls, "buckets": buckets}
        total += calls
    return {"total_calls": total, "by_module": by_module}


def _legacy_block(
    total: int, *, bucket: str = "test", fn: str = "C_Sign", rv: int = 0
) -> dict[str, Any]:
    return {
        "total_calls": total,
        "buckets": {bucket: {"calls": total, "by_fn": {fn: _fn_block(total, rv=rv)}}},
    }


def _session_record(
    pid: int,
    block: dict[str, Any] | None = None,
    total: int = 10,
    *,
    isolation: str = "file",
    probes_lost: int = 0,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "$report_type": "CallCountersReport",
        "pid": pid,
        "probes_lost": probes_lost,
        "isolation": isolation,
    }
    record.update(_legacy_block(total) if block is None else block)
    if extra:
        record.update(extra)
    return record
