"""Process-global PKCS#11 call counters with bucket attribution (fw#73).

Every ``C_*`` call through the loaded module is counted here: entry increments
the call count, exit records the ``CK_RV``. A call that crashes the process
inside the module therefore counts with no RV (``sum(by_rv) <= calls``).

This module is the ONLY owner of counter state. It must import nothing from
``pkcs11_check.raw.api`` (that module imports this one at the ``_call`` choke
point); ``ckr_name`` is imported lazily inside the serializer.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from threading import RLock
from typing import Any

BUCKETS: tuple[str, ...] = ("test", "setup_teardown", "session_provisioning", "module_init")
DEFAULT_BUCKET = "session_provisioning"

CALL_COUNTERS_REPORT_TYPE = "CallCountersReport"
CALL_COUNTERS_PROPERTY = "pkcs11_call_counters"
ISOLATION_ENV = "PKCS11_CHECK_ISOLATION"

_lock = RLock()
_entry_counts: Counter[tuple[str, str]] = Counter()
_exit_counts: Counter[tuple[str, str, int]] = Counter()
_bucket_stack: list[str] = []
_probes_lost = 0


def current_bucket() -> str:
    """Return the innermost pushed bucket, or the default when the stack is empty."""
    with _lock:
        return _bucket_stack[-1] if _bucket_stack else DEFAULT_BUCKET


@contextmanager
def counted_bucket(name: str) -> Iterator[None]:
    """Attribute calls in the body to ``name``; restore the previous bucket on exit."""
    if name not in BUCKETS:
        raise ValueError(f"unknown call-counter bucket: {name!r}")
    with _lock:
        _bucket_stack.append(name)
    try:
        yield
    finally:
        with _lock:
            _bucket_stack.pop()


def record_call(fn: str) -> None:
    """Count one entry into the PKCS#11 function ``fn`` under the active bucket."""
    with _lock:
        _entry_counts[(current_bucket(), fn)] += 1


def record_return(fn: str, rv: int) -> None:
    """Count one return from ``fn`` with ``rv`` under the active bucket."""
    with _lock:
        _exit_counts[(current_bucket(), fn, rv)] += 1


def record_direct_call(fn: str, rv: int) -> None:
    """Count a call made outside the ``_call`` choke point (entry + exit together)."""
    with _lock:
        _entry_counts[(current_bucket(), fn)] += 1
        _exit_counts[(current_bucket(), fn, rv)] += 1


def _serialize(
    entry: Counter[tuple[str, str]] | dict[tuple[str, str], int],
    exits: Counter[tuple[str, str, int]] | dict[tuple[str, str, int], int],
) -> dict[str, Any]:
    """Render counters in the serialized schema shape (sparse: nonzero only)."""
    from pkcs11_check.raw.rv import ckr_name

    buckets: dict[str, dict[str, Any]] = {}
    total = 0
    for (bucket, fn), calls in entry.items():
        if calls <= 0:
            continue
        total += calls
        bucket_block = buckets.setdefault(bucket, {"calls": 0, "by_fn": {}})
        bucket_block["calls"] += calls
        bucket_block["by_fn"][fn] = {"calls": calls, "by_rv": {}}
    for (bucket, fn, rv), count in exits.items():
        if count <= 0:
            continue
        by_fn = buckets.setdefault(bucket, {"calls": 0, "by_fn": {}})["by_fn"]
        target = by_fn.setdefault(fn, {"calls": 0, "by_rv": {}})
        target["by_rv"][str(rv)] = {"name": ckr_name(rv), "count": count}
    return {"total_calls": total, "buckets": buckets}


Snapshot = tuple[Counter[tuple[str, str]], Counter[tuple[str, str, int]]]


def take_snapshot() -> Snapshot:
    """Return a detached copy of both counters for later ``diff_snapshots``."""
    with _lock:
        return (Counter(_entry_counts), Counter(_exit_counts))


def diff_snapshots(before: Snapshot, after: Snapshot) -> dict[str, Any]:
    """Serialize the ``after - before`` delta in the serialized schema shape.

    Only positive deltas are reported; buckets, functions, and RVs with no
    new calls in the window are omitted (sparse).
    """
    before_entry, before_exit = before
    after_entry, after_exit = after
    entry_delta = {
        key: after_entry[key] - before_entry[key]
        for key in after_entry
        if after_entry[key] - before_entry[key] > 0
    }
    exit_delta = {
        key: after_exit[key] - before_exit[key]
        for key in after_exit
        if after_exit[key] - before_exit[key] > 0
    }
    return _serialize(entry_delta, exit_delta)


def serialize_current() -> dict[str, Any]:
    """Serialize all counters recorded so far in the serialized schema shape."""
    with _lock:
        return _serialize(Counter(_entry_counts), Counter(_exit_counts))


def flatten_current() -> list[list[str | int | None]]:
    """Flatten all counters to the child wire format ``[[fn, rv_or_None, count]]``.

    Bucket attribution is dropped (the ingesting parent applies its own
    bucket); ``rv None`` marks entries that never returned. Sorted by fn,
    then RV ascending with the unreturned row last per fn.
    """
    with _lock:
        entries: Counter[str] = Counter()
        for (_bucket, fn), calls in _entry_counts.items():
            entries[fn] += calls
        exits: Counter[tuple[str, int]] = Counter()
        for (_bucket, fn, rv), count in _exit_counts.items():
            exits[(fn, rv)] += count
    typed: list[tuple[str, int | None, int]] = []
    for (fn, rv), count in exits.items():
        typed.append((fn, rv, count))
        entries[fn] -= count
    for fn, unreturned in entries.items():
        if unreturned > 0:
            typed.append((fn, None, unreturned))
    typed.sort(key=lambda item: (item[0], item[1] is None, item[1] or 0))
    return [[fn, rv, count] for fn, rv, count in typed]


def ingest_child_counts(flat: list[Any], *, bucket: str | None = None) -> None:
    """Merge child wire-format rows into the globals under ``bucket`` (or active).

    Only ``[fn, rv_or_None, count]`` rows with a non-empty str fn, an
    int-or-None rv, and a positive int count are applied; every other shape
    (including a non-list/tuple payload) is ignored without raising. An
    explicitly unknown ``bucket`` raises ValueError like ``counted_bucket``.
    """
    target = bucket if bucket is not None else current_bucket()
    if target not in BUCKETS:
        raise ValueError(f"unknown call-counter bucket: {target!r}")
    if not isinstance(flat, (list, tuple)):
        return
    parsed: list[tuple[str, int | None, int]] = []
    for row in flat:
        if not isinstance(row, (list, tuple)) or len(row) != 3:
            continue
        fn: Any = row[0]
        rv: Any = row[1]
        count: Any = row[2]
        if not isinstance(fn, str) or not fn:
            continue
        if rv is not None and (not isinstance(rv, int) or isinstance(rv, bool)):
            continue
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            continue
        parsed.append((fn, rv, count))
    with _lock:
        for fn, rv, count in parsed:
            _entry_counts[(target, fn)] += count
            if rv is not None:
                _exit_counts[(target, fn, rv)] += count


def merge_serialized(target: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """Add ``incoming`` counts into ``target`` in place and return ``target``.

    Both dicts must have the serialized schema shape; buckets, functions, or
    RVs missing from ``target`` are created (leaf dicts are copied, never
    aliased). Touches no global counter state.
    """
    target["total_calls"] = target.get("total_calls", 0) + incoming.get("total_calls", 0)
    target_buckets: dict[str, Any] = target.setdefault("buckets", {})
    incoming_buckets: dict[str, Any] = incoming.get("buckets", {})
    for bucket, block in incoming_buckets.items():
        target_block = target_buckets.setdefault(bucket, {"calls": 0, "by_fn": {}})
        target_block["calls"] = target_block.get("calls", 0) + block.get("calls", 0)
        target_by_fn = target_block.setdefault("by_fn", {})
        for fn, fn_block in block.get("by_fn", {}).items():
            target_fn = target_by_fn.setdefault(fn, {"calls": 0, "by_rv": {}})
            target_fn["calls"] = target_fn.get("calls", 0) + fn_block.get("calls", 0)
            target_by_rv = target_fn.setdefault("by_rv", {})
            for rv_key, rv_block in fn_block.get("by_rv", {}).items():
                existing = target_by_rv.get(rv_key)
                if existing is None:
                    target_by_rv[rv_key] = {
                        "name": rv_block["name"],
                        "count": rv_block["count"],
                    }
                else:
                    existing["count"] += rv_block["count"]
    return target


def note_lost_probe() -> None:
    """Record one probe child whose counters could not be recovered."""
    global _probes_lost
    with _lock:
        _probes_lost += 1


def add_lost_probes(n: Any) -> None:
    """Add ``n`` child-side losses propagated through a coverage payload.

    Garbage-tolerant like :func:`ingest_child_counts`: anything that is not a
    positive ``int`` (bools included) is ignored without raising, so a hostile
    payload value can never break the ingest path.
    """
    if not isinstance(n, int) or isinstance(n, bool) or n <= 0:
        return
    global _probes_lost
    with _lock:
        _probes_lost += n


def probes_lost() -> int:
    """Return the number of probe children with unrecoverable counters."""
    with _lock:
        return _probes_lost


def reset_for_tests() -> None:
    """Clear all counters, the bucket stack, and the lost-probe count."""
    global _probes_lost
    with _lock:
        _entry_counts.clear()
        _exit_counts.clear()
        _bucket_stack.clear()
        _probes_lost = 0


__all__ = [
    "BUCKETS",
    "CALL_COUNTERS_PROPERTY",
    "CALL_COUNTERS_REPORT_TYPE",
    "DEFAULT_BUCKET",
    "ISOLATION_ENV",
    "Snapshot",
    "add_lost_probes",
    "counted_bucket",
    "current_bucket",
    "diff_snapshots",
    "flatten_current",
    "ingest_child_counts",
    "merge_serialized",
    "note_lost_probe",
    "probes_lost",
    "record_call",
    "record_direct_call",
    "record_return",
    "reset_for_tests",
    "serialize_current",
    "take_snapshot",
]
