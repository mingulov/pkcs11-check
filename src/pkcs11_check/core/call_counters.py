"""Process-global PKCS#11 call counters with bucket attribution (fw#73).

Every ``C_*`` call through the loaded module is counted here: entry increments
the call count, exit records the ``CK_RV``. A call that crashes the process
inside the module therefore counts with no RV (``sum(by_rv) <= calls``).

Attribution is two-level: a process-global PHASE (set by the pytest
setup/call/teardown hooks, which are sequential, so phases never nest) plus a
thread-local REGION stack (``counted_bucket``). The active bucket is the
calling thread's innermost region, else the phase -- so overlapping regions in
other threads never misattribute this thread's calls, while worker threads
still inherit the phase. Entry/exit pairs additionally bind the exit to the
bucket captured at entry, so a mid-call bucket switch cannot split one call
across two buckets.

Identity is two more axes: every call carries the MODULE id bound to the
handle it passed through (``RawPKCS11`` binds its lib path before the first
loader C call; direct ``record_*`` calls without a handle count under the
``""`` unknown module, never inferred), and every record carries the process
``worker_uuid`` minted here (allocation only; durable registration is Task 3).
Core keys are ``(module, bucket, fn)`` / ``(module, bucket, fn, rv)`` and the
serialized shape is module-first.

This module is the ONLY owner of counter state. It must import nothing from
``pkcs11_check.raw.api`` (that module imports this one at the ``_call`` choke
point); ``ckr_name`` is imported lazily inside the serializer.
``counters_schema`` and ``_counters_durability`` are safe to import (stdlib
plus schema only, no cycles).

Durability (rc2 Task 3): when ``PKCS11_CHECK_COUNTERS_DIR`` is set, the
first provider call self-registers this process (registry file + birth
token), and evidence flushes to a sidecar/journal pair every K calls, at
test-window boundaries, and at exit — all under this module's lock with a
dirty flag covering every evidence mutation. Without the env var every
durability entry point is inert. A sealed dir or an I/O failure raises
``CounterPersistenceError`` out of the recording call, blocking provider
entry rather than silently undercounting; a failed K flush rolls back
the just-admitted call, so a provider call that never ran leaves no
trace in the session either.
"""

from __future__ import annotations

import atexit
import os
import warnings
from collections import Counter
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from threading import RLock, local
from typing import Any

from pkcs11_check.core._counters_durability import (
    COUNTERS_ATTEMPT_ENV,
    COUNTERS_FLUSH_K_ENV,
    COUNTERS_ROLE_ENV,
    COUNTERS_UNIT_ENV,
    FLUSH_WINDOW_K,
    PROBE_SEQ_ENV,
    PROBE_SIDECAR_ENV,
    CounterPersistenceError,
    Registration,
    append_journal,
    durability_dir,
    probe_sidecar_identity_from_env,
    register_worker,
    write_probe_sidecar,
    write_sidecar_atomic,
)
from pkcs11_check.core.counters_schema import (
    UNKNOWN_MODULE,
    ensure_five_buckets,
    is_lost_key,
    is_module_first_block,
    is_probe_seq,
    is_receipt,
    is_worker_uuid,
    mint_worker_uuid,
)

BUCKETS: tuple[str, ...] = ("test", "setup_teardown", "session_provisioning", "module_init")
DEFAULT_BUCKET = "session_provisioning"

CALL_COUNTERS_REPORT_TYPE = "CallCountersReport"
CALL_COUNTERS_PROPERTY = "pkcs11_call_counters"
ISOLATION_ENV = "PKCS11_CHECK_ISOLATION"
RUN_ID_ENV = "PKCS11_CHECK_RUN_ID"


class _ThreadState(local):
    """Per-thread counter attribution state (a region stack per thread)."""

    def __init__(self) -> None:
        self.regions: list[str] = []


_lock = RLock()
_state = _ThreadState()
_entry_counts: Counter[tuple[str, str, str]] = Counter()
_exit_counts: Counter[tuple[str, str, str, int]] = Counter()
_phase_name: str = DEFAULT_BUCKET
#: Keyed losses ``(accounting_parent_uuid, probe_seq)``: probes noted lost
#: with identity. Recovery removes the key; ``probes_lost()`` derives the
#: total as keyed + unkeyed so the two can never drift apart.
_lost_keys: set[tuple[str, int]] = set()
#: Unkeyed losses: notes without identity plus legacy scalar remainders.
#: Never heals (nothing to cancel against); sources dedupe at ingest.
_unkeyed_lost = 0
#: Ingested child-payload sources ``(parent_uuid, probe_seq)``: a repeat
#: ingest adds nothing (idempotent).
_ingested_sources: set[tuple[str, int]] = set()
#: Admitted-but-undurable evidence after a failed return/mutation checkpoint
#: (``{"checkpoint": kind, "unit": str, "attempt": int}``), else None. Entries
#: never set it (they roll back instead); it clears only when a sidecar flush
#: or journal append durably covers the retained evidence. A marker surviving
#: to session emission forces counter-specific incomplete. Fork children
#: inherit it like ``_dirty`` (their first covering flush clears it). No
#: sidecar leg exists by construction: a failed flush cannot persist a
#: marker to the file it failed to write, and a dead producer is already
#: structurally incomplete via its partial+lost records.
_persistence_pending: dict[str, Any] | None = None
_worker_uuid: str | None = None
_worker_uuid_pid: int | None = None
_registration: Registration | None = None
_registration_pid: int | None = None
_dirty = False
_pending_calls = 0
#: Effective sidecar flush cadence (None until first read, then cached for
#: the process; children inherit via env, so a normal run is consistent).
_flush_k_cache: int | None = None
#: Evidence units since the last probe-slot flush (probe children only;
#: registered processes use ``_pending_calls``). Read fresh from the
#: environment-gated branch below, never cached across fork.
_probe_pending_calls = 0
#: Whether the probe-slot degraded-mode warning already fired this process.
_probe_flush_warned = False
#: (child uuid, seq) pairs absorbed via sidecar fallback, pending delete.
#: Persisted with the checkpoint (same flush as the absorbed counts), so a
#: parent death between fallback persistence and sidecar deletion suppresses
#: the retained orphan instead of double-folding it (codex RC4-R1-2).
#: Distinct from ``_receipts`` (claimed folds with detail rows); consumed
#: pairs never earn rows.
_consumed_probes: set[tuple[str, int]] = set()
_receipts: set[tuple[str, int]] = set()
_probe_seq = 0
_inprog_entry: Counter[tuple[str, str, str]] = Counter()
_inprog_exit: Counter[tuple[str, str, str, int]] = Counter()
_journal_len = 0
_atexit_installed = False


def _get_worker_uuid_locked() -> str:
    """Mint-or-return the producer identity; caller must hold ``_lock``."""
    global _worker_uuid, _worker_uuid_pid
    pid = os.getpid()
    if _worker_uuid is None or _worker_uuid_pid != pid:
        _worker_uuid = mint_worker_uuid()
        _worker_uuid_pid = pid
    return _worker_uuid


def get_worker_uuid() -> str:
    """Return the process-scoped producer identity, minting it once (Task 1 helper).

    Allocation only: no filesystem or registry I/O happens here (durable
    registration is Task 3). Fork-safe via a pid guard -- a forked child that
    never minted mints its own, and a child inheriting a minted value remints
    on first use, so two processes never share an identity.
    """
    with _lock:
        return _get_worker_uuid_locked()


def _current_bucket_locked() -> str:
    """Return the active bucket; caller must hold ``_lock`` for the phase read."""
    if _state.regions:
        return _state.regions[-1]
    return _phase_name


def current_bucket() -> str:
    """Return the calling thread's innermost region, else the global phase."""
    if _state.regions:
        return _state.regions[-1]
    with _lock:
        return _phase_name


def _ensure_registered_locked() -> Registration | None:
    """Register this process when durability is engaged; caller holds ``_lock``.

    Returns the registration, or None when disengaged. A forked child
    (pid mismatch) re-registers with a fresh identity and fresh evidence
    files, never touching the parent's. Raises ``CounterPersistenceError``
    when sealed or on invalid identity inputs / I/O failure.
    """
    global _registration, _registration_pid, _atexit_installed
    root = durability_dir()
    if root is None:
        return None
    # Resolve the flush cadence on every engaged call, before any evidence
    # is admitted: a garbage setting must warn (or raise, under -W error)
    # before admission, never after, or a warnings-as-errors run would keep
    # phantom counts for a provider call that never ran (codex R1). Cached,
    # so the steady state costs one global read.
    _effective_flush_k_locked()
    pid = os.getpid()
    if _registration is not None and _registration_pid == pid:
        return _registration
    attempt_raw = os.environ.get(COUNTERS_ATTEMPT_ENV, "0")
    try:
        attempt = int(attempt_raw)
    except ValueError:
        raise CounterPersistenceError(f"invalid {COUNTERS_ATTEMPT_ENV}: {attempt_raw!r}") from None
    registration = register_worker(
        root,
        run_id=os.environ.get(RUN_ID_ENV, ""),
        unit=os.environ.get(COUNTERS_UNIT_ENV, "") or "<in-process>",
        attempt=attempt,
        role=os.environ.get(COUNTERS_ROLE_ENV, "") or "unit",
        isolation=os.environ.get(ISOLATION_ENV, "") or "unknown",
        worker_uuid=_get_worker_uuid_locked(),
        pid=pid,
    )
    _registration = registration
    _registration_pid = pid
    if not _atexit_installed:
        _atexit_installed = True
        atexit.register(_exit_flush)
    return registration


def ensure_registered() -> dict[str, Any] | None:
    """Register this process when durability is engaged; return its identity.

    Returns None when disengaged. Raises ``CounterPersistenceError`` when
    sealed or on I/O failure (provider entry stays blocked).
    """
    with _lock:
        registration = _ensure_registered_locked()
        return _registration_info_locked() if registration is not None else None


def _registration_info_locked() -> dict[str, Any] | None:
    """Return the current registration identity; caller must hold ``_lock``."""
    if _registration is None or _registration_pid != os.getpid():
        return None
    return {
        "worker_uuid": _registration.worker_uuid,
        "pid": _registration.pid,
        "run_id": _registration.run_id,
        "unit": _registration.unit,
        "attempt": _registration.attempt,
        "role": _registration.role,
        "registry_path": str(_registration.registry_path),
        "sidecar_path": str(_registration.sidecar_path),
        "journal_path": str(_registration.journal_path),
    }


def registration_info() -> dict[str, Any] | None:
    """Return the current registration identity, or None (no side effects)."""
    with _lock:
        return _registration_info_locked()


def _flush_locked() -> None:
    """Write the in-progress snapshot; caller holds ``_lock`` (whole-transaction).

    No-op unless registered in this pid. Raises ``CounterPersistenceError``
    on I/O failure (the old sidecar stays intact; dirty stays set so the
    evidence is retried by the next flush). A successful write covers every
    retained kind, so it also clears the pending-persistence marker.
    """
    global _dirty, _pending_calls, _persistence_pending
    if _registration is None or _registration_pid != os.getpid():
        return
    if durability_dir() is None:
        return
    payload = {
        "worker_uuid": _registration.worker_uuid,
        "run_id": _registration.run_id,
        "unit": _registration.unit,
        "attempt": _registration.attempt,
        "pid": _registration.pid,
        # Attribution stamp for registryless adoption (robustness N1):
        # a torn registry with a surviving sidecar recovers these.
        "role": _registration.role,
        "isolation": _registration.isolation,
        "journal_seq": _journal_len,
        "in_progress": _serialize(Counter(_inprog_entry), Counter(_inprog_exit)),
        "receipts": [{"worker_uuid": uuid, "probe_seq": seq} for uuid, seq in sorted(_receipts)],
        "consumed_probes": [
            {"worker_uuid": uuid, "probe_seq": seq} for uuid, seq in sorted(_consumed_probes)
        ],
        "probes_lost": len(_lost_keys) + _unkeyed_lost,
        "lost_keys": [
            {"parent_uuid": parent, "probe_seq": seq} for parent, seq in sorted(_lost_keys)
        ],
    }
    write_sidecar_atomic(_registration.sidecar_path, payload)
    _dirty = False
    _pending_calls = 0
    # This flush covered every retained kind (counts, receipts, loss scalar).
    _persistence_pending = None


def flush_counters() -> bool:
    """Flush the in-progress snapshot when dirty; return whether it wrote.

    Never registers (best-effort persistence, no side effects beyond the
    sidecar): False when disengaged, unregistered, fork-guarded, or clean.
    Raises ``CounterPersistenceError`` on I/O failure.
    """
    with _lock:
        if durability_dir() is None:
            return False
        if _registration is None or _registration_pid != os.getpid():
            return False
        if not _dirty:
            return False
        _flush_locked()
        return True


def _exit_flush() -> None:
    """Best-effort exit flush for the atexit backstop (loud, never raises)."""
    try:
        with _lock:
            if durability_dir() is None:
                return
            if _registration is None or _registration_pid != os.getpid():
                return
            if not _dirty:
                return
            _flush_locked()
    except CounterPersistenceError as exc:
        warnings.warn(f"call-counter exit flush failed: {exc}", UserWarning, stacklevel=2)


def _effective_flush_k_locked() -> int:
    """Return the cached sidecar flush cadence; caller holds ``_lock``.

    Split out so the hot path adds no lock acquisition (ingest holds
    the counters lock exactly once per transaction); external callers
    use :func:`effective_flush_k`, which takes it. Same global lock
    either way, so the garbage warning fires exactly once per process
    even under threads.
    """
    global _flush_k_cache
    if _flush_k_cache is not None:
        return _flush_k_cache
    raw = os.environ.get(COUNTERS_FLUSH_K_ENV, "").strip()
    if not raw:
        _flush_k_cache = FLUSH_WINDOW_K
        return _flush_k_cache
    try:
        parsed = int(raw)
    except ValueError:
        parsed = 0
    if parsed < 1:
        warnings.warn(
            f"invalid {COUNTERS_FLUSH_K_ENV}={raw!r}: expected a positive int; "
            "falling back to 1 (exact)",
            UserWarning,
            stacklevel=2,
        )
        _flush_k_cache = FLUSH_WINDOW_K
        return _flush_k_cache
    _flush_k_cache = parsed
    return _flush_k_cache


def effective_flush_k() -> int:
    """Return the sidecar flush cadence for this process (cached).

    ``PKCS11_CHECK_COUNTERS_FLUSH_K`` sets how many evidence units
    accumulate before the sidecar snapshot persists; unset means
    ``FLUSH_WINDOW_K`` (1, exact). Garbage (non-int, < 1) warns loudly
    once per process and falls back to 1 -- the safe direction is
    exactness, and a perf-knob typo must not brick runs the way an
    identity typo must. Read once per process (children inherit via
    env); ``reset_for_tests`` clears the cache.
    """
    with _lock:
        return _effective_flush_k_locked()


def _probe_slot_seq() -> int | None:
    """Return this probe child's assigned seqno, else None. Holds ``_lock``."""
    try:
        seq = int(os.environ.get(PROBE_SEQ_ENV, ""))
    except (TypeError, ValueError):
        return None
    return seq if seq >= 0 else None


def _flush_probe_slot_locked() -> None:
    """Persist flattened counters to the assigned probe slot. Holds ``_lock``.

    Best-effort by design: counter plumbing must never break provider
    stimulus, so a failure warns once per process and keeps counting in
    memory (the exit coverage write still folds via TMPDIR). The pending
    window resets either way, bounding retry attempts under a persistently
    broken slot.
    """
    global _probe_pending_calls, _probe_flush_warned
    slot = os.environ.get(PROBE_SIDECAR_ENV, "")
    seq = _probe_slot_seq()
    _probe_pending_calls = 0
    if not slot or seq is None:
        return
    try:
        write_probe_sidecar(
            slot,
            worker_uuid=get_worker_uuid(),
            probe_seq=seq,
            counters=flatten_current(),
            lost_keys=[
                {"parent_uuid": uuid, "probe_seq": seq_no} for uuid, seq_no in sorted(_lost_keys)
            ]
            or None,
            identity=probe_sidecar_identity_from_env(os.environ),
            finalized=False,
            probes_lost=probes_lost(),
        )
    except (OSError, TypeError, ValueError) as exc:
        if not _probe_flush_warned:
            _probe_flush_warned = True
            try:
                warnings.warn(
                    f"probe sidecar slot unwritable ({slot}): {exc}; counting continues in memory",
                    UserWarning,
                    stacklevel=2,
                )
            except Warning:
                # Best-effort stays best-effort even under -W error:
                # stimulus must flow. The degradation stays visible as
                # a missing sidecar (parent notes the loss).
                pass


def _mark_dirty_locked(calls: int = 0) -> None:
    """Mark evidence mutated; flush when the K window fills. Holds ``_lock``."""
    global _dirty, _pending_calls, _probe_pending_calls
    _dirty = True
    if _registration is not None and _registration_pid == os.getpid():
        _pending_calls += calls
        if _pending_calls >= _effective_flush_k_locked():
            _flush_locked()
    elif os.environ.get(PROBE_SIDECAR_ENV):
        # Disengaged probe child with an assigned slot: persist the
        # flattened snapshot at the same K cadence, so a mid-run kill
        # leaves foldable evidence (fw#73 lost-probe recovery). The slot
        # is read fresh every mark (never cached): a fork child unsets
        # it and must stop flushing immediately. A leaked slot in a
        # registered process is ignored: the registration wins.
        _probe_pending_calls += calls
        if _probe_pending_calls >= _effective_flush_k_locked():
            _flush_probe_slot_locked()


def _unadmit(counter: Counter[Any], key: Any) -> None:
    """Remove one just-admitted count, dropping keys that were absent (holds ``_lock``)."""
    counter[key] -= 1
    if counter[key] <= 0:
        counter.pop(key, None)


@contextmanager
def _rollback_admission(
    entry_key: tuple[str, str, str] | None,
    exit_key: tuple[str, str, str, int] | None,
) -> Iterator[None]:
    """Roll back just-admitted counts if the dirty-mark flush fails (holds ``_lock``).

    Entries only: the provider never ran, so unadmitting is honest. Returns,
    direct calls, and ingests must NOT use this guard (their traffic already
    happened); they retain and mark pending instead. The caller admits the
    counts first, then marks dirty inside this guard: a
    ``CounterPersistenceError`` from the K-boundary flush decrements exactly
    the just-admitted counts (global and in-progress alike) and restores the
    pending window, while ``_dirty`` stays set so the earlier evidence is
    retried by the next flush. The error re-raises: the provider call never
    ran (the record precedes it), so the session must not show it either.
    Anything other than the persistence error propagates with the admission
    kept. Read under the same lock hold as the admission, so no other thread
    can interleave a counter mutation between the two.
    """
    global _pending_calls
    pending_before = _pending_calls
    admitted_inprog = _registration is not None
    try:
        yield
    except CounterPersistenceError:
        _pending_calls = pending_before
        if entry_key is not None:
            _unadmit(_entry_counts, entry_key)
            if admitted_inprog:
                _unadmit(_inprog_entry, entry_key)
        if exit_key is not None:
            _unadmit(_exit_counts, exit_key)
            if admitted_inprog:
                _unadmit(_inprog_exit, exit_key)
        raise


def _set_pending_locked(checkpoint: str) -> None:
    """Mark admitted evidence undurable after a failed checkpoint. Holds ``_lock``.

    ``checkpoint`` is the failed kind (``"return"``, ``"direct"``,
    ``"ingest"``, ``"note"``). Entries never call this (they roll back, so
    nothing is retained); every other record path calls it when its flush
    fails, keeping the real traffic admitted. No-op when unregistered (an
    unregistered mark never attempts a flush, so nothing failed).
    """
    global _persistence_pending
    if _registration is None:
        return
    _persistence_pending = {
        "checkpoint": checkpoint,
        "unit": _registration.unit,
        "attempt": _registration.attempt,
    }


def _recover_pending_locked() -> None:
    """Retry persistence for marked evidence; block while undurable. Holds ``_lock``.

    Entry-only pre-check (call after ``_ensure_registered_locked``): a
    surviving marker retries the covering flush first, and while the writer
    is still broken the entry raises WITHOUT admitting, so the provider
    never runs on unrecordable evidence. A covering flush clears the marker
    (see :func:`_flush_locked`) and the entry proceeds. When the retry
    covers nothing (a flush that cannot write in this process), the entry
    stays blocked: fail closed, never silently unmarked.
    """
    if _persistence_pending is None:
        return
    try:
        _flush_locked()
    except CounterPersistenceError as exc:
        raise CounterPersistenceError(
            "counter persistence still failing; retained evidence undurable, "
            f"provider entry blocked: {exc}"
        ) from exc
    if _persistence_pending is not None:
        raise CounterPersistenceError(
            "counter persistence pending and unrecoverable in this process; provider entry blocked"
        )


@contextmanager
def _phase(name: str) -> Iterator[None]:
    """Set the process-global phase bucket, restoring the previous on exit.

    Internal: the pytest phase hooks attribute through this. Phases never
    nest (hooks are sequential), so a single global with save/restore
    suffices; worker threads inherit the phase, while a thread-local
    ``counted_bucket`` region still wins within its own thread.
    """
    if name not in BUCKETS:
        raise ValueError(f"unknown call-counter bucket: {name!r}")
    global _phase_name
    with _lock:
        previous = _phase_name
        _phase_name = name
    try:
        yield
    finally:
        with _lock:
            _phase_name = previous


@contextmanager
def counted_bucket(name: str) -> Iterator[None]:
    """Attribute this thread's calls in the body to ``name`` (a region).

    Regions nest per thread, restore on exit (even on exception), and win
    over the process-global phase within their own thread only; overlapping
    regions in other threads are isolated and cannot pop each other's frames.
    """
    if name not in BUCKETS:
        raise ValueError(f"unknown call-counter bucket: {name!r}")
    _state.regions.append(name)
    try:
        yield
    finally:
        _state.regions.pop()


def _resolve_bucket_locked(bucket: str | None) -> str:
    """Return the explicit bucket (validated) or the active one (holds ``_lock``)."""
    if bucket is not None:
        if bucket not in BUCKETS:
            raise ValueError(f"unknown call-counter bucket: {bucket!r}")
        return bucket
    return _current_bucket_locked()


def _resolve_module(module: str) -> str:
    """Return the module id, failing loud on a non-string (a caller bug, not wire data)."""
    if not isinstance(module, str):
        raise ValueError(f"invalid call-counter module: {module!r}")
    return module


def record_call(fn: str, *, bucket: str | None = None, module: str = UNKNOWN_MODULE) -> None:
    """Count one entry into the PKCS#11 function ``fn``.

    Attributed to ``bucket`` when given (validated like ``counted_bucket``),
    else to the calling thread's active bucket. ``module`` is the id bound to
    the handle the call passed through; the default ``""`` marks calls with
    no handle (never inferred to a real module). When durability is engaged
    the call self-registers first (raising ``CounterPersistenceError`` when
    sealed or on I/O failure, blocking provider entry), recovers any
    pending-persistence marker (retrying the covering flush; while the writer
    is still broken the entry raises without admitting), and K-flushes under
    the same lock acquisition. A failed K flush rolls back the just-admitted
    entry (strong exception guarantee): the provider never ran, so the
    session must not show the call either.
    """
    module_id = _resolve_module(module)
    if bucket is not None and bucket not in BUCKETS:
        raise ValueError(f"unknown call-counter bucket: {bucket!r}")
    with _lock:
        target = _resolve_bucket_locked(bucket)
        _ensure_registered_locked()
        _recover_pending_locked()
        key = (module_id, target, fn)
        _entry_counts[key] += 1
        if _registration is not None:
            _inprog_entry[key] += 1
        with _rollback_admission(entry_key=key, exit_key=None):
            _mark_dirty_locked(calls=1)


def record_return(
    fn: str, rv: int, *, bucket: str | None = None, module: str = UNKNOWN_MODULE
) -> None:
    """Count one return from ``fn`` with ``rv`` (same bucket rule as entry).

    Call sites that pair with :func:`record_call` must capture the bucket
    once at entry and pass it to both halves, so a mid-call bucket switch
    cannot land the entry and the RV in different buckets. The module halves
    must likewise match: entry and exit of one call always share a handle.
    The return fills the K window like an entry (with K=1 every return
    persists immediately). A failed flush RETAINS the just-admitted exit —
    the provider already returned, so rolling back would hide real traffic —
    marks the undurable evidence pending, and raises.
    """
    module_id = _resolve_module(module)
    if bucket is not None and bucket not in BUCKETS:
        raise ValueError(f"unknown call-counter bucket: {bucket!r}")
    with _lock:
        target = _resolve_bucket_locked(bucket)
        _ensure_registered_locked()
        key = (module_id, target, fn, rv)
        _exit_counts[key] += 1
        if _registration is not None:
            _inprog_exit[key] += 1
        try:
            _mark_dirty_locked(calls=1)
        except CounterPersistenceError:
            _set_pending_locked("return")
            raise


def record_direct_call(
    fn: str, rv: int, *, bucket: str | None = None, module: str = UNKNOWN_MODULE
) -> None:
    """Count a call made outside the ``_call`` choke point (entry + exit together).

    Post-hoc counting: the provider already ran, so unlike :func:`record_call`
    a failed flush RETAINS both halves (rolling back would hide real traffic),
    marks the undurable evidence pending, and raises.
    """
    module_id = _resolve_module(module)
    if bucket is not None and bucket not in BUCKETS:
        raise ValueError(f"unknown call-counter bucket: {bucket!r}")
    with _lock:
        target = _resolve_bucket_locked(bucket)
        _ensure_registered_locked()
        entry_key = (module_id, target, fn)
        exit_key = (module_id, target, fn, rv)
        _entry_counts[entry_key] += 1
        _exit_counts[exit_key] += 1
        if _registration is not None:
            _inprog_entry[entry_key] += 1
            _inprog_exit[exit_key] += 1
        try:
            _mark_dirty_locked(calls=1)
        except CounterPersistenceError:
            _set_pending_locked("direct")
            raise


def _serialize(
    entry: Counter[tuple[str, str, str]] | dict[tuple[str, str, str], int],
    exits: Counter[tuple[str, str, str, int]] | dict[tuple[str, str, str, int], int],
) -> dict[str, Any]:
    """Render counters in the module-first shape (uniform-5 per module block).

    ``{total_calls, by_module{module: {calls, buckets}}}`` with exact totals
    at both levels; inner buckets keep the rc1 serialized contract, and
    every module block present carries all five bucket keys (zero buckets
    explicit as ``{"calls": 0, "by_fn": {}}``) while functions/RVs stay
    sparse. An exit without an entry (a lone return) still opens its
    module map entry with zero calls, but the result fails validation;
    production return sites are always paired. Empty counters emit
    no module blocks at all (``{"total_calls": 0, "by_module": {}}``).
    """
    from pkcs11_check.raw.rv import ckr_name

    by_module: dict[str, dict[str, Any]] = {}
    total = 0
    for (module, bucket, fn), calls in entry.items():
        if calls <= 0:
            continue
        total += calls
        module_block = by_module.setdefault(module, {"calls": 0, "buckets": {}})
        module_block["calls"] += calls
        bucket_block = module_block["buckets"].setdefault(bucket, {"calls": 0, "by_fn": {}})
        bucket_block["calls"] += calls
        bucket_block["by_fn"][fn] = {"calls": calls, "by_rv": {}}
    for (module, bucket, fn, rv), count in exits.items():
        if count <= 0:
            continue
        module_block = by_module.setdefault(module, {"calls": 0, "buckets": {}})
        by_fn = module_block["buckets"].setdefault(bucket, {"calls": 0, "by_fn": {}})["by_fn"]
        target = by_fn.setdefault(fn, {"calls": 0, "by_rv": {}})
        target["by_rv"][str(rv)] = {"name": ckr_name(rv), "count": count}
    for module_block in by_module.values():
        module_block["buckets"] = ensure_five_buckets(module_block["buckets"])
    return {"total_calls": total, "by_module": by_module}


Snapshot = tuple[Counter[tuple[str, str, str]], Counter[tuple[str, str, str, int]]]


def take_snapshot() -> Snapshot:
    """Return a detached copy of both counters for later ``diff_snapshots``."""
    with _lock:
        return (Counter(_entry_counts), Counter(_exit_counts))


def diff_snapshots(before: Snapshot, after: Snapshot) -> dict[str, Any]:
    """Serialize the ``after - before`` delta in the module-first shape.

    Only positive deltas are reported; modules, functions, and RVs with no
    new calls in the window are omitted (sparse), while every module block
    present carries all five bucket keys (uniform-5, zero buckets explicit).
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
    """Serialize all counters recorded so far in the module-first shape."""
    with _lock:
        return _serialize(Counter(_entry_counts), Counter(_exit_counts))


def flatten_current() -> list[list[str | int | None]]:
    """Flatten all counters to the child wire format ``[[module, fn, rv_or_None, count]]``.

    Bucket attribution is dropped (the ingesting parent applies its own
    bucket); the module id is kept so absorbed traffic stays attributable and
    ``rv None`` marks entries that never returned. Sorted by module, then fn,
    then RV ascending with the unreturned row last per fn.
    """
    with _lock:
        entries: Counter[tuple[str, str]] = Counter()
        for (module, _bucket, fn), calls in _entry_counts.items():
            entries[(module, fn)] += calls
        exits: Counter[tuple[str, str, int]] = Counter()
        for (module, _bucket, fn, rv), count in _exit_counts.items():
            exits[(module, fn, rv)] += count
    typed: list[tuple[str, str, int | None, int]] = []
    for (module, fn, rv), count in exits.items():
        typed.append((module, fn, rv, count))
        entries[(module, fn)] -= count
    for (module, fn), unreturned in entries.items():
        if unreturned > 0:
            typed.append((module, fn, None, unreturned))
    typed.sort(key=lambda item: (item[0], item[1], item[2] is None, item[2] or 0))
    return [[module, fn, rv, count] for module, fn, rv, count in typed]


def _parse_flat_rows(flat: Any) -> list[tuple[str, str, int | None, int]]:
    """Parse child wire-format rows (pure; garbage rows skipped, never raised)."""
    if not isinstance(flat, (list, tuple)):
        return []
    parsed: list[tuple[str, str, int | None, int]] = []
    for row in flat:
        if not isinstance(row, (list, tuple)):
            continue
        module: Any
        fn: Any
        rv: Any
        count: Any
        if len(row) == 3:
            module = UNKNOWN_MODULE
            fn, rv, count = row[0], row[1], row[2]
        elif len(row) == 4:
            module, fn, rv, count = row[0], row[1], row[2], row[3]
        else:
            continue
        if not isinstance(module, str):
            continue
        if not isinstance(fn, str) or not fn:
            continue
        if rv is not None and (not isinstance(rv, int) or isinstance(rv, bool) or rv < 0):
            continue
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            continue
        parsed.append((module, fn, rv, count))
    return parsed


def _parse_lost_count(value: Any) -> int:
    """Return a propagated loss count, or 0 for garbage (never raises)."""
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        return 0
    return value


def _parse_receipts(value: Any) -> set[tuple[str, int]]:
    """Return the well-formed receipt keys from a payload value (never raises)."""
    if not isinstance(value, (list, tuple)):
        return set()
    keys: set[tuple[str, int]] = set()
    for entry in value:
        if is_receipt(entry):
            keys.add((entry["worker_uuid"], entry["probe_seq"]))
    return keys


def _parse_lost_keys(value: Any) -> set[tuple[str, int]]:
    """Return the well-formed lost keys from a payload value (never raises)."""
    if not isinstance(value, (list, tuple)):
        return set()
    keys: set[tuple[str, int]] = set()
    for entry in value:
        if is_lost_key(entry):
            keys.add((entry["parent_uuid"], entry["probe_seq"]))
    return keys


def _count_malformed_lost_keys(value: Any) -> int:
    """Count malformed lost-key items (each floors one unkeyed loss).

    Mirrors the probe-orphan reader: explicit null reads absent (the
    ingest parser's tolerance), a non-list field counts one corrupt
    blob, else each ill-formed item counts one. Never raises.
    """
    if value is None:
        return 0
    if not isinstance(value, (list, tuple)):
        return 1
    return sum(1 for entry in value if not is_lost_key(entry))


def _parse_ingest_source(value: Any) -> tuple[str, int] | None:
    """Return a well-formed ingest source ``(parent_uuid, probe_seq)``, else None."""
    if not isinstance(value, tuple) or len(value) != 2:
        return None
    parent, seq = value
    if not is_worker_uuid(parent) or not is_probe_seq(seq):
        return None
    assert isinstance(parent, str) and isinstance(seq, int)
    return (parent, seq)


def ingest_child_evidence(
    flat: Any,
    lost: Any = 0,
    receipts: Any = (),
    *,
    bucket: str | None = None,
    lost_keys: Any = (),
    source: Any = None,
    consumed_probe: Any = None,
) -> None:
    """Merge one child's evidence atomically: counts + losses + receipts.

    ``consumed_probe`` is a validated ``(child_uuid, probe_seq)`` pair
    for a sidecar-fallback absorption: it lands in ``_consumed_probes``
    under the same lock acquisition, BEFORE any K auto-flush, so no
    checkpoint ever carries absorbed counts without their
    anti-double-fold proof (a parent death between the auto-flush and
    a later note would otherwise double-fold the retained orphan).
    Malformed rows, loss values, and receipts are ignored like any
    other garbage item; malformed lost keys instead floor unkeyed
    losses (each proves a loss without naming it, exactly what the
    unkeyed remainder means), so corrupt key metadata can never
    vanish silently (codex R7-F3).

    ONE atomic transaction under the counters lock (validate counts,
    propagated losses, keys, and receipt inserts, apply, mark dirty):
    checkpoints and flushes observe all-or-none. Garbage-tolerant per item
    (a hostile row, loss value, key, or receipt never breaks the ingest);
    an explicitly unknown ``bucket`` raises ValueError like
    ``counted_bucket``. Keyed losses union (idempotent); the scalar covers
    the child's whole loss total, so the unkeyed remainder is
    ``max(0, scalar - len(keys))`` (identities win over an inconsistent
    scalar, fail closed toward incomplete), plus the malformed-key
    floor when no positive total was propagated (a positive total
    already includes every loss counted at write time). A well-formed
    ``source``
    ``(parent_uuid, probe_seq)`` makes repeat ingests of one payload a
    no-op (same source implies same payload); sourceless payloads always
    apply (no fresh-run vector re-ingests them). When durability is engaged
    the ingest self-registers first (raising ``CounterPersistenceError``
    when sealed) and K-flushes under the same acquisition. Unlike the
    ``record_*`` entry points, a failed K flush here does NOT roll back:
    child evidence is post-hoc real provider data, so it stays admitted
    (dirty, retried by the next flush) rather than undercounting calls that
    provably ran; the undurable evidence is marked pending instead.
    Loss-only and receipt-only ingests flush immediately (they count one
    window unit despite carrying zero calls).
    """
    global _unkeyed_lost, _receipts, _lost_keys
    if bucket is not None and bucket not in BUCKETS:
        raise ValueError(f"unknown call-counter bucket: {bucket!r}")
    parsed = _parse_flat_rows(flat)
    lost_count = _parse_lost_count(lost)
    receipt_keys = _parse_receipts(receipts)
    key_set = _parse_lost_keys(lost_keys)
    malformed_keys = _count_malformed_lost_keys(lost_keys)
    src = _parse_ingest_source(source)
    consumed_key = _parse_ingest_source(consumed_probe)
    with _lock:
        target = _resolve_bucket_locked(bucket)
        _ensure_registered_locked()
        if src is not None and src in _ingested_sources:
            return
        for module, fn, rv, count in parsed:
            _entry_counts[(module, target, fn)] += count
            if _registration is not None:
                _inprog_entry[(module, target, fn)] += count
            if rv is not None:
                _exit_counts[(module, target, fn, rv)] += count
                if _registration is not None:
                    _inprog_exit[(module, target, fn, rv)] += count
        _lost_keys |= key_set
        # Without a positive total nothing was ever counted inside
        # it, so each malformed item floors one unkeyed loss on its
        # own (a positive total already includes them: the remainder
        # carries them, never the bump too).
        _unkeyed_lost += max(0, lost_count - len(key_set)) + (
            malformed_keys if lost_count == 0 else 0
        )
        _receipts |= receipt_keys
        if consumed_key is not None:
            _consumed_probes.add(consumed_key)
        if src is not None:
            _ingested_sources.add(src)
        if parsed or lost_count or receipt_keys or key_set or consumed_key is not None:
            try:
                units = sum(count for _, _, _, count in parsed) if parsed else 1
                _mark_dirty_locked(calls=units)
            except CounterPersistenceError:
                _set_pending_locked("ingest")
                raise


def ingest_child_counts(flat: list[Any], *, bucket: str | None = None) -> None:
    """Merge child wire-format rows into the globals under ``bucket`` (or active).

    Only ``[module, fn, rv_or_None, count]`` rows with a str module, a
    non-empty str fn, a None-or-non-negative-int rv (bools rejected), and a
    positive int count are applied; legacy 3-column ``[fn, rv, count]`` rows
    fold under the ``""`` unknown module, and every other shape (including a
    non-list/tuple payload) is ignored without raising. A negative rv is
    garbage per-row, never folded: serializing one would emit a ``"-1"`` RV
    key the extractor rejects whole-record, discarding valid traffic. An
    explicitly unknown ``bucket`` raises ValueError like ``counted_bucket``.
    Applies through :func:`ingest_child_evidence` (one lock acquisition).
    """
    ingest_child_evidence(flat, 0, (), bucket=bucket)


def note_lost_probe(*, parent_uuid: Any = None, probe_seq: Any = None) -> None:
    """Record one probe child whose counters could not be recovered.

    With a well-formed ``(parent_uuid, probe_seq)`` identity the loss is
    keyed (duplicates collapse to one); otherwise it lands unkeyed (never
    heals, never breaks the caller). Self-registers first like the
    record_* paths (a loss note is a zero-call mutation, so an engaged
    but fresh process must still persist it); sealed raises before
    anything is admitted. A failed flush retains the loss, marks it
    pending, and raises (never silently dropped).
    """
    global _unkeyed_lost
    key: tuple[str, int] | None = None
    if (
        parent_uuid is not None
        and probe_seq is not None
        and is_worker_uuid(parent_uuid)
        and is_probe_seq(probe_seq)
    ):
        assert isinstance(parent_uuid, str) and isinstance(probe_seq, int)
        key = (parent_uuid, probe_seq)
    with _lock:
        _ensure_registered_locked()
        if key is not None:
            _lost_keys.add(key)
        else:
            _unkeyed_lost += 1
        try:
            _mark_dirty_locked(calls=1)
        except CounterPersistenceError:
            _set_pending_locked("note")
            raise


def add_lost_probes(n: Any) -> None:
    """Add ``n`` child-side losses propagated through a coverage payload.

    Garbage-tolerant like :func:`ingest_child_counts`: anything that is not a
    positive ``int`` (bools included) is ignored without raising, so a hostile
    payload value can never break the ingest path (garbage parses out before
    registration, so it stays silent even when sealed). Real losses
    self-register first like the record_* paths; sealed raises before
    anything is admitted. A failed flush retains the losses, marks them
    pending, and raises.
    """
    global _unkeyed_lost
    with _lock:
        lost_count = _parse_lost_count(n)
        if lost_count:
            _ensure_registered_locked()
            _unkeyed_lost += lost_count
            try:
                _mark_dirty_locked(calls=1)
            except CounterPersistenceError:
                _set_pending_locked("note")
                raise


def probes_lost() -> int:
    """Return the number of probe children with unrecoverable counters.

    Derived as keyed + unkeyed so the two can never drift apart.
    """
    with _lock:
        return len(_lost_keys) + _unkeyed_lost


def lost_probe_keys() -> list[dict[str, Any]]:
    """Return the live keyed-loss set as sorted ``{parent_uuid, probe_seq}`` dicts."""
    with _lock:
        return [{"parent_uuid": parent, "probe_seq": seq} for parent, seq in sorted(_lost_keys)]


def persistence_pending() -> bool:
    """Whether admitted counter evidence is still undurable.

    True after a failed return/mutation checkpoint until a sidecar flush or
    journal append durably covers the retained evidence. Session emission
    reads this: a surviving marker forces counter-specific incomplete.
    """
    with _lock:
        return _persistence_pending is not None


def pending_marker() -> dict[str, Any] | None:
    """Return the pending-persistence marker for session emission, else None.

    The marker carries the failed checkpoint kind plus unit/attempt
    identity (a copy; mutating it affects nothing).
    """
    with _lock:
        return dict(_persistence_pending) if _persistence_pending is not None else None


def assign_probe_seq() -> int:
    """Assign the next folded-probe sequence number for this process (0-based).

    The parent assigns one seqno per probe launch and the child echoes it in
    its coverage receipt; the parent accepts the receipt only on an exact
    match. Pure in-memory counter (no registration, never raises).
    """
    global _probe_seq
    with _lock:
        seq = _probe_seq
        _probe_seq += 1
        return seq


def current_receipts() -> list[dict[str, Any]]:
    """Return the folded-probe receipts accumulated so far (sorted, detached)."""
    with _lock:
        return [{"worker_uuid": uuid, "probe_seq": seq} for uuid, seq in sorted(_receipts)]


def current_consumed() -> list[dict[str, Any]]:
    """Return the consumed fallback-absorption proofs so far (sorted, detached).

    Same shape as :func:`current_receipts`, disjoint meaning: these
    suppress retained orphans at collection but never earn detail
    rows. Teardown entries snapshot the window-scoped delta.
    """
    with _lock:
        return [{"worker_uuid": uuid, "probe_seq": seq} for uuid, seq in sorted(_consumed_probes)]


def publish_test_window(nodeid: str, block: Mapping[str, Any] | None = None) -> None:
    """Publish one test window to the journal and reset the in-progress tail.

    No-op when disengaged. Otherwise appends ``(nodeid, block, receipts)``
    to the journal FIRST, then resets the in-progress accumulator and
    boundary-flushes (carrying the new journal length), so any crash
    interleaving stays sound: journaled-but-unflushed windows subsume the
    stale snapshot (the collector's older-mark arm folds the journal and
    excludes it). A failed append leaves the baseline unadvanced (nothing is
    eagerly cleared) and any pending marker set. A successful append covers
    all retained evidence, so it clears a pre-existing marker even when the
    boundary sidecar flush then fails (that failure still raises,
    fail-visible, but sets no marker: the journal leg already covers the
    evidence). Callers passing an explicit block promise it covers the
    accumulator, as snapshot-derived windows do. Raises
    ``CounterPersistenceError`` when sealed or on I/O failure, ValueError on
    a caller-bug block/nodeid.
    """
    global _journal_len, _dirty, _persistence_pending
    if durability_dir() is None:
        return
    if not isinstance(nodeid, str) or not nodeid:
        raise ValueError(f"invalid test window nodeid: {nodeid!r}")
    with _lock:
        registration = _ensure_registered_locked()
        assert registration is not None
        if block is None:
            window = _serialize(Counter(_inprog_entry), Counter(_inprog_exit))
        else:
            if not is_module_first_block(block):
                raise ValueError(f"invalid test window block for {nodeid!r}")
            window = {"total_calls": block["total_calls"], "by_module": block["by_module"]}
        try:
            append_journal(
                registration.journal_path,
                {
                    "nodeid": nodeid,
                    "block": window,
                    "receipts": [
                        {"worker_uuid": uuid, "probe_seq": seq} for uuid, seq in sorted(_receipts)
                    ],
                    # The anti-double-fold proof rides with the counts:
                    # a death between this append and the boundary
                    # sidecar replacement below must still suppress the
                    # retained orphan (codex RC4-R2).
                    "consumed_probes": [
                        {"worker_uuid": uuid, "probe_seq": seq}
                        for uuid, seq in sorted(_consumed_probes)
                    ],
                },
            )
        except OSError as exc:
            raise CounterPersistenceError(f"cannot publish test window {nodeid}: {exc}") from exc
        _journal_len += 1
        # The append covered every retained kind: clear any marker even
        # though the boundary flush below may still fail (journal leg).
        _persistence_pending = None
        _inprog_entry.clear()
        _inprog_exit.clear()
        _dirty = True
        _flush_locked()


def reset_for_tests() -> None:
    """Clear counters, phase, regions, losses, identity, receipts, and durability."""
    global _unkeyed_lost, _phase_name, _worker_uuid, _worker_uuid_pid
    global _registration, _registration_pid, _dirty, _pending_calls, _probe_seq, _journal_len
    global _persistence_pending, _flush_k_cache, _probe_pending_calls, _probe_flush_warned
    global _consumed_probes
    with _lock:
        _entry_counts.clear()
        _exit_counts.clear()
        _phase_name = DEFAULT_BUCKET
        _lost_keys.clear()
        _unkeyed_lost = 0
        _ingested_sources.clear()
        _persistence_pending = None
        _worker_uuid = None
        _worker_uuid_pid = None
        _registration = None
        _registration_pid = None
        _dirty = False
        _pending_calls = 0
        _flush_k_cache = None
        _probe_pending_calls = 0
        _probe_flush_warned = False
        _consumed_probes.clear()
        _receipts.clear()
        _probe_seq = 0
        _inprog_entry.clear()
        _inprog_exit.clear()
        _journal_len = 0
    _state.regions.clear()


__all__ = [
    "BUCKETS",
    "CALL_COUNTERS_PROPERTY",
    "CALL_COUNTERS_REPORT_TYPE",
    "DEFAULT_BUCKET",
    "ISOLATION_ENV",
    "RUN_ID_ENV",
    "Snapshot",
    "CounterPersistenceError",
    "add_lost_probes",
    "assign_probe_seq",
    "counted_bucket",
    "current_bucket",
    "current_consumed",
    "current_receipts",
    "diff_snapshots",
    "ensure_registered",
    "flatten_current",
    "flush_counters",
    "get_worker_uuid",
    "ingest_child_counts",
    "ingest_child_evidence",
    "lost_probe_keys",
    "note_lost_probe",
    "pending_marker",
    "persistence_pending",
    "probes_lost",
    "publish_test_window",
    "record_call",
    "record_direct_call",
    "record_return",
    "registration_info",
    "reset_for_tests",
    "serialize_current",
    "take_snapshot",
]
