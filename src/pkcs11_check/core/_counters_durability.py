"""Durable counter evidence: registry, sidecars, collection, sweep, fence (rc2 Task 3).

Child-side self-registration into per-process registry files, gap-only
sidecar/journal persistence, parent-side collection into JSONL-anchored
partial/lost records, orphan sweep, and incarnation-verified fencing behind
the admission barrier. Engaged only when ``PKCS11_CHECK_COUNTERS_DIR`` is set;
without it every entry point is inert and counter behavior is unchanged.

File layout under the counters dir (all names carry the producer identity;
at most one writer ever touches one file, so no locks are needed)::

    registrations/<worker_uuid>.json      O_EXCL self-describing registration
    <uuid>-<nonce>.partial.json           in-progress snapshot (tmp+replace)
    <uuid>-<nonce>.windows.jsonl          published per-test windows (append)
    probe-<uuid8>-<seq>-<nonce>.json      retained probe evidence (adopted at collect)

Crash-consistency rule: the journal appends first, the in-progress
accumulator resets second, and the sidecar (carrying ``journal_seq``, the
journal length reflected in the reset) flushes third. The collector compares
the mark against n, the number of content-valid journal windows anywhere in
the file (a torn middle line flags ``conflict`` but valid lines still fold:
single-writer append order keeps every valid line a real window). Three
arms: mark == n folds the valid windows plus the in-progress tail; mark < n
(crash between journal append and sidecar replace, possibly repeatedly)
folds every valid window and EXCLUDES the stale snapshot, which the first
valid window beyond the mark subsumes (failed appends never reset, so that
window is a superset of the last-flushed accumulator); mark > n is a
vanished append (corruption: conflict, lost record only). A missing mark
with a non-empty journal folds the snapshot only and conflicts (overlap
unknowable). A torn tail is the crash-mid-append shape (dropped, benign).

Scope is process death (SIGKILL, ``os._exit``, C-level termination): page
cache survives those, so no fsync is used anywhere here. Machine crash can
lose the unflushed tail; that is documented and out of scope.

This module imports only stdlib plus ``counters_schema`` and
``report_log.user_property`` (both stdlib-only leaves), so
``call_counters`` can import it without cycles.
"""

from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
import select
import signal
import sys
import time
import warnings
from collections.abc import Callable, Collection, Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pkcs11_check.core.counters_schema import (
    LOST_REPORT_TYPE,
    PARTIAL_ALLOWED_KEYS,
    PARTIAL_REPORT_TYPE,
    PARTIAL_REQUIRED_KEYS,
    REGISTRY_DIRNAME,
    SESSION_REPORT_TYPE,
    TEST_ENTRY_PROPERTY,
    UNKNOWN_MODULE,
    ensure_five_buckets,
    is_birth_token,
    is_legacy_buckets_block,
    is_lost_key,
    is_lost_record,
    is_module_first_block,
    is_receipt,
    is_registry_content,
    is_role,
    is_session_record,
    is_test_entry,
    is_worker_uuid,
    key_violations,
    merge_module_first,
    mint_filename_nonce,
    parse_registry_filename,
    wrap_module_first,
)
from pkcs11_check.core.report_log import (
    iter_report_log_records,
    parse_report_log_line,
    user_property,
)

COUNTERS_DIR_ENV = "PKCS11_CHECK_COUNTERS_DIR"
COUNTERS_UNIT_ENV = "PKCS11_CHECK_COUNTERS_UNIT"
COUNTERS_ATTEMPT_ENV = "PKCS11_CHECK_COUNTERS_ATTEMPT"
COUNTERS_ROLE_ENV = "PKCS11_CHECK_COUNTERS_ROLE"
PROBE_SEQ_ENV = "_P11CHECK_PROBE_SEQ"
PROBE_SIDECAR_ENV = "_P11CHECK_PROBE_SIDECAR"
#: Parent-identity context for one probe child (rc3 Area B, F2): the runner
#: exports all six so the child's sidecar is self-describing even when the
#: parent's registry is gone. The child embeds the set ones; unset or
#: malformed values omit that field (legacy shape stays byte-identical).
PROBE_PARENT_ENV = "_P11CHECK_PROBE_PARENT"
PROBE_RUN_ENV = "_P11CHECK_PROBE_RUN"
PROBE_UNIT_ENV = "_P11CHECK_PROBE_UNIT"
PROBE_ATTEMPT_ENV = "_P11CHECK_PROBE_ATTEMPT"
PROBE_ROLE_ENV = "_P11CHECK_PROBE_ROLE"
PROBE_ISOLATION_ENV = "_P11CHECK_PROBE_ISOLATION"

#: Evidence units between automatic sidecar flushes (K bound, per producer).
#: K=1 (rc3 Area A): every entry, every return, and every zero-call
#: mutation (loss notes, receipt/loss-only ingests) persists immediately,
#: so a crash loses at most the in-flight checkpoint itself. ``_pending_calls``
#: still counts toward the window (entries, returns, and mutations each add
#: one unit); with K=1 it returns to zero after every mark.
#: This constant is the DEFAULT; ``PKCS11_CHECK_COUNTERS_FLUSH_K`` may raise
#: it per run (see ``call_counters.effective_flush_k``).
FLUSH_WINDOW_K = 1
#: Opt-in sidecar flush cadence: persist every K evidence units instead of
#: every unit. Unset (or garbage, with a loud one-per-process warning)
#: means 1 (exact, the default). K counts evidence units -- entries,
#: returns, and zero-call mutations each add one; ingests add their row
#: counts -- not completed PKCS#11 calls: a crash can lose up to the last
#: K-1 unflushed units of sidecar tail (counts and key detail alike),
#: always flagged incomplete by the producer's death. Boundary, exit,
#: probe flush-before-delete, and persistence-recovery flushes stay
#: unconditional at any K. Read once per process; children inherit via env.
COUNTERS_FLUSH_K_ENV = "PKCS11_CHECK_COUNTERS_FLUSH_K"
SEAL_FILENAME = "SEALED"
#: Round stamp for corrupt sidecar runs: present-but-unusable (null,
#: mistyped) reads this sentinel, never the implicit round, so
#: explicitly corrupt rounds stay distinguishable from absent ones.
#: Reserved: a manual PKCS11_CHECK_RUN_ID=unknown would merge with
#: corrupt evidence (the CLI seeds structured run ids, never this).
_UNKNOWN_RUN = "unknown"


def reject_reserved_run_id(run_id: str | None) -> None:
    """Raise ``CounterPersistenceError`` when ``run_id`` abuses the sentinel.

    ``"unknown"`` stamps corrupt-evidence rounds (see ``_UNKNOWN_RUN``):
    no live producer may run under it, or its session would silently
    supersede corrupt checkpoints sharing its uuid (codex R9-F2).
    Anything else (including None/unset) passes. Enforced everywhere
    live evidence takes a run: registration, session records,
    per-test window entries, and preflight/recovery engagement.
    """
    if run_id == _UNKNOWN_RUN:
        raise CounterPersistenceError(
            "reserved run_id 'unknown': it stamps corrupt-evidence rounds and "
            "must never identify a live run "
            "(unset PKCS11_CHECK_RUN_ID or pick another run id)"
        )


SIDECAR_SUFFIX = ".partial.json"
JOURNAL_SUFFIX = ".windows.jsonl"
RECOVERY_SUPPLEMENTS_SUFFIX = ".recovery-counters.jsonl"
#: Retained probe sidecars (``probe-<parent-uuid8>-<seq>-<nonce>.json``).
PROBE_FILE_PREFIX = "probe-"
PROBE_FILE_SUFFIX = ".json"
#: Consumed markers: a committed probe sidecar whose delete failed, renamed
#: to ``probe-consumed-<parent-uuid8>-<seq>-<nonce>.json`` (same content) so
#: orphan adoption suppresses it instead of folding it a second time.
PROBE_CONSUMED_PREFIX = "probe-consumed-"
#: Resume-barrier staging: the collected plan persisted (atomically) before
#: any source file is consumed, so a controller death between the barrier
#: and its application loses nothing. Matches no collector/sweep glob.
BARRIER_STAGING_FILENAME = "barrier-staging.json"


def _is_authoritative_staged_record(record: Any) -> bool:
    """Whether a staged record proves the evidence behind a uuid claim (#88R12-3).

    Only extractor-acceptable barrier records authorize suppression: a
    partial needs the partial key shape with valid values (mirroring
    the extractor's own acceptance: exact ``truncated``, valid uuid,
    usable total, well-formed round, one valid counters shape, and
    valid pid/role/probes_lost when present), and a loss needs the
    loss schema with a valid worker uuid. A bare dict with a tag --
    or the right keys with garbage values the extractor would reject
    -- proves nothing (#88R13-1). The discriminator is type-checked
    first: an unhashable tag degrades, never raises. Never raises.
    """
    if not isinstance(record, dict):
        return False
    report_type = record.get("$report_type")
    if not isinstance(report_type, str):
        return False
    if report_type == PARTIAL_REPORT_TYPE:
        if key_violations(record, allowed=PARTIAL_ALLOWED_KEYS, required=PARTIAL_REQUIRED_KEYS):
            return False
        if record.get("truncated") is not True:
            return False
        if not is_worker_uuid(record.get("worker_uuid")):
            return False
        total = record.get("total_calls")
        if not _is_nonneg_int(total):
            return False
        if "run_id" in record:
            run_id = record.get("run_id")
            if not isinstance(run_id, str) or not run_id:
                return False
        has_buckets = "buckets" in record
        has_modules = "by_module" in record
        if has_buckets == has_modules:
            return False
        assert isinstance(total, int)
        if has_buckets:
            if not is_legacy_buckets_block({"total_calls": total, "buckets": record["buckets"]}):
                return False
        elif not is_module_first_block({"total_calls": total, "by_module": record["by_module"]}):
            return False
        if "pid" in record and not _is_nonneg_int(record.get("pid")):
            return False
        role = record.get("role")
        if role is not None and not is_role(role):
            return False
        return _is_nonneg_int(record.get("probes_lost", 0))
    if report_type == LOST_REPORT_TYPE:
        return is_lost_record(record) and is_worker_uuid(record.get("worker_uuid"))
    return False


ProducerVerdict = Literal["alive", "dead", "unknown"]
FenceOutcome = Literal["fenced", "unresolved"]

#: Signals that mean "killed from outside" rather than "crashed itself".
#: Literal POSIX numbers (SIGKILL=9, SIGTERM=15): negative return codes are
#: POSIX signal-death encoding (Windows never yields them), and a pure
#: mapping must not vary by platform.
_KILL_SIGNALS = frozenset({9, 15})

#: Win32 process rights + wait/error codes shared by the kernel32 call sites.
_PROCESS_TERMINATE = 0x0001
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x00100000
_WAIT_OBJECT_0 = 0x00000000
_ERROR_INVALID_PARAMETER = 87


class CounterPersistenceError(Exception):
    """Counter evidence could not be registered, flushed, or published.

    Raised child-side (registration/flush/publish paths in
    ``call_counters``), where it blocks the provider call: unregistered
    evidence would silently undercount. Parent-side collection never raises
    this (it warns and retains the files for a later pass instead), so a
    counter I/O failure can never fail a run's verdicts. Routing (CLI exit
    codes, pytest errors, preflight manifests) is Task 4's scope.
    """


@dataclass(frozen=True)
class Registration:
    """One producer's durable registration (registry file + evidence paths)."""

    worker_uuid: str
    pid: int
    run_id: str
    unit: str
    attempt: int
    role: str
    isolation: str
    registry_path: Path
    sidecar_path: Path
    journal_path: Path


def durability_dir() -> Path | None:
    """Return the engaged counters dir, or None when durability is off."""
    raw = os.environ.get(COUNTERS_DIR_ENV, "").strip()
    return Path(raw) if raw else None


def counters_dir_for_state(state_file: Path | str) -> Path:
    """Return the legacy canonical counters dir for one isolated run series.

    Kept for retiring pre-N-C3 runs (fresh reset removes it); new series
    allocate :func:`counters_run_dir_for_state` instead, so a fresh run
    can never absorb a dead series' evidence through a reused directory.
    """
    state_path = Path(state_file)
    return state_path.with_name(f"{state_path.name}.counters")


def counters_run_dir_for_state(state_file: Path | str, nonce: str) -> Path:
    """Return a fresh-series counters dir: ``{state}.counters.{nonce}``.

    A pure function of the state path plus a per-invocation nonce, so the
    F-038 state guard still covers it (same-state runs are serialized;
    different-state runs use different names) with no separate guard
    entry. Resume reuses the state's recorded dir; fresh runs allocate a
    new one and retire the previous series' dir with its state.
    """
    state_path = Path(state_file)
    return state_path.with_name(f"{state_path.name}.counters.{nonce}")


def ensure_layout(root: Path | str) -> Path:
    """Create the counters dir + registrations subdir (idempotent).

    Raises:
        CounterPersistenceError: When the layout cannot be created.
    """
    resolved = Path(root)
    try:
        (resolved / REGISTRY_DIRNAME).mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CounterPersistenceError(f"cannot create counters dir {resolved}: {exc}") from exc
    return resolved


def is_sealed(root: Path | str) -> bool:
    """Whether the admission barrier is sealed (post-seal producers rejected)."""
    return (Path(root) / SEAL_FILENAME).exists()


def seal(root: Path | str, *, reason: str = "") -> Path:
    """Seal the admission barrier (idempotent; first seal wins).

    Raises:
        CounterPersistenceError: When the seal cannot be written.
    """
    resolved = ensure_layout(root)
    path = resolved / SEAL_FILENAME
    if path.exists():
        return path
    payload = json.dumps({"sealed": True, "timestamp": time.time(), "reason": reason})
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        return path
    except OSError as exc:
        raise CounterPersistenceError(f"cannot seal counters dir {resolved}: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
    except OSError as exc:
        raise CounterPersistenceError(f"cannot seal counters dir {resolved}: {exc}") from exc
    return path


def unseal(root: Path | str) -> None:
    """Lift the admission barrier (idempotent; missing seal is a no-op).

    Raises:
        CounterPersistenceError: When the seal cannot be removed.
    """
    path = Path(root) / SEAL_FILENAME
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise CounterPersistenceError(f"cannot unseal counters dir {Path(root)}: {exc}") from exc


def birth_token_for_pid(pid: int) -> int | None:
    """Return the OS process-birth id for ``pid``, or None when unverifiable.

    Linux ``/proc/<pid>/stat`` starttime (field 22), Windows process
    creation time; None on dead pids and on platforms without a birth
    source (macOS). None means fencing must report unresolved without
    signaling, never guess.
    """
    if pid < 0:
        return None
    if sys.platform == "win32":
        return _windows_creation_time(pid)
    if sys.platform.startswith("linux"):
        return _linux_starttime(pid)
    return None


def _linux_starttime(pid: int) -> int | None:
    """Return ``/proc/<pid>/stat`` field 22 (starttime), or None."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            data = fh.read()
    except (OSError, ValueError):
        return None
    # comm (field 2) may contain spaces and parens: everything after the
    # LAST ')' starts at field 3 (state), so starttime (field 22) sits at
    # index 19 of the remainder.
    tail = data[data.rfind(")") + 1 :].split()
    if len(tail) < 20:
        return None
    try:
        starttime = int(tail[19])
    except ValueError:
        return None
    return starttime if starttime >= 0 else None


def _kernel32() -> Any:
    """Return kernel32 with the process-handle entry points declared.

    Single declaration site for the three Windows call sites (birth
    tokens, liveness, fencing): HANDLEs are pointer-sized (``c_void_p``)
    on both 32- and 64-bit targets, and ``use_last_error`` is on so
    callers discriminate a dead pid from access-denied through
    ``GetLastError``. Windows only; tests inject doubles behind this seam.
    """
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    handle = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = [ctypes.c_uint, ctypes.c_bool, ctypes.c_uint]
    kernel32.OpenProcess.restype = handle
    filetime = ctypes.POINTER(ctypes.c_ulonglong)
    kernel32.GetProcessTimes.argtypes = [handle, filetime, filetime, filetime, filetime]
    kernel32.GetProcessTimes.restype = ctypes.c_bool
    kernel32.TerminateProcess.argtypes = [handle, ctypes.c_uint]
    kernel32.TerminateProcess.restype = ctypes.c_bool
    kernel32.CloseHandle.argtypes = [handle]
    kernel32.CloseHandle.restype = ctypes.c_bool
    kernel32.WaitForSingleObject.argtypes = [handle, ctypes.c_uint]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint
    kernel32.GetLastError.argtypes = []
    kernel32.GetLastError.restype = ctypes.c_uint
    return kernel32


def _process_creation_time(kernel32: Any, handle: Any) -> int | None:
    """Read one open handle's creation FILETIME as an int, or None.

    All four out-params get real buffers: GetProcessTimes writes each
    unconditionally, so a NULL out-pointer access-violates instead of
    being skipped.
    """
    import ctypes

    creation = ctypes.c_ulonglong(0)
    exit_time = ctypes.c_ulonglong(0)
    kernel_time = ctypes.c_ulonglong(0)
    user_time = ctypes.c_ulonglong(0)
    if not kernel32.GetProcessTimes(
        handle,
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel_time),
        ctypes.byref(user_time),
    ):
        return None
    return int(creation.value)


def _windows_creation_time(pid: int) -> int | None:
    """Return a process's creation FILETIME as an int, or None."""
    kernel32 = _kernel32()
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        return _process_creation_time(kernel32, handle)
    finally:
        kernel32.CloseHandle(handle)


def _pid_exists(pid: int) -> bool:
    """Whether ``pid`` currently names a live process (no signaling)."""
    if pid < 0:
        return False
    if sys.platform == "win32":
        kernel32 = _kernel32()
        handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            # Access-denied (or any non-not-found failure) names something
            # we cannot open: alive-conservative. Only the not-found error
            # proves death; True still funnels into the birth check, which
            # reads None here and degrades to unknown (never signaled).
            return bool(kernel32.GetLastError() != _ERROR_INVALID_PARAMETER)
        kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def verify_producer(registry: dict[str, Any]) -> ProducerVerdict:
    """Classify a registered producer without touching it.

    ``alive`` requires the pid to exist AND the live birth token to match
    the registered one (a recycled pid reads ``dead``: the registered
    incarnation is gone). ``unknown`` means alive-but-unverifiable or an
    invalid identity: fencing must report unresolved, never signal.
    """
    pid = registry.get("pid")
    if not _is_nonneg_int(pid):
        return "unknown"
    assert isinstance(pid, int)
    if not _pid_exists(pid):
        return "dead"
    current = birth_token_for_pid(pid)
    if current is None:
        return "unknown"
    claimed = registry.get("birth_token")
    if not is_birth_token(claimed):
        return "unknown"
    return "alive" if current == claimed else "dead"


def _is_nonneg_int(value: object) -> bool:
    """Whether ``value`` is a non-negative int (bools rejected)."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def register_worker(
    root: Path | str,
    *,
    run_id: str,
    unit: str,
    attempt: int,
    role: str,
    isolation: str,
    worker_uuid: str,
    pid: int,
) -> Registration:
    """Self-register one producer (O_EXCL registry file + evidence paths).

    Registration causally precedes the producer's first provider call, so a
    torn or missing registry proves zero-loss: nothing was ever admitted.
    Filenames carry identity + nonce (uuid4, randomness only), so two
    producers never share evidence files. Registry invariant: isolation
    is required and non-empty here, so every registry-backed producer
    carries its attribution stamp from birth (records read it back,
    defaulting to ``unknown`` only for legacy registry-less evidence).

    Raises:
        CounterPersistenceError: When sealed (pre-check, or a barrier seal
            landing between the check and the publish, in which case the
            late registry is unlinked again), on invalid identity inputs,
            on I/O failure, or on a uuid collision with a live file.
    """
    resolved = Path(root)
    if not isinstance(run_id, str):
        raise CounterPersistenceError(f"invalid run_id: {run_id!r}")
    reject_reserved_run_id(run_id)
    if not isinstance(unit, str) or not unit:
        raise CounterPersistenceError(f"invalid unit: {unit!r}")
    if not _is_nonneg_int(attempt):
        raise CounterPersistenceError(f"invalid attempt: {attempt!r}")
    if not is_role(role):
        raise CounterPersistenceError(f"invalid role: {role!r}")
    if not isinstance(isolation, str) or not isolation:
        raise CounterPersistenceError(f"invalid isolation: {isolation!r}")
    if not is_worker_uuid(worker_uuid):
        raise CounterPersistenceError(f"invalid worker_uuid: {worker_uuid!r}")
    if not _is_nonneg_int(pid):
        raise CounterPersistenceError(f"invalid pid: {pid!r}")
    assert isinstance(attempt, int) and isinstance(pid, int)
    if is_sealed(resolved):
        raise CounterPersistenceError(
            f"counters dir {resolved} is sealed: registration rejected, provider entry blocked"
        )
    ensure_layout(resolved)
    # Birth 0 marks an unverifiable platform (macOS): the registry stays
    # schema-valid while verification degrades to unknown (never signaled).
    birth = birth_token_for_pid(pid)
    content: dict[str, Any] = {
        "worker_uuid": worker_uuid,
        "run_id": run_id,
        "unit": unit,
        "attempt": attempt,
        "pid": pid,
        "role": role,
        "isolation": isolation,
        "timestamp": time.time(),
        "sidecar": str(resolved / f"{worker_uuid}-{mint_filename_nonce()}{SIDECAR_SUFFIX}"),
        "birth_token": birth if birth is not None else 0,
    }
    registry_path = resolved / REGISTRY_DIRNAME / f"{worker_uuid}.json"
    payload = json.dumps(content)
    try:
        fd = os.open(str(registry_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        raise CounterPersistenceError(
            f"registry collision for worker {worker_uuid}: file already exists"
        ) from None
    except OSError as exc:
        raise CounterPersistenceError(f"cannot register worker {worker_uuid}: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
    except OSError as exc:
        try:
            registry_path.unlink()
        except OSError:
            pass
        raise CounterPersistenceError(f"cannot register worker {worker_uuid}: {exc}") from exc
    if is_sealed(resolved):
        # The barrier sealed between our pre-check and our publish: this
        # registration is late, so retract it and block the provider call
        # rather than orphan evidence the barrier already enumerated past.
        try:
            registry_path.unlink()
        except OSError:
            pass
        raise CounterPersistenceError(
            f"counters dir {resolved} sealed during registration: "
            "late registration rejected, provider entry blocked"
        )
    sidecar_path = Path(content["sidecar"])
    journal_path = sidecar_path.with_name(
        sidecar_path.name[: -len(SIDECAR_SUFFIX)] + JOURNAL_SUFFIX
    )
    return Registration(
        worker_uuid=worker_uuid,
        pid=pid,
        run_id=run_id,
        unit=unit,
        attempt=attempt,
        role=role,
        isolation=isolation,
        registry_path=registry_path,
        sidecar_path=sidecar_path,
        journal_path=journal_path,
    )


def _json_loads_evidence(raw: str) -> Any:
    """Decode evidence JSON; decoder-limit nesting reads as torn (#88R4).

    ``json.loads`` raises ``RecursionError`` (not ``ValueError``) past
    the decoder depth limit; every evidence caller treats it exactly
    like undecodable content. Never raises ``RecursionError``.
    """
    try:
        return json.loads(raw)
    except RecursionError as exc:
        raise ValueError(f"JSON exceeds decoder depth: {exc}") from exc


def _parse_registry_content(name: str, raw: str) -> dict[str, Any] | None:
    """Parse registry file content; None unless filename/shape/uuid all check out."""
    if parse_registry_filename(name) is None:
        return None
    try:
        content = _json_loads_evidence(raw)
    except ValueError:
        return None
    if not is_registry_content(content):
        return None
    if content["worker_uuid"] != parse_registry_filename(name):
        return None
    return dict(content)


def read_registry_file(path: Path | str) -> dict[str, Any] | None:
    """Read one registry file; torn/invalid/mismatched reads as absent (None)."""
    resolved = Path(path)
    try:
        raw = resolved.read_text(encoding="utf-8")
    except (OSError, ValueError):
        return None
    return _parse_registry_content(resolved.name, raw)


def read_json_file(path: Path | str) -> Any | None:
    """Read one JSON file; missing/torn reads as absent (None, never raises)."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except (OSError, ValueError):
        return None
    try:
        return _json_loads_evidence(raw)
    except ValueError:
        return None


def _read_json_evidence(path: Path) -> tuple[str, Any | None]:
    """Read a JSON evidence file, classifying the failure (#88R3-F5).

    Returns ``("ok", payload)``, ``("unreadable", None)`` (an I/O fault
    that must never authorize deletion), ``("torn", None)``
    (undecodable or invalid content: provably unusable evidence), or
    ``("gone", None)`` (a mid-pass race deleted the file: nothing to
    decide). Transient faults retry first, so "unreadable" means
    persistently unreadable. Never raises.
    """
    try:
        raw = _read_text_with_retry(path)
    except FileNotFoundError:
        return ("gone", None)
    except OSError:
        return ("unreadable", None)
    except ValueError:
        return ("torn", None)
    try:
        return ("ok", _json_loads_evidence(raw))
    except ValueError:
        return ("torn", None)


def _read_json_evidence_digested(path: Path) -> tuple[str, Any | None, str | None]:
    """Read JSON evidence plus the digest of the exact bytes parsed (#88R13-2).

    Same classification as ``_read_json_evidence``, but the digest binds
    the adjudicated bytes: decisions made from the payload carry it, so
    a later retry proves the file byte-identical (not merely
    re-readable) before acting on the old decision. Gone/unreadable
    yield None (no bytes to bind); torn yields the torn bytes' digest
    (stable debris identity). Never raises.
    """
    try:
        data = _read_bytes_with_retry(path)
    except FileNotFoundError:
        return ("gone", None, None)
    except OSError:
        return ("unreadable", None, None)
    digest = hashlib.sha256(data).hexdigest()
    try:
        return ("ok", _json_loads_evidence(data.decode("utf-8")), digest)
    except ValueError:
        return ("torn", None, digest)


#: OSError errnos worth a bounded retry inside a persistence write.
_TRANSIENT_WRITE_ERRNOS = frozenset({errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR})
#: Extra transient errnos on Windows (AV scanners/indexers briefly hold files).
_WIN32_TRANSIENT_WRITE_ERRNOS = frozenset({errno.EACCES, errno.EPERM})
#: Total write attempts per persistence call (initial + retries); the 1ms
#: backoff costs nothing on the healthy path (no failure, no sleep) and at
#: most ~2ms on a failing one.
_WRITE_RETRY_ATTEMPTS = 3
_WRITE_RETRY_BACKOFF_S = 0.001


def _is_transient_write_error(exc: OSError) -> bool:
    """Whether a failed persistence write is worth retrying (bounded, rare)."""
    if exc.errno in _TRANSIENT_WRITE_ERRNOS:
        return True
    return sys.platform == "win32" and exc.errno in _WIN32_TRANSIENT_WRITE_ERRNOS


def append_journal(path: Path | str, record: dict[str, Any]) -> None:
    """Append one window record to a journal (no fsync by design).

    Unbuffered ``os.open`` (``O_APPEND``) plus an ``os.write`` loop that
    completes short writes, so every byte lands at most once: a failed
    attempt retries only the unwritten remainder, never the whole line
    (a buffered retry could double-append when ``close`` completes a
    failed ``flush`` behind it). Transient open/write errors retry
    boundedly; anything else raises, leaving at most a torn partial prefix
    (benign: unparseable, and the next publish's superset window recovers
    it, flagged as a torn middle). Errors from ``os.close`` after a
    complete write are swallowed, not retried: the bytes already left the
    process (page-cache durable, which is this module's whole scope), so
    retrying would duplicate the window, while raising would make the next
    publish double-count via its superset window.

    Raises:
        CounterPersistenceError: When the record cannot be appended.
    """
    try:
        line = (json.dumps(record) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CounterPersistenceError(f"cannot encode journal record: {exc}") from exc
    remaining = line
    for attempt in range(_WRITE_RETRY_ATTEMPTS):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o666)
        except OSError as exc:
            if attempt + 1 >= _WRITE_RETRY_ATTEMPTS or not _is_transient_write_error(exc):
                raise CounterPersistenceError(f"cannot append journal {path}: {exc}") from exc
            time.sleep(_WRITE_RETRY_BACKOFF_S)
            continue
        try:
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError(errno.EAGAIN, "short write")
                remaining = remaining[written:]
        except OSError as exc:
            try:
                os.close(fd)
            except OSError:
                pass
            if attempt + 1 >= _WRITE_RETRY_ATTEMPTS or not _is_transient_write_error(exc):
                raise CounterPersistenceError(f"cannot append journal {path}: {exc}") from exc
            time.sleep(_WRITE_RETRY_BACKOFF_S)
            continue
        try:
            os.close(fd)
        except OSError:
            pass  # bytes already left the process; close cannot un-land them
        return


def write_sidecar_atomic(path: Path | str, payload: dict[str, Any]) -> None:
    """Write one sidecar atomically (tmp + replace; tmp cleaned on failure).

    A crash lands the old or the new content, never a mix; readers treat a
    torn file as absent. Transient write errors retry boundedly (each attempt
    cleans its tmp first), then raise.

    Raises:
        CounterPersistenceError: When the payload cannot be encoded or written.
    """
    resolved = Path(path)
    try:
        text = json.dumps(payload)
    except (TypeError, ValueError) as exc:
        raise CounterPersistenceError(f"cannot encode sidecar {resolved}: {exc}") from exc
    tmp = resolved.with_name(f"{resolved.name}.tmp-{os.getpid()}-{mint_filename_nonce()}")
    for attempt in range(_WRITE_RETRY_ATTEMPTS):
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
            os.replace(tmp, resolved)
            return
        except OSError as exc:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            if attempt + 1 >= _WRITE_RETRY_ATTEMPTS or not _is_transient_write_error(exc):
                raise CounterPersistenceError(f"cannot write sidecar {resolved}: {exc}") from exc
            time.sleep(_WRITE_RETRY_BACKOFF_S)


def fence_producer(registry: dict[str, Any], *, timeout_s: float = 5.0) -> FenceOutcome:
    """Prove one producer quiescent, signaling only a verified incarnation.

    Dead producers (including recycled pids, whose registered birth is gone)
    need no signal. Only a pid whose live birth matches the registry is ever
    signaled, through an incarnation-pinning handle (pidfd on Linux, process
    handle on Windows); the birth is re-verified immediately before the
    signal closes the TOCTOU window. Unverifiable producers (unknown
    platform, unreadable birth) report ``unresolved`` with a warning and are
    never signaled; resume must skip their conflicting reruns.
    """
    verdict = verify_producer(registry)
    if verdict == "dead":
        return "fenced"
    pid = registry.get("pid")
    claimed = registry.get("birth_token")
    if verdict == "unknown" or not _is_nonneg_int(pid) or not is_birth_token(claimed):
        warnings.warn(
            f"counter producer {registry.get('worker_uuid', '?')} (pid {pid}): "
            "incarnation unverifiable, left unresolved (reruns unrelated to it may proceed; "
            "its own unit must be skipped, never assumed quiescent)",
            UserWarning,
            stacklevel=2,
        )
        return "unresolved"
    assert isinstance(pid, int) and isinstance(claimed, int)
    current = birth_token_for_pid(pid)
    if current is None:
        warnings.warn(
            f"counter producer {registry.get('worker_uuid', '?')} (pid {pid}): "
            "birth became unreadable before fencing, left unresolved",
            UserWarning,
            stacklevel=2,
        )
        return "unresolved"
    if current != claimed:
        return "fenced"
    if _terminate_verified(pid, claimed, timeout_s):
        return "fenced"
    warnings.warn(
        f"counter producer {registry.get('worker_uuid', '?')} (pid {pid}): "
        "verified signal sent but termination unproven, left unresolved",
        UserWarning,
        stacklevel=2,
    )
    return "unresolved"


def _terminate_verified(pid: int, birth: int, timeout_s: float) -> bool:
    """Signal a birth-verified pid through a pinning handle; poll to prove death.

    Single signaling seam (tests spy on this to prove no-signal paths).
    Returns True when termination is proven (or the pid died first); False
    when unproven or the platform cannot pin (never signals there).
    """
    if sys.platform.startswith("linux"):
        return _terminate_pidfd(pid, birth, timeout_s)
    if sys.platform == "win32":
        return _terminate_handle(pid, birth, timeout_s)
    return False


def _pidfd_exited(fd: int, timeout_s: float) -> bool:
    """Whether a pidfd reports its pinned process exited in time (#88R3).

    Exit readiness (POLLIN) on the pinned fd proves the process
    exited (zombies included: they hold no writers, so they are
    quiescent). No /proc consult, so permission faults can never
    masquerade as death. Only POLLIN counts: hangup/error/invalid
    masks and any poll failure or unmet wait read unresolved (False).
    """
    try:
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        events = poller.poll(max(int(timeout_s * 1000), 0))
    except (OSError, ValueError):
        return False
    for _, mask in events:
        if mask & (select.POLLNVAL | select.POLLERR):
            return False
        if mask & (select.POLLIN | select.POLLHUP):
            return True
    return False


def _incarnation_alive(pid: int, birth: int | None) -> bool:
    """Whether a stamped writer incarnation is provably still running (#88R10-1).

    Detection only (never signals): on pidfd platforms the fd pins the
    occupant and exit readiness covers zombies (a zombie holds no
    writer, so it reads dead); elsewhere a stated birth must match the
    live one (a mismatch proves recycle, hence death). Anything
    unprovable (unreadable birth, missing pidfd, faulted lookup)
    reads alive: only proven death proceeds past a covered suppress.
    """
    open_pidfd = getattr(os, "pidfd_open", None)
    if open_pidfd is not None:
        try:
            fd = open_pidfd(pid, 0)
        except ProcessLookupError:
            return False
        except OSError:
            return True
        try:
            if birth is not None:
                current = birth_token_for_pid(pid)
                if current is None:
                    return True
                if current != birth:
                    return False
            return not _pidfd_exited(fd, 0)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
    if birth is not None:
        current = birth_token_for_pid(pid)
        if current is None:
            return True
        if current != birth:
            return False
    return _pid_exists(pid)


def _terminate_pidfd(pid: int, birth: int, timeout_s: float) -> bool:
    """SIGKILL through a pidfd (pins the incarnation) and wait for exit.

    The birth is re-read after the open: the fd pins the open-time
    occupant, so a starttime mismatch proves the claimed incarnation died
    and the pid was recycled between verification and open (close, no
    signal, fenced). Only a lookup failure proves death at the excepts;
    permission/syscall failures are unresolved, never assumed quiescent.
    The post-signal wait polls the pidfd itself for exit readiness
    (never /proc, whose faults must not masquerade as death).

    Tick-granularity residual: starttime ticks in jiffies, so two
    incarnations forked within one tick of the same pid slot share a
    birth token. A recycle inside that window still matches and would be
    signaled through the (wrong-incarnation) fd. The window is one tick
    wide and requires the claimed producer to die first; narrowing it
    further needs fd-pinned identity the stdlib does not expose.
    """
    try:
        fd = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    try:
        current = _linux_starttime(pid)
        if current is None:
            # Unreadable birth: identity unprovable, so no signal may
            # fire even though the likeliest cause is a death mid-fence.
            return False
        if current != birth:
            return True
        try:
            signal.pidfd_send_signal(fd, signal.SIGKILL)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        return _pidfd_exited(fd, timeout_s)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _terminate_handle(pid: int, birth: int, timeout_s: float) -> bool:
    """TerminateProcess through an open handle (pins the incarnation) and wait.

    Mirrors the pidfd narrowing: only a lookup failure (OpenProcess
    reporting no-such-pid) or a birth mismatch proves the target gone;
    every other failure (access-denied open, unreadable times, refused
    terminate, unmet wait) is unresolved, never assumed quiescent.
    """
    kernel32 = _kernel32()
    handle = kernel32.OpenProcess(
        _PROCESS_TERMINATE | _PROCESS_QUERY_LIMITED_INFORMATION | _SYNCHRONIZE, False, pid
    )
    if not handle:
        return bool(kernel32.GetLastError() == _ERROR_INVALID_PARAMETER)
    try:
        creation = _process_creation_time(kernel32, handle)
        if creation is None:
            return False
        if creation != birth:
            return True
        if not kernel32.TerminateProcess(handle, 1):
            return False
        wait_ms = max(int(timeout_s * 1000), 0)
        return bool(kernel32.WaitForSingleObject(handle, wait_ms) == _WAIT_OBJECT_0)
    finally:
        kernel32.CloseHandle(handle)


def validate_probe_receipt(receipt: Any, expected_seq: int) -> tuple[str, int] | None:
    """Validate a probe coverage receipt against the parent-assigned seqno.

    Returns the ``(worker_uuid, probe_seq)`` key on an exact match, else
    None (missing keys, malformed uuid/seq, or a seq that is not the one
    this parent assigned to this launch — never guessed, never coerced).
    """
    if not isinstance(receipt, dict):
        return None
    if not is_receipt(receipt):
        return None
    uuid = receipt["worker_uuid"]
    seq = receipt["probe_seq"]
    assert isinstance(uuid, str) and isinstance(seq, int)
    if seq != expected_seq:
        return None
    return (uuid, seq)


def end_state_for_attempt(*, status: str, returncode: int | None, timed_out: bool = False) -> str:
    """Map a unit attempt outcome onto the loss ``end_state`` enum.

    Timeouts (flag or status) read ``timeout``; negative return codes read
    ``killed`` for SIGKILL/SIGTERM (outer kills) and ``crashed`` for other
    fatal signals; a ``crashed`` status with a non-negative code is the
    abrupt-exit shape (also ``crashed``); anything else without counter
    evidence reads ``unknown``.
    """
    if timed_out or status == "timeout":
        return "timeout"
    if returncode is not None and returncode < 0 and status != "timeout":
        if -returncode in _KILL_SIGNALS:
            return "killed"
        return "crashed"
    if status == "crashed":
        return "crashed"
    return "unknown"


def _read_jsonl_lines(path: Path) -> list[bytes] | None:
    """Read one JSONL file as raw lines; None when unreadable (never raises)."""
    try:
        with path.open("rb") as fh:
            return fh.read().split(b"\n")
    except OSError:
        return None


def _iter_jsonl_line_records(lines: Iterable[bytes]) -> Iterator[dict[str, Any]]:
    """Yield parsed dict records from raw JSONL lines (bad lines skipped).

    Parses through the shared ``report_log`` line parser (never a local
    reimplementation): collection and extraction agree on record
    existence by construction, since a framing or decoding split
    between them silently breaks reconciliation (codex R3/R4).
    """
    for raw in lines:
        record = parse_report_log_line(raw)
        if record is not None:
            yield record


def _committed_from_jsonl(
    path: Path | str | None,
) -> tuple[set[tuple[str, str]], set[tuple[str, str]], set[tuple[str, str]]] | None:
    """Return ``(sessions, entries, lenient sessions)``, runs included.

    Sessions are authoritative for their whole producer; entries are
    authoritative per test window. Used to compute the sidecar gap (full
    entry supersedes same-(uuid, test) partial) and delete-after-commit.
    Returns None when the file exists but cannot be read (fail-closed:
    the caller degrades instead of reasoning from an empty snapshot).
    Session sets key on ``(run, uuid)`` exactly like the extractor's
    authority staging (absent run reads ``""``, malformed run skips the
    record): uuid-only matching would let a cross-round session divert
    a foreign checkpoint into the committed path and delete its gap
    (codex R5).

    Authority equals extractor acceptance: sessions gate on
    ``is_session_record`` and entries on the extractor's own first-match
    ``user_property`` gated by ``is_test_entry`` (``_parse_*`` reuse would
    cycle through ``call_counters``). Every gate-admitted record is one
    the extractor folds (identical pid/total/counters/uuid/role/round
    checks); the gate is only stricter (unknown keys, non-string
    isolation, partly-malformed receipts). That denied direction is
    benign for path choice and deletion (files retained; re-collection
    folds exactly once under the authoritative ``(run, uuid)`` staging
    key, which supersedes the gap partial), and writer-unreachable for
    entries (fixed keys, valid receipts, string isolation) -- but it is
    NOT benign for orphan healing (a gap-path heal would pierce the
    supersede the extractor applies), so healing consults the lenient
    set instead: any session-shaped record with a valid uuid, whatever
    the strict schema says. Overshoot there only ever yields
    spurious-incomplete, never silent-complete.
    """
    sessions: set[tuple[str, str]] = set()
    entries: set[tuple[str, str]] = set()
    lenient: set[tuple[str, str]] = set()
    if path is None:
        return sessions, entries, lenient
    lines = _read_jsonl_lines(Path(path))
    if lines is None:
        return None
    for record in _iter_jsonl_line_records(lines):
        report_type = record.get("$report_type", "TestReport")
        if report_type == SESSION_REPORT_TYPE:
            uuid = record.get("worker_uuid")
            # Mirror _parse_round exactly (a _parse_* import would cycle):
            # absent run reads implicit, malformed run stages nothing.
            run = record.get("run_id", "")
            run_ok = isinstance(run, str) and (bool(run) or "run_id" not in record)
            if is_worker_uuid(uuid) and run_ok:
                assert isinstance(uuid, str) and isinstance(run, str)
                lenient.add((run, uuid))
            if not is_session_record(record):
                continue
            if is_worker_uuid(uuid):
                assert isinstance(uuid, str) and isinstance(run, str)
                sessions.add((run, uuid))
        elif report_type == "TestReport":
            nodeid = record.get("nodeid")
            if not isinstance(nodeid, str) or not nodeid:
                continue
            if not isinstance(record.get("user_properties"), (list, tuple)):
                continue
            entry = user_property(record, TEST_ENTRY_PROPERTY)
            if not is_test_entry(entry):
                continue
            uuid = entry.get("worker_uuid")
            if is_worker_uuid(uuid):
                assert isinstance(uuid, str)
                entries.add((uuid, nodeid))
    return sessions, entries, lenient


def _claimed_receipts_from_jsonl(
    path: Path | str | None,
) -> dict[str, set[tuple[str, int]]] | None:
    """Return per-producer folded-probe claims ``{uuid: {(uuid, seq)}}`` from JSONL.

    Claims ride C4-valid sessions and valid per-test entries (first-match
    ``user_property``, mirroring :func:`_committed_from_jsonl`); uuid-less
    records claim nothing (unattributable). The orphan collector unions
    these with the producer's durable file receipts: either holder proves
    the probe evidence durable, so the orphan suppresses instead of
    folding twice. Returns None when the file exists but cannot be read
    (the caller degrades instead of suppressing nothing). Claims stay
    global across runs deliberately (receipt identities are unique per
    probe child; per-round scoping would break cross-round dedup the
    resume track relies on) -- see the review report for the full
    tradeoff.
    """
    claims: dict[str, set[tuple[str, int]]] = {}
    if path is None:
        return claims
    lines = _read_jsonl_lines(Path(path))
    if lines is None:
        return None
    for record in _iter_jsonl_line_records(lines):
        report_type = record.get("$report_type", "TestReport")
        if report_type == SESSION_REPORT_TYPE:
            if not is_session_record(record):
                continue
            uuid = record.get("worker_uuid")
            if not is_worker_uuid(uuid):
                continue
            assert isinstance(uuid, str)
            keys = _receipt_keys(record.get("receipts"))
        elif report_type == "TestReport":
            nodeid = record.get("nodeid")
            if not isinstance(nodeid, str) or not nodeid:
                continue
            if not isinstance(record.get("user_properties"), (list, tuple)):
                continue
            entry = user_property(record, TEST_ENTRY_PROPERTY)
            if not is_test_entry(entry):
                continue
            uuid = entry.get("worker_uuid")
            if not is_worker_uuid(uuid):
                continue
            assert isinstance(uuid, str)
            # Entry receipts and entry consumed proofs both claim
            # before orphan adoption: a teardown entry that survives
            # a failed journal publish still suppresses the retained
            # orphan (codex RC4-R3). Suppression-only: claims never
            # earn extractor rows.
            keys = _receipt_keys(entry.get("receipts")) | _receipt_keys(
                entry.get("consumed_probes")
            )
        else:
            continue
        if keys:
            claims.setdefault(uuid, set()).update(keys)
    return claims


def _known_producer_uuids(root: Path) -> set[str]:
    """Return every producer uuid visible in the counters dir (content-authoritative)."""
    uuids: set[str] = set()
    reg_dir = root / REGISTRY_DIRNAME
    if reg_dir.is_dir():
        for registry_path in reg_dir.glob("*.json"):
            content = read_registry_file(registry_path)
            if content is not None:
                uuids.add(content["worker_uuid"])
    for sidecar_path in root.glob(f"*{SIDECAR_SUFFIX}"):
        sidecar = read_json_file(sidecar_path)
        if isinstance(sidecar, dict) and is_worker_uuid(sidecar.get("worker_uuid")):
            uuids.add(sidecar["worker_uuid"])
    return uuids


def _valid_receipts(value: Any) -> list[dict[str, Any]]:
    """Return the well-formed receipts from a sidecar/journal receipts list."""
    if not isinstance(value, list):
        return []
    return [
        {"worker_uuid": entry["worker_uuid"], "probe_seq": entry["probe_seq"]}
        for entry in value
        if is_receipt(entry)
    ]


def _receipt_keys(value: Any) -> set[tuple[str, int]]:
    """Return the well-formed receipt keys from a receipts list."""
    return {(entry["worker_uuid"], entry["probe_seq"]) for entry in _valid_receipts(value)}


def _parse_probe_filename(name: str) -> tuple[str, int] | None:
    """Return ``(parent prefix, seq)`` bound by a probe sidecar filename, else None."""
    if not name.startswith(PROBE_FILE_PREFIX) or not name.endswith(PROBE_FILE_SUFFIX):
        return None
    stem = name[len(PROBE_FILE_PREFIX) : -len(PROBE_FILE_SUFFIX)]
    parts = stem.split("-")
    if len(parts) != 3:
        return None
    parent8, seq, nonce = parts
    if len(parent8) != 8 or any(char not in "0123456789abcdef" for char in parent8):
        return None
    if not nonce or not seq.isascii() or not seq.isdigit():
        return None
    return (parent8, int(seq))


def _parse_consumed_probe_filename(name: str) -> tuple[str, int] | None:
    """Return ``(owner claim, seq)`` bound by a consumed-marker name, else None.

    The owner claim is the full 32-hex parent uuid for new markers
    (#88R5-4: routable by owner even when unreadable) or the legacy
    8-hex parent prefix.
    """
    if not name.startswith(PROBE_CONSUMED_PREFIX) or not name.endswith(PROBE_FILE_SUFFIX):
        return None
    stem = name[len(PROBE_CONSUMED_PREFIX) : -len(PROBE_FILE_SUFFIX)]
    parts = stem.split("-")
    if len(parts) != 3:
        return None
    owner, seq, nonce = parts
    if len(owner) not in (8, 32) or any(char not in "0123456789abcdef" for char in owner):
        return None
    if not nonce or not seq.isascii() or not seq.isdigit():
        return None
    return (owner, int(seq))


#: F2 identity fields in wire order (single source; both the exit flush
#: and the mid-run record-path trigger build through here).
_PROBE_IDENTITY_WIRE_ORDER = (
    "parent_uuid",
    "run_id",
    "unit",
    "role",
    "isolation",
    "attempt",
)


def probe_sidecar_identity_from_env(env: Any) -> dict[str, Any]:
    """Read the F2 parent-identity block from a probe child's environment.

    Each field is present only when set and well-typed (non-empty strings;
    ``attempt`` must int-parse, negatives included -- the reader drops
    out-of-range values). Never raises.
    """
    identity: dict[str, Any] = {}
    try:
        for env_key, field in (
            (PROBE_PARENT_ENV, "parent_uuid"),
            (PROBE_RUN_ENV, "run_id"),
            (PROBE_UNIT_ENV, "unit"),
            (PROBE_ROLE_ENV, "role"),
            (PROBE_ISOLATION_ENV, "isolation"),
        ):
            value = env.get(env_key)
            if value:
                identity[field] = value
        attempt_raw = env.get(PROBE_ATTEMPT_ENV)
        if attempt_raw:
            try:
                identity["attempt"] = int(attempt_raw)
            except (TypeError, ValueError):
                pass
    except (AttributeError, TypeError):
        pass
    return identity


def write_probe_sidecar(
    path: Path | str,
    *,
    worker_uuid: str,
    probe_seq: int,
    counters: list[Any],
    lost_keys: list[dict[str, Any]] | None = None,
    identity: dict[str, Any] | None = None,
    finalized: bool = True,
    probes_lost: int = 0,
    pid: int | None = None,
    birth: int | None = None,
) -> None:
    """Write one probe sidecar atomically (single attempt, tmp + replace).

    The single writer behind the exit flush and the mid-run record-path
    trigger: worker/seq/counters, then ``lost_keys`` when non-empty,
    then ``probes_lost`` when nonzero (the child's cumulative total,
    keyed + unkeyed, so a finalized heal cannot drop a loss that
    exists nowhere),
    then the F2 identity block in wire order. Mid-run snapshots add
    ``"finalized": false`` (fold but never heal: the tail they never
    saw stays a named loss); finalized snapshots omit the key, so the
    exit shape stays byte-identical to legacy. A crash lands the old
    or the new content, never a mix. ``pid``/``birth_token`` bind the
    slot to the writer incarnation when given (#88R3: quiescence);
    omitted entirely when None, so legacy shapes stay byte-identical.

    Raises:
        OSError: When the file cannot be written.
        TypeError: When the payload cannot be encoded.
        ValueError: When the payload cannot be encoded.
    """
    payload: dict[str, Any] = {
        "worker_uuid": worker_uuid,
        "probe_seq": probe_seq,
        "counters": counters,
    }
    if lost_keys:
        payload["lost_keys"] = lost_keys
    if probes_lost:
        payload["probes_lost"] = probes_lost
    if pid is not None:
        payload["pid"] = pid
    if birth is not None:
        payload["birth_token"] = birth
    for field in _PROBE_IDENTITY_WIRE_ORDER:
        if identity and field in identity:
            payload[field] = identity[field]
    if not finalized:
        payload["finalized"] = False
    tmp = f"{path}.tmp-{os.getpid()}"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
            fh.flush()
        os.replace(tmp, path)
    except (OSError, TypeError, ValueError):
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def mark_probe_consumed(sidecar: Path | str, *, parent_uuid: str | None = None) -> Path:
    """Rename a committed probe sidecar to its consumed marker (atomic).

    Used when the sidecar delete fails after the parent checkpoint
    flushed: the parent already holds the counts, and the marker tells
    orphan adoption to suppress instead of folding them again. Same
    directory, same content, ``probe-consumed-`` prefix. The marker
    carries the full parent uuid -- the caller's ``parent_uuid`` when
    given (the absorbing checkpoint's owner; infallible and immune to
    stamp-read faults, #88R6-2c), else the sidecar's stamped
    ``parent_uuid`` (#88R5-4: routable by owner even when unreadable),
    else the legacy 8-hex filename prefix.

    Raises:
        CounterPersistenceError: When the name is foreign (unparseable),
            when ``parent_uuid`` contradicts a stamped sidecar parent
            (naming one producer with another's body would strand the
            marker unclaimable), or when the rename fails. All are loud:
            proceeding would risk a silent double-fold.
    """
    path = Path(sidecar)
    parsed = _parse_probe_filename(path.name)
    if parsed is None:
        raise CounterPersistenceError(f"cannot mark foreign probe sidecar consumed: {path}")
    stem = path.name[len(PROBE_FILE_PREFIX) : -len(PROBE_FILE_SUFFIX)]
    _, seq, nonce = stem.split("-")
    owner = parsed[0]
    if is_worker_uuid(parent_uuid):
        assert isinstance(parent_uuid, str)
        content = read_json_file(path)
        if isinstance(content, dict):
            stamped = content.get("parent_uuid")
            if is_worker_uuid(stamped) and stamped != parent_uuid:
                raise CounterPersistenceError(
                    f"marker parent {parent_uuid} contradicts sidecar stamp {stamped}: {path}"
                )
        owner = parent_uuid
    else:
        content = read_json_file(path)
        if isinstance(content, dict):
            parent = content.get("parent_uuid")
            if is_worker_uuid(parent):
                assert isinstance(parent, str)
                owner = parent
    marked = path.with_name(f"{PROBE_CONSUMED_PREFIX}{owner}-{seq}-{nonce}{PROBE_FILE_SUFFIX}")
    try:
        os.replace(path, marked)
    except OSError as exc:
        raise CounterPersistenceError(f"cannot mark probe sidecar consumed: {exc}") from exc
    return marked


def _parse_probe_orphan_payload(
    data: Any,
) -> (
    tuple[
        str,
        int,
        list[Any],
        frozenset[tuple[str, int]],
        dict[str, Any],
        bool,
        int,
        bool,
        int | None,
        int | None,
    ]
    | None
):
    """Parse one decoded probe sidecar/marker payload (#88R5).

    Returns ``(child_uuid, seq, counters, keys, identity, finalized,
    adopted, vacuous_ok)`` plus the trailing writer incarnation
    ``(pid, birth_token)`` (#88R3, each None unless well-typed):
    quiescence binds the slot to a dead or recycled writer, never a
    live one. Pure: callers own the (single, retrying) read, so a
    transient fault heals inside that read and the healed payload is
    parsed -- never discarded (#88R5-1).

    ``identity`` is the F2 self-describing block (parent_uuid/run_id/unit/
    attempt/role/isolation, each present only when well-typed); legacy
    sidecars yield ``{}``. ``finalized`` is False for explicit
    mid-run snapshots (absent or explicit ``true`` reads finalized:
    legacy and exit writes; any other present value reads
    non-finalized, failing closed toward a named loss). ``adopted`` is
    the unkeyed remainder this orphan contributes: a valid scalar is
    the child's TOTAL (keyed + unkeyed), so adoption forwards the
    remainder over the surviving valid keys; without a usable total
    (absent, zero, or malformed scalar) each malformed item floors one
    unkeyed loss on its own and valid keys are never subtracted (they
    were never inside any total). ``vacuous_ok`` is True only beside
    an absent-or-zero scalar with clean keys (a malformed scalar is
    unknown, never zero-evidence). Counts still fold in every case.
    Returns None unless the core shape parses.
    """
    if not isinstance(data, dict):
        return None
    uuid = data.get("worker_uuid")
    seq = data.get("probe_seq")
    counters = data.get("counters")
    if not is_worker_uuid(uuid):
        return None
    if not _is_nonneg_int(seq):
        return None
    if not isinstance(counters, (list, tuple)):
        return None
    assert isinstance(uuid, str) and isinstance(seq, int)
    raw_keys = data.get("lost_keys", ())
    keys: set[tuple[str, int]] = set()
    # Malformed key items degrade to unkeyed losses instead of
    # vanishing: each proves a loss occurred without naming it, which
    # is exactly what the unkeyed remainder means. A non-list field
    # counts one corrupt blob; explicit null reads absent (matches the
    # ingest parser's tolerance). Without this, malformed keys would
    # drop silently AND read vacuous (codex R5).
    malformed_keys = 0
    if raw_keys is None:
        pass
    elif isinstance(raw_keys, (list, tuple)):
        for entry in raw_keys:
            if is_lost_key(entry):
                keys.add((entry["parent_uuid"], entry["probe_seq"]))
            else:
                malformed_keys += 1
    else:
        malformed_keys = 1
    identity: dict[str, Any] = {}
    parent = data.get("parent_uuid")
    if is_worker_uuid(parent):
        identity["parent_uuid"] = parent
    for field in ("run_id", "unit", "role", "isolation"):
        value = data.get(field)
        if isinstance(value, str) and value:
            identity[field] = value
    attempt = data.get("attempt")
    if _is_nonneg_int(attempt):
        # Parsed for evidence completeness; the reunion matches run/unit
        # only (an exact parent_uuid implies the registration and hence
        # the attempt, so matching it would be vacuous).
        identity["attempt"] = attempt
    finalized = data.get("finalized", True) is True
    # The remainder is computed here (the reader holds every fact: the
    # fold cannot tell a total from a floor). A positive total
    # provably counted something -- in-memory keys are always
    # valid-shaped when counted, so malformed items were inside it and
    # the remainder already carries them. A zero total counted
    # nothing, so malformed items beside it bump loud rather than
    # trust the zero (codex R7-F3).
    if "probes_lost" not in data:
        adopted = malformed_keys
        vacuous_ok = malformed_keys == 0
    elif _is_nonneg_int(data["probes_lost"]):
        assert isinstance(data["probes_lost"], int)
        total = data["probes_lost"]
        adopted = max(0, total - len(keys)) + (malformed_keys if total == 0 else 0)
        vacuous_ok = total == 0 and malformed_keys == 0
    elif malformed_keys:
        adopted = malformed_keys
        vacuous_ok = False
    else:
        adopted = 0
        vacuous_ok = False
    pid = data.get("pid")
    birth = data.get("birth_token")
    return (
        uuid,
        seq,
        list(counters),
        frozenset(keys),
        identity,
        finalized,
        adopted,
        vacuous_ok,
        pid if _is_nonneg_int(pid) else None,
        birth if is_birth_token(birth) else None,
    )


def _read_probe_orphan(
    path: Path,
) -> (
    tuple[
        str,
        int,
        list[Any],
        frozenset[tuple[str, int]],
        dict[str, Any],
        bool,
        int,
        bool,
        int | None,
        int | None,
    ]
    | None
):
    """Read + parse one probe sidecar/marker (single non-retrying read).

    Thin wrapper for non-collection callers; the collection loops read
    once with retry via ``_read_json_evidence`` and parse the payload
    directly, so a healed transient is never discarded (#88R5-1).
    """
    return _parse_probe_orphan_payload(read_json_file(path))


def _rows_exit_total(rows: list[Any]) -> int:
    """Sum returned-call counts over flat probe rows (garbage skipped).

    Replay adopts exits on a superset rule only, so a changed total
    proves adoption exactly (order/format rebuilds never move it).
    """
    total = 0
    for row in rows:
        parsed = _parse_probe_flat_row(row)
        if parsed is not None and parsed[2] is not None:
            total += parsed[3]
    return total


def _parse_probe_flat_row(row: Any) -> tuple[str, str, int | None, int] | None:
    """Validate one flat counter row (mirrors the live ingest parser)."""
    if not isinstance(row, (list, tuple)):
        return None
    if len(row) == 3:
        module: Any = UNKNOWN_MODULE
        fn, rv, count = row[0], row[1], row[2]
    elif len(row) == 4:
        module, fn, rv, count = row[0], row[1], row[2], row[3]
    else:
        return None
    if not isinstance(module, str):
        return None
    if not isinstance(fn, str) or not fn:
        return None
    if rv is not None and (not isinstance(rv, int) or isinstance(rv, bool) or rv < 0):
        return None
    if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
        return None
    return (module, fn, rv, count)


def _probe_rows_to_block(rows: list[Any]) -> dict[str, Any] | None:
    """Render flat probe rows as a module-first block under ``test``, else None.

    Recovery attribution: the parent's active bucket at ingest time is
    unknowable post-hoc, and probes launch from test bodies, so orphan
    traffic folds under ``test`` (provisioning-spawned orphans recover
    here too: the live bucket is unknowable post-hoc). Row validation
    mirrors the live ingest parser (garbage rows skipped, never fatal);
    None when no row parses.
    """
    from pkcs11_check.raw.rv import ckr_name

    entries: dict[tuple[str, str], int] = {}
    exits: dict[tuple[str, str, int], int] = {}
    for row in rows:
        parsed = _parse_probe_flat_row(row)
        if parsed is None:
            continue
        module, fn, rv, count = parsed
        entries[(module, fn)] = entries.get((module, fn), 0) + count
        if rv is not None:
            exits[(module, fn, rv)] = exits.get((module, fn, rv), 0) + count
    if not entries:
        return None
    modules: dict[str, dict[str, Any]] = {}
    for (module, fn), calls in entries.items():
        bucket = modules.setdefault(module, {"test": {"calls": 0, "by_fn": {}}})["test"]
        bucket["calls"] += calls
        target = bucket["by_fn"].setdefault(fn, {"calls": 0, "by_rv": {}})
        target["calls"] += calls
    for (module, fn, rv), count in exits.items():
        by_rv: dict[str, Any] = modules[module]["test"]["by_fn"][fn]["by_rv"]
        leaf = by_rv.get(str(rv))
        if leaf is None:
            by_rv[str(rv)] = {"name": ckr_name(rv), "count": count}
        else:
            leaf["count"] += count
    uniform = {module: ensure_five_buckets(buckets) for module, buckets in modules.items()}
    block = wrap_module_first(uniform)
    assert is_module_first_block(block)
    return block


def _durable_receipts(sidecar: Any | None, journal_lines: list[str]) -> set[tuple[str, int]]:
    """Return every receipt key in a sidecar plus ALL its journal windows.

    Committed windows count too: their receipts live on in the JSONL
    entries that superseded them, so either holder proves the evidence
    durable and a covered orphan must suppress rather than fold twice.
    Sidecar ``consumed_probes`` (fallback absorptions pending delete)
    join the same set: absorbed counts already sit in the checkpoint,
    so a retained orphan with a consumed key suppresses too (codex
    RC4-R1-2). Journal windows carry the same key for the same reason:
    a death between the window append and the boundary sidecar
    replacement strands journal-first counts that must still suppress
    (codex RC4-R2). Malformed entries never parse, here or anywhere.
    """
    keys: set[tuple[str, int]] = set()
    if isinstance(sidecar, dict):
        keys.update(_receipt_keys(sidecar.get("receipts")))
        keys.update(_receipt_keys(sidecar.get("consumed_probes")))
    for line in journal_lines:
        try:
            window = _json_loads_evidence(line)
        except ValueError:
            continue
        if isinstance(window, dict):
            keys.update(_receipt_keys(window.get("receipts")))
            keys.update(_receipt_keys(window.get("consumed_probes")))
    return keys


def _probe_rows_groups(rows: list[Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """Group flat rows per (module, fn) into entries + per-RV exits (#88R8-1).

    Garbage rows are skipped, mirroring the merge. Shared by the
    returns merge and the marker-coverage subset check so both agree
    on what a row set proves.
    """
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        parsed = _parse_probe_flat_row(row)
        if parsed is None:
            continue
        module, fn, rv, count = parsed
        group = groups.setdefault((module, fn), {"entries": 0, "exits": {}})
        group["entries"] += count
        if rv is not None:
            group["exits"][rv] = group["exits"].get(rv, 0) + count
    return groups


def _snapshots_equal(first: Any, second: Any) -> bool:
    """Type-sensitive deep equality for evidence snapshots (#88R9-1b).

    Plain ``==`` is blind to bool/int swaps (``True == 1``) that flip
    a row from garbage to valid across a fence race. Iterative (never
    recurses no matter how deep a hostile payload nests); NaN compares
    stable so identical payloads never read as changed.
    """
    stack: list[tuple[Any, Any]] = [(first, second)]
    while stack:
        left, right = stack.pop()
        if left is right:
            continue
        if type(left) is not type(right):
            return False
        if isinstance(left, dict):
            if left.keys() != right.keys():
                return False
            stack.extend((left[key], right[key]) for key in left)
        elif isinstance(left, (list, tuple)):
            if len(left) != len(right):
                return False
            stack.extend(zip(left, right))
        elif isinstance(left, float) and left != left and right != right:
            continue
        elif left != right:
            return False
    return True


def _snapshot_covered_by(
    orphan_rows: list[Any],
    orphan_keys: frozenset[tuple[str, int]],
    orphan_adopted: int,
    marker_rows: list[Any],
    marker_keys: frozenset[tuple[str, int]],
    marker_adopted: int,
) -> bool:
    """Whether a marker snapshot covers an orphan's rows and losses (#88R8-1).

    Rows compare per (module, fn) key (entries and every exit count
    inside the marker's); loss keys subset and the unkeyed remainder
    must not exceed the marker's -- a newer rewrite, a new loss key,
    or a larger unkeyed remainder fails the subset and defers instead
    of dropping or doubling (#88R9-2).
    """
    own = _probe_rows_groups(orphan_rows)
    covered = _probe_rows_groups(marker_rows)
    for key, group in own.items():
        other = covered.get(key)
        if other is None:
            return False
        if group["entries"] > other["entries"]:
            return False
        for rv, count in group["exits"].items():
            if other["exits"].get(rv, 0) < count:
                return False
    if not orphan_keys <= marker_keys:
        return False
    return orphan_adopted <= marker_adopted


def _merge_probe_tmp_rows(own: list[Any], tmp: list[Any]) -> list[list[Any]]:
    """Merge a same-probe rewrite tmp's returns into orphan rows (#88).

    Keyed returns-only merge per (module, fn): a key replays only on
    an exact entry-population match whose tmp exits contain the
    orphan's per RV (#88R3 -- returns are unattributable across
    differing populations or divergent RV sets, so both keep the
    orphan's rows and stay named in-flight downstream). Tmp entry
    rows (rv None) never transfer: a tmp holding newer entries is an
    uncommitted admission snapshot. Keys present only in the tmp are
    skipped (their entries are unproved). Garbage rows on either side
    are skipped, never fatal.
    """
    own_groups = _probe_rows_groups(own)
    tmp_groups = _probe_rows_groups(tmp)
    merged: list[list[Any]] = []
    for (module, fn), group in own_groups.items():
        exits: dict[int, int] = dict(group["exits"])
        tmp_group = tmp_groups.get((module, fn))
        if tmp_group is not None and tmp_group["entries"] == group["entries"]:
            if all(tmp_group["exits"].get(rv, 0) >= count for rv, count in group["exits"].items()):
                exits = dict(tmp_group["exits"])
        for rv in sorted(exits):
            merged.append([module, fn, rv, exits[rv]])
        unreturned = group["entries"] - sum(exits.values())
        if unreturned > 0:
            merged.append([module, fn, None, unreturned])
    merged.sort(key=lambda item: (item[0], item[1], item[2] is None, item[2] or 0))
    return merged


def _int_stamp_clash(mine: Any, theirs: Any) -> bool:
    """Whether two stated int stamps contradict (bools never match)."""
    if mine is None or theirs is None:
        return False
    return type(mine) is not int or type(theirs) is not int or mine != theirs


def _str_stamp_clash(mine: Any, theirs: Any) -> bool:
    """Whether two stated string stamps contradict."""
    if mine is None or theirs is None:
        return False
    return not isinstance(mine, str) or not isinstance(theirs, str) or mine != theirs


def _tmp_stamp_clash(
    payload: dict[str, Any],
    identity: dict[str, Any],
    producer_run: str | None,
    producer_unit: str | None,
    orphan_pid: int | None = None,
    orphan_birth: int | None = None,
    producer_uuid: str | None = None,
) -> bool:
    """Whether a probe tmp's stamps contradict its orphan or producer (#88R3).

    Each F2 stamp (parent, run, unit, attempt) disqualifies only on an
    explicit contradiction with the orphan's -- a side that does not
    state a stamp cannot contradict on it (legacy orphans state
    nothing). The producer's identity (uuid, run, unit) additionally
    disqualifies a tmp that contradicts the collecting pass, so a
    legacy orphan cannot launder a cross-producer tmp past the reunion
    checks. The writer incarnation (pid, birth) disqualifies on
    contradiction the same way: a tmp from another incarnation never
    replays. Integer stamps compare type-strictly (a JSON ``true``
    never equals sequence ``1``).
    """
    for key in ("parent_uuid", "run_id", "unit"):
        if _str_stamp_clash(payload.get(key), identity.get(key)):
            return True
    if _int_stamp_clash(payload.get("attempt"), identity.get("attempt")):
        return True
    if _str_stamp_clash(payload.get("run_id"), producer_run):
        return True
    if _str_stamp_clash(payload.get("unit"), producer_unit):
        return True
    if _str_stamp_clash(payload.get("parent_uuid"), producer_uuid):
        return True
    tmp_pid = payload.get("pid")
    if orphan_pid is not None and tmp_pid is not None:
        if type(tmp_pid) is not int or tmp_pid != orphan_pid:
            return True
    tmp_birth = payload.get("birth_token")
    if orphan_birth is not None and tmp_birth is not None:
        if type(tmp_birth) is not int or tmp_birth != orphan_birth:
            return True
    return False


def _replay_probe_tmp_rows(
    path: Path,
    child_uuid: str,
    seq: int,
    identity: dict[str, Any],
    counters: list[Any],
    *,
    producer_run: str | None = None,
    producer_unit: str | None = None,
    orphan_pid: int | None = None,
    orphan_birth: int | None = None,
    producer_uuid: str,
    digests: dict[str, str] | None = None,
) -> tuple[list[Any], bool]:
    """Replay the best same-probe rewrite tmp into orphan rows (#88).

    A probe return flush that dies inside ``os.replace`` leaves the
    new snapshot in a complete ``{probe}.tmp-{pid}`` while the orphan
    sidecar stays pre-return. A candidate must parse, bind to the
    probe run (child uuid, probe seq, the F2 parent/run/unit/
    attempt stamps, and the writer incarnation -- each compared only
    when both sides state it, mirroring reunion strictness -- plus
    the producer's run/unit so legacy orphans cannot launder a
    cross-run tmp), and carry a row list; selection scores replayable
    returns, never raw volume, and divergent candidates warn loudly
    while the orphan rows win.
    Torn, foreign, or row-less tmps read as absent. The orphan's own
    loss keys/scalar always win (a tmp's marginal loss evidence stays
    dropped, as before -- counters-only replay). Raises
    ``_DeferProducerError`` on a persistently unreadable candidate.
    Returns ``(rows, divergent)``: a held conflict the caller must
    not silently clear when the baseline is covered (#88R8-2).
    ``digests`` records ``{path: sha256}`` for every candidate read
    (None discards: live ingest has no staging to bind to).
    """
    quarantined = _list_tmp_paths(path.parent, f"{path.name}.quarantined-")
    if quarantined is None:
        raise _DeferProducerError(producer_uuid, None, source=path.name, reason="enum")
    candidates = _list_tmp_paths(path.parent, f"{path.name}.tmp-")
    if candidates is None:
        raise _DeferProducerError(producer_uuid, None, source=path.name, reason="enum")

    def _gates(payload: Any) -> bool:
        return _probe_tmp_gates_clean(
            payload,
            child_uuid=child_uuid,
            seq=seq,
            identity=identity,
            producer_run=producer_run,
            producer_unit=producer_unit,
            orphan_pid=orphan_pid,
            orphan_birth=orphan_birth,
            producer_uuid=producer_uuid,
        )

    gated: list[tuple[Path, list[Any]]] = []
    for tmp in candidates:
        status, payload, digest = _read_json_evidence_digested(tmp)
        if digest is not None and digests is not None:
            digests[str(tmp)] = digest
        if status == "gone":
            continue
        if status == "unreadable":
            # An I/O fault is never a skip (see the producer replay):
            # defer for a coherent retry.
            raise _DeferProducerError(producer_uuid, None, source=tmp.name)
        if not _gates(payload):
            continue
        assert isinstance(payload, dict)
        gated.append((tmp, payload["counters"]))
    if quarantined and _divergence_vetoed(quarantined, _gates, producer_uuid):
        # A previous pass already judged this probe divergent but died
        # between renames: re-quarantine stragglers and hold the
        # conflict without replaying (#88R4-F3). The orphan rows win.
        # Only a same-child, same-seq quarantine vetoes (#88R5-3).
        kept, dropped = _quarantine_all([tmp for tmp, _ in gated])
        prior = ", ".join(path.name for path in quarantined)
        detail = f"quarantined: {prior}"
        if kept:
            detail += f"; re-quarantined stragglers: {', '.join(kept)}"
        warnings.warn(
            f"probe tmps for {path.name} already divergent "
            f"({detail}): conflict held, the orphan rows win"
            + (f"; dropped {dropped} (quarantine failed)" if dropped else ""),
            UserWarning,
            stacklevel=2,
        )
        return counters, True
    if not gated:
        return counters, False
    vectors: list[dict[tuple[str, ...], int]] = []
    merged_sides: list[list[list[Any]]] = []
    for _, rows in gated:
        merged = _merge_probe_tmp_rows(counters, rows)
        merged_sides.append(merged)
        vectors.append(_rows_returns_diff(merged, counters))
    winner_indexes, divergent = _maximal_replayable(
        [(index, vector) for index, vector in enumerate(vectors)]
    )
    if divergent:
        kept, dropped = _quarantine_all([tmp for tmp, _ in gated])
        warnings.warn(
            f"divergent probe tmps for {path.name} quarantined: "
            f"{', '.join(kept)} (irreconcilable rewrites; the orphan rows win)"
            + (f"; dropped {dropped} (quarantine failed)" if dropped else ""),
            UserWarning,
            stacklevel=2,
        )
        return counters, True
    if all(not vector for vector in vectors):
        return counters, False
    winner = max(winner_indexes, key=lambda index: _probe_rows_volume(gated[index][1]))
    return merged_sides[winner], False


def _probe_rows_volume(counters: list[Any]) -> int:
    """Parsed call volume of flat probe rows (garbage skipped)."""
    volume = 0
    for row in counters:
        parsed = _parse_probe_flat_row(row)
        if parsed is not None:
            volume += parsed[3]
    return volume


def _rows_returns_diff(merged: list[Any], own: list[Any]) -> dict[tuple[str, ...], int]:
    """Per-(module, fn, rv) returns a probe replay would add (#88R3)."""
    diff: dict[tuple[str, ...], int] = {}
    own_exits: dict[tuple[str, str, int], int] = {}
    for row in own:
        parsed = _parse_probe_flat_row(row)
        if parsed is None:
            continue
        module, fn, rv, count = parsed
        if rv is not None:
            own_exits[(module, fn, rv)] = own_exits.get((module, fn, rv), 0) + count
    merged_exits: dict[tuple[str, str, int], int] = {}
    for row in merged:
        parsed = _parse_probe_flat_row(row)
        if parsed is None:
            continue
        module, fn, rv, count = parsed
        if rv is not None:
            merged_exits[(module, fn, rv)] = merged_exits.get((module, fn, rv), 0) + count
    for key, merged_count in merged_exits.items():
        if merged_count > own_exits.get(key, 0):
            diff[(key[0], key[1], str(key[2]))] = merged_count - own_exits.get(key, 0)
    return diff


class _DeferProducerError(Exception):
    """Quiescence deferral: this pass cannot decide this producer (#88R3).

    Raised when a stamped probe writer is alive but unfenceable (no
    verified termination possible), or when evidence the decision
    needs is unreadable (#88R4-F1: an I/O fault that must retry, never
    a torn file): the caller retains the whole producer state (no
    records, no consume) so a later pass collects parent and probe
    coherently. Carries the producer uuid, the live writer pid (None
    for I/O deferrals), and the unreadable file name for the warning.
    """

    def __init__(self, uuid: str, pid: int | None, source: str = "", reason: str = "") -> None:
        super().__init__(uuid, pid, source, reason)
        self.uuid = uuid
        self.pid = pid
        self.source = source
        self.reason = reason

    @property
    def detail(self) -> str:
        """Human-readable deferral cause for the warning."""
        if self.pid is not None:
            return f"live probe writer (pid {self.pid}) unfenceable"
        if self.reason == "rewrite":
            return f"rewrite newer than marker coverage ({self.source or 'unknown file'})"
        if self.reason == "divergent":
            return f"divergent rewrites under marker coverage ({self.source or 'unknown file'})"
        if self.reason == "changed":
            return f"evidence changed during collection ({self.source or 'unknown file'})"
        if self.reason == "enum":
            return f"tmp listing failed under {self.source or 'unknown file'}"
        if self.source:
            return f"unreadable evidence ({self.source})"
        return "unreadable evidence"


def _adopt_probe_orphans(
    root: Path,
    *,
    worker_uuid: str,
    sidecar: Any | None,
    journal_lines: list[str],
    claims: dict[str, set[tuple[str, int]]],
    known_uuids: set[str],
    producer_run: str | None = None,
    producer_unit: str | None = None,
    heal_orphans: bool = True,
    fence_live: bool,
    digests: dict[str, str] | None = None,
) -> tuple[
    dict[str, Any] | None,
    list[dict[str, Any]],
    list[Path],
    list[tuple[str, int]],
    set[tuple[str, int]],
    int,
    bool,
]:
    """Fold one producer's retained probe sidecars.

    Returns ``(block, receipts, consumed, recovered, orphan_keys,
    adopted_lost, skipped_live)``: ``skipped_live`` reports covered
    orphans skipped for a live or racing writer, whose parent
    association the caller must retain for a coherent retry
    (#88R11-1). ``digests`` records ``{path: sha256}`` for every
    probe file read (None discards): the barrier stages them so a
    retry proves byte-identity before acting on the old adjudication
    (#88R13-2).

    ``heal_orphans`` is False on the committed path (a live session is
    authoritative): an uncovered orphan was never absorbed, so healing
    its claim would pierce supersede while the counts die to it. Only
    vacuous orphans heal there; markers always heal (absorbed-live
    proof the session includes). ``fence_live`` fences stamped live
    writers on postmortem paths (dead/torn/resume-dead) and raises
    ``_DeferProducerError`` when a writer cannot be verified terminated;
    committed paths pass False (never fence a live producer's probe).
    Orphans covered by the producer's durable receipts (sidecar + all
    journal windows + JSONL session/entry claims) suppress silently: their
    evidence is already durable. Uncovered orphans fold into one
    module-first block keyed by the PARENT uuid (never the child's: a
    child-keyed partial would fold beside the parent's gap and
    double-count) and their receipts are claimed, so the extractor reports
    them folded without inflating ``probes_lost``. Adopted orphans also
    yield ``recovered`` ``(parent, seq)`` identities (exact healing of the
    parent's live-claimed keys) and union their own nested ``orphan_keys``
    (fresh grandchild-scope info no session could hold). Recovery fires
    only when the filename and content seq agree; a mismatch still folds
    counts best-effort but heals nothing (fail closed toward incomplete).
    Consumed files go only after the caller durably records the fold
    (append-then-delete, like parent files). Both directory listings
    snapshot up front (``sorted`` over a full glob), so a sidecar landing
    mid-pass waits for the next pass instead of half-folding (TOCTOU-safe).

    Reunion is two passes (rc3 Area B, F3). Pass 1 reunites by the F2
    content identity (``parent_uuid``): the filename hint only pre-filters,
    so a shared 8-char prefix never misattributes. Pass 2 keeps the legacy
    filename fallback, but only when the prefix names exactly this
    producer; under a collision the legacy orphan retains with one
    ``ambiguous`` warning (reported by the lowest colliding uuid, so every
    colliding pass does not warn). A content identity whose run or unit
    contradicts the producer's (``producer_run``/``producer_unit``, each
    compared only when both sides state it) is stale evidence from another
    run or unit: retained with a ``cross-run``/``cross-unit`` warning,
    never folded. Retained, never destroyed: ambiguous legacy orphans,
    cross-run/cross-unit orphans, parentless orphans, and dict-shaped but
    schema-invalid files (mirroring invalid sidecars). Torn (unparseable
    or non-dict) files are provably unrecoverable debris and consume with
    the fold.

    Residual: entry-claim suppression needs the entry's
    ``consumed_probes`` proof, so evidence predating it (or entries
    whose proof failed validation) still double-folds on the triple
    fault -- live sidecar-fallback ingest, failed parent flush,
    pre-flush death -- and stays fail-visible through the lost
    record. The adopted scalar doubles with the counts there for the
    same reason (the proof never lands); same visibility, same rarity.
    Adopted orphans' nested receipts are dropped, never propagated:
    probe sidecars carry counters, keyed losses, the unkeyed scalar,
    and F2 identity, and only the orphan's own receipt is claimed here.
    """
    prefix = worker_uuid[:8]
    colliders = sorted(uuid for uuid in known_uuids if uuid.startswith(prefix))
    unambiguous = colliders == [worker_uuid]
    coverage = _durable_receipts(sidecar, journal_lines) | claims.get(worker_uuid, set())
    coverage_snapshots: dict[
        tuple[str, int], tuple[list[Any], frozenset[tuple[str, int]], int]
    ] = {}
    merged: dict[str, Any] = {"total_calls": 0, "by_module": {}}
    claimed: list[dict[str, Any]] = []
    consumed: list[Path] = []
    skipped: list[Path] = []
    marker_paths: dict[tuple[str, int], list[Path]] = {}
    recovered: list[tuple[str, int]] = []
    orphan_keys: set[tuple[str, int]] = set()
    adopted_lost: list[int] = []

    def _skip_covered_orphan(path: Path, child_uuid: str, seq: int, reason: str) -> None:
        """Skip a covered orphan, rolling back its marker's consume+heal (#88R12-1).

        The marker's coverage and keys stand (absorbed facts), but the
        marker file and the heal wait for the retry: consuming the
        marker now would strand an advanced orphan uncovered, and
        healing now would resolve a loss whose tail is outstanding.
        """
        skipped.append(path)
        for marker_path in marker_paths.pop((child_uuid, seq), []):
            if marker_path in consumed:
                consumed.remove(marker_path)
        recovered[:] = [entry for entry in recovered if entry != (worker_uuid, seq)]
        warnings.warn(
            f"covered probe orphan {path.name} {reason}; retained for a later pass",
            UserWarning,
            stacklevel=3,
        )

    def _fold(
        path: Path,
        child_uuid: str,
        seq: int,
        counters: list[Any],
        keys: frozenset[tuple[str, int]],
        filename_seq: int,
        finalized: bool,
        adopted: int,
        vacuous_ok: bool,
        replayed_adopted: bool,
        replay_divergent: bool,
        raw_snapshot: Any,
    ) -> None:
        if (child_uuid, seq) in coverage:
            if replay_divergent:
                # An unresolved conflict must never clear silently
                # under coverage: the baseline, marker, and loss claim
                # stay associated for forensic resolution (#88R8-2).
                raise _DeferProducerError(worker_uuid, None, source=path.name, reason="divergent")
            marker_snapshot = coverage_snapshots.get((child_uuid, seq))
            # Stability reread (#88R11-1): suppression consumes the
            # file, so the file must still hold the folded snapshot.
            # A writer that advanced it after the first reread (an
            # unstamped writer racing collection, or any writer
            # released late) invalidates the consume: marker-covered
            # orphans skip (their snapshot makes the retry safe --
            # an advance defers on subset mismatch), while
            # durable-covered or postmortem orphans defer (no
            # snapshot could detect the advance at retry).
            fold_status, fold_raw = _read_json_evidence(path)
            if fold_status == "unreadable":
                raise _DeferProducerError(worker_uuid, None, source=path.name)
            if fold_status != "gone" and not _snapshots_equal(fold_raw, raw_snapshot):
                if not fence_live and marker_snapshot is not None:
                    _skip_covered_orphan(path, child_uuid, seq, "advanced during collection")
                    return
                raise _DeferProducerError(worker_uuid, None, source=path.name, reason="changed")
            if marker_snapshot is not None:
                # Marker coverage proves exactly the marker snapshot:
                # anything beyond it is a newer rewrite the marker
                # never saw (or a mid-fence replacement the reread
                # caught) and defers instead of dropping (#88R8-1).
                marker_rows, marker_keys, marker_adopted = marker_snapshot
                if not _snapshot_covered_by(
                    counters, keys, adopted, marker_rows, marker_keys, marker_adopted
                ):
                    raise _DeferProducerError(worker_uuid, None, source=path.name, reason="rewrite")
            elif replayed_adopted:
                # Durable (session/checkpoint) coverage carries no
                # snapshot to compare: any adopted rewrite is
                # unprovably newer, so it defers rather than dropping
                # silently (#88R7-1).
                raise _DeferProducerError(worker_uuid, None, source=path.name, reason="rewrite")
            # Covered orphans union their keys anyway (#88R11-4):
            # marker subsets re-union idempotently, while durable
            # coverage may have absorbed the counts without the keys
            # (a loss that landed between absorb and commit) -- keys
            # union safely either way. The unkeyed scalar stays
            # dropped (no baseline compares it).
            orphan_keys.update(keys)
            consumed.append(path)
            return
        # Healing and key-union never gate on counts: a zero-counters
        # orphan still names its (parent, seq) identity (the child
        # accounted for zero calls) and may carry nested grandchild
        # keys (robustness M1). Only the count merge and the receipt
        # claim need a block. (.update, not |=: rebinding the closure
        # name would raise UnboundLocalError.)
        orphan_keys.update(keys)
        # The unkeyed remainder rides the same gate: folded implies
        # uncovered implies never absorbed live (except the disclosed
        # triple-fault window below, where the proof never lands and
        # the lost record keeps the outcome fail-visible), so adding
        # here cannot double against a live absorb (suppressed orphans
        # return above, their scalar already in the parent state).
        # Remainder, not total: nested keys union separately while the
        # extractor subtracts only part_keys, so forwarding the total
        # would count every adopted keyed loss twice (batch-2 review).
        # The reader precomputes the remainder (a total minus its
        # surviving keys, a floor standing alone); a corrupt scalar
        # with no malformed items floors to 0 here but never reads
        # vacuous below (R2-F3).
        adopted_lost.append(adopted)
        block = _probe_rows_to_block(counters)
        # Healing gates on finalized: a mid-run prefix folds its counts
        # but never heals, since the tail it never saw stays genuinely
        # outstanding (codex RC4-R1-1). On the committed path (session
        # authoritative) orphan heals are disabled: an uncovered orphan
        # was never absorbed, so the session lacks its counts, which
        # supersede drops while a heal would pierce -- healing would
        # report complete with real calls silently missing (codex R2
        # F1). The known cost: absorbed-but-never-flushed evidence
        # (persistent sidecar failure + survival) reads spurious-
        # incomplete instead of exact-complete; loud beats silent, and
        # full linkage awaits the heal-linkage design. Vacuous evidence
        # (wire-empty counters, zero scalar, clean keys) still heals:
        # the session trivially contains nothing -- but present-yet-
        # unparseable rows or corrupt keys prove nothing about zero
        # calls, so they never heal (codex R3/R6). Markers heal on
        # every path: a marker proves a live absorb the session
        # includes.
        if finalized and seq == filename_seq and (heal_orphans or (not counters and vacuous_ok)):
            recovered.append((worker_uuid, seq))
        if block is not None:
            merge_module_first(merged, block)
            claimed.append({"worker_uuid": child_uuid, "probe_seq": seq})
        consumed.append(path)

    # Markers (order-free, conservative): consumed markers suppress before
    # any orphan folds. A marker's counts already sit in the parent
    # checkpoint, so its identity joins coverage and the marker itself
    # consumes. Torn markers are debris: unparseable content folds nothing.
    # Valid FINALIZED markers still heal (their evidence is checkpoint-
    # durable); prefix markers suppress without healing, since the tail
    # they never saw stays outstanding. Both union their nested keys.
    # Ownership mirrors the orphan reunion (#88R5-4): content-exact
    # parent/run/unit first, exact-name routing for new full-uuid
    # markers, prefix fallback only for legacy markers under an
    # unambiguous prefix. A foreign marker heals nothing here.
    ambiguous_reporter = colliders[:1] == [worker_uuid]
    for path in sorted(root.glob(f"{PROBE_CONSUMED_PREFIX}*{PROBE_FILE_SUFFIX}")):
        parsed_name = _parse_consumed_probe_filename(path.name)
        if parsed_name is None:
            continue
        owner, filename_seq = parsed_name
        if len(owner) == 32:
            if owner != worker_uuid:
                continue  # Another producer's marker (name-routed).
        elif owner != prefix:
            continue
        status, raw, read_digest = _read_json_evidence_digested(path)
        if read_digest is not None and digests is not None:
            digests[str(path)] = read_digest
        if status == "gone":
            continue
        if status == "unreadable":
            # An unreadable marker still owns its suppression coverage
            # -- consuming it would double-fold the orphan it covers,
            # so the producer defers instead. Full-uuid names route
            # foreign markers away above; legacy names defer whenever
            # the prefix matches (loud under a collision, since the
            # owner cannot be proved).
            if len(owner) != 32 and not unambiguous and ambiguous_reporter:
                warnings.warn(
                    f"ambiguous consumed marker {path.name} retained "
                    f"({len(colliders)} producers share prefix {prefix})",
                    UserWarning,
                    stacklevel=2,
                )
            raise _DeferProducerError(worker_uuid, None, source=path.name)
        orphan = _parse_probe_orphan_payload(raw)
        if orphan is None:
            consumed.append(path)
            continue
        (
            marker_child,
            marker_seq,
            marker_counters,
            marker_keys,
            marker_identity,
            marker_finalized,
            marker_adopted,
            _,
            _,
            _,
        ) = orphan
        parent_claim = marker_identity.get("parent_uuid")
        if parent_claim is not None and parent_claim != worker_uuid:
            continue  # Another producer's marker (content-exact).
        if parent_claim is None and len(owner) != 32 and not unambiguous:
            if ambiguous_reporter:
                warnings.warn(
                    f"ambiguous consumed marker {path.name} retained "
                    f"({len(colliders)} producers share prefix {prefix})",
                    UserWarning,
                    stacklevel=2,
                )
            continue
        # Run/unit agreement holds for stamped and legacy-routed alike:
        # any stated stamp contradicting the producer retains loudly.
        marker_run = marker_identity.get("run_id")
        if marker_run is not None and producer_run is not None and marker_run != producer_run:
            warnings.warn(
                f"cross-run consumed marker {path.name} retained "
                f"(marker run {marker_run!r} != producer run {producer_run!r})",
                UserWarning,
                stacklevel=2,
            )
            continue
        marker_unit = marker_identity.get("unit")
        if marker_unit is not None and producer_unit is not None and marker_unit != producer_unit:
            warnings.warn(
                f"cross-unit consumed marker {path.name} retained "
                f"(marker unit {marker_unit!r} != producer unit {producer_unit!r})",
                UserWarning,
                stacklevel=2,
            )
            continue
        coverage.add((marker_child, marker_seq))
        coverage_snapshots[(marker_child, marker_seq)] = (
            marker_counters,
            marker_keys,
            marker_adopted,
        )
        orphan_keys |= marker_keys
        # A surviving rewrite tmp for this slot means the absorbed
        # snapshot is not the latest word: healing here would clear a
        # stranded rewrite silently (the orphan loop never visits a
        # gone baseline, so the tmp's returns would fold nowhere).
        # Coverage still applies (the absorb is a static fact, and the
        # snapshot stays load-bearing for the reappearing-baseline
        # catch in _fold), but recovery and marker consumption withhold
        # until the slot's latest word is provable; the tmp's own
        # replay/prune paths converge the retry (#88R10-2).
        slot_name = _marker_slot_name(path.name)
        assert slot_name is not None  # parsed_name guarantees the shape
        if _slot_rewrite_unresolved(root, slot_name, digests):
            warnings.warn(
                f"consumed marker {path.name} slot {slot_name} keeps an unresolved "
                "rewrite; recovery withheld",
                UserWarning,
                stacklevel=2,
            )
            continue
        if marker_finalized and marker_seq == filename_seq:
            recovered.append((worker_uuid, marker_seq))
        marker_paths.setdefault((marker_child, marker_seq), []).append(path)
        consumed.append(path)
    for path in sorted(root.glob(f"{PROBE_FILE_PREFIX}*{PROBE_FILE_SUFFIX}")):
        parsed_name = _parse_probe_filename(path.name)
        if parsed_name is None or parsed_name[0] != prefix:
            continue
        status, raw, read_digest = _read_json_evidence_digested(path)
        if read_digest is not None and digests is not None:
            digests[str(path)] = read_digest
        if status == "gone":
            continue
        if status == "unreadable":
            # The baseline may still carry unabsorbed returns: keep
            # it and its parent association for a coherent retry.
            raise _DeferProducerError(worker_uuid, None, source=path.name)
        orphan = _parse_probe_orphan_payload(raw)
        if orphan is None:
            if raw is None or not isinstance(raw, dict):
                consumed.append(path)
            continue
        (
            child_uuid,
            seq,
            counters,
            keys,
            identity,
            finalized,
            adopted,
            vacuous_ok,
            orphan_pid,
            orphan_birth,
        ) = orphan
        # Ownership precedes every side effect (#88R4-REG1): pid checks,
        # fencing, replay, and quarantine must never touch another
        # producer's evidence on a shared filename prefix.
        parent_claim = identity.get("parent_uuid")
        if parent_claim is not None and parent_claim != worker_uuid:
            continue  # Another producer's pass owns it (content-exact).
        if parent_claim is None and not unambiguous and (child_uuid, seq) not in coverage:
            # Pass 2: legacy filename fallback (no content identity).
            # Under a prefix collision the orphan could belong to any
            # collider, so it retains with one warning instead of
            # attributing by a hint. A marker-covered copy instead falls
            # through to fencing + replay like owned evidence (#88R6-2a):
            # its writer and rewrites are quiesced before _fold
            # suppresses the duplicate (or defers on a newer rewrite).
            if ambiguous_reporter:
                warnings.warn(
                    f"ambiguous probe orphan {path.name} retained "
                    f"({len(colliders)} producers share prefix {prefix})",
                    UserWarning,
                    stacklevel=2,
                )
            continue
        # Run/unit agreement holds for content-exact and legacy-routed
        # alike (#88R6-2b): any stated stamp contradicting the producer
        # retains loudly instead of misfolding another run's calls.
        orphan_run = identity.get("run_id")
        if orphan_run is not None and producer_run is not None and orphan_run != producer_run:
            warnings.warn(
                f"cross-run probe orphan {path.name} retained "
                f"(orphan run {orphan_run!r} != producer run {producer_run!r})",
                UserWarning,
                stacklevel=2,
            )
            continue
        orphan_unit = identity.get("unit")
        if orphan_unit is not None and producer_unit is not None and orphan_unit != producer_unit:
            warnings.warn(
                f"cross-unit probe orphan {path.name} retained "
                f"(orphan unit {orphan_unit!r} != producer unit {producer_unit!r})",
                UserWarning,
                stacklevel=2,
            )
            continue
        if fence_live and orphan_pid is not None:
            # Quiescence (#88R3): on postmortem paths a stamped live
            # writer is fenced first (its test died with its parent, so
            # its tail is moot; the fence names it in-flight). Only a
            # verified termination (or an already-dead pid) proceeds;
            # unfenceable writers defer the whole producer (the caller
            # retains everything and warns) so a later pass collects
            # parent and probe coherently. Committed paths never fence
            # (their producer may still be running its tests).
            # A present pid with unverifiable identity (#88R3-F4: no
            # birth stamp, an unreadable birth token, or a platform
            # without birth tokens) is unresolved, never dead:
            # signaling is forbidden without an incarnation binding,
            # so a live-or-unverifiable pid defers; only a
            # proven-dead pid proceeds.
            if orphan_birth is None:
                if _pid_exists(orphan_pid):
                    raise _DeferProducerError(worker_uuid, orphan_pid)
            elif not _terminate_verified(orphan_pid, orphan_birth, 5.0):
                raise _DeferProducerError(worker_uuid, orphan_pid)
        # A covered orphan with a live writer must not suppress: the
        # writer may replace the file after our reads. Only the
        # committed path skips (postmortem paths fence first and defer
        # on failure); detection is incarnation-aware so recycled pids
        # and zombies never read as running. The skip retains the
        # parent association (the caller drops the parent files from
        # its consume set and reports them held): the parent's records
        # are complete without this file, but only a coherent retry
        # may revisit it, so the skip reports through the return flag
        # (#88R11-1). Only marker-covered orphans skip: their snapshot
        # makes the retry safe (an advance defers on subset mismatch).
        # Durable-covered orphans carry no snapshot to detect an
        # advance, so a live writer defers the whole producer instead
        # (loud and honest; convergence awaits the delta-reunion
        # design). Unstamped orphans cannot be gated (no identity to
        # check): they proceed to the rereads, and the fold-time
        # reread skips-or-defers them on any advance.
        if (
            not fence_live
            and (child_uuid, seq) in coverage
            and orphan_pid is not None
            and _incarnation_alive(orphan_pid, orphan_birth)
        ):
            if (child_uuid, seq) not in coverage_snapshots:
                raise _DeferProducerError(worker_uuid, orphan_pid)
            _skip_covered_orphan(path, child_uuid, seq, f"has a live writer (pid {orphan_pid})")
            continue
        # Re-read after quiescence (#88R8-1): a writer that replaced
        # the file during the fence invalidates the pre-fence rows. Any
        # change (type-strict: True is not 1) or new read fault defers;
        # a vanished file was absorbed live -- unless a rewrite tmp
        # survives it, which no later pass could rediscover: that tmp
        # stays loudly forensic while the parent proceeds (#88R9-1c).
        fresh_status, fresh_raw = _read_json_evidence(path)
        if fresh_status == "gone":
            survivors = _list_tmp_paths(path.parent, f"{path.name}.tmp-")
            if survivors:
                names = ", ".join(sorted(p.name for p in survivors))
                warnings.warn(
                    f"probe baseline {path.name} vanished with surviving rewrite tmps "
                    f"({names}); tmps retained for forensics",
                    UserWarning,
                    stacklevel=2,
                )
            elif survivors is None:
                warnings.warn(
                    f"probe baseline {path.name} vanished and its rewrite tmps "
                    "cannot be listed (I/O fault); proceeding without them",
                    UserWarning,
                    stacklevel=2,
                )
            continue
        if fresh_status == "unreadable":
            raise _DeferProducerError(worker_uuid, None, source=path.name)
        if not _snapshots_equal(fresh_raw, raw):
            raise _DeferProducerError(worker_uuid, None, source=path.name, reason="changed")
        # #88: a same-probe rewrite tmp replays its returns onto the
        # orphan's rows before the reunion fold.
        pre_replay_exits = _rows_exit_total(counters)
        counters, replay_divergent = _replay_probe_tmp_rows(
            path,
            child_uuid,
            seq,
            identity,
            counters,
            producer_run=producer_run,
            producer_unit=producer_unit,
            orphan_pid=orphan_pid,
            orphan_birth=orphan_birth,
            producer_uuid=worker_uuid,
            digests=digests,
        )
        replayed_adopted = _rows_exit_total(counters) != pre_replay_exits
        _fold(
            path,
            child_uuid,
            seq,
            counters,
            keys,
            parsed_name[1],
            finalized,
            adopted,
            vacuous_ok,
            replayed_adopted,
            replay_divergent,
            raw,
        )
    adopted = sum(adopted_lost)
    skipped_live = len(skipped) > 0
    if merged["total_calls"] == 0:
        return None, [], consumed, sorted(set(recovered)), orphan_keys, adopted, skipped_live
    claimed.sort(key=lambda item: (item["worker_uuid"], item["probe_seq"]))
    return merged, claimed, consumed, sorted(set(recovered)), orphan_keys, adopted, skipped_live


def _sidecar_loss_keys(sidecar: Any | None) -> set[tuple[str, int]]:
    """Return the sidecar's keyed-loss set (tolerantly parsed, never raises).

    Keys are read from the sidecar only, never the journal: with K=1
    every loss mutation flushes the sidecar immediately, so its key set
    is always at least as current as any journal window (a union there
    would be set-idempotent but pointless).
    """
    if not isinstance(sidecar, dict):
        return set()
    raw = sidecar.get("lost_keys", ())
    if not isinstance(raw, (list, tuple)):
        return set()
    return {(entry["parent_uuid"], entry["probe_seq"]) for entry in raw if is_lost_key(entry)}


def _keys_to_wire(keys: set[tuple[str, int]] | frozenset[tuple[str, int]]) -> list[dict[str, Any]]:
    """Render a key set as sorted wire dicts (deterministic order)."""
    return [{"parent_uuid": parent, "probe_seq": seq} for parent, seq in sorted(keys)]


def _gap_for_producer(
    sidecar: Any | None,
    journal_lines: list[str],
    committed_entries: set[tuple[str, str]],
    worker_uuid: str,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], bool]:
    """Compute one dead producer's gap ``(block, receipts, conflict)``.

    ``block`` is None when nothing recoverable remains (no partial is
    emitted, only the lost record); ``conflict`` marks evidence that
    cannot be reconciled and must surface as a ``conflict`` end state
    rather than invented or doubled counts. n counts content-valid journal
    windows anywhere in the file; tears only flag (an unparseable tail is
    the benign crash-mid-append shape; anything else unparseable, or a
    parseable line with invalid window content, flags conflict while valid
    lines still fold). Three arms on the sidecar mark: equal folds the
    valid windows plus the in-progress tail; older folds every valid window
    and excludes the subsumed stale snapshot; newer is a vanished append
    (corruption: conflict, lost record only — deliberately conservative on
    untrustworthy evidence). A missing mark with a non-empty journal folds
    the snapshot only and conflicts (overlap unknowable).
    """
    receipts: list[dict[str, Any]] = []
    if sidecar is None:
        if not journal_lines:
            return None, [], False
        return None, [], True
    if not isinstance(sidecar, dict):
        return None, [], True
    in_progress = sidecar.get("in_progress")
    if not is_module_first_block(in_progress):
        return None, [], True
    receipts.extend(_valid_receipts(sidecar.get("receipts")))
    windows: list[dict[str, Any]] = []
    conflict = False
    for index, line in enumerate(journal_lines):
        try:
            parsed = _json_loads_evidence(line)
        except ValueError:
            parsed = None
        if not isinstance(parsed, dict):
            if index != len(journal_lines) - 1:
                conflict = True
            continue
        if not isinstance(parsed.get("nodeid"), str) or not parsed.get("nodeid"):
            conflict = True
            continue
        if not is_module_first_block(parsed.get("block")):
            conflict = True
            continue
        windows.append(parsed)
    n = len(windows)
    seq = sidecar.get("journal_seq")
    gap = {"total_calls": 0, "by_module": {}}
    if not journal_lines:
        if _is_nonneg_int(seq) and seq != 0:
            # A mark with no journal means every append vanished.
            return None, receipts, True
        merge_module_first(gap, in_progress)
    elif not _is_nonneg_int(seq):
        merge_module_first(gap, in_progress)
        conflict = True
    else:
        assert isinstance(seq, int)
        if seq > n:
            return None, receipts, True
        if seq == n:
            merge_module_first(gap, in_progress)
        # Else (seq < n): the stale snapshot is subsumed by the first valid
        # window beyond the mark — fold every valid window, exclude it.
        for window in windows:
            nodeid = window["nodeid"]
            assert isinstance(nodeid, str)
            if (worker_uuid, nodeid) in committed_entries:
                continue
            receipts.extend(_valid_receipts(window.get("receipts")))
            merge_module_first(gap, window["block"])
    if gap["total_calls"] == 0:
        return None, receipts, conflict
    if not is_module_first_block(gap):
        return None, receipts, True
    return gap, receipts, conflict


def _journal_for_sidecar(sidecar_path: Path) -> Path:
    """Return the journal path derived from a sidecar path (same stem)."""
    if sidecar_path.name.endswith(SIDECAR_SUFFIX):
        stem = sidecar_path.name[: -len(SIDECAR_SUFFIX)]
    else:
        stem = sidecar_path.name
    return sidecar_path.with_name(stem + JOURNAL_SUFFIX)


def _tmp_has_return_rows(payload: Any) -> bool:
    """Whether a parsed tmp payload carries any return rows (#88R3)."""
    if not isinstance(payload, dict):
        return False
    in_progress = payload.get("in_progress")
    if isinstance(in_progress, dict):
        by_module = in_progress.get("by_module")
        if isinstance(by_module, dict):
            for module_block in by_module.values():
                if not isinstance(module_block, dict):
                    continue
                buckets = module_block.get("buckets")
                if not isinstance(buckets, dict):
                    continue
                for bucket_block in buckets.values():
                    if not isinstance(bucket_block, dict):
                        continue
                    by_fn = bucket_block.get("by_fn")
                    if not isinstance(by_fn, dict):
                        continue
                    for leaf in by_fn.values():
                        if isinstance(leaf, dict) and leaf.get("by_rv"):
                            return True
        return False
    counters = payload.get("counters")
    if isinstance(counters, list):
        for row in counters:
            parsed = _parse_probe_flat_row(row)
            if parsed is not None and parsed[2] is not None:
                return True
    return False


def _sha256_file_hex(path: Path) -> str | None:
    """Hex digest of a file's bytes, else None (missing/unreadable). Never raises."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _marker_slot_name(marker_name: str) -> str | None:
    """Original slot name for a consumed marker, else None (#88R10-2)."""
    if not marker_name.startswith(PROBE_CONSUMED_PREFIX):
        return None
    if not marker_name.endswith(PROBE_FILE_SUFFIX):
        return None
    stem = marker_name[len(PROBE_CONSUMED_PREFIX) : -len(PROBE_FILE_SUFFIX)]
    parts = stem.split("-")
    if len(parts) != 3:
        return None
    owner, seq, nonce = parts
    return f"{PROBE_FILE_PREFIX}{owner[:8]}-{seq}-{nonce}{PROBE_FILE_SUFFIX}"


def _slot_rewrite_unresolved(
    root: Path, slot_name: str, digests: dict[str, str] | None = None
) -> bool:
    """Whether a slot keeps an undecided rewrite tmp (#88R10-2).

    A tmp survives "undecided" only when it decodes and carries return
    rows: torn or returnless tmps are debris that converge through the
    normal replay/prune paths. Unreadable state (tmp listing refused,
    payload unreadable) fails closed: the caller must withhold recovery
    until the slot's latest word is provable. ``digests`` records
    ``{path: sha256}`` for every tmp read (None discards).
    """
    tmps = _list_tmp_paths(root, f"{slot_name}.tmp-")
    if tmps is None:
        return True
    for tmp in tmps:
        status, payload, digest = _read_json_evidence_digested(tmp)
        if digest is not None and digests is not None:
            digests[str(tmp)] = digest
        if status in {"gone", "torn"}:
            continue
        if status != "ok":
            return True
        if _tmp_has_return_rows(payload):
            return True
    return False


def _replay_baseline_usable(path: Path) -> bool:
    """Whether a sidecar file could anchor tmp replay (#88R3)."""
    payload = read_json_file(path)
    if not isinstance(payload, dict):
        return False
    in_progress = payload.get("in_progress")
    if isinstance(in_progress, dict):
        return is_module_first_block(in_progress) and _is_nonneg_int(payload.get("journal_seq"))
    if isinstance(payload.get("counters"), list):
        return _read_probe_orphan(path) is not None
    return False


def _read_bytes_with_retry(path: Path) -> bytes:
    """Read a file's bytes, retrying transient faults (AV locks); raises persistently."""
    attempts = 0
    while True:
        try:
            return path.read_bytes()
        except FileNotFoundError:
            raise
        except OSError:
            attempts += 1
            if attempts >= 3:
                raise
            time.sleep(0.001)


def _read_text_with_retry(path: Path) -> str:
    """Read a text file, retrying transient faults (AV locks); raises persistently."""
    attempts = 0
    while True:
        try:
            return path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise
        except ValueError:
            raise
        except OSError:
            attempts += 1
            if attempts >= 3:
                raise
            time.sleep(0.001)


def _unlink_quietly(path: Path) -> None:
    """Unlink one path; missing or failed unlinks never raise."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _unlink_counted(path: Path) -> bool:
    """Unlink one path; True only when it is provably gone (#88R3-F5)."""
    _unlink_quietly(path)
    try:
        return not path.exists()
    except OSError:
        return False


def _list_tmp_paths(directory: Path, prefix: str) -> list[Path] | None:
    """List ``prefix*`` entries; None when enumeration itself faults (#88R7-4).

    ``pathlib`` globbing swallows listing errors (an EACCES reads as
    empty), which would silently strand tmps behind a deleted
    baseline. ``os.scandir`` surfaces them instead: a missing
    directory reads as empty (no tmps possible), any other OSError
    reads as None (callers hold or defer for retry). Never raises.
    """
    try:
        with os.scandir(directory) as entries:
            return sorted(
                directory / entry.name for entry in entries if entry.name.startswith(prefix)
            )
    except FileNotFoundError:
        return []
    except OSError:
        return None


def _prune_sidecar_tmps(
    path: Path, listed: Mapping[str, str] | None = None
) -> tuple[int, int, bool]:
    """Delete a sidecar's rewrite tmps except unadjudicable ones (#88R3).

    A tmp deletes when it proves debris (torn/unparseable, or carrying
    no return rows) or when a usable baseline exists (its returns were
    replayed or ruled out upstream). Unreadable tmps (after retry) and
    complete-with-returns tmps without a usable baseline retain for a
    later pass or forensic review, named loudly (never silently).
    ``listed`` maps adjudicated tmp paths to their byte digests (None
    keeps the legacy content-only rules): an unlisted or evolved tmp
    retains and holds its baseline instead of deleting unread
    (#88R13-2). Markers also cover their original slot's tmps (a
    marker rename orphans the slot glob otherwise).
    Returns ``(removed, retained, hold_baseline)``: authoritative
    callers (the sweep) hold the baseline while any tmp unlink failed
    or any tmp stayed unreadable (#88R5-6/#88R6-3: a baseline removed
    around either would strand the tmp beyond re-discovery). Forensic
    retention of a classified-complete tmp never holds. Never raises.
    """
    maybe_tmps = _list_tmp_paths(path.parent, f"{path.name}.tmp-")
    if maybe_tmps is None:
        warnings.warn(
            f"cannot enumerate tmps under {path.name} (I/O fault); baseline held for retry",
            UserWarning,
            stacklevel=3,
        )
        return (0, 0, True)
    tmps = list(maybe_tmps)
    slot_name = _marker_slot_name(path.name)
    if slot_name is not None:
        slot_tmps = _list_tmp_paths(path.parent, f"{slot_name}.tmp-")
        if slot_tmps is None:
            warnings.warn(
                f"cannot enumerate tmps under {slot_name} (I/O fault); baseline held",
                UserWarning,
                stacklevel=3,
            )
            return (0, 0, True)
        tmps.extend(slot_tmps)
    if not tmps:
        return (0, 0, False)
    baseline_usable = _replay_baseline_usable(path)
    retained: list[str] = []
    removed = 0
    hold_baseline = False
    for tmp in tmps:
        if listed is not None:
            digest = _sha256_file_hex(tmp)
            if digest is None or listed.get(str(tmp)) != digest:
                retained.append(tmp.name)
                hold_baseline = True
                continue
        try:
            raw = _read_text_with_retry(tmp)
        except FileNotFoundError:
            continue
        except ValueError:
            if _unlink_counted(tmp):
                removed += 1
            else:
                retained.append(tmp.name)
                hold_baseline = True
            continue
        except OSError:
            retained.append(tmp.name)
            hold_baseline = True
            continue
        try:
            payload = _json_loads_evidence(raw)
        except ValueError:
            if _unlink_counted(tmp):
                removed += 1
            else:
                retained.append(tmp.name)
                hold_baseline = True
            continue
        if _tmp_has_return_rows(payload) and not baseline_usable:
            retained.append(tmp.name)
            continue
        if _unlink_counted(tmp):
            removed += 1
        else:
            retained.append(tmp.name)
            hold_baseline = True
    if retained:
        shown = ", ".join(retained[:3])
        if len(retained) > 3:
            shown += f", +{len(retained) - 3} more"
        warnings.warn(
            f"retained {len(retained)} unadjudicated tmp(s) under {path.name}: {shown}",
            UserWarning,
            stacklevel=3,
        )
    return (removed, len(retained), hold_baseline)


def _consume_producer_files(
    paths: list[Path], digests: Mapping[str, str] | None = None
) -> list[Path]:
    """Delete collected/committed evidence files (best effort, never raises).

    A baseline whose tmps the prune holds (failed unlink, unreadable
    tmp, or listing fault) stays as the discoverable cleanup record:
    the tmp glob keys off its name, so a later sweep retries the whole
    set without publishing anything twice (unit collection is
    single-shot per attempt; resume re-collection dedups through
    barrier staging and session routing).

    ``digests`` maps adjudicated paths to their byte digests: a listed
    file whose bytes changed since adjudication holds (never deletes
    evolved evidence), and an unlisted probe file holds too
    (orphaned writers can ghost probe slots). Unlisted producer
    files delete as before (dead/fenced writers cannot ghost), as do
    producer-baseline tmps (legacy content rules); probe-baseline
    tmps delete only when listed and identical (#88R13-2).

    Returns the targets still present afterwards (held): the resume
    barrier reports them so application keeps the staging that
    authorizes their retry instead of discarding it (#88R10-4c).
    """
    held: list[Path] = []
    for path in paths:
        key = str(path)
        if digests is not None and key in digests:
            if (path.exists() or path.is_symlink()) and _sha256_file_hex(path) != digests[key]:
                warnings.warn(
                    f"cleanup target {path.name} changed since adjudication; held",
                    UserWarning,
                    stacklevel=2,
                )
                held.append(path)
                continue
        elif (
            digests is not None
            and path.name.startswith(PROBE_FILE_PREFIX)
            and path.name.endswith(PROBE_FILE_SUFFIX)
        ):
            warnings.warn(
                f"cleanup target {path.name} was never adjudicated; held",
                UserWarning,
                stacklevel=2,
            )
            held.append(path)
            continue
        listed: Mapping[str, str] | None = None
        if (
            digests is not None
            and path.name.startswith(PROBE_FILE_PREFIX)
            and path.name.endswith(PROBE_FILE_SUFFIX)
        ):
            listed = digests
        _, _, hold = _prune_sidecar_tmps(path, listed)
        if not hold:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        if path.exists() or path.is_symlink():
            held.append(path)
    return held


def _producer_files(registry: dict[str, Any], registry_path: Path) -> list[Path]:
    """Return the evidence files owned by one registry (registry first)."""
    sidecar = Path(str(registry.get("sidecar", "")))
    files = [registry_path]
    if str(registry.get("sidecar", "")):
        files.append(sidecar)
        files.append(_journal_for_sidecar(sidecar))
    return files


def _sidecar_tmps(content: dict[str, Any]) -> list[Path] | None:
    """Rewrite tmps keyed off a registry's sidecar name (never raises).

    None when enumeration itself faults (callers hold the baseline).
    """
    sidecar_raw = str(content.get("sidecar", ""))
    if not sidecar_raw:
        return []
    sidecar_path = Path(sidecar_raw)
    return _list_tmp_paths(sidecar_path.parent, f"{sidecar_path.name}.tmp-")


def _partial_record(
    *,
    worker_uuid: str,
    run_id: str,
    unit: str,
    attempt: int,
    pid: int | None,
    block: dict[str, Any],
    receipts: list[dict[str, Any]],
    probes_lost: int = 0,
    role: str = "unit",
    isolation: str = "unknown",
    lost_keys: list[dict[str, Any]] | None = None,
    orphan_keys: list[dict[str, Any]] | None = None,
    recovered_keys: list[dict[str, Any]] | None = None,
    in_flight: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a ``CallCountersPartial`` record (schema-valid).

    Gap-only for dead producers, zero-call loss-only when only a loss
    scalar/keys survive, claim-only when only adopted-orphan evidence
    rides along. ``in_flight`` names entries without returns (#88);
    omitted when empty.
    """
    record: dict[str, Any] = {
        "$report_type": "CallCountersPartial",
        "worker_uuid": worker_uuid,
        "truncated": True,
        "total_calls": block["total_calls"],
        "by_module": block["by_module"],
    }
    if run_id:
        record["run_id"] = run_id
    if unit:
        record["unit"] = unit
    record["attempt"] = attempt
    if pid is not None:
        record["pid"] = pid
    if receipts:
        record["receipts"] = sorted(
            receipts, key=lambda item: (item["worker_uuid"], item["probe_seq"])
        )
    if probes_lost:
        record["probes_lost"] = probes_lost
    if role != "unit":
        record["role"] = role
    if isolation != "unknown":
        record["isolation"] = isolation
    if lost_keys:
        record["lost_keys"] = lost_keys
    if orphan_keys:
        record["orphan_keys"] = orphan_keys
    if recovered_keys:
        record["recovered_keys"] = recovered_keys
    if in_flight:
        record["in_flight"] = in_flight
    return record


def _lost_record(
    *,
    end_state: str,
    worker_uuid: str | None,
    pid: int | None,
    run_id: str,
    unit: str,
    attempt: int | None,
    role: str = "unit",
    isolation: str = "unknown",
) -> dict[str, Any] | None:
    """Build an identity-bearing ``CallCountersLost`` record, else None.

    ``scope_index`` is a placeholder: the extractor rebases it to the
    assembly scope (parents cannot know merge order). None when no identity
    is nameable (nothing to report, nothing lost).
    """
    if worker_uuid is None and pid is None:
        return None
    record: dict[str, Any] = {
        "$report_type": "CallCountersLost",
        "end_state": end_state,
        "scope_index": 0,
    }
    if worker_uuid is not None:
        record["worker_uuid"] = worker_uuid
    if pid is not None:
        record["pid"] = pid
    if run_id:
        record["run_id"] = run_id
    if unit:
        record["unit"] = unit
    if attempt is not None:
        record["attempt"] = attempt
    if role != "unit":
        record["role"] = role
    if isolation != "unknown":
        record["isolation"] = isolation
    return record


def _collect_unreadable_child(
    root: Path,
    reg_dir: Path,
    child_path: Path,
    unit: str,
    current_run: str | None,
) -> list[dict[str, Any]]:
    """Degrade loudly when the child JSONL exists but cannot be read.

    Sessions, entries, and claims are all unknown, so every fold risks
    doubling what extraction later sees: fold nothing, retain every
    file for a later pass, and name one conflict per dead producer in
    unit (codex R2-F1a). Never raises (collection cannot fail verdicts).
    """
    warnings.warn(
        f"call-counter collection cannot read {child_path.name}: "
        "retaining evidence, naming conflict",
        UserWarning,
        stacklevel=3,
    )
    appended: list[dict[str, Any]] = []
    for registry_path in sorted(reg_dir.glob("*.json")):
        content = read_registry_file(registry_path)
        if content is None:
            _reap_torn_registry(root, registry_path)
            continue
        uuid = content["worker_uuid"]
        if content["unit"] != unit:
            continue
        if current_run is not None and content["run_id"] != current_run:
            continue
        if verify_producer(content) != "dead":
            continue
        lost = _lost_record(
            end_state="conflict",
            worker_uuid=uuid,
            pid=content["pid"],
            run_id=content["run_id"],
            unit=content["unit"],
            attempt=content["attempt"],
            role=content["role"],
            isolation=content.get("isolation", "unknown"),
        )
        if lost is not None and _append_collected(child_path, [lost]):
            appended.append(lost)
    return appended


def collect_unit(
    counters_dir: Path | str,
    *,
    unit: str,
    child_jsonl: Path | str,
    status: str,
    returncode: int | None,
    timed_out: bool = False,
    current_run: str | None = None,
) -> list[dict[str, Any]]:
    """Collect one finished attempt's counter evidence into its child JSONL.

    When ``current_run`` is given, registries from other runs are skipped
    (retained, never consumed): a shared counters dir must not let one
    run's collection fold another run's calls (rc2 N-C3).

    For every producer registered under ``unit``: committed producers
    (authoritative session in the child JSONL) are consumed silently
    (delete-after-commit), adopting their retained probe sidecars first
    (covered ones suppressed, uncovered ones folded into a superseded
    claim partial); live producers are skipped untouched; dead producers
    yield a gap-only partial (when recoverable counts remain, probe
    orphans merged in) plus an identity-bearing lost record. Torn
    registries with a surviving sidecar are adopted via the sidecar's
    identity; torn registries without one are zero-loss absent. Consumed
    files are deleted, so collection is idempotent, and extractor dedup
    makes even a crash between append and delete benign (re-collection
    folds exactly once).

    Never raises: I/O failures warn and retain the files for a later pass,
    so counter collection can never fail a run's verdicts.
    """
    root = Path(counters_dir)
    reg_dir = root / REGISTRY_DIRNAME
    if not reg_dir.is_dir():
        return []
    child_path = Path(child_jsonl)
    child_arg = child_path if child_path.exists() else None
    committed = _committed_from_jsonl(child_arg)
    claims = _claimed_receipts_from_jsonl(child_arg)
    if committed is None or claims is None:
        # Unreadable child: sessions, entries, and claims are all
        # unknown, so every fold risks doubling what extraction later
        # sees. Degrade loudly: retain every file for a later pass and
        # name one conflict per dead producer (codex R2-F1a).
        return _collect_unreadable_child(root, reg_dir, child_path, unit, current_run)
    sessions, entries, lenient_sessions = committed
    assert claims is not None
    known_uuids = _known_producer_uuids(root)
    end_state = end_state_for_attempt(status=status, returncode=returncode, timed_out=timed_out)
    appended: list[dict[str, Any]] = []
    seen_sidecar_uuids: set[str] = set()
    read_digests: dict[str, str] = {}
    for registry_path in sorted(reg_dir.glob("*.json")):
        content = read_registry_file(registry_path)
        if content is None:
            # #88R2: an I/O-failed read is unreadable, never torn: reserve
            # the filename uuid so the torn-sidecar sweep cannot adopt a
            # live producer's evidence (and name false losses) this pass.
            reserved = _unreadable_registry_uuid(registry_path)
            if reserved is not None:
                warnings.warn(
                    f"unreadable registry {registry_path.name} retained "
                    "(I/O failure, not torn content; its sidecar waits a later pass)",
                    UserWarning,
                    stacklevel=2,
                )
                seen_sidecar_uuids.add(reserved)
            _reap_torn_registry(root, registry_path)
            continue
        uuid = content["worker_uuid"]
        # Every registry-backed uuid suppresses the torn-sidecar path,
        # foreign runs/units included: a live registry proves the uuid is
        # no orphan, whatever this collection filters out.
        seen_sidecar_uuids.add(uuid)
        if content["unit"] != unit:
            continue
        if current_run is not None and content["run_id"] != current_run:
            continue
        if (content["run_id"], uuid) in sessions:
            try:
                claim_records, consumed, skipped_live = _collect_committed_producer(
                    content,
                    uuid,
                    root=root,
                    known_uuids=known_uuids,
                    claims=claims,
                    digests=read_digests,
                )
            except _DeferProducerError as exc:
                # The session is authoritative but its probe evidence is
                # not decidable this pass (unreadable files): retain the
                # whole producer state for a coherent retry (#88R5-2).
                warnings.warn(
                    f"producer {exc.uuid} deferred: {exc.detail}; evidence retained",
                    UserWarning,
                    stacklevel=2,
                )
                continue
            if _append_collected(child_path, claim_records):
                appended.extend(claim_records)
                if not skipped_live:
                    _consume_producer_files(_producer_files(content, registry_path), read_digests)
                _consume_producer_files(consumed, read_digests)
            continue
        if verify_producer(content) != "dead":
            continue
        try:
            records, consumed = _collect_dead_producer(
                content,
                entries,
                uuid,
                end_state,
                root=root,
                known_uuids=known_uuids,
                claims=claims,
                heal_orphans=_orphan_heal_allowed(lenient_sessions, content["run_id"], uuid),
                digests=read_digests,
            )
        except _DeferProducerError as exc:
            # A live probe writer (or unreadable evidence) survives
            # collection: retain the whole producer state (no records,
            # no consume) so a later pass collects coherently.
            warnings.warn(
                f"producer {exc.uuid} deferred: {exc.detail}; evidence retained",
                UserWarning,
                stacklevel=2,
            )
            continue
        if _append_collected(child_path, records):
            appended.extend(records)
            _consume_producer_files(_producer_files(content, registry_path), read_digests)
            _consume_producer_files(consumed, read_digests)
    for sidecar_path in sorted(root.glob(f"*{SIDECAR_SUFFIX}")):
        adopted = _adopt_orphan_sidecar(sidecar_path, seen_sidecar_uuids)
        if adopted is None:
            continue
        uuid, sidecar = adopted
        if _registry_claims_orphan(reg_dir, uuid):
            # A registry that appeared or healed after the main loop owns
            # this sidecar: skip it this pass (the next pass routes it by
            # its registry instead of adopting it as an orphan).
            continue
        # A registryless sidecar from another unit or run is stale evidence
        # (its barrier owns prior runs): skip it loudly, never misfold it.
        # Live-registry uuids never reach here (``seen_sidecar_uuids`` holds
        # every registry-backed uuid, foreign runs/units included), so these
        # warns fire only for genuinely suspicious torn evidence, not for
        # healthy foreign producers sharing the dir.
        if sidecar.get("unit") != unit:
            warnings.warn(
                f"cross-unit producer sidecar {sidecar_path.name} retained "
                f"(sidecar unit {sidecar.get('unit')!r} != collecting unit {unit!r})",
                UserWarning,
                stacklevel=2,
            )
            continue
        if current_run is not None and sidecar.get("run_id") != current_run:
            warnings.warn(
                f"cross-run producer sidecar {sidecar_path.name} retained "
                f"(sidecar run {sidecar.get('run_id')!r} != collecting run {current_run!r})",
                UserWarning,
                stacklevel=2,
            )
            continue
        journal_path = _journal_for_sidecar(sidecar_path)
        sidecar_run = sidecar.get("run_id")
        sidecar_unit = sidecar.get("unit")
        try:
            journal_lines = _read_journal_lines_strict(journal_path, uuid)
            (
                orphan_block,
                orphan_receipts,
                consumed,
                recovered,
                orphan_keys,
                adopted_lost,
                _skipped_live,
            ) = _adopt_probe_orphans(
                root,
                worker_uuid=uuid,
                sidecar=sidecar,
                journal_lines=journal_lines,
                claims=claims,
                known_uuids=known_uuids,
                producer_run=sidecar_run if isinstance(sidecar_run, str) else None,
                producer_unit=sidecar_unit if isinstance(sidecar_unit, str) else None,
                heal_orphans=_orphan_heal_allowed(
                    lenient_sessions,
                    sidecar_run if isinstance(sidecar_run, str) else None,
                    uuid,
                ),
                fence_live=True,
                digests=read_digests,
            )
        except _DeferProducerError as exc:
            warnings.warn(
                f"producer {exc.uuid} deferred: {exc.detail}; evidence retained",
                UserWarning,
                stacklevel=2,
            )
            continue
        if isinstance(sidecar_run, str) and (sidecar_run, uuid) in sessions:
            records = []
            # Recovery-only evidence still emits its zero-call claim
            # partial (same CX2 rule as the registry-committed path):
            # the session supersedes the zero counts while the
            # recovered_keys harvest pierces supersede to heal it.
            claim_block = (
                orphan_block if orphan_block is not None else {"total_calls": 0, "by_module": {}}
            )
            if orphan_block is not None or recovered or orphan_keys or adopted_lost:
                torn_stamp_role, torn_stamp_isolation = _sidecar_stamp(sidecar)
                records.append(
                    _partial_record(
                        worker_uuid=uuid,
                        run_id=_sidecar_run(sidecar),
                        unit=str(sidecar.get("unit", "")),
                        attempt=sidecar.get("attempt", 0)
                        if _is_nonneg_int(sidecar.get("attempt"))
                        else 0,
                        pid=sidecar.get("pid") if _is_nonneg_int(sidecar.get("pid")) else None,
                        block=claim_block,
                        receipts=orphan_receipts,
                        probes_lost=adopted_lost,
                        role=torn_stamp_role,
                        isolation=torn_stamp_isolation,
                        orphan_keys=_keys_to_wire(orphan_keys),
                        recovered_keys=_keys_to_wire(set(recovered)),
                    )
                )
            if _append_collected(child_path, records):
                appended.extend(records)
                _consume_producer_files([sidecar_path, journal_path], read_digests)
                _consume_producer_files(consumed, read_digests)
            continue
        block, receipts, conflict = _gap_for_producer(sidecar, journal_lines, entries, uuid)
        scalar = sidecar.get("probes_lost") if isinstance(sidecar, dict) else None
        if scalar is None:
            scalar_count = 0
        elif _is_nonneg_int(scalar):
            assert isinstance(scalar, int)
            scalar_count = scalar
        else:
            scalar_count = 0
            conflict = True
        gap_keys = _sidecar_loss_keys(sidecar)
        if orphan_block is not None:
            block = orphan_block if block is None else merge_module_first(block, orphan_block)
            receipts = [*receipts, *orphan_receipts]
        records = []
        if block is None and (scalar_count or gap_keys or orphan_keys or adopted_lost):
            block = {"total_calls": 0, "by_module": {}}
        stamp_role, stamp_isolation = _sidecar_stamp(sidecar)
        if block is not None:
            records.append(
                _partial_record(
                    worker_uuid=uuid,
                    run_id=_sidecar_run(sidecar),
                    unit=str(sidecar.get("unit", "")),
                    attempt=sidecar.get("attempt", 0)
                    if _is_nonneg_int(sidecar.get("attempt"))
                    else 0,
                    pid=sidecar.get("pid") if _is_nonneg_int(sidecar.get("pid")) else None,
                    block=block,
                    receipts=receipts,
                    probes_lost=scalar_count + adopted_lost,
                    role=stamp_role,
                    isolation=stamp_isolation,
                    lost_keys=_keys_to_wire(gap_keys),
                    orphan_keys=_keys_to_wire(orphan_keys),
                    recovered_keys=_keys_to_wire(set(recovered)),
                    in_flight=_in_flight_rows(block),
                )
            )
        lost = _lost_record(
            end_state="conflict" if conflict else end_state,
            worker_uuid=uuid,
            pid=sidecar.get("pid") if _is_nonneg_int(sidecar.get("pid")) else None,
            run_id=_sidecar_run(sidecar),
            unit=str(sidecar.get("unit", "")),
            attempt=sidecar.get("attempt") if _is_nonneg_int(sidecar.get("attempt")) else None,
            role=stamp_role,
            isolation=stamp_isolation,
        )
        if lost is not None:
            records.append(lost)
        if _append_collected(child_path, records):
            appended.extend(records)
            _consume_producer_files(
                [sidecar_path, _journal_for_sidecar(sidecar_path)], read_digests
            )
            _consume_producer_files(consumed, read_digests)
            # The twin funnels through the reaper (valid content and
            # I/O failure retain; only provably-torn content reaps),
            # exactly like the sweep and the main loop (codex R7-F2).
            _reap_torn_registry(root, reg_dir / f"{uuid}.json")
    return appended


def _orphan_heal_allowed(
    lenient_sessions: set[tuple[str, str]], run: str | None, uuid: str
) -> bool:
    """Whether orphan heals are safe for one producer pass.

    Heals are unsafe exactly when extraction could supersede this
    pass's partial (same ``(run, uuid)`` authority staged): the counts
    would die to supersede while the heal pierced it. A known run
    checks membership precisely; an unknown run (torn evidence)
    falls back to uuid-only matching (conservative: extra no-heals
    read spurious-incomplete, never silent-complete).
    """
    if run is None:
        return all(known_uuid != uuid for _, known_uuid in lenient_sessions)
    return (run, uuid) not in lenient_sessions


def _torn_registry_shields_live(root: Path, uuid: str) -> bool:
    """Whether a torn registry guards a live-possible sidecar (#88R4-F5a).

    True when at least one matching sidecar is readable (a dict) or
    unreadable (an I/O fault that must retry): either may still belong
    to a live producer. Proved mutual debris (every match torn, gone,
    or invalid) reads False so the sweep converges it. Never raises.
    """
    try:
        matches = sorted(root.glob(f"{uuid}-*{SIDECAR_SUFFIX}"))
    except OSError:
        return False
    for match in matches:
        status, payload = _read_json_evidence(match)
        if status == "unreadable" or (status == "ok" and isinstance(payload, dict)):
            return True
    return False


def _reap_torn_registry(root: Path, registry_path: Path) -> bool:
    """Delete a torn registry only when no sidecar could still adopt it.

    Triaged on a single read: I/O failure retains (a transient fault
    must never destroy the producer record a later pass needs);
    undecodable or invalid content reaps when no sidecar matches (the
    project writes strict UTF-8, so undecodable bytes are provably
    torn); valid content retains (a fault that healed between the
    caller's read and this one must not delete a healthy record).
    Returns True when the file was unlinked. All registry deletion
    funnels through here (collection and sweep alike) so the triage
    cannot be bypassed.
    """
    try:
        raw: str | None = registry_path.read_text(encoding="utf-8")
    except OSError:
        return False
    except ValueError:
        raw = None
    if raw is not None and _parse_registry_content(registry_path.name, raw) is not None:
        return False
    uuid = parse_registry_filename(registry_path.name)
    if uuid is not None and list(root.glob(f"{uuid}-*{SIDECAR_SUFFIX}")):
        return False
    try:
        registry_path.unlink(missing_ok=True)
    except OSError:
        return False
    return True


def _sidecar_stamp(sidecar: dict[str, Any]) -> tuple[str, str]:
    """Return the (role, isolation) stamp from sidecar content (tolerant).

    Sidecars are unvalidated evidence (unlike registries), so a mistyped
    stamp falls back to the defaults instead of failing the adoption.
    """
    role = sidecar.get("role")
    isolation = sidecar.get("isolation")
    # isinstance narrows for mypy (is_role returns plain bool).
    stamped_role = role if isinstance(role, str) and is_role(role) else "unit"
    stamped_isolation = isolation if isinstance(isolation, str) else "unknown"
    return (stamped_role, stamped_isolation)


def _sidecar_run(sidecar: dict[str, Any]) -> str:
    """Return the sidecar's run stamp (tolerant).

    Sidecars are unvalidated evidence (unlike registries). An absent
    run reads implicit (legacy omits the key; live no-run-id sidecars
    stamp ``""``). A present string stamps itself. Anything else
    (null, mistyped) stamps the ``"unknown"`` sentinel, never
    ``str(value)`` and never implicit: stringifying ``None`` would
    mint a fake ``"None"`` round colliding with session authority
    (codex R7-F1), and implicit would merge corrupt evidence into a
    genuine implicit-round session's authority, dropping the
    checkpoint silently (codex R8-F1).
    """
    if "run_id" not in sidecar:
        return ""
    run = sidecar["run_id"]
    if isinstance(run, str):
        return run
    return _UNKNOWN_RUN


def _strictly_contains(
    first: dict[tuple[str, ...], int], second: dict[tuple[str, ...], int]
) -> bool:
    """Whether replayable vector ``first`` strictly contains ``second``."""
    greater = False
    for key in set(first) | set(second):
        if first.get(key, 0) < second.get(key, 0):
            return False
        if first.get(key, 0) > second.get(key, 0):
            greater = True
    return greater


def _quarantine_tmp(path: Path) -> Path | None:
    """Rename an irreconcilable tmp out of the consume namespace (#88R3).

    Returns the quarantine path, or None when the rename fails (the
    caller then consumes normally and says so). Quarantined names
    carry no ``.tmp-`` infix, so no later glob re-matches them: the
    evidence persists exactly once, for forensic review.
    """
    if ".tmp-" not in path.name:
        return None
    target = path.with_name(path.name.replace(".tmp-", ".quarantined-", 1))
    try:
        os.replace(path, target)
    except OSError:
        return None
    return target


def _quarantine_all(paths: list[Path]) -> tuple[list[str], list[str]]:
    """Quarantine divergent tmps; returns (kept names, dropped names)."""
    kept: list[str] = []
    dropped: list[str] = []
    for path in paths:
        target = _quarantine_tmp(path)
        if target is not None:
            kept.append(target.name)
        else:
            dropped.append(path.name)
    return kept, dropped


def _producer_tmp_gates_clean(
    payload: Any,
    *,
    uuid: str,
    run_id: str,
    unit: str,
    attempt: int,
    pid: int,
    committed_seq: int,
) -> bool:
    """Whether a rewrite-tmp payload gates for replay (#88R6-1).

    Single predicate shared by candidate gating and the quarantine
    veto: a quarantine vetoes only evidence that would gate today
    (same writer, run, unit, attempt, pid, window, and a valid
    block) -- stale quarantines from another incarnation bind
    nothing.
    """
    if not isinstance(payload, dict):
        return False
    if payload.get("worker_uuid") != uuid:
        return False
    if payload.get("run_id") != run_id:
        return False
    if payload.get("unit") != unit:
        return False
    tmp_attempt = payload.get("attempt")
    if type(tmp_attempt) is not int or tmp_attempt != attempt:
        return False
    tmp_pid = payload.get("pid")
    if type(tmp_pid) is not int or tmp_pid != pid:
        return False
    tmp_seq = payload.get("journal_seq")
    if not _is_nonneg_int(tmp_seq) or tmp_seq != committed_seq:
        return False
    return is_module_first_block(payload.get("in_progress"))


def _probe_tmp_gates_clean(
    payload: Any,
    *,
    child_uuid: str,
    seq: int,
    identity: dict[str, Any],
    producer_run: str | None,
    producer_unit: str | None,
    orphan_pid: int | None,
    orphan_birth: int | None,
    producer_uuid: str,
) -> bool:
    """Whether a probe rewrite-tmp payload gates for replay (#88R6-1).

    Single predicate shared by candidate gating and the quarantine
    veto (same writer, seq, stamps, incarnation, and a row list).
    """
    if not isinstance(payload, dict):
        return False
    if payload.get("worker_uuid") != child_uuid:
        return False
    tmp_seq = payload.get("probe_seq")
    if type(tmp_seq) is not int or tmp_seq != seq:
        return False
    if _tmp_stamp_clash(
        payload,
        identity,
        producer_run,
        producer_unit,
        orphan_pid,
        orphan_birth,
        producer_uuid,
    ):
        return False
    return isinstance(payload.get("counters"), list)


def _divergence_vetoed(
    quarantined: list[Path],
    gate: Callable[[Any], bool],
    defer_uuid: str,
) -> bool:
    """Whether a prior divergence decision binds this checkpoint (#88R5-3).

    A quarantined payload vetoes replay only when it passes today's
    gate predicate: same writer, checkpoint, and identity stamps as a
    live candidate would need. Gated candidates always carry those
    fields, so a match proves a previous pass judged THIS checkpoint
    divergent (possibly dying between renames). Torn quarantines match
    nothing; an unreadable one defers the producer rather than vetoing
    (or clearing) silently.
    """
    for path in quarantined:
        status, payload = _read_json_evidence(path)
        if status == "gone":
            continue
        if status == "unreadable":
            raise _DeferProducerError(defer_uuid, None, source=path.name)
        if gate(payload):
            return True
    return False


def _maximal_replayable(
    scored: list[tuple[Any, dict[tuple[str, ...], int]]],
) -> tuple[list[Any], bool]:
    """Split scored tmp candidates into (equivalent maxima, divergent).

    Tokens are opaque (indexes or payloads -- only vectors compare). A
    candidate is maximal when no other candidate's replayable vector
    strictly contains it. Equivalent maxima (identical vectors) select
    deterministically downstream; divergent maxima (no single vector
    contains the rest) flag a conflict instead of picking silently.
    Empty vectors are all equivalent (nothing replayable).
    """
    maximal_indexes = [
        index
        for index, (_, vector) in enumerate(scored)
        if not any(
            _strictly_contains(other, vector)
            for other_index, (_, other) in enumerate(scored)
            if other_index != index
        )
    ]
    if not maximal_indexes:
        return [], False
    first = scored[maximal_indexes[0]][1]
    if any(scored[index][1] != first for index in maximal_indexes):
        return [], True
    return [scored[index][0] for index in maximal_indexes], False


def _block_returns_diff(merged_prog: Any, committed_prog: Any) -> dict[tuple[str, ...], int]:
    """Per-(module, bucket, fn, rv) returns a replay would add (#88R3)."""
    diff: dict[tuple[str, ...], int] = {}
    if not isinstance(merged_prog, dict) or not isinstance(committed_prog, dict):
        return diff
    merged_modules = merged_prog.get("by_module", {})
    committed_modules = committed_prog.get("by_module", {})
    if not isinstance(merged_modules, dict) or not isinstance(committed_modules, dict):
        return diff
    for module, merged_module in merged_modules.items():
        if not isinstance(module, str) or not isinstance(merged_module, dict):
            continue
        own_module = committed_modules.get(module, {})
        if not isinstance(own_module, dict):
            continue
        merged_buckets = merged_module.get("buckets", {})
        own_buckets = own_module.get("buckets", {})
        if not isinstance(merged_buckets, dict) or not isinstance(own_buckets, dict):
            continue
        for bucket, merged_bucket in merged_buckets.items():
            if not isinstance(bucket, str) or not isinstance(merged_bucket, dict):
                continue
            own_bucket = own_buckets.get(bucket, {})
            if not isinstance(own_bucket, dict):
                continue
            merged_fns = merged_bucket.get("by_fn", {})
            own_fns = own_bucket.get("by_fn", {})
            if not isinstance(merged_fns, dict) or not isinstance(own_fns, dict):
                continue
            for fn, merged_leaf in merged_fns.items():
                if not isinstance(fn, str):
                    continue
                own_leaf = own_fns.get(fn, {})
                merged_rv = merged_leaf.get("by_rv", {}) if isinstance(merged_leaf, dict) else {}
                own_rv = own_leaf.get("by_rv", {}) if isinstance(own_leaf, dict) else {}
                if not isinstance(merged_rv, dict) or not isinstance(own_rv, dict):
                    continue
                for rv, merged_item in merged_rv.items():
                    merged_count = (
                        merged_item.get("count") if isinstance(merged_item, dict) else None
                    )
                    own_item = own_rv.get(rv)
                    own_count = own_item.get("count") if isinstance(own_item, dict) else 0
                    if _is_nonneg_int(merged_count) and _is_nonneg_int(own_count):
                        assert isinstance(merged_count, int) and isinstance(own_count, int)
                        if merged_count > own_count:
                            diff[(module, bucket, fn, str(rv))] = merged_count - own_count
    return diff


def _replay_orphan_tmps(
    sidecar_path: Path,
    committed: dict[str, Any] | None,
    *,
    uuid: str,
    run_id: str,
    unit: str,
    attempt: int,
    pid: int,
) -> tuple[dict[str, Any] | None, bool]:
    """Replay the best same-window rewrite tmp, or flag divergence (#88).

    Returns ``(replayed sidecar or None, divergent)``. A K=1 return
    flush that dies inside ``os.replace`` leaves the new payload in a
    complete orphan tmp while the committed sidecar stays pre-return.
    A candidate must parse as a sidecar, bind to the producer's full
    identity (uuid, run, unit, attempt, pid), hold a valid
    in-progress block, and carry the committed window mark: the
    in-progress totals reset at every journal boundary, so only
    same-window snapshots are comparable. Torn, foreign,
    stale-window, or mark-less tmps read as absent, as does every tmp
    when the committed sidecar itself is missing or mark-less.
    Selection scores replayable returns, never raw volume: a stale
    larger snapshot cannot displace a smaller one that actually
    replays. Divergent candidates (no single replayable vector
    contains the rest) keep the committed baseline and flag a
    conflict for the lost record. Only called for dead-or-fenced
    producers. Raises ``_DeferProducerError`` on a persistently
    unreadable candidate (an I/O fault is never a skip).
    """
    if not isinstance(committed, dict):
        return None, False
    committed_seq = committed.get("journal_seq")
    if not _is_nonneg_int(committed_seq):
        return None, False
    assert isinstance(committed_seq, int)
    quarantined = _list_tmp_paths(sidecar_path.parent, f"{sidecar_path.name}.quarantined-")
    if quarantined is None:
        raise _DeferProducerError(uuid, None, source=sidecar_path.name, reason="enum")
    candidates = _list_tmp_paths(sidecar_path.parent, f"{sidecar_path.name}.tmp-")
    if candidates is None:
        raise _DeferProducerError(uuid, None, source=sidecar_path.name, reason="enum")

    def _gates(payload: Any) -> bool:
        return _producer_tmp_gates_clean(
            payload,
            uuid=uuid,
            run_id=run_id,
            unit=unit,
            attempt=attempt,
            pid=pid,
            committed_seq=committed_seq,
        )

    gated: list[tuple[Path, dict[str, Any]]] = []
    for tmp in candidates:
        status, payload = _read_json_evidence(tmp)
        if status == "gone":
            continue
        if status == "unreadable":
            # An I/O fault is never a skip: replaying without this
            # candidate while the prune later deletes it healed would
            # silently drop its return. Defer for a coherent retry.
            raise _DeferProducerError(uuid, None, source=tmp.name)
        if not _gates(payload):
            continue
        assert isinstance(payload, dict)
        gated.append((tmp, payload))
    if quarantined and _divergence_vetoed(quarantined, _gates, uuid):
        # A previous pass already judged this checkpoint divergent but
        # died between renames (or before reporting): re-quarantine any
        # stragglers and hold the conflict without replaying (#88R4-F3).
        # Replaying a lone survivor would silently publish one side of
        # the conflict the quarantine already decided. Only a
        # same-writer, same-window quarantine vetoes (#88R5-3).
        kept, dropped = _quarantine_all([tmp for tmp, _ in gated])
        prior = ", ".join(path.name for path in quarantined)
        detail = f"quarantined: {prior}"
        if kept:
            detail += f"; re-quarantined stragglers: {', '.join(kept)}"
        warnings.warn(
            f"rewrite tmps under {sidecar_path.name} already divergent "
            f"({detail}): conflict held, committed wins"
            + (f"; dropped {dropped} (quarantine failed)" if dropped else ""),
            UserWarning,
            stacklevel=2,
        )
        return None, True
    if not gated:
        return None, False
    committed_prog = committed.get("in_progress")
    vectors: list[dict[tuple[str, ...], int]] = []
    merged_sides: list[dict[str, Any]] = []
    for _, payload in gated:
        merged = _replay_tmp_returns(committed, payload)
        merged_sides.append(merged)
        vectors.append(_block_returns_diff(merged.get("in_progress"), committed_prog))
    winner_indexes, divergent = _maximal_replayable(
        [(index, vector) for index, vector in enumerate(vectors)]
    )
    if divergent:
        kept, dropped = _quarantine_all([tmp for tmp, _ in gated])
        warnings.warn(
            f"divergent rewrite tmps under {sidecar_path.name} quarantined: "
            f"{', '.join(kept)} (irreconcilable snapshots; committed wins)"
            + (f"; dropped {dropped} (quarantine failed)" if dropped else ""),
            UserWarning,
            stacklevel=2,
        )
        return None, True
    if all(not vector for vector in vectors):
        # Loss-only adoption (#88R4-F2): no RV advanced, but gated
        # candidates may still carry newer loss metadata (a loss-note
        # rewrite has an empty return vector by construction). The
        # per-side merges below already passed the suppression-bearing
        # coverage guard, so only guard-clean losses union. Shallow
        # copy: the union replaces top-level loss fields only, and a
        # deep copy would recurse into unbounded extension fields
        # (#88R5-5). Aliasing matches the winner path (whose merge is
        # shallow above in-progress); downstream readers never mutate.
        loss_only = dict(committed)
        if _apply_loss_union(loss_only, committed, merged_sides):
            return loss_only, False
        return None, False
    winner = max(
        winner_indexes,
        key=lambda index: gated[index][1]["in_progress"]["total_calls"],
    )
    merged = merged_sides[winner]
    _apply_loss_union(merged, committed, merged_sides)
    return merged, False


def _apply_loss_union(
    target: dict[str, Any],
    committed: dict[str, Any],
    sides: list[dict[str, Any]],
) -> bool:
    """Union loss metadata from replayed sides onto ``target`` (#88R4-F2).

    Loss keys never suppress orphan folds and the scalar is monotonic,
    so every guard-clean candidate's losses join whether or not any RV
    advanced. Suppression-bearing coverage is never unioned (the sides
    passed that guard in ``_replay_tmp_returns``). Returns True when
    the target advanced beyond ``committed``.
    """
    united = _loss_keyset(committed)
    for side in sides:
        united |= _loss_keyset(side)
    scalars: list[int] = []
    for side in [committed, *sides]:
        value = side.get("probes_lost")
        if _is_nonneg_int(value):
            assert isinstance(value, int)
            scalars.append(value)
    advanced = False
    if united != _loss_keyset(committed):
        target["lost_keys"] = _keys_to_wire(united)
        advanced = True
    if scalars and max(scalars) != committed.get("probes_lost"):
        target["probes_lost"] = max(scalars)
        advanced = True
    return advanced


def _coverage_keyset(payload: dict[str, Any]) -> set[tuple[str, int]]:
    """Suppression-bearing coverage a sidecar claims (receipts + consumed).

    Only these keys suppress orphan folds (``_durable_receipts``); loss
    metadata (``lost_keys``, ``probes_lost``) names losses without
    suppressing anything, so it unions independently of replay.
    """
    keys: set[tuple[str, int]] = set()
    for field in ("receipts", "consumed_probes"):
        items = payload.get(field)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            first, second = item.get("worker_uuid"), item.get("probe_seq")
            if isinstance(first, str) and _is_nonneg_int(second):
                assert isinstance(second, int)
                keys.add((first, second))
    return keys


def _loss_keyset(payload: dict[str, Any]) -> set[tuple[str, int]]:
    """Keyed-loss set a sidecar claims (never suppresses folds)."""
    keys: set[tuple[str, int]] = set()
    items = payload.get("lost_keys")
    if not isinstance(items, list):
        return keys
    for item in items:
        if not isinstance(item, dict):
            continue
        first, second = item.get("parent_uuid"), item.get("probe_seq")
        if isinstance(first, str) and _is_nonneg_int(second):
            assert isinstance(second, int)
            keys.add((first, second))
    return keys


def _rv_superset(tmp_rv: dict[str, Any], own_rv: dict[str, Any]) -> bool:
    """Whether tmp by_rv counts contain the committed ones per RV (#88R3)."""
    for rv, own_item in own_rv.items():
        own_count = own_item.get("count") if isinstance(own_item, dict) else None
        tmp_item = tmp_rv.get(rv)
        tmp_count = tmp_item.get("count") if isinstance(tmp_item, dict) else None
        if not _is_nonneg_int(own_count) or not _is_nonneg_int(tmp_count):
            return False
        assert isinstance(own_count, int) and isinstance(tmp_count, int)
        if tmp_count < own_count:
            return False
    return True


def _replay_tmp_returns(committed: dict[str, Any], tmp: dict[str, Any]) -> dict[str, Any]:
    """Replay a same-window tmp's returns onto committed entries (#88).

    Entries are NEVER adopted: a tmp holding newer entry counts is an
    uncommitted admission snapshot (at K=1 its provider never ran --
    the failed flush rolls back and blocks dispatch), so adopting it
    would report calls that never happened. A leaf replays only on an
    exact entry-population match whose tmp returns contain the
    committed ones per RV (#88R3): returns are unattributable across
    differing populations (an unkeyed ingest's return belongs to a
    call the committed leaf never saw) and across divergent RV sets
    (max-union would fabricate returns neither snapshot holds); both
    keep the committed leaf untouched and stay named in-flight.
    Coverage stays coupled to its counts (#88R3):
    a tmp naming coverage the committed sidecar lacks is an ingest
    checkpoint, and replaying its returns would orphan the only other
    copy -- so it replays nothing and the orphan folds normally. The
    loss scalar takes the max when both sides type-check (adopted
    as-is when the committed sidecar omits it; a mistyped committed
    scalar stays untouched for the gap arms to conflict on). The
    window mark is preserved, so the gap arms treat the replayed sidecar
    exactly as the committed one. Returns ``committed`` unchanged
    when its in-progress block is invalid (the gap arms conflict on
    it as before); callers pass a validated tmp.
    """
    in_progress = committed.get("in_progress")
    if not is_module_first_block(in_progress):
        return committed
    tmp_progress = tmp.get("in_progress")
    if not is_module_first_block(tmp_progress):
        return committed
    if not _coverage_keyset(tmp) <= _coverage_keyset(committed):
        return committed
    merged_prog: dict[str, Any] = copy.deepcopy(in_progress)
    for module, tmp_module in tmp_progress["by_module"].items():
        own_module = merged_prog["by_module"].get(module)
        if not isinstance(own_module, dict):
            continue
        for bucket, tmp_bucket in tmp_module.get("buckets", {}).items():
            own_bucket = own_module.get("buckets", {}).get(bucket)
            if not isinstance(own_bucket, dict):
                continue
            for fn, tmp_leaf in tmp_bucket.get("by_fn", {}).items():
                own_leaf = own_bucket.get("by_fn", {}).get(fn)
                if not isinstance(own_leaf, dict) or not isinstance(tmp_leaf, dict):
                    continue
                # Population match (#88R3): returns are unattributable
                # across differing entry counts (an unkeyed ingest's
                # return belongs to a call the committed leaf never
                # saw), so only identical populations replay.
                own_calls = own_leaf.get("calls")
                tmp_calls = tmp_leaf.get("calls")
                if (
                    not _is_nonneg_int(own_calls)
                    or not _is_nonneg_int(tmp_calls)
                    or own_calls != tmp_calls
                ):
                    continue
                own_rv = own_leaf.get("by_rv")
                tmp_rv = tmp_leaf.get("by_rv")
                if not isinstance(own_rv, dict) or not isinstance(tmp_rv, dict):
                    continue
                if not _rv_superset(tmp_rv, own_rv):
                    # Divergent returns (neither side contains the other)
                    # keep the committed leaf: max-union would fabricate
                    # returns neither snapshot holds.
                    continue
                for rv, tmp_item in tmp_rv.items():
                    tmp_count = tmp_item.get("count") if isinstance(tmp_item, dict) else None
                    if not _is_nonneg_int(tmp_count):
                        continue
                    own_item = own_rv.get(rv)
                    if isinstance(own_item, dict):
                        own_item["count"] = tmp_count
                    else:
                        own_rv[rv] = {
                            "name": tmp_item.get("name") if isinstance(tmp_item, dict) else None,
                            "count": tmp_count,
                        }
    merged = dict(committed)
    merged["in_progress"] = merged_prog
    # Loss metadata unions independently of the returns replay: loss
    # keys never suppress orphan folds, so a tmp's newer losses join
    # the committed set even when (and especially when) its returns
    # replay. Suppression-bearing coverage is never unioned (ingest
    # checkpoints return above).
    united_losses = _loss_keyset(committed) | _loss_keyset(tmp)
    if united_losses:
        merged["lost_keys"] = _keys_to_wire(united_losses)
    else:
        merged.pop("lost_keys", None)
    own_lost = committed.get("probes_lost")
    tmp_lost = tmp.get("probes_lost")
    if _is_nonneg_int(tmp_lost):
        assert isinstance(tmp_lost, int)
        if own_lost is None:
            # The committed sidecar predates (or omits) the scalar: the
            # tmp's valid scalar is pure gain, adopted as-is.
            merged["probes_lost"] = tmp_lost
        elif _is_nonneg_int(own_lost):
            assert isinstance(own_lost, int)
            merged["probes_lost"] = max(own_lost, tmp_lost)
        # A mistyped committed scalar stays untouched: the gap arms
        # conflict on it loudly instead of silently adopting over it.
    return merged


def _in_flight_rows(block: dict[str, Any]) -> list[dict[str, Any]]:
    """Name every (module, bucket, fn) with entries but no return (#88).

    Sorted for determinism. Malformed leaves are skipped defensively
    (callers pass gap blocks, already valid); a lone return without
    an entry never rows (negative gaps are a different anomaly).
    """
    rows: list[dict[str, Any]] = []
    by_module = block.get("by_module")
    if not isinstance(by_module, dict):
        return []
    for module in sorted(key for key in by_module if isinstance(key, str)):
        module_block = by_module[module]
        buckets = module_block.get("buckets") if isinstance(module_block, dict) else None
        if not isinstance(buckets, dict):
            continue
        for bucket in sorted(key for key in buckets if isinstance(key, str)):
            bucket_block = buckets[bucket]
            by_fn = bucket_block.get("by_fn") if isinstance(bucket_block, dict) else None
            if not isinstance(by_fn, dict):
                continue
            for fn in sorted(key for key in by_fn if isinstance(key, str)):
                leaf = by_fn[fn]
                if not isinstance(leaf, dict):
                    continue
                calls = leaf.get("calls")
                by_rv = leaf.get("by_rv")
                if not _is_nonneg_int(calls) or not isinstance(by_rv, dict):
                    continue
                assert isinstance(calls, int)
                returned = 0
                for item in by_rv.values():
                    count = item.get("count") if isinstance(item, dict) else None
                    if _is_nonneg_int(count):
                        assert isinstance(count, int)
                        returned += count
                if calls - returned > 0 and bucket and fn:
                    # The module keeps the unknown-module sentinel ("")
                    # when the call carried no handle (issue #87 item 6).
                    rows.append(
                        {"module": module, "bucket": bucket, "fn": fn, "count": calls - returned}
                    )
    return rows


def _unreadable_registry_uuid(registry_path: Path) -> str | None:
    """Return the filename uuid when a registry read fails I/O-side (#88R2).

    Permission and other OS read errors are unreadable, never torn: the
    caller reserves the uuid so the torn-sidecar sweep cannot adopt a
    live producer's evidence this pass. Missing files, undecodable
    bytes, and readable content all return None (gone, torn, or owned
    -- none of which reserve).
    """
    try:
        Path(registry_path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except ValueError:
        return None
    except OSError:
        return parse_registry_filename(Path(registry_path).name)
    return None


def _registry_claims_orphan(reg_dir: Path, uuid: str) -> bool:
    """Whether a registry file currently owns one uuid (#88R2).

    The adoption-time probe against mid-pass races (a registry that
    appeared or healed after the main loop): present-and-parsing
    means owned, never orphan. Anything else (missing, torn,
    unreadable) leaves the torn path to decide.
    """
    return read_registry_file(reg_dir / f"{uuid}.json") is not None


def _adopt_orphan_sidecar(sidecar_path: Path, seen: set[str]) -> tuple[str, dict[str, Any]] | None:
    """Adopt a sidecar with no live registry via its carried identity."""
    sidecar = read_json_file(sidecar_path)
    if not isinstance(sidecar, dict):
        return None
    uuid = sidecar.get("worker_uuid")
    if not is_worker_uuid(uuid) or uuid in seen:
        return None
    assert isinstance(uuid, str)
    if not isinstance(sidecar.get("unit"), str) or not sidecar.get("unit"):
        return None
    pid = sidecar.get("pid")
    if _is_nonneg_int(pid):
        # Quiescence (#88R2, strict #88R3): without a birth anchor the
        # only sound question is presence -- a pid that names anything
        # alive (or unreadable: EPERM proves existence too) may still
        # be the producer, so the sidecar retains for a later pass
        # instead of folding (and naming losses) under a live writer.
        # Only a proven-dead pid (lookup failure) adopts; recycled
        # slots delay one pass, never misfold.
        assert isinstance(pid, int)
        if _pid_exists(pid):
            return None
    return (uuid, sidecar)


def _read_journal_lines(journal_path: Path) -> list[str]:
    """Read raw journal lines (missing file reads as empty, never raises)."""
    try:
        text = journal_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return []
    return [line for line in text.splitlines() if line.strip()]


def _read_journal_lines_strict(journal_path: Path, uuid: str) -> list[str]:
    """Read journal lines; a persistent I/O fault defers the producer (#88R4-F1).

    Missing files read as empty (most producers never journal) and
    undecodable bytes keep the legacy errors="replace" read with
    per-line skips; only a proven-persistent read fault raises
    ``_DeferProducerError`` (a sidecar-only gap would orphan the
    journal's windows once consumed).
    """
    attempts = 0
    while True:
        try:
            text = journal_path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return []
        except OSError:
            attempts += 1
            if attempts >= 3:
                raise _DeferProducerError(uuid, None, source=journal_path.name) from None
            time.sleep(0.001)
            continue
        except ValueError:
            return []
        return [line for line in text.splitlines() if line.strip()]


def _collect_dead_producer(
    content: dict[str, Any],
    entries: set[tuple[str, str]],
    uuid: str,
    end_state: str,
    *,
    root: Path,
    known_uuids: set[str],
    claims: dict[str, set[tuple[str, int]]],
    heal_orphans: bool = True,
    digests: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], list[Path]]:
    """Build the partial+lost records for one dead producer (reads orphans only).

    Returns ``(records, consumed_orphans)``: the caller's append-then-delete
    consumes the orphan files only after the records land in the JSONL.
    """
    sidecar_raw = str(content.get("sidecar", ""))
    sidecar_path = Path(sidecar_raw)
    sidecar: Any | None = None
    if sidecar_raw:
        status, raw_sidecar = _read_json_evidence(sidecar_path)
        if status == "unreadable":
            # A journal-only gap would orphan the sidecar's in-progress
            # snapshot once consumed: defer for a coherent retry.
            raise _DeferProducerError(uuid, None, source=sidecar_path.name)
        if status != "gone" and isinstance(raw_sidecar, dict):
            sidecar = raw_sidecar
    divergent_tmps = False
    if sidecar_raw:
        # #88: a same-window orphan rewrite tmp replays the return its
        # death orphaned (dead-or-fenced producers only; torn, foreign,
        # or stale-window tmps read as absent). Returns merge onto
        # committed entries; entry counts are never adopted (a tmp
        # holding newer entries is an uncommitted admission snapshot).
        # Divergent tmps keep the committed baseline and conflict.
        replayed, divergent_tmps = _replay_orphan_tmps(
            sidecar_path,
            sidecar if isinstance(sidecar, dict) else None,
            uuid=uuid,
            run_id=content["run_id"],
            unit=content["unit"],
            attempt=content["attempt"],
            pid=content["pid"],
        )
        if replayed is not None:
            sidecar = replayed
    journal_lines = (
        _read_journal_lines_strict(_journal_for_sidecar(sidecar_path), uuid) if sidecar_raw else []
    )
    block, receipts, conflict = _gap_for_producer(sidecar, journal_lines, entries, uuid)
    conflict = conflict or divergent_tmps
    scalar = sidecar.get("probes_lost") if isinstance(sidecar, dict) else None
    if scalar is None:
        scalar_count = 0
    elif _is_nonneg_int(scalar):
        assert isinstance(scalar, int)
        scalar_count = scalar
    else:
        # Fail closed: an unreadable loss scalar conflicts loudly instead of
        # inventing (or silently dropping) a loss count.
        scalar_count = 0
        conflict = True
    gap_keys = _sidecar_loss_keys(sidecar)
    (
        orphan_block,
        orphan_receipts,
        consumed,
        recovered,
        orphan_keys,
        adopted_lost,
        _skipped_live,
    ) = _adopt_probe_orphans(
        root,
        worker_uuid=uuid,
        sidecar=sidecar,
        journal_lines=journal_lines,
        claims=claims,
        known_uuids=known_uuids,
        producer_run=content["run_id"],
        producer_unit=content["unit"],
        heal_orphans=heal_orphans,
        fence_live=True,
        digests=digests,
    )
    if orphan_block is not None:
        block = orphan_block if block is None else merge_module_first(block, orphan_block)
        receipts = [*receipts, *orphan_receipts]
    records: list[dict[str, Any]] = []
    if block is None and (scalar_count or gap_keys or orphan_keys or adopted_lost):
        # No counts but real losses: still emit them (a zero-call partial),
        # so validated loss evidence never silently drops. Recovered-only
        # (nothing claimed anywhere) emits nothing: the lost record below
        # already names the death.
        block = {"total_calls": 0, "by_module": {}}
    if block is not None:
        records.append(
            _partial_record(
                worker_uuid=uuid,
                run_id=content["run_id"],
                unit=content["unit"],
                attempt=content["attempt"],
                pid=content["pid"],
                block=block,
                receipts=receipts,
                probes_lost=scalar_count + adopted_lost,
                role=content["role"],
                isolation=content.get("isolation", "unknown"),
                lost_keys=_keys_to_wire(gap_keys),
                orphan_keys=_keys_to_wire(orphan_keys),
                recovered_keys=_keys_to_wire(set(recovered)),
                in_flight=_in_flight_rows(block),
            )
        )
    lost = _lost_record(
        end_state="conflict" if conflict else end_state,
        worker_uuid=uuid,
        pid=content["pid"],
        run_id=content["run_id"],
        unit=content["unit"],
        attempt=content["attempt"],
        role=content["role"],
        isolation=content.get("isolation", "unknown"),
    )
    if lost is not None:
        records.append(lost)
    return records, consumed


def _collect_committed_producer(
    content: dict[str, Any],
    uuid: str,
    *,
    root: Path,
    known_uuids: set[str],
    claims: dict[str, set[tuple[str, int]]],
    digests: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], list[Path], bool]:
    """Adopt one committed producer's probe orphans (claim-only partial, never lost).

    The session already holds the producer's counts, so a partial appends
    only for uncovered orphans: orphan counts under the parent uuid (the
    session supersedes them at extraction, keeping totals exact) that
    claims the receipts. Covered orphans consume silently. No lost record
    ever emits here: the producer lived, so a loss claim would be false.
    The third element reports skipped-live orphans, whose parent files
    the caller must retain (not consume) for a coherent retry
    (#88R11-1).
    """
    sidecar_raw = str(content.get("sidecar", ""))
    sidecar_path = Path(sidecar_raw)
    sidecar = read_json_file(sidecar_path) if sidecar_raw else None
    journal_lines = _read_journal_lines(_journal_for_sidecar(sidecar_path)) if sidecar_raw else []
    (
        orphan_block,
        orphan_receipts,
        consumed,
        recovered,
        orphan_keys,
        adopted_lost,
        skipped_live,
    ) = _adopt_probe_orphans(
        root,
        worker_uuid=uuid,
        sidecar=sidecar,
        journal_lines=journal_lines,
        claims=claims,
        known_uuids=known_uuids,
        producer_run=content["run_id"],
        producer_unit=content["unit"],
        heal_orphans=False,
        fence_live=False,
        digests=digests,
    )
    if orphan_block is None and not recovered and not orphan_keys and not adopted_lost:
        return [], consumed, skipped_live
    # Claim-only: orphan evidence rides orphan_keys (union-always); no gap
    # set (the live session is authoritative for this producer's own keys).
    # Recovery-only evidence (a consumed marker's healed identity, or an
    # empty orphan's) still emits a zero-call partial: dropping it would
    # delete the heal the session's loss claim waits for (codex CX2). The
    # session supersedes the zero counts at extraction; the recovered_keys
    # harvest pierces supersede by design.
    block = orphan_block if orphan_block is not None else {"total_calls": 0, "by_module": {}}
    return (
        [
            _partial_record(
                worker_uuid=uuid,
                run_id=content["run_id"],
                unit=content["unit"],
                attempt=content["attempt"],
                pid=content["pid"],
                block=block,
                receipts=orphan_receipts,
                probes_lost=adopted_lost,
                role=content["role"],
                isolation=content.get("isolation", "unknown"),
                orphan_keys=_keys_to_wire(orphan_keys),
                recovered_keys=_keys_to_wire(set(recovered)),
            )
        ],
        consumed,
        skipped_live,
    )


def _append_collected(child_path: Path, records: list[dict[str, Any]]) -> bool:
    """Append collected records to a child JSONL (warn-and-retain on failure)."""
    if not records:
        return True
    try:
        with open(child_path, "a", encoding="utf-8") as fh:
            for record in records:
                fh.write(json.dumps(record) + "\n")
    except OSError as exc:
        warnings.warn(
            f"counter collection for {child_path} failed ({exc}); "
            "evidence retained on disk for a later pass",
            UserWarning,
            stacklevel=3,
        )
        return False
    return True


def _uuid_from_evidence_name(name: str) -> str | None:
    """Return the producer uuid bound by a sidecar/journal filename, else None."""
    for suffix in (SIDECAR_SUFFIX, JOURNAL_SUFFIX):
        if name.endswith(suffix):
            stem = name[: -len(suffix)]
            candidate = stem.split("-", 1)[0]
            return candidate if is_worker_uuid(candidate) else None
    return None


def sweep_orphans(
    counters_dir: Path | str,
    *,
    current_run: str | None,
    committed_uuids: frozenset[str] = frozenset(),
    collected_runs: frozenset[str] = frozenset(),
    retain_uuids: frozenset[str] = frozenset(),
) -> dict[str, int]:
    """Delete provably-consumable evidence files; retain everything else.

    Removes: committed producers' files (uuid with an authoritative
    session), runs fully collected by a resume barrier (never the current
    run, even if a caller mislists it), torn registries with no adoptable
    sidecar, torn sidecars (a present registry shields a readable
    sidecar even when torn itself; mutual debris clears the torn
    baseline and reaps the registry on the next pass), journals with no
    sidecar (undisambiguable debris), and torn probe sidecars. Removed
    sidecars take their rewrite tmps with them on the authoritative
    paths (committed/collected runs); torn baselines prune tmps by
    content first (complete ones retain loudly for forensics). Retains:
    everything else, including live producers' files (verified before
    any destructive decision), unreadable files (an I/O fault never
    proves debris), valid probe orphans (only collection proves them
    consumable), other-run evidence no barrier has claimed, and every
    file attributable to ``retain_uuids`` (#88R3: barrier-retained
    producers whose run credited collected via siblings). Idempotent:
    a second sweep removes nothing further (mutual debris converges in
    two passes). Never raises.
    """
    root = Path(counters_dir)
    removed = 0
    retained = 0
    reg_dir = root / REGISTRY_DIRNAME
    if not reg_dir.is_dir():
        return {"removed": 0, "retained": 0}

    def _remove(paths: list[Path]) -> None:
        nonlocal removed, retained
        for path in paths:
            if not path.exists() and not path.is_symlink():
                continue
            try:
                path.unlink()
                removed += 1
            except OSError:
                retained += 1

    def _remove_with_tmps(paths: list[Path], tmps: list[Path] | None) -> None:
        """Authoritative removal, tmps first (#88R5-6).

        The tmps key off the baseline name, so the baseline goes only
        when every tmp is gone: a failed tmp unlink holds the whole
        set for the next sweep to rediscover and retry (silent +
        counted: the retained count already surfaces, and the next
        pass converges). An unlistable tmp set holds too (#88R7-4).
        """
        nonlocal removed, retained
        if tmps is None:
            for path in paths:
                if path.exists() or path.is_symlink():
                    retained += 1
            return
        for index, tmp in enumerate(tmps):
            if not tmp.exists() and not tmp.is_symlink():
                continue
            try:
                tmp.unlink()
                removed += 1
            except OSError:
                # Every survivor counts: the failed tmp, the unvisited
                # rest, and the held primaries (#88R6-3).
                for rest in tmps[index:]:
                    if rest.exists() or rest.is_symlink():
                        retained += 1
                for path in paths:
                    if path.exists() or path.is_symlink():
                        retained += 1
                return
        _remove(paths)

    for registry_path in sorted(reg_dir.glob("*.json")):
        claimed = parse_registry_filename(registry_path.name)
        if claimed is not None and claimed in retain_uuids:
            retained += 1
            continue
        content = read_registry_file(registry_path)
        if content is None:
            if _reap_torn_registry(root, registry_path):
                removed += 1
            else:
                retained += 1
            continue
        uuid = content["worker_uuid"]
        if uuid in committed_uuids:
            _remove_with_tmps(_producer_files(content, registry_path), _sidecar_tmps(content))
            continue
        run_id = content["run_id"]
        if run_id in collected_runs and run_id != current_run:
            if verify_producer(content) == "alive":
                retained += len([p for p in _producer_files(content, registry_path)])
            else:
                _remove_with_tmps(_producer_files(content, registry_path), _sidecar_tmps(content))
            continue
        retained += 1
        sidecar_raw = str(content.get("sidecar", ""))
        if sidecar_raw:
            sidecar_path = Path(sidecar_raw)
            if sidecar_path.exists():
                retained += 1
            if _journal_for_sidecar(sidecar_path).exists():
                retained += 1
    for sidecar_path in sorted(root.glob(f"*{SIDECAR_SUFFIX}")):
        uuid = _uuid_from_evidence_name(sidecar_path.name)
        if uuid is None:
            continue
        if uuid in retain_uuids:
            retained += 1
            if _journal_for_sidecar(sidecar_path).exists():
                retained += 1
            continue
        reg_path = reg_dir / f"{uuid}.json"
        if reg_path.exists() and read_registry_file(reg_path) is not None:
            continue
        status, sidecar = _read_json_evidence(sidecar_path)
        journal_path = _journal_for_sidecar(sidecar_path)
        if status == "gone":
            continue
        if uuid in committed_uuids:
            _remove_with_tmps(
                [sidecar_path, journal_path],
                _list_tmp_paths(sidecar_path.parent, f"{sidecar_path.name}.tmp-"),
            )
        elif status == "unreadable" or (reg_path.exists() and isinstance(sidecar, dict)):
            # An I/O fault proves nothing either way (retry later), and a
            # present registry shields a readable sidecar even when the
            # registry itself is torn (a live producer's evidence must
            # never die to a sibling-credited collected run).
            retained += 1
            if journal_path.exists():
                retained += 1
        elif not isinstance(sidecar, dict):
            # Provably unusable evidence. A torn registry alongside is
            # mutual debris: the torn baseline goes (the registry reaps
            # on the next pass), but rewrite tmps triage by content --
            # complete ones retain loudly for forensics (F1), never
            # silently with the baseline.
            pruned, kept, hold = _prune_sidecar_tmps(sidecar_path)
            removed += pruned
            retained += kept
            if hold:
                retained += 1
            else:
                _remove([sidecar_path])
        elif sidecar.get("run_id") in collected_runs and sidecar.get("run_id") != current_run:
            _remove_with_tmps(
                [sidecar_path, journal_path],
                _list_tmp_paths(sidecar_path.parent, f"{sidecar_path.name}.tmp-"),
            )
        else:
            retained += 1
            if journal_path.exists():
                retained += 1
    for journal_path in sorted(root.glob(f"*{JOURNAL_SUFFIX}")):
        uuid = _uuid_from_evidence_name(journal_path.name)
        if uuid is None:
            continue
        if uuid in retain_uuids:
            retained += 1
            continue
        stem = journal_path.name[: -len(JOURNAL_SUFFIX)]
        if list(root.glob(f"{stem}{SIDECAR_SUFFIX}")):
            continue
        if (reg_dir / f"{uuid}.json").exists():
            retained += 1
            continue
        _remove([journal_path])
    for probe_path in sorted(root.glob(f"{PROBE_FILE_PREFIX}*{PROBE_FILE_SUFFIX}")):
        status, raw = _read_json_evidence(probe_path)
        if status == "gone":
            continue
        if status == "unreadable":
            # An I/O fault is never debris: the baseline and its tmps
            # wait for a later pass (a fault that heals must find the
            # evidence it almost destroyed).
            retained += 1
            continue
        if raw is None or not isinstance(raw, dict):
            pruned, kept, hold = _prune_sidecar_tmps(probe_path)
            removed += pruned
            retained += kept
            if hold:
                retained += 1
            else:
                _remove([probe_path])
        else:
            retained += 1
    return {"removed": removed, "retained": retained}


def _write_barrier_staging(
    root: Path,
    cache_records: dict[str, list[dict[str, Any]]],
    consumed: int,
    collected: Collection[str],
    targets: Collection[tuple[str, str]],
) -> bool:
    """Persist the collected barrier plan atomically (never raises).

    ``collected`` carries the worker uuids whose evidence this barrier
    took into consumption: a retry finishes their cleanup without
    adjudicating (and re-emitting) the evidence again (#88R9-4).
    ``targets`` carries the exact adjudicated probe cleanup targets as
    ``(path, sha256)`` pairs: a retry adopts only listed, byte-identical
    slots, never newly discovered ones (#88R11-6).
    """
    path = root / BARRIER_STAGING_FILENAME
    tmp = path.with_name(f"{path.name}.tmp-{os.getpid()}")
    try:
        tmp.write_text(
            json.dumps(
                {
                    "cache_records": cache_records,
                    "consumed": consumed,
                    "collected_uuids": sorted(set(collected)),
                    "cleanup_targets": [
                        {"path": target_path, "sha256": digest}
                        for target_path, digest in sorted(set(targets))
                    ],
                }
            ),
            encoding="utf-8",
        )
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False
    for leftover in root.glob(f"{BARRIER_STAGING_FILENAME}.tmp-*"):
        try:
            leftover.unlink()
        except OSError:
            pass
    return True


def _load_barrier_staging(
    root: Path,
) -> tuple[dict[str, list[dict[str, Any]]], int, frozenset[str], frozenset[tuple[str, str]]]:
    """Load retained staging ``(cache_records, consumed, collected, targets)``.

    Absent reads empty. Torn or misshapen staging warns loudly (staged
    recovery evidence may be lost: atomic writes make this
    corruption-only) and the debris is discarded. A malformed
    ``collected_uuids`` list degrades leniently to empty (pre-key
    staging behaves exactly as before). A malformed ``cleanup_targets``
    list degrades to empty with a loud warning (probe adoption
    disables for the pass); an absent list reads empty silently
    (pre-targets staging adopts nothing until re-staged). Never raises.
    """
    path = root / BARRIER_STAGING_FILENAME
    if not path.exists():
        return {}, 0, frozenset(), frozenset()
    try:
        raw = _json_loads_evidence(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raw = None
    records = raw.get("cache_records") if isinstance(raw, dict) else None
    consumed = raw.get("consumed") if isinstance(raw, dict) else 0
    if (
        not isinstance(records, dict)
        or not all(isinstance(per_unit, list) for per_unit in records.values())
        or not isinstance(consumed, int)
    ):
        warnings.warn(
            f"counter barrier staging {path} is torn; staged recovery evidence may be lost",
            UserWarning,
            stacklevel=2,
        )
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return {}, 0, frozenset(), frozenset()
    collected: frozenset[str] = frozenset()
    claimed_clean = True
    if isinstance(raw, dict):
        claimed = raw.get("collected_uuids", [])
        if isinstance(claimed, list) and all(isinstance(uuid, str) for uuid in claimed):
            collected = frozenset(claimed)
        elif "collected_uuids" in raw:
            # Every present-but-malformed field warns: only an absent
            # list reads clean (pre-key staging behaves as before).
            # A falsy-malformed value degrades the same loud way as a
            # truthy one (#88R10-4b).
            claimed_clean = False
            warnings.warn(
                f"counter barrier staging {path} has a malformed collected_uuids list; "
                "retried producers may re-emit already-staged records",
                UserWarning,
                stacklevel=2,
            )
    assert isinstance(records, dict) and isinstance(consumed, int)
    if claimed_clean and isinstance(raw, dict) and "collected_uuids" in raw:
        if consumed != len(collected):
            # The writer stages consumed == len(collected_uuids)
            # exactly (both count the same collected population), so a
            # mismatch is corruption and warns loudly. Suppression
            # itself stays per-uuid (staged evidence or session behind
            # each claim): degrading the whole set on a count mismatch
            # would re-emit valid staged records a second time, while
            # unmentioned claims still drop at validation (#88R10-4b).
            warnings.warn(
                f"counter barrier staging {path} claims {len(collected)} collected uuids "
                "for a consumed count of "
                f"{consumed}; per-uuid evidence still decides suppression",
                UserWarning,
                stacklevel=2,
            )
    targets: frozenset[tuple[str, str]] = frozenset()
    if isinstance(raw, dict) and "cleanup_targets" in raw:
        claimed_targets = raw["cleanup_targets"]
        if isinstance(claimed_targets, list) and all(
            isinstance(entry, dict)
            and isinstance(entry.get("path"), str)
            and isinstance(entry.get("sha256"), str)
            and len(entry["sha256"]) == 64
            and all(char in "0123456789abcdef" for char in entry["sha256"])
            for entry in claimed_targets
        ):
            targets = frozenset((entry["path"], entry["sha256"]) for entry in claimed_targets)
        else:
            warnings.warn(
                f"counter barrier staging {path} has malformed cleanup_targets; "
                "probe adoption disabled for this pass",
                UserWarning,
                stacklevel=2,
            )
    return records, consumed, collected, targets


def discard_barrier_staging(root: Path | str) -> bool:
    """Remove applied/superseded barrier staging (never raises)."""
    try:
        (Path(root) / BARRIER_STAGING_FILENAME).unlink(missing_ok=True)
    except OSError:
        return False
    return True


def _staged_parent_link(
    probe_path: Path, content_parent: Any, validated: frozenset[str]
) -> bool | None:
    """Whether a probe links to exactly one validated parent (#88R10-4c).

    True links (a content-exact uuid, a full-uuid marker owner, or a
    unique legacy prefix match); False is fresh or foreign (the caller
    skips silently for the normal paths); None is ambiguous (the
    caller skips loudly).
    """
    if isinstance(content_parent, str):
        return content_parent in validated
    if content_parent is not None:
        return False
    consumed_name = _parse_consumed_probe_filename(probe_path.name)
    if consumed_name is not None and len(consumed_name[0]) == 32:
        return consumed_name[0] in validated
    prefix: str | None = None
    if consumed_name is not None:
        prefix = consumed_name[0]
    else:
        orphan_name = _parse_probe_filename(probe_path.name)
        if orphan_name is not None:
            prefix = orphan_name[0]
    if prefix is None:
        return False
    matches = [uuid for uuid in validated if uuid.startswith(prefix)]
    if len(matches) == 1:
        return True
    if not matches:
        return False
    return None


def _adopted_staged_probe_targets(
    root: Path,
    validated: frozenset[str],
    staged_targets: frozenset[tuple[str, str]],
    digests: dict[str, str] | None = None,
) -> list[Path]:
    """Cleanup targets for parentless probes of collected parents (#88R10-4c).

    A valid probe orphan or marker whose parent validated as collected
    is interrupted cleanup, not fresh evidence: the earlier barrier
    folded it (its path rode to_consume) but the delete held while
    its parent files went. Adopt it straight into to_consume (its
    tmps first: direct targets bypass prune's content rules under
    adoption authority) without adjudication. Adoption needs a
    proven-dead stamped writer -- deletion demands proof, so an
    unstamped or live writer retains loudly (an orphaned child may
    still be writing), as do an ambiguous legacy prefix match, an
    unreadable body, or an unlistable tmp set. Authority is exact
    (#88R11-6): only slots the earlier barrier adjudicated --
    listed in the staged ``(path, sha256)`` targets and byte-identical
    since -- adopt; a linked but unlisted slot is new evidence (or
    evolved), never cleanup, and retains loudly for the
    parentless-fold design. Withheld markers never adopt (#88R11-2):
    a marker whose original slot keeps an undecided rewrite stays
    until the slot resolves. Quarantined forensics never adopt (the
    glob excludes them). ``digests`` records ``{path: sha256}`` for
    every probe file read (None discards). Never raises.
    """
    adopted: list[Path] = []
    if not validated:
        return adopted
    for probe_path in sorted(root.glob(f"{PROBE_FILE_PREFIX}*{PROBE_FILE_SUFFIX}")):
        status, raw, read_digest = _read_json_evidence_digested(probe_path)
        if read_digest is not None and digests is not None:
            digests[str(probe_path)] = read_digest
        if status == "gone":
            continue
        if status == "unreadable":
            # Filename linkage only (the content is unknown): fresh or
            # foreign probes skip silently for the normal paths.
            if _staged_parent_link(probe_path, None, validated):
                warnings.warn(
                    f"staged probe {probe_path.name} unreadable; retained for a later pass",
                    UserWarning,
                    stacklevel=2,
                )
            continue
        if not isinstance(raw, dict):
            # Torn: the sweep converges debris; adoption needs linkage.
            continue
        link = _staged_parent_link(
            probe_path,
            raw.get("parent_uuid"),
            validated,
        )
        if link is None:
            warnings.warn(
                f"staged probe {probe_path.name} matches several staged parents; "
                "retained (ambiguous linkage)",
                UserWarning,
                stacklevel=2,
            )
            continue
        if not link:
            continue
        pid = raw.get("pid")
        birth_raw = raw.get("birth_token")
        birth = birth_raw if type(birth_raw) is int else None
        if type(pid) is not int or pid <= 0:
            warnings.warn(
                f"staged probe {probe_path.name} names no verifiable writer; "
                "retained (writer quiescence unprovable)",
                UserWarning,
                stacklevel=2,
            )
            continue
        if _incarnation_alive(pid, birth):
            warnings.warn(
                f"staged probe {probe_path.name} has a live writer (pid {pid}); "
                "retained for a later pass",
                UserWarning,
                stacklevel=2,
            )
            continue
        digest = _sha256_file_hex(probe_path)
        if digest is None or (str(probe_path), digest) not in staged_targets:
            warnings.warn(
                f"staged probe {probe_path.name} is not a staged cleanup target; "
                "retained (new or evolved since collection)",
                UserWarning,
                stacklevel=2,
            )
            continue
        if digests is not None:
            digests[str(probe_path)] = digest
        slot_tmps: list[Path] = []
        if _parse_consumed_probe_filename(probe_path.name) is not None:
            slot_name = _marker_slot_name(probe_path.name)
            if slot_name is None or _slot_rewrite_unresolved(root, slot_name, digests):
                warnings.warn(
                    f"staged marker {probe_path.name} keeps an unresolved rewrite; "
                    "retained for a later pass",
                    UserWarning,
                    stacklevel=2,
                )
                continue
            # Resolved slots contribute their debris tmps too: the gate
            # above proved no complete-with-returns tmp survives, so
            # whatever the slot glob finds is torn or returnless.
            maybe_slot_tmps = _list_tmp_paths(root, f"{slot_name}.tmp-")
            if maybe_slot_tmps is None:
                warnings.warn(
                    f"staged marker {probe_path.name} slot tmps unlistable (I/O fault); retained",
                    UserWarning,
                    stacklevel=2,
                )
                continue
            slot_tmps = maybe_slot_tmps
        tmps = _list_tmp_paths(root, f"{probe_path.name}.tmp-")
        if tmps is None:
            warnings.warn(
                f"staged probe {probe_path.name} tmps unlistable (I/O fault); retained",
                UserWarning,
                stacklevel=2,
            )
            continue
        # Set-atomic authority (#88R12-4): every rewrite under the
        # slot must be listed and byte-identical -- an unlisted rewrite
        # (appended after staging) holds its whole slot for replay or
        # conflict handling instead of deleting unread. Only the
        # baseline adopts here; its verified tmps converge through
        # prune at consume time (listedness re-verified there).
        for tmp in [*tmps, *slot_tmps]:
            tmp_digest = _sha256_file_hex(tmp)
            if tmp_digest is None or (str(tmp), tmp_digest) not in staged_targets:
                warnings.warn(
                    f"staged probe {probe_path.name} keeps an unlisted rewrite "
                    f"({tmp.name}); retained for replay or conflict handling",
                    UserWarning,
                    stacklevel=2,
                )
                break
            if digests is not None:
                digests[str(tmp)] = tmp_digest
        else:
            adopted.append(probe_path)
    return adopted


def prepare_resume(
    counters_dir: Path | str, *, prior_merged_jsonl: Path | str | None
) -> dict[str, Any]:
    """Run the resume admission barrier: seal, collect, fence.

    Seals registration (post-seal producers are rejected and blocked),
    collects every unclaimed producer (committed ones consumed silently
    after adopting their probe orphans, dead ones as partial+lost with
    ``unknown`` end state — no observation survives across runs), and
    fences live ones (verified-terminate or ``unresolved``). Unresolved
    producers name their loss, keep their files, and force their units
    onto ``skipped_units``: resume must skip those reruns, report them,
    and never assume quiescence.

    Returns a plan ``{barrier_ok, fenced, unresolved, skipped_units,
    cache_records, collected_runs, consumed, counters_dir}``;
    ``barrier_ok`` is False when the seal could not be established or the
    plan could not be staged (quiescence unproven or evidence unlanded:
    the caller must stop before any provider work). The caller applies
    ``cache_records`` per
    unit (supplements for pending units, cache write-through for skipped
    ones) and filters ``pending_units`` by ``skipped_units``. Fresh
    records stage to ``barrier-staging.json`` (atomically, merged with any
    retained staging) BEFORE any source file is consumed, so a controller
    death between the barrier and its application loses nothing: the next
    barrier reloads the staging and the plan re-applies idempotently
    (extractor dedup absorbs repeats). The barrier releases before
    returning so rerun producers can register; a stuck seal warns loudly
    (reruns then fail visibly at registration).
    Never raises.
    """
    root = Path(counters_dir)
    plan: dict[str, Any] = {
        "barrier_ok": True,
        "fenced": [],
        "unresolved": [],
        "retained_uuids": [],
        "skipped_units": [],
        "skipped_live": [],
        "cache_records": {},
        "collected_runs": [],
        "consumed": 0,
        "counters_dir": str(root),
        "cleanup_held": [],
    }
    try:
        ensure_layout(root)
        seal(root, reason="resume-barrier")
    except CounterPersistenceError as exc:
        warnings.warn(f"counter resume barrier unavailable ({exc})", UserWarning, stacklevel=2)
        plan["barrier_ok"] = False
        return plan
    staged_records, staged_consumed, staged_collected, staged_targets = _load_barrier_staging(root)
    for staged_unit, staged_list in staged_records.items():
        plan["cache_records"].setdefault(staged_unit, []).extend(staged_list)
    plan["consumed"] += staged_consumed
    collected_now: set[str] = set()
    to_consume: list[Path] = []
    skip_retained: list[Path] = []
    read_digests: dict[str, str] = {}
    prior: Path | None = Path(prior_merged_jsonl) if prior_merged_jsonl else None
    prior_arg = prior if prior and prior.exists() else None
    # Resume track (postponed past 0.3.0): an unreadable prior keeps the
    # legacy empty-reading here; behavior preserved exactly.
    committed = _committed_from_jsonl(prior_arg)
    sessions, entries = committed[:2] if committed is not None else (set(), set())
    claims = _claimed_receipts_from_jsonl(prior_arg)
    if claims is None:
        claims = {}
    # Cleanup authority needs staged evidence or an authoritative
    # session: a staged uuid suppresses re-emission only when the
    # staged records mention it or the prior merged stream carries its
    # session. Anything else is an inconsistent claim -- it re-collects
    # as fresh (loud) instead of suppressing a record that never
    # landed (#88R10-4b).
    recorded_uuids = {
        record["worker_uuid"]
        for per_unit in staged_records.values()
        for record in per_unit
        if _is_authoritative_staged_record(record)
    }
    session_uuids = {known_uuid for _, known_uuid in sessions if isinstance(known_uuid, str)}
    validated_collected = frozenset(
        uuid for uuid in staged_collected if uuid in recorded_uuids or uuid in session_uuids
    )
    dropped_claims = sorted(staged_collected - validated_collected)
    if dropped_claims:
        warnings.warn(
            f"counter barrier staging claims {len(dropped_claims)} collected uuid(s) "
            f"with no staged evidence or session ({', '.join(dropped_claims)}); "
            "they re-collect as fresh",
            UserWarning,
            stacklevel=2,
        )
    known_uuids = _known_producer_uuids(root)
    reg_dir = root / REGISTRY_DIRNAME
    seen_runs: set[str] = set()
    retained_runs: set[str] = set()
    deferred_units: set[str] = set()
    skipped_live_units: set[str] = set()
    seen_uuids: set[str] = set()

    def _emit(unit: str, records: list[dict[str, Any]]) -> None:
        if records:
            plan["cache_records"].setdefault(unit, []).extend(records)

    def _note_collected(uuid: str) -> bool:
        """Record uuid as collected; False when already staged (#88R9-4).

        A retry re-collects staged evidence to finish its cleanup
        (held files) but must not adjudicate or re-emit it: the staged
        records already stand. Callers still extend to_consume either
        way; only emission is gated. Only validated staging gates
        (evidence or session behind the claim); only newly collected
        uuids join this pass's set or bump the consumed count, so the
        staged invariant consumed == len(collected_uuids) holds at
        every write (#88R10-4b).
        """
        if uuid in validated_collected:
            return False
        collected_now.add(uuid)
        return True

    for registry_path in sorted(reg_dir.glob("*.json")):
        content = read_registry_file(registry_path)
        if content is None:
            # #88R2: unreadable is never torn (see collect_unit): reserve
            # the filename uuid so the torn-sidecar sweep cannot adopt a
            # live producer's evidence this pass. #88R3: the reservation
            # rides the plan so the post-barrier sweep keeps its hands
            # off too (its run may still credit collected via siblings).
            reserved = _unreadable_registry_uuid(registry_path)
            if reserved is not None:
                warnings.warn(
                    f"unreadable registry {registry_path.name} retained "
                    "(I/O failure, not torn content; its sidecar waits a later pass)",
                    UserWarning,
                    stacklevel=2,
                )
                seen_uuids.add(reserved)
                plan["retained_uuids"].append(reserved)
            reaped = _reap_torn_registry(root, registry_path)
            if not reaped and reserved is None:
                # #88R3-F5: a torn registry the reap declined still
                # shields a live producer's sidecar -- but only the
                # presence-shield knows that. Reserve the filename uuid
                # so the post-barrier sweep skips it too (a sibling may
                # still credit its run collected). Deliberately NOT in
                # seen_uuids: the dead case must still converge through
                # the orphan-sidecar loop below. #88R4-F5a: reservation
                # needs a live-possible sidecar (readable or unreadable);
                # proved mutual debris reserves nothing, so the sweep
                # converges it instead of re-skipping it every cycle.
                claimed = parse_registry_filename(registry_path.name)
                if claimed is not None and _torn_registry_shields_live(root, claimed):
                    warnings.warn(
                        f"torn registry {registry_path.name} retained "
                        "(its sidecar waits a later pass; sweep skips it too)",
                        UserWarning,
                        stacklevel=2,
                    )
                    plan["retained_uuids"].append(claimed)
            continue
        uuid = content["worker_uuid"]
        seen_uuids.add(uuid)
        seen_runs.add(content["run_id"])
        if uuid in validated_collected and verify_producer(content) == "dead":
            # Staged retry (#88R13-2): this producer's evidence was
            # adjudicated by the earlier barrier and its records stand
            # staged, so reunion runs no second adjudication (a
            # post-stage ghost would fold and discard under the gate).
            # The parent files consume directly (a dead writer cannot
            # ghost them) while parentless probes converge through
            # digest-gated adoption below. Anything not proven dead
            # reunites normally (a live writer needs fencing).
            to_consume.extend(_producer_files(content, registry_path))
            continue
        # Resume track (postponed): uuid-only matching preserves the
        # frozen committed-vs-gap routing exactly.
        if any(known_uuid == uuid for _, known_uuid in sessions):
            try:
                claim_records, consumed, skipped_live = _collect_committed_producer(
                    content,
                    uuid,
                    root=root,
                    known_uuids=known_uuids,
                    claims=claims,
                    digests=read_digests,
                )
            except _DeferProducerError as exc:
                warnings.warn(
                    f"producer {exc.uuid} deferred: {exc.detail}; evidence retained",
                    UserWarning,
                    stacklevel=2,
                )
                plan["unresolved"].append(uuid)
                retained_runs.add(content["run_id"])
                deferred_units.add(content["unit"])
                if exc.pid is not None:
                    skipped_live_units.add(content["unit"])
                continue
            if _note_collected(uuid):
                _emit(content["unit"], claim_records)
                plan["consumed"] += 1
            if skipped_live:
                # A skipped-live orphan keeps its parent association:
                # the parent files ride the held list (not to_consume)
                # so the staging survives for a coherent retry
                # (#88R11-1), and the uuid joins retained_uuids so the
                # post-application sweep keeps its hands off while the
                # writer is still live (#88R12-1).
                skip_retained.extend(_producer_files(content, registry_path))
                plan["retained_uuids"].append(uuid)
            else:
                to_consume.extend(_producer_files(content, registry_path))
            to_consume.extend(consumed)
            continue
        verdict = verify_producer(content)
        if verdict == "dead":
            try:
                records, consumed = _collect_dead_producer(
                    content,
                    entries,
                    uuid,
                    "unknown",
                    root=root,
                    known_uuids=known_uuids,
                    claims=claims,
                    digests=read_digests,
                )
            except _DeferProducerError as exc:
                warnings.warn(
                    f"producer {exc.uuid} deferred: {exc.detail}; evidence retained",
                    UserWarning,
                    stacklevel=2,
                )
                plan["unresolved"].append(uuid)
                retained_runs.add(content["run_id"])
                deferred_units.add(content["unit"])
                if exc.pid is not None:
                    skipped_live_units.add(content["unit"])
                continue
            if _note_collected(uuid):
                _emit(content["unit"], records)
                plan["consumed"] += 1
            to_consume.extend(_producer_files(content, registry_path))
            to_consume.extend(consumed)
            plan["fenced"].append(uuid)
            continue
        if verdict == "alive" and fence_producer(content) == "fenced":
            try:
                records, consumed = _collect_dead_producer(
                    content,
                    entries,
                    uuid,
                    "killed",
                    root=root,
                    known_uuids=known_uuids,
                    claims=claims,
                    digests=read_digests,
                )
            except _DeferProducerError as exc:
                warnings.warn(
                    f"producer {exc.uuid} deferred: {exc.detail}; evidence retained",
                    UserWarning,
                    stacklevel=2,
                )
                plan["unresolved"].append(uuid)
                retained_runs.add(content["run_id"])
                deferred_units.add(content["unit"])
                if exc.pid is not None:
                    skipped_live_units.add(content["unit"])
                continue
            if _note_collected(uuid):
                _emit(content["unit"], records)
                plan["consumed"] += 1
            to_consume.extend(_producer_files(content, registry_path))
            to_consume.extend(consumed)
            plan["fenced"].append(uuid)
            continue
        if verdict == "unknown":
            fence_producer(content)
        lost = _lost_record(
            end_state="unresolved",
            worker_uuid=uuid,
            pid=content["pid"],
            run_id=content["run_id"],
            unit=content["unit"],
            attempt=content["attempt"],
            role=content["role"],
            isolation=content.get("isolation", "unknown"),
        )
        if lost is not None:
            _emit(content["unit"], [lost])
        plan["unresolved"].append(uuid)
        retained_runs.add(content["run_id"])
        skipped_live_units.add(content["unit"])
    for sidecar_path in sorted(root.glob(f"*{SIDECAR_SUFFIX}")):
        adopted = _adopt_orphan_sidecar(sidecar_path, seen_uuids)
        if adopted is None:
            continue
        uuid, sidecar = adopted
        if _registry_claims_orphan(reg_dir, uuid):
            # A registry that appeared or healed after the main loop owns
            # this sidecar: skip it this pass (mirrors collect_unit).
            continue
        barrier_run = sidecar.get("run_id")
        # Sweep authority needs a genuine stamp: only real strings
        # credit a run ("" included -- live writers emit it when no
        # run id is set). A junk token from unknown evidence ("None"
        # from null, ...) must never authorize the sweep to delete
        # same-token sidecars it never staged (codex R8-F2).
        if isinstance(barrier_run, str):
            seen_runs.add(barrier_run)
        journal_path = _journal_for_sidecar(sidecar_path)
        if uuid in validated_collected:
            # Staged retry (#88R13-2): no second reunion (see the
            # registry loop); the files consume directly while probes
            # converge through digest-gated adoption. Quiescence was
            # proven by the adoption gate above.
            to_consume.extend([sidecar_path, journal_path])
            continue
        # Resume track (postponed past 0.3.0): recovered/orphan-keys/
        # adopted scalar are unpacked but deliberately not wired yet;
        # behavior preserved exactly.
        barrier_unit = sidecar.get("unit")
        try:
            journal_lines = _read_journal_lines_strict(journal_path, uuid)
            orphan_block, orphan_receipts, consumed, _recovered, _orphan_keys, _adopted, _ = (
                _adopt_probe_orphans(
                    root,
                    worker_uuid=uuid,
                    sidecar=sidecar,
                    journal_lines=journal_lines,
                    claims=claims,
                    known_uuids=known_uuids,
                    producer_run=barrier_run if isinstance(barrier_run, str) else None,
                    producer_unit=barrier_unit if isinstance(barrier_unit, str) else None,
                    fence_live=True,
                    digests=read_digests,
                )
            )
        except _DeferProducerError as exc:
            warnings.warn(
                f"producer {exc.uuid} deferred: {exc.detail}; evidence retained",
                UserWarning,
                stacklevel=2,
            )
            plan["unresolved"].append(uuid)
            if isinstance(barrier_run, str):
                retained_runs.add(barrier_run)
            if isinstance(barrier_unit, str):
                deferred_units.add(barrier_unit)
                if exc.pid is not None:
                    skipped_live_units.add(barrier_unit)
            continue
        # Resume track (postponed): uuid-only matching preserves the
        # frozen claim-vs-gap routing exactly.
        if any(known_uuid == uuid for _, known_uuid in sessions):
            claim_records = []
            if orphan_block is not None:
                barrier_stamp_role, barrier_stamp_isolation = _sidecar_stamp(sidecar)
                claim_records.append(
                    _partial_record(
                        worker_uuid=uuid,
                        run_id=_sidecar_run(sidecar),
                        unit=str(sidecar.get("unit", "")),
                        attempt=sidecar.get("attempt", 0)
                        if _is_nonneg_int(sidecar.get("attempt"))
                        else 0,
                        pid=sidecar.get("pid") if _is_nonneg_int(sidecar.get("pid")) else None,
                        block=orphan_block,
                        receipts=orphan_receipts,
                        role=barrier_stamp_role,
                        isolation=barrier_stamp_isolation,
                    )
                )
            if _note_collected(uuid):
                _emit(str(sidecar.get("unit", "")), claim_records)
                plan["consumed"] += 1
            to_consume.extend([sidecar_path, journal_path])
            to_consume.extend(consumed)
            continue
        block, receipts, conflict = _gap_for_producer(sidecar, journal_lines, entries, uuid)
        if orphan_block is not None:
            block = orphan_block if block is None else merge_module_first(block, orphan_block)
            receipts = [*receipts, *orphan_receipts]
        records = []
        barrier_stamp_role, barrier_stamp_isolation = _sidecar_stamp(sidecar)
        if block is not None:
            records.append(
                _partial_record(
                    worker_uuid=uuid,
                    run_id=_sidecar_run(sidecar),
                    unit=str(sidecar.get("unit", "")),
                    attempt=sidecar.get("attempt", 0)
                    if _is_nonneg_int(sidecar.get("attempt"))
                    else 0,
                    pid=sidecar.get("pid") if _is_nonneg_int(sidecar.get("pid")) else None,
                    block=block,
                    receipts=receipts,
                    role=barrier_stamp_role,
                    isolation=barrier_stamp_isolation,
                    in_flight=_in_flight_rows(block),
                )
            )
        lost = _lost_record(
            end_state="conflict" if conflict else "unknown",
            worker_uuid=uuid,
            pid=sidecar.get("pid") if _is_nonneg_int(sidecar.get("pid")) else None,
            run_id=_sidecar_run(sidecar),
            unit=str(sidecar.get("unit", "")),
            attempt=sidecar.get("attempt") if _is_nonneg_int(sidecar.get("attempt")) else None,
            role=barrier_stamp_role,
            isolation=barrier_stamp_isolation,
        )
        if lost is not None:
            records.append(lost)
        if _note_collected(uuid):
            _emit(str(sidecar.get("unit", "")), records)
            plan["consumed"] += 1
        to_consume.extend([sidecar_path, _journal_for_sidecar(sidecar_path)])
        to_consume.extend(consumed)
    # Parentless probe adoption: probes of validated parents are
    # interrupted cleanup, never fresh evidence (#88R10-4c).
    to_consume.extend(
        _adopted_staged_probe_targets(root, validated_collected, staged_targets, read_digests)
    )
    plan["fenced"].sort()
    plan["unresolved"].sort()
    plan["skipped_units"] = sorted(
        {
            unit
            for unit, records in plan["cache_records"].items()
            if any(rec.get("end_state") == "unresolved" for rec in records)
        }
        | deferred_units
    )
    # The live subset of skipped units (#88R8-5): the runner reports
    # these as still-running producers and every other skip as
    # undecided evidence, so a quiescent rewrite conflict never reads
    # as a live process.
    plan["skipped_live"] = sorted(skipped_live_units & set(plan["skipped_units"]))
    # Run-granular authority (known residual, codex R9-F1): consumption
    # is file-granular but the sweep deletes by run match, so a same-run
    # straggler unreadable during the barrier is swept as a leftover
    # once readable -- and these branches double as staged-source
    # cleanup, so they cannot simply be removed. Staged-identity
    # authority is resume-design work (post-0.3.0). Fresh runs are
    # immune: they sweep with empty collected_runs, which makes the
    # run-match branches dead code there.
    plan["collected_runs"] = sorted(seen_runs - retained_runs)
    if plan["cache_records"]:
        collected_union = collected_now | set(validated_collected)
        # Self-healing count (#88R11-5): the staged invariant is
        # consumed == len(collected_uuids); a corrupt staged count
        # recomputes from the validated union instead of persisting.
        plan["consumed"] = len(collected_union)
        # Exact cleanup targets (#88R11-6): the digests captured
        # atomically with this pass's reads, restricted to consumed
        # files and their read rewrite tmps. Nothing is re-read here:
        # a fresh read at stage time could digest post-adjudication
        # ghosts, but captured bytes are exactly what reunion decided
        # on (#88R13-2).
        consumed_set = {str(path) for path in to_consume}
        probe_targets = sorted(
            (path_str, digest)
            for path_str, digest in read_digests.items()
            if path_str in consumed_set or path_str.split(".tmp-", 1)[0] in consumed_set
        )
        if not _write_barrier_staging(
            root,
            plan["cache_records"],
            plan["consumed"],
            collected_union,
            probe_targets,
        ):
            warnings.warn(
                f"counter resume barrier cannot stage recovery evidence in {root}; "
                "sources left unconsumed for retry",
                UserWarning,
                stacklevel=2,
            )
            plan["barrier_ok"] = False
            return plan
    held = _consume_producer_files(to_consume, read_digests)
    # Held cleanup targets ride the plan: application keeps the staging
    # that authorizes their retry instead of discarding it, so the next
    # barrier finishes the cleanup without re-emitting (#88R10-4c).
    # Skip-retained parents ride along: their association stays until
    # a coherent retry revisits the skipped orphan (#88R11-1).
    plan["cleanup_held"] = sorted({str(path) for path in [*held, *skip_retained]})
    try:
        unseal(root)
    except CounterPersistenceError as exc:
        warnings.warn(f"counter resume barrier stuck sealed ({exc})", UserWarning, stacklevel=2)
    return plan


def supplements_path(state_file: Path | str, unit: str) -> Path:
    """Return the per-unit recovery-supplements path next to a state file."""
    state_path = Path(state_file)
    digest = hashlib.sha256(unit.encode("utf-8")).hexdigest()
    return state_path.with_name(f"{state_path.name}.{digest}{RECOVERY_SUPPLEMENTS_SUFFIX}")


def _record_identity_hex(record: Any) -> str | None:
    """Stable identity hash for barrier-application dedup, else None (#88R11-7).

    Canonical JSON (sorted keys, tight separators) hashed with sha256.
    None when the record is not JSON-stable (fail-open to append: the
    record lands, exactly as before dedup).
    """
    try:
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def append_supplement_records(
    state_file: Path | str, unit: str, records: list[dict[str, Any]]
) -> bool:
    """Append verbatim records to one unit's recovery supplements (never raises).

    Used for resume-barrier recovery records (partials + losses) aimed at
    units that will rerun: the rerun's cache prepends the supplements, so
    the recovered evidence folds in its own scope. Idempotent: records
    already present (a cleanup retry re-applying an applied batch) are
    skipped by identity hash, so the supplements never republish
    (#88R11-7). Returns False (with a warning) on I/O failure.
    """
    if not records:
        return True
    path = supplements_path(state_file, unit)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Production-reader parity (#88R13-5): applied-ness is what
        # the production JSONL reader yields (binary b"\n" split,
        # per-line decode, dict-or-skip) -- never str.splitlines,
        # which splits unicode boundaries like \x1e that production
        # treats as line content.
        applied: set[str] = set()
        for record in iter_report_log_records(path):
            identity = _record_identity_hex(record)
            if identity is not None:
                applied.add(identity)
        if path.exists():
            tail = path.read_bytes()
            if tail and not tail.endswith(b"\n"):
                # Torn tail (a crash mid-append left an unterminated
                # fragment): isolate it on its own line so the records
                # below land readable. The fragment itself stays for
                # forensics; only the boundary is repaired (#88R12-5).
                warnings.warn(
                    f"counter supplements for {unit} end in a torn record; "
                    "the tail is isolated before appending",
                    UserWarning,
                    stacklevel=2,
                )
                with open(path, "ab") as fh:
                    fh.write(b"\n")
        fresh: list[dict[str, Any]] = []
        for record in records:
            identity = _record_identity_hex(record)
            if identity is None or identity not in applied:
                if identity is not None:
                    applied.add(identity)
                fresh.append(record)
        if not fresh:
            return True
        with open(path, "a", encoding="utf-8") as fh:
            for record in fresh:
                fh.write(json.dumps(record) + "\n")
    except OSError as exc:
        warnings.warn(
            f"counter supplements for {unit} failed ({exc}); recovery evidence dropped",
            UserWarning,
            stacklevel=2,
        )
        return False
    return True


def write_recovery_supplements(
    state_file: Path | str,
    unit: str,
    records: list[dict[str, Any]],
    *,
    engaged: bool | None = None,
) -> Path | None:
    """Archive one requeued attempt's session records for its rerun's cache.

    Only ``CallCountersReport`` session records are kept (authoritative per
    producer; per-test entries would duplicate test detail downstream). Each
    archived batch opens with a ``SessionStart`` bookend so the supplements
    source is standard-shaped: the cache writer frames it with its own
    marker and the archived attempt folds as its own scope. Returns
    the supplements path, or None when disengaged or when no session
    records were archived. Never raises. ``engaged`` overrides the
    environment check (the runner passes its run-resolved engagement).
    """
    if engaged is None:
        engaged = durability_dir() is not None
    if not engaged:
        return None
    sessions = [rec for rec in records if rec.get("$report_type") == SESSION_REPORT_TYPE]
    if not sessions:
        return None
    path = supplements_path(state_file, unit)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"$report_type": "SessionStart"}) + "\n")
            for record in sessions:
                fh.write(json.dumps(record) + "\n")
    except OSError as exc:
        warnings.warn(
            f"counter recovery supplements for {unit} failed ({exc}); "
            "the archived attempt stays dropped",
            UserWarning,
            stacklevel=2,
        )
        return None
    return path


__all__ = [
    "BARRIER_STAGING_FILENAME",
    "COUNTERS_ATTEMPT_ENV",
    "COUNTERS_DIR_ENV",
    "COUNTERS_FLUSH_K_ENV",
    "COUNTERS_ROLE_ENV",
    "COUNTERS_UNIT_ENV",
    "FLUSH_WINDOW_K",
    "FenceOutcome",
    "JOURNAL_SUFFIX",
    "PROBE_CONSUMED_PREFIX",
    "PROBE_FILE_PREFIX",
    "PROBE_FILE_SUFFIX",
    "PROBE_SEQ_ENV",
    "PROBE_SIDECAR_ENV",
    "PROBE_PARENT_ENV",
    "PROBE_RUN_ENV",
    "PROBE_UNIT_ENV",
    "PROBE_ATTEMPT_ENV",
    "PROBE_ROLE_ENV",
    "PROBE_ISOLATION_ENV",
    "ProducerVerdict",
    "RECOVERY_SUPPLEMENTS_SUFFIX",
    "SEAL_FILENAME",
    "SIDECAR_SUFFIX",
    "CounterPersistenceError",
    "Registration",
    "append_journal",
    "append_supplement_records",
    "birth_token_for_pid",
    "collect_unit",
    "counters_dir_for_state",
    "counters_run_dir_for_state",
    "discard_barrier_staging",
    "durability_dir",
    "end_state_for_attempt",
    "ensure_layout",
    "fence_producer",
    "is_sealed",
    "mark_probe_consumed",
    "prepare_resume",
    "read_json_file",
    "read_registry_file",
    "register_worker",
    "reject_reserved_run_id",
    "seal",
    "supplements_path",
    "sweep_orphans",
    "unseal",
    "validate_probe_receipt",
    "verify_producer",
    "write_recovery_supplements",
    "write_sidecar_atomic",
]
