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

import errno
import hashlib
import json
import os
import signal
import sys
import time
import warnings
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pkcs11_check.core.counters_schema import (
    REGISTRY_DIRNAME,
    SESSION_REPORT_TYPE,
    TEST_ENTRY_PROPERTY,
    UNKNOWN_MODULE,
    ensure_five_buckets,
    is_birth_token,
    is_lost_key,
    is_module_first_block,
    is_receipt,
    is_registry_content,
    is_role,
    is_session_record,
    is_test_entry,
    is_worker_uuid,
    merge_module_first,
    mint_filename_nonce,
    parse_registry_filename,
    wrap_module_first,
)
from pkcs11_check.core.report_log import user_property

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
FLUSH_WINDOW_K = 1
SEAL_FILENAME = "SEALED"
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


def read_registry_file(path: Path | str) -> dict[str, Any] | None:
    """Read one registry file; torn/invalid/mismatched reads as absent (None)."""
    resolved = Path(path)
    if parse_registry_filename(resolved.name) is None:
        return None
    try:
        raw = resolved.read_text(encoding="utf-8")
    except (OSError, ValueError):
        return None
    try:
        content = json.loads(raw)
    except ValueError:
        return None
    if not is_registry_content(content):
        return None
    if content["worker_uuid"] != parse_registry_filename(resolved.name):
        return None
    return dict(content)


def read_json_file(path: Path | str) -> Any | None:
    """Read one JSON file; missing/torn reads as absent (None, never raises)."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except (OSError, ValueError):
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


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


def _linux_terminated(pid: int, birth: int) -> bool:
    """Whether a Linux pid is provably not the registered incarnation anymore."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            data = fh.read()
    except (OSError, ValueError):
        return True
    tail = data[data.rfind(")") + 1 :].split()
    if len(tail) < 20:
        return True
    if tail[0] == "Z":
        return True
    try:
        return int(tail[19]) != birth
    except ValueError:
        return True


def _terminate_pidfd(pid: int, birth: int, timeout_s: float) -> bool:
    """SIGKILL through a pidfd (pins the incarnation) and poll for death.

    The birth is re-read after the open: the fd pins the open-time
    occupant, so a starttime mismatch proves the claimed incarnation died
    and the pid was recycled between verification and open (close, no
    signal, fenced). Only a lookup failure proves death at the excepts;
    permission/syscall failures are unresolved, never assumed quiescent.

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
        deadline = time.monotonic() + max(timeout_s, 0.0)
        while True:
            if _linux_terminated(pid, birth):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)
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


def _iter_jsonl_records(path: Path) -> Iterator[dict[str, Any]]:
    """Yield parsed dict records from a JSONL file (bad lines skipped)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            yield record


def _committed_from_jsonl(path: Path | str | None) -> tuple[set[str], set[tuple[str, str]]]:
    """Return committed ``(session uuids, (uuid, nodeid) entries)`` from JSONL.

    Sessions are authoritative for their whole producer; entries are
    authoritative per test window. Used to compute the sidecar gap (full
    entry supersedes same-(uuid, test) partial) and delete-after-commit.

    Authority equals extractor acceptance: sessions gate on
    ``is_session_record`` and entries on the extractor's own first-match
    ``user_property`` gated by ``is_test_entry`` (``_parse_*`` reuse would
    cycle through ``call_counters``). Every gate-admitted record is one
    the extractor folds (identical pid/total/counters/uuid/role/round
    checks); the gate is only stricter (unknown keys, non-string
    isolation, partly-malformed receipts). That denied direction is benign
    for sessions (files retained; re-collection folds exactly once under
    the authoritative ``(run, uuid)`` staging key, which supersedes the
    gap partial), and writer-unreachable for entries (fixed keys, valid
    receipts, string isolation), so real-run authority is exactly
    extractor acceptance in both directions.
    """
    sessions: set[str] = set()
    entries: set[tuple[str, str]] = set()
    if path is None:
        return sessions, entries
    for record in _iter_jsonl_records(Path(path)):
        report_type = record.get("$report_type", "TestReport")
        if report_type == SESSION_REPORT_TYPE:
            if not is_session_record(record):
                continue
            uuid = record.get("worker_uuid")
            if is_worker_uuid(uuid):
                assert isinstance(uuid, str)
                sessions.add(uuid)
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
    return sessions, entries


def _claimed_receipts_from_jsonl(path: Path | str | None) -> dict[str, set[tuple[str, int]]]:
    """Return per-producer folded-probe claims ``{uuid: {(uuid, seq)}}`` from JSONL.

    Claims ride C4-valid sessions and valid per-test entries (first-match
    ``user_property``, mirroring :func:`_committed_from_jsonl`); uuid-less
    records claim nothing (unattributable). The orphan collector unions
    these with the producer's durable file receipts: either holder proves
    the probe evidence durable, so the orphan suppresses instead of
    folding twice.
    """
    claims: dict[str, set[tuple[str, int]]] = {}
    if path is None:
        return claims
    for record in _iter_jsonl_records(Path(path)):
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
            keys = _receipt_keys(entry.get("receipts"))
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
    """Return ``(parent prefix, seq)`` bound by a consumed-marker name, else None."""
    if not name.startswith(PROBE_CONSUMED_PREFIX) or not name.endswith(PROBE_FILE_SUFFIX):
        return None
    stem = name[len(PROBE_CONSUMED_PREFIX) : -len(PROBE_FILE_SUFFIX)]
    parts = stem.split("-")
    if len(parts) != 3:
        return None
    parent8, seq, nonce = parts
    if len(parent8) != 8 or any(char not in "0123456789abcdef" for char in parent8):
        return None
    if not nonce or not seq.isascii() or not seq.isdigit():
        return None
    return (parent8, int(seq))


def mark_probe_consumed(sidecar: Path | str) -> Path:
    """Rename a committed probe sidecar to its consumed marker (atomic).

    Used when the sidecar delete fails after the parent checkpoint
    flushed: the parent already holds the counts, and the marker tells
    orphan adoption to suppress instead of folding them again. Same
    directory, same content, ``probe-consumed-`` prefix.

    Raises:
        CounterPersistenceError: When the name is foreign (unparseable)
            or the rename fails. Both are loud: proceeding would risk a
            silent double-fold.
    """
    path = Path(sidecar)
    if _parse_probe_filename(path.name) is None:
        raise CounterPersistenceError(f"cannot mark foreign probe sidecar consumed: {path}")
    marked = path.with_name(f"{PROBE_CONSUMED_PREFIX}{path.name[len(PROBE_FILE_PREFIX) :]}")
    try:
        os.replace(path, marked)
    except OSError as exc:
        raise CounterPersistenceError(f"cannot mark probe sidecar consumed: {exc}") from exc
    return marked


def _read_probe_orphan(
    path: Path,
) -> tuple[str, int, list[Any], frozenset[tuple[str, int]], dict[str, Any]] | None:
    """Return ``(child_uuid, seq, counters, lost_keys, identity)`` from a probe sidecar.

    ``identity`` is the F2 self-describing block (parent_uuid/run_id/unit/
    attempt/role/isolation, each present only when well-typed); legacy
    sidecars yield ``{}``. Returns None unless the core shape parses.
    """
    data = read_json_file(path)
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
    if isinstance(raw_keys, (list, tuple)):
        for entry in raw_keys:
            if is_lost_key(entry):
                keys.add((entry["parent_uuid"], entry["probe_seq"]))
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
    return (uuid, seq, list(counters), frozenset(keys), identity)


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
    """
    keys: set[tuple[str, int]] = set()
    if isinstance(sidecar, dict):
        keys.update(_receipt_keys(sidecar.get("receipts")))
    for line in journal_lines:
        try:
            window = json.loads(line)
        except ValueError:
            continue
        if isinstance(window, dict):
            keys.update(_receipt_keys(window.get("receipts")))
    return keys


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
) -> tuple[
    dict[str, Any] | None,
    list[dict[str, Any]],
    list[Path],
    list[tuple[str, int]],
    set[tuple[str, int]],
]:
    """Fold one producer's retained probe sidecars.

    Returns ``(block, receipts, consumed, recovered, orphan_keys)``.
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

    Residual: a probe ingested via the live sidecar-fallback path (whose
    receipt is suppressed by design), followed by a failed parent flush
    and a pre-flush death, folds once via its committed entry and once
    here. That triple fault stays fail-visible through the lost record.
    Adopted orphans' nested receipts are dropped, never propagated:
    probe sidecars carry counters, keyed losses, and F2 identity only,
    and only the orphan's own receipt is claimed here.
    """
    prefix = worker_uuid[:8]
    colliders = sorted(uuid for uuid in known_uuids if uuid.startswith(prefix))
    unambiguous = colliders == [worker_uuid]
    coverage = _durable_receipts(sidecar, journal_lines) | claims.get(worker_uuid, set())
    merged: dict[str, Any] = {"total_calls": 0, "by_module": {}}
    claimed: list[dict[str, Any]] = []
    consumed: list[Path] = []
    recovered: list[tuple[str, int]] = []
    orphan_keys: set[tuple[str, int]] = set()

    def _fold(
        path: Path,
        child_uuid: str,
        seq: int,
        counters: list[Any],
        keys: frozenset[tuple[str, int]],
        filename_seq: int,
    ) -> None:
        if (child_uuid, seq) in coverage:
            consumed.append(path)
            return
        # Healing and key-union never gate on counts: a zero-counters
        # orphan still names its (parent, seq) identity (the child
        # accounted for zero calls) and may carry nested grandchild
        # keys (robustness M1). Only the count merge and the receipt
        # claim need a block. (.update, not |=: rebinding the closure
        # name would raise UnboundLocalError.)
        orphan_keys.update(keys)
        if seq == filename_seq:
            recovered.append((worker_uuid, seq))
        block = _probe_rows_to_block(counters)
        if block is not None:
            merge_module_first(merged, block)
            claimed.append({"worker_uuid": child_uuid, "probe_seq": seq})
        consumed.append(path)

    # Markers (order-free, conservative): consumed markers suppress before
    # any orphan folds. A marker's counts already sit in the parent
    # checkpoint, so its identity joins coverage and the marker itself
    # consumes. Torn markers are debris: unparseable content folds nothing.
    # Valid markers still heal (their evidence is checkpoint-durable) and
    # union their nested keys. Filename-prefix match only, and only when
    # the prefix is unambiguous, exactly as before the reunion passes.
    if unambiguous:
        for path in sorted(root.glob(f"{PROBE_CONSUMED_PREFIX}*{PROBE_FILE_SUFFIX}")):
            parsed_name = _parse_consumed_probe_filename(path.name)
            if parsed_name is None or parsed_name[0] != prefix:
                continue
            orphan = _read_probe_orphan(path)
            if orphan is not None:
                coverage.add((orphan[0], orphan[1]))
                orphan_keys |= orphan[3]
                if orphan[1] == parsed_name[1]:
                    recovered.append((worker_uuid, orphan[1]))
            consumed.append(path)
    ambiguous_reporter = colliders[:1] == [worker_uuid]
    for path in sorted(root.glob(f"{PROBE_FILE_PREFIX}*{PROBE_FILE_SUFFIX}")):
        parsed_name = _parse_probe_filename(path.name)
        if parsed_name is None or parsed_name[0] != prefix:
            continue
        orphan = _read_probe_orphan(path)
        if orphan is None:
            raw = read_json_file(path)
            if raw is None or not isinstance(raw, dict):
                consumed.append(path)
            continue
        child_uuid, seq, counters, keys, identity = orphan
        parent_claim = identity.get("parent_uuid")
        if parent_claim is not None and parent_claim != worker_uuid:
            continue  # Another producer's pass owns it (content-exact).
        if parent_claim == worker_uuid:
            # Pass 1: content-exact reunion. Run/unit must agree with the
            # producer when both sides state them; a contradiction retains
            # the orphan loudly instead of misfolding another run's calls.
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
            if (
                orphan_unit is not None
                and producer_unit is not None
                and orphan_unit != producer_unit
            ):
                warnings.warn(
                    f"cross-unit probe orphan {path.name} retained "
                    f"(orphan unit {orphan_unit!r} != producer unit {producer_unit!r})",
                    UserWarning,
                    stacklevel=2,
                )
                continue
            _fold(path, child_uuid, seq, counters, keys, parsed_name[1])
            continue
        # Pass 2: legacy filename fallback (no content identity). Under a
        # prefix collision the orphan could belong to any collider, so it
        # retains with one warning instead of attributing by a hint.
        if not unambiguous:
            if ambiguous_reporter:
                warnings.warn(
                    f"ambiguous probe orphan {path.name} retained "
                    f"({len(colliders)} producers share prefix {prefix})",
                    UserWarning,
                    stacklevel=2,
                )
            continue
        _fold(path, child_uuid, seq, counters, keys, parsed_name[1])
    if merged["total_calls"] == 0:
        return None, [], consumed, sorted(set(recovered)), orphan_keys
    claimed.sort(key=lambda item: (item["worker_uuid"], item["probe_seq"]))
    return merged, claimed, consumed, sorted(set(recovered)), orphan_keys


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
            parsed = json.loads(line)
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


def _consume_producer_files(paths: list[Path]) -> None:
    """Delete collected/committed evidence files (best effort, never raises)."""
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        for tmp in path.parent.glob(f"{path.name}.tmp-*"):
            try:
                tmp.unlink()
            except OSError:
                pass


def _producer_files(registry: dict[str, Any], registry_path: Path) -> list[Path]:
    """Return the evidence files owned by one registry (registry first)."""
    sidecar = Path(str(registry.get("sidecar", "")))
    files = [registry_path]
    if str(registry.get("sidecar", "")):
        files.append(sidecar)
        files.append(_journal_for_sidecar(sidecar))
    return files


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
) -> dict[str, Any]:
    """Build a ``CallCountersPartial`` record (schema-valid).

    Gap-only for dead producers, zero-call loss-only when only a loss
    scalar/keys survive, claim-only when only adopted-orphan evidence
    rides along.
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
    sessions, entries = _committed_from_jsonl(child_arg)
    claims = _claimed_receipts_from_jsonl(child_arg)
    known_uuids = _known_producer_uuids(root)
    end_state = end_state_for_attempt(status=status, returncode=returncode, timed_out=timed_out)
    appended: list[dict[str, Any]] = []
    seen_sidecar_uuids: set[str] = set()
    for registry_path in sorted(reg_dir.glob("*.json")):
        content = read_registry_file(registry_path)
        if content is None:
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
        if uuid in sessions:
            claim_records, consumed = _collect_committed_producer(
                content, uuid, root=root, known_uuids=known_uuids, claims=claims
            )
            if _append_collected(child_path, claim_records):
                appended.extend(claim_records)
                _consume_producer_files(_producer_files(content, registry_path))
                _consume_producer_files(consumed)
            continue
        if verify_producer(content) != "dead":
            continue
        records, consumed = _collect_dead_producer(
            content,
            entries,
            uuid,
            end_state,
            root=root,
            known_uuids=known_uuids,
            claims=claims,
        )
        if _append_collected(child_path, records):
            appended.extend(records)
            _consume_producer_files(_producer_files(content, registry_path))
            _consume_producer_files(consumed)
    for sidecar_path in sorted(root.glob(f"*{SIDECAR_SUFFIX}")):
        adopted = _adopt_orphan_sidecar(sidecar_path, seen_sidecar_uuids)
        if adopted is None:
            continue
        uuid, sidecar = adopted
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
        journal_lines = _read_journal_lines(journal_path)
        sidecar_run = sidecar.get("run_id")
        sidecar_unit = sidecar.get("unit")
        orphan_block, orphan_receipts, consumed, recovered, orphan_keys = _adopt_probe_orphans(
            root,
            worker_uuid=uuid,
            sidecar=sidecar,
            journal_lines=journal_lines,
            claims=claims,
            known_uuids=known_uuids,
            producer_run=sidecar_run if isinstance(sidecar_run, str) else None,
            producer_unit=sidecar_unit if isinstance(sidecar_unit, str) else None,
        )
        if uuid in sessions:
            records = []
            if orphan_block is not None:
                records.append(
                    _partial_record(
                        worker_uuid=uuid,
                        run_id=str(sidecar.get("run_id", "")),
                        unit=str(sidecar.get("unit", "")),
                        attempt=sidecar.get("attempt", 0)
                        if _is_nonneg_int(sidecar.get("attempt"))
                        else 0,
                        pid=sidecar.get("pid") if _is_nonneg_int(sidecar.get("pid")) else None,
                        block=orphan_block,
                        receipts=orphan_receipts,
                        orphan_keys=_keys_to_wire(orphan_keys),
                        recovered_keys=_keys_to_wire(set(recovered)),
                    )
                )
            if _append_collected(child_path, records):
                appended.extend(records)
                _consume_producer_files([sidecar_path, journal_path])
                _consume_producer_files(consumed)
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
        if block is None and (scalar_count or gap_keys or orphan_keys):
            block = {"total_calls": 0, "by_module": {}}
        stamp_role, stamp_isolation = _sidecar_stamp(sidecar)
        if block is not None:
            records.append(
                _partial_record(
                    worker_uuid=uuid,
                    run_id=str(sidecar.get("run_id", "")),
                    unit=str(sidecar.get("unit", "")),
                    attempt=sidecar.get("attempt", 0)
                    if _is_nonneg_int(sidecar.get("attempt"))
                    else 0,
                    pid=sidecar.get("pid") if _is_nonneg_int(sidecar.get("pid")) else None,
                    block=block,
                    receipts=receipts,
                    probes_lost=scalar_count,
                    role=stamp_role,
                    isolation=stamp_isolation,
                    lost_keys=_keys_to_wire(gap_keys),
                    orphan_keys=_keys_to_wire(orphan_keys),
                    recovered_keys=_keys_to_wire(set(recovered)),
                )
            )
        lost = _lost_record(
            end_state="conflict" if conflict else end_state,
            worker_uuid=uuid,
            pid=sidecar.get("pid") if _is_nonneg_int(sidecar.get("pid")) else None,
            run_id=str(sidecar.get("run_id", "")),
            unit=str(sidecar.get("unit", "")),
            attempt=sidecar.get("attempt") if _is_nonneg_int(sidecar.get("attempt")) else None,
            role=stamp_role,
            isolation=stamp_isolation,
        )
        if lost is not None:
            records.append(lost)
        if _append_collected(child_path, records):
            appended.extend(records)
            _consume_producer_files([sidecar_path, _journal_for_sidecar(sidecar_path)])
            _consume_producer_files(consumed)
            torn_twin = reg_dir / f"{uuid}.json"
            if read_registry_file(torn_twin) is None and torn_twin.exists():
                _consume_producer_files([torn_twin])
    return appended


def _reap_torn_registry(root: Path, registry_path: Path) -> None:
    """Delete a torn registry only when no sidecar could still adopt it."""
    uuid = parse_registry_filename(registry_path.name)
    if uuid is not None and list(root.glob(f"{uuid}-*{SIDECAR_SUFFIX}")):
        return
    try:
        registry_path.unlink(missing_ok=True)
    except OSError:
        pass


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
    return (uuid, sidecar)


def _read_journal_lines(journal_path: Path) -> list[str]:
    """Read raw journal lines (missing file reads as empty, never raises)."""
    try:
        text = journal_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
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
) -> tuple[list[dict[str, Any]], list[Path]]:
    """Build the partial+lost records for one dead producer (reads orphans only).

    Returns ``(records, consumed_orphans)``: the caller's append-then-delete
    consumes the orphan files only after the records land in the JSONL.
    """
    sidecar_raw = str(content.get("sidecar", ""))
    sidecar_path = Path(sidecar_raw)
    sidecar = read_json_file(sidecar_path) if sidecar_raw else None
    journal_lines = _read_journal_lines(_journal_for_sidecar(sidecar_path)) if sidecar_raw else []
    block, receipts, conflict = _gap_for_producer(sidecar, journal_lines, entries, uuid)
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
    orphan_block, orphan_receipts, consumed, recovered, orphan_keys = _adopt_probe_orphans(
        root,
        worker_uuid=uuid,
        sidecar=sidecar,
        journal_lines=journal_lines,
        claims=claims,
        known_uuids=known_uuids,
        producer_run=content["run_id"],
        producer_unit=content["unit"],
    )
    if orphan_block is not None:
        block = orphan_block if block is None else merge_module_first(block, orphan_block)
        receipts = [*receipts, *orphan_receipts]
    records: list[dict[str, Any]] = []
    if block is None and (scalar_count or gap_keys or orphan_keys):
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
                probes_lost=scalar_count,
                role=content["role"],
                isolation=content.get("isolation", "unknown"),
                lost_keys=_keys_to_wire(gap_keys),
                orphan_keys=_keys_to_wire(orphan_keys),
                recovered_keys=_keys_to_wire(set(recovered)),
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
) -> tuple[list[dict[str, Any]], list[Path]]:
    """Adopt one committed producer's probe orphans (claim-only partial, never lost).

    The session already holds the producer's counts, so a partial appends
    only for uncovered orphans: orphan counts under the parent uuid (the
    session supersedes them at extraction, keeping totals exact) that
    claims the receipts. Covered orphans consume silently. No lost record
    ever emits here: the producer lived, so a loss claim would be false.
    """
    sidecar_raw = str(content.get("sidecar", ""))
    sidecar_path = Path(sidecar_raw)
    sidecar = read_json_file(sidecar_path) if sidecar_raw else None
    journal_lines = _read_journal_lines(_journal_for_sidecar(sidecar_path)) if sidecar_raw else []
    orphan_block, orphan_receipts, consumed, recovered, orphan_keys = _adopt_probe_orphans(
        root,
        worker_uuid=uuid,
        sidecar=sidecar,
        journal_lines=journal_lines,
        claims=claims,
        known_uuids=known_uuids,
        producer_run=content["run_id"],
        producer_unit=content["unit"],
    )
    if orphan_block is None:
        return [], consumed
    # Claim-only: orphan evidence rides orphan_keys (union-always); no gap
    # set (the live session is authoritative for this producer's own keys).
    return (
        [
            _partial_record(
                worker_uuid=uuid,
                run_id=content["run_id"],
                unit=content["unit"],
                attempt=content["attempt"],
                pid=content["pid"],
                block=orphan_block,
                receipts=orphan_receipts,
                role=content["role"],
                isolation=content.get("isolation", "unknown"),
                orphan_keys=_keys_to_wire(orphan_keys),
                recovered_keys=_keys_to_wire(set(recovered)),
            )
        ],
        consumed,
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
) -> dict[str, int]:
    """Delete provably-consumable evidence files; retain everything else.

    Removes: committed producers' files (uuid with an authoritative
    session), runs fully collected by a resume barrier (never the current
    run, even if a caller mislists it), torn registries with no adoptable
    sidecar, torn sidecars with no registry, journals with no sidecar
    (undisambiguable debris), and torn probe sidecars. Retains: everything
    else, including live producers' files (verified before any destructive
    decision), valid probe orphans (only collection proves them
    consumable), and other-run evidence no barrier has claimed. Idempotent:
    a second sweep removes nothing further. Never raises.
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

    for registry_path in sorted(reg_dir.glob("*.json")):
        content = read_registry_file(registry_path)
        if content is None:
            uuid = parse_registry_filename(registry_path.name)
            siblings = list(root.glob(f"{uuid}-*{SIDECAR_SUFFIX}")) if uuid is not None else []
            if siblings:
                retained += 1
            else:
                _remove([registry_path])
            continue
        uuid = content["worker_uuid"]
        if uuid in committed_uuids:
            _remove(_producer_files(content, registry_path))
            continue
        run_id = content["run_id"]
        if run_id in collected_runs and run_id != current_run:
            if verify_producer(content) == "alive":
                retained += len([p for p in _producer_files(content, registry_path)])
            else:
                _remove(_producer_files(content, registry_path))
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
        if (reg_dir / f"{uuid}.json").exists() and read_registry_file(reg_dir / f"{uuid}.json"):
            continue
        sidecar = read_json_file(sidecar_path)
        journal_path = _journal_for_sidecar(sidecar_path)
        if uuid in committed_uuids:
            _remove([sidecar_path, journal_path])
        elif not isinstance(sidecar, dict):
            _remove([sidecar_path])
        elif sidecar.get("run_id") in collected_runs and sidecar.get("run_id") != current_run:
            _remove([sidecar_path, journal_path])
        else:
            retained += 1
            if journal_path.exists():
                retained += 1
    for journal_path in sorted(root.glob(f"*{JOURNAL_SUFFIX}")):
        uuid = _uuid_from_evidence_name(journal_path.name)
        if uuid is None:
            continue
        stem = journal_path.name[: -len(JOURNAL_SUFFIX)]
        if list(root.glob(f"{stem}{SIDECAR_SUFFIX}")):
            continue
        if (reg_dir / f"{uuid}.json").exists():
            retained += 1
            continue
        _remove([journal_path])
    for probe_path in sorted(root.glob(f"{PROBE_FILE_PREFIX}*{PROBE_FILE_SUFFIX}")):
        raw = read_json_file(probe_path)
        if raw is None or not isinstance(raw, dict):
            _remove([probe_path])
        else:
            retained += 1
    return {"removed": removed, "retained": retained}


def _write_barrier_staging(
    root: Path, cache_records: dict[str, list[dict[str, Any]]], consumed: int
) -> bool:
    """Persist the collected barrier plan atomically (never raises)."""
    path = root / BARRIER_STAGING_FILENAME
    tmp = path.with_name(f"{path.name}.tmp-{os.getpid()}")
    try:
        tmp.write_text(
            json.dumps({"cache_records": cache_records, "consumed": consumed}),
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


def _load_barrier_staging(root: Path) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Load retained staging ``(cache_records, consumed)``; absent reads empty.

    Torn or misshapen staging warns loudly (staged recovery evidence may
    be lost: atomic writes make this corruption-only) and the debris is
    discarded. Never raises.
    """
    path = root / BARRIER_STAGING_FILENAME
    if not path.exists():
        return {}, 0
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
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
        return {}, 0
    return records, consumed


def discard_barrier_staging(root: Path | str) -> bool:
    """Remove applied/superseded barrier staging (never raises)."""
    try:
        (Path(root) / BARRIER_STAGING_FILENAME).unlink(missing_ok=True)
    except OSError:
        return False
    return True


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
        "skipped_units": [],
        "cache_records": {},
        "collected_runs": [],
        "consumed": 0,
        "counters_dir": str(root),
    }
    try:
        ensure_layout(root)
        seal(root, reason="resume-barrier")
    except CounterPersistenceError as exc:
        warnings.warn(f"counter resume barrier unavailable ({exc})", UserWarning, stacklevel=2)
        plan["barrier_ok"] = False
        return plan
    staged_records, staged_consumed = _load_barrier_staging(root)
    for staged_unit, staged_list in staged_records.items():
        plan["cache_records"].setdefault(staged_unit, []).extend(staged_list)
    plan["consumed"] += staged_consumed
    to_consume: list[Path] = []
    prior: Path | None = Path(prior_merged_jsonl) if prior_merged_jsonl else None
    prior_arg = prior if prior and prior.exists() else None
    sessions, entries = _committed_from_jsonl(prior_arg)
    claims = _claimed_receipts_from_jsonl(prior_arg)
    known_uuids = _known_producer_uuids(root)
    reg_dir = root / REGISTRY_DIRNAME
    seen_runs: set[str] = set()
    retained_runs: set[str] = set()
    seen_uuids: set[str] = set()

    def _emit(unit: str, records: list[dict[str, Any]]) -> None:
        if records:
            plan["cache_records"].setdefault(unit, []).extend(records)

    for registry_path in sorted(reg_dir.glob("*.json")):
        content = read_registry_file(registry_path)
        if content is None:
            _reap_torn_registry(root, registry_path)
            continue
        uuid = content["worker_uuid"]
        seen_uuids.add(uuid)
        seen_runs.add(content["run_id"])
        if uuid in sessions:
            claim_records, consumed = _collect_committed_producer(
                content, uuid, root=root, known_uuids=known_uuids, claims=claims
            )
            _emit(content["unit"], claim_records)
            to_consume.extend(_producer_files(content, registry_path))
            to_consume.extend(consumed)
            plan["consumed"] += 1
            continue
        verdict = verify_producer(content)
        if verdict == "dead":
            records, consumed = _collect_dead_producer(
                content,
                entries,
                uuid,
                "unknown",
                root=root,
                known_uuids=known_uuids,
                claims=claims,
            )
            _emit(content["unit"], records)
            to_consume.extend(_producer_files(content, registry_path))
            to_consume.extend(consumed)
            plan["consumed"] += 1
            plan["fenced"].append(uuid)
            continue
        if verdict == "alive" and fence_producer(content) == "fenced":
            records, consumed = _collect_dead_producer(
                content,
                entries,
                uuid,
                "killed",
                root=root,
                known_uuids=known_uuids,
                claims=claims,
            )
            _emit(content["unit"], records)
            to_consume.extend(_producer_files(content, registry_path))
            to_consume.extend(consumed)
            plan["consumed"] += 1
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
    for sidecar_path in sorted(root.glob(f"*{SIDECAR_SUFFIX}")):
        adopted = _adopt_orphan_sidecar(sidecar_path, seen_uuids)
        if adopted is None:
            continue
        uuid, sidecar = adopted
        seen_runs.add(str(sidecar.get("run_id", "")))
        journal_path = _journal_for_sidecar(sidecar_path)
        journal_lines = _read_journal_lines(journal_path)
        # Resume track (postponed past 0.3.0): recovered/orphan-keys are
        # unpacked but deliberately not wired yet; behavior preserved exactly.
        barrier_run = sidecar.get("run_id")
        barrier_unit = sidecar.get("unit")
        orphan_block, orphan_receipts, consumed, _recovered, _orphan_keys = _adopt_probe_orphans(
            root,
            worker_uuid=uuid,
            sidecar=sidecar,
            journal_lines=journal_lines,
            claims=claims,
            known_uuids=known_uuids,
            producer_run=barrier_run if isinstance(barrier_run, str) else None,
            producer_unit=barrier_unit if isinstance(barrier_unit, str) else None,
        )
        if uuid in sessions:
            claim_records = []
            if orphan_block is not None:
                barrier_stamp_role, barrier_stamp_isolation = _sidecar_stamp(sidecar)
                claim_records.append(
                    _partial_record(
                        worker_uuid=uuid,
                        run_id=str(sidecar.get("run_id", "")),
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
            _emit(str(sidecar.get("unit", "")), claim_records)
            to_consume.extend([sidecar_path, journal_path])
            to_consume.extend(consumed)
            plan["consumed"] += 1
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
                    run_id=str(sidecar.get("run_id", "")),
                    unit=str(sidecar.get("unit", "")),
                    attempt=sidecar.get("attempt", 0)
                    if _is_nonneg_int(sidecar.get("attempt"))
                    else 0,
                    pid=sidecar.get("pid") if _is_nonneg_int(sidecar.get("pid")) else None,
                    block=block,
                    receipts=receipts,
                    role=barrier_stamp_role,
                    isolation=barrier_stamp_isolation,
                )
            )
        lost = _lost_record(
            end_state="conflict" if conflict else "unknown",
            worker_uuid=uuid,
            pid=sidecar.get("pid") if _is_nonneg_int(sidecar.get("pid")) else None,
            run_id=str(sidecar.get("run_id", "")),
            unit=str(sidecar.get("unit", "")),
            attempt=sidecar.get("attempt") if _is_nonneg_int(sidecar.get("attempt")) else None,
            role=barrier_stamp_role,
            isolation=barrier_stamp_isolation,
        )
        if lost is not None:
            records.append(lost)
        _emit(str(sidecar.get("unit", "")), records)
        to_consume.extend([sidecar_path, _journal_for_sidecar(sidecar_path)])
        to_consume.extend(consumed)
        plan["consumed"] += 1
    plan["fenced"].sort()
    plan["unresolved"].sort()
    plan["skipped_units"] = sorted(
        {
            unit
            for unit, records in plan["cache_records"].items()
            if any(rec.get("end_state") == "unresolved" for rec in records)
        }
    )
    plan["collected_runs"] = sorted(seen_runs - retained_runs)
    if plan["cache_records"]:
        if not _write_barrier_staging(root, plan["cache_records"], plan["consumed"]):
            warnings.warn(
                f"counter resume barrier cannot stage recovery evidence in {root}; "
                "sources left unconsumed for retry",
                UserWarning,
                stacklevel=2,
            )
            plan["barrier_ok"] = False
            return plan
    _consume_producer_files(to_consume)
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


def append_supplement_records(
    state_file: Path | str, unit: str, records: list[dict[str, Any]]
) -> bool:
    """Append verbatim records to one unit's recovery supplements (never raises).

    Used for resume-barrier recovery records (partials + losses) aimed at
    units that will rerun: the rerun's cache prepends the supplements, so
    the recovered evidence folds in its own scope. Returns False (with a
    warning) on I/O failure.
    """
    if not records:
        return True
    path = supplements_path(state_file, unit)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            for record in records:
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
    "seal",
    "supplements_path",
    "sweep_orphans",
    "unseal",
    "validate_probe_receipt",
    "verify_producer",
    "write_recovery_supplements",
    "write_sidecar_atomic",
]
