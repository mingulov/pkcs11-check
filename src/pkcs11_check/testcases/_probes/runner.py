"""Parent-side launcher: run a _probes module in a fresh subprocess.

Replaces the ``run_with_coverage`` / ``run_raw_script`` launch paths for probe
modules.  PIN travels only via ``_P11CHECK_PIN`` env (I3).  Coverage is routed
to the correct accumulator by the ``coverage`` argument (I6).  The rv-trace is
recorded by ``record_subprocess_rv_trace`` (I7).  Timeouts are converted to rc
124 + ``SUBPROCESS_TIMEOUT_MARKER`` on stderr (I8).  The child is launched via
``python -u -m pkcs11_check.testcases._probes.<probe>`` (I11, no shell).

Probe-invariant legend (I1–I12): bare ``(I#)`` cites across the framework resolve
here — NOT June-gap I1–I7 or FABLE I-1–I-5. I1 crash isolation (crash-is-a-finding);
I2 honeypot (demand-zero mmap) semantics; I3 no PIN leakage (child gets the PIN via
_P11CHECK_PIN only); I4 classification stays parent-side (child prints data, never
classify/fail_as/xfail_as); I5 each family's output protocol unchanged; I6 coverage
preserved; I7 rv-trace preserved; I8 hang → rc 124 + timeout marker (crash-class
finding); I9 pytest markers unchanged; I10 behavioral equivalence via
compare-results; I11 Windows ABI (argv list, no shell quoting); I12 vendor-neutral
probes.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import warnings
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, final

from pkcs11_check.core._counters_durability import (
    COUNTERS_ATTEMPT_ENV,
    COUNTERS_DIR_ENV,
    COUNTERS_ROLE_ENV,
    COUNTERS_UNIT_ENV,
    PROBE_ATTEMPT_ENV,
    PROBE_ISOLATION_ENV,
    PROBE_PARENT_ENV,
    PROBE_ROLE_ENV,
    PROBE_RUN_ENV,
    PROBE_SEQ_ENV,
    PROBE_SIDECAR_ENV,
    PROBE_UNIT_ENV,
    CounterPersistenceError,
    _DeferProducerError,
    _is_sha256_hex,
    _prune_sidecar_tmps,
    _replay_probe_tmp_rows,
    _snapshot_covered_by,
    birth_token_for_pid,
    durability_dir,
    mark_probe_consumed,
    validate_probe_receipt,
)
from pkcs11_check.core.call_counters import (
    ISOLATION_ENV,
    assign_probe_seq,
    ensure_registered,
    flush_counters,
    forget_probe_spawn,
    get_worker_uuid,
    ingest_child_evidence,
    note_folded_probe_digest,
    note_lost_probe,
    note_probe_spawned,
    registration_info,
)
from pkcs11_check.core.counters_schema import is_lost_key, is_worker_uuid, mint_filename_nonce
from pkcs11_check.core.loader import SUPPORTED_INTERFACES
from pkcs11_check.core.process_observation import (
    SUBPROCESS_ABRUPT_EXIT_MARKER,
    build_process_observation,
    record_process_observation,
)
from pkcs11_check.core.subprocess_trace import record_subprocess_rv_trace
from pkcs11_check.testcases._probes.params import ProbeParams
from pkcs11_check.testcases._raw_subprocess import ingest_raw_subprocess_coverage
from pkcs11_check.testcases._subprocess_preamble import (
    SUBPROCESS_TIMEOUT_MARKER,
    SUBPROCESS_TIMEOUT_RC,
    ingest_subprocess_coverage,
)


def _as_text(stream: str | bytes | None) -> str:
    """Decode a possibly-bytes subprocess stream to text.

    ``TimeoutExpired.stdout`` / ``.stderr`` can be ``bytes`` even when
    ``subprocess.run`` is called with ``text=True``; the exception is raised
    mid-``communicate()`` before decoding completes.  This mirrors the same
    helper in ``_subprocess_preamble.py``.
    """
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode(errors="replace")
    return stream


@dataclass(frozen=True)
class ProbeResult:
    """Return value of :func:`run_probe`."""

    returncode: int
    stdout: str
    stderr: str
    observation: dict[str, object] | None = None


_PYTHON_TRACEBACK = "Traceback (most recent call last)"


def _normalize_interface_selector(value: object) -> str:
    """Canonicalize a supported selector exactly as the child treats auto values."""
    if value is None:
        return "auto"
    if not isinstance(value, str):
        raise ValueError(f"Unknown PKCS#11 interface {value!r}")
    normalized = value.strip().lower() or "auto"
    if normalized not in SUPPORTED_INTERFACES:
        raise ValueError(f"Unknown PKCS#11 interface {value!r}")
    return normalized


def _finalizer_ran(cov_path: str) -> bool:
    """Whether the child reached its own exit path, per the coverage file it always writes.

    ``probe_main`` writes this file from a ``finally`` block and again from ``atexit``, so
    a clean return, ``sys.exit``, ``SETUP_XFAIL``, or any uncaught Python exception all
    leave a parseable JSON object behind. Nothing Python-side can skip both writes. An
    empty or unreadable file on a non-zero exit therefore means the process was torn down
    below CPython -- i.e. the module terminated its host.

    Returns False on an unreadable or empty file. That alone is NOT sufficient to call a
    death abrupt -- see :func:`_module_terminated_process` for the conjunction that is.
    """
    try:
        with open(cov_path, encoding="utf-8") as fh:
            return isinstance(json.load(fh), dict)
    except RecursionError:
        # Deep-JSON hostile nesting proves the child finalized (it wrote a
        # non-empty file); a C-exit leaves empty/torn files (ValueError).
        # True here avoids abrupt misattribution; ingest still returns False
        # so the launcher accounts exactly one lost probe.
        return True
    except (OSError, ValueError):
        return False


def _module_terminated_process(rc: int, stderr: str, cov_path: str) -> bool:
    """Whether the MODULE tore the process down, rather than Python dying normally.

    Requires both halves, because neither alone is safe:

    * the child's finalizer never ran (:func:`_finalizer_ran`) -- but ``probe_main`` loads
      the params file and the module BEFORE registering that finalizer, so a bad params
      file or a module that will not load also leaves no coverage, and must never be
      reported as a provider crash;
    * and stderr carries no Python traceback -- a C ``exit()`` from inside a PKCS#11 call
      pre-empts CPython entirely, so there is nothing to print. Every Python-level death
      leaves a traceback, including the pre-registration failures above.

    A module that writes its own diagnostics to stderr before exiting is still caught: the
    test is for a traceback specifically, not for silence.

    The exit code is deliberately ``>= 0`` rather than ``> 0``: a C ``exit(0)`` from
    inside a PKCS#11 call skips the finalizer exactly like ``exit(n)`` does, so a clean
    code with no finalizer and no traceback is the same abrupt termination, not a pass.
    """
    return rc >= 0 and not _finalizer_ran(cov_path) and _PYTHON_TRACEBACK not in stderr


@final
class _UnreadableEvidence:
    """Sentinel: an evidence file exists but could not be read (I/O failure)."""

    __slots__ = ()


_UNREADABLE = _UnreadableEvidence()


def _read_probe_json(path: str | None) -> dict[str, Any] | None | _UnreadableEvidence:
    """Read one probe evidence file (never raises).

    Missing files and torn/unparseable content read as absent (None);
    a file that exists but fails to open/read reports _UNREADABLE, so
    the caller can retain it for a later retry instead of deleting
    possibly recoverable evidence (codex 6.2 F4).
    """
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return None
    except OSError:
        return _UNREADABLE
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def _delete_probe_sidecar(path: str | None, *, force_tmps: bool = False) -> bool:
    """Remove a probe sidecar and its adjudicated rewrite tmps (never raises).

    True when the sidecar is gone or absent. A missing file counts as
    deleted: the sidecar writer suppresses I/O failures, so valid
    coverage may arrive with no sidecar at all, and that must not
    escalate into a consumed-marker rename of nothing. Rewrite tmps
    triage through the shared collector prune (#88R3): unreadable
    tmps and complete-with-returns tmps without a usable baseline
    retain for retry/forensics (named loudly), everything else goes
    with the sidecar. ``force_tmps`` deletes tmps unconditionally
    for superseded evidence (a receipt-bound exit coverage already
    subsumes every mid-run tmp).
    """
    if not path:
        return True
    if force_tmps:
        parent = os.path.dirname(path) or "."
        try:
            names = os.listdir(parent)
        except OSError:
            names = []
        prefix = os.path.basename(path) + ".tmp-"
        for name in names:
            if name.startswith(prefix):
                try:
                    os.unlink(os.path.join(parent, name))
                except OSError:
                    pass
    else:
        # Parent-assigned paths (never evidence content): containment
        # anchors at the sidecar's own parent. This API accepts
        # sidecars anywhere (callers plant them outside the engaged
        # counters dir); trust here comes from assignment, not
        # location, so the check is a no-op by layout. Root stays a
        # required parameter so collection/sweep (untrusted evidence
        # paths) cannot pass an unanchored prune.
        _prune_sidecar_tmps(Path(path), root=Path(path).parent)
    try:
        os.unlink(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return True


def _legacy_subsumption_proof(
    body: dict[str, Any], seq: int, absorbed_rows: list[Any]
) -> tuple[tuple[str, int], list[dict[str, Any]]] | None:
    """(receipt, keys) when a stamped body is proved subsumed, else None (#88R10-4a).

    A stamped sidecar beside receipt-less exit coverage for the same
    probe is subsumed when its stamp validates against the caller seq,
    its unkeyed scalar is falsy (unkeyed remainders are unmatchable
    across the version gap: absorbing them additively double-counts on
    overlap and dropping them loses on disjointness), every stated
    loss key parses (anything stated-but-unparseable fails closed),
    and its rows subset the absorbed exit rows (the slot nonce plus
    the seq bind one probe execution, so a row-subset is a proved
    prefix, never a coincidental match). Callers absorb the returned
    keys with the coverage (idempotent union), record the receipt as
    a consumed probe (the anti-double-fold proof rides the same
    transaction, so a later commit failure cannot double-fold the
    retained copy (#88R11-4)), and retire the body at commit; a swap
    between absorb and commit still retains loudly, and the absorbed
    keys cannot double. The caller owns the launcher-clash check
    (foreign bodies never contribute).
    """
    validated = validate_probe_receipt(
        {"worker_uuid": body.get("worker_uuid"), "probe_seq": body.get("probe_seq")},
        seq,
    )
    if validated is None:
        return None
    if body.get("probes_lost"):
        return None
    raw_keys = body.get("lost_keys", [])
    if "lost_keys" not in body:
        keys: list[dict[str, Any]] = []
    elif isinstance(raw_keys, list) and all(is_lost_key(entry) for entry in raw_keys):
        keys = [dict(entry) for entry in raw_keys]
    else:
        return None
    rows = body.get("counters")
    if not isinstance(rows, list):
        return None
    if not _snapshot_covered_by(rows, frozenset(), 0, list(absorbed_rows), frozenset(), 0):
        return None
    return validated, keys


def _fallback_body_is_debris(fallback: Any) -> bool:
    """Whether a fallback sidecar body is safe to delete unabsorbed (#88R11-3).

    Only missing/torn bodies (no parsed content) and unstamped
    payload-free debris (no receipt, no counters, no loss) delete: a
    stated receipt or any evidence retains loudly for file collection
    to adjudicate under the body's own identity.
    """
    if fallback is None or isinstance(fallback, _UnreadableEvidence):
        return fallback is None
    if not isinstance(fallback, dict):
        return True
    if fallback.get("worker_uuid") is not None or fallback.get("probe_seq") is not None:
        return False
    counters = fallback.get("counters")
    if isinstance(counters, (list, tuple)):
        if len(counters) > 0:
            return False
    elif counters is not None:
        return False
    return not fallback.get("probes_lost") and not fallback.get("lost_keys")


def _commit_sidecar_owned(
    path: str,
    expected: tuple[str, int] | None,
    absorbed: tuple[int, list[Any], frozenset[tuple[str, int]], tuple[str, int] | None]
    | None = None,
) -> bool:
    """Whether the sidecar at commit time is provably this execution's (#88R8-3).

    A stale or foreign sidecar can reach the commit: deleting it would
    destroy foreign evidence and marking it would mint an unclaimable
    marker. Launcher stamps must agree when stated (both-sides rule);
    the child receipt must validate against the receipt the ingest
    just absorbed: an exact match proceeds, a mismatch/partial/garbage
    receipt retains, and version-incoherent shapes (evidence-bearing
    but unstamped bodies beside stamped coverage, or stamped bodies
    beside legacy-quiet coverage) retain for file collection to
    adjudicate -- only fully-quiet legacy pairs proceed by slot
    freshness. The one proved exception is legacy subsumption
    (#88R10-4a): when ``absorbed`` carries the exit coverage just
    folded, a stamped body proved to be its prefix (stamp, lossless
    scalar, parsed keys, row-subset) retires -- its counts already
    sit in the parent checkpoint and its keys were absorbed with the
    coverage. Missing or torn files proceed, as do unstamped
    payload-free files (nothing attributable to protect); any stated
    receipt validates first, even on a payload-free body -- an empty
    baseline must never authorize deleting a foreign rewrite
    (#88R10-3, #88R11-3). Unreadable bodies retain loudly.
    """
    fallback = _read_probe_json(path)
    if fallback is None:
        return True
    if isinstance(fallback, _UnreadableEvidence):
        warnings.warn(
            f"probe sidecar {path} unreadable at commit; evidence retained",
            UserWarning,
            stacklevel=2,
        )
        return False
    clash = _fallback_identity_clash(fallback, get_worker_uuid(), registration_info())
    if clash is not None:
        warnings.warn(
            f"probe sidecar {path} contradicts the launcher ({clash}); evidence retained",
            UserWarning,
            stacklevel=2,
        )
        return False
    worker = fallback.get("worker_uuid")
    pseq = fallback.get("probe_seq")
    if worker is None and pseq is None:
        counters = fallback.get("counters")
        has_counters = isinstance(counters, (list, tuple)) and len(counters) > 0
        # A loss-only body (retired records, zero retained rows) is
        # evidence too: an empty counters list beside a nonzero loss
        # scalar or a nonempty key set must enter receipt validation,
        # not retire by the payload-free quiet path -- retiring it
        # would also co-delete any surviving rewrite tmps unread
        # (#88R10-3).
        has_loss = bool(fallback.get("probes_lost")) or bool(fallback.get("lost_keys"))
        if not has_counters and not has_loss:
            return True
        if expected is None:
            return True
        warnings.warn(
            f"probe sidecar {path} carries evidence but no receipt under stamped "
            "coverage; evidence retained for file collection",
            UserWarning,
            stacklevel=2,
        )
        return False
    if expected is None:
        if absorbed is not None:
            proved = _legacy_subsumption_proof(fallback, absorbed[0], absorbed[1])
            if proved is not None:
                # A loss key that landed between absorb and commit was
                # never checkpointed: only a key set within the
                # absorbed set retires (#88R11-4). And the commit-time
                # receipt must equal the receipt proved and
                # checkpointed at ingestion: same rows and keys from a
                # different child are a different execution, never a
                # duplicate (#88R12-2).
                commit_receipt, commit_keys = proved
                commit_set = frozenset(
                    (key["parent_uuid"], key["probe_seq"]) for key in commit_keys
                )
                if commit_receipt == absorbed[3] and commit_set <= absorbed[2]:
                    return True
        if absorbed is not None and type(pseq) is int and pseq == absorbed[0]:
            warnings.warn(
                f"probe sidecar {path} states this probe's receipt under legacy-quiet "
                "coverage with unproved equivalence; evidence retained for file "
                "collection (which may double-count the overlap)",
                UserWarning,
                stacklevel=2,
            )
            return False
        warnings.warn(
            f"probe sidecar {path} states a receipt under legacy-quiet coverage; "
            "evidence retained for file collection",
            UserWarning,
            stacklevel=2,
        )
        return False
    if not is_worker_uuid(worker) or type(pseq) is not int:
        warnings.warn(
            f"probe sidecar {path} states a malformed receipt; evidence retained",
            UserWarning,
            stacklevel=2,
        )
        return False
    if (worker, pseq) != expected:
        warnings.warn(
            f"probe sidecar {path} contradicts the absorbed receipt "
            f"({worker!r}, {pseq!r} != {expected!r}); evidence retained",
            UserWarning,
            stacklevel=2,
        )
        return False
    return True


def _commit_probe_sidecar(
    path: str | None,
    *,
    force_tmps: bool = False,
    expected: tuple[str, int] | None = None,
    absorbed: tuple[int, list[Any], frozenset[tuple[str, int]], tuple[str, int] | None]
    | None = None,
) -> None:
    """Flush-then-delete: persist the parent checkpoint, then drop the sidecar.

    The parent checkpoint must be durable before the probe's own evidence
    goes: an ingest below K otherwise lives only in memory, and a worker
    death after the delete would lose the recoverable probe evidence. The
    sidecar is deleted only on flush success and retained on failure (the
    orphan collector then suppresses-or-folds it from disk). When the
    delete itself fails after a good flush, the sidecar renames to a
    consumed marker instead: the parent checkpoint already holds the
    counts, and the marker tells orphan adoption to suppress rather than
    fold them a second time. Delete and mark both require validated
    ownership first (a foreign, unreadable, or receipt-contradictory
    body is retained loudly); ``expected`` is the receipt the ingest
    just absorbed (None for legacy-quiet coverage). ``absorbed`` is
    the ``(seq, exit rows, absorbed keys, proved receipt)`` just
    folded from receipt-less coverage: it re-proves legacy
    subsumption at commit time, including the key-subset and
    receipt-identity checks (None disables the proof; only the
    legacy-quiet path passes it).

    Raises:
        CounterPersistenceError: When the parent checkpoint cannot be
            flushed (the sidecar is retained and the error propagates loud;
            the in-memory ingest is kept), or when neither delete nor the
            consumed-marker rename succeeds (proceeding would risk a
            silent double-fold).
    """
    flush_counters()
    if path is None:
        return
    if not _commit_sidecar_owned(path, expected, absorbed):
        return
    if _delete_probe_sidecar(path, force_tmps=force_tmps):
        return
    mark_probe_consumed(path, parent_uuid=get_worker_uuid())


def _fallback_identity_clash(
    fallback: dict[str, Any], launcher: str, info: dict[str, Any] | None
) -> str | None:
    """Describe a fallback/launcher identity contradiction, if any (#88R7-3).

    Mirrors the file-reunion ownership rule: the sidecar's stated
    parent/run/unit must agree with the launcher's, each compared only
    when both sides state it. A contradiction means the slot holds a
    stale or foreign sidecar that live ingest must not absorb (it
    would also poison the consumed marker the commit path writes).
    """
    parent = fallback.get("parent_uuid")
    if parent is not None and parent != launcher:
        return f"parent {parent!r} != launcher {launcher!r}"
    run = fallback.get("run_id")
    launcher_run = info.get("run_id") if info else None
    if run is not None and launcher_run is not None and run != launcher_run:
        return f"run {run!r} != launcher run {launcher_run!r}"
    unit = fallback.get("unit")
    launcher_unit = info.get("unit") if info else None
    if unit is not None and launcher_unit is not None and unit != launcher_unit:
        return f"unit {unit!r} != launcher unit {launcher_unit!r}"
    return None


def _admit_folded_probe_digest(data: Any, validated: tuple[str, int]) -> None:
    """Admit one folded probe's sidecar digest for attestation (#88R44-G7).

    Called on the folded paths only, after the receipt validated and
    only when the counters transaction applied (the caller gates on
    the ingest's admitted flag (#88R44-F5): a deduplicated re-ingest
    admits nothing, so proof never advances past counts). The digest
    attests the exact sidecar bytes the exit coverage was written
    against, keyed by the validated receipt. Absent (legacy coverage)
    or malformed digests admit nothing, silently: hostile payload
    values stay silent on the ingest path by design (add_lost_probes
    precedent); a systematically missing digest surfaces loudly at
    the veto as an unproved replacement hold instead. Never raises.
    """
    if not isinstance(data, dict):
        return
    digest = data.get("sidecar_digest")
    if digest is None:
        return
    if not _is_sha256_hex(digest):
        return
    note_folded_probe_digest(child_uuid=validated[0], probe_seq=validated[1], digest=digest)


def ingest_probe_payload(
    cov_path: str | Path,
    *,
    seq: int,
    sidecar_path: str | Path | None,
) -> Literal["folded", "partial", "lost"]:
    """Fold one probe child's counter evidence (receipt-aware, never raises loss).

    Returns ``"folded"`` when the coverage channel carried usable counters
    (a present receipt must exactly match the assigned ``seq``; absent
    receipt folds legacy-style with no receipt recorded; propagated
    grandchild receipts union in), ``"partial"`` when only the probe
    sidecar carried usable counters for this seq (counts fold, the receipt
    is suppressed — partial evidence never earns a folded receipt), and
    ``"lost"`` otherwise. After a commit the sidecar goes only once the
    parent checkpoint flushed (flush-then-delete); on flush failure the
    sidecar is retained and the persistence error propagates loud. A
    definitive miss still deletes the sidecar (torn, missing, or
    unstamped payload-free debris: nothing recoverable remains); a
    stated-but-mismatched or evidence-bearing body retains loudly
    for file collection to adjudicate under its own identity
    (#88R11-3). An unreadable sidecar (I/O failure) is retained for
    collection to retry, as is an unreadable rewrite tmp (replay
    defers to file collection instead of ingesting a return-less
    prefix). This function never
    accounts loss itself: the caller owns ``note_lost_probe`` for
    ``"partial"`` and ``"lost"`` alike (the single accounting site).

    Raises:
        CounterPersistenceError: When the parent checkpoint cannot be
            flushed after a commit (the sidecar is retained).
    """
    sidecar = str(sidecar_path) if sidecar_path is not None else None
    data = _read_probe_json(str(cov_path))
    if isinstance(data, _UnreadableEvidence):
        # Coverage files are never retried (collection reads sidecars,
        # never coverage), so an unreadable one falls through to the
        # sidecar fallback exactly like a torn one.
        data = None
    source = (get_worker_uuid(), seq)
    if data is not None:
        counters = data.get("call_counters")
        receipt = data.get("receipt")
        if isinstance(counters, (list, tuple)) and receipt is None:
            absorbed_rows = list(counters)
            # A stamped sidecar proved subsumed by this exit coverage
            # contributes its keyed losses to the same ingest (idempotent
            # union) so the commit below can retire it: without the keys
            # the retire would drop them, and without the retire the
            # retained copy would double-fold against the checkpoint
            # (#88R10-4a). The proof re-runs at commit against a fresh
            # read, so a swap between absorb and commit still retains.
            extra_keys: list[dict[str, Any]] = []
            proved_receipt: tuple[str, int] | None = None
            if sidecar is not None:
                pre = _read_probe_json(sidecar)
                if isinstance(pre, dict) and (
                    _fallback_identity_clash(pre, get_worker_uuid(), registration_info()) is None
                ):
                    proved = _legacy_subsumption_proof(pre, seq, absorbed_rows)
                    if proved is not None:
                        proved_receipt, extra_keys = proved
            raw_keys = data.get("lost_keys", ())
            if extra_keys:
                if not isinstance(raw_keys, (list, tuple)):
                    raw_keys = [raw_keys]
                merged_keys: Any = (*raw_keys, *extra_keys)
            else:
                merged_keys = raw_keys
            ingest_child_evidence(
                absorbed_rows,
                data.get("probes_lost", 0),
                data.get("receipts", ()),
                lost_keys=merged_keys,
                source=source,
                consumed_probe=proved_receipt,
            )
            if proved_receipt is not None:
                _admit_folded_probe_digest(data, proved_receipt)
            absorbed_keys = frozenset((key["parent_uuid"], key["probe_seq"]) for key in extra_keys)
            # Exit coverage subsumes every mid-run tmp (#88R3).
            _commit_probe_sidecar(
                sidecar,
                force_tmps=True,
                absorbed=(seq, absorbed_rows, absorbed_keys, proved_receipt),
            )
            return "folded"
        if isinstance(counters, (list, tuple)) and receipt is not None:
            validated = validate_probe_receipt(receipt, seq)
            if validated is not None:
                propagated: list[Any] = (
                    list(data["receipts"]) if isinstance(data.get("receipts"), list) else []
                )
                propagated.append({"worker_uuid": validated[0], "probe_seq": validated[1]})
                admitted = ingest_child_evidence(
                    list(counters),
                    data.get("probes_lost", 0),
                    propagated,
                    lost_keys=data.get("lost_keys", ()),
                    source=source,
                )
                # Admit the digest only when the counters transaction
                # applied (#88R44-F5): a deduplicated re-ingest must
                # not advance attestation past the counts it skipped.
                if admitted:
                    _admit_folded_probe_digest(data, validated)
                # Exit coverage subsumes every mid-run tmp (#88R3).
                _commit_probe_sidecar(sidecar, force_tmps=True, expected=validated)
                return "folded"
    fallback = _read_probe_json(sidecar)
    if isinstance(fallback, _UnreadableEvidence):
        # A read failure is not a definitive miss: retain the sidecar
        # so collection retries it later (codex 6.2 F4). The caller
        # still accounts the loss, so the outcome stays fail-visible.
        return "lost"
    if fallback is not None:
        fallback_receipt = {
            "worker_uuid": fallback.get("worker_uuid"),
            "probe_seq": fallback.get("probe_seq"),
        }
        fallback_counters = fallback.get("counters")
        validated_fallback = validate_probe_receipt(fallback_receipt, seq)
        if validated_fallback is not None and isinstance(fallback_counters, (list, tuple)):
            # The child is reaped before ingest (run_probe waits), so its
            # rewrite tmps are quiescent by construction: replay returns
            # onto the sidecar rows with the shared collector logic
            # (#88R3). Path freshness usually binds the run (the slot
            # path carries a per-spawn nonce), but a stale or foreign
            # sidecar can still land here: identity is validated
            # against the launcher before anything is absorbed (#88R7-3).
            assert sidecar is not None  # fallback read implies a path
            info = registration_info()
            clash = _fallback_identity_clash(fallback, get_worker_uuid(), info)
            if clash is not None:
                warnings.warn(
                    f"probe sidecar {sidecar} contradicts the launcher ({clash}); "
                    "evidence retained for file collection",
                    UserWarning,
                    stacklevel=2,
                )
                return "lost"
            try:
                # Divergent rewrites keep the orphan rows (quarantined
                # loudly inside the replay); the live path ingests that
                # baseline exactly like the file path folds it. Refused
                # garbage is warned inside the replay; live ingest has
                # no receipt flags (it never heals), so the flag reads
                # here only to keep the 3-tuple unpack aligned.
                # Containment anchors the engaged counters dir (authoritative),
                # never the sidecar's own parent: the sidecar path rides the
                # child payload, so deriving root from it would be
                # self-justifying (#88R44-F1b). The parent fallback covers
                # durability-off unit shapes only.
                quarantine_root = durability_dir() or Path(sidecar).parent
                fallback_counters, _divergent, _refused_garbage = _replay_probe_tmp_rows(
                    Path(sidecar),
                    validated_fallback[0],
                    validated_fallback[1],
                    fallback,
                    list(fallback_counters),
                    producer_run=info["run_id"] if info else None,
                    producer_unit=info["unit"] if info else None,
                    orphan_pid=fallback.get("pid"),
                    orphan_birth=fallback.get("birth_token"),
                    producer_uuid=get_worker_uuid(),
                    root=quarantine_root,
                )
            except _DeferProducerError:
                # An unreadable rewrite tmp is not a definitive miss:
                # retain everything for file collection to retry (the
                # caller still accounts the loss, so the outcome stays
                # fail-visible).
                return "lost"
            # The consumed identity rides inside the ingest transaction:
            # no checkpoint ever carries absorbed counts without their
            # anti-double-fold proof (codex RC4-R1-2; a post-ingest
            # note would leave a death window after the K auto-flush).
            ingest_child_evidence(
                list(fallback_counters),
                fallback.get("probes_lost", 0),
                (),
                lost_keys=fallback.get("lost_keys", ()),
                source=source,
                consumed_probe=validated_fallback,
            )
            _commit_probe_sidecar(sidecar, expected=validated_fallback)
            return "partial"
    if sidecar is not None and not _fallback_body_is_debris(fallback):
        # Torn coverage with an attributable or evidence-bearing body:
        # live ingest cannot attribute it (no validated receipt), but
        # deleting it would destroy evidence file collection can still
        # adjudicate under the body's own identity -- so it retains
        # loudly instead (#88R11-3). Only missing/torn bodies and
        # unstamped payload-free debris delete here.
        warnings.warn(
            f"probe sidecar {sidecar} unabsorbed at fallback "
            "(torn coverage, unattributable body); "
            "evidence retained for file collection",
            UserWarning,
            stacklevel=2,
        )
        return "lost"
    _delete_probe_sidecar(sidecar)
    return "lost"


def run_probe(
    probe: str,
    params: Mapping[str, Any],
    *,
    pin: str | None = None,
    timeout: int = 15,
    coverage: Literal["session", "raw"] = "session",
    interface: str | None = None,
) -> ProbeResult:
    """Launch a _probes module in a subprocess and return its result.

    Args:
        probe: Module name under ``pkcs11_check.testcases._probes`` (e.g. ``"session"``).
        params: Probe parameters dict.  Must include ``"module_path"``.  Must NOT contain
            any PIN-bearing key (``ProbeParams.dump`` raises ``PinInParamsError`` if one
            is found — Invariant I3).
        pin: User PIN.  Forwarded to the child via ``_P11CHECK_PIN`` env only (I3).
        timeout: Subprocess timeout in seconds.  Exceeded -> rc 124 + timeout marker (I8).
        coverage: ``"session"`` routes ingested coverage to the preamble accumulators
            (``ingest_subprocess_coverage``); ``"raw"`` routes to the raw accumulators
            (``ingest_raw_subprocess_coverage``) — Invariant I6.
        interface: Explicit PKCS#11 interface selector to serialize into the child params.
            An existing, different selector is rejected before the child is launched.

    Returns:
        :class:`ProbeResult` with ``returncode``, ``stdout``, ``stderr``.

    Raises:
        PinInParamsError: if ``params`` contains a PIN-bearing key.
    """
    serialized_params = dict(params)
    existing_interface = "interface" in serialized_params
    normalized_existing = (
        _normalize_interface_selector(serialized_params["interface"])
        if existing_interface
        else None
    )
    if interface is not None:
        normalized_requested = _normalize_interface_selector(interface)
        if existing_interface and normalized_existing != normalized_requested:
            raise ValueError(
                "conflicting interface selectors: "
                f"params contains {serialized_params['interface']!r}, "
                f"keyword requested {interface!r}"
            )
        serialized_params["interface"] = normalized_requested
    elif existing_interface:
        serialized_params["interface"] = normalized_existing
    payload = ProbeParams.dump(serialized_params)  # raises PinInParamsError on PIN keys (I3)

    env = dict(os.environ)
    if pin is not None:
        env["_P11CHECK_PIN"] = pin
    else:
        env.pop("_P11CHECK_PIN", None)

    # Probe children ride the receipt channel (coverage + probe sidecar),
    # never the registry: strip the counters identity so a grandchild can
    # neither register under its parent's (unit, attempt) nor flush into
    # the parent's evidence files (that would double-count on collection).
    # The F2 parent-context keys strip here too, so ambient values from an
    # enclosing probe never leak into this child's self-describing block.
    # FLUSH_K is deliberately NOT stripped: cadence policy inherits, so a
    # run batches uniformly (default 1 when unset anywhere).
    for counters_key in (
        COUNTERS_DIR_ENV,
        COUNTERS_UNIT_ENV,
        COUNTERS_ATTEMPT_ENV,
        COUNTERS_ROLE_ENV,
        PROBE_PARENT_ENV,
        PROBE_RUN_ENV,
        PROBE_UNIT_ENV,
        PROBE_ATTEMPT_ENV,
        PROBE_ROLE_ENV,
        PROBE_ISOLATION_ENV,
    ):
        env.pop(counters_key, None)
    probe_seq = assign_probe_seq()
    env[PROBE_SEQ_ENV] = str(probe_seq)
    probe_sidecar: str | None = None
    counters_root = durability_dir()
    if counters_root is not None:
        # Eager registration (rc3 Area B): the parent's registry entry is
        # published before the child can die, so a dead parent still leaves
        # attributable evidence for the reunion pass. Sealed raises before
        # the spawn (fail fast, no phantom traffic).
        registration = ensure_registered()
        assert registration is not None  # engaged above; sealed raises
        # Absolute spelling (#88R34-6): the slot path rides into the
        # parent-side spawn record, PROBE_SIDECAR_ENV, and the child's
        # own spawn file, and every reader resolves it against the
        # root -- a cwd-relative spelling would misresolve at
        # collection time. abspath normalizes without resolving
        # symlinks, so the final directory entry stays the identity.
        probe_sidecar = os.path.abspath(
            counters_root
            / f"probe-{get_worker_uuid()[:8]}-{probe_seq}-{mint_filename_nonce()}.json"
        )
        env[PROBE_SIDECAR_ENV] = probe_sidecar
        # F2: the child embeds these into its sidecar, making the orphan
        # self-describing even when the parent's registry is gone.
        env[PROBE_PARENT_ENV] = get_worker_uuid()
        # The run stamp comes from the validated registration, not
        # ambient env: a mid-run mutation must not cross-wire the
        # orphan's round (codex R10-F1).
        env[PROBE_RUN_ENV] = registration["run_id"]
        env[PROBE_UNIT_ENV] = os.environ.get(COUNTERS_UNIT_ENV, "")
        env[PROBE_ATTEMPT_ENV] = os.environ.get(COUNTERS_ATTEMPT_ENV, "0")
        env[PROBE_ROLE_ENV] = os.environ.get(COUNTERS_ROLE_ENV, "")
        env[PROBE_ISOLATION_ENV] = os.environ.get(ISOLATION_ENV, "")
    else:
        env.pop(PROBE_SIDECAR_ENV, None)

    params_fd, params_path = tempfile.mkstemp(suffix=".json", prefix="p11probe-")
    cov_fd, cov_path = tempfile.mkstemp(suffix=".json", prefix="p11cov-")
    os.close(cov_fd)
    env["_P11CHECK_SUBPROCESS_COVERAGE"] = cov_path

    rc: int | None = None
    out: str = ""
    err: str = ""
    timed_out = False

    try:
        with os.fdopen(params_fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)

        cmd = [sys.executable, "-u", "-m", f"pkcs11_check.testcases._probes.{probe}", params_path]
        # Popen + communicate, mirroring subprocess.run exactly
        # (same kwargs, same TimeoutExpired kill/reap/partial semantics
        # including the Windows re-collect): run() drops the child pid,
        # but the spawn record below needs it.
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            # F18: provider bytes on the pipe must not cost the markers.
            errors="replace",
            env=env,
        ) as proc:
            if probe_sidecar is not None:
                # Durable spawn record before the child can flush
                # (#88R22-4): a supervisor killed before its child
                # flushes must still leave the launch attributable, or
                # a first flush landing between passes would fold into
                # a retry that discards it. A failed record kills the
                # child and raises (fail fast: an untracked child
                # would silently reopen that hole).
                try:
                    note_probe_spawned(
                        probe_seq=probe_seq,
                        slot=probe_sidecar,
                        pid=proc.pid,
                        birth=birth_token_for_pid(proc.pid),
                    )
                except (ValueError, CounterPersistenceError):
                    # Reap without draining (#88R23-6): communicate()
                    # waits for pipe EOF, which a grandchild holding an
                    # inherited pipe delays past the probe timeout. The
                    # output is discarded (we raise), so wait() suffices
                    # on every platform (unlike the timeout path, which
                    # mirrors run()'s partial-output capture).
                    proc.kill()
                    proc.wait()
                    raise
            try:
                out, err = proc.communicate(timeout=timeout)
                rc = proc.returncode
            except subprocess.TimeoutExpired as exc:
                # TimeoutExpired.stdout/.stderr can be bytes even with text=True
                # (raised mid-communicate() before decoding) -- use _as_text (I8).
                proc.kill()
                if sys.platform == "win32":
                    exc.stdout, exc.stderr = proc.communicate()
                else:
                    proc.wait()
                timed_out = True
                out = _as_text(exc.stdout)
                err = _as_text(exc.stderr) + f"\n{SUBPROCESS_TIMEOUT_MARKER}:{timeout}s\n"  # I8
                rc = SUBPROCESS_TIMEOUT_RC

        # A non-negative exit code alone cannot tell "the module called exit() from inside
        # the PKCS#11 call" apart from "Python raised and died normally" -- both arrive
        # as rc>=0 (a C exit(0) looks exactly like a pass). The discriminator is the
        # coverage file: probe_main writes it from its
        # own `finally` AND from atexit, so every Python-level termination leaves
        # parseable JSON there, while a C exit()/_exit() bypasses CPython finalization
        # and leaves it empty. Publish that observation on stderr so it reaches every
        # downstream classifier and the visible stderr excerpt (mirrors the I8 timeout
        # marker above), rather than re-deriving it at each of the ~70 call sites.
        if rc is not None and not timed_out and _module_terminated_process(rc, err, cov_path):
            err += f"\n{SUBPROCESS_ABRUPT_EXIT_MARKER}:{rc}\n"

        if coverage == "raw":
            ingest_raw_subprocess_coverage(cov_path, ingest_counters=False)  # I6
        else:
            ingest_subprocess_coverage(cov_path, ingest_counters=False)  # I6
        try:
            counters_status = ingest_probe_payload(
                cov_path, seq=probe_seq, sidecar_path=probe_sidecar
            )
        except CounterPersistenceError:
            # A failed commit holds absorbed-or-absent evidence with no
            # durable checkpoint: strictly worse than "partial", so it
            # earns the same keyed loss note before the error propagates
            # (codex 6.2 F1). Without the note the run could read
            # complete with the child's unflushed tail silently missing.
            note_lost_probe(parent_uuid=get_worker_uuid(), probe_seq=probe_seq)
            raise
        if counters_status != "folded":
            # The child's C_* traffic never fully arrived (crash, corrupt
            # file, unattributable receipt, or sidecar-only partial
            # evidence): account it as lost (fw#73), keyed by this parent's
            # identity plus the assigned probe seqno so a late arrival can
            # heal exactly this claim. This is the only lost-probe
            # accounting site; ingests never account loss.
            note_lost_probe(parent_uuid=get_worker_uuid(), probe_seq=probe_seq)
        # The child has exited (communicate waited) whatever the outcome:
        # its spawn record is settled. Pruning is lazy (rides the next
        # flush); a crash before it leaves a stale record the death
        # check still resolves (#88R22-4).
        forget_probe_spawn(probe_seq)

        # I7 AFTER ingest + loss accounting: the rv-trace is an optional
        # diagnostic parse, so it must never run before (or block) counter
        # ingestion -- a poisoned trace marker would otherwise bypass both
        # ingestion and loss accounting (fw#73).
        record_subprocess_rv_trace(out, err)  # I7

        observation = build_process_observation(
            probe, "probe", 0, rc, timed_out=timed_out, stderr=err
        )
        record_process_observation(observation)
        return ProbeResult(returncode=rc, stdout=out, stderr=err, observation=observation)
    finally:
        # The params file is a standalone-repro artifact, useful only for a
        # failed probe. Retain it only when the debug env var is set AND the probe
        # failed; otherwise always delete it. Now that run_probe drives real
        # probes, expected crash(rc<0)/timeout(124) outcomes are routine, so
        # unconditional on-failure retention would accumulate p11probe-*.json in
        # TMPDIR without bound. The coverage temp is always removed.
        keep_params = (
            rc is not None and rc != 0 and bool(os.environ.get("PKCS11_CHECK_KEEP_PROBE_PARAMS"))
        )
        to_remove = [cov_path] if keep_params else [cov_path, params_path]
        for p in to_remove:
            try:
                os.unlink(p)
            except OSError:
                pass
