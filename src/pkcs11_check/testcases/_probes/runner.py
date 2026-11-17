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
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pkcs11_check.core._counters_durability import (
    COUNTERS_ATTEMPT_ENV,
    COUNTERS_DIR_ENV,
    COUNTERS_ROLE_ENV,
    COUNTERS_UNIT_ENV,
    PROBE_SEQ_ENV,
    PROBE_SIDECAR_ENV,
    durability_dir,
    mark_probe_consumed,
    validate_probe_receipt,
)
from pkcs11_check.core.call_counters import (
    assign_probe_seq,
    flush_counters,
    get_worker_uuid,
    ingest_child_evidence,
    note_lost_probe,
)
from pkcs11_check.core.counters_schema import mint_filename_nonce
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


def _read_probe_json(path: str | None) -> dict[str, Any] | None:
    """Read one probe evidence file; missing/torn reads as absent (never raises)."""
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def _delete_probe_sidecar(path: str | None) -> bool:
    """Remove a probe sidecar (never raises). True when gone or absent.

    A missing file counts as deleted: the sidecar writer suppresses I/O
    failures, so valid coverage may arrive with no sidecar at all, and
    that must not escalate into a consumed-marker rename of nothing.
    """
    if not path:
        return True
    try:
        os.unlink(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return True


def _commit_probe_sidecar(path: str | None) -> None:
    """Flush-then-delete: persist the parent checkpoint, then drop the sidecar.

    The parent checkpoint must be durable before the probe's own evidence
    goes: an ingest below K otherwise lives only in memory, and a worker
    death after the delete would lose the recoverable probe evidence. The
    sidecar is deleted only on flush success and retained on failure (the
    orphan collector then suppresses-or-folds it from disk). When the
    delete itself fails after a good flush, the sidecar renames to a
    consumed marker instead: the parent checkpoint already holds the
    counts, and the marker tells orphan adoption to suppress rather than
    fold them a second time.

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
    if _delete_probe_sidecar(path):
        return
    mark_probe_consumed(path)


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
    definitive miss still deletes the sidecar (validated-unusable, torn, or
    missing: nothing recoverable remains). This function never accounts
    loss itself: the caller owns ``note_lost_probe`` for ``"partial"`` and
    ``"lost"`` alike (the single accounting site).

    Raises:
        CounterPersistenceError: When the parent checkpoint cannot be
            flushed after a commit (the sidecar is retained).
    """
    sidecar = str(sidecar_path) if sidecar_path is not None else None
    data = _read_probe_json(str(cov_path))
    source = (get_worker_uuid(), seq)
    if data is not None:
        counters = data.get("call_counters")
        receipt = data.get("receipt")
        if isinstance(counters, (list, tuple)) and receipt is None:
            ingest_child_evidence(
                list(counters),
                data.get("probes_lost", 0),
                data.get("receipts", ()),
                lost_keys=data.get("lost_keys", ()),
                source=source,
            )
            _commit_probe_sidecar(sidecar)
            return "folded"
        if isinstance(counters, (list, tuple)) and receipt is not None:
            validated = validate_probe_receipt(receipt, seq)
            if validated is not None:
                propagated: list[Any] = (
                    list(data["receipts"]) if isinstance(data.get("receipts"), list) else []
                )
                propagated.append({"worker_uuid": validated[0], "probe_seq": validated[1]})
                ingest_child_evidence(
                    list(counters),
                    data.get("probes_lost", 0),
                    propagated,
                    lost_keys=data.get("lost_keys", ()),
                    source=source,
                )
                _commit_probe_sidecar(sidecar)
                return "folded"
    fallback = _read_probe_json(sidecar)
    if fallback is not None:
        fallback_receipt = {
            "worker_uuid": fallback.get("worker_uuid"),
            "probe_seq": fallback.get("probe_seq"),
        }
        fallback_counters = fallback.get("counters")
        if validate_probe_receipt(fallback_receipt, seq) is not None and isinstance(
            fallback_counters, (list, tuple)
        ):
            ingest_child_evidence(
                list(fallback_counters),
                0,
                (),
                lost_keys=fallback.get("lost_keys", ()),
                source=source,
            )
            _commit_probe_sidecar(sidecar)
            return "partial"
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
    for counters_key in (
        COUNTERS_DIR_ENV,
        COUNTERS_UNIT_ENV,
        COUNTERS_ATTEMPT_ENV,
        COUNTERS_ROLE_ENV,
    ):
        env.pop(counters_key, None)
    probe_seq = assign_probe_seq()
    env[PROBE_SEQ_ENV] = str(probe_seq)
    probe_sidecar: str | None = None
    counters_root = durability_dir()
    if counters_root is not None:
        probe_sidecar = str(
            counters_root
            / f"probe-{get_worker_uuid()[:8]}-{probe_seq}-{mint_filename_nonce()}.json"
        )
        env[PROBE_SIDECAR_ENV] = probe_sidecar
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
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                # F18: provider bytes on the pipe must not cost the markers.
                errors="replace",
                env=env,
                timeout=timeout,
            )
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            # TimeoutExpired.stdout/.stderr can be bytes even with text=True
            # (raised mid-communicate() before decoding) -- use _as_text (I8).
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
        counters_status = ingest_probe_payload(cov_path, seq=probe_seq, sidecar_path=probe_sidecar)
        if counters_status != "folded":
            # The child's C_* traffic never fully arrived (crash, corrupt
            # file, unattributable receipt, or sidecar-only partial
            # evidence): account it as lost (fw#73), keyed by this parent's
            # identity plus the assigned probe seqno so a late arrival can
            # heal exactly this claim. This is the only lost-probe
            # accounting site; ingests never account loss.
            note_lost_probe(parent_uuid=get_worker_uuid(), probe_seq=probe_seq)

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
