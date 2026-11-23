"""Collection-safe PKCS#11 capability probing via a helper subprocess.

Counter accounting (rc2 Task 4): the census probe (``test`` CLI) and the
recovery liveness probes count their provider calls through the standard
``_call`` choke point into durability sidecars (role ``preflight``); the
parent collects each child into synthesized ``preflight``-bucket session
records (or gap-only partials + identity-bearing losses) appended to a
retained counter-only JSONL evidence file. ``doctor`` and the pytest-plugin
manifest re-probe never engage: their children inherit a scrubbed env, so a
stray caller ``PKCS11_CHECK_COUNTERS_DIR`` cannot leak registrations into
a run they do not belong to (the ``test`` CLI drops such a value outright
and allocates its own run-owned dir instead).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import warnings
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from pkcs11_check.core._counters_durability import (
    COUNTERS_ATTEMPT_ENV,
    COUNTERS_DIR_ENV,
    COUNTERS_ROLE_ENV,
    COUNTERS_UNIT_ENV,
    JOURNAL_SUFFIX,
    PROBE_ATTEMPT_ENV,
    PROBE_ISOLATION_ENV,
    PROBE_PARENT_ENV,
    PROBE_ROLE_ENV,
    PROBE_RUN_ENV,
    PROBE_SEQ_ENV,
    PROBE_SIDECAR_ENV,
    PROBE_UNIT_ENV,
    SIDECAR_SUFFIX,
    end_state_for_attempt,
    read_json_file,
    read_registry_file,
    reject_reserved_run_id,
)
from pkcs11_check.core.call_counters import (
    RUN_ID_ENV,
    CounterPersistenceError,
    flush_counters,
)
from pkcs11_check.core.counters_schema import (
    REGISTRY_DIRNAME,
    ensure_five_buckets,
    is_module_first_block,
    is_preflight_synth_record,
    is_receipt,
    is_worker_uuid,
)
from pkcs11_check.core.crash_codes import (
    crash_detail_name,
    ctypes_access_violation_code,
    is_crash_returncode,
)
from pkcs11_check.core.loader import load_module
from pkcs11_check.core.process_observation import build_process_observation
from pkcs11_check.raw.bootstrap import resolve_slot_id

#: Env key carrying the retained preflight evidence path (parent-side only;
#: never forwarded to the child). Set by the ``test`` CLI; recovery probes
#: resolve it from the environment.
PREFLIGHT_EVIDENCE_ENV = "PKCS11_CHECK_PREFLIGHT_EVIDENCE"

#: Registry/sidecar unit key for the CLI census probe.
PREFLIGHT_UNIT = "preflight"

#: Reason carried by error manifests caused by counter persistence (never the
#: load-failure reason: the module may be fine while counting is broken).
COUNTER_PERSISTENCE_REASON = "counter_persistence"

#: Child-env keys scrubbed from every preflight child. Disengaged children
#: (doctor, plugin re-probe) inherit none of them, so they can neither
#: register nor flush; engaged children get the overlay below instead.
_SCRUBBED_CHILD_ENV_KEYS = frozenset(
    {
        COUNTERS_DIR_ENV,
        COUNTERS_UNIT_ENV,
        COUNTERS_ATTEMPT_ENV,
        COUNTERS_ROLE_ENV,
        RUN_ID_ENV,
        PREFLIGHT_EVIDENCE_ENV,
        PROBE_SEQ_ENV,
        PROBE_SIDECAR_ENV,
        PROBE_PARENT_ENV,
        PROBE_RUN_ENV,
        PROBE_UNIT_ENV,
        PROBE_ATTEMPT_ENV,
        PROBE_ROLE_ENV,
        PROBE_ISOLATION_ENV,
    }
)


@dataclass(frozen=True)
class PreflightCounters:
    """Parent-side engagement for one counted preflight child."""

    counters_dir: Path
    run_id: str
    unit: str
    attempt: int
    evidence_path: Path

    def __post_init__(self) -> None:
        # Direct construction bypasses resolve_from_env, so the
        # dataclass itself rejects the sentinel (codex R10-F2).
        reject_reserved_run_id(self.run_id)

    @classmethod
    def resolve_from_env(cls, *, unit: str, attempt: int) -> PreflightCounters | None:
        """Resolve engagement from the environment, else None (disengaged).

        All three keys (CLI-allocated counters dir, CLI-seeded run id,
        CLI-set evidence path) must be present and non-empty; anything less
        is an ordinary uncounted probe, never a partial engagement.
        """
        counters_dir = os.environ.get(COUNTERS_DIR_ENV, "").strip()
        run_id = os.environ.get(RUN_ID_ENV, "").strip()
        evidence = os.environ.get(PREFLIGHT_EVIDENCE_ENV, "").strip()
        if not counters_dir or not run_id or not evidence:
            return None
        reject_reserved_run_id(run_id)
        return cls(
            counters_dir=Path(counters_dir),
            run_id=run_id,
            unit=unit,
            attempt=attempt,
            evidence_path=Path(evidence),
        )


def preflight_child_env(counters: PreflightCounters | None) -> dict[str, str]:
    """Build the preflight child's environment (scrubbed, then overlaid).

    The scrub always applies: even a disengaged child must not inherit a
    stale caller identity. The overlay (dir + run id + preflight role)
    applies only when engaged.
    """
    env = {key: value for key, value in os.environ.items() if key not in _SCRUBBED_CHILD_ENV_KEYS}
    if counters is not None:
        env[COUNTERS_DIR_ENV] = str(counters.counters_dir)
        env[COUNTERS_UNIT_ENV] = counters.unit
        env[COUNTERS_ATTEMPT_ENV] = str(counters.attempt)
        env[COUNTERS_ROLE_ENV] = PREFLIGHT_UNIT
        env[RUN_ID_ENV] = counters.run_id
    return env


def preflight_evidence_path_for_state(state_file: Path) -> Path:
    """Return the accumulating evidence file for one isolated run series.

    A pure function of the state path (like the recovery sidecar), so the
    F-038 state guard already covers it and resume rounds accumulate while
    fresh runs reset it.
    """
    return state_file.with_name(f"{state_file.name}.preflight-counters.jsonl")


def rebucket_to_preflight(block: Any) -> dict[str, Any] | None:
    """Re-bucket a module-first block entirely under ``preflight``, else None.

    The child records under its natural buckets (loader traffic lands in
    ``module_init``, the census under the default phase); the parent
    synthesizes one ``preflight`` bucket per module with merged functions
    and RVs, zero-filling the other four buckets (uniform-five emission).
    Totals, RV names, and the ``sum(by_rv) <= calls`` bound are
    preserved exactly; garbage in yields None (never invented counts).
    """
    if not is_module_first_block(block):
        return None
    by_module: dict[str, Any] = {}
    total = 0
    for module, module_block in block["by_module"].items():
        merged_by_fn: dict[str, Any] = {}
        calls = 0
        for bucket in module_block["buckets"].values():
            calls += bucket["calls"]
            for fn, fn_block in bucket["by_fn"].items():
                target = merged_by_fn.setdefault(fn, {"calls": 0, "by_rv": {}})
                target["calls"] += fn_block["calls"]
                for rv, leaf in fn_block["by_rv"].items():
                    slot = target["by_rv"].setdefault(rv, {"name": leaf["name"], "count": 0})
                    slot["count"] += leaf["count"]
        by_module[module] = {
            "calls": calls,
            "buckets": ensure_five_buckets({"preflight": {"calls": calls, "by_fn": merged_by_fn}}),
        }
        total += calls
    uniform = {"total_calls": total, "by_module": by_module}
    return uniform if is_module_first_block(uniform) else None


def _is_pid(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _valid_receipts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        {"worker_uuid": entry["worker_uuid"], "probe_seq": entry["probe_seq"]}
        for entry in value
        if is_receipt(entry)
    ]


def _journal_for_sidecar(sidecar_path: Path) -> Path:
    if sidecar_path.name.endswith(SIDECAR_SUFFIX):
        stem = sidecar_path.name[: -len(SIDECAR_SUFFIX)]
    else:
        stem = sidecar_path.name
    return sidecar_path.with_name(stem + JOURNAL_SUFFIX)


def _consume_preflight_files(paths: list[Path]) -> None:
    """Delete collected evidence files (best effort, never raises)."""
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            tmps = list(path.parent.glob(f"{path.name}.tmp-*"))
        except OSError:
            continue
        for tmp in tmps:
            try:
                tmp.unlink()
            except OSError:
                pass


@dataclass
class _ProducerEvidence:
    """One collected producer: identity + sidecar payload + owned files."""

    worker_uuid: str | None
    pid: int | None
    sidecar: dict[str, Any] | None
    sidecar_missing: bool
    journal_lines: list[str]
    files: list[Path]


def _matching_preflight_producers(counters: PreflightCounters) -> list[_ProducerEvidence]:
    """Collect the evidence bundles for one (run, unit, attempt) launch.

    Registry matches are strict on all three keys; sidecars without a
    matching registry are adopted by their self-described identity (torn
    registry, surviving sidecar). Anything else in the dir belongs to
    another producer and is left untouched.
    """
    bundles: list[_ProducerEvidence] = []
    seen_uuids: set[str] = set()
    reg_dir = counters.counters_dir / REGISTRY_DIRNAME
    if reg_dir.is_dir():
        for registry_path in sorted(reg_dir.glob("*.json")):
            content = read_registry_file(registry_path)
            if content is None:
                continue
            if (
                content.get("run_id") != counters.run_id
                or content.get("unit") != counters.unit
                or content.get("attempt") != counters.attempt
            ):
                continue
            uuid = content["worker_uuid"]
            seen_uuids.add(uuid)
            sidecar_path = Path(str(content.get("sidecar", "")))
            sidecar = read_json_file(sidecar_path)
            journal_path = _journal_for_sidecar(sidecar_path)
            bundles.append(
                _ProducerEvidence(
                    worker_uuid=uuid,
                    pid=content.get("pid") if _is_pid(content.get("pid")) else None,
                    sidecar=sidecar if isinstance(sidecar, dict) else None,
                    sidecar_missing=not sidecar_path.exists(),
                    journal_lines=_read_journal_lines(journal_path),
                    files=[registry_path, sidecar_path, journal_path],
                )
            )
    for sidecar_path in sorted(counters.counters_dir.glob(f"*{SIDECAR_SUFFIX}")):
        sidecar = read_json_file(sidecar_path)
        if not isinstance(sidecar, dict):
            continue
        uuid = sidecar.get("worker_uuid")
        if not is_worker_uuid(uuid) or uuid in seen_uuids:
            continue
        assert isinstance(uuid, str)
        if (
            sidecar.get("run_id") != counters.run_id
            or sidecar.get("unit") != counters.unit
            or sidecar.get("attempt") != counters.attempt
        ):
            continue
        seen_uuids.add(uuid)
        journal_path = _journal_for_sidecar(sidecar_path)
        bundles.append(
            _ProducerEvidence(
                worker_uuid=uuid,
                pid=sidecar.get("pid") if _is_pid(sidecar.get("pid")) else None,
                sidecar=sidecar,
                sidecar_missing=False,
                journal_lines=_read_journal_lines(journal_path),
                files=[sidecar_path, journal_path],
            )
        )
    return bundles


def _read_journal_lines(journal_path: Path) -> list[str]:
    try:
        raw = journal_path.read_text(encoding="utf-8")
    except (OSError, ValueError):
        return []
    return [line for line in raw.splitlines() if line.strip()]


def _synth_session_record(
    *,
    pid: int,
    worker_uuid: str,
    run_id: str,
    block: dict[str, Any],
    receipts: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Build the authoritative preflight synth, else None (never invalid)."""
    record: dict[str, Any] = {
        "$report_type": "CallCountersReport",
        "pid": pid,
        "worker_uuid": worker_uuid,
        "isolation": "none",
        "probes_lost": 0,
        "run_id": run_id,
        "role": "preflight",
        "total_calls": block["total_calls"],
        "by_module": block["by_module"],
    }
    if receipts:
        record["receipts"] = sorted(
            receipts, key=lambda item: (item["worker_uuid"], item["probe_seq"])
        )
    return record if is_preflight_synth_record(record) else None


def _preflight_partial_record(
    *,
    worker_uuid: str,
    run_id: str,
    unit: str,
    attempt: int,
    pid: int | None,
    block: dict[str, Any],
    receipts: list[dict[str, Any]],
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "$report_type": "CallCountersPartial",
        "worker_uuid": worker_uuid,
        "truncated": True,
        "total_calls": block["total_calls"],
        "by_module": block["by_module"],
        "run_id": run_id,
        "unit": unit,
        "attempt": attempt,
        "role": "preflight",
        "isolation": "none",
        "probe_snapshots": [],
    }
    if pid is not None:
        record["pid"] = pid
    if receipts:
        record["receipts"] = sorted(
            receipts, key=lambda item: (item["worker_uuid"], item["probe_seq"])
        )
    return record


def _preflight_lost_record(
    *,
    end_state: str,
    worker_uuid: str | None,
    pid: int | None,
    run_id: str,
    unit: str,
    attempt: int,
) -> dict[str, Any] | None:
    """Build an identity-bearing loss, else None when nothing is nameable."""
    if worker_uuid is None and pid is None:
        return None
    record: dict[str, Any] = {
        "$report_type": "CallCountersLost",
        "end_state": end_state,
        "scope_index": 0,  # placeholder: the extractor rebases to the assembly scope
        "run_id": run_id,
        "unit": unit,
        "attempt": attempt,
    }
    if worker_uuid is not None:
        record["worker_uuid"] = worker_uuid
    if pid is not None:
        record["pid"] = pid
    return record


def collect_preflight_counters(
    counters: PreflightCounters,
    *,
    child_pid: int | None,
    returncode: int | None,
    timed_out: bool,
    manifest_status: str,
    manifest_reason: str | None,
) -> tuple[list[dict[str, Any]], Callable[[], None]]:
    """Collect one preflight child's counter evidence into JSONL records.

    A clean exit with evidence yields the authoritative preflight synth
    (re-bucketed session); a dead child with evidence yields a gap-only
    partial plus an identity-bearing loss; no evidence after possible
    provider entry yields a pid-bearing loss -- except ``module_unloadable``
    with no registration, which proves the provider was never entered and
    yields nothing. A ``PreflightNote`` heads every non-trivial outcome; it
    explains, never replaces, the evidence.

    Non-consuming: returns ``(records, commit)`` where collection itself
    is read-only. The caller appends and closes the retained JSONL
    evidence FIRST and calls the (best-effort, never-raising) commit
    only on success; on failure the source files stay for a retry.
    A repeated collection returns the same records -- the extractor
    folds uuid-bearing sessions first-wins, so a torn-append retry
    counts exactly once. Only after commit does a second collection
    find nothing (loud unknown loss on ``ok``, never a double count).
    """
    bundles = _matching_preflight_producers(counters)
    owned: list[Path] = []
    for bundle in bundles:
        owned.extend(bundle.files)

    def _commit() -> None:
        _consume_preflight_files(owned)

    clean_exit = returncode == 0 and not timed_out
    attempt_end = end_state_for_attempt(
        status=manifest_status, returncode=returncode, timed_out=timed_out
    )
    records: list[dict[str, Any]] = []
    for bundle in sorted(bundles, key=lambda item: item.worker_uuid or f"pid-{item.pid}"):
        records.extend(
            _bundle_records(
                counters,
                bundle,
                child_pid=child_pid,
                clean_exit=clean_exit,
                attempt_end=attempt_end,
            )
        )
    if not bundles:
        if clean_exit and manifest_reason == "module_unloadable":
            return [], _commit
        lost = _preflight_lost_record(
            end_state=attempt_end if not clean_exit else "unknown",
            worker_uuid=None,
            pid=child_pid,
            run_id=counters.run_id,
            unit=counters.unit,
            attempt=counters.attempt,
        )
        if lost is not None:
            records.append(lost)
    if not records:
        return [], _commit
    if manifest_status != "ok" or any(
        record.get("$report_type") == "CallCountersLost" for record in records
    ):
        records.insert(
            0,
            {
                "$report_type": "PreflightNote",
                "status": manifest_status,
                "reason": manifest_reason or manifest_status,
                "run_id": counters.run_id,
                "unit": counters.unit,
            },
        )
    return records, _commit


def _bundle_records(
    counters: PreflightCounters,
    bundle: _ProducerEvidence,
    *,
    child_pid: int | None,
    clean_exit: bool,
    attempt_end: str,
) -> list[dict[str, Any]]:
    """Fold one producer bundle into synth / partial+lost / lost records."""
    pid = bundle.pid if bundle.pid is not None else child_pid
    assert bundle.worker_uuid is not None  # registries and adoptees always name one
    in_progress = bundle.sidecar.get("in_progress") if bundle.sidecar is not None else None
    block = in_progress if is_module_first_block(in_progress) else None
    receipts = _valid_receipts(bundle.sidecar.get("receipts") if bundle.sidecar else None)
    # Torn means evidence corruption (present but unusable); a missing file
    # is absence, not corruption, and reads the attempt's end state.
    torn = (bundle.sidecar is not None and block is None) or (
        bundle.sidecar is None and not bundle.sidecar_missing
    )
    foreign_journal = bool(bundle.journal_lines)  # preflight children never publish windows
    rebucketed = rebucket_to_preflight(block) if block is not None else None
    if clean_exit and not torn and not foreign_journal and block is not None:
        if pid is not None and rebucketed is not None:
            synth = _synth_session_record(
                pid=pid,
                worker_uuid=bundle.worker_uuid,
                run_id=counters.run_id,
                block=rebucketed,
                receipts=receipts,
            )
            if synth is not None:
                return [synth]
        # A clean exit whose synth cannot be built honestly (invalid shape,
        # unnameable pid) keeps its counts as a partial plus a conflict.
        fallback = rebucketed if rebucketed is not None else block
        lost = _preflight_lost_record(
            end_state="conflict",
            worker_uuid=bundle.worker_uuid,
            pid=pid,
            run_id=counters.run_id,
            unit=counters.unit,
            attempt=counters.attempt,
        )
        partial = _preflight_partial_record(
            worker_uuid=bundle.worker_uuid,
            run_id=counters.run_id,
            unit=counters.unit,
            attempt=counters.attempt,
            pid=pid,
            block=fallback,
            receipts=receipts,
        )
        return [partial, lost] if lost is not None else [partial]
    if block is not None and rebucketed is not None:
        # Clean exits with clean evidence returned above; a surviving
        # journal on a clean exit is corruption, hence conflict.
        end_state = "conflict" if clean_exit else attempt_end
        lost = _preflight_lost_record(
            end_state=end_state,
            worker_uuid=bundle.worker_uuid,
            pid=pid,
            run_id=counters.run_id,
            unit=counters.unit,
            attempt=counters.attempt,
        )
        partial = _preflight_partial_record(
            worker_uuid=bundle.worker_uuid,
            run_id=counters.run_id,
            unit=counters.unit,
            attempt=counters.attempt,
            pid=pid,
            block=rebucketed,
            receipts=receipts,
        )
        return [partial, lost] if lost is not None else [partial]
    if torn or foreign_journal:
        end_state = "conflict"
    elif clean_exit:
        end_state = "unknown"
    else:
        end_state = attempt_end
    lost = _preflight_lost_record(
        end_state=end_state,
        worker_uuid=bundle.worker_uuid,
        pid=pid,
        run_id=counters.run_id,
        unit=counters.unit,
        attempt=counters.attempt,
    )
    return [lost] if lost is not None else []


def append_preflight_evidence(evidence_path: Path, records: list[dict[str, Any]]) -> int:
    """Append one bookended evidence scope; return the records appended.

    A no-op (the file untouched) when there is nothing to retain. Raises
    ``OSError`` on I/O failure -- the caller warns, never fails the run.
    """
    if not records:
        return 0
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    # LF-exact bytes on every platform (machine artifact, like report.jsonl).
    with evidence_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps({"$report_type": "SessionStart"}) + "\n")
        for record in records:
            handle.write(json.dumps(record) + "\n")
        handle.write(json.dumps({"$report_type": "SessionFinish", "exitstatus": 0}) + "\n")
    return len(records)


@dataclass(frozen=True)
class CapabilityManifest:
    """Minimal capability snapshot used for safe skip decisions."""

    status: str
    module_path: str
    requested_interface: str
    interface_version: str | None
    slot_index: int
    slot_count: int | None
    mechanisms: list[str]
    functions: list[str] = field(default_factory=list)
    error: str | None = None
    reason: str | None = None
    mechanism_info: dict[str, dict[str, Any]] = field(default_factory=dict)
    process_observation: dict[str, Any] | None = None


def _mechanism_name(value: object) -> str:
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    if name is not None:
        return str(name)
    if isinstance(value, int):
        return f"0x{value:08x}"
    return str(value)


def probe_capabilities(module: Path, interface: str, slot: int) -> CapabilityManifest:
    """Probe module capabilities inside a short-lived helper process."""
    load_failure = False
    try:
        try:
            p11 = load_module(module, interface=interface)
        except Exception:
            load_failure = True
            raise
        slots = p11.get_slots(token_present=True)
        # Single slot resolver (H-9): the old `slot >= len(slots)` guard let a
        # negative index wrap to the last slot. Out-of-range now raises
        # IndexError, caught below as an error manifest -- never a wrong slot.
        slot_obj = resolve_slot_id(slots, slot)
        raw_mechs = slot_obj.get_mechanisms()
        mechanisms = sorted(_mechanism_name(mech) for mech in raw_mechs)
        mech_info: dict[str, dict[str, Any]] = {}
        for mech in raw_mechs:
            name = _mechanism_name(mech)
            try:
                info = slot_obj.get_mechanism_info(mech)
            except Exception as exc:
                # One hostile mechanism must not void the whole manifest:
                # record the failure against that mechanism and continue.
                # Downstream (MechanismCatalog.from_manifest) tolerates the
                # missing flags/min/max keys via .get() defaults.
                mech_info[name] = {"error": f"{type(exc).__name__}: {exc}"}
                continue
            mech_info[name] = {
                "flags": int(info.flags),
                "min_key_size": int(info.min_key_length),
                "max_key_size": int(info.max_key_length),
            }
        return CapabilityManifest(
            status="ok",
            module_path=str(module),
            requested_interface=interface,
            interface_version=p11.interface_version,
            slot_index=slot,
            slot_count=len(slots),
            mechanisms=mechanisms,
            functions=sorted(p11.raw.available_function_names()),
            mechanism_info=mech_info,
        )
    except CounterPersistenceError as exc:
        # Harness-side counting failure (sealed/unwritable dir): the provider
        # call that triggered it never ran (record-before-invoke at the
        # choke point), so the census is incomplete for harness reasons --
        # never the load-failure reason, which claims the module is at fault.
        return CapabilityManifest(
            status="error",
            module_path=str(module),
            requested_interface=interface,
            interface_version=None,
            slot_index=slot,
            slot_count=None,
            mechanisms=[],
            error=f"call-counter persistence failed: {exc}",
            reason=COUNTER_PERSISTENCE_REASON,
        )
    except Exception as exc:
        windows_status = ctypes_access_violation_code(exc)
        return CapabilityManifest(
            status="crashed" if windows_status is not None else "error",
            module_path=str(module),
            requested_interface=interface,
            interface_version=None,
            slot_index=slot,
            slot_count=None,
            mechanisms=[],
            error=(
                f"provider call crashed ({crash_detail_name(windows_status)}): {exc}"
                if windows_status is not None
                else f"{type(exc).__name__}: {exc}"
            ),
            reason="module_unloadable" if load_failure else None,
        )


def load_manifest(path: Path) -> CapabilityManifest:
    """Load a capability manifest from disk."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return CapabilityManifest(**raw)


def save_manifest(path: Path, manifest: CapabilityManifest) -> None:
    """Persist a capability manifest as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(manifest), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_preflight_subprocess(
    module: Path,
    *,
    interface: str,
    slot: int,
    timeout: int,
    output_path: Path,
    counters: PreflightCounters | None = None,
) -> CapabilityManifest:
    """Probe capabilities in a fresh Python subprocess and load the manifest.

    ``counters`` engages counter collection (census/recovery); ``None``
    (doctor, plugin re-probe) keeps today's uncounted behavior with a
    scrubbed child env. Collection never alters the returned manifest and
    never raises: evidence failures warn.
    """
    cmd = [
        sys.executable,
        "-m",
        "pkcs11_check.core.preflight",
        "--module",
        str(module),
        "--interface",
        interface,
        "--slot",
        str(slot),
        "--output",
        str(output_path),
    ]
    process = subprocess.Popen(cmd, env=preflight_child_env(counters))
    raw_pid = getattr(process, "pid", None)
    child_pid = raw_pid if isinstance(raw_pid, int) else None

    def _retain(
        status: str, reason: str | None, *, returncode: int | None, timed_out: bool
    ) -> None:
        if counters is None:
            return
        try:
            records, commit = collect_preflight_counters(
                counters,
                child_pid=child_pid,
                returncode=returncode,
                timed_out=timed_out,
                manifest_status=status,
                manifest_reason=reason,
            )
        except Exception as exc:  # noqa: BLE001 -- counters never fail preflight; warn
            warnings.warn(
                f"preflight counter evidence for {counters.unit} not collected: {exc}",
                UserWarning,
                stacklevel=2,
            )
            return
        try:
            append_preflight_evidence(counters.evidence_path, records)
        except OSError as exc:
            warnings.warn(
                f"preflight counter evidence for {counters.unit} not retained: {exc}",
                UserWarning,
                stacklevel=2,
            )
            # The source files stay for a retry: only a retained
            # (appended and closed) scope may consume its evidence.
            return
        commit()

    try:
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            returncode = process.wait()
            manifest = CapabilityManifest(
                status="timeout",
                module_path=str(module),
                requested_interface=interface,
                interface_version=None,
                slot_index=slot,
                slot_count=None,
                mechanisms=[],
                error=f"preflight timed out after {timeout}s",
                process_observation=build_process_observation(
                    str(module), "preflight", 0, returncode, timed_out=True
                ),
            )
            _retain("timeout", None, returncode=returncode, timed_out=True)
            return manifest
    except BaseException:
        try:
            process.kill()
        except BaseException:
            pass
        else:
            try:
                process.wait()
            except BaseException:
                pass
        _retain("aborted", None, returncode=None, timed_out=False)
        raise

    if returncode == 0 and output_path.exists():
        try:
            manifest = load_manifest(output_path)
        except BaseException:
            # An unreadable manifest keeps today's propagation (recovery
            # treats it as dead), but the child's evidence is still retained:
            # exit-0 collection cannot prove never-entered, so it stays loud.
            _retain("error", None, returncode=returncode, timed_out=False)
            raise
        _retain(manifest.status, manifest.reason, returncode=returncode, timed_out=False)
        return manifest

    if is_crash_returncode(returncode):
        manifest = CapabilityManifest(
            status="crashed",
            module_path=str(module),
            requested_interface=interface,
            interface_version=None,
            slot_index=slot,
            slot_count=None,
            mechanisms=[],
            error=f"preflight crashed ({crash_detail_name(returncode)})",
            process_observation=build_process_observation(str(module), "preflight", 0, returncode),
        )
        _retain("crashed", None, returncode=returncode, timed_out=False)
        return manifest

    manifest = CapabilityManifest(
        status="error",
        module_path=str(module),
        requested_interface=interface,
        interface_version=None,
        slot_index=slot,
        slot_count=None,
        mechanisms=[],
        error=f"preflight exited with code {returncode}",
    )
    _retain("error", None, returncode=returncode, timed_out=False)
    return manifest


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write a PKCS#11 capability manifest")
    parser.add_argument("--module", required=True)
    parser.add_argument("--interface", default="auto")
    parser.add_argument("--slot", type=int, default=0)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> None:
    """CLI entry point for the helper subprocess."""
    args = _parse_args()
    manifest = probe_capabilities(
        Path(args.module),
        interface=args.interface,
        slot=args.slot,
    )
    try:
        flush_counters()
    except CounterPersistenceError as exc:
        # The census ran but its tail cannot be accounted: fail the manifest
        # loud (harness reason) rather than certify an undercounted census.
        manifest = CapabilityManifest(
            status="error",
            module_path=str(args.module),
            requested_interface=args.interface,
            interface_version=None,
            slot_index=args.slot,
            slot_count=None,
            mechanisms=[],
            error=f"call-counter persistence failed: {exc}",
            reason=COUNTER_PERSISTENCE_REASON,
        )
    save_manifest(Path(args.output), manifest)


if __name__ == "__main__":
    main()
