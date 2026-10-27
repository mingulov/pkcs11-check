"""pkcs11-check evidence commands: export / admit / compare."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from pkcs11_check.core.evidence.admit import (
    PredeclaredRoster,
    ShardExpectation,
    admit_lane,
)
from pkcs11_check.core.evidence.compare import (
    ComparisonVerdict,
    Delta,
    QuorumPolicy,
    Regression,
    RotationDeltas,
    combine_attempts,
    compare_lanes,
)
from pkcs11_check.core.evidence.export import export_ledger, load_ledger
from pkcs11_check.core.evidence.obligations import compile_obligations
from pkcs11_check.core.evidence.schema import LedgerHeader, LedgerRow
from pkcs11_check.core.report_log import iter_report_log_records

console = Console()

_DELTA_VERSION = "ComparisonAdmissionV1"


def _check_output(output: str) -> None:
    """Reject unknown output formats as a usage error (exit 2)."""
    if output not in {"summary", "json"}:
        console.print(f"[red]Error:[/red] Unknown output format: {output!r}")
        raise typer.Exit(code=2)


def _load_ledger(path: Path) -> tuple[LedgerHeader, list[LedgerRow]]:
    """Load a ledger: missing file is usage (2), malformed evidence is red (1)."""
    if not path.exists():
        console.print(f"[red]Error:[/red] {path} not found")
        raise typer.Exit(code=2)
    try:
        return load_ledger(path)
    except ValueError as exc:
        if "unreadable" in str(exc):
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        console.print(f"[red]Evidence failure:[/red] {exc}")
        raise typer.Exit(code=1) from exc


def _load_json_doc(path: Path) -> Any:
    """Load a JSON sidecar: missing/unreadable/unparseable is usage (2)."""
    if not path.exists():
        console.print(f"[red]Error:[/red] {path} not found")
        raise typer.Exit(code=2)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        console.print(f"[red]Error:[/red] {path} unreadable ({exc})")
        raise typer.Exit(code=2) from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        console.print(f"[red]Error:[/red] invalid JSON in {path}: {exc}")
        raise typer.Exit(code=2) from exc


def _fp_to_json(fp: tuple[str, ...] | str) -> list[str] | str:
    """Render a fingerprint for machine output (tuples become lists)."""
    return list(fp) if isinstance(fp, tuple) else fp


def _regression_to_json(regression: Regression) -> dict[str, Any]:
    """Render one regression/improvement for machine output."""
    return {
        "node_id": regression.node_id,
        "phase": regression.phase,
        "old": _fp_to_json(regression.old),
        "new": _fp_to_json(regression.new),
        "axis": regression.axis,
    }


def _summarize_fp(fp: tuple[str, ...] | str) -> str:
    """Render one fingerprint as a single triage line."""
    if isinstance(fp, str):
        return fp
    outcome, reason, class_reason, category, ckr_expected, ckr_actual, termination = fp
    parts = [outcome]
    if reason:
        parts.append(f"reason={reason}")
    if class_reason:
        parts.append(f"class={class_reason}")
    if category:
        parts.append(category)
    if ckr_expected or ckr_actual:
        parts.append(f"ckr={ckr_expected}/{ckr_actual}")
    if termination:
        parts.append(f"term={termination}")
    return " ".join(parts)


def _sha_prefix(*headers: LedgerHeader) -> str:
    """Return the first available raw-stream sha prefix, else 'unknown'."""
    for header in headers:
        if header.raw_stream_sha256:
            return header.raw_stream_sha256[:12]
    return "unknown"


def _locator(lane: str, row: LedgerRow, prefix: str) -> str:
    """Render the artifact locator line for one ledger row."""
    return f"{lane}/{row.shard_id}/{row.node_id}::{row.phase}@{row.attempt} raw:{prefix}"


def _split_unstable_entry(entry: str) -> tuple[str, str, str] | None:
    """Split an unstable entry back into (node_id, phase, axis), best effort."""
    try:
        node_id, tail = entry.rsplit("::", 1)
        phase, axis = tail.rsplit(":", 1)
    except ValueError:
        return None
    if not node_id or not phase or not axis:
        return None
    return node_id, phase, axis


def evidence_export_command(
    report: Path = typer.Argument(..., help="Input report.jsonl (raw report-log stream)"),
    ledger: Path = typer.Argument(..., help="Output ledger.jsonl path"),
    lane: str = typer.Option("", "--lane", help="Lane name echoed into the header"),
    lane_os: str = typer.Option("", "--lane-os", help="Lane OS echoed into the header"),
    lane_arch: str = typer.Option("", "--lane-arch", help="Lane arch echoed into the header"),
    framework_sha: str = typer.Option("", "--framework-sha", help="Framework SHA identity"),
    p11lab_sha: str = typer.Option("", "--p11lab-sha", help="p11lab SHA identity"),
    image_digest: str = typer.Option("", "--image-digest", help="Image digest identity"),
    corpus_hash: str = typer.Option("", "--corpus-hash", help="Corpus hash identity"),
    disabled_hash: str = typer.Option("", "--disabled-hash", help="Disabled-set hash identity"),
    output: str = typer.Option("summary", "--output", "-o", help="Output: summary|json"),
) -> None:
    """Export a raw report.jsonl stream to a semantic evidence ledger."""
    _check_output(output)
    try:
        raw = report.read_bytes()
    except OSError:
        console.print(f"[red]Error:[/red] {report} not found or unreadable")
        raise typer.Exit(code=2)
    # THE R16 OBLIGATION: reader-invalid lines are counted here and threaded
    # into the exporter, landing in header.malformed_lines.
    invalid = 0

    def _count_invalid() -> None:
        nonlocal invalid
        invalid += 1

    records = iter_report_log_records(report, on_invalid=_count_invalid)
    identity = {
        "lane": lane,
        "lane_os": lane_os,
        "lane_arch": lane_arch,
        "framework_sha": framework_sha,
        "p11lab_sha": p11lab_sha,
        "image_digest": image_digest,
        "corpus_hash": corpus_hash,
        "disabled_hash": disabled_hash,
        # planned_count is 0 from this exporter (documented); E5 overrides it
        # with the reconciled planned-collection count at orchestration time.
        "planned_count": "0",
        "raw_stream_bytes": str(len(raw)),
        "raw_stream_sha256": hashlib.sha256(raw).hexdigest(),
    }
    try:
        sink = ledger.open("w", encoding="utf-8")
    except OSError as exc:
        console.print(f"[red]Error:[/red] {ledger} not writable ({exc})")
        raise typer.Exit(code=2) from exc
    with sink:
        try:
            header = export_ledger(records, identity, sink, reader_invalid_lines=lambda: invalid)
        except ValueError as exc:
            console.print(f"[red]Evidence failure:[/red] {exc}")
            raise typer.Exit(code=1) from exc
    # Every row increments exactly one outcome counter; incomplete is the only
    # other counter this exporter can set (missing/child_* stay 0).
    rows = sum(header.counters.values()) - header.counters.get("incomplete", 0)
    red = header.malformed_lines > 0 or header.counters.get("incomplete", 0) > 0

    if output == "json":
        typer.echo(json.dumps({"header": header.to_record(), "rows": rows}, indent=2))
    else:
        console.print(f"evidence export: lane {lane!r} -> {ledger} ({rows} rows)")
        console.print(
            f"  malformed_lines: {header.malformed_lines}  "
            f"incomplete: {header.counters.get('incomplete', 0)}"
        )
        if red:
            console.print("[red]evidence failure:[/red] exported ledger is not clean")
        else:
            console.print("[green]exported clean ledger[/green]")

    if red:
        raise typer.Exit(code=1)


def _build_roster(doc: Any) -> PredeclaredRoster:
    """Build a predeclared roster from parsed JSON (config errors exit 2)."""
    if not isinstance(doc, dict):
        console.print("[red]Error:[/red] roster JSON is not an object")
        raise typer.Exit(code=2)
    lane = doc.get("lane")
    shards = doc.get("shards")
    if not isinstance(lane, str):
        console.print("[red]Error:[/red] roster JSON lacks a string 'lane'")
        raise typer.Exit(code=2)
    if not isinstance(shards, dict):
        console.print("[red]Error:[/red] roster JSON lacks an object 'shards'")
        raise typer.Exit(code=2)
    expectations: dict[str, ShardExpectation] = {}
    for shard_id, spec in shards.items():
        if not isinstance(shard_id, str) or not isinstance(spec, dict):
            console.print(f"[red]Error:[/red] roster shard {shard_id!r} is malformed")
            raise typer.Exit(code=2)
        records = spec.get("records")
        sha256 = spec.get("sha256")
        if type(records) is not int or not isinstance(sha256, str):
            console.print(
                f"[red]Error:[/red] roster shard {shard_id!r} needs "
                "int 'records' and string 'sha256'"
            )
            raise typer.Exit(code=2)
        try:
            expectations[shard_id] = ShardExpectation(records=records, sha256=sha256)
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=2) from exc
    required = doc.get("required_identity", ("lane", "framework_sha"))
    if isinstance(required, tuple):
        required_identity = required
    elif isinstance(required, list) and all(isinstance(name, str) for name in required):
        required_identity = tuple(required)
    else:
        console.print("[red]Error:[/red] roster 'required_identity' is not a string list")
        raise typer.Exit(code=2)
    return PredeclaredRoster(lane=lane, shards=expectations, required_identity=required_identity)


def evidence_admit_command(
    ledger: Path = typer.Argument(..., help="Ledger.jsonl to admit"),
    roster: Path = typer.Option(..., "--roster", help="Predeclared roster JSON"),
    obligations: Path = typer.Option(..., "--obligations", help="Catalog/profile JSON"),
    output: str = typer.Option("summary", "--output", "-o", help="Output: summary|json"),
) -> None:
    """Admit a lane ledger against its roster and obligation inventory."""
    _check_output(output)
    header, rows = _load_ledger(ledger)
    roster_obj = _build_roster(_load_json_doc(roster))
    obligations_doc = _load_json_doc(obligations)
    if (
        not isinstance(obligations_doc, dict)
        or not isinstance(obligations_doc.get("catalog"), dict)
        or not isinstance(obligations_doc.get("profile"), dict)
    ):
        console.print("[red]Error:[/red] obligations JSON needs 'catalog' and 'profile'")
        raise typer.Exit(code=2)
    try:
        inventory = compile_obligations(obligations_doc["catalog"], obligations_doc["profile"])
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    verdict = admit_lane(header, rows, roster_obj, inventory)

    if output == "json":
        typer.echo(
            json.dumps(
                {
                    "admitted": verdict.admitted,
                    "failures": verdict.failures,
                    "warnings": verdict.warnings,
                },
                indent=2,
            )
        )
    elif verdict.admitted:
        console.print(
            f"[green]admitted:[/green] lane {header.lane!r} "
            f"({len(rows)} rows, {len(verdict.warnings)} warnings)"
        )
        for warning in verdict.warnings:
            console.print(f"  warning: {warning}")
    else:
        console.print(f"[red]evidence failure:[/red] lane {header.lane!r} not admitted")
        for failure in verdict.failures:
            console.print(f"  {failure}")
        for warning in verdict.warnings:
            console.print(f"  warning: {warning}")
        console.print(f"  {header.lane} raw:{_sha_prefix(header)}")

    if not verdict.admitted:
        raise typer.Exit(code=1)


def _coerce_delta_fp(value: Any) -> tuple[str, ...] | str:
    """Coerce one JSON delta fp side (7-list or 'absent') to Delta shape."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return tuple(value)
    # Anything else stringifies into a shape validate_deltas rejects.
    return str(value)


def _build_deltas(doc: Any) -> RotationDeltas:
    """Build a rotation bundle from parsed JSON (bad paperwork exits 1)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
        console.print("[red]Evidence failure:[/red] deltas JSON needs 'entries'")
        raise typer.Exit(code=1)
    entries: list[Delta] = []
    for index, item in enumerate(doc["entries"]):
        if not isinstance(item, dict):
            console.print(f"[red]Evidence failure:[/red] deltas entry {index} is not an object")
            raise typer.Exit(code=1)
        missing = [
            key
            for key in ("lane", "case_id", "phase", "old_fp", "new_fp", "reason", "ttl")
            if key not in item
        ]
        if missing:
            console.print(f"[red]Evidence failure:[/red] deltas entry {index} lacks {missing!r}")
            raise typer.Exit(code=1)
        entries.append(
            Delta(
                lane=item["lane"],
                case_id=item["case_id"],
                phase=item["phase"],
                old_fp=_coerce_delta_fp(item["old_fp"]),
                new_fp=_coerce_delta_fp(item["new_fp"]),
                reason=item["reason"],
                ttl=item["ttl"],
            )
        )
    # A missing/non-string version stringifies into a value validation rejects.
    return RotationDeltas(version=str(doc.get("version")), entries=tuple(entries))


def _print_compare_summary(
    verdict: ComparisonVerdict,
    base_header: LedgerHeader,
    base_rows: list[LedgerRow],
    cand_header: LedgerHeader,
    cand_rows: list[LedgerRow],
    quorum: QuorumPolicy,
) -> None:
    """Print the per-red-item triage summary (first triage without raw streams)."""
    lane = base_header.lane
    prefix = _sha_prefix(cand_header, base_header)
    base_groups: dict[tuple[str, str], list[LedgerRow]] = {}
    for row in base_rows:
        base_groups.setdefault((row.node_id, row.phase), []).append(row)
    cand_groups: dict[tuple[str, str], list[LedgerRow]] = {}
    for row in cand_rows:
        cand_groups.setdefault((row.node_id, row.phase), []).append(row)

    for regression in verdict.regressions:
        if not regression.node_id:
            console.print(
                f"[red]regression[/red] load/admission failure: axis={regression.axis} "
                f"lane={lane} raw:{prefix}"
            )
            continue
        members = cand_groups.get(
            (regression.node_id, regression.phase),
            base_groups.get((regression.node_id, regression.phase), []),
        )
        attempts = ",".join(str(row.attempt) for row in sorted(members, key=lambda r: r.attempt))
        old_disp = _summarize_fp(regression.old).split(" ")[0]
        new_disp = _summarize_fp(regression.new).split(" ")[0]
        console.print(
            f"[red]regression[/red] {regression.node_id} "
            f"phase={regression.phase} attempts={attempts}"
        )
        console.print(f"  {old_disp} -> {new_disp} (axis: {regression.axis})")
        if regression.axis == "stale_delta":
            console.print("  delta failure: rotation paperwork does not match reality")
        console.print(f"  old: {_summarize_fp(regression.old)}")
        console.print(f"  new: {_summarize_fp(regression.new)}")
        if members:
            first = min(members, key=lambda row: row.attempt)
            console.print(f"  {_locator(lane, first, prefix)}")

    for entry in verdict.unstable:
        parsed = _split_unstable_entry(entry)
        if parsed is None:
            console.print(f"[red]unstable[/red] {entry}")
            continue
        node_id, phase, axis = parsed
        key = (node_id, phase)
        console.print(f"[red]unstable[/red] {node_id} phase={phase} (axis: {axis})")
        for side, groups in (("base", base_groups), ("cand", cand_groups)):
            members = groups.get(key, [])
            if not members:
                console.print(f"  {side}: absent")
                continue
            combined, findings = combine_attempts(members, quorum)
            attempts = ",".join(
                str(row.attempt) for row in sorted(members, key=lambda r: r.attempt)
            )
            console.print(
                f"  {side}: attempts={attempts} findings={findings or 'none'} "
                f"{_summarize_fp(combined)}"
            )
        members = cand_groups.get(key, base_groups.get(key, []))
        if members:
            first = min(members, key=lambda row: row.attempt)
            console.print(f"  {_locator(lane, first, prefix)}")

    for improvement in verdict.improvements:
        old_disp = _summarize_fp(improvement.old).split(" ")[0]
        new_disp = _summarize_fp(improvement.new).split(" ")[0]
        console.print(
            f"[green]improvement[/green] {improvement.node_id} "
            f"phase={improvement.phase}: {old_disp} -> {new_disp} "
            f"(axis: {improvement.axis})"
        )

    counts = verdict.counts
    console.print(
        f"compared={counts['compared']} regressions={counts['regressions']} "
        f"improvements={counts['improvements']} unstable={counts['unstable']} "
        f"deltas_applied={counts['deltas_applied']} deltas_stale={counts['deltas_stale']}"
    )
    if not verdict.regressions and not verdict.unstable:
        console.print("[green]no regressions[/green]")


def evidence_compare_command(
    baseline: Path = typer.Argument(..., help="Baseline ledger.jsonl"),
    candidate: Path = typer.Argument(..., help="Candidate ledger.jsonl"),
    deltas: Path | None = typer.Option(None, "--deltas", help="Rotation deltas JSON"),
    quorum_min_repeats: int = typer.Option(3, "--quorum-min-repeats", help="Quorum repeats"),
    quorum_frac: float = typer.Option(2 / 3, "--quorum-frac", help="Quorum fraction"),
    output: str = typer.Option("summary", "--output", "-o", help="Output: summary|json"),
) -> None:
    """Compare baseline vs candidate ledgers for one lane under rotation deltas."""
    _check_output(output)
    if quorum_min_repeats < 1:
        console.print("[red]Error:[/red] --quorum-min-repeats must be >= 1")
        raise typer.Exit(code=2)
    if not 0.0 < quorum_frac <= 1.0:
        console.print("[red]Error:[/red] --quorum-frac must be in (0, 1]")
        raise typer.Exit(code=2)
    base_header, base_rows = _load_ledger(baseline)
    cand_header, cand_rows = _load_ledger(candidate)
    rotation = (
        RotationDeltas(version=_DELTA_VERSION, entries=())
        if deltas is None
        else _build_deltas(_load_json_doc(deltas))
    )
    quorum = QuorumPolicy(
        min_repeats=quorum_min_repeats,
        quorum_frac=quorum_frac,
        disagree_is_unstable=True,
    )
    try:
        verdict = compare_lanes(
            (base_header, base_rows), (cand_header, cand_rows), rotation, quorum
        )
    except ValueError as exc:
        console.print(f"[red]Evidence failure:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if output == "json":
        typer.echo(
            json.dumps(
                {
                    "regressions": [_regression_to_json(item) for item in verdict.regressions],
                    "improvements": [_regression_to_json(item) for item in verdict.improvements],
                    "unstable": verdict.unstable,
                    "counts": dict(verdict.counts),
                },
                indent=2,
            )
        )
    else:
        _print_compare_summary(verdict, base_header, base_rows, cand_header, cand_rows, quorum)

    if verdict.regressions or verdict.unstable:
        raise typer.Exit(code=1)
