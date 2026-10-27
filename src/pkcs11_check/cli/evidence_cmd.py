"""pkcs11-check evidence commands: export / admit / compare."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape

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

#: Max implicated rows rendered per row-predicate admission failure.
_ADMIT_ROW_CAP = 5

#: Max admission failures / warnings rendered before a "+N more" bound line.
_ADMIT_FAILURE_CAP = 20
_ADMIT_WARNING_CAP = 20

#: One Python string-literal token, as E2's ``{value!r}`` shapes emit (either
#: quote style, with backslash escapes when the value mixes quote kinds).
_REPR_TOKEN = r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'"
#: E2's TESTED reference shapes (see admit.py; pinned by E3's F4 tests).
_SHARD_REF_RE = re.compile(rf"shard ({_REPR_TOKEN})")
_BUCKET_REF_RE = re.compile(rf"bucket ({_REPR_TOKEN})")
_ROW_INDEX_RE = re.compile(r"row (\d+)")
_OCCURRENCE_GROUP_RE = re.compile(r"group \((.*)\) (?:has|disagrees)")


def _parse_repr_token(match: re.Match[str] | None) -> str | None:
    """Evaluate one ``{value!r}`` token to its string (None when unparseable).

    Defensive fallback: anything ``ast.literal_eval`` rejects (or that does
    not evaluate to a ``str``) yields None so callers keep their raw-message
    note instead of raising on a future E2 message change.
    """
    if match is None:
        return None
    try:
        value = ast.literal_eval(match.group(1))
    except (SyntaxError, ValueError):
        return None
    return value if isinstance(value, str) else None


def _check_output(output: str) -> None:
    """Reject unknown output formats as a usage error (exit 2)."""
    if output not in {"summary", "json"}:
        console.print(f"[red]Error:[/red] Unknown output format: {escape(repr(output))}")
        raise typer.Exit(code=2)


def _die(output: str, code: int, kind: str, detail: object) -> NoReturn:
    """Emit one fatal error honoring --output json, then exit with `code`.

    Machine output is always the error envelope
    ``{"status": "error", "errors": [...]}``; human output keeps the
    ``Kind: detail`` shape with evidence-derived detail Rich-escaped.
    Verdict-carrying paths (export/admit/compare results) keep their
    verdict JSON instead of this envelope.
    """
    text = str(detail)
    if output == "json":
        typer.echo(json.dumps({"status": "error", "errors": [text]}, indent=2))
    else:
        console.print(f"[red]{kind}:[/red] {escape(text)}")
    raise typer.Exit(code=code)


def _load_ledger(path: Path, output: str) -> tuple[LedgerHeader, list[LedgerRow]]:
    """Load a ledger: unreadable/unparseable file is usage (2), bad content is red (1).

    Classification is by failure SITE, never message content: the open-probe
    maps pre-load I/O loss to exit 2, unparseable bytes (non-UTF-8 text,
    ``RecursionError`` from the JSON parser) map to exit 2, and every
    ``load_ledger`` ValueError maps to exit 1. TOCTOU residue: a ledger that
    vanishes between the probe and the load fails closed as gate-red
    (``load_ledger`` surfaces mid-run I/O loss as ValueError), never as infra.

    Residual (R36): the 4300-digit int-limit ValueError from ``json.loads`` is
    indistinguishable from content errors, so it stays exit 1 (fail closed).
    """
    try:
        with path.open("rb"):
            pass
    except OSError as exc:
        _die(output, 2, "Error", f"{path} not found or unreadable ({exc})")
    try:
        return load_ledger(path)
    except RecursionError:
        # Mirror of the _load_json_doc hardening: static message only, never
        # str(exc)/repr of attacker-controlled input (RecursionError-safe).
        _die(output, 2, "Error", f"ledger {path}: RecursionError (input too deeply nested)")
    except UnicodeDecodeError as exc:
        # Must precede ValueError: UnicodeDecodeError subclasses it, but
        # undecodable bytes are unparseable input (usage), not evidence.
        _die(output, 2, "Error", f"invalid UTF-8 in {path}: {exc}")
    except ValueError as exc:
        _die(output, 1, "Evidence failure", str(exc))


def _load_json_doc(path: Path, output: str) -> Any:
    """Load a JSON sidecar: missing/unreadable/unparseable is usage (2)."""
    if not path.exists():
        _die(output, 2, "Error", f"{path} not found")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        _die(output, 2, "Error", f"invalid UTF-8 in {path}: {exc}")
    except OSError as exc:
        _die(output, 2, "Error", f"{path} unreadable ({exc})")
    try:
        return json.loads(text)
    except RecursionError:
        # Mirror of E4's parser hardening (verify_round_receipt): the handler
        # stays trivial and RecursionError-safe -- static message only, never
        # str(exc)/repr of attacker-controlled input.
        _die(
            output,
            2,
            "Error",
            f"invalid JSON in {path}: RecursionError (input nesting exceeds parser limits)",
        )
    except ValueError as exc:
        # JSONDecodeError subclasses ValueError; this also covers parser
        # failures beyond it (e.g. the 4300-digit int conversion limit).
        _die(output, 2, "Error", f"invalid JSON in {path}: {exc}")


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
    # R27/F6r: no Typer-level readability validation -- every path failure
    # routes through the command's JSON-aware preflight below.
    report: Path = typer.Argument(
        ..., readable=False, help="Input report.jsonl (raw report-log stream)"
    ),
    ledger: Path = typer.Argument(..., readable=False, help="Output ledger.jsonl path"),
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
        _die(output, 2, "Error", f"{report} not found or unreadable")
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
        _die(output, 2, "Error", f"{ledger} not writable ({exc})")
    with sink:
        try:
            header = export_ledger(records, identity, sink, reader_invalid_lines=lambda: invalid)
        except ValueError as exc:
            _die(output, 1, "Evidence failure", str(exc))
    # Every row increments exactly one outcome counter; incomplete is the only
    # other counter this exporter can set (missing/child_* stay 0).
    rows = sum(header.counters.values()) - header.counters.get("incomplete", 0)
    red = header.malformed_lines > 0 or header.counters.get("incomplete", 0) > 0

    if output == "json":
        typer.echo(json.dumps({"header": header.to_record(), "rows": rows}, indent=2))
    else:
        console.print(
            f"evidence export: lane {escape(repr(lane))} -> {escape(str(ledger))} ({rows} rows)"
        )
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


def _build_roster(doc: Any, output: str) -> PredeclaredRoster:
    """Build a predeclared roster from parsed JSON (config errors exit 2)."""
    if not isinstance(doc, dict):
        _die(output, 2, "Error", "roster JSON is not an object")
    lane = doc.get("lane")
    shards = doc.get("shards")
    if not isinstance(lane, str):
        _die(output, 2, "Error", "roster JSON lacks a string 'lane'")
    if not isinstance(shards, dict):
        _die(output, 2, "Error", "roster JSON lacks an object 'shards'")
    expectations: dict[str, ShardExpectation] = {}
    for shard_id, spec in shards.items():
        if not isinstance(shard_id, str) or not isinstance(spec, dict):
            _die(output, 2, "Error", f"roster shard {shard_id!r} is malformed")
        records = spec.get("records")
        sha256 = spec.get("sha256")
        if type(records) is not int or not isinstance(sha256, str):
            _die(
                output,
                2,
                "Error",
                f"roster shard {shard_id!r} needs int 'records' and string 'sha256'",
            )
        try:
            expectations[shard_id] = ShardExpectation(records=records, sha256=sha256)
        except ValueError as exc:
            _die(output, 2, "Error", str(exc))
    required = doc.get("required_identity", ("lane", "framework_sha"))
    if isinstance(required, tuple):
        required_identity = required
    elif isinstance(required, list) and all(isinstance(name, str) for name in required):
        required_identity = tuple(required)
    else:
        _die(output, 2, "Error", "roster 'required_identity' is not a string list")
    return PredeclaredRoster(lane=lane, shards=expectations, required_identity=required_identity)


def _admit_row_lines(lane: str, row: LedgerRow, prefix: str) -> list[str]:
    """Render one implicated row: facet line plus artifact locator line."""
    facet = (
        f"{row.outcome.value} reason={row.reason or '-'} "
        f"ckr={row.ckr_expected or '-'}/{row.ckr_actual or '-'} "
        f"term={row.termination or '-'} shard={row.shard_id}"
    )
    return [f"    {facet}", f"    {_locator(lane, row, prefix)}"]


def _header_facts(header: LedgerHeader, row_count: int) -> str:
    """Render the header facts line for header-level admission failures."""
    return (
        f"header: lane={header.lane!r} rows={row_count} "
        f"incomplete={header.counters.get('incomplete')} "
        f"malformed_lines={header.malformed_lines}"
    )


def _capped_row_lines(lane: str, implicated: list[LedgerRow], prefix: str) -> list[str]:
    """Render implicated rows bounded by _ADMIT_ROW_CAP with a '+N more' line."""
    lines: list[str] = []
    for row in implicated[:_ADMIT_ROW_CAP]:
        lines.extend(_admit_row_lines(lane, row, prefix))
    if len(implicated) > _ADMIT_ROW_CAP:
        lines.append(f"    +{len(implicated) - _ADMIT_ROW_CAP} more rows")
    return lines


def _parse_occurrence_group(failure: str) -> tuple[str, str] | None:
    """Parse E2's ``group ('node_id', 'phase')`` shape, defensively (None if not)."""
    match = _OCCURRENCE_GROUP_RE.search(failure)
    if match is None:
        return None
    try:
        parsed = ast.literal_eval(f"({match.group(1)})")
    except (SyntaxError, ValueError):
        return None
    if isinstance(parsed, tuple) and len(parsed) == 2 and all(isinstance(p, str) for p in parsed):
        first, second = parsed
        return (first, second)
    return None


def _admit_failure_lines(
    failure: str, header: LedgerHeader, rows: Sequence[LedgerRow]
) -> list[str]:
    """Render one admission failure plus its implicated rows (A-16/C14 triage).

    Parses E2's TESTED message shapes (see admit.py; E2 message changes break
    E3's pinned F4 tests loudly by design -- no E2 file changes here).
    Row-predicate failures render up to _ADMIT_ROW_CAP implicated rows with
    facets + locators; header-level predicates render a no-rows note plus
    header facts. Every list is bounded with a "+N more" line. Returned lines
    are unescaped; call sites escape before printing.
    """
    lane = header.lane
    prefix = _sha_prefix(header)
    lines = [f"  {failure}"]
    predicate = failure.split(":", 1)[0]
    if predicate == "roster_complete":
        shard = _parse_repr_token(_SHARD_REF_RE.search(failure))
        if shard is None:
            lines.append("    note: shard unparseable; raw message above")
        elif "missing from rows" in failure:
            lines.append(f"    shard {shard!r}: 0 rows present (missing from rows)")
        else:
            implicated = [row for row in rows if row.shard_id == shard]
            if not implicated:
                lines.append(f"    shard {shard!r}: 0 rows present")
            else:
                lines.append(f"    shard {shard!r}: {len(implicated)} row(s) implicated")
                lines.extend(_capped_row_lines(lane, implicated, prefix))
    elif predicate == "typed_fields":
        indexes = [int(text) for text in _ROW_INDEX_RE.findall(failure)]
        in_range = [index for index in indexes if 0 <= index < len(rows)]
        if not in_range:
            lines.append("    note: implicated row indexes out of range; raw message above")
        else:
            lines.append(f"    {len(indexes)} row(s) implicated")
            lines.extend(_capped_row_lines(lane, [rows[i] for i in in_range], prefix))
            skipped = len(indexes) - len(in_range)
            if skipped:
                lines.append(f"    +{skipped} more rows (index out of range)")
    elif predicate == "occurrence_preserved":
        key = _parse_occurrence_group(failure)
        if key is None:
            lines.append("    note: group unparseable; raw message above")
        else:
            implicated = [row for row in rows if (row.node_id, row.phase) == key]
            if not implicated:
                lines.append(f"    group {key!r}: 0 rows present")
            else:
                lines.append(f"    group {key!r}: {len(implicated)} row(s) implicated")
                lines.extend(_capped_row_lines(lane, implicated, prefix))
    elif predicate == "session_framing":
        if "header counters sum to" in failure:
            lines.append("    note: no implicated rows (header-level sum check)")
            lines.append(f"    {_header_facts(header, len(rows))}")
        else:
            bucket = _parse_repr_token(_BUCKET_REF_RE.search(failure))
            if bucket is None:
                lines.append("    note: bucket unparseable; raw message above")
            elif "counter is not an int" in failure:
                lines.append("    note: no implicated rows (header counter mistyped)")
                lines.append(f"    {_header_facts(header, len(rows))}")
            else:
                implicated = [row for row in rows if row.outcome.value == bucket]
                lines.append(f"    bucket {bucket!r}: {len(implicated)} row(s) with that outcome")
                lines.extend(_capped_row_lines(lane, implicated, prefix))
    else:
        # zero_malformed, observability_complete, provenance_present,
        # obligations_executed (the case has no rows by definition), and any
        # future header-level predicate: no rows to implicate.
        lines.append("    note: no implicated rows (header-level predicate)")
        lines.append(f"    {_header_facts(header, len(rows))}")
    return lines


def evidence_admit_command(
    # R27/F6r: no Typer-level readability validation -- every path failure
    # routes through the command's JSON-aware preflight below.
    ledger: Path = typer.Argument(..., readable=False, help="Ledger.jsonl to admit"),
    roster: Path = typer.Option(..., "--roster", readable=False, help="Predeclared roster JSON"),
    obligations: Path = typer.Option(
        ..., "--obligations", readable=False, help="Catalog/profile JSON"
    ),
    output: str = typer.Option("summary", "--output", "-o", help="Output: summary|json"),
) -> None:
    """Admit a lane ledger against its roster and obligation inventory."""
    _check_output(output)
    header, rows = _load_ledger(ledger, output)
    roster_obj = _build_roster(_load_json_doc(roster, output), output)
    obligations_doc = _load_json_doc(obligations, output)
    if (
        not isinstance(obligations_doc, dict)
        or not isinstance(obligations_doc.get("catalog"), dict)
        or not isinstance(obligations_doc.get("profile"), dict)
    ):
        _die(output, 2, "Error", "obligations JSON needs 'catalog' and 'profile'")
    try:
        inventory = compile_obligations(obligations_doc["catalog"], obligations_doc["profile"])
    except ValueError as exc:
        _die(output, 2, "Error", str(exc))

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
            f"[green]admitted:[/green] lane {escape(repr(header.lane))} "
            f"({len(rows)} rows, {len(verdict.warnings)} warnings)"
        )
        for warning in verdict.warnings[:_ADMIT_WARNING_CAP]:
            console.print(f"  warning: {escape(warning)}")
        if len(verdict.warnings) > _ADMIT_WARNING_CAP:
            console.print(f"  +{len(verdict.warnings) - _ADMIT_WARNING_CAP} more warnings")
    else:
        console.print(f"[red]evidence failure:[/red] lane {escape(repr(header.lane))} not admitted")
        for failure in verdict.failures[:_ADMIT_FAILURE_CAP]:
            for line in _admit_failure_lines(failure, header, rows):
                console.print(escape(line))
        if len(verdict.failures) > _ADMIT_FAILURE_CAP:
            console.print(f"  +{len(verdict.failures) - _ADMIT_FAILURE_CAP} more failures")
        for warning in verdict.warnings[:_ADMIT_WARNING_CAP]:
            console.print(f"  warning: {escape(warning)}")
        if len(verdict.warnings) > _ADMIT_WARNING_CAP:
            console.print(f"  +{len(verdict.warnings) - _ADMIT_WARNING_CAP} more warnings")
        console.print(f"  {escape(header.lane)} raw:{escape(_sha_prefix(header))}")

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


def _build_deltas(doc: Any, output: str) -> RotationDeltas:
    """Build a rotation bundle from parsed JSON (bad paperwork exits 1)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
        _die(output, 1, "Evidence failure", "deltas JSON needs 'entries'")
    entries: list[Delta] = []
    for index, item in enumerate(doc["entries"]):
        if not isinstance(item, dict):
            _die(output, 1, "Evidence failure", f"deltas entry {index} is not an object")
        missing = [
            key
            for key in ("lane", "case_id", "phase", "old_fp", "new_fp", "reason", "ttl")
            if key not in item
        ]
        if missing:
            _die(output, 1, "Evidence failure", f"deltas entry {index} lacks {missing!r}")
        ttl = item["ttl"]
        if type(ttl) is not int or ttl != 1:
            _die(output, 1, "Evidence failure", f"deltas entry {index} has ttl {ttl!r}, must be 1")
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
    base_prefix = _sha_prefix(base_header)
    cand_prefix = _sha_prefix(cand_header)
    # Header-level (keyless) regressions are lane-level, not row-sourced: the
    # candidate-first chain applies to those lines only.
    lane_prefix = _sha_prefix(cand_header, base_header)
    base_groups: dict[tuple[str, str], list[LedgerRow]] = {}
    for row in base_rows:
        base_groups.setdefault((row.node_id, row.phase), []).append(row)
    cand_groups: dict[tuple[str, str], list[LedgerRow]] = {}
    for row in cand_rows:
        cand_groups.setdefault((row.node_id, row.phase), []).append(row)

    for regression in verdict.regressions:
        if not regression.node_id:
            console.print(
                f"[red]regression[/red] load/admission failure: "
                f"axis={escape(regression.axis)} lane={escape(lane)} raw:{escape(lane_prefix)}"
            )
            continue
        key = (regression.node_id, regression.phase)
        # F3: the locator names the artifact holding the row -- candidate SHA
        # when the key exists there (matched/added), else baseline SHA (removed).
        prefix = cand_prefix if key in cand_groups else base_prefix
        members = cand_groups.get(
            key,
            base_groups.get(key, []),
        )
        attempts = ",".join(str(row.attempt) for row in sorted(members, key=lambda r: r.attempt))
        old_disp = _summarize_fp(regression.old).split(" ")[0]
        new_disp = _summarize_fp(regression.new).split(" ")[0]
        console.print(
            f"[red]regression[/red] {escape(regression.node_id)} "
            f"phase={escape(regression.phase)} attempts={escape(attempts)}"
        )
        console.print(
            f"  {escape(old_disp)} -> {escape(new_disp)} (axis: {escape(regression.axis)})"
        )
        if regression.axis == "stale_delta":
            console.print("  delta failure: rotation paperwork does not match reality")
        console.print(f"  old: {escape(_summarize_fp(regression.old))}")
        console.print(f"  new: {escape(_summarize_fp(regression.new))}")
        if members:
            first = min(members, key=lambda row: row.attempt)
            console.print(f"  {escape(_locator(lane, first, prefix))}")

    for entry in verdict.unstable:
        parsed = _split_unstable_entry(entry)
        if parsed is None:
            console.print(f"[red]unstable[/red] {escape(entry)}")
            continue
        node_id, phase, axis = parsed
        key = (node_id, phase)
        prefix = cand_prefix if key in cand_groups else base_prefix
        console.print(
            f"[red]unstable[/red] {escape(node_id)} phase={escape(phase)} (axis: {escape(axis)})"
        )
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
                f"  {side}: attempts={escape(attempts)} "
                f"findings={escape(repr(findings or 'none'))} "
                f"{escape(_summarize_fp(combined))}"
            )
        members = cand_groups.get(key, base_groups.get(key, []))
        if members:
            first = min(members, key=lambda row: row.attempt)
            console.print(f"  {escape(_locator(lane, first, prefix))}")

    for improvement in verdict.improvements:
        old_disp = _summarize_fp(improvement.old).split(" ")[0]
        new_disp = _summarize_fp(improvement.new).split(" ")[0]
        console.print(
            f"[green]improvement[/green] {escape(improvement.node_id)} "
            f"phase={escape(improvement.phase)}: {escape(old_disp)} -> {escape(new_disp)} "
            f"(axis: {escape(improvement.axis)})"
        )
        key = (improvement.node_id, improvement.phase)
        members = cand_groups.get(key, base_groups.get(key, []))
        if members:
            first = min(members, key=lambda row: row.attempt)
            prefix = cand_prefix if key in cand_groups else base_prefix
            console.print(f"  {escape(_locator(lane, first, prefix))}")

    counts = verdict.counts
    console.print(
        f"compared={counts['compared']} regressions={counts['regressions']} "
        f"improvements={counts['improvements']} unstable={counts['unstable']} "
        f"deltas_applied={counts['deltas_applied']} deltas_stale={counts['deltas_stale']}"
    )
    if not verdict.regressions and not verdict.unstable:
        console.print("[green]no regressions[/green]")


def evidence_compare_command(
    # R27/F6r: no Typer-level readability validation -- every path failure
    # routes through the command's JSON-aware preflight below.
    baseline: Path = typer.Argument(..., readable=False, help="Baseline ledger.jsonl"),
    candidate: Path = typer.Argument(..., readable=False, help="Candidate ledger.jsonl"),
    deltas: Path | None = typer.Option(
        None, "--deltas", readable=False, help="Rotation deltas JSON"
    ),
    quorum_min_repeats: int = typer.Option(3, "--quorum-min-repeats", help="Quorum repeats"),
    quorum_frac: float = typer.Option(2 / 3, "--quorum-frac", help="Quorum fraction"),
    output: str = typer.Option("summary", "--output", "-o", help="Output: summary|json"),
) -> None:
    """Compare baseline vs candidate ledgers for one lane under rotation deltas."""
    _check_output(output)
    if quorum_min_repeats < 1:
        _die(output, 2, "Error", "--quorum-min-repeats must be >= 1")
    if not 0.0 < quorum_frac <= 1.0:
        _die(output, 2, "Error", "--quorum-frac must be in (0, 1]")
    base_header, base_rows = _load_ledger(baseline, output)
    cand_header, cand_rows = _load_ledger(candidate, output)
    rotation = (
        RotationDeltas(version=_DELTA_VERSION, entries=())
        if deltas is None
        else _build_deltas(_load_json_doc(deltas, output), output)
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
        _die(output, 1, "Evidence failure", str(exc))

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
