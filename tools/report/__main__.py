"""CLI: generate per-provider conformance reports from at-source classifications.

Single provider::

    python -m tools.report --report-log report.jsonl \\
        [--results-json results.json] --provider softhsm2 --out out/

Multiple providers (repeat ``--report-log NAME=path``; ``--results-json`` too)::

    python -m tools.report \\
        --report-log softhsm2=sh.jsonl --report-log kryoptic=kry.jsonl \\
        --results-json softhsm2=sh.results.json \\
        --out out/

For each provider this writes ``<out>/<provider>.md`` (render) and
``<out>/<provider>.jsonl`` (one enriched group per line). With more than one
provider it also writes ``<out>/_index.md`` (counts table + top themes + links)
and ``<out>/_universal.md`` (cross-provider correlation).

``docs/module-issues.md`` is read (when present) to drive known-issue enrichment.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from tools.report.correlate import correlate, enrich
from tools.report.extract import extract_groups
from tools.report.render import render_provider


def crashes_from_results(results_json: Path | None) -> list[dict[str, Any]]:
    """Build Classification-shaped crash findings from a ``results.json`` file.

    Crashed/timed-out units are converted with
    :func:`pkcs11_check.core.file_runner.crash_classification`. The stored
    ``returncode`` is an absolute value, so it is re-negated for signal lookup.
    """
    if results_json is None:
        return []
    try:
        payload = json.loads(results_json.read_text())
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return []
    units = payload.get("units", []) if isinstance(payload, dict) else []

    from pkcs11_check.core.file_runner import crash_classification

    crashes: list[dict[str, Any]] = []
    for unit in units:
        if not isinstance(unit, dict):
            continue
        status = str(unit.get("status", "")).strip()
        target = str(unit.get("target", "")).strip()
        if not target:
            continue
        if status == "crashed":
            rc_raw = unit.get("returncode")
            rc = -abs(int(rc_raw)) if isinstance(rc_raw, int) and rc_raw else None
            crashes.append(crash_classification(returncode=rc, target=target))
        elif status == "timeout":
            crashes.append(crash_classification(returncode=None, target=target, timed_out=True))
    return crashes


def passed_from_results(results_json: Path | None) -> int | None:
    """Read ``summary.passed`` from a ``results.json`` file, if available.

    Returns ``None`` when the file is missing/unreadable or carries no
    ``summary.passed`` integer, so the report header simply omits the
    ``passed`` token in that case.
    """
    if results_json is None:
        return None
    try:
        payload = json.loads(results_json.read_text())
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    summary = payload.get("summary") if isinstance(payload, dict) else None
    if not isinstance(summary, dict):
        return None
    passed = summary.get("passed")
    return passed if isinstance(passed, int) else None


def _parse_named(values: list[str] | None, default_provider: str | None) -> dict[str, Path]:
    """Parse repeated ``NAME=path`` (or bare ``path`` for a single provider)."""
    out: dict[str, Path] = {}
    for value in values or []:
        if "=" in value:
            name, _, path = value.partition("=")
            out[name.strip()] = Path(path.strip())
        elif default_provider is not None:
            out[default_provider] = Path(value.strip())
        else:
            raise SystemExit(
                f"--report-log/--results-json need NAME=path with multiple providers: {value!r}"
            )
    return out


def _module_issues_text(repo_root: Path) -> str:
    path = repo_root / "docs" / "module-issues.md"
    try:
        return path.read_text()
    except (FileNotFoundError, OSError):
        return ""


def _counts(groups: list[dict[str, Any]]) -> dict[str, int]:
    out = {"fail": 0, "xfail": 0, "crash": 0}
    for g in groups:
        n = int(g.get("count", 0))
        if g.get("reason") == "crash":
            out["crash"] += n
        elif g.get("outcome") == "xfail":
            out["xfail"] += n
        elif g.get("outcome") == "fail":
            out["fail"] += n
    return out


def _write_provider(
    provider: str,
    groups: list[dict[str, Any]],
    out_dir: Path,
    pass_count: int | None = None,
) -> None:
    md = render_provider(provider, groups, pass_count=pass_count)
    (out_dir / f"{provider}.md").write_text(md)
    with (out_dir / f"{provider}.jsonl").open("w") as fh:
        for group in groups:
            fh.write(json.dumps(group, sort_keys=True) + "\n")


def _write_index(
    provider_groups: dict[str, list[dict[str, Any]]],
    correlation: dict[str, Any],
    out_dir: Path,
) -> None:
    lines = ["# conformance index", "", "| provider | fail | xfail | crash |", "|---|---|---|---|"]
    for provider in sorted(provider_groups):
        c = _counts(provider_groups[provider])
        lines.append(f"| [{provider}]({provider}.md) | {c['fail']} | {c['xfail']} | {c['crash']} |")
    lines.append("")
    lines.append("## top universal themes")
    for theme in correlation["universal_themes"][:10]:
        mech = theme["mechanism"] or "-"
        lines.append(
            f"- {theme['providers']}x · {theme['reason']} · {theme['kind'] or '-'} · {mech}"
        )
    lines.append("")
    lines.append("See [_universal.md](_universal.md) for the full correlation.")
    (out_dir / "_index.md").write_text("\n".join(lines) + "\n")


def _write_universal(correlation: dict[str, Any], out_dir: Path) -> None:
    lines = ["# universal themes (shared by >=2 providers)", ""]
    for theme in correlation["universal_themes"]:
        mech = theme["mechanism"] or "-"
        names = ", ".join(theme["provider_names"])
        lines.append(
            f"- [{theme['providers']}] {theme['reason']} · {theme['kind'] or '-'} · {mech} "
            f"— {names}"
        )
    lines.append("")
    lines.append("## single-provider outliers")
    for theme in correlation["outliers"]:
        mech = theme["mechanism"] or "-"
        names = ", ".join(theme["provider_names"])
        lines.append(f"- {theme['reason']} · {theme['kind'] or '-'} · {mech} — {names}")
    (out_dir / "_universal.md").write_text("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.report")
    parser.add_argument(
        "--report-log",
        action="append",
        required=True,
        help="report.jsonl path (or NAME=path, repeatable for multiple providers)",
    )
    parser.add_argument(
        "--results-json",
        action="append",
        help="results.json path for crash findings (or NAME=path, repeatable)",
    )
    parser.add_argument(
        "--provider",
        help="provider name (required for single-provider bare-path form)",
    )
    parser.add_argument("--out", required=True, help="output directory")
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    report_logs = _parse_named(args.report_log, args.provider)
    results_jsons = _parse_named(args.results_json, args.provider)

    repo_root = Path(__file__).resolve().parents[2]
    module_issues = _module_issues_text(repo_root)

    provider_groups: dict[str, list[dict[str, Any]]] = {}
    for provider, report_path in report_logs.items():
        results_json = results_jsons.get(provider)
        crashes = crashes_from_results(results_json)
        groups = extract_groups(report_path, crashes=crashes)
        enrich(groups, module_issues_text=module_issues, provider=provider)
        provider_groups[provider] = groups
        _write_provider(provider, groups, out_dir, pass_count=passed_from_results(results_json))

    if len(provider_groups) > 1:
        correlation = correlate(provider_groups)
        _write_index(provider_groups, correlation, out_dir)
        _write_universal(correlation, out_dir)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
