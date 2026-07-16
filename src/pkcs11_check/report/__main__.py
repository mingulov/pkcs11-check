"""CLI: generate per-provider conformance reports from at-source classifications.

Single provider::

    pkcs11-check-report --report-log report.jsonl \\
        [--results-json results.json] --provider my-module --out out/

Multiple providers (repeat ``--report-log NAME=path``; ``--results-json`` too)::

    pkcs11-check-report \\
        --report-log module-a=a.jsonl --report-log module-b=b.jsonl \\
        --results-json module-a=a.results.json \\
        --out out/

Also callable as ``python -m pkcs11_check.report``.

For each provider this writes ``<out>/<provider>.md`` (render) and
``<out>/<provider>.jsonl`` (one enriched group per line). With more than one
provider it also writes ``<out>/_index.md`` (counts table + top themes + links)
and ``<out>/_universal.md`` (cross-provider correlation).

Known-issue enrichment is driven by a module-issues file resolved in this order:

1. ``--module-issues PATH`` CLI flag
2. ``PKCS11_CHECK_MODULE_ISSUES`` environment variable
3. No enrichment (empty)
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from pkcs11_check.report import health
from pkcs11_check.report.correlate import correlate, enrich
from pkcs11_check.report.extract import extract_groups
from pkcs11_check.report.render import render_provider

_DISCLAIMER = (
    "> These are pkcs11-check's observations under a software-token threat model"
    " - behavioral evidence, not verdicts or CVE claims;"
    " a clean pass is not the only useful result."
)


def crashes_from_results(results_json: Path | None) -> list[dict[str, Any]]:
    """Build Classification-shaped crash findings from a ``results.json`` file.

    Crashed/timed-out units are converted with
    :func:`pkcs11_check.core.file_runner.crash_classification`. The stored
    ``returncode`` is an absolute value, so it is re-negated for signal lookup.
    """
    if results_json is None:
        return []
    try:
        payload = json.loads(results_json.read_text(encoding="utf-8"))
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


def _payload_from_results(results_json: Path | None) -> dict[str, Any]:
    """Read the full results.json payload (summary/coverage/units), or ``{}``."""
    if results_json is None:
        return {}
    try:
        payload = json.loads(results_json.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _quality_for(results_json: Path | None) -> dict[str, Any]:
    """Read quality.json sitting next to results.json, or ``{}``."""
    if results_json is None:
        return {}
    try:
        payload = json.loads((results_json.parent / "quality.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


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


def _resolve_module_issues_text(explicit: Path | None) -> str:
    """Resolve module-issues text from explicit path, env var, or empty.

    Resolution order:
    1. ``explicit`` arg (``--module-issues`` CLI flag)
    2. ``PKCS11_CHECK_MODULE_ISSUES`` environment variable
    3. ``""`` (no-op enrichment)
    """
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    env_val = os.environ.get("PKCS11_CHECK_MODULE_ISSUES")
    if env_val:
        candidates.append(Path(env_val))

    for path in candidates:
        try:
            return path.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            pass
    return ""


def _write_provider(
    provider: str,
    groups: list[dict[str, Any]],
    out_dir: Path,
    *,
    summary: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
    units: list[dict[str, Any]] | None = None,
    quality: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
) -> None:
    md = render_provider(
        provider,
        groups,
        summary=summary,
        coverage=coverage,
        units=units,
        quality=quality,
        provenance=provenance,
    )
    (out_dir / f"{provider}.md").write_text(_DISCLAIMER + "\n\n" + md, encoding="utf-8")
    with (out_dir / f"{provider}.jsonl").open("w", encoding="utf-8") as fh:
        for group in groups:
            fh.write(json.dumps(group, sort_keys=True, ensure_ascii=False) + "\n")


def _write_index(
    provider_groups: dict[str, list[dict[str, Any]]],
    correlation: dict[str, Any],
    out_dir: Path,
) -> None:
    lines = [
        _DISCLAIMER,
        "",
        "# conformance index",
        "",
        "| provider | fail | xfail | crash | unclassified |",
        "|---|---|---|---|---|",
    ]
    for provider in sorted(provider_groups):
        # health.outcome_counts is the single source of truth, matching each
        # provider header: `fail` excludes the unclassified backlog, which gets
        # its own column instead of inflating the headline fail number.
        c = health.outcome_counts(provider_groups[provider])
        lines.append(
            f"| [{provider}]({provider}.md) | {c['fail']} | {c['xfail']} | "
            f"{c['crash']} | {c['unclassified']} |"
        )
    lines.append("")
    lines.append("## top universal themes")
    for theme in correlation["universal_themes"][:10]:
        mech = theme["mechanism"] or "-"
        lines.append(
            f"- {theme['providers']}x · {theme['reason']} · {theme['kind'] or '-'} · {mech}"
        )
    lines.append("")
    lines.append("See [_universal.md](_universal.md) for the full correlation.")
    (out_dir / "_index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_universal(correlation: dict[str, Any], out_dir: Path) -> None:
    lines = ["# universal themes (shared by >=2 providers)", ""]
    for theme in correlation["universal_themes"]:
        mech = theme["mechanism"] or "-"
        names = ", ".join(theme["provider_names"])
        lines.append(
            f"- [{theme['providers']}] {theme['reason']} · {theme['kind'] or '-'} · {mech} "
            f"- {names}"
        )
    lines.append("")
    lines.append("## single-provider outliers")
    for theme in correlation["outliers"]:
        mech = theme["mechanism"] or "-"
        names = ", ".join(theme["provider_names"])
        lines.append(f"- {theme['reason']} · {theme['kind'] or '-'} · {mech} - {names}")
    (out_dir / "_universal.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pkcs11-check-report")
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
    parser.add_argument(
        "--module-issues",
        metavar="PATH",
        help=(
            "path to a known-issue enrichment file (overrides PKCS11_CHECK_MODULE_ISSUES env var)"
        ),
    )
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    report_logs = _parse_named(args.report_log, args.provider)
    results_jsons = _parse_named(args.results_json, args.provider)

    explicit_mi = Path(args.module_issues) if args.module_issues else None
    module_issues = _resolve_module_issues_text(explicit=explicit_mi)

    provider_groups: dict[str, list[dict[str, Any]]] = {}
    for provider, report_path in report_logs.items():
        results_json = results_jsons.get(provider)
        crashes = crashes_from_results(results_json)
        payload = _payload_from_results(results_json)
        groups = extract_groups(report_path, crashes=crashes)
        enrich(groups, module_issues_text=module_issues, provider=provider)
        provider_groups[provider] = groups
        _write_provider(
            provider,
            groups,
            out_dir,
            summary=payload.get("summary") or {},
            coverage=payload.get("coverage"),
            units=payload.get("units") or [],
            quality=_quality_for(results_json),
            provenance=payload.get("provenance") or None,
        )

    if len(provider_groups) > 1:
        correlation = correlate(provider_groups)
        _write_index(provider_groups, correlation, out_dir)
        _write_universal(correlation, out_dir)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
