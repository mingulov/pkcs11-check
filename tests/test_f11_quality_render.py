"""F11 slice B: rendering the `classification_observability` block in provider markdown.

Covers ``report.render.render_provider``'s new section against the shared contract's exact
rendering rule: partial counts render ``>=N``, unavailable/legacy renders ``--``, and a
fabricated zero is never emitted. See
``.superpowers/sdd/2026-09-08-v020-reporting-integrity-fixes/f11-shared-contract.md``.
"""

from __future__ import annotations

from pkcs11_check.core.report_log import F11_CONTRACT_VERSION
from pkcs11_check.report.render import render_provider


def _observability(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "contract_version": F11_CONTRACT_VERSION,
        "source_artifact": "report.jsonl",
        "status": "complete",
        "status_reasons": [],
        "expected_sources": 1,
        "readable_sources": 1,
        "missing_sources": 0,
        "malformed_records": 0,
        "malformed_markers": 0,
        "malformed_properties": 0,
        "malformed_entries": 0,
        "count_semantics": "serialized_classification_occurrences",
        "unclassified": {
            "occurrences": 0,
            "lower_bound": False,
            "unique_testcases": 0,
            "exact_duplicate_occurrences": 0,
            "phase_counts": {},
            "target_counts": {},
            "attempt_counts": {},
            "unattributed_occurrences": 0,
            "per_file_counts": {},
            "samples": [],
        },
    }
    base.update(overrides)
    return base


def _render(quality: dict[str, object] | None) -> str:
    return render_provider("prov", groups=[], quality=quality)


def _section(md: str) -> str:
    marker = "## classification observability"
    assert marker in md
    return md[md.index(marker) :]


# --------------------------------------------------------------------------- #
# Absent / legacy quality.json: no section, no crash (backward compatibility)
# --------------------------------------------------------------------------- #


def test_no_quality_payload_renders_no_observability_section() -> None:
    md = _render(None)
    assert "## classification observability" not in md


def test_legacy_quality_without_the_block_renders_no_section() -> None:
    """An older quality.json (no `classification_observability` key at all) must keep
    rendering fine -- the section is simply absent, not an error and not a fabricated `--`
    line with no context."""
    md = _render({"data_quality_warnings": []})
    assert "## classification observability" not in md


# --------------------------------------------------------------------------- #
# Unsupported declared contract versions
# --------------------------------------------------------------------------- #


def test_unsupported_contract_version_renders_dashes_not_the_counts() -> None:
    quality = {"classification_observability": _observability(contract_version="99")}
    section = _section(_render(quality))
    assert "status: --" in section
    assert "unsupported or legacy" in section
    # Must not print any real-looking count line for data we do not trust the shape of.
    assert "occurrences" not in section


def test_unsupported_status_value_renders_dashes() -> None:
    quality = {"classification_observability": _observability(status="weird-future-status")}
    section = _section(_render(quality))
    assert "status: --" in section


# --------------------------------------------------------------------------- #
# unavailable: unclassified is null -> "--", never a fabricated zero
# --------------------------------------------------------------------------- #


def test_unavailable_status_renders_dashes_never_zero() -> None:
    quality = {
        "classification_observability": _observability(
            status="unavailable",
            status_reasons=["no raw source declared"],
            expected_sources=0,
            readable_sources=0,
            unclassified=None,
        )
    }
    section = _section(_render(quality))
    assert "status: unavailable" in section
    assert "unclassified occurrences: --" in section
    assert "unclassified occurrences: 0" not in section


# --------------------------------------------------------------------------- #
# complete-zero vs partial/lower-bound
# --------------------------------------------------------------------------- #


def test_complete_zero_renders_a_real_exact_zero() -> None:
    quality = {"classification_observability": _observability()}
    section = _section(_render(quality))
    assert "unclassified occurrences: 0 across 0 logical testcase(s)" in section


def test_partial_status_renders_lower_bound_counts_with_gte_prefix() -> None:
    quality = {
        "classification_observability": _observability(
            status="partial",
            status_reasons=["malformed JSON/object record(s): 1"],
            unclassified={
                "occurrences": 4,
                "lower_bound": True,
                "unique_testcases": 3,
                "exact_duplicate_occurrences": 1,
                "phase_counts": {"call": 3, "teardown": 1},
                "target_counts": {"tests/test_x.py": 2, "tests/test_y.py": 2},
                "attempt_counts": {"0": 3, "1": 1},
                "unattributed_occurrences": 1,
                "per_file_counts": {"tests/test_x.py": 3, "tests/test_y.py": 1},
                "samples": [],
            },
        )
    }
    section = _section(_render(quality))
    assert "status: partial (malformed JSON/object record(s): 1)" in section
    assert "unclassified occurrences: >=4 across >=3 logical testcase(s)" in section
    assert "by phase: call=>=3, teardown=>=1" in section
    assert "exact duplicate occurrences: >=1" in section
    assert "unattributed (no isolation marker) occurrences: >=1" in section
    assert "top retry targets: tests/test_x.py (>=2), tests/test_y.py (>=2)" in section
    assert "top files: tests/test_x.py (>=3), tests/test_y.py (>=1)" in section
    # Never a bare unqualified count once the status is partial.
    assert "occurrences: 4 " not in section


# --------------------------------------------------------------------------- #
# Malformed numeric counts: never crash, never fabricate a zero
# --------------------------------------------------------------------------- #


def test_malformed_numeric_counts_render_dashes_instead_of_crashing_or_zero() -> None:
    quality = {
        "classification_observability": _observability(
            unclassified={
                "occurrences": "not-a-number",
                "lower_bound": False,
                "unique_testcases": None,
                "exact_duplicate_occurrences": [],
                "phase_counts": "not-a-mapping",
                "target_counts": {},
                "attempt_counts": {},
                "unattributed_occurrences": {},
                "per_file_counts": {},
                "samples": [],
            }
        )
    }
    section = _section(_render(quality))  # must not raise
    assert "unclassified occurrences: -- across -- logical testcase(s)" in section
    assert "exact duplicate occurrences: --" in section
    occurrences_line = next(
        line for line in section.splitlines() if line.startswith("- unclassified occurrences")
    )
    assert "0" not in occurrences_line  # no fabricated zero anywhere on that line


# --------------------------------------------------------------------------- #
# Existing golden fixture is unaffected (no `quality=` argument passed there)
# --------------------------------------------------------------------------- #


def test_render_provider_without_quality_argument_has_no_observability_section() -> None:
    """Mirrors tests/test_report_golden.py's call shape exactly: `quality` is never passed,
    so the golden markdown must stay byte-identical -- no observability section appears."""
    md = render_provider("prov", groups=[], summary={}, coverage=None, units=[])
    assert "## classification observability" not in md
