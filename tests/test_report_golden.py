"""Golden test for the per-provider report generator (pkcs11_check.report).

Drives extract -> enrich -> render on a committed mini fixture spanning every
classification reason (incl. a crash from results.json) and asserts the rendered
``softhsm2.md`` matches the committed golden byte-for-byte, plus a size budget.

To regenerate the golden after an intentional layout change::

    uv run python tests/test_report_golden.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pkcs11_check.report.correlate import enrich
from pkcs11_check.report.extract import extract_groups
from pkcs11_check.report.render import render_provider

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "report"
MINI_REPORT = FIXTURE_DIR / "mini_report.jsonl"
MINI_RESULTS = FIXTURE_DIR / "mini_results.json"
GOLDEN_MD = FIXTURE_DIR / "expected_provider.md"

PROVIDER = "example-provider"


def _crashes_from_results(path: Path) -> list[dict[str, Any]]:
    from pkcs11_check.core.file_runner import crash_classification

    payload = json.loads(path.read_text(encoding="utf-8"))
    crashes: list[dict[str, Any]] = []
    for unit in payload.get("units", []):
        if str(unit.get("status")) == "crashed":
            rc_raw = unit.get("returncode")
            rc = -abs(int(rc_raw)) if isinstance(rc_raw, int) and rc_raw else None
            crashes.append(crash_classification(returncode=rc, target=str(unit.get("target"))))
    return crashes


def generate_markdown() -> str:
    """Build the provider markdown from the committed fixtures (no docs dependency)."""
    payload = json.loads(MINI_RESULTS.read_text(encoding="utf-8"))
    crashes = _crashes_from_results(MINI_RESULTS)
    groups = extract_groups(MINI_REPORT, crashes=crashes)
    # empty module-issues so the golden is provider-independent
    enrich(groups, module_issues_text="", provider=PROVIDER)
    return render_provider(
        PROVIDER,
        groups,
        summary=payload.get("summary") or {},
        coverage=payload.get("coverage"),
        units=payload.get("units") or [],
    )


def test_generated_markdown_matches_golden() -> None:
    generated = generate_markdown()
    expected = GOLDEN_MD.read_text(encoding="utf-8")
    assert generated == expected, (
        "generated provider markdown drifted from golden; "
        "regenerate with `uv run python tests/test_report_golden.py`"
    )


def test_golden_size_budget() -> None:
    """Even spanning every reason + a crash, the report stays ~one screen."""
    md = generate_markdown()
    assert len(md.splitlines()) < 90


def test_golden_has_no_sha1() -> None:
    assert "sha1" not in generate_markdown().lower()


if __name__ == "__main__":
    GOLDEN_MD.write_text(generate_markdown(), encoding="utf-8")
    print(f"wrote {GOLDEN_MD}")
