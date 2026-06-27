"""Golden test for the per-provider report generator (tools.report).

Drives extract -> enrich -> render on a committed mini fixture spanning every
classification reason (incl. a crash from results.json) and asserts the rendered
``softhsm2.md`` matches the committed golden byte-for-byte, plus a size budget.

To regenerate the golden after an intentional layout change::

    uv run python tests/test_report_golden.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Allow `python tests/test_report_golden.py` (regen) to import the tools package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.report.correlate import enrich  # noqa: E402
from tools.report.extract import extract_groups  # noqa: E402
from tools.report.render import render_provider  # noqa: E402

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "report"
MINI_REPORT = FIXTURE_DIR / "mini_report.jsonl"
MINI_RESULTS = FIXTURE_DIR / "mini_results.json"
GOLDEN_MD = FIXTURE_DIR / "expected_provider.md"

PROVIDER = "softhsm2"


def _crashes_from_results(path: Path) -> list[dict[str, Any]]:
    from pkcs11_check.core.file_runner import crash_classification

    payload = json.loads(path.read_text())
    crashes: list[dict[str, Any]] = []
    for unit in payload.get("units", []):
        if str(unit.get("status")) == "crashed":
            rc_raw = unit.get("returncode")
            rc = -abs(int(rc_raw)) if isinstance(rc_raw, int) and rc_raw else None
            crashes.append(crash_classification(returncode=rc, target=str(unit.get("target"))))
    return crashes


def generate_markdown() -> str:
    """Build the provider markdown from the committed fixtures (no docs dependency)."""
    crashes = _crashes_from_results(MINI_RESULTS)
    groups = extract_groups(MINI_REPORT, crashes=crashes)
    # empty module-issues so the golden is provider-independent
    enrich(groups, module_issues_text="", provider=PROVIDER)
    return render_provider(PROVIDER, groups, pass_count=44957)


def test_generated_markdown_matches_golden() -> None:
    generated = generate_markdown()
    expected = GOLDEN_MD.read_text()
    assert generated == expected, (
        "generated provider markdown drifted from golden; "
        "regenerate with `uv run python tests/test_report_golden.py`"
    )


def test_golden_size_budget() -> None:
    """Even spanning every reason + a crash, the report stays ~one screen."""
    md = generate_markdown()
    assert len(md.splitlines()) < 60


def test_golden_has_no_sha1() -> None:
    assert "sha1" not in generate_markdown().lower()


if __name__ == "__main__":
    GOLDEN_MD.write_text(generate_markdown())
    print(f"wrote {GOLDEN_MD}")
