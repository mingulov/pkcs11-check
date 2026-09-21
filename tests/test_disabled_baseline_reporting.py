"""Loud deselected-count reporting for the disabled baseline (H-7).

A baseline that silently drops whole units -- or matches nothing because it
went stale -- is invisible in results today: excluded files simply never run,
and per-file deselections hide inside child outputs. The console banner and
the results.json block make every baseline effect explicit and machine-auditable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pkcs11_check.cli import test_cmd
from pkcs11_check.core._report_writers import _build_isolated_json_payload
from pkcs11_check.core._run_units import FileRunState, IsolatedReportConfig
from pkcs11_check.core.disabled_baseline import (
    NO_BASELINE_FINGERPRINT,
    build_disabled_baseline_block,
    format_disabled_baseline_banner,
)


def test_banner_reports_all_baseline_effects() -> None:
    banner = format_disabled_baseline_banner(
        nodeid_count=12,
        excluded_units=2,
        per_file_deselected=5,
        fingerprint="abcdef1234567890",
    )
    assert "12" in banner
    assert "2 unit(s) fully excluded" in banner
    assert "5 deselected in scheduled units" in banner
    assert "abcdef123456" in banner  # short fingerprint for log correlation


def test_banner_is_loud_when_baseline_matches_nothing() -> None:
    # A stale baseline that matches zero collected items is the suspicious
    # case -- the banner must show it, not hide behind "0 deselected" silence.
    banner = format_disabled_baseline_banner(
        nodeid_count=12,
        excluded_units=0,
        per_file_deselected=0,
        fingerprint="abcdef1234567890",
    )
    assert "12" in banner
    assert "0 unit(s) fully excluded" in banner
    assert "0 deselected in scheduled units" in banner


def test_block_carries_fingerprint_and_counts() -> None:
    block = build_disabled_baseline_block(
        fingerprint="fp-sha",
        deselect_by_file={"a.py": {"n1", "n2"}, "b.py": {"n3"}},
        excluded_units=1,
    )
    assert block == {
        "fingerprint": "fp-sha",
        "excluded_units": 1,
        "per_file_deselected": {"a.py": 2, "b.py": 1},
        "total_per_file_deselected": 3,
    }


def test_block_present_but_zeroed_when_baseline_matches_nothing() -> None:
    block = build_disabled_baseline_block(
        fingerprint="fp-sha",
        deselect_by_file={},
        excluded_units=0,
    )
    assert block is not None
    assert block["total_per_file_deselected"] == 0
    assert block["excluded_units"] == 0


def test_block_absent_without_baseline() -> None:
    assert (
        build_disabled_baseline_block(
            fingerprint=NO_BASELINE_FINGERPRINT,
            deselect_by_file={},
            excluded_units=0,
        )
        is None
    )
    assert (
        build_disabled_baseline_block(
            fingerprint=None,
            deselect_by_file={},
            excluded_units=0,
        )
        is None
    )


def _empty_state() -> FileRunState:
    return FileRunState(units=[], fingerprint="abc", results=[])


def test_results_payload_omits_block_without_baseline() -> None:
    payload = _build_isolated_json_payload(_empty_state())
    assert "disabled_baseline" not in payload


def test_results_payload_carries_block() -> None:
    block: dict[str, Any] = {
        "fingerprint": "fp-sha",
        "excluded_units": 1,
        "per_file_deselected": {"a.py": 2},
        "total_per_file_deselected": 2,
    }
    payload = _build_isolated_json_payload(_empty_state(), disabled_baseline=block)
    assert payload["disabled_baseline"] == block


def test_collection_failure_results_carry_block(tmp_path: Path) -> None:
    """H-7: the collection-failure results.json forwards the baseline block too."""
    results_path = tmp_path / "results.json"
    report_config = IsolatedReportConfig(
        "json",
        results_path,
        jsonl_path=tmp_path / "report.jsonl",
        disabled_baseline={
            "fingerprint": "fp-sha",
            "excluded_units": 0,
            "per_file_deselected": {},
            "total_per_file_deselected": 0,
        },
    )
    test_cmd._persist_collection_failure(
        diagnostic="boom",
        state_file=Path(tmp_path / "state.json"),
        report_config=report_config,
        resume=False,
        provenance={},
    )
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    assert payload["disabled_baseline"]["fingerprint"] == "fp-sha"
