"""Merge provenance honesty: no borrowed identity for unattributed shards (F-025).

Merging a payload with provenance and one without used to stamp the whole
merge with the first-known provenance while reporting incomplete=false.
Mixed merges now carry an explicit mixed marker (counts, reason, and the
shared known value kept subordinate for diagnosis) and report incomplete,
because unattributed inputs cannot prove a complete run. Differing known
provenance still refuses outright; all-unknown still omits the block.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pkcs11_check.core.merge import merge_results_payloads, merge_shard_dirs

_KNOWN = {
    "framework": {"version": "v1", "dirty": False},
    "provider": {"name": "softhsm2", "commit": "abc"},
    "test_data": [{"name": "cts", "present": True}],
}


def _payload(passed: int, *, provenance: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "summary": {"passed": passed},
        "units": [],
    }
    if provenance is not None:
        payload["provenance"] = provenance
    return payload


def test_mixed_known_unknown_marks_mixed_and_incomplete() -> None:
    """F-025: the known stamp must not cover an unattributed shard."""
    merged = merge_results_payloads(
        [_payload(1, provenance=dict(_KNOWN)), _payload(2)], coverage=None
    )
    provenance = merged["provenance"]
    assert provenance["status"] == "mixed"
    assert provenance["shards_with_provenance"] == 1
    assert provenance["shards_without_provenance"] == 1
    assert "reason" in provenance
    assert provenance["known_provenance"] == _KNOWN
    assert merged["provenance"] != _KNOWN
    assert merged["summary"]["incomplete"] is True
    assert merged["summary"]["passed"] == 3


def test_non_dict_provenance_counts_as_unknown() -> None:
    """F-025: a malformed (non-dict) provenance block is unattributed, not skipped."""
    p1 = _payload(1, provenance=dict(_KNOWN))
    p2 = _payload(1)
    p2["provenance"] = "v1"
    merged = merge_results_payloads([p1, p2], coverage=None)
    assert merged["provenance"]["status"] == "mixed"
    assert merged["summary"]["incomplete"] is True


def test_all_known_agreeing_stamps() -> None:
    """Unanimous provenance still stamps the merge (no-regression pin)."""
    merged = merge_results_payloads(
        [_payload(1, provenance=dict(_KNOWN)), _payload(2, provenance=dict(_KNOWN))],
        coverage=None,
    )
    assert merged["provenance"] == _KNOWN
    assert merged["summary"]["incomplete"] is False


def _write_shard(
    d: Path,
    *,
    summary: dict[str, int],
    provenance: dict[str, Any] | None = None,
) -> None:
    d.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": summary,
        "units": [],
    }
    if provenance is not None:
        payload["provenance"] = provenance
    (d / "results.json").write_text(json.dumps(payload), encoding="utf-8")
    # A present (if empty) stream: absence is the merge's designed partial
    # signal, and these tests pin provenance -- not stream -- semantics.
    (d / "report.jsonl").write_text("", encoding="utf-8")


def test_merge_shard_dirs_mixed_warns_and_marks(tmp_path: Path) -> None:
    """F-025 dir-level: mixed shards warn loudly and carry the marker."""
    s0 = tmp_path / "shard0"
    s1 = tmp_path / "shard1"
    _write_shard(s0, summary={"passed": 1}, provenance=dict(_KNOWN))
    _write_shard(s1, summary={"passed": 2})
    out = tmp_path / "merged"

    merged = merge_shard_dirs([s0, s1], out)

    assert merged["provenance"]["status"] == "mixed"
    assert merged["summary"]["incomplete"] is True
    warnings = merged["shards"].get("warnings", [])
    assert any("provenance" in warning for warning in warnings)


def test_merge_shard_dirs_unanimous_stamps(tmp_path: Path) -> None:
    """Dir-level unanimous provenance still stamps (no-regression pin)."""
    s0 = tmp_path / "shard0"
    s1 = tmp_path / "shard1"
    _write_shard(s0, summary={"passed": 1}, provenance=dict(_KNOWN))
    _write_shard(s1, summary={"passed": 2}, provenance=dict(_KNOWN))
    out = tmp_path / "merged"

    merged = merge_shard_dirs([s0, s1], out)

    assert merged["provenance"] == _KNOWN
    assert merged["summary"]["incomplete"] is False
