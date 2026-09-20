"""Order-1 merge-safety goldens (validation N-001/N-002, F-013/F-014/F-015).

Each test pins evidence preservation: merges must never destroy or silently
double-count the raw shard artifacts they read.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.cli.app import app
from pkcs11_check.core.merge import merge_results_payloads, merge_shard_dirs
from pkcs11_check.core.test_selection import CaseSelection, compute_batch_id
from tests._plain_cli_runner import PlainCliRunner

runner = PlainCliRunner()


def _write_shard(
    d: Path,
    units: list[dict[str, Any]],
    summary: dict[str, Any],
    nodeids: list[str],
) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "results.json").write_text(
        json.dumps(
            {
                "tool": "pkcs11-check",
                "kind": "test-run",
                "summary": summary,
                "units": units,
            }
        ),
        encoding="utf-8",
    )
    (d / "report.jsonl").write_text(
        "".join(
            json.dumps(
                {
                    "$report_type": "TestReport",
                    "nodeid": nodeid,
                    "when": "call",
                    "outcome": "passed",
                }
            )
            + "\n"
            for nodeid in nodeids
        ),
        encoding="utf-8",
    )


def _snapshot_files(d: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(d.iterdir()) if p.is_file() or p.is_symlink()}


# ---------------------------------------------------------------------------
# N-001: merging into an input directory must be rejected before any write
# ---------------------------------------------------------------------------


def test_merge_into_own_input_dir_is_rejected_with_inputs_intact(tmp_path: Path) -> None:
    """N-001: output == input shard must raise; raw evidence bytes unchanged."""
    shard = tmp_path / "shard"
    _write_shard(
        shard,
        [{"target": "test_a.py", "status": "passed", "returncode": 0}],
        {"passed": 1},
        ["test_a.py::test_a"],
    )
    before = _snapshot_files(shard)

    with pytest.raises(ValueError, match="aliases its input"):
        merge_shard_dirs([shard], shard)

    assert _snapshot_files(shard) == before


def test_merge_into_symlinked_input_dir_is_rejected(tmp_path: Path) -> None:
    """N-001: file-alias (symlink) outputs must be rejected the same way."""
    shard = tmp_path / "shard"
    _write_shard(
        shard,
        [{"target": "test_a.py", "status": "passed", "returncode": 0}],
        {"passed": 1},
        ["test_a.py::test_a"],
    )
    link = tmp_path / "out_link"
    link.symlink_to(shard, target_is_directory=True)
    before = _snapshot_files(shard)

    with pytest.raises(ValueError, match="aliases its input"):
        merge_shard_dirs([shard], link)

    assert _snapshot_files(shard) == before


def test_merge_to_separate_dir_preserves_input_bytes(tmp_path: Path) -> None:
    """Valid merges never mutate their inputs (acceptance: byte preservation)."""
    shard = tmp_path / "shard"
    _write_shard(
        shard,
        [{"target": "test_a.py", "status": "passed", "returncode": 0}],
        {"passed": 1},
        ["test_a.py::test_a"],
    )
    before = _snapshot_files(shard)

    merged = merge_shard_dirs([shard], tmp_path / "out")

    assert merged["summary"]["passed"] == 1
    assert _snapshot_files(shard) == before


def _unit_payload(target: str, passed: int = 1) -> dict[str, Any]:
    return {
        "summary": {"passed": passed},
        "units": [{"target": target, "status": "passed"}],
    }


# ---------------------------------------------------------------------------
# N-002: whole-file / per-node overlaps must be rejected, not summed
# ---------------------------------------------------------------------------


def test_merge_rejects_whole_file_plus_node_overlap() -> None:
    """N-002: a whole-file unit includes its nodes under the ordinary contract."""
    with pytest.raises(ValueError, match="overlapping execution coverage"):
        merge_results_payloads(
            [_unit_payload("test_a.py", 2), _unit_payload("test_a.py::test_a")],
            coverage=None,
        )


def test_merge_rejects_duplicate_node_units() -> None:
    """N-002: the same node in two shards is a double-count."""
    with pytest.raises(ValueError, match="overlapping execution coverage"):
        merge_results_payloads(
            [_unit_payload("test_a.py::test_a"), _unit_payload("test_a.py::test_a")],
            coverage=None,
        )


def test_merge_rejects_node_containment_overlap() -> None:
    """N-002: a class-level unit contains its test-level node."""
    with pytest.raises(ValueError, match="overlapping execution coverage"):
        merge_results_payloads(
            [
                _unit_payload("test_a.py::TestClass"),
                _unit_payload("test_a.py::TestClass::test_x"),
            ],
            coverage=None,
        )


def test_merge_accepts_disjoint_node_units() -> None:
    """N-002: disjoint nodes merge and sum normally."""
    merged = merge_results_payloads(
        [_unit_payload("test_a.py::test_1"), _unit_payload("test_a.py::test_2")],
        coverage=None,
    )
    assert merged["summary"]["passed"] == 2


def test_merge_node_prefix_match_needs_separator_boundary() -> None:
    """N-002: test_1 must not 'contain' test_10 (no naive startswith)."""
    merged = merge_results_payloads(
        [
            _unit_payload("test_a.py::TestClass::test_1"),
            _unit_payload("test_a.py::TestClass::test_10"),
        ],
        coverage=None,
    )
    assert merged["summary"]["passed"] == 2


def _make_selection(source: str, nodeids: list[str], plan_id: str = "a" * 64) -> CaseSelection:
    nodeids_tuple = tuple(nodeids)
    return CaseSelection(
        schema=1,
        plan_id=plan_id,
        batch_id=compute_batch_id(
            source=source,
            source_collection_count=len(nodeids_tuple),
            source_collection_sha256="b" * 64,
            nodeids=nodeids_tuple,
        ),
        source=source,
        source_collection_count=len(nodeids_tuple),
        source_collection_sha256="b" * 64,
        nodeids=nodeids_tuple,
    )


def _selection_payload(source: str, nodeids: list[str], passed: int) -> dict[str, Any]:
    selection = _make_selection(source, nodeids)
    return {
        "summary": {"passed": passed},
        "units": [{"target": source, "status": "passed"}],
        "selection": selection.to_dict(),
    }


# ---------------------------------------------------------------------------
# F-015: selection presence must not disable the ordinary overlap checks
# ---------------------------------------------------------------------------


def _selection_root(tmp_path: Path) -> Path:
    """A testcases root where selection sources resolve to real files."""
    (tmp_path / "test_a.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path


def test_merge_rejects_selection_batch_plus_whole_file_source(tmp_path: Path) -> None:
    """F-015: a batch's cases are included in the whole-file run of its source."""
    root = _selection_root(tmp_path)
    with pytest.raises(ValueError, match="overlapping execution coverage"):
        merge_results_payloads(
            [
                _selection_payload("test_a.py", ["test_a.py::test_1"], 1),
                _unit_payload("test_a.py", 2),
            ],
            coverage=None,
            testcases_root=root,
        )


def test_merge_rejects_selection_batch_plus_same_node(tmp_path: Path) -> None:
    """F-015: a batch node also covered by an ordinary node unit overlaps."""
    root = _selection_root(tmp_path)
    with pytest.raises(ValueError, match="overlapping execution coverage"):
        merge_results_payloads(
            [
                _selection_payload("test_a.py", ["test_a.py::test_1"], 1),
                _unit_payload("test_a.py::test_1"),
            ],
            coverage=None,
            testcases_root=root,
        )


def test_merge_rejects_selection_batch_plus_duplicate_ordinary(tmp_path: Path) -> None:
    """F-015: one batch must not disable duplicate checks between ordinaries."""
    root = _selection_root(tmp_path)
    with pytest.raises(ValueError, match="overlapping execution coverage"):
        merge_results_payloads(
            [
                _selection_payload("test_a.py", ["test_a.py::test_1"], 1),
                _unit_payload("other.py"),
                _unit_payload("other.py"),
            ],
            coverage=None,
            testcases_root=root,
        )


def test_merge_accepts_selection_batch_plus_disjoint_file(tmp_path: Path) -> None:
    """F-015: a batch and an ordinary run of another file are disjoint."""
    root = _selection_root(tmp_path)
    merged = merge_results_payloads(
        [
            _selection_payload("test_a.py", ["test_a.py::test_1"], 1),
            _unit_payload("other.py"),
        ],
        coverage=None,
        testcases_root=root,
    )
    assert merged["summary"]["passed"] == 2


def test_merge_accepts_disjoint_selection_batches_same_source(tmp_path: Path) -> None:
    """F-015: disjoint batches may share a whole-file unit target (by design)."""
    root = _selection_root(tmp_path)
    merged = merge_results_payloads(
        [
            _selection_payload("test_a.py", ["test_a.py::test_1"], 1),
            _selection_payload("test_a.py", ["test_a.py::test_2"], 1),
        ],
        coverage=None,
        testcases_root=root,
    )
    assert merged["summary"]["passed"] == 2


# ---------------------------------------------------------------------------
# F-013: missing shard evidence must surface as incomplete + warning
# ---------------------------------------------------------------------------


def test_merge_marks_incomplete_when_report_jsonl_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """F-013: valid results.json but no report.jsonl shortens the merged JSONL.

    The merged summary must say incomplete and the merge must warn, instead of
    reporting complete quality over silently short evidence.
    """
    shard = tmp_path / "shard"
    _write_shard(
        shard,
        [{"target": "test_a.py", "status": "passed", "returncode": 0}],
        {"passed": 1},
        ["test_a.py::test_a"],
    )
    (shard / "report.jsonl").unlink()

    merged = merge_shard_dirs([shard], tmp_path / "out")

    assert merged["summary"]["incomplete"] is True
    assert merged["summary"]["passed"] == 1
    assert "report.jsonl" in capsys.readouterr().err


def test_merge_marks_incomplete_when_a_shard_dir_is_empty(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """F-013/F-014: a shard dir with no artifacts warns and marks incomplete."""
    good = tmp_path / "good"
    _write_shard(
        good,
        [{"target": "test_a.py", "status": "passed", "returncode": 0}],
        {"passed": 1},
        ["test_a.py::test_a"],
    )
    empty = tmp_path / "empty"
    empty.mkdir()

    merged = merge_shard_dirs([good, empty], tmp_path / "out")

    assert merged["summary"]["passed"] == 1
    assert merged["summary"]["incomplete"] is True
    assert "empty" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# F-014: every requested shard must reach validation (no silent pre-filter)
# ---------------------------------------------------------------------------


def test_merge_shards_cli_warns_on_unknown_dir(tmp_path: Path) -> None:
    """F-014: a mistyped/empty dir alongside valid shards must warn loudly."""
    good = tmp_path / "good"
    _write_shard(
        good,
        [{"target": "test_a.py", "status": "passed", "returncode": 0}],
        {"passed": 1},
        ["test_a.py::test_a"],
    )
    bad = tmp_path / "typo-dir"
    bad.mkdir()

    out = tmp_path / "out"
    res = runner.invoke(app, ["merge-shards", str(good), str(bad), "-o", str(out)])

    assert res.exit_code == 0
    assert (out / "results.json").exists()
    merged = json.loads((out / "results.json").read_text(encoding="utf-8"))
    assert merged["summary"]["incomplete"] is True
    assert "typo-dir" in (res.stdout + (res.stderr or ""))


def test_merge_shards_cli_rejects_all_unknown_dirs(tmp_path: Path) -> None:
    """F-014: nothing mergeable at all stays a hard error (exit 2)."""
    bad = tmp_path / "typo-dir"
    bad.mkdir()

    res = runner.invoke(app, ["merge-shards", str(bad), "-o", str(tmp_path / "out")])

    assert res.exit_code == 2


# ---------------------------------------------------------------------------
# Executed-coverage fallback: manifest-less per-node batches of one file
# ---------------------------------------------------------------------------


def test_merge_allows_disjoint_node_batches_without_manifests(tmp_path: Path) -> None:
    """Same whole-file unit target, disjoint executed nodeids: merge, don't refuse."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    units = [{"target": "test_a.py", "status": "passed", "returncode": 0}]
    _write_shard(a, units, {"passed": 1}, ["test_a.py::t1"])
    _write_shard(b, units, {"passed": 1}, ["test_a.py::t2"])

    merged = merge_shard_dirs([a, b], tmp_path / "out")

    assert merged["summary"]["passed"] == 2


def test_merge_refuses_overlapping_node_batches_without_manifests(tmp_path: Path) -> None:
    """Same whole-file unit target, shared executed nodeid: refuse (no double-count)."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    units = [{"target": "test_a.py", "status": "passed", "returncode": 0}]
    _write_shard(a, units, {"passed": 1}, ["test_a.py::t1"])
    _write_shard(b, units, {"passed": 1}, ["test_a.py::t1"])

    with pytest.raises(ValueError, match="overlapping execution coverage"):
        merge_shard_dirs([a, b], tmp_path / "out")


def test_merge_refuses_collision_when_sidecar_missing(tmp_path: Path) -> None:
    """No report.jsonl on a colliding shard: disjointness is unprovable, refuse."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    units = [{"target": "test_a.py", "status": "passed", "returncode": 0}]
    _write_shard(a, units, {"passed": 1}, ["test_a.py::t1"])
    _write_shard(b, units, {"passed": 1}, ["test_a.py::t2"])
    (b / "report.jsonl").unlink()

    with pytest.raises(ValueError, match="overlapping execution coverage"):
        merge_shard_dirs([a, b], tmp_path / "out")


def test_merge_refuses_aliased_spelling_across_batches(tmp_path: Path) -> None:
    """Win vs posix spelling of the same test is the same test: refuse."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    _write_shard(
        a,
        [{"target": "sub\\test_a.py", "status": "passed", "returncode": 0}],
        {"passed": 1},
        ["sub\\test_a.py::t1"],
    )
    _write_shard(
        b,
        [{"target": "sub/test_a.py", "status": "passed", "returncode": 0}],
        {"passed": 1},
        ["sub/test_a.py::t1"],
    )

    with pytest.raises(ValueError, match="overlapping execution coverage"):
        merge_shard_dirs([a, b], tmp_path / "out")


def test_merge_ignores_file_level_synthetic_records_in_fallback(tmp_path: Path) -> None:
    """Bare-file abrupt records on both shards must not block disjoint batches."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    units = [{"target": "test_a.py", "status": "failed", "returncode": 1}]
    _write_shard(a, units, {"passed": 1}, ["test_a.py::t1", "test_a.py"])
    _write_shard(b, units, {"passed": 1}, ["test_a.py::t2", "test_a.py"])

    merged = merge_shard_dirs([a, b], tmp_path / "out")

    assert merged["summary"]["passed"] == 2


def test_merge_refuses_mixed_manifest_and_plain_batches_with_disjoint_proof(
    tmp_path: Path,
) -> None:
    """A manifest batch plus a manifest-less batch of one file always refuses."""
    root = _selection_root(tmp_path)
    a = tmp_path / "a"
    b = tmp_path / "b"
    _write_shard(
        a,
        [{"target": "test_a.py", "status": "passed", "returncode": 0}],
        {"passed": 1},
        ["test_a.py::t1"],
    )
    results_a = json.loads((a / "results.json").read_text(encoding="utf-8"))
    results_a["selection"] = _make_selection("test_a.py", ["test_a.py::t1"]).to_dict()
    (a / "results.json").write_text(json.dumps(results_a), encoding="utf-8")
    _write_shard(
        b,
        [{"target": "test_a.py", "status": "passed", "returncode": 0}],
        {"passed": 1},
        ["test_a.py::t2"],
    )

    with pytest.raises(ValueError, match="overlapping execution coverage"):
        merge_shard_dirs([a, b], tmp_path / "out", testcases_root=root)
