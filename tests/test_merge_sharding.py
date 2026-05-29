"""Tests for multi-shard sharding (LPT) and artifact merge."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pkcs11_check.core.merge import merge_results_payloads, merge_shard_dirs
from pkcs11_check.core.sharding import duration_by_unit_from_results, plan_shards

# --------------------------------------------------------------------------- #
# Sharding
# --------------------------------------------------------------------------- #


def test_plan_shards_single_returns_all() -> None:
    units = ["a.py", "b.py", "c.py"]
    assert plan_shards(units, 1) == [units]


def test_plan_shards_is_a_partition() -> None:
    units = [f"f{i}.py" for i in range(20)]
    shards = plan_shards(units, 4)
    assert len(shards) == 4
    flat = sorted(u for s in shards for u in s)
    assert flat == sorted(units)  # disjoint + complete


def test_plan_shards_spreads_heavy_files() -> None:
    # Three heavy files + many light ones: the heavy ones must land on
    # different shards (LPT), not pile onto one.
    durations = {"heavy_a.py": 660.0, "heavy_b.py": 660.0, "heavy_c.py": 660.0}
    light = {f"light{i}.py": 1.0 for i in range(30)}
    durations.update(light)
    shards = plan_shards(list(durations), 3, duration_by_unit=durations)
    heavy_locations = {
        unit: i for i, s in enumerate(shards) for unit in s if unit.startswith("heavy")
    }
    assert len(set(heavy_locations.values())) == 3  # one heavy file per shard


def test_plan_shards_balances_by_count_without_durations() -> None:
    units = [f"f{i}.py" for i in range(12)]
    shards = plan_shards(units, 4)
    assert sorted(len(s) for s in shards) == [3, 3, 3, 3]


def test_duration_by_unit_folds_per_test_nodeids(tmp_path: Path) -> None:
    results = {
        "units": [
            {"target": "a.py", "duration_s": 5.0},
            {"target": "a.py::test_x", "duration_s": 2.0},
            {"target": "b.py", "duration_s": 1.0},
        ]
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results))
    durs = duration_by_unit_from_results(path)
    assert durs == {"a.py": 7.0, "b.py": 1.0}


# --------------------------------------------------------------------------- #
# Merge
# --------------------------------------------------------------------------- #


def test_merge_results_payloads_sums_and_concats() -> None:
    p1 = {"summary": {"passed": 2, "failed": 1}, "units": [{"target": "a.py"}]}
    p2 = {"summary": {"passed": 3, "skipped": 4}, "units": [{"target": "b.py"}]}
    merged = merge_results_payloads([p1, p2], coverage=None)
    assert merged["summary"]["passed"] == 5
    assert merged["summary"]["failed"] == 1
    assert merged["summary"]["skipped"] == 4
    assert merged["summary"]["total"] == 5 + 1 + 4
    assert [u["target"] for u in merged["units"]] == ["a.py", "b.py"]


def _coverage_report(
    called: list[str], invoked: list[str], available_funcs: int, available_mechs: list[str]
) -> dict[str, Any]:
    return {
        "$report_type": "CoverageReport",
        "function_coverage": {
            "available": available_funcs,
            "called": len(called),
            "called_names": called,
            "called_counts": {name: 1 for name in called},
            "bootstrap_counts": {"C_Initialize": 1},
            "uncalled_names": [],
        },
        "mechanism_coverage": {
            "available": len(available_mechs),
            "available_names": available_mechs,
            "invoked": len(invoked),
            "invoked_names": invoked,
            "invoked_counts": {name: 1 for name in invoked},
            "not_invoked": len(available_mechs) - len(invoked),
            "not_invoked_names": [m for m in available_mechs if m not in invoked],
            "invoked_detail": invoked,
            "invoked_detail_counts": {name: 1 for name in invoked},
        },
    }


def _testreport(nodeid: str, outcome: str) -> dict[str, Any]:
    return {
        "$report_type": "TestReport",
        "nodeid": nodeid,
        "when": "call",
        "outcome": outcome,
        "duration": 0.1,
    }


def _write_shard(
    d: Path, units: list[dict[str, Any]], summary: dict[str, int], records: list[dict[str, Any]]
) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "results.json").write_text(
        json.dumps({"tool": "pkcs11-check", "kind": "test-run", "summary": summary, "units": units})
    )
    (d / "report.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))


def test_merge_shard_dirs_unions_coverage_and_sums_results(tmp_path: Path) -> None:
    s0 = tmp_path / "shard0"
    s1 = tmp_path / "shard1"
    _write_shard(
        s0,
        units=[{"target": "a.py", "status": "passed"}],
        summary={"passed": 2, "failed": 0},
        records=[
            _testreport("a.py::t1", "passed"),
            _testreport("a.py::t2", "passed"),
            _coverage_report(["C_Encrypt"], ["CKM_AES_CBC"], 10, ["CKM_AES_CBC", "CKM_AES_GCM"]),
        ],
    )
    _write_shard(
        s1,
        units=[{"target": "b.py", "status": "failed"}],
        summary={"passed": 1, "failed": 1},
        records=[
            _testreport("b.py::t1", "passed"),
            _testreport("b.py::t2", "failed"),
            _coverage_report(["C_Decrypt"], ["CKM_AES_GCM"], 10, ["CKM_AES_CBC", "CKM_AES_GCM"]),
        ],
    )

    out = tmp_path / "merged"
    merged = merge_shard_dirs([s0, s1], out)

    # results: summed summary, concatenated units
    assert merged["summary"]["passed"] == 3
    assert merged["summary"]["failed"] == 1
    assert {u["target"] for u in merged["units"]} == {"a.py", "b.py"}
    assert merged["shards"]["count"] == 2

    # artifacts written
    assert (out / "report.jsonl").exists()
    assert (out / "results.json").exists()
    assert (out / "coverage.json").exists()
    assert (out / "quality.json").exists()

    # coverage: union across shards
    cov = json.loads((out / "coverage.json").read_text())
    assert set(cov["function_coverage"]["called_names"]) == {"C_Encrypt", "C_Decrypt"}
    assert set(cov["mechanism_coverage"]["invoked_names"]) == {"CKM_AES_CBC", "CKM_AES_GCM"}
    # both available mechanisms were invoked across shards -> none not-invoked
    assert cov["mechanism_coverage"]["not_invoked"] == 0


def test_merge_shard_dirs_round_trip_identity(tmp_path: Path) -> None:
    """Splitting one run's records into 2 shards then merging reproduces it.

    This is the core guarantee: a sharded run's merge is exact for the merge
    logic itself (any outcome differences come from device state, not merging).
    """
    full_records = [
        _testreport("a.py::t1", "passed"),
        _testreport("b.py::t1", "failed"),
        _testreport("c.py::t1", "passed"),
        _coverage_report(
            ["C_Encrypt", "C_Sign"], ["CKM_AES_CBC"], 10, ["CKM_AES_CBC", "CKM_RSA_PKCS"]
        ),
    ]
    full_summary = {"passed": 2, "failed": 1}

    # Split: shard0 gets a+coverage, shard1 gets b,c
    s0 = tmp_path / "s0"
    s1 = tmp_path / "s1"
    _write_shard(s0, [{"target": "a.py"}], {"passed": 1}, full_records[:1] + full_records[3:])
    _write_shard(
        s1, [{"target": "b.py"}, {"target": "c.py"}], {"passed": 1, "failed": 1}, full_records[1:3]
    )

    out = tmp_path / "merged"
    merged = merge_shard_dirs([s0, s1], out)

    assert merged["summary"]["passed"] == full_summary["passed"]
    assert merged["summary"]["failed"] == full_summary["failed"]
    assert {u["target"] for u in merged["units"]} == {"a.py", "b.py", "c.py"}
    cov = json.loads((out / "coverage.json").read_text())
    assert set(cov["function_coverage"]["called_names"]) == {"C_Encrypt", "C_Sign"}
