"""Tests for multi-shard sharding (LPT) and artifact merge."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.core.merge import merge_results_payloads, merge_shard_dirs
from pkcs11_check.core.process_observation import build_process_observation
from pkcs11_check.core.run_metrics import RESULT_OUTCOME_KEYS
from pkcs11_check.core.sharding import (
    duration_by_unit_from_results,
    estimate_shard_load,
    plan_shards,
)
from pkcs11_check.core.test_selection import CaseSelection, compute_batch_id

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


def test_plan_shards_isolates_known_heavy_files_without_oracle() -> None:
    # The 3 ACVP-AES MCT files must land in DISTINCT batches even with no duration
    # oracle (via the synthetic heavy weight), so no batch concentrates them.
    base = "src/pkcs11_check/testcases/acvp/aes/"
    heavy = [base + n for n in ("test_cfb8.py", "test_ofb.py", "test_cfb128.py")]
    light = [f"src/pkcs11_check/testcases/test_light_{i}.py" for i in range(40)]
    shards = plan_shards(heavy + light, 4)  # no durations -> heavy weighting kicks in
    heavy_locations = {
        u.rsplit("/", 1)[-1]: i
        for i, s in enumerate(shards)
        for u in s
        if u.rsplit("/", 1)[-1] in {"test_cfb8.py", "test_ofb.py", "test_cfb128.py"}
    }
    assert len(set(heavy_locations.values())) == 3  # one heavy file per batch
    # still a complete, disjoint partition
    flat = sorted(u for s in shards for u in s)
    assert flat == sorted(heavy + light)


def test_plan_shards_isolates_widened_heavy_files() -> None:
    # The straggler (test_parameter_validation.py) and other recurring long poles
    # added to DEFAULT_HEAVY_BASENAMES must spread across batches instead of being
    # count-lumped into one (the 1270s bouncyhsm straggler bug).
    base = "src/pkcs11_check/testcases/"
    targets = {"test_parameter_validation.py", "test_wycheproof_ecdsa.py", "test_ccm.py"}
    heavy = [base + n for n in targets]
    light = [f"{base}test_light_{i}.py" for i in range(40)]
    shards = plan_shards(heavy + light, 3)  # no durations -> heavy weighting
    locations = {
        u.rsplit("/", 1)[-1]: i
        for i, s in enumerate(shards)
        for u in s
        if u.rsplit("/", 1)[-1] in targets
    }
    assert len(set(locations.values())) == 3  # one heavy file per batch


def test_plan_shards_heavy_disabled_when_none() -> None:
    base = "src/pkcs11_check/testcases/acvp/aes/"
    heavy = [base + n for n in ("test_cfb8.py", "test_ofb.py", "test_cfb128.py")]
    shards = plan_shards([*heavy, "x.py"], 2, heavy_basenames=None)
    flat = sorted(u for s in shards for u in s)
    assert flat == sorted([*heavy, "x.py"])  # partition intact, no special handling


def test_plan_shards_provider_specific_zero_duration_beats_synthetic_heavy() -> None:
    # Provider-local results are authoritative for that provider: if opencryptoki
    # skipped a synthetic-heavy ACVP file in 0s, do not rebalance it as if it
    # were a bouncyhsm long pole.
    heavy_zero = "src/pkcs11_check/testcases/acvp/aes/test_ccm.py"
    slow = "src/pkcs11_check/testcases/test_slow.py"
    light = "src/pkcs11_check/testcases/test_light.py"
    durations = {heavy_zero: 0.0, slow: 10.0, light: 1.0}

    shards = plan_shards([heavy_zero, slow, light], 2, duration_by_unit=durations)
    heavy_shard = next(s for s in shards if heavy_zero in s)

    assert light in heavy_shard
    assert slow not in heavy_shard


def test_estimate_shard_load_uses_provider_specific_zero_duration() -> None:
    heavy_zero = "src/pkcs11_check/testcases/acvp/aes/test_ccm.py"
    light = "src/pkcs11_check/testcases/test_light.py"

    load = estimate_shard_load(
        [heavy_zero, light],
        duration_by_unit={heavy_zero: 0.0, light: 1.25},
    )

    assert load == 1.25


def test_duration_by_unit_folds_per_test_nodeids(tmp_path: Path) -> None:
    results = {
        "units": [
            {"target": "a.py", "duration_s": 5.0},
            {"target": "a.py::test_x", "duration_s": 2.0},
            {"target": "b.py", "duration_s": 1.0},
        ]
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results), encoding="utf-8")
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
    assert merged["summary"]["total"] == sum(
        merged["summary"][k] for k in ("passed", "failed", "skipped")
    )
    assert [u["target"] for u in merged["units"]] == ["a.py", "b.py"]


def test_merge_recomputes_child_metrics_from_units() -> None:
    # Payload 1: a unit whose tests[] contains a child-subprocess crash finding.
    # The longrepr contains "module crashed with signal 11" which is one of the
    # _CHILD_CRASH_MARKERS recognised by compute_child_subprocess_counts.
    p1: dict[str, Any] = {
        "summary": {"failed": 1},
        "units": [
            {
                "target": "security/test_bounds.py",
                "status": "failed",
                "tests": [
                    {
                        "outcome": "failed",
                        "longrepr": "AssertionError: module crashed with signal 11",
                    }
                ],
            }
        ],
    }
    # Payload 2: crash_limited unit — tests abandoned after per-file crash budget.
    p2: dict[str, Any] = {
        "summary": {"crash_limited": 2},
        "units": [
            {
                "target": "security/test_overflow.py",
                "status": "crash_limited",
            }
        ],
    }
    merged = merge_results_payloads([p1, p2], coverage=None)
    s = merged["summary"]
    assert s["child_crash"] == 1
    assert s["child_timeout"] == 0
    assert s["incomplete"] is True
    # child_crash / child_timeout are a subset of failed — they must NOT inflate total
    assert s["total"] == sum(s[k] for k in RESULT_OUTCOME_KEYS)


def test_merge_preserves_structured_execution_evidence() -> None:
    observation = build_process_observation(
        "probe", "probe", 0, -9, parent_nodeid="security/test.py::test_probe"
    )
    payload = {
        "summary": {"failed": 1},
        "units": [{"target": "security/test.py", "executions": [observation]}],
    }

    merged = merge_results_payloads([payload], coverage=None)

    assert merged["units"][0]["executions"] == [observation]


def test_merge_child_metrics_prefer_structured_execution_evidence() -> None:
    observation = build_process_observation(
        "probe", "probe", 0, 0, parent_nodeid="security/test.py::test_probe"
    )
    payload = {
        "summary": {"failed": 1},
        "units": [
            {
                "target": "security/test.py",
                "tests": [
                    {
                        "outcome": "failed",
                        "longrepr": "old child crashed with signal 11",
                    }
                ],
                "executions": [observation],
            }
        ],
    }

    merged = merge_results_payloads([payload], coverage=None)

    assert merged["summary"]["child_crash"] == 0
    assert merged["summary"]["child_timeout"] == 0


def test_merge_counts_crash_limited_into_total() -> None:
    a = {"summary": {"passed": 5, "crash_limited": 2}, "units": []}
    b = {"summary": {"failed": 1, "crash_limited": 3}, "units": []}
    merged = merge_results_payloads([a, b], coverage=None)
    s = merged["summary"]
    assert s["crash_limited"] == 5
    assert s["total"] == 5 + 1 + 5  # passed + failed + crash_limited


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
    d: Path,
    units: list[dict[str, Any]],
    summary: dict[str, int],
    records: list[dict[str, Any]],
    *,
    provenance: dict[str, Any] | None = None,
    selection: CaseSelection | dict[str, Any] | None = None,
    write_sidecar: bool = True,
) -> None:
    d.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": summary,
        "units": units,
    }
    if provenance is not None:
        payload["provenance"] = provenance
    if selection is not None:
        sel_dict = selection.to_dict() if isinstance(selection, CaseSelection) else selection
        payload["selection"] = sel_dict
        batch_id = (
            selection.batch_id
            if isinstance(selection, CaseSelection)
            else selection.get("batch_id")
        )
        if write_sidecar:
            (d / "selection.json").write_text(
                json.dumps(sel_dict, indent=2) + "\n", encoding="utf-8"
            )
        if batch_id:
            # Mirror the framework writer: synthetic daemon-recovery units are not
            # part of a case batch and never carry a batch identity.
            for u in units:
                if "::daemon-recovery-" in str(u.get("target", "")):
                    continue
                u.setdefault("selection_batch_id", batch_id)
    (d / "results.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )
    (d / "report.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8"
    )


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
    cov = json.loads((out / "coverage.json").read_text(encoding="utf-8"))
    assert set(cov["function_coverage"]["called_names"]) == {"C_Encrypt", "C_Decrypt"}
    assert set(cov["mechanism_coverage"]["invoked_names"]) == {"CKM_AES_CBC", "CKM_AES_GCM"}
    # both available mechanisms were invoked across shards -> none not-invoked
    assert cov["mechanism_coverage"]["not_invoked"] == 0


def test_merge_shard_dirs_preserves_file_skip_quality_accounting(tmp_path: Path) -> None:
    s0 = tmp_path / "shard0"
    _write_shard(
        s0,
        units=[
            {
                "target": "test_cctv_ed25519.py",
                "status": "passed",
                "counts": {
                    "passed": 0,
                    "failed": 0,
                    "skipped": 914,
                    "xfailed": 0,
                    "xpassed": 0,
                    "error": 0,
                    "crashed": 0,
                    "timeout": 0,
                },
                "skip_reasons": {"EDDSA not supported by module": 914},
                "file_skip": True,
            }
        ],
        summary={"passed": 0, "failed": 0, "skipped": 914},
        records=[],
    )

    out = tmp_path / "merged"
    merge_shard_dirs([s0], out)

    quality = json.loads((out / "quality.json").read_text(encoding="utf-8"))
    assert quality["file_skipped_units"] == [
        {"target": "test_cctv_ed25519.py", "reason": "EDDSA not supported by module"}
    ]


def test_merge_shard_dirs_salvages_compliance_notes_from_report_jsonl(
    tmp_path: Path,
) -> None:
    s0 = tmp_path / "shard0"
    s0.mkdir()
    (s0 / "report.jsonl").write_text(
        json.dumps(
            {
                "$report_type": "TestReport",
                "nodeid": "test_mech_encrypt.py::test_encrypt_claim",
                "when": "call",
                "outcome": "passed",
                "duration": 0.1,
                "user_properties": [
                    [
                        "pkcs11_compliance_notes",
                        [
                            {
                                "description": "validation policy accepted",
                                "level": "standard",
                                "reference": "PKCS#11 v3.2",
                                "test_id": "test_encrypt_claim",
                                "nodeid": "test_mech_encrypt.py::test_encrypt_claim",
                            }
                        ],
                    ]
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    out = tmp_path / "merged"
    merge_shard_dirs([s0], out)

    merged = json.loads((out / "results.json").read_text(encoding="utf-8"))
    assert merged["units"][0]["compliance_notes"] == [
        {
            "description": "validation policy accepted",
            "level": "standard",
            "reference": "PKCS#11 v3.2",
            "test_id": "test_encrypt_claim",
            "nodeid": "test_mech_encrypt.py::test_encrypt_claim",
        }
    ]


def test_merge_shard_dirs_promotes_teardown_trace_to_failed_call_report(tmp_path: Path) -> None:
    s0 = tmp_path / "shard0"
    trace = [
        {
            "i": 0,
            "fn": "C_GetSessionInfo",
            "mech": None,
            "rv": 48,
            "rv_name": "CKR_DEVICE_ERROR",
        }
    ]
    _write_shard(
        s0,
        units=[{"target": "a.py", "status": "failed"}],
        summary={"passed": 0, "failed": 1},
        records=[
            {
                "$report_type": "TestReport",
                "nodeid": "a.py::test_failure",
                "when": "call",
                "outcome": "failed",
                "user_properties": [],
            },
            {
                "$report_type": "TestReport",
                "nodeid": "a.py::test_failure",
                "when": "teardown",
                "outcome": "passed",
                "user_properties": [["pkcs11_rv_trace", trace]],
            },
        ],
    )

    out = tmp_path / "merged"
    merge_shard_dirs([s0], out)

    call_report = next(
        record
        for record in (
            json.loads(line)
            for line in (out / "report.jsonl").read_text(encoding="utf-8").splitlines()
        )
        if record.get("$report_type") == "TestReport" and record.get("when") == "call"
    )
    assert dict(call_report["user_properties"])["pkcs11_rv_trace"] == trace


def test_merge_shard_dirs_promotes_subprocess_marker_to_failed_call_report(
    tmp_path: Path,
) -> None:
    s0 = tmp_path / "shard0"
    trace = [
        {
            "i": 0,
            "fn": "C_DigestInit",
            "mech": None,
            "rv": 48,
            "rv_name": "CKR_DEVICE_ERROR",
        }
    ]
    marker = json.dumps(trace, separators=(",", ":"))
    _write_shard(
        s0,
        units=[{"target": "a.py", "status": "failed"}],
        summary={"passed": 0, "failed": 1},
        records=[
            {
                "$report_type": "TestReport",
                "nodeid": "a.py::test_child_failure",
                "when": "call",
                "outcome": "failed",
                "longrepr": {
                    "reprcrash": {
                        "message": (
                            "child failed\n"
                            f"stdout: P11_RV_TRACE_JSON:{marker}\n"
                            "stderr: AssertionError"
                        )
                    }
                },
                "user_properties": [],
            },
        ],
    )

    out = tmp_path / "merged"
    merge_shard_dirs([s0], out)

    call_report = json.loads((out / "report.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert dict(call_report["user_properties"])["pkcs11_rv_trace"] == trace


def test_merge_shard_dirs_replaces_empty_trace_with_subprocess_marker(
    tmp_path: Path,
) -> None:
    s0 = tmp_path / "shard0"
    trace = [
        {
            "i": 0,
            "fn": "C_GenerateKey",
            "mech": 4224,
            "rv": 48,
            "rv_name": "CKR_DEVICE_ERROR",
        }
    ]
    marker = json.dumps(trace, separators=(",", ":"))
    _write_shard(
        s0,
        units=[{"target": "a.py", "status": "failed"}],
        summary={"passed": 0, "failed": 1},
        records=[
            {
                "$report_type": "TestReport",
                "nodeid": "a.py::test_child_failure",
                "when": "call",
                "outcome": "failed",
                "longrepr": {
                    "reprcrash": {
                        "message": (
                            "child failed\n"
                            f"stdout: P11_RV_TRACE_JSON:{marker}\n"
                            "stderr: AssertionError"
                        )
                    }
                },
                "user_properties": [["pkcs11_rv_trace", []]],
            },
        ],
    )

    out = tmp_path / "merged"
    merge_shard_dirs([s0], out)

    call_report = json.loads((out / "report.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert dict(call_report["user_properties"])["pkcs11_rv_trace"] == trace


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
    cov = json.loads((out / "coverage.json").read_text(encoding="utf-8"))
    assert set(cov["function_coverage"]["called_names"]) == {"C_Encrypt", "C_Sign"}


def _make_selection(
    source: str,
    nodeids: list[str],
    *,
    plan_id: str = "a" * 64,
    source_collection_count: int | None = None,
    source_collection_sha256: str = "b" * 64,
) -> CaseSelection:
    nodeids_tuple = tuple(nodeids)
    count = source_collection_count if source_collection_count is not None else len(nodeids_tuple)
    batch_id = compute_batch_id(
        source=source,
        source_collection_count=count,
        source_collection_sha256=source_collection_sha256,
        nodeids=nodeids_tuple,
    )
    return CaseSelection(
        schema=1,
        plan_id=plan_id,
        batch_id=batch_id,
        source=source,
        source_collection_count=count,
        source_collection_sha256=source_collection_sha256,
        nodeids=nodeids_tuple,
    )


def test_merge_shard_dirs_ordinary_and_selected_batches_from_same_source(tmp_path: Path) -> None:
    source = "wycheproof/test_wycheproof_ecdsa.py"
    prov = {"framework_version": "0.1.9", "module_version": "3.2"}

    # Ordinary shard: test_encrypt.py
    s0 = tmp_path / "shard0"
    _write_shard(
        s0,
        units=[{"target": "test_encrypt.py", "status": "passed"}],
        summary={"passed": 5},
        records=[_testreport(f"test_encrypt.py::test_{i}", "passed") for i in range(5)],
        provenance=prov,
    )

    # Selected batch 1: ecdsa case1, case2
    sel1 = _make_selection(
        source,
        [f"{source}::test_verify[case1]", f"{source}::test_verify[case2]"],
        plan_id="1" * 64,
        source_collection_count=4,
    )
    s1 = tmp_path / "shard1"
    _write_shard(
        s1,
        units=[{"target": source, "status": "passed"}],
        summary={"passed": 2},
        records=[
            _testreport(f"{source}::test_verify[case1]", "passed"),
            _testreport(f"{source}::test_verify[case2]", "passed"),
        ],
        provenance=prov,
        selection=sel1,
    )

    # Selected batch 2: ecdsa case3, case4
    sel2 = _make_selection(
        source,
        [f"{source}::test_verify[case3]", f"{source}::test_verify[case4]"],
        plan_id="1" * 64,
        source_collection_count=4,
    )
    s2 = tmp_path / "shard2"
    _write_shard(
        s2,
        units=[{"target": source, "status": "passed"}],
        summary={"passed": 2},
        records=[
            _testreport(f"{source}::test_verify[case3]", "passed"),
            _testreport(f"{source}::test_verify[case4]", "passed"),
        ],
        provenance=prov,
        selection=sel2,
    )

    out = tmp_path / "merged"
    merged = merge_shard_dirs([s0, s1, s2], out)

    # Summary summed
    assert merged["summary"]["passed"] == 9
    assert merged["summary"]["total"] == 9

    # Common provenance unchanged
    assert merged["provenance"] == prov

    # Distinct unit batch identities preserved
    assert len(merged["units"]) == 3
    ord_unit = next(u for u in merged["units"] if u["target"] == "test_encrypt.py")
    assert "selection_batch_id" not in ord_unit

    ecdsa_units = [u for u in merged["units"] if u["target"] == source]
    assert len(ecdsa_units) == 2
    assert {u["selection_batch_id"] for u in ecdsa_units} == {sel1.batch_id, sel2.batch_id}
    assert sel1.batch_id != sel2.batch_id

    # Raw records preserved without deduplication
    merged_lines = [
        line.strip()
        for line in (out / "report.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(merged_lines) == 9


def test_merge_shard_dirs_rejects_conflicting_plan_ids(tmp_path: Path) -> None:
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel1 = _make_selection(
        source,
        [f"{source}::test_verify[case1]"],
        plan_id="1" * 64,
        source_collection_count=2,
    )
    sel2 = _make_selection(
        source,
        [f"{source}::test_verify[case2]"],
        plan_id="2" * 64,
        source_collection_count=2,
    )
    s1 = tmp_path / "shard1"
    _write_shard(
        s1,
        units=[{"target": source, "status": "passed"}],
        summary={"passed": 1},
        records=[_testreport(f"{source}::test_verify[case1]", "passed")],
        selection=sel1,
    )
    s2 = tmp_path / "shard2"
    _write_shard(
        s2,
        units=[{"target": source, "status": "passed"}],
        summary={"passed": 1},
        records=[_testreport(f"{source}::test_verify[case2]", "passed")],
        selection=sel2,
    )

    out = tmp_path / "merged"
    with pytest.raises(ValueError, match="conflicting selection plan IDs"):
        merge_shard_dirs([s1, s2], out)


def test_merge_shard_dirs_rejects_duplicate_batch_ids(tmp_path: Path) -> None:
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel = _make_selection(
        source,
        [f"{source}::test_verify[case1]"],
        plan_id="1" * 64,
        source_collection_count=2,
    )
    s1 = tmp_path / "shard1"
    _write_shard(
        s1,
        units=[{"target": source, "status": "passed"}],
        summary={"passed": 1},
        records=[_testreport(f"{source}::test_verify[case1]", "passed")],
        selection=sel,
    )
    s2 = tmp_path / "shard2"
    _write_shard(
        s2,
        units=[{"target": source, "status": "passed"}],
        summary={"passed": 1},
        records=[_testreport(f"{source}::test_verify[case1]", "passed")],
        selection=sel,
    )

    out = tmp_path / "merged"
    with pytest.raises(ValueError, match="duplicate selection batch ID"):
        merge_shard_dirs([s1, s2], out)


def test_merge_shard_dirs_rejects_overlapping_nodeids(tmp_path: Path) -> None:
    source = "wycheproof/test_wycheproof_ecdsa.py"
    # Overlapping node: case2 is in both batches, but batches have distinct other nodes
    sel1 = _make_selection(
        source,
        [f"{source}::test_verify[case1]", f"{source}::test_verify[case2]"],
        plan_id="1" * 64,
        source_collection_count=3,
    )
    sel2 = _make_selection(
        source,
        [f"{source}::test_verify[case2]", f"{source}::test_verify[case3]"],
        plan_id="1" * 64,
        source_collection_count=3,
    )
    assert sel1.batch_id != sel2.batch_id

    s1 = tmp_path / "shard1"
    _write_shard(
        s1,
        units=[{"target": source, "status": "passed"}],
        summary={"passed": 2},
        records=[
            _testreport(f"{source}::test_verify[case1]", "passed"),
            _testreport(f"{source}::test_verify[case2]", "passed"),
        ],
        selection=sel1,
    )
    s2 = tmp_path / "shard2"
    _write_shard(
        s2,
        units=[{"target": source, "status": "passed"}],
        summary={"passed": 2},
        records=[
            _testreport(f"{source}::test_verify[case2]", "passed"),
            _testreport(f"{source}::test_verify[case3]", "passed"),
        ],
        selection=sel2,
    )

    out = tmp_path / "merged"
    with pytest.raises(ValueError, match="overlapping execution coverage"):
        merge_shard_dirs([s1, s2], out)


def test_merge_shard_dirs_rejects_selection_result_mismatch(tmp_path: Path) -> None:
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel_sidecar = _make_selection(
        source,
        [f"{source}::test_verify[case1]"],
        plan_id="1" * 64,
        source_collection_count=2,
    )
    sel_results = _make_selection(
        source,
        [f"{source}::test_verify[case2]"],
        plan_id="1" * 64,
        source_collection_count=2,
    )
    s0 = tmp_path / "shard0"
    _write_shard(
        s0,
        units=[{"target": source, "status": "passed"}],
        summary={"passed": 1},
        records=[_testreport(f"{source}::test_verify[case1]", "passed")],
        selection=sel_results,
        write_sidecar=False,
    )
    # Write different sidecar
    (s0 / "selection.json").write_text(
        json.dumps(sel_sidecar.to_dict(), indent=2) + "\n", encoding="utf-8"
    )

    out = tmp_path / "merged"
    with pytest.raises(
        ValueError, match="selection mismatch between results.json and selection.json"
    ):
        merge_shard_dirs([s0], out)


def test_merge_shard_dirs_rejects_unit_batch_id_mismatch(tmp_path: Path) -> None:
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel = _make_selection(
        source,
        [f"{source}::test_verify[case1]"],
        plan_id="1" * 64,
        source_collection_count=2,
    )
    s0 = tmp_path / "shard0"
    _write_shard(
        s0,
        units=[{"target": source, "status": "passed", "selection_batch_id": "9" * 64}],
        summary={"passed": 1},
        records=[_testreport(f"{source}::test_verify[case1]", "passed")],
        selection=sel,
    )

    out = tmp_path / "merged"
    with pytest.raises(ValueError, match="unit selection_batch_id .* does not match"):
        merge_shard_dirs([s0], out)


def test_merge_shard_dirs_rejects_malformed_selection_sidecar(tmp_path: Path) -> None:
    s0 = tmp_path / "shard0"
    s0.mkdir()
    (s0 / "selection.json").write_text('{"schema": 999}', encoding="utf-8")
    (s0 / "results.json").write_text('{"tool": "pkcs11-check", "units": []}', encoding="utf-8")
    (s0 / "report.jsonl").write_text("", encoding="utf-8")

    out = tmp_path / "merged"
    with pytest.raises(ValueError):
        merge_shard_dirs([s0], out)


def test_merge_shard_dirs_aborts_without_replacing_output_on_invalid_selection(
    tmp_path: Path,
) -> None:
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel1 = _make_selection(
        source,
        [f"{source}::test_verify[case1]"],
        plan_id="1" * 64,
        source_collection_count=2,
    )
    sel2 = _make_selection(
        source,
        [f"{source}::test_verify[case2]"],
        plan_id="2" * 64,  # Conflicting plan ID!
        source_collection_count=2,
    )
    s1 = tmp_path / "shard1"
    _write_shard(
        s1,
        units=[{"target": source, "status": "passed"}],
        summary={"passed": 1},
        records=[_testreport(f"{source}::test_verify[case1]", "passed")],
        selection=sel1,
    )
    s2 = tmp_path / "shard2"
    _write_shard(
        s2,
        units=[{"target": source, "status": "passed"}],
        summary={"passed": 1},
        records=[_testreport(f"{source}::test_verify[case2]", "passed")],
        selection=sel2,
    )

    out = tmp_path / "merged"
    out.mkdir()
    sentinel_report = "INITIAL_REPORT_PRESERVED\n"
    sentinel_results = "INITIAL_RESULTS_PRESERVED\n"
    (out / "report.jsonl").write_text(sentinel_report, encoding="utf-8")
    (out / "results.json").write_text(sentinel_results, encoding="utf-8")

    with pytest.raises(ValueError, match="conflicting selection plan IDs"):
        merge_shard_dirs([s1, s2], out)

    # Existing outputs must be completely untouched
    assert (out / "report.jsonl").read_text(encoding="utf-8") == sentinel_report
    assert (out / "results.json").read_text(encoding="utf-8") == sentinel_results


def test_merge_results_payloads_selection_validation() -> None:
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel1 = _make_selection(
        source,
        [f"{source}::test_verify[c1]"],
        plan_id="1" * 64,
        source_collection_count=2,
    )
    sel2_conflict_plan = _make_selection(
        source,
        [f"{source}::test_verify[c2]"],
        plan_id="2" * 64,
        source_collection_count=2,
    )
    p1 = {
        "summary": {"passed": 1},
        "units": [{"target": source, "selection_batch_id": sel1.batch_id}],
        "selection": sel1.to_dict(),
    }
    p2 = {
        "summary": {"passed": 1},
        "units": [
            {
                "target": source,
                "selection_batch_id": sel2_conflict_plan.batch_id,
            }
        ],
        "selection": sel2_conflict_plan.to_dict(),
    }
    with pytest.raises(ValueError, match="conflicting selection plan IDs"):
        merge_results_payloads([p1, p2], coverage=None)


def test_merge_shard_dirs_intact_payload_is_its_own_batch_proof(tmp_path: Path) -> None:
    """State (a): results.json carries its own selection block matching the sidecar.

    This is the normal selected run: the framework emitted the block because
    ``--selection-manifest`` was honored, so membership is proven by the payload
    itself and nothing is recovered from the sidecar.
    """
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel = _make_selection(
        source,
        [f"{source}::test_verify[case1]", f"{source}::test_verify[case2]"],
        plan_id="1" * 64,
        source_collection_count=4,
    )
    s0 = tmp_path / "shard0"
    _write_shard(
        s0,
        units=[{"target": source, "status": "passed"}],
        summary={"passed": 2},
        records=[
            _testreport(f"{source}::test_verify[case1]", "passed"),
            _testreport(f"{source}::test_verify[case2]", "passed"),
        ],
        selection=sel,
    )

    out = tmp_path / "merged"
    merged = merge_shard_dirs([s0], out)

    assert merged["summary"]["passed"] == 2
    assert merged["units"][0]["selection_batch_id"] == sel.batch_id
    assert merged["summary"]["incomplete"] is False
    assert "warnings" not in merged.get("shards", {})


def test_merge_shard_dirs_rejects_intact_payload_missing_selection_block(tmp_path: Path) -> None:
    """State (b) at the merge entry point: abort before replacing any output."""
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel = _make_selection(
        source,
        [f"{source}::test_verify[case1]"],
        plan_id="1" * 64,
        source_collection_count=4,
    )
    s0 = tmp_path / "shard0"
    _write_shard(
        s0,
        units=[{"target": source, "status": "passed"}],
        summary={"passed": 1},
        records=[_testreport(f"{source}::test_verify[case1]", "passed")],
    )
    # The sidecar says a batch was assigned, but results.json never recorded one.
    (s0 / "selection.json").write_text(json.dumps(sel.to_dict(), indent=2) + "\n", encoding="utf-8")

    out = tmp_path / "merged"
    out.mkdir()
    sentinel = "sentinel\n"
    (out / "results.json").write_text(sentinel, encoding="utf-8")

    with pytest.raises(ValueError, match="no selection block"):
        merge_shard_dirs([s0], out)

    assert (out / "results.json").read_text(encoding="utf-8") == sentinel
    assert not (out / "report.jsonl").exists()


def test_merge_shard_dirs_leaves_daemon_recovery_units_unstamped(tmp_path: Path) -> None:
    """A ``::daemon-recovery-`` unit is never part of a case batch (sidecar path).

    Those synthetic units stand for a confirmed daemon death, not a collected
    test case, so no stamping path may annotate them with a batch identity.
    """
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel = _make_selection(
        source,
        [f"{source}::test_verify[case1]"],
        plan_id="1" * 64,
        source_collection_count=4,
    )
    s0 = tmp_path / "shard0"
    _write_shard(
        s0,
        units=[
            {"target": source, "status": "passed"},
            {"target": f"{source}::daemon-recovery-1", "status": "crashed", "returncode": 1},
        ],
        summary={"passed": 1, "crashed": 1},
        records=[_testreport(f"{source}::test_verify[case1]", "passed")],
        selection=sel,
    )

    merged = merge_shard_dirs([s0], tmp_path / "merged")

    real_unit = next(u for u in merged["units"] if u["target"] == source)
    recovery_unit = next(u for u in merged["units"] if u["target"].endswith("daemon-recovery-1"))
    assert real_unit["selection_batch_id"] == sel.batch_id
    assert "selection_batch_id" not in recovery_unit


def test_merge_shard_dirs_daemon_recovery_unstamped_without_sidecar(tmp_path: Path) -> None:
    """Same rule on the results.json-only stamping path (no sidecar present)."""
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel = _make_selection(
        source,
        [f"{source}::test_verify[case1]"],
        plan_id="1" * 64,
        source_collection_count=4,
    )
    s0 = tmp_path / "shard0"
    _write_shard(
        s0,
        units=[
            {"target": source, "status": "passed"},
            {"target": f"{source}::daemon-recovery-2", "status": "crashed", "returncode": 1},
        ],
        summary={"passed": 1, "crashed": 1},
        records=[_testreport(f"{source}::test_verify[case1]", "passed")],
        selection=sel,
        write_sidecar=False,
    )

    merged = merge_shard_dirs([s0], tmp_path / "merged")

    recovery_unit = next(u for u in merged["units"] if u["target"].endswith("daemon-recovery-2"))
    assert "selection_batch_id" not in recovery_unit
    assert (
        next(u for u in merged["units"] if u["target"] == source)["selection_batch_id"]
        == sel.batch_id
    )


def test_merge_results_payloads_leaves_daemon_recovery_units_unstamped() -> None:
    """Same rule on the cross-shard validation path (``_validate_selection_payloads``)."""
    source = "wycheproof/test_wycheproof_ecdsa.py"
    sel = _make_selection(
        source,
        [f"{source}::test_verify[c1]"],
        plan_id="1" * 64,
        source_collection_count=2,
    )
    payload = {
        "summary": {"passed": 1},
        "units": [
            {"target": source, "status": "passed"},
            {"target": f"{source}::daemon-recovery-1", "status": "crashed", "returncode": 1},
        ],
        "selection": sel.to_dict(),
    }

    merged = merge_results_payloads([payload], coverage=None)

    real_unit = next(u for u in merged["units"] if u["target"] == source)
    recovery_unit = next(u for u in merged["units"] if u["target"].endswith("daemon-recovery-1"))
    assert real_unit["selection_batch_id"] == sel.batch_id
    assert "selection_batch_id" not in recovery_unit
