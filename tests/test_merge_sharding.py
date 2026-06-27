"""Tests for multi-shard sharding (LPT) and artifact merge."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pkcs11_check.core.merge import merge_results_payloads, merge_shard_dirs
from pkcs11_check.core.run_metrics import RESULT_OUTCOME_KEYS
from pkcs11_check.core.sharding import (
    duration_by_unit_from_results,
    estimate_shard_load,
    plan_shards,
)

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

    quality = json.loads((out / "quality.json").read_text())
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
        + "\n"
    )

    out = tmp_path / "merged"
    merge_shard_dirs([s0], out)

    merged = json.loads((out / "results.json").read_text())
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
        for record in (json.loads(line) for line in (out / "report.jsonl").read_text().splitlines())
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

    call_report = json.loads((out / "report.jsonl").read_text().splitlines()[0])
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

    call_report = json.loads((out / "report.jsonl").read_text().splitlines()[0])
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
    cov = json.loads((out / "coverage.json").read_text())
    assert set(cov["function_coverage"]["called_names"]) == {"C_Encrypt", "C_Sign"}
