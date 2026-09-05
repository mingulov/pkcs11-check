"""Tests for production disabled-baseline loading and planning."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkcs11_check.core import test_selection as test_selection_mod
from pkcs11_check.core.collection import CollectedPytestItem
from pkcs11_check.core.test_selection import (
    DisabledBaseline,
    DisabledCandidateReviewRecord,
    DisabledSelectionPlan,
    build_disabled_selection_plan,
    collect_disabled_candidate_review_records,
    collect_disabled_candidates,
    extract_required_mechanisms,
    load_disabled_baseline,
    parse_disabled_nodeids,
    write_deselect_file,
)


def test_parse_disabled_nodeids_ignores_comments_blanks_and_duplicates() -> None:
    text = """
    # comment
    src/pkcs11_check/testcases/test_encrypt.py::test_roundtrip

    src/pkcs11_check/testcases/test_encrypt.py::test_roundtrip
    src/pkcs11_check/testcases/acvp/aes/test_cfb.py::test_acvp_aes_cfb[AES-enc-tc1021]
    """.strip()

    nodeids = parse_disabled_nodeids(text)

    assert nodeids == [
        "src/pkcs11_check/testcases/test_encrypt.py::test_roundtrip",
        "src/pkcs11_check/testcases/acvp/aes/test_cfb.py::test_acvp_aes_cfb[AES-enc-tc1021]",
    ]


def test_load_disabled_baseline_returns_none_for_none_path() -> None:
    assert load_disabled_baseline(None) is None


def test_load_disabled_baseline_raises_for_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="disabled"):
        load_disabled_baseline(tmp_path / "missing.txt")


def test_load_disabled_baseline_fingerprint_changes_with_content(tmp_path: Path) -> None:
    path = tmp_path / "disabled.txt"
    path.write_text("a.py::test_one\n", encoding="utf-8")

    first = load_disabled_baseline(path)
    assert isinstance(first, DisabledBaseline)

    path.write_text("a.py::test_one\nb.py::test_two\n", encoding="utf-8")
    second = load_disabled_baseline(path)
    assert isinstance(second, DisabledBaseline)

    assert first.fingerprint != second.fingerprint


def test_write_deselect_file_removes_temp_when_write_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Path] = {}
    real_mkstemp = test_selection_mod.tempfile.mkstemp
    real_write_text = Path.write_text

    def observing_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        fd, raw_path = real_mkstemp(*args, **kwargs)
        observed["path"] = Path(raw_path)
        return fd, raw_path

    def fail_write(self: Path, *args: object, **kwargs: object) -> int:
        if self == observed["path"]:
            raise RuntimeError("deselect write failed")
        return real_write_text(self, *args, **kwargs)

    monkeypatch.setattr(test_selection_mod.tempfile, "mkstemp", observing_mkstemp)
    monkeypatch.setattr(Path, "write_text", fail_write)

    with pytest.raises(RuntimeError, match="deselect write failed"):
        write_deselect_file(["test_demo.py::test_disabled"])

    assert not observed["path"].exists()


def test_build_disabled_selection_plan_drops_disabled_test_units(tmp_path: Path) -> None:
    unit_a = f"{tmp_path / 'test_demo.py'}::test_a"
    unit_b = f"{tmp_path / 'test_demo.py'}::test_b"

    plan = build_disabled_selection_plan(
        units=[unit_a, unit_b],
        disabled_nodeids={unit_b},
        baseline_fingerprint="fp-1",
        collected_items=None,
    )

    assert isinstance(plan, DisabledSelectionPlan)
    assert plan.units == [unit_a]
    assert plan.deselect_by_file == {}
    assert plan.baseline_fingerprint == "fp-1"


def test_build_disabled_selection_plan_drops_fully_disabled_file_units(tmp_path: Path) -> None:
    file_path = tmp_path / "test_demo.py"
    unit = str(file_path)
    items = [
        CollectedPytestItem(nodeid=f"{unit}::test_a", file_path=str(file_path), markers=[]),
        CollectedPytestItem(nodeid=f"{unit}::test_b", file_path=str(file_path), markers=[]),
    ]

    plan = build_disabled_selection_plan(
        units=[unit],
        disabled_nodeids={f"{unit}::test_a", f"{unit}::test_b"},
        baseline_fingerprint="fp-2",
        collected_items=items,
    )

    assert plan.units == []
    assert plan.deselect_by_file == {}


def test_build_disabled_selection_plan_retains_mixed_file_units_with_deselects(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "test_demo.py"
    unit = str(file_path)
    items = [
        CollectedPytestItem(nodeid=f"{unit}::test_a", file_path=str(file_path), markers=[]),
        CollectedPytestItem(nodeid=f"{unit}::test_b", file_path=str(file_path), markers=[]),
    ]

    plan = build_disabled_selection_plan(
        units=[unit],
        disabled_nodeids={f"{unit}::test_b"},
        baseline_fingerprint="fp-3",
        collected_items=items,
    )

    assert plan.units == [unit]
    # Keys are scheduling units (native paths, handed back to the runner as-is); VALUES are
    # node-ids, which the plan emits in canonical forward-slash form so they compare equal
    # against a disabled-tests file written on any platform. Both sides of the eventual
    # match are normalized in plugin.py, so the canonical form is what belongs here.
    assert plan.deselect_by_file == {unit: {f"{file_path.as_posix()}::test_b"}}


def test_build_disabled_selection_plan_matches_windows_written_nodeids(tmp_path: Path) -> None:
    """A disabled-tests file written on Windows must still match, whatever the host.

    Every comparison inside the plan happens in normalized (forward-slash) space, but the
    incoming ``disabled_nodeids`` used to be trusted as already-normalized -- true only
    because the one production caller happened to run them through
    ``parse_disabled_nodeids`` first. That made it an invisible precondition: any new source
    of disabled node-ids (a resume state file, a manifest, a new flag) would match NOTHING
    on Windows and silently run tests the operator had disabled.

    Backslash node-ids are fed in deliberately here so the assertion holds on POSIX too,
    rather than only failing on a Windows runner.
    """
    file_path = tmp_path / "test_demo.py"
    unit = str(file_path)
    items = [
        CollectedPytestItem(nodeid=f"{unit}::test_a", file_path=unit, markers=[]),
        CollectedPytestItem(nodeid=f"{unit}::test_b", file_path=unit, markers=[]),
    ]
    windows_style = f"{file_path.as_posix().replace('/', chr(92))}::test_b"

    plan = build_disabled_selection_plan(
        units=[unit],
        disabled_nodeids={windows_style},
        baseline_fingerprint="fp-win",
        collected_items=items,
    )

    assert plan.deselect_by_file == {unit: {f"{file_path.as_posix()}::test_b"}}


def test_build_disabled_selection_plan_rebuilds_from_saved_units(tmp_path: Path) -> None:
    file_path = tmp_path / "test_demo.py"
    file_unit = str(file_path)
    test_unit = f"{tmp_path / 'test_other.py'}::test_live"
    items = [
        CollectedPytestItem(nodeid=f"{file_unit}::test_a", file_path=str(file_path), markers=[]),
        CollectedPytestItem(nodeid=f"{file_unit}::test_b", file_path=str(file_path), markers=[]),
    ]
    saved_units = [file_unit, test_unit]

    first = build_disabled_selection_plan(
        units=saved_units,
        disabled_nodeids={f"{file_unit}::test_b"},
        baseline_fingerprint="fp-4",
        collected_items=items,
    )
    second = build_disabled_selection_plan(
        units=saved_units,
        disabled_nodeids={f"{file_unit}::test_b"},
        baseline_fingerprint="fp-4",
        collected_items=items,
    )

    assert first == second
    assert first.units == saved_units
    # Node-id values are canonical (forward-slash); the unit key stays native. See the
    # comment in test_build_disabled_selection_plan_retains_mixed_file_units_with_deselects.
    assert first.deselect_by_file == {file_unit: {f"{file_path.as_posix()}::test_b"}}


def test_collect_disabled_candidates_from_report_jsonl_supports_multiple_outcomes(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir()
    report_path = artifact_dir / "report.jsonl"
    report_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_demo.py::test_failed",
                        "when": "call",
                        "outcome": "failed",
                    }
                ),
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_demo.py::test_skipped",
                        "when": "call",
                        "outcome": "skipped",
                    }
                ),
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_demo.py::test_xfailed",
                        "when": "call",
                        "outcome": "skipped",
                        "wasxfail": "known bug",
                    }
                ),
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_demo.py::test_passed",
                        "when": "call",
                        "outcome": "passed",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    candidates, manual = collect_disabled_candidates(
        [artifact_dir],
        outcomes={"failed", "skipped", "xfailed"},
    )

    assert candidates == [
        "test_demo.py::test_failed",
        "test_demo.py::test_skipped",
        "test_demo.py::test_xfailed",
    ]
    assert manual == []


def test_collect_disabled_candidates_streams_report_jsonl(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir()
    (artifact_dir / "report.jsonl").write_text(
        json.dumps(
            {
                "$report_type": "TestReport",
                "nodeid": "test_demo.py::test_failed",
                "when": "call",
                "outcome": "failed",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    def _load_all_forbidden(_path: Path) -> list[dict[str, object]]:
        pytest.fail("collect_disabled_candidates must stream report.jsonl")

    monkeypatch.setattr(test_selection_mod, "_load_report_log_records", _load_all_forbidden)

    candidates, manual = collect_disabled_candidates([artifact_dir], outcomes={"failed"})

    assert candidates == ["test_demo.py::test_failed"]
    assert manual == []


def test_collect_disabled_candidates_preserves_parametrized_nodeids_sorted(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir()
    (artifact_dir / "report.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_vectors.py::test_case[param-b]",
                        "when": "call",
                        "outcome": "failed",
                    }
                ),
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_vectors.py::test_case[param-a]",
                        "when": "call",
                        "outcome": "failed",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    candidates, manual = collect_disabled_candidates([artifact_dir], outcomes={"failed"})

    assert candidates == [
        "test_vectors.py::test_case[param-a]",
        "test_vectors.py::test_case[param-b]",
    ]
    assert manual == []


def test_collect_disabled_candidates_recovers_crash_culprit_from_results_json(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir()
    (artifact_dir / "report.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_a.py::test_done",
                        "when": "setup",
                        "outcome": "passed",
                    }
                ),
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_a.py::test_done",
                        "when": "call",
                        "outcome": "passed",
                    }
                ),
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_a.py::test_done",
                        "when": "teardown",
                        "outcome": "passed",
                    }
                ),
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_a.py::test_culprit",
                        "when": "setup",
                        "outcome": "passed",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (artifact_dir / "results.json").write_text(
        json.dumps(
            {
                "units": [
                    {
                        "target": "test_a.py",
                        "status": "crashed",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    candidates, manual = collect_disabled_candidates([artifact_dir], outcomes={"crashed"})

    assert candidates == ["test_a.py::test_culprit"]
    assert manual == []


def test_collect_disabled_candidates_reports_manual_review_when_culprit_missing(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir()
    (artifact_dir / "report.jsonl").write_text("", encoding="utf-8")
    (artifact_dir / "results.json").write_text(
        json.dumps(
            {
                "units": [
                    {
                        "target": "test_a.py",
                        "status": "timeout",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    candidates, manual = collect_disabled_candidates([artifact_dir], outcomes={"timeout"})

    assert candidates == []
    assert len(manual) == 1
    assert "manual review" in manual[0]


def test_collect_disabled_candidates_reads_explicit_crash_and_timeout_tests_from_results_json(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir()
    (artifact_dir / "results.json").write_text(
        json.dumps(
            {
                "units": [
                    {
                        "target": "test_a.py",
                        "status": "failed",
                        "tests": [
                            {
                                "nodeid": "test_a.py::test_crashed",
                                "outcome": "crashed",
                            },
                            {
                                "nodeid": "test_a.py::test_timed_out",
                                "outcome": "timeout",
                            },
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    candidates, manual = collect_disabled_candidates(
        [artifact_dir],
        outcomes={"crashed", "timeout"},
    )

    assert candidates == [
        "test_a.py::test_crashed",
        "test_a.py::test_timed_out",
    ]
    assert manual == []


def test_collect_disabled_candidate_review_records_include_sources_and_inference(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir()
    (artifact_dir / "report.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_a.py::test_failed",
                        "when": "call",
                        "outcome": "failed",
                    }
                ),
                json.dumps(
                    {
                        "$report_type": "TestReport",
                        "nodeid": "test_a.py::test_crash",
                        "when": "setup",
                        "outcome": "passed",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (artifact_dir / "results.json").write_text(
        json.dumps(
            {
                "units": [
                    {
                        "target": "test_a.py",
                        "status": "crashed",
                        "tests": [
                            {
                                "nodeid": "test_a.py::test_timeout",
                                "outcome": "timeout",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    records, manual = collect_disabled_candidate_review_records(
        [artifact_dir],
        outcomes={"failed", "crashed", "timeout"},
    )

    assert manual == []
    assert records == [
        DisabledCandidateReviewRecord(
            artifact_dir=str(artifact_dir),
            nodeid="test_a.py::test_crash",
            outcome="crashed",
            file_target="test_a.py",
            unit_target="test_a.py",
            unit_status="crashed",
            discovery_mode="inferred",
            sources=("results.status+report.jsonl",),
        ),
        DisabledCandidateReviewRecord(
            artifact_dir=str(artifact_dir),
            nodeid="test_a.py::test_failed",
            outcome="failed",
            file_target="test_a.py",
            unit_target="test_a.py",
            unit_status=None,
            discovery_mode="explicit",
            sources=("report.jsonl",),
        ),
        DisabledCandidateReviewRecord(
            artifact_dir=str(artifact_dir),
            nodeid="test_a.py::test_timeout",
            outcome="timeout",
            file_target="test_a.py",
            unit_target="test_a.py",
            unit_status="crashed",
            discovery_mode="explicit",
            sources=("results.tests",),
        ),
    ]


def test_extract_required_mechanisms_single(tmp_path: Path) -> None:
    f = tmp_path / "test_example.py"
    f.write_text('REQUIRED_MECHANISMS = ["AES_CCM"]\n', encoding="utf-8")
    assert extract_required_mechanisms(str(f)) == ["AES_CCM"]


def test_extract_required_mechanisms_multiple(tmp_path: Path) -> None:
    f = tmp_path / "test_example.py"
    f.write_text('REQUIRED_MECHANISMS = ["AES_KEY_WRAP", "AES_KEY_WRAP_KWP"]\n', encoding="utf-8")
    assert extract_required_mechanisms(str(f)) == ["AES_KEY_WRAP", "AES_KEY_WRAP_KWP"]


def test_extract_required_mechanisms_absent(tmp_path: Path) -> None:
    f = tmp_path / "test_example.py"
    f.write_text("pytestmark = [pytest.mark.kat]\n", encoding="utf-8")
    assert extract_required_mechanisms(str(f)) is None


def test_extract_required_mechanisms_empty_list(tmp_path: Path) -> None:
    f = tmp_path / "test_example.py"
    f.write_text("REQUIRED_MECHANISMS = []\n", encoding="utf-8")
    assert extract_required_mechanisms(str(f)) is None


def test_cctv_ed25519_declares_required_mechanism() -> None:
    assert extract_required_mechanisms("src/pkcs11_check/testcases/test_cctv_ed25519.py") == [
        "EDDSA"
    ]


def test_cctv_mldsa_declares_required_mechanisms() -> None:
    assert extract_required_mechanisms("src/pkcs11_check/testcases/test_cctv_mldsa.py") == [
        "ML_DSA",
        "ML_DSA_KEY_PAIR_GEN",
    ]


# ---------------------------------------------------------------------------
# Exact case batching tests (Schema 1 selection manifest)
# ---------------------------------------------------------------------------


def test_case_selection_valid_manifest_and_canonical_json(tmp_path: Path) -> None:
    from pkcs11_check.core.test_selection import (
        CaseSelection,
        compute_batch_id,
        compute_collection_sha256,
        get_testcases_root,
        load_case_selection,
    )

    root = get_testcases_root()
    # Find a real test file in testcases root
    target_rel = "test_encrypt.py"
    assert (root / target_rel).is_file()

    nodeids = [
        f"{target_rel}::test_roundtrip",
        f"{target_rel}::test_param[unicode-✓-ü-🔥]",
        f"{target_rel}::test_param[with spaces and brackets [x]]",
        r"test_encrypt.py::test_param[with\backslash]",
    ]
    col_sha = compute_collection_sha256(nodeids)
    batch_id = compute_batch_id(
        source=target_rel,
        source_collection_count=len(nodeids),
        source_collection_sha256=col_sha,
        nodeids=nodeids,
    )
    plan_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    manifest_data = {
        "schema": 1,
        "plan_id": plan_id,
        "batch_id": batch_id,
        "source": target_rel,
        "source_collection_count": len(nodeids),
        "source_collection_sha256": col_sha,
        "nodeids": nodeids,
    }
    manifest_file = tmp_path / "selection.json"
    manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

    sel = load_case_selection(manifest_file)
    assert isinstance(sel, CaseSelection)
    assert sel.schema == 1
    assert sel.plan_id == plan_id
    assert sel.batch_id == batch_id
    assert sel.source == target_rel
    assert sel.source_collection_count == len(nodeids)
    assert sel.source_collection_sha256 == col_sha
    assert sel.nodeids == tuple(nodeids)

    # Check canonical JSON preserves suffix and formatting
    canonical = sel.canonical_json()
    roundtrip = json.loads(canonical)
    assert roundtrip["nodeids"] == nodeids
    assert roundtrip["batch_id"] == batch_id


def test_case_selection_rejects_missing_file(tmp_path: Path) -> None:
    from pkcs11_check.core.test_selection import load_case_selection

    with pytest.raises(FileNotFoundError):
        load_case_selection(tmp_path / "nonexistent.json")


def test_case_selection_rejects_non_json(tmp_path: Path) -> None:
    from pkcs11_check.core.test_selection import load_case_selection

    bad_file = tmp_path / "bad.json"
    bad_file.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON"):
        load_case_selection(bad_file)


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda d: d.update({"extra": 123}), "unknown keys"),
        (lambda d: d.pop("schema"), "missing required keys"),
        (lambda d: d.pop("plan_id"), "missing required keys"),
        (lambda d: d.pop("batch_id"), "missing required keys"),
        (lambda d: d.pop("source"), "missing required keys"),
        (lambda d: d.pop("source_collection_count"), "missing required keys"),
        (lambda d: d.pop("source_collection_sha256"), "missing required keys"),
        (lambda d: d.pop("nodeids"), "missing required keys"),
        (lambda d: d.update({"schema": 2}), "schema version"),
        (lambda d: d.update({"schema": "1"}), "schema"),
        (lambda d: d.update({"schema": True}), "schema"),
        (lambda d: d.update({"plan_id": "not-64-chars"}), "plan_id"),
        (lambda d: d.update({"plan_id": "G" * 64}), "plan_id"),
        (lambda d: d.update({"batch_id": "0" * 64}), "batch_id mismatch"),
        (lambda d: d.update({"source_collection_sha256": "invalid"}), "source_collection_sha256"),
        (lambda d: d.update({"source_collection_count": 0}), "source_collection_count"),
        (lambda d: d.update({"source_collection_count": -5}), "source_collection_count"),
        (lambda d: d.update({"source_collection_count": True}), "source_collection_count"),
        (lambda d: d.update({"source_collection_count": 1}), "count"),  # < len(nodeids)
        (lambda d: d.update({"nodeids": []}), "empty"),
        (lambda d: d.update({"nodeids": "string"}), "nodeids"),
        (lambda d: d.update({"nodeids": [d["nodeids"][0], d["nodeids"][0]]}), "duplicate"),
        (lambda d: d.update({"nodeids": ["other_file.py::test_foo"]}), "mixed source"),
        (lambda d: d.update({"nodeids": [d["source"]]}), "malformed"),  # missing ::
        (lambda d: d.update({"nodeids": [f"::{d['source']}"]}), "malformed"),
        (lambda d: d.update({"nodeids": [f"{d['source']}::"]}), "malformed"),
        (lambda d: d.update({"source": ""}), "source"),
        (lambda d: d.update({"source": "../test_encrypt.py"}), "source"),
        (lambda d: d.update({"source": "/test_encrypt.py"}), "source"),
        (lambda d: d.update({"source": r"C:\test_encrypt.py"}), "source"),
        (lambda d: d.update({"source": r"\\server\share\test_encrypt.py"}), "source"),
        (lambda d: d.update({"source": "nonexistent_dir/"}), "source"),
        (lambda d: d.update({"source": "testcases"}), "source"),
    ],
)
def test_case_selection_schema_validation_failures(
    tmp_path: Path, mutate: object, match: str
) -> None:
    from pkcs11_check.core.test_selection import (
        compute_batch_id,
        compute_collection_sha256,
        get_testcases_root,
        load_case_selection,
    )

    root = get_testcases_root()
    target_rel = "test_encrypt.py"
    assert (root / target_rel).is_file()

    nodeids = [f"{target_rel}::test_a", f"{target_rel}::test_b"]
    col_sha = compute_collection_sha256(nodeids)
    batch_id = compute_batch_id(
        source=target_rel,
        source_collection_count=10,
        source_collection_sha256=col_sha,
        nodeids=nodeids,
    )
    plan_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    manifest_data = {
        "schema": 1,
        "plan_id": plan_id,
        "batch_id": batch_id,
        "source": target_rel,
        "source_collection_count": 10,
        "source_collection_sha256": col_sha,
        "nodeids": list(nodeids),
    }

    assert callable(mutate)
    mutate(manifest_data)

    p = tmp_path / "manifest.json"
    p.write_text(json.dumps(manifest_data), encoding="utf-8")

    with pytest.raises(ValueError, match=match):
        load_case_selection(p)


@pytest.mark.parametrize(
    "disabled_entry",
    [
        "test_encrypt.py::test_a",
        "src/pkcs11_check/testcases/test_encrypt.py::test_a",
        r"src\pkcs11_check\testcases\test_encrypt.py::test_a",
        None,  # will be computed as absolute path
    ],
)
def test_case_selection_rejects_disabled_intersection(
    tmp_path: Path, disabled_entry: str | None
) -> None:
    from pkcs11_check.core.test_selection import (
        compute_batch_id,
        compute_collection_sha256,
        get_testcases_root,
        load_case_selection,
    )

    root = get_testcases_root()
    target_rel = "test_encrypt.py"
    nodeids = [f"{target_rel}::test_a", f"{target_rel}::test_b"]
    col_sha = compute_collection_sha256(nodeids)
    batch_id = compute_batch_id(
        source=target_rel,
        source_collection_count=2,
        source_collection_sha256=col_sha,
        nodeids=nodeids,
    )
    plan_id = "a" * 64

    manifest_data = {
        "schema": 1,
        "plan_id": plan_id,
        "batch_id": batch_id,
        "source": target_rel,
        "source_collection_count": 2,
        "source_collection_sha256": col_sha,
        "nodeids": nodeids,
    }
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps(manifest_data), encoding="utf-8")

    if disabled_entry is None:
        disabled = {f"{(root / target_rel).resolve()}::test_a"}
    else:
        disabled = {disabled_entry}

    with pytest.raises(ValueError, match="disabled"):
        load_case_selection(p, disabled_nodeids=disabled)


def test_case_selection_rejects_symlink_escape(tmp_path: Path) -> None:
    from pkcs11_check.core.test_selection import (
        compute_batch_id,
        compute_collection_sha256,
        load_case_selection,
    )

    mock_root = tmp_path / "testcases"
    mock_root.mkdir()
    outside_file = tmp_path / "outside.py"
    outside_file.write_text("def test_outside(): pass\n", encoding="utf-8")

    symlink_target = mock_root / "symlink_escape.py"
    try:
        symlink_target.symlink_to(outside_file)
    except OSError:
        pytest.skip("symlinks not supported on this platform/filesystem")

    source = "symlink_escape.py"
    nodeids = [f"{source}::test_outside"]
    col_sha = compute_collection_sha256(nodeids)
    batch_id = compute_batch_id(
        source=source,
        source_collection_count=1,
        source_collection_sha256=col_sha,
        nodeids=nodeids,
    )
    manifest_data = {
        "schema": 1,
        "plan_id": "b" * 64,
        "batch_id": batch_id,
        "source": source,
        "source_collection_count": 1,
        "source_collection_sha256": col_sha,
        "nodeids": nodeids,
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    with pytest.raises(ValueError, match="escapes testcase root"):
        load_case_selection(manifest_path, testcases_root=mock_root)


def test_portable_nodeid_valid_and_preserves_suffix() -> None:
    from pkcs11_check.core.test_selection import get_testcases_root, portable_nodeid

    root = get_testcases_root()
    source = "test_encrypt.py"
    full_path = (root / source).resolve()

    # Absolute path
    collected = f"{full_path}::test_foo[param-1]"
    assert portable_nodeid(source, collected) == f"{source}::test_foo[param-1]"

    # Relative path from project
    rel_collected = f"src/pkcs11_check/testcases/{source}::test_bar[✓-unicode]"
    assert portable_nodeid(source, rel_collected) == f"{source}::test_bar[✓-unicode]"

    # Slash-less absolute path (rootdir = /)
    slashless = f"{full_path.as_posix().lstrip('/')}::test_slashless[1]"
    assert portable_nodeid(source, slashless) == f"{source}::test_slashless[1]"

    # Suffix with brackets, spaces, backslash
    raw_tail = r"test_complex[a[b] c\d]"
    assert portable_nodeid(source, f"{full_path}::{raw_tail}") == f"{source}::{raw_tail}"


def test_portable_nodeid_mismatched_source_fails() -> None:
    from pkcs11_check.core.test_selection import get_testcases_root, portable_nodeid

    root = get_testcases_root()
    source = "test_encrypt.py"
    other_file = root / "test_reinitialize.py"

    with pytest.raises(ValueError, match="match"):
        portable_nodeid(source, f"{other_file}::test_reinit")


def test_portable_nodeid_invalid_source_escapes_fails() -> None:
    from pkcs11_check.core.test_selection import portable_nodeid

    with pytest.raises(ValueError, match="source path"):
        portable_nodeid("../outside.py", "outside.py::test_case")


def test_portable_nodeid_malformed_fails() -> None:
    from pkcs11_check.core.test_selection import portable_nodeid

    with pytest.raises(ValueError, match="malformed"):
        portable_nodeid("test_encrypt.py", "no_double_colon")
