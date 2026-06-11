from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location("_docker_test_pool", ROOT / "docker/test_pool.py")
assert _spec and _spec.loader
test_pool = importlib.util.module_from_spec(_spec)
sys.modules["_docker_test_pool"] = test_pool
_spec.loader.exec_module(test_pool)


def test_pool_all_covers_non_default_release_and_branch_targets() -> None:
    assert "wolfpkcs11" in test_pool.ALL_PROVIDERS
    assert "wolfpkcs11-master" in test_pool.ALL_PROVIDERS
    assert "corepkcs11" in test_pool.ALL_PROVIDERS
    assert "corepkcs11-main" in test_pool.ALL_PROVIDERS

    assert "wolfpkcs11" not in test_pool.DEFAULT_PROVIDERS
    assert "wolfpkcs11-master" not in test_pool.DEFAULT_PROVIDERS
    assert "corepkcs11" not in test_pool.DEFAULT_PROVIDERS
    assert "corepkcs11-main" not in test_pool.DEFAULT_PROVIDERS


def test_pool_heavy_targets_are_explicit_not_regular_all() -> None:
    assert test_pool.HEAVY_PROVIDERS == ["optee-pkcs11"]
    assert test_pool.HEAVY_VARIANT_PROVIDERS == ["optee-pkcs11-master"]
    assert test_pool.ALL_HEAVY_PROVIDERS == ["optee-pkcs11", "optee-pkcs11-master"]
    assert "optee-pkcs11" not in test_pool.DEFAULT_PROVIDERS
    assert "optee-pkcs11-master" not in test_pool.DEFAULT_PROVIDERS
    assert "optee-pkcs11" not in test_pool.ALL_PROVIDERS
    assert "optee-pkcs11-master" not in test_pool.ALL_PROVIDERS


def test_pool_discover_files_accepts_single_test_file(tmp_path: Path) -> None:
    test_file = tmp_path / "test_one.py"
    test_file.write_text("def test_one():\n    pass\n")

    assert test_pool.discover_files(str(test_file)) == [str(test_file)]


def test_pool_dry_run_heavy_uses_optee_manual_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    testcases = tmp_path / "testcases"
    testcases.mkdir()
    (testcases / "test_one.py").write_text("def test_one():\n    pass\n")

    monkeypatch.setattr(
        sys,
        "argv",
        ["test_pool.py", "--dry-run", "--heavy", "--testcases", str(testcases)],
    )

    assert test_pool.main() == 0

    out = capsys.readouterr().out
    assert "optee-pkcs11: 1 batch(es), 1 files (full, synthetic-heavy, partition ok)" in out
    assert "optee-pkcs11:0  1 files" in out
    assert "optee-pkcs11-master" not in out


def test_pool_dry_run_all_heavy_includes_optee_release_and_master(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    testcases = tmp_path / "testcases"
    testcases.mkdir()
    (testcases / "test_one.py").write_text("def test_one():\n    pass\n")

    monkeypatch.setattr(
        sys,
        "argv",
        ["test_pool.py", "--dry-run", "--all-heavy", "--testcases", str(testcases)],
    )

    assert test_pool.main() == 0

    out = capsys.readouterr().out
    assert "optee-pkcs11: 1 batch(es), 1 files (full, synthetic-heavy, partition ok)" in out
    assert (
        "optee-pkcs11-master: 1 batch(es), 1 files (full, synthetic-heavy, partition ok)"
        in out
    )


def test_pool_dry_run_uses_explicit_duration_artifact_root_provider_locally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    testcases = tmp_path / "testcases"
    testcases.mkdir()
    (testcases / "test_fast.py").write_text("def test_fast():\n    pass\n")
    (testcases / "test_slow.py").write_text("def test_slow():\n    pass\n")
    history = tmp_path / "history"
    results_path = history / "bouncyhsm-pooled" / "results.json"
    results_path.parent.mkdir(parents=True)
    results_path.write_text(
        json.dumps(
            {
                "units": [
                    {"target": str(testcases / "test_slow.py"), "duration_s": 12.0},
                    {"target": str(testcases / "test_fast.py"), "duration_s": 2.0},
                ]
            }
        )
    )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "test_pool.py",
            "--dry-run",
            "--duration-artifacts-dir",
            str(history),
            "--testcases",
            str(testcases),
            "bouncyhsm:2",
            "opencryptoki:2",
        ],
    )

    assert test_pool.main() == 0

    out = capsys.readouterr().out
    assert "bouncyhsm: 2 batch(es), 2 files (full, duration-oracle, partition ok)" in out
    assert "opencryptoki: 2 batch(es), 2 files (full, synthetic-heavy, partition ok)" in out
    assert "bouncyhsm:0  1 files  load~12.0s" in out
    assert "opencryptoki:0  1 files  load~1.0s" in out


def test_pool_dry_run_reports_duration_hot_node_split(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    testcases = tmp_path / "src/pkcs11_check/testcases"
    mct_file = testcases / "acvp/aes/test_cfb128.py"
    light_file = testcases / "test_light.py"
    mct_file.parent.mkdir(parents=True)
    light_file.parent.mkdir(parents=True, exist_ok=True)
    mct_file.write_text("def test_placeholder():\n    pass\n")
    light_file.write_text("def test_light():\n    pass\n")
    history = tmp_path / "history"
    results_path = history / "bouncyhsm-pooled" / "results.json"
    results_path.parent.mkdir(parents=True)
    results_path.write_text(
        json.dumps(
            {
                "units": [
                    {"target": str(mct_file), "duration_s": 900.0},
                    {"target": str(light_file), "duration_s": 2.0},
                ]
            }
        )
    )
    monkeypatch.setattr(
        test_pool,
        "collect_pytest_nodeids",
        lambda targets, pytest_args, env=None: [
            f"{mct_file}::test_acvp_aes_cfb128_encrypt[AES-enc-tc1]",
            f"{mct_file}::test_acvp_aes_cfb128_multiblock_encrypt[AES-enc-tc2]",
            f"{mct_file}::test_acvp_aes_cfb128_multiblock_decrypt[AES-dec-tc3]",
        ]
        if targets == [str(mct_file)]
        else [],
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "test_pool.py",
            "--dry-run",
            "--duration-artifacts-dir",
            str(history),
            "--testcases",
            str(testcases),
            "bouncyhsm:2",
        ],
    )

    assert test_pool.main() == 0

    out = capsys.readouterr().out
    assert (
        "bouncyhsm: 2 batch(es), 2 files -> 4 targets "
        "(full, duration-oracle, node-split 1 file(s), partition ok)"
    ) in out
    assert "bouncyhsm:0  2 targets" in out
    assert "bouncyhsm:1  2 targets" in out


def test_pool_expands_duration_hot_mct_files_to_node_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mct_file = tmp_path / "src/pkcs11_check/testcases/acvp/aes/test_cfb128.py"
    light_file = tmp_path / "src/pkcs11_check/testcases/test_light.py"
    mct_file.parent.mkdir(parents=True)
    light_file.parent.mkdir(parents=True, exist_ok=True)
    mct_file.write_text("def test_placeholder():\n    pass\n")
    light_file.write_text("def test_light():\n    pass\n")
    nodeids = [
        f"{mct_file}::test_acvp_aes_cfb128_encrypt[AES-enc-tc1]",
        f"{mct_file}::test_acvp_aes_cfb128_multiblock_encrypt[AES-enc-tc2]",
        f"{mct_file}::test_acvp_aes_cfb128_multiblock_decrypt[AES-dec-tc3]",
    ]

    monkeypatch.setattr(
        test_pool,
        "collect_pytest_nodeids",
        lambda targets, pytest_args, env=None: nodeids if targets == [str(mct_file)] else [],
    )

    units, durations, expanded = test_pool.expand_duration_hot_node_units(
        [str(mct_file), str(light_file)],
        {str(mct_file): 900.0, str(light_file): 2.0},
    )

    assert str(mct_file) not in units
    assert str(light_file) in units
    assert all(nodeid in units for nodeid in nodeids)
    assert expanded == {str(mct_file): len(nodeids)}
    assert durations[nodeids[1]] == durations[nodeids[2]]
    assert durations[nodeids[1]] > durations[nodeids[0]]


def test_pool_keeps_provider_local_fast_or_skipped_mct_files_at_file_level(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mct_file = tmp_path / "src/pkcs11_check/testcases/acvp/aes/test_cfb128.py"
    mct_file.parent.mkdir(parents=True)
    mct_file.write_text("def test_placeholder():\n    pass\n")
    collect_calls: list[list[str]] = []

    def fake_collect(
        targets: list[str], pytest_args: list[str], env: dict[str, str] | None = None
    ) -> list[str]:
        collect_calls.append(targets)
        return [f"{mct_file}::test_acvp_aes_cfb128_multiblock_encrypt[AES-enc-tc2]"]

    monkeypatch.setattr(test_pool, "collect_pytest_nodeids", fake_collect)

    units, durations, expanded = test_pool.expand_duration_hot_node_units(
        [str(mct_file)],
        {str(mct_file): 0.0},
    )

    assert units == [str(mct_file)]
    assert durations == {str(mct_file): 0.0}
    assert expanded == {}
    assert collect_calls == []


def test_pool_node_split_collection_uses_caller_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mct_file = tmp_path / "src/pkcs11_check/testcases/acvp/aes/test_ofb.py"
    mct_file.parent.mkdir(parents=True)
    mct_file.write_text("def test_placeholder():\n    pass\n")
    seen_env: list[dict[str, str] | None] = []

    def fake_collect(
        targets: list[str], pytest_args: list[str], env: dict[str, str] | None = None
    ) -> list[str]:
        seen_env.append(env)
        return [
            f"{mct_file}::test_acvp_aes_ofb_multiblock_encrypt[AES-enc-tc2]",
            f"{mct_file}::test_acvp_aes_ofb_multiblock_decrypt[AES-dec-tc3]",
        ]

    monkeypatch.setattr(test_pool, "collect_pytest_nodeids", fake_collect)
    collection_env = {"PKCS11_CHECK_DATA_DIR": "/custom/data"}

    units, _durations, _expanded = test_pool.expand_duration_hot_node_units(
        [str(mct_file)],
        {str(mct_file): 600.0},
        collection_env=collection_env,
    )

    assert len(units) == 2
    assert seen_env == [collection_env]


def test_pool_uses_fetched_user_data_cache_when_repo_data_is_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_root = tmp_path / "repo"
    (project_root / "data").mkdir(parents=True)
    xdg_data = tmp_path / "xdg-data"
    user_data = xdg_data / "pkcs11-check" / "data"
    (user_data / "acvp").mkdir(parents=True)

    monkeypatch.delenv("PKCS11_CHECK_HOST_DATA_DIR", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg_data))

    assert test_pool.resolve_host_data_dir(project_root) == user_data


def test_pool_keeps_explicit_host_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    explicit = tmp_path / "explicit-data"
    explicit.mkdir()

    monkeypatch.setenv("PKCS11_CHECK_HOST_DATA_DIR", str(explicit))

    assert test_pool.resolve_host_data_dir(tmp_path / "repo") == explicit


def test_pool_builds_provider_image_once_regardless_of_shard_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    testcases = tmp_path / "testcases"
    testcases.mkdir()
    for index in range(3):
        (testcases / f"test_{index}.py").write_text("def test_one():\n    pass\n")

    build_calls: list[str] = []
    run_calls: list[tuple[str, int, list[str]]] = []

    def fake_build_image(provider: str, env: dict[str, str]) -> tuple[str, bool]:
        build_calls.append(provider)
        return provider, True

    def fake_run_item(
        provider: str, idx: int, files: list[str], env: dict[str, str]
    ) -> tuple[str, int, int]:
        run_calls.append((provider, idx, files))
        shard_dir = Path("artifacts") / f"{provider}-shard-{idx}"
        shard_dir.mkdir(parents=True)
        shard_dir.joinpath("results.json").write_text(
            json.dumps({"summary": {"passed": len(files)}, "units": []})
        )
        return provider, idx, 0

    def fake_merge_shard_dirs(shard_dirs: list[Path], output_dir: Path) -> None:
        output_dir.mkdir(parents=True)
        output_dir.joinpath("results.json").write_text(
            json.dumps(
                {
                    "summary": {
                        "total": len(shard_dirs),
                        "passed": len(shard_dirs),
                        "failed": 0,
                        "crashed": 0,
                        "timeout": 0,
                    }
                }
            )
        )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(test_pool, "COMPOSE", ["docker", "compose"])
    monkeypatch.setattr(test_pool, "build_image", fake_build_image)
    monkeypatch.setattr(test_pool, "run_item", fake_run_item)
    monkeypatch.setattr(test_pool, "clean_prior_shards", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_pool, "merge_shard_dirs", fake_merge_shard_dirs)
    monkeypatch.setattr(
        sys,
        "argv",
        ["test_pool.py", "--testcases", str(testcases), "optee-pkcs11:3"],
    )

    assert test_pool.main() == 0

    assert build_calls == ["optee-pkcs11"]
    assert sorted((provider, idx) for provider, idx, _files in run_calls) == [
        ("optee-pkcs11", 0),
        ("optee-pkcs11", 1),
        ("optee-pkcs11", 2),
    ]


def test_pool_reports_shard_progress_and_provider_elapsed_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    testcases = tmp_path / "testcases"
    testcases.mkdir()
    for index in range(2):
        (testcases / f"test_{index}.py").write_text("def test_one():\n    pass\n")

    clock = iter([10.0, 12.5, 20.0, 21.25])

    def fake_monotonic() -> float:
        return next(clock)

    def fake_strftime(format_string: str) -> str:
        assert format_string == "%Y-%m-%d %H:%M:%S"
        return "2026-06-11 12:34:56"

    def fake_run_item(
        provider: str, idx: int, files: list[str], env: dict[str, str]
    ) -> tuple[str, int, int]:
        shard_dir = Path("artifacts") / f"{provider}-shard-{idx}"
        shard_dir.mkdir(parents=True)
        shard_dir.joinpath("results.json").write_text(
            json.dumps({"summary": {"passed": len(files)}, "units": []})
        )
        return provider, idx, 0

    def fake_merge_shard_dirs(shard_dirs: list[Path], output_dir: Path) -> None:
        assert len(shard_dirs) == 2
        output_dir.mkdir(parents=True)
        output_dir.joinpath("results.json").write_text(
            json.dumps(
                {
                    "summary": {
                        "total": 11,
                        "passed": 7,
                        "failed": 1,
                        "xfailed": 3,
                        "crashed": 0,
                        "timeout": 0,
                    }
                }
            )
        )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(test_pool.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(test_pool.time, "strftime", fake_strftime)
    monkeypatch.setattr(test_pool, "run_item", fake_run_item)
    monkeypatch.setattr(test_pool, "clean_prior_shards", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_pool, "merge_shard_dirs", fake_merge_shard_dirs)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "test_pool.py",
            "--no-build",
            "-j",
            "1",
            "--testcases",
            str(testcases),
            "optee-pkcs11:2",
        ],
    )

    assert test_pool.main() == 0

    out = capsys.readouterr().out
    assert (
        "[2026-06-11 12:34:56] "
        "=== running 2 items through 1 workers (mixed) ==="
    ) in out
    assert (
        "[2026-06-11 12:34:56] "
        "--- START optee-pkcs11:0 files=1 load~1.0s log=/tmp/pool-optee-pkcs11-0.log ---"
    ) in out
    assert "--- START optee-pkcs11:0 files=1 load~1.0s log=/tmp/pool-optee-pkcs11-0.log ---" in out
    assert "--- DONE optee-pkcs11:0 rc=0 took=2.5s ---" in out
    assert "--- DONE optee-pkcs11:1 rc=0 took=1.2s ---" in out
    assert "xfailed" in out
    assert "shard_time" in out
    assert "optee-pkcs11" in out
    assert "3.8s" in out


def test_pool_reports_elapsed_time_when_provider_has_no_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    testcases = tmp_path / "testcases"
    testcases.mkdir()
    (testcases / "test_one.py").write_text("def test_one():\n    pass\n")

    clock = iter([30.0, 34.0])

    def fake_monotonic() -> float:
        return next(clock)

    def fake_run_item(
        provider: str, idx: int, files: list[str], env: dict[str, str]
    ) -> tuple[str, int, int]:
        return provider, idx, 2

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(test_pool.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(test_pool, "run_item", fake_run_item)
    monkeypatch.setattr(test_pool, "clean_prior_shards", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "test_pool.py",
            "--no-build",
            "-j",
            "1",
            "--testcases",
            str(testcases),
            "optee-pkcs11:1",
        ],
    )

    assert test_pool.main() == 1

    out = capsys.readouterr().out
    assert "--- DONE optee-pkcs11:0 rc=2 took=4.0s ---" in out
    assert "NO-RESULTS" in out
    assert "4.0s" in out


def test_pool_returns_nonzero_when_provider_coverage_state_regresses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    testcases = tmp_path / "testcases"
    testcases.mkdir()
    (testcases / "test_one.py").write_text("def test_one():\n    pass\n")

    baseline_root = tmp_path / "baseline"
    baseline_dir = baseline_root / "optee-pkcs11-pooled"
    baseline_dir.mkdir(parents=True)
    baseline_dir.joinpath("coverage.json").write_text(
        json.dumps(
            {
                "mechanism_coverage": {
                    "accepted_names": ["CKM_AES_CBC", "CKM_AES_GCM"],
                    "attempted_names": ["CKM_AES_CBC", "CKM_AES_GCM"],
                }
            }
        )
        + "\n"
    )

    def fake_run_item(
        provider: str, idx: int, files: list[str], env: dict[str, str]
    ) -> tuple[str, int, int]:
        shard_dir = Path("artifacts") / f"{provider}-shard-{idx}"
        shard_dir.mkdir(parents=True)
        shard_dir.joinpath("results.json").write_text(
            json.dumps({"summary": {"passed": len(files)}, "units": []})
        )
        return provider, idx, 0

    def fake_merge_shard_dirs(shard_dirs: list[Path], output_dir: Path) -> None:
        assert len(shard_dirs) == 1
        output_dir.mkdir(parents=True)
        output_dir.joinpath("results.json").write_text(
            json.dumps(
                {
                    "summary": {
                        "total": 1,
                        "passed": 1,
                        "failed": 0,
                        "crashed": 0,
                        "timeout": 0,
                    }
                }
            )
        )
        output_dir.joinpath("coverage.json").write_text(
            json.dumps(
                {
                    "mechanism_coverage": {
                        "accepted_names": ["CKM_AES_CBC"],
                        "attempted_names": ["CKM_AES_CBC"],
                    }
                }
            )
        )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(test_pool, "build_image", lambda provider, env: (provider, True))
    monkeypatch.setattr(test_pool, "run_item", fake_run_item)
    monkeypatch.setattr(test_pool, "clean_prior_shards", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_pool, "merge_shard_dirs", fake_merge_shard_dirs)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "test_pool.py",
            "--testcases",
            str(testcases),
            "--coverage-baseline-artifacts-dir",
            str(baseline_root),
            "optee-pkcs11:1",
        ],
    )

    assert test_pool.main() == 1

    out = capsys.readouterr().out
    assert "COVERAGE LOSS optee-pkcs11" in out
    assert "accepted: CKM_AES_GCM" in out
    assert "attempted: CKM_AES_GCM" in out


def test_pool_returns_nonzero_when_a_shard_produces_no_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    testcases = tmp_path / "testcases"
    testcases.mkdir()
    for index in range(2):
        (testcases / f"test_{index}.py").write_text("def test_one():\n    pass\n")

    def fake_run_item(
        provider: str, idx: int, files: list[str], env: dict[str, str]
    ) -> tuple[str, int, int]:
        if idx == 0:
            shard_dir = Path("artifacts") / f"{provider}-shard-{idx}"
            shard_dir.mkdir(parents=True)
            shard_dir.joinpath("results.json").write_text(
                json.dumps({"summary": {"passed": len(files)}, "units": []})
            )
        return provider, idx, 0

    def fake_merge_shard_dirs(shard_dirs: list[Path], output_dir: Path) -> None:
        output_dir.mkdir(parents=True)
        output_dir.joinpath("results.json").write_text(
            json.dumps(
                {
                    "summary": {
                        "total": 1,
                        "passed": 1,
                        "failed": 0,
                        "crashed": 0,
                        "timeout": 0,
                    }
                }
            )
        )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(test_pool, "build_image", lambda provider, env: (provider, True))
    monkeypatch.setattr(test_pool, "run_item", fake_run_item)
    monkeypatch.setattr(test_pool, "clean_prior_shards", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_pool, "merge_shard_dirs", fake_merge_shard_dirs)
    monkeypatch.setattr(
        sys,
        "argv",
        ["test_pool.py", "--testcases", str(testcases), "optee-pkcs11:2"],
    )

    assert test_pool.main() == 1
