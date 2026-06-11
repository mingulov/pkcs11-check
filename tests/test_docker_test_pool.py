"""Tests for docker/test_pool.py planning helpers."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType


def _load_test_pool() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "docker" / "test_pool.py"
    spec = importlib.util.spec_from_file_location("docker_test_pool", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_transport_heavy_providers_are_sharded_by_default() -> None:
    pool = _load_test_pool()

    assert pool.SHARD_MAP["bouncyhsm"] >= 16
    assert pool.SHARD_MAP["wolfpkcs11"] >= 8
    assert pool.SHARD_MAP["wolfpkcs11-master"] >= 8


def test_global_pool_default_concurrency_keeps_transport_shards_useful() -> None:
    pool = _load_test_pool()

    assert pool.DEFAULT_CONCURRENCY >= 6


def test_duration_oracle_uses_provider_pooled_results(tmp_path: Path) -> None:
    pool = _load_test_pool()
    results_path = tmp_path / "artifacts" / "bouncyhsm-pooled" / "results.json"
    results_path.parent.mkdir(parents=True)
    results_path.write_text(
        json.dumps(
            {
                "units": [
                    {"target": "slow.py", "duration_s": 10.0},
                    {"target": "slow.py::test_retry", "duration_s": 2.5},
                    {"target": "fast.py", "duration_s": 1.0},
                ]
            }
        )
    )

    assert pool.duration_oracle_for_provider(tmp_path, "bouncyhsm") == {
        "slow.py": 12.5,
        "fast.py": 1.0,
    }
    assert pool.duration_oracle_for_provider(tmp_path, "opencryptoki") is None


def test_workitems_start_heaviest_estimated_batches_first() -> None:
    pool = _load_test_pool()
    items = [
        ("bouncyhsm", 0, ["bouncy-small.py"], 10.0),
        ("wolfpkcs11-master", 0, ["wolf-long.py"], 1000.0),
        ("opencryptoki", 0, ["open-medium.py"], 100.0),
    ]

    ordered = pool.sort_workitems(items)

    assert [item[0] for item in ordered] == [
        "wolfpkcs11-master",
        "opencryptoki",
        "bouncyhsm",
    ]


def test_duration_oracle_absent_when_provider_has_no_prior_results(tmp_path: Path) -> None:
    pool = _load_test_pool()

    assert pool.duration_oracle_for_provider(tmp_path, "bouncyhsm") is None
