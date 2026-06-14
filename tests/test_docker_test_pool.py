"""Tests for docker/test_pool.py planning helpers."""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType

COMPOSE_FILE = Path(__file__).resolve().parents[1] / "docker" / "docker-compose.test.yml"


def _compose_text() -> str:
    return COMPOSE_FILE.read_text(encoding="utf-8")


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

    # DEFAULT_CONCURRENCY is intentionally 4: it matches the typical host and avoids
    # oversubscribing small boxes. Per-run concurrency is set with the pool's -j flag.
    assert pool.DEFAULT_CONCURRENCY >= 4


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


def test_duration_oracle_can_use_explicit_provider_local_artifact_root(tmp_path: Path) -> None:
    pool = _load_test_pool()
    results_path = tmp_path / "history" / "bouncyhsm-pooled" / "results.json"
    results_path.parent.mkdir(parents=True)
    results_path.write_text(
        json.dumps(
            {
                "units": [
                    {"target": "slow.py", "duration_s": 10.0},
                    {"target": "fast.py", "duration_s": 1.0},
                ]
            }
        )
    )

    assert pool.duration_oracle_for_provider(
        tmp_path, "bouncyhsm", artifacts_root=tmp_path / "history"
    ) == {
        "slow.py": 10.0,
        "fast.py": 1.0,
    }
    assert (
        pool.duration_oracle_for_provider(
            tmp_path, "opencryptoki", artifacts_root=tmp_path / "history"
        )
        is None
    )


def test_duration_oracle_ignores_empty_or_malformed_history(tmp_path: Path) -> None:
    pool = _load_test_pool()
    empty_results = tmp_path / "empty" / "bouncyhsm-pooled" / "results.json"
    empty_results.parent.mkdir(parents=True)
    empty_results.write_text(json.dumps({"units": []}))
    malformed_results = tmp_path / "bad" / "bouncyhsm-pooled" / "results.json"
    malformed_results.parent.mkdir(parents=True)
    malformed_results.write_text("{")

    assert (
        pool.duration_oracle_for_provider(tmp_path, "bouncyhsm", artifacts_root=tmp_path / "empty")
        is None
    )
    assert (
        pool.duration_oracle_for_provider(tmp_path, "bouncyhsm", artifacts_root=tmp_path / "bad")
        is None
    )


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


def test_compose_x_common_anchor_isolates_the_network() -> None:
    """Security invariant: the shared x-common anchor declares network_mode: none, so
    every target that merges it runs with no external network at run time."""
    compose = _compose_text()
    assert "x-common: &common" in compose
    anchor = compose.split("x-common: &common", 1)[1].split("\nservices:", 1)[0]
    assert "network_mode: none" in anchor, (
        "x-common must declare 'network_mode: none' so all targets run without network"
    )


def test_every_compose_service_is_network_isolated() -> None:
    """No test container may get the network at run time (a module shipping hidden
    telemetry cannot phone home). Each service must either merge the isolated x-common
    anchor or declare network_mode: none itself. This auto-covers every new target and
    fails if a future service silently opts out."""
    compose = _compose_text()
    lines = compose.splitlines()
    headers = [
        (i, m.group(1))
        for i, line in enumerate(lines)
        if (m := re.match(r"  (test-[a-z0-9-]+):\s*$", line))
    ]
    assert headers, "no test-* services found in docker-compose.test.yml"
    for idx, (start, name) in enumerate(headers):
        end = headers[idx + 1][0] if idx + 1 < len(headers) else len(lines)
        block = "\n".join(lines[start:end])
        isolated = "<<: *common" in block or "network_mode: none" in block
        assert isolated, (
            f"service {name} is not network-isolated (needs <<: *common or network_mode: none)"
        )
