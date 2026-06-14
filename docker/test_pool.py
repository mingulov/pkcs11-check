#!/usr/bin/env python3
"""Global mixed pool — run providers as ONE pool of K concurrent containers.

Each provider is sharded to its own count (in-process providers undivided,
bouncyhsm heavily, opencryptoki moderately). Every ``(provider, file-batch)``
pair goes into one queue and runs K-at-a-time, MIXED across providers, so the K
docker slots stay full even while a slow provider's heavy batches grind next to
a fast provider's whole run. Results are merged per provider.

PKCS#11-safe: one container == one server+token, one serial process over a
disjoint subset of files. Never concurrent same-token access.

Total wall ~= max(largest single batch, total_work_all_providers / K) — not the
sum of per-provider runs.

Run from the project root:  uv run python docker/test_pool.py [opts] [provider[:shards] ...]
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
from typing import Any, NamedTuple

from pkcs11_check.core.file_runner import collect_pytest_nodeids
from pkcs11_check.core.merge import merge_shard_dirs
from pkcs11_check.core.quality_audit import compare_mechanism_coverage_states
from pkcs11_check.core.sharding import (
    duration_by_unit_from_results,
    estimate_shard_load,
    plan_shards,
)

# Per-test CK_RV trace, on by default for pooled runs in COMPACT mode: every test
# under N C_* calls is recorded in full; only the ~dozen MCT cases (one test =
# ~100k chained ops) are bounded to their last N. Override via the pool's own env
# (set a different N, or empty to disable). See docs/rv-trace-design.md.
RV_TRACE_COMPACT_N = os.environ.get("PKCS11_CHECK_RV_TRACE_COMPACT", "512")
HOST_ARTIFACT_OWNER = os.environ.get("PKCS11_CHECK_ARTIFACT_OWNER", f"{os.getuid()}:{os.getgid()}")

# Crash-call journal: OFF by default (per-call flush has a cost). Set
# PKCS11_CHECK_CRASH_JOURNAL=1 in the pool env to write per-unit write-ahead
# journals under each shard's artifact dir, so `pkcs11-check crash-calls
# <artifact>/crash-journals` pinpoints the C_* call a crashed unit died in.
CRASH_JOURNAL = os.environ.get("PKCS11_CHECK_CRASH_JOURNAL", "").strip().lower() not in (
    "",
    "0",
    "false",
    "no",
)

# Editable per-provider shard counts; providers not listed default to 1 (undivided).
SHARD_MAP: dict[str, int] = {
    "bouncyhsm": 16,
    "opencryptoki": 3,
    "opencryptoki-master": 3,
    "wolfpkcs11": 8,
    "wolfpkcs11-master": 8,
    "tpm2": 2,
    "kryoptic": 2,
    "kryoptic-main": 2,
    "kryoptic-fips": 2,
}
DEFAULT_PROVIDERS = [
    "softhsm2",
    "kryoptic",
    "nss",
    # NSS digest/hash/cipher mechanisms live only on slot 0 (Internal Crypto
    # Services); the default nss/nss-pqc passes use slot 1 (cert/key DB). The
    # -slot0 passes cover the slot-0-only mechanisms. See docs/module-issues.md.
    "nss-slot0",
    "nss-pqc",
    "nss-pqc-slot0",
    "opencryptoki",
    "bouncyhsm",
    "pkcs11-mock",
    "tpm2",
]
# Additional stable providers that are tracked but intentionally not part of the
# default quick matrix because they are slower, narrower, or non-system tokens.
ADDITIONAL_PROVIDERS = [
    "wolfpkcs11",
    "corepkcs11",
]
# Development-branch / variant images (cold builds; some may build-fail and be skipped).
VARIANT_PROVIDERS = [
    "softhsm2-main",
    "softhsm2-generated-iv",
    "kryoptic-main",
    "kryoptic-fips",
    "nss-main",
    "nss-main-slot0",
    "opencryptoki-master",
    "wolfpkcs11-master",
    "corepkcs11-main",
    # craton-hsm-core has no release tags — only ever a main build (cold build may be
    # skipped on failure), so it lives with the other dev/variant images.
    "craton-hsm",
    # NetHSM: keyfender server + nethsm-pkcs11 co-located; undivided (not in SHARD_MAP) —
    # narrow/fast coverage and each shard would re-provision its own server.
    "nethsm",
]
# Heavy/manual providers are runnable through the pool, but not included in
# default or normal --all sweeps.
HEAVY_PROVIDERS = [
    "optee-pkcs11",
]
HEAVY_VARIANT_PROVIDERS = [
    "optee-pkcs11-master",
]
ALL_HEAVY_PROVIDERS = HEAVY_PROVIDERS + HEAVY_VARIANT_PROVIDERS
ALL_PROVIDERS = DEFAULT_PROVIDERS + ADDITIONAL_PROVIDERS + VARIANT_PROVIDERS
TESTCASES = "src/pkcs11_check/testcases"
COMPOSE = ["docker", "compose", "-f", "docker/docker-compose.test.yml"]
VECTOR_DATA_DIRS = ("wycheproof", "acvp", "cctv", "x509-limbo")
DEFAULT_CONCURRENCY = 4
WorkItem = tuple[str, int, list[str], float]
NODE_SPLIT_MIN_DURATION_S = 300.0
NODE_SPLIT_BASENAMES: tuple[str, ...] = (
    "test_cfb8.py",
    "test_cfb128.py",
    "test_ofb.py",
)
NODE_SPLIT_SLOW_NAME_PARTS: tuple[str, ...] = ("multiblock",)


class RunResult(NamedTuple):
    provider: str
    idx: int
    returncode: int
    elapsed_s: float


# NSS exposes the digest / bulk-cipher / KDF mechanisms only on slot 0 (Internal
# Cryptographic Services); the default slot-1 (cert/key DB) pass skips them. The
# `*-slot0` providers re-run to cover exactly those, but today they re-run the
# WHOLE suite — ~456s/pass of byte-identical re-runs of the slot-1 pass. These
# are the files that actually have a test node which RUNS on slot 0 but SKIPS on
# slot 1 (computed from artifacts: nodes covered on nss-slot0 but not nss). The
# slot0 passes are scoped to these, keeping every slot-0-unique finding while
# dropping the redundant re-runs. Regenerate after suite changes by diffing
# call-phase node coverage of <provider>-slot0 vs <provider> report.jsonl.
# Coverage-neutral: the dropped files have ZERO slot-0-unique nodes (the slot-1
# pass already covers them). Guarded by tests/test_slot0_scope.py.
SLOT0_UNIQUE_FILES: tuple[str, ...] = (
    "acvp/test_acvp_hash.py",
    "acvp/test_acvp_sha3.py",
    "security/test_crypto_weakness.py",
    "security/test_ffi_length_boundary.py",
    "security/test_ffi_null_pointer.py",
    "test_aes_kdf.py",
    "test_benchmark.py",
    "test_buffers.py",
    "test_camellia.py",
    "test_crossverify.py",
    "test_des.py",
    "test_digest.py",
    "test_dual_function.py",
    "test_errors.py",
    "test_fuzz.py",
    "test_kat.py",
    "test_mech_attribute.py",
    "test_mech_derive.py",
    "test_mech_digest.py",
    "test_mech_encrypt.py",
    "test_mech_flags.py",
    "test_mech_keygen.py",
    "test_mech_lifecycle.py",
    "test_mech_multipart.py",
    "test_mech_negative.py",
    "test_mech_sign.py",
    "test_mech_state.py",
    "test_mech_wrap.py",
    "test_metamorphic.py",
    "test_misc_kdf.py",
    "test_multipart.py",
    "test_multipart_streaming.py",
    "test_operation_state.py",
    "test_operation_termination.py",
    "test_resource.py",
    "test_sha3.py",
    "test_ssl3.py",
    "test_stress.py",
    "test_tls12.py",
)


def discover_files(testcases: str) -> list[str]:
    root = Path(testcases)
    if root.is_file():
        return [str(root)] if root.match("test_*.py") else []
    return sorted(str(p) for p in root.rglob("test_*.py"))


def has_vector_data(data_dir: Path) -> bool:
    return any((data_dir / name).is_dir() for name in VECTOR_DATA_DIRS)


def resolve_host_data_dir(project_root: Path) -> Path:
    explicit = os.environ.get("PKCS11_CHECK_HOST_DATA_DIR")
    if explicit:
        return Path(explicit)

    repo_data = project_root / "data"
    if has_vector_data(repo_data):
        return repo_data

    xdg_data_home = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
    user_data = xdg_data_home / "pkcs11-check" / "data"
    if has_vector_data(user_data):
        return user_data

    return repo_data


def compose_env(project_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["PKCS11_CHECK_HOST_DATA_DIR"] = str(resolve_host_data_dir(project_root))
    return env


def resolve_duration_artifacts_root(project_root: Path, artifacts_root: Path | None) -> Path:
    if artifacts_root is None:
        return project_root / "artifacts"
    if artifacts_root.is_absolute():
        return artifacts_root
    return project_root / artifacts_root


def duration_oracle_for_provider(
    project_root: Path, provider: str, *, artifacts_root: Path | None = None
) -> dict[str, float] | None:
    """Return provider-local per-file durations from the previous pooled artifact."""
    root = resolve_duration_artifacts_root(project_root, artifacts_root)
    prior_results = root / f"{provider}-pooled" / "results.json"
    if not prior_results.exists():
        return None
    try:
        durations = duration_by_unit_from_results(prior_results)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    return durations or None


def _read_json_mapping(path: Path) -> Mapping[str, Any] | None:
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, Mapping) else None


def provider_coverage_payload(
    artifacts_root: Path,
    provider: str,
) -> tuple[Path, Mapping[str, Any]] | None:
    """Load coverage for one provider from <root>/<provider>-pooled artifacts."""
    provider_dir = artifacts_root / f"{provider}-pooled"
    coverage_path = provider_dir / "coverage.json"
    coverage_payload = _read_json_mapping(coverage_path)
    if coverage_payload is not None and isinstance(
        coverage_payload.get("mechanism_coverage"), Mapping
    ):
        return coverage_path, coverage_payload

    results_path = provider_dir / "results.json"
    results_payload = _read_json_mapping(results_path)
    if results_payload is None:
        return None
    embedded_coverage = results_payload.get("coverage")
    if isinstance(embedded_coverage, Mapping) and isinstance(
        embedded_coverage.get("mechanism_coverage"), Mapping
    ):
        return results_path, embedded_coverage
    return None


def compare_provider_coverage(
    project_root: Path,
    provider: str,
    *,
    baseline_artifacts_root: Path,
) -> tuple[str, dict[str, Any] | None]:
    """Compare provider-local baseline coverage against the just-merged artifact."""
    baseline = provider_coverage_payload(baseline_artifacts_root, provider)
    if baseline is None:
        return "missing-baseline", None

    current_root = project_root / "artifacts"
    candidate = provider_coverage_payload(current_root, provider)
    if candidate is None:
        return "missing-candidate", None

    _baseline_path, baseline_payload = baseline
    _candidate_path, candidate_payload = candidate
    return "compared", compare_mechanism_coverage_states(baseline_payload, candidate_payload)


def sort_workitems(workitems: list[WorkItem]) -> list[WorkItem]:
    """Order queued batches so the longest estimated work starts first."""
    return sorted(workitems, key=lambda item: (-item[3], item[0], item[1]))


def files_for_provider(provider: str, all_files: list[str], testcases: str) -> list[str]:
    """Scope the `*-slot0` NSS passes to the slot-0-unique files (coverage-neutral);
    every other provider runs the full suite."""
    if not provider.endswith("-slot0"):
        return all_files
    wanted = {str(Path(testcases) / rel) for rel in SLOT0_UNIQUE_FILES}
    present = set(all_files)
    missing = sorted(rel for rel in SLOT0_UNIQUE_FILES if str(Path(testcases) / rel) not in present)
    if missing:
        print(
            f"WARNING: {provider}: slot0-unique file(s) not found (renamed/removed?): {missing}; "
            "falling back to the FULL suite to avoid dropping coverage.",
            file=sys.stderr,
        )
        return all_files
    return sorted(f for f in all_files if f in wanted)


def _is_duration_hot_node_split_candidate(unit: str, duration_by_unit: dict[str, float]) -> bool:
    if unit.rsplit("/", 1)[-1] not in NODE_SPLIT_BASENAMES:
        return False
    return duration_by_unit.get(unit, 0.0) >= NODE_SPLIT_MIN_DURATION_S


def _is_slow_nodeid(nodeid: str) -> bool:
    lowered = nodeid.lower()
    return any(part in lowered for part in NODE_SPLIT_SLOW_NAME_PARTS)


def expand_duration_hot_node_units(
    units: list[str],
    duration_by_unit: dict[str, float] | None,
    *,
    collection_env: dict[str, str] | None = None,
) -> tuple[list[str], dict[str, float] | None, dict[str, int]]:
    """Expand prior-slow MCT files into pytest nodeids for finer pool sharding.

    Expansion is provider-local because it is driven only by that provider's
    prior ``results.json`` durations. A provider that skipped the same file in
    0s, or has no history, keeps the file-level unit.
    """
    if not duration_by_unit:
        return list(units), duration_by_unit, {}

    expanded_units: list[str] = []
    expanded_durations = dict(duration_by_unit)
    expanded_files: dict[str, int] = {}

    for unit in units:
        if not _is_duration_hot_node_split_candidate(unit, duration_by_unit):
            expanded_units.append(unit)
            continue

        try:
            nodeids = collect_pytest_nodeids([unit], [], env=collection_env)
        except ValueError:
            expanded_units.append(unit)
            continue
        if len(nodeids) <= 1:
            expanded_units.append(unit)
            continue

        expanded_files[unit] = len(nodeids)
        total_duration = max(duration_by_unit.get(unit, 0.0), 0.0)
        slow_nodeids = [nodeid for nodeid in nodeids if _is_slow_nodeid(nodeid)]
        slow_nodeid_set = set(slow_nodeids)
        fast_nodeids = [nodeid for nodeid in nodeids if nodeid not in slow_nodeid_set]
        if slow_nodeids:
            slow_budget = total_duration * 0.95
            fast_budget = total_duration - slow_budget
            slow_weight = slow_budget / len(slow_nodeids)
            fast_weight = fast_budget / max(len(fast_nodeids), 1)
        else:
            slow_weight = total_duration / len(nodeids)
            fast_weight = slow_weight

        for nodeid in nodeids:
            expanded_units.append(nodeid)
            expanded_durations[nodeid] = slow_weight if nodeid in slow_nodeid_set else fast_weight

    return expanded_units, expanded_durations, expanded_files


def build_image(provider: str, env: dict[str, str]) -> tuple[str, bool]:
    log = Path(f"/tmp/pool-build-{provider}.log")
    with log.open("w") as fh:
        rc = subprocess.run(  # noqa: S603
            [*COMPOSE, "build", f"test-{provider}"],
            stdout=fh,
            stderr=subprocess.STDOUT,
            env=env,
        ).returncode
    return provider, rc == 0


def pool_log_path(provider: str, idx: int) -> Path:
    return Path(f"/tmp/pool-{provider}-{idx}.log")


def format_elapsed(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    total = int(round(seconds))
    return f"{total // 60}m{total % 60:02d}s"


def timestamped_message(message: str) -> str:
    return f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}"


_CONTROLLED_CHILD_CRASH_MARKERS = (
    "module crashed with signal",
    "subprocess crashed with signal",
)
_CONTROLLED_CHILD_TIMEOUT_MARKERS = (
    "subprocess.timeoutexpired",
    "subprocess timeout",
    "timed out after",
)


def controlled_child_counts(results: Mapping[str, Any]) -> tuple[int, int]:
    """Count crash-safe child subprocess findings that live inside failed tests."""
    child_crash = 0
    child_timeout = 0
    units = results.get("units")
    if not isinstance(units, list):
        return child_crash, child_timeout
    for unit in units:
        if not isinstance(unit, Mapping):
            continue
        tests = unit.get("tests")
        if not isinstance(tests, list):
            continue
        for record in tests:
            if not isinstance(record, Mapping) or record.get("outcome") != "failed":
                continue
            longrepr = str(record.get("longrepr", "")).lower()
            if any(marker in longrepr for marker in _CONTROLLED_CHILD_CRASH_MARKERS):
                child_crash += 1
            elif any(marker in longrepr for marker in _CONTROLLED_CHILD_TIMEOUT_MARKERS):
                child_timeout += 1
    return child_crash, child_timeout


def print_pool_event(
    message: str, output_lock: Any | None = None, *, file: Any | None = None
) -> None:
    rendered = timestamped_message(message)
    if output_lock is None:
        print(rendered, flush=True, file=file)
        return
    with output_lock:
        print(rendered, flush=True, file=file)


def run_item(
    provider: str, idx: int, files: list[str], env: dict[str, str]
) -> tuple[str, int, int]:
    """Run one (provider, batch) container. Returns (provider, idx, returncode)."""
    log = pool_log_path(provider, idx)
    rv_trace_env = (
        ["-e", f"PKCS11_CHECK_RV_TRACE_COMPACT={RV_TRACE_COMPACT_N}"] if RV_TRACE_COMPACT_N else []
    )
    if CRASH_JOURNAL:
        rv_trace_env += [
            "-e",
            f"PKCS11_CHECK_RV_TRACE_JOURNAL_DIR=/artifacts/{provider}-shard-{idx}/crash-journals",
        ]
    with log.open("w") as fh:
        rc = subprocess.run(  # noqa: S603
            [
                *COMPOSE,
                "run",
                "--rm",
                "-e",
                f"PKCS11_CHECK_TARGETS={' '.join(files)}",
                "-e",
                f"PKCS11_CHECK_ARTIFACT_DIR=/artifacts/{provider}-shard-{idx}",
                "-e",
                f"PKCS11_CHECK_ARTIFACT_OWNER={HOST_ARTIFACT_OWNER}",
                *rv_trace_env,
                f"test-{provider}",
            ],
            stdout=fh,
            stderr=subprocess.STDOUT,
            env=env,
        ).returncode
    return provider, idx, rc


def run_workitem(
    workitem: WorkItem, env: dict[str, str], output_lock: Any | None = None
) -> RunResult:
    provider, idx, files, load = workitem
    log = pool_log_path(provider, idx)
    print_pool_event(
        f"--- START {provider}:{idx} files={len(files)} load~{load:.1f}s log={log} ---",
        output_lock,
    )
    started = time.monotonic()
    rc: int | None = None
    try:
        provider_out, idx_out, rc = run_item(provider, idx, files, env)
    finally:
        elapsed = time.monotonic() - started
        rc_text = "error" if rc is None else str(rc)
        print_pool_event(
            f"--- DONE {provider}:{idx} rc={rc_text} took={format_elapsed(elapsed)} ---",
            output_lock,
        )
    return RunResult(provider_out, idx_out, rc, elapsed)


def ensure_artifacts_root_writable(project_root: Path, env: dict[str, str]) -> None:
    """Create or repair the host artifacts root before Docker bind mounts use it."""
    artifacts_root = project_root / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    if os.access(artifacts_root, os.W_OK | os.X_OK):
        return

    mount = f"{artifacts_root}:/artifacts"
    repair_commands = (
        [
            "docker",
            "run",
            "--rm",
            "-v",
            mount,
            "busybox",
            "chown",
            HOST_ARTIFACT_OWNER,
            "/artifacts",
        ],
        [
            "docker",
            "run",
            "--rm",
            "-v",
            mount,
            "busybox",
            "chmod",
            "u+rwx",
            "/artifacts",
        ],
    )
    for command in repair_commands:
        subprocess.run(  # noqa: S603
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            check=False,
        )

    if not os.access(artifacts_root, os.W_OK | os.X_OK):
        raise PermissionError(
            f"{artifacts_root} is not writable by the current user; "
            "remove it or fix ownership before running docker/test_pool.py"
        )


def _provider_artifact_globs(providers: list[str]) -> list[str]:
    paths: list[str] = []
    for provider in providers:
        provider_token = shlex.quote(provider)
        paths.extend(
            [
                f"/artifacts/{provider_token}-shard-*",
                f"/artifacts/{provider_token}-pooled",
            ]
        )
    return paths


def _needs_merge_permission_repair(artifacts_root: Path, providers: list[str]) -> bool:
    if not os.access(artifacts_root, os.W_OK | os.X_OK):
        return True
    for provider in providers:
        for shard_dir in artifacts_root.glob(f"{provider}-shard-*"):
            if not os.access(shard_dir, os.R_OK | os.X_OK):
                return True
        pooled_dir = artifacts_root / f"{provider}-pooled"
        if pooled_dir.exists() and not os.access(pooled_dir, os.W_OK | os.X_OK):
            return True
    return False


def repair_artifacts_for_merge(
    project_root: Path, providers: list[str], env: dict[str, str]
) -> None:
    """Repair Docker-created artifact ownership before Python merges shard results."""
    artifacts_root = project_root / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    if not _needs_merge_permission_repair(artifacts_root, providers):
        return

    mount = f"{artifacts_root}:/artifacts"
    provider_paths = " ".join(_provider_artifact_globs(providers))
    owner = shlex.quote(HOST_ARTIFACT_OWNER)
    repair_script = (
        f"chown {owner} /artifacts 2>/dev/null || true; "
        f"chown -R {owner} {provider_paths} 2>/dev/null || true; "
        "chmod u+rwx /artifacts 2>/dev/null || true; "
        f"chmod -R u+rwX {provider_paths} 2>/dev/null || true"
    )
    subprocess.run(  # noqa: S603
        [
            "docker",
            "run",
            "--rm",
            "-v",
            mount,
            "busybox",
            "sh",
            "-c",
            repair_script,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        check=False,
    )
    if not os.access(artifacts_root, os.W_OK | os.X_OK):
        raise PermissionError(
            f"{artifacts_root} is not writable by the current user after Docker cleanup; "
            "remove it or fix ownership before generating pooled results"
        )


def clean_prior_shards(project_root: Path, providers: list[str]) -> None:
    # Remove BOTH the per-shard dirs and the merged *-pooled dir for each
    # provider being run. Clearing -pooled too is essential: if a provider
    # produces nothing this run (build/container failure), a stale -pooled from
    # a previous green run must not be read back and reported as this run's
    # result (which would show a non-running provider as green).
    rm = "".join(f"rm -rf /artifacts/{p}-shard-* /artifacts/{p}-pooled; " for p in providers)
    subprocess.run(  # noqa: S603
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{project_root}/artifacts:/artifacts",
            "busybox",
            "sh",
            "-c",
            rm,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Global mixed pool across PKCS#11 providers.")
    ap.add_argument(
        "-j",
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help="max concurrent containers (K)",
    )
    ap.add_argument("--no-build", action="store_true", help="skip rebuilding provider images")
    ap.add_argument(
        "--all",
        action="store_true",
        help="run the stable tracked set PLUS dev/variant images; excludes heavy/manual targets",
    )
    ap.add_argument(
        "--heavy",
        action="store_true",
        help="run heavy/manual targets only (currently optee-pkcs11)",
    )
    ap.add_argument(
        "--all-heavy",
        action="store_true",
        help="run heavy/manual release and dev/variant targets",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="plan + verify the partition and print the work list; launch nothing",
    )
    ap.add_argument(
        "--duration-artifacts-dir",
        type=Path,
        default=None,
        help=(
            "provider-local artifact root for duration planning "
            "(reads <root>/<provider>-pooled/results.json)"
        ),
    )
    ap.add_argument(
        "--coverage-baseline-artifacts-dir",
        type=Path,
        default=None,
        help=(
            "provider-local artifact root for mechanism coverage regression gating "
            "(compares <root>/<provider>-pooled to artifacts/<provider>-pooled)"
        ),
    )
    ap.add_argument("--testcases", default=TESTCASES)
    ap.add_argument(
        "providers", nargs="*", help="provider or provider:shards (default: stable set)"
    )
    args = ap.parse_args()

    shard_map = dict(SHARD_MAP)
    providers: list[str] = []
    for tok in args.providers:
        name, _, n = tok.partition(":")
        providers.append(name)
        if n:
            shard_map[name] = int(n)
    if not providers:
        if args.all_heavy:
            providers = list(ALL_HEAVY_PROVIDERS)
        elif args.heavy:
            providers = list(HEAVY_PROVIDERS)
        else:
            providers = list(ALL_PROVIDERS if args.all else DEFAULT_PROVIDERS)

    project_root = Path.cwd()
    coverage_baseline_root = (
        resolve_duration_artifacts_root(project_root, args.coverage_baseline_artifacts_dir)
        if args.coverage_baseline_artifacts_dir is not None
        else None
    )
    docker_env = compose_env(project_root)
    host_data_dir = Path(docker_env["PKCS11_CHECK_HOST_DATA_DIR"])
    if not has_vector_data(host_data_dir):
        print_pool_event(
            "WARNING: no test vector data found; full vector-backed collection may be incomplete. "
            "Run: uv run pkcs11-check fetch-data all",
            file=sys.stderr,
        )
    elif "PKCS11_CHECK_HOST_DATA_DIR" not in os.environ and host_data_dir != project_root / "data":
        print_pool_event(f"Using fetched test vector data: {host_data_dir}", file=sys.stderr)

    files = discover_files(args.testcases)
    if not files:
        print_pool_event(f"ERROR: no test_*.py under {args.testcases}", file=sys.stderr)
        return 2
    print_pool_event(
        f"=== global mixed pool: {len(providers)} providers, K={args.concurrency}, "
        f"{len(files)} test files/provider ==="
    )

    if not args.no_build and not args.dry_run:
        for p in providers:
            print_pool_event(f"--- build test-{p} ---")
            _, ok = build_image(p, docker_env)
            if not ok:
                print_pool_event(f"  BUILD FAILED (see /tmp/pool-build-{p}.log)")

    # Shard each provider; verify per-provider partition (nothing forgotten); build work list.
    workitems: list[WorkItem] = []
    for p in providers:
        n = shard_map.get(p, 1)
        provider_files = files_for_provider(p, files, args.testcases)
        durations = duration_oracle_for_provider(
            project_root, p, artifacts_root=args.duration_artifacts_dir
        )
        collection_env = os.environ.copy()
        collection_env["PKCS11_CHECK_DATA_DIR"] = str(host_data_dir)
        provider_units, planning_durations, expanded_files = expand_duration_hot_node_units(
            provider_files,
            durations,
            collection_env=collection_env,
        )
        batches = plan_shards(provider_units, n, duration_by_unit=planning_durations)
        batched = sum(len(b) for b in batches)
        if batched != len(provider_units):
            print_pool_event(
                f"ERROR: {p} partition {batched} != {len(provider_units)} — refusing to drop tests",
                file=sys.stderr,
            )
            return 1
        for i, batch in enumerate(batches):
            load = estimate_shard_load(batch, duration_by_unit=planning_durations)
            workitems.append((p, i, batch, load))
        scope = "slot-0-unique" if len(provider_files) != len(files) else "full"
        balance = "duration-oracle" if durations else "synthetic-heavy"
        unit_count = (
            f"{len(provider_files)} files -> {batched} targets"
            if expanded_files
            else f"{batched} files"
        )
        node_split = f", node-split {len(expanded_files)} file(s)" if expanded_files else ""
        print_pool_event(
            f"  {p}: {n} batch(es), {unit_count} ({scope}, {balance}{node_split}, partition ok)"
        )

    # Longest estimated batches first so the long poles start early.
    workitems = sort_workitems(workitems)

    if args.dry_run:
        print_pool_event(
            f"=== DRY RUN: {len(workitems)} items, K={args.concurrency} (launch nothing) ==="
        )
        for p, i, batch, load in workitems:
            unit_label = "targets" if any("::" in unit for unit in batch) else "files"
            print_pool_event(f"  {p}:{i}  {len(batch)} {unit_label}  load~{load:.1f}s")
        return 0

    ensure_artifacts_root_writable(project_root, docker_env)
    clean_prior_shards(project_root, providers)

    print_pool_event(
        f"=== running {len(workitems)} items through {args.concurrency} workers (mixed) ==="
    )
    start = time.time()
    output_lock = Lock()
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        results = list(ex.map(lambda w: run_workitem(w, docker_env, output_lock), workitems))
    wall = int(time.time() - start)
    nonzero = sum(1 for result in results if result.returncode not in (0, 1))
    if nonzero:
        print_pool_event(
            f"  note: {nonzero} item(s) exited with an unexpected code (see /tmp/pool-*.log)"
        )
    try:
        repair_artifacts_for_merge(project_root, providers, docker_env)
    except PermissionError as exc:
        print_pool_event(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # Merge per provider + comparison summary.
    print()
    shard_time_by_provider: defaultdict[str, float] = defaultdict(float)
    for result in results:
        shard_time_by_provider[result.provider] += result.elapsed_s
    hdr = (
        f"{'provider':<20} {'shards':>6} {'total':>8} {'passed':>8} "
        f"{'failed':>8} {'xfailed':>8} {'crashed':>8} {'timeout':>8} "
        f"{'child_crash':>11} {'child_timeout':>13} {'shard_time':>10}"
    )
    print(hdr)
    print("-" * len(hdr))
    incomplete_results = False
    coverage_loss = False
    for p in providers:
        n = shard_map.get(p, 1)
        dirs = [Path(f"artifacts/{p}-shard-{i}") for i in range(n)]
        # Pass any shard that produced EITHER artifact to the merge: a shard
        # killed (OOM/SIGKILL) between writing report.jsonl (incrementally) and
        # results.json (last) still holds real failed/crashed records in its
        # JSONL, and merge_shard_dirs salvages them from there. Filtering on
        # results.json alone here would silently drop a crashed shard's findings
        # and defeat that salvage.
        present = [
            d for d in dirs if (d / "results.json").exists() or (d / "report.jsonl").exists()
        ]
        complete = sum(1 for d in dirs if (d / "results.json").exists())
        if complete != n:
            incomplete_results = True
            salvageable = len(present) - complete
            print_pool_event(
                f"  WARN: {p} produced {complete}/{n} complete shard results "
                f"({salvageable} salvageable from report.jsonl) — incomplete!",
                file=sys.stderr,
            )
        if present:
            merge_shard_dirs(present, Path(f"artifacts/{p}-pooled"))
        res = Path(f"artifacts/{p}-pooled/results.json")
        shard_time = format_elapsed(shard_time_by_provider[p])
        if res.exists():
            result_payload = json.loads(res.read_text())
            s = result_payload["summary"]
            child_crash, child_timeout = controlled_child_counts(result_payload)
            print(
                f"{p:<20} {n:>6} {s.get('total', 0):>8} {s.get('passed', 0):>8} "
                f"{s.get('failed', 0):>8} {s.get('xfailed', 0):>8} "
                f"{s.get('crashed', 0):>8} {s.get('timeout', 0):>8} "
                f"{child_crash:>11} {child_timeout:>13} {shard_time:>10}"
            )
        else:
            incomplete_results = True
            print(
                f"{p:<20} {n:>6} {'NO-RESULTS':>8} {'':>8} {'':>8} "
                f"{'':>8} {'':>8} {'':>8} {'':>11} {'':>13} {shard_time:>10}"
            )
        if coverage_baseline_root is not None:
            status, comparison = compare_provider_coverage(
                project_root,
                p,
                baseline_artifacts_root=coverage_baseline_root,
            )
            if status == "missing-baseline":
                print_pool_event(f"  coverage-baseline {p}: no provider-local baseline (skipped)")
            elif status == "missing-candidate":
                coverage_loss = True
                print_pool_event(f"  COVERAGE LOSS {p}: candidate coverage missing")
            elif comparison is not None and comparison.get("has_loss"):
                coverage_loss = True
                print_pool_event(f"  COVERAGE LOSS {p}:")
                lost_by_state = comparison.get("lost_by_state", {})
                if isinstance(lost_by_state, Mapping):
                    for state, names in sorted(lost_by_state.items()):
                        if isinstance(names, list) and names:
                            print_pool_event(f"    {state}: {', '.join(str(n) for n in names)}")
            else:
                print_pool_event(f"  coverage-baseline {p}: ok")

    print_pool_event(
        f"=== GLOBAL wall: {wall // 60}m{wall % 60}s for {len(providers)} providers / "
        f"{len(workitems)} items / K={args.concurrency} ==="
    )
    return 1 if nonzero or incomplete_results or coverage_loss else 0


if __name__ == "__main__":
    sys.exit(main())
