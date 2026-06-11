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
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pkcs11_check.core.merge import merge_shard_dirs
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
DEFAULT_CONCURRENCY = 6
WorkItem = tuple[str, int, list[str], float]

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


def duration_oracle_for_provider(project_root: Path, provider: str) -> dict[str, float] | None:
    """Return provider-local per-file durations from the previous pooled artifact."""
    prior_results = project_root / "artifacts" / f"{provider}-pooled" / "results.json"
    if not prior_results.exists():
        return None
    durations = duration_by_unit_from_results(prior_results)
    return durations or None


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


def run_item(
    provider: str, idx: int, files: list[str], env: dict[str, str]
) -> tuple[str, int, int]:
    """Run one (provider, batch) container. Returns (provider, idx, returncode)."""
    log = Path(f"/tmp/pool-{provider}-{idx}.log")
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
    docker_env = compose_env(project_root)
    host_data_dir = Path(docker_env["PKCS11_CHECK_HOST_DATA_DIR"])
    if not has_vector_data(host_data_dir):
        print(
            "WARNING: no test vector data found; full vector-backed collection may be incomplete. "
            "Run: uv run pkcs11-check fetch-data all",
            file=sys.stderr,
        )
    elif "PKCS11_CHECK_HOST_DATA_DIR" not in os.environ and host_data_dir != project_root / "data":
        print(f"Using fetched test vector data: {host_data_dir}", file=sys.stderr)

    files = discover_files(args.testcases)
    if not files:
        print(f"ERROR: no test_*.py under {args.testcases}", file=sys.stderr)
        return 2
    print(
        f"=== global mixed pool: {len(providers)} providers, K={args.concurrency}, "
        f"{len(files)} test files/provider ==="
    )

    if not args.no_build and not args.dry_run:
        for p in providers:
            print(f"--- build test-{p} ---")
            _, ok = build_image(p, docker_env)
            if not ok:
                print(f"  BUILD FAILED (see /tmp/pool-build-{p}.log)")

    # Shard each provider; verify per-provider partition (nothing forgotten); build work list.
    workitems: list[WorkItem] = []
    for p in providers:
        n = shard_map.get(p, 1)
        provider_files = files_for_provider(p, files, args.testcases)
        durations = duration_oracle_for_provider(project_root, p)
        batches = plan_shards(provider_files, n, duration_by_unit=durations)
        batched = sum(len(b) for b in batches)
        if batched != len(provider_files):
            print(
                f"ERROR: {p} partition {batched} != {len(provider_files)} — refusing to drop tests",
                file=sys.stderr,
            )
            return 1
        for i, batch in enumerate(batches):
            load = estimate_shard_load(batch, duration_by_unit=durations)
            workitems.append((p, i, batch, load))
        scope = "slot-0-unique" if len(provider_files) != len(files) else "full"
        balance = "duration-oracle" if durations else "synthetic-heavy"
        print(
            f"  {p}: {n} batch(es), {batched} files "
            f"({scope}, {balance}, partition ok)"
        )

    # Longest estimated batches first so the long poles start early.
    workitems = sort_workitems(workitems)

    if args.dry_run:
        print(f"=== DRY RUN: {len(workitems)} items, K={args.concurrency} (launch nothing) ===")
        for p, i, batch, load in workitems:
            print(f"  {p}:{i}  {len(batch)} files  load~{load:.1f}s")
        return 0

    clean_prior_shards(project_root, providers)

    print(f"=== running {len(workitems)} items through {args.concurrency} workers (mixed) ===")
    start = time.time()
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        results = list(ex.map(lambda w: run_item(w[0], w[1], w[2], docker_env), workitems))
    wall = int(time.time() - start)
    nonzero = sum(1 for _, _, rc in results if rc not in (0, 1))  # 1 == failing tests (expected)
    if nonzero:
        print(f"  note: {nonzero} item(s) exited with an unexpected code (see /tmp/pool-*.log)")

    # Merge per provider + comparison summary.
    print()
    hdr = (
        f"{'provider':<20} {'shards':>6} {'total':>8} {'passed':>8} "
        f"{'failed':>8} {'crashed':>8} {'timeout':>8}"
    )
    print(hdr)
    print("-" * len(hdr))
    incomplete_results = False
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
            print(
                f"  WARN: {p} produced {complete}/{n} complete shard results "
                f"({salvageable} salvageable from report.jsonl) — incomplete!",
                file=sys.stderr,
            )
        if present:
            merge_shard_dirs(present, Path(f"artifacts/{p}-pooled"))
        res = Path(f"artifacts/{p}-pooled/results.json")
        if res.exists():
            s = json.loads(res.read_text())["summary"]
            print(
                f"{p:<20} {n:>6} {s.get('total', 0):>8} {s.get('passed', 0):>8} "
                f"{s.get('failed', 0):>8} {s.get('crashed', 0):>8} {s.get('timeout', 0):>8}"
            )
        else:
            incomplete_results = True
            print(f"{p:<20} {n:>6} {'NO-RESULTS':>8}")

    print(
        f"=== GLOBAL wall: {wall // 60}m{wall % 60}s for {len(providers)} providers / "
        f"{len(workitems)} items / K={args.concurrency} ==="
    )
    return 1 if nonzero or incomplete_results else 0


if __name__ == "__main__":
    sys.exit(main())
