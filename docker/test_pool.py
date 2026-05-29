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
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pkcs11_check.core.merge import merge_shard_dirs
from pkcs11_check.core.sharding import plan_shards

# Editable per-provider shard counts; providers not listed default to 1 (undivided).
SHARD_MAP: dict[str, int] = {"bouncyhsm": 8, "opencryptoki": 3}
DEFAULT_PROVIDERS = [
    "softhsm2",
    "kryoptic",
    "nss",
    "nss-pqc",
    "opencryptoki",
    "bouncyhsm",
    "pkcs11-mock",
    "tpm2",
]
TESTCASES = "src/pkcs11_check/testcases"
COMPOSE = ["docker", "compose", "-f", "docker/docker-compose.test.yml"]


def discover_files(testcases: str) -> list[str]:
    return sorted(str(p) for p in Path(testcases).rglob("test_*.py"))


def build_image(provider: str) -> tuple[str, bool]:
    log = Path(f"/tmp/pool-build-{provider}.log")
    with log.open("w") as fh:
        rc = subprocess.run(  # noqa: S603
            [*COMPOSE, "build", f"test-{provider}"], stdout=fh, stderr=subprocess.STDOUT
        ).returncode
    return provider, rc == 0


def run_item(provider: str, idx: int, files: list[str]) -> tuple[str, int, int]:
    """Run one (provider, batch) container. Returns (provider, idx, returncode)."""
    log = Path(f"/tmp/pool-{provider}-{idx}.log")
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
                f"test-{provider}",
            ],
            stdout=fh,
            stderr=subprocess.STDOUT,
        ).returncode
    return provider, idx, rc


def clean_prior_shards(project_root: Path, providers: list[str]) -> None:
    rm = "".join(f"rm -rf /artifacts/{p}-shard-*; " for p in providers)
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
        "-j", "--concurrency", type=int, default=3, help="max concurrent containers (K)"
    )
    ap.add_argument("--no-build", action="store_true", help="skip rebuilding provider images")
    ap.add_argument(
        "--dry-run", action="store_true",
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
        providers = list(DEFAULT_PROVIDERS)

    project_root = Path.cwd()
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
            _, ok = build_image(p)
            if not ok:
                print(f"  BUILD FAILED (see /tmp/pool-build-{p}.log)")

    # Shard each provider; verify per-provider partition (nothing forgotten); build work list.
    workitems: list[tuple[str, int, list[str]]] = []
    for p in providers:
        n = shard_map.get(p, 1)
        batches = plan_shards(files, n)  # count-balanced (even chunks); pool absorbs imbalance
        batched = sum(len(b) for b in batches)
        if batched != len(files):
            print(
                f"ERROR: {p} partition {batched} != {len(files)} — refusing to drop tests",
                file=sys.stderr,
            )
            return 1
        for i, batch in enumerate(batches):
            workitems.append((p, i, batch))
        print(f"  {p}: {n} batch(es), {batched} files (partition ok)")

    # Heaviest-provider-first so the long poles start early (the pool consumes in order).
    workitems.sort(key=lambda w: -shard_map.get(w[0], 1))

    if args.dry_run:
        print(f"=== DRY RUN: {len(workitems)} items, K={args.concurrency} (launch nothing) ===")
        for p, i, batch in workitems:
            print(f"  {p}:{i}  {len(batch)} files")
        return 0

    clean_prior_shards(project_root, providers)

    print(f"=== running {len(workitems)} items through {args.concurrency} workers (mixed) ===")
    start = time.time()
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        results = list(ex.map(lambda w: run_item(*w), workitems))
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
    for p in providers:
        n = shard_map.get(p, 1)
        dirs = [Path(f"artifacts/{p}-shard-{i}") for i in range(n)]
        present = [d for d in dirs if (d / "results.json").exists()]
        if len(present) != n:
            print(
                f"  WARN: {p} produced {len(present)}/{n} shard results — incomplete!",
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
            print(f"{p:<20} {n:>6} {'NO-RESULTS':>8}")

    print(
        f"=== GLOBAL wall: {wall // 60}m{wall % 60}s for {len(providers)} providers / "
        f"{len(workitems)} items / K={args.concurrency} ==="
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
