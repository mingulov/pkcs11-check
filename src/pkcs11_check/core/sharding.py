"""Balance test files across N shards for parallel multi-container runs.

Sharding is at **whole-file** granularity (preserves per-file isolation and
file-scoped fixtures). Balance uses Longest-Processing-Time-first (LPT)
bin-packing over per-file durations from a prior run's ``results.json`` so the
heavy files (e.g. the ACVP-AES MCT files, ~11 min each on bouncyhsm) are spread
across shards rather than piling onto one — the difference between a ~Nx and a
~2x speedup. Files with no known duration get the median (so a first run with
no history still balances by count).
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path


def duration_by_unit_from_results(results_path: Path) -> dict[str, float]:
    """Extract per-unit (file) wall durations from a prior ``results.json``."""
    payload = json.loads(results_path.read_text())
    out: dict[str, float] = {}
    for unit in payload.get("units", []) or []:
        target = unit.get("target")
        if isinstance(target, str):
            # Use the file part (strip any ::nodeid) so per-test units fold in.
            out[target.split("::", 1)[0]] = out.get(target.split("::", 1)[0], 0.0) + float(
                unit.get("duration_s", 0.0) or 0.0
            )
    return out


def plan_shards(
    units: list[str],
    num_shards: int,
    *,
    duration_by_unit: dict[str, float] | None = None,
) -> list[list[str]]:
    """Partition ``units`` into ``num_shards`` balanced groups (LPT).

    Returns a list of ``num_shards`` lists. Deterministic: ties broken by unit
    name so the same inputs always produce the same shards.
    """
    if num_shards < 1:
        raise ValueError("num_shards must be >= 1")
    if num_shards == 1:
        return [list(units)]

    durations = duration_by_unit or {}
    known = [d for d in durations.values() if d > 0]
    fallback = statistics.median(known) if known else 1.0

    def weight(unit: str) -> float:
        return durations.get(unit, fallback) or fallback

    shards: list[list[str]] = [[] for _ in range(num_shards)]
    loads = [0.0] * num_shards
    # Heaviest first; tie-break on name for determinism.
    for unit in sorted(units, key=lambda u: (-weight(u), u)):
        target = min(range(num_shards), key=lambda i: (loads[i], i))
        shards[target].append(unit)
        loads[target] += weight(unit)
    return shards
