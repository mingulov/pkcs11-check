"""Balance test files across N shards for parallel multi-container runs.

Sharding is at **whole-file** granularity (preserves per-file isolation and
file-scoped fixtures). Balance uses Longest-Processing-Time-first (LPT)
bin-packing over per-file durations from a prior run's ``results.json`` so the
heavy files (e.g. the ACVP-AES MCT files, ~11 min each on slow modules) are spread
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


# Files known to dominate wall time on transport-bound providers: the ACVP-AES
# MCT cases run ~100k chained ops (~11 min each on slow modules) and are indivisible
# at file granularity. Lacking a measured duration, they get a synthetic weight so
# the balancer ISOLATES them into separate batches instead of lumping them (which
# produces a straggler batch). Provider-agnostic: with a real oracle a measured
# duration wins (a file a provider skips stays light); on a first run a skipped
# heavy file just yields an instant batch the pool immediately moves past.
DEFAULT_HEAVY_BASENAMES: tuple[str, ...] = (
    # AES multi-block-chained (MCT) cases: ~11 min each on transport-bound
    # providers, and other large ACVP-AES corpora.
    "test_cfb8.py",
    "test_ofb.py",
    "test_cfb128.py",
    "test_ccm.py",
    "test_cts.py",
    "test_wrap.py",
    # Recurring long poles the count-balancer would otherwise lump into one
    # straggler batch (e.g. test_parameter_validation.py ~553s on slow modules,
    # 16s elsewhere; the big Wycheproof/ACVP/DSA corpora). A curated, static,
    # provider-agnostic list — NOT measured durations (those don't transfer
    # across providers, which depend on advertised mechanisms).
    "test_parameter_validation.py",
    "test_wycheproof_ecdsa.py",
    "test_wycheproof_ecdh.py",
    "test_wycheproof_rsa.py",
    "test_acvp_rsa.py",
    "test_dsa_complete.py",
)
_HEAVY_WEIGHT_SECONDS = 660.0


def _fallback_duration(duration_by_unit: dict[str, float]) -> float:
    known = [d for d in duration_by_unit.values() if d > 0]
    return statistics.median(known) if known else 1.0


def estimate_unit_weight(
    unit: str,
    *,
    duration_by_unit: dict[str, float] | None = None,
    heavy_basenames: tuple[str, ...] | None = DEFAULT_HEAVY_BASENAMES,
) -> float:
    """Return the balancing weight for one test-file unit."""
    durations = duration_by_unit or {}
    if unit in durations:
        return max(durations[unit], 0.0)
    if unit.rsplit("/", 1)[-1] in set(heavy_basenames or ()):
        return _HEAVY_WEIGHT_SECONDS
    return _fallback_duration(durations)


def estimate_shard_load(
    units: list[str],
    *,
    duration_by_unit: dict[str, float] | None = None,
    heavy_basenames: tuple[str, ...] | None = DEFAULT_HEAVY_BASENAMES,
) -> float:
    """Estimate a shard's total load using the same weights as ``plan_shards``."""
    return sum(
        estimate_unit_weight(
            unit,
            duration_by_unit=duration_by_unit,
            heavy_basenames=heavy_basenames,
        )
        for unit in units
    )


def plan_shards(
    units: list[str],
    num_shards: int,
    *,
    duration_by_unit: dict[str, float] | None = None,
    heavy_basenames: tuple[str, ...] | None = DEFAULT_HEAVY_BASENAMES,
) -> list[list[str]]:
    """Partition ``units`` into ``num_shards`` balanced groups (LPT).

    Returns a list of ``num_shards`` lists. Deterministic: ties broken by unit
    name so the same inputs always produce the same shards. Known-heavy files
    (``heavy_basenames``) lacking a measured duration are weighted so they land in
    separate batches rather than concentrating in one (straggler avoidance);
    pass ``heavy_basenames=None`` to disable.
    """
    if num_shards < 1:
        raise ValueError("num_shards must be >= 1")
    if num_shards == 1:
        return [list(units)]

    weights = {
        unit: estimate_unit_weight(
            unit,
            duration_by_unit=duration_by_unit,
            heavy_basenames=heavy_basenames,
        )
        for unit in units
    }

    shards: list[list[str]] = [[] for _ in range(num_shards)]
    loads = [0.0] * num_shards
    # Heaviest first; tie-break on name for determinism.
    for unit in sorted(units, key=lambda u: (-weights[u], u)):
        target = min(range(num_shards), key=lambda i: (loads[i], i))
        shards[target].append(unit)
        loads[target] += weights[unit]
    return shards
