"""Aggregate hollow-pass execution-coverage oracle.

A green pass must mean the claimed operation actually ran. This post-run oracle compares,
per PKCS#11 operation, the number of tests that PASSED claiming to exercise it against the
number of PRODUCTIVE (CKR_OK) invocations of that operation. Each passing op-test invokes
the op at least once, so a healthy ratio is >= 1; a large claimed-pass population with a
near-zero ratio means most of those green passes never actually ran the op (the kmsp11
"C_Sign ran once in 110k tests, yet green" pattern). It is a run-quality finding for triage,
not a provider-bug accusation. See docs/.../hollow-pass-coverage-oracle-design.md.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

_DEFAULT_MIN_POPULATION = 20
_DEFAULT_RATIO_THRESHOLD = 0.10


@dataclass(frozen=True)
class HollowCoverageFinding:
    """One operation whose passing tests did not productively exercise it."""

    operation: str
    claimed_passes: int
    productive_ok: int
    ratio: float


def assess_hollow_coverage(
    claimed_passes: Mapping[str, int],
    productive_ok: Mapping[str, int],
    *,
    min_population: int = _DEFAULT_MIN_POPULATION,
    ratio_threshold: float = _DEFAULT_RATIO_THRESHOLD,
    family_map: Mapping[str, frozenset[str]] | None = None,
) -> list[HollowCoverageFinding]:
    """Flag operations whose passing tests did not productively invoke them.

    Args:
        claimed_passes: operation -> count of tests that passed claiming to exercise it.
        productive_ok: C_* function name -> count of CKR_OK invocations.
        min_population: ignore operations with fewer claimed passes (too small to judge).
        ratio_threshold: flag when productive/claimed < this (healthy is >= 1).
        family_map: optional operation -> set of function names whose productive counts sum
            for it (e.g. a "C_Sign" claim satisfied by C_SignInit/C_Sign/C_SignUpdate/Final).
            Operations absent from the map use their own name.

    Returns findings sorted most-hollow (lowest ratio) first.
    """
    findings: list[HollowCoverageFinding] = []
    for operation, claimed in claimed_passes.items():
        if claimed < min_population:
            continue
        funcs = family_map.get(operation) if family_map else None
        if funcs:
            produced = sum(productive_ok.get(fn, 0) for fn in funcs)
        else:
            produced = productive_ok.get(operation, 0)
        ratio = produced / claimed  # claimed >= min_population >= 1, so no ZeroDivision
        if ratio < ratio_threshold:
            findings.append(
                HollowCoverageFinding(
                    operation=operation,
                    claimed_passes=claimed,
                    productive_ok=produced,
                    ratio=ratio,
                )
            )
    findings.sort(key=lambda f: f.ratio)
    return findings
