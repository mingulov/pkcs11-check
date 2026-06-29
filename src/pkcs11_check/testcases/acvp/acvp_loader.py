"""ACVP test vector loader - adapter for NIST ACVP-Server JSON format.

ACVP format: each algorithm has prompt.json (inputs) + expectedResults.json (outputs).
This loader merges them into a unified list of test dicts.

Usage:
    from pkcs11_check.testcases.acvp.acvp_loader import load_acvp_vectors, ACVP_AVAILABLE

    if not ACVP_AVAILABLE:
        pytest.skip("ACVP vectors not cloned")

    vectors = load_acvp_vectors("SLH-DSA-SHA2-128s-sigGen")
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.testcases.data import ACVP_DIR, load_json_cached

ACVP_AVAILABLE = ACVP_DIR.exists()


def require_acvp_vectors() -> None:
    """Skip the calling test module when ACVP vectors are not present.

    Call this at the module scope of a *leaf test module* only. pytest catches a
    ``Skipped(allow_module_level=True)`` raised while it imports a test module
    during collection, marking that module skipped. Do NOT call it from a helper
    that is imported eagerly (a package ``__init__`` re-export, a ``conftest``, or
    a module one of those pulls in): the skip would then fire outside the
    collection path, where pytest does not catch it, and crash ``pytest.main()``
    instead of skipping (regression: tests/test_acvp_collection_no_data.py).
    """
    if not ACVP_AVAILABLE:
        pytest.skip(
            "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
            allow_module_level=True,
        )


def _find_vector_dir(algorithm: str) -> Path | None:
    """Find the vector directory for an algorithm."""
    # ACVP_DIR already points to gen-val/json-files/
    candidate = ACVP_DIR / algorithm
    if candidate.exists():
        return candidate
    return None


def load_acvp_vectors(algorithm: str) -> list[dict[str, Any]]:
    """Load ACVP vectors for an algorithm.

    Returns list of dicts with:
    - 'input': the prompt test case
    - 'expected': the expected result
    - 'group': the test group metadata
    - 'algorithm': algorithm name
    """
    vec_dir = _find_vector_dir(algorithm)
    if vec_dir is None:
        return []

    # Find prompt and expected results
    prompt_files = sorted(vec_dir.glob("prompt*.json"))
    result_files = sorted(vec_dir.glob("expectedResults*.json"))

    if not prompt_files or not result_files:
        return []

    vectors = []
    for pf, rf in zip(prompt_files, result_files):
        prompt = load_json_cached(pf)
        results = load_json_cached(rf)

        # Merge prompt test groups with expected results
        p_groups = prompt.get("testGroups", [])
        r_groups = results.get("testGroups", [])

        for pg, rg in zip(p_groups, r_groups):
            p_tests = pg.get("tests", [])
            r_tests = rg.get("tests", [])
            # Merge metadata from both prompt and results groups
            group_meta = {k: v for k, v in pg.items() if k != "tests"}
            group_meta.update({k: v for k, v in rg.items() if k != "tests" and k not in group_meta})

            for pt, rt in zip(p_tests, r_tests):
                merged: dict[str, Any] = {
                    "input": pt,
                    "expected": rt,
                    "group": group_meta,
                    "algorithm": algorithm,
                }
                merged["_source"] = f"acvp:{algorithm}"
                merged["_vector_id"] = f"tcId={pt.get('tcId')}"
                vectors.append(merged)

    return vectors


def list_acvp_algorithms() -> list[str]:
    """List available ACVP algorithm directories."""
    if not ACVP_AVAILABLE:
        return []
    return sorted(d.name for d in ACVP_DIR.iterdir() if d.is_dir())
