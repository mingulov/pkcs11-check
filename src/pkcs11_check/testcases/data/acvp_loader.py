"""ACVP test vector loader -- adapter for NIST ACVP-Server JSON format.

ACVP format: each algorithm has prompt.json (inputs) + expectedResults.json (outputs).
This loader merges them into a unified list of test dicts.

Usage:
    from pkcs11_check.testcases.data.acvp_loader import load_acvp_vectors, ACVP_AVAILABLE

    if not ACVP_AVAILABLE:
        pytest.skip("ACVP vectors not cloned")

    vectors = load_acvp_vectors("SLH-DSA-SHA2-128s-sigGen")
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pkcs11_check.testcases.data import ACVP_DIR

ACVP_AVAILABLE = ACVP_DIR.exists()


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
        with open(pf) as f:
            prompt = json.load(f)
        with open(rf) as f:
            results = json.load(f)

        # Merge prompt test groups with expected results
        p_groups = prompt.get("testGroups", [])
        r_groups = results.get("testGroups", [])

        for pg, rg in zip(p_groups, r_groups):
            p_tests = pg.get("tests", [])
            r_tests = rg.get("tests", [])
            group_meta = {k: v for k, v in pg.items() if k != "tests"}

            for pt, rt in zip(p_tests, r_tests):
                vectors.append({
                    "input": pt,
                    "expected": rt,
                    "group": group_meta,
                    "algorithm": algorithm,
                })

    return vectors


def list_acvp_algorithms() -> list[str]:
    """List available ACVP algorithm directories."""
    if not ACVP_AVAILABLE:
        return []
    return sorted(d.name for d in ACVP_DIR.iterdir() if d.is_dir())
