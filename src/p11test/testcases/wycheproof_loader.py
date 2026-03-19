"""Wycheproof vector loader utility.

Provides a unified interface for loading and flattening Wycheproof test vectors.
The vectors are stored in the C2SP/wycheproof git submodule at:
  vectors/wycheproof/testvectors_v1/

Usage:
    from p11test.testcases.wycheproof_loader import load_vectors, WYCHEPROOF_DIR

    vectors = load_vectors("aes_gcm_test.json")
    # Returns list of dicts, each with _group metadata attached

References:
    - https://github.com/C2SP/wycheproof
    - https://github.com/awslabs/pkcs11-runners-for-project-wycheproof (prior art)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from p11test.testcases.data import WYCHEPROOF_DIR  # noqa: E402


def load_vectors(filename: str) -> list[dict[str, Any]]:
    """Load and flatten a Wycheproof JSON test vector file.

    Returns a list of individual test vectors, each enriched with
    a '_group' key containing the parent testGroup metadata.

    Returns empty list if the file doesn't exist (graceful degradation).
    """
    path = WYCHEPROOF_DIR / filename
    if not path.exists():
        return []
    with open(path) as f:
        data = json.load(f)
    vectors: list[dict[str, Any]] = []
    for group in data.get("testGroups", []):
        group_meta = {k: v for k, v in group.items() if k != "tests"}
        for test in group.get("tests", []):
            test["_group"] = group_meta
            vectors.append(test)
    return vectors


def vec_id(vec: dict[str, Any]) -> str:
    """Generate a human-readable test ID from a Wycheproof vector."""
    return f"tc{vec['tcId']}-{vec['result']}"


def available_files() -> list[str]:
    """List all available Wycheproof vector files."""
    if not WYCHEPROOF_DIR.exists():
        return []
    return sorted(f.name for f in WYCHEPROOF_DIR.glob("*.json"))
