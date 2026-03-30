"""Centralized test data paths — single source of truth.

Own data (mechanism_vectors, KAT JSONs) lives here in src/.
Third-party vendor data lives in root data/, fetched by scripts/fetch-data.sh.
"""
from __future__ import annotations

import os
from pathlib import Path

# Own data (tracked in git, part of the package)
DATA_DIR = Path(__file__).parent
KAT_DIR = DATA_DIR


def _find_project_root() -> Path:
    """Walk up to find pyproject.toml (project root marker)."""
    p = Path(__file__).resolve().parent
    while p != p.parent:
        if (p / "pyproject.toml").exists():
            return p
        p = p.parent
    return Path.cwd()


# Third-party vendor data (root data/, fetched by scripts/fetch-data.sh)
# Override with PKCS11_CHECK_DATA_DIR env var for CI/Docker/worktrees.
_VENDOR_DIR = Path(os.environ.get(
    "PKCS11_CHECK_DATA_DIR",
    str(_find_project_root() / "data"),
))

WYCHEPROOF_DIR = _VENDOR_DIR / "wycheproof" / "testvectors_v1"
CCTV_DIR = _VENDOR_DIR / "cctv"
ACVP_DIR = _VENDOR_DIR / "acvp" / "gen-val" / "json-files"
X509_LIMBO_DIR = _VENDOR_DIR / "x509-limbo"
