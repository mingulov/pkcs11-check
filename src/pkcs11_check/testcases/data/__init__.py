"""Centralized test data paths — single source of truth.

Own data (mechanism_vectors, KAT JSONs) lives here in src/.
Third-party vendor data lives in a resolved data directory.
"""

from __future__ import annotations

import os
from pathlib import Path

# Own data (tracked in git, part of the package)
DATA_DIR = Path(__file__).parent
KAT_DIR = DATA_DIR

# Path to the bundled sources.toml manifest
SOURCES_TOML = DATA_DIR / "sources.toml"

_XDG_DATA_DIR = Path.home() / ".local" / "share" / "pkcs11-check" / "data"


def _find_project_root() -> Path | None:
    """Walk up to find pyproject.toml (project root marker)."""
    p = Path(__file__).resolve().parent
    while p != p.parent:
        if (p / "pyproject.toml").exists():
            return p
        p = p.parent
    return None


def _find_repo_data_dir() -> Path | None:
    """Find repo-root data/ dir if we're running from the repo."""
    root = _find_project_root()
    if root is None:
        return None
    data = root / "data"
    # Only use repo data dir if it has fetched content (not just .gitignore)
    if data.is_dir() and any(p.is_dir() and p.name != "__pycache__" for p in data.iterdir()):
        return data
    return None


def resolve_data_dir() -> Path:
    """Resolve the third-party vendor data directory.

    Resolution order:
    1. PKCS11_CHECK_DATA_DIR env var
    2. Repo root data/ dir (dev mode, if fetched content exists)
    3. ~/.local/share/pkcs11-check/data/ (XDG default)
    """
    env = os.environ.get("PKCS11_CHECK_DATA_DIR")
    if env:
        return Path(env)

    repo_dir = _find_repo_data_dir()
    if repo_dir is not None:
        return repo_dir

    return _XDG_DATA_DIR


# Resolved vendor data directory
_VENDOR_DIR = resolve_data_dir()

WYCHEPROOF_DIR = _VENDOR_DIR / "wycheproof" / "testvectors_v1"
CCTV_DIR = _VENDOR_DIR / "cctv"
ACVP_DIR = _VENDOR_DIR / "acvp" / "gen-val" / "json-files"
X509_LIMBO_DIR = _VENDOR_DIR / "x509-limbo"
