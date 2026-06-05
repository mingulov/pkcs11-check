"""Centralized test data paths -- single source of truth.

Own data (mechanism_vectors, KAT JSONs) lives here in src/.
Third-party vendor data lives in a resolved data directory.
"""

from __future__ import annotations

import hashlib
import json
import marshal
import os
import sys
import tempfile
from functools import cache
from pathlib import Path
from typing import Any

from pkcs11_check.core.cache_paths import secure_cache_dir

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

# Cache for parsed vector JSON, keyed by source mtime+size. The JSON files stay
# the source of truth; the cache is a regenerable sidecar that avoids re-parsing
# large vector files in every isolated subprocess.
# marshal (not pickle) is used deliberately: the cached data is pure JSON
# (dicts/lists/scalars), and marshal -- unlike pickle -- cannot execute
# arbitrary code on load. The cache lives in a private, owner-only directory
# (never /tmp), is versioned + keyed by (mtime, size), and falls back to JSON on
# any error. See docs/findings/test-execution-speedup-gap-analysis-2026-06-04.md.
_VECTOR_CACHE_VERSION = 1
# marshal format is Python-version specific; key on the interpreter too so an
# upgrade transparently rebuilds the cache instead of erroring.
_VECTOR_CACHE_TAG = (_VECTOR_CACHE_VERSION, sys.hexversion)


@cache
def _vector_cache_dir() -> Path | None:
    return secure_cache_dir("vectors")


def _vector_cache_path(source: Path) -> Path | None:
    cache_dir = _vector_cache_dir()
    if cache_dir is None:
        return None
    key = hashlib.sha256(str(source.resolve()).encode("utf-8")).hexdigest()
    return cache_dir / f"{key}.marshal"


def _write_vector_cache(cache: Path, key: tuple[Any, ...], data: Any) -> None:
    """Atomically write the cache; best-effort (never break the caller)."""
    try:
        fd, tmp = tempfile.mkstemp(dir=cache.parent, suffix=".tmp")
    except OSError:
        return
    try:
        with os.fdopen(fd, "wb") as f:
            marshal.dump((key, data), f)
        os.replace(tmp, cache)
    except (OSError, ValueError):
        Path(tmp).unlink(missing_ok=True)


def load_json_cached(path: str | Path) -> Any:
    """``json.load`` a vector file, backed by a marshal cache keyed by mtime+size.

    The returned data is identical to ``json.load``; the cache only avoids the
    (much slower) JSON re-parse on repeated/isolated runs. Any cache miss,
    staleness, or corruption transparently falls back to parsing the JSON.
    """
    source = Path(path)
    try:
        st = source.stat()
    except OSError:
        with source.open(encoding="utf-8") as f:
            return json.load(f)
    key = (*_VECTOR_CACHE_TAG, st.st_mtime_ns, st.st_size)
    cache = _vector_cache_path(source)
    if cache is not None:
        try:
            with cache.open("rb") as f:
                stored_key, data = marshal.load(f)  # noqa: S302 - basic types only, no code exec
            if stored_key == key:
                return data
        except (OSError, EOFError, ValueError, TypeError):
            pass  # cold, stale, or corrupt cache -> reparse below
    with source.open(encoding="utf-8") as f:
        data = json.load(f)
    if cache is not None:
        _write_vector_cache(cache, key, data)
    return data
