"""Pytest collection metadata helpers for isolation planning."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

import pytest

from pkcs11_check.core.cache_paths import secure_cache_dir
from pkcs11_check.core.collection_errors import collection_failure_message
from pkcs11_check.core.nodeids import item_nodeid

# Collection-metadata cache (Lever 2 of the speedup gap analysis). The full
# --collect-only pass over ~106k items costs ~13-18s but its result changes only
# when an input that affects collection changes. We key a cache on a digest of
# ALL such inputs -- every .py in the package, every vendor vector file, the
# collection-affecting pytest args, and the tool/interpreter versions -- so a
# cache hit provably yields identical collection. Any change (or any error
# computing the digest) falls back to a fresh collection: the cache can never
# drop or alter a test. The cache lives in a private owner-only dir (never /tmp,
# which is world-writable) and is stored as plain JSON (no code-object surface).
# Disable with PKCS11_CHECK_NO_COLLECTION_CACHE=1.
_CACHE_FORMAT = 4
_PACKAGE_DIR = Path(__file__).resolve().parents[1]
# pytest args that name a per-run temp file and do NOT affect which items are
# collected (the manifest is only consulted at runtime, never during
# --collect-only). Excluded from the digest so a fresh manifest path each run
# does not defeat the cache.
_VOLATILE_ARG_FLAGS = frozenset({"--p11-manifest"})


def _collection_cache_dir() -> Path | None:
    return secure_cache_dir("collection")


def _digest_args(pytest_args: list[str]) -> list[str]:
    """Drop volatile (per-run temp path) flag/value pairs from the digest args."""
    out: list[str] = []
    skip_next = False
    for arg in pytest_args:
        if skip_next:
            skip_next = False
            continue
        flag = arg.split("=", 1)[0]
        if flag in _VOLATILE_ARG_FLAGS:
            skip_next = "=" not in arg  # "--flag value" form consumes the next token
            continue
        out.append(arg)
    return out


def _iter_input_files(data_dir_override: str | None = None) -> list[Path]:
    """All files whose content can change what pytest collects: package source
    plus the resolved vendor vector data.

    `data_dir_override` is the child env's PKCS11_CHECK_DATA_DIR (see
    `_collection_inputs_digest`): the digest runs in the parent but collection
    runs in the child, so the walked tree must be the child's effective one.
    """
    files = list(_PACKAGE_DIR.rglob("*.py"))
    if data_dir_override:
        # Child resolves vendor data elsewhere: walk the effective tree (whole
        # dir, layout-agnostic) so content changes there invalidate the cache.
        override = Path(data_dir_override)
        if override.exists():
            files.extend(p for p in override.rglob("*") if p.is_file())
        return files
    # Deliberate lazy import of the test-vector data roots: the collection cache must know
    # which data dirs affect collection to invalidate correctly (an inherent cache<->data
    # coupling), and those roots belong in testcases.data. Importing at call time keeps it a
    # localised seam and avoids a core<->testcases import cycle at module load.
    from pkcs11_check.testcases.data import (
        ACVP_DIR,
        CCTV_DIR,
        WYCHEPROOF_DIR,
        X509_LIMBO_DIR,
    )

    for data_dir in (WYCHEPROOF_DIR, ACVP_DIR, CCTV_DIR, X509_LIMBO_DIR):
        if data_dir.exists():
            files.extend(p for p in data_dir.rglob("*") if p.is_file())
    return files


def _collection_inputs_digest(
    targets: list[str],
    pytest_args: list[str],
    data_dir_override: str | None = None,
) -> str | None:
    """Digest every input that affects collection, or None to bypass the cache.

    `data_dir_override` is the collecting child's PKCS11_CHECK_DATA_DIR: the
    digest runs in the parent while collection runs in the child, so without
    it two children with different data dirs would alias to one cache entry
    (stale fetch-then-test ordering). The override string itself is digested
    so distinct-but-empty dirs still key apart.
    """
    try:
        from pkcs11_check import __version__ as pkg_version

        parts = [
            f"fmt={_CACHE_FORMAT}",
            f"py={sys.hexversion}",
            f"pytest={pytest.__version__}",
            f"pkg={pkg_version}",
            f"targets={sorted(str(Path(t)) for t in targets)}",
            f"args={_digest_args(pytest_args)}",
            f"data_dir={data_dir_override or ''}",
        ]
        stats: list[str] = []
        for path in _iter_input_files(data_dir_override):
            st = path.stat()
            stats.append(f"{path}:{st.st_mtime_ns}:{st.st_size}")
        stats.sort()
        parts.extend(stats)
    except OSError:
        return None
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def _read_collection_cache(cache: Path) -> list[CollectedPytestItem] | None:
    try:
        return load_collection_manifest(cache)
    except (OSError, ValueError):
        return None  # cold, corrupt, or malformed cache -> fresh collection


def _write_collection_cache(cache: Path, items: list[CollectedPytestItem]) -> None:
    """Atomically write the cache as compact JSON (mkstemp gives 0o600 files)."""
    payload = json.dumps({"items": [asdict(item) for item in items]})
    try:
        fd, tmp = tempfile.mkstemp(dir=cache.parent, suffix=".tmp")
    except OSError:
        return
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
        os.replace(tmp, cache)
    except OSError:
        Path(tmp).unlink(missing_ok=True)


@dataclass(frozen=True)
class CollectedPytestItem:
    """Collection metadata for one pytest item."""

    nodeid: str
    file_path: str
    markers: list[str]


def save_collection_manifest(path: Path, items: list[CollectedPytestItem]) -> None:
    """Persist collected pytest item metadata as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"items": [asdict(item) for item in items]}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_collection_manifest(path: Path) -> list[CollectedPytestItem]:
    """Load collected pytest item metadata from JSON.

    Strict (F-016): any malformed entry raises ValueError. For the cache that
    reads as a miss and triggers fresh collection; for fresh helper output it
    fails collection visibly. Unknown extra keys stay tolerated for
    forward compatibility.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw_items = raw.get("items", raw) if isinstance(raw, dict) else raw
    if not isinstance(raw_items, list):
        msg = f"invalid collection manifest: {path}"
        raise ValueError(msg)
    items: list[CollectedPytestItem] = []
    for index, item in enumerate(raw_items):
        if not isinstance(item, dict):
            raise ValueError(
                f"invalid collection manifest entry #{index} in {path}: "
                f"expected an object, got {type(item).__name__}"
            )
        nodeid = item.get("nodeid")
        file_path = item.get("file_path")
        markers = item.get("markers", [])
        if not isinstance(nodeid, str):
            raise ValueError(
                f"invalid collection manifest entry #{index} in {path}: "
                f"nodeid must be a string, got {type(nodeid).__name__}"
            )
        if not isinstance(file_path, str):
            raise ValueError(
                f"invalid collection manifest entry #{index} in {path}: "
                f"file_path must be a string, got {type(file_path).__name__}"
            )
        if not isinstance(markers, list):
            raise ValueError(
                f"invalid collection manifest entry #{index} in {path}: "
                f"markers must be a list, got {type(markers).__name__}"
            )
        for marker in markers:
            if not isinstance(marker, str):
                raise ValueError(
                    f"invalid collection manifest entry #{index} in {path}: "
                    f"marker must be a string, got {type(marker).__name__}"
                )
        items.append(
            CollectedPytestItem(
                nodeid=nodeid,
                file_path=file_path,
                markers=list(markers),
            )
        )
    return items


def collect_pytest_item_metadata(
    targets: list[str],
    pytest_args: list[str],
    *,
    env: dict[str, str] | None = None,
) -> list[CollectedPytestItem]:
    """Collect pytest item metadata in a fresh subprocess.

    Backed by a content-addressed cache (see module docstring): on a digest hit
    the ~13-18s --collect-only pass is skipped. Set
    PKCS11_CHECK_NO_COLLECTION_CACHE=1 to bypass it entirely.
    """
    effective_env = env or os.environ
    cache_enabled = effective_env.get("PKCS11_CHECK_NO_COLLECTION_CACHE") not in {"1", "true"}
    cache_dir = _collection_cache_dir() if cache_enabled else None
    digest = (
        _collection_inputs_digest(targets, pytest_args, effective_env.get("PKCS11_CHECK_DATA_DIR"))
        if cache_dir is not None
        else None
    )
    cache_path = cache_dir / f"{digest}.json" if (cache_dir is not None and digest) else None
    if cache_path is not None:
        cached = _read_collection_cache(cache_path)
        if cached is not None:
            return cached

    input_fd, input_raw_path = tempfile.mkstemp(
        prefix="pkcs11-check-collect-input-",
        suffix=".json",
    )
    output_fd, output_raw_path = tempfile.mkstemp(
        prefix="pkcs11-check-collect-output-",
        suffix=".json",
    )
    input_path = Path(input_raw_path)
    output_path = Path(output_raw_path)
    os.close(input_fd)
    os.close(output_fd)

    try:
        input_path.write_text(
            json.dumps({"targets": targets, "pytest_args": pytest_args}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        cmd = [
            sys.executable,
            "-m",
            "pkcs11_check.core.collection",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ]
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            # F18: a stray provider byte must not lose the collection result.
            errors="replace",
            env=dict(env or os.environ),
        )

        if completed.returncode not in {0, 5}:
            raise ValueError(
                collection_failure_message(
                    returncode=completed.returncode,
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                    targets=targets,
                    pytest_args=pytest_args,
                )
            )

        if not output_path.exists():
            return []

        items = load_collection_manifest(output_path)
        if cache_path is not None and items:
            _write_collection_cache(cache_path, items)
        return items
    finally:
        input_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)


class _CollectionPlugin:
    """Collect marker metadata for each pytest item."""

    def __init__(self) -> None:
        self.items: list[CollectedPytestItem] = []

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        for item in session.items:
            item_path = getattr(item, "path", None)
            if item_path is None:
                file_path = Path(item.nodeid.split("::", 1)[0]).resolve()
            else:
                file_path = Path(item_path).resolve()
            markers = sorted({marker.name for marker in item.iter_markers()})
            self.items.append(
                CollectedPytestItem(
                    nodeid=item_nodeid(item),
                    file_path=str(file_path),
                    markers=markers,
                )
            )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write pytest collection metadata")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> None:
    """CLI entry point for the helper subprocess."""
    args = _parse_args()
    raw = json.loads(Path(args.input).read_text(encoding="utf-8"))
    targets = [str(target) for target in raw.get("targets", [])]
    pytest_args = [str(arg) for arg in raw.get("pytest_args", [])]
    plugin = _CollectionPlugin()
    exit_code = pytest.main(
        [
            *targets,
            *pytest_args,
            "--collect-only",
            "-qq",
            "--no-header",
        ],
        plugins=[plugin],
    )
    save_collection_manifest(Path(args.output), plugin.items)
    raise SystemExit(int(exit_code))


if __name__ == "__main__":
    main()
