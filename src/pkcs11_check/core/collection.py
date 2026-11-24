"""Pytest collection metadata helpers for isolation planning."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

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
_CACHE_FORMAT = 5
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


# Collection-affecting files pytest loads above a target: conftest.py at
# every level plus the rootdir config files (markers, options). Walked per
# target so an edit above an external target invalidates the cache (R20-2);
# in-tree files duplicate the package walk harmlessly (same key material).
# The config names mirror pytest's own locate_config list exactly (R21-2).
_COLLECTION_CONFIG_NAMES: tuple[str, ...] = (
    "conftest.py",
    "pytest.toml",
    ".pytest.toml",
    "pytest.ini",
    ".pytest.ini",
    "pyproject.toml",
    "tox.ini",
    "setup.cfg",
)


def _iter_target_files(targets: list[str]) -> list[Path]:
    """Target files whose content affects collection (R19-2).

    The package walk covers in-tree targets only; an edited external
    target otherwise reuses a stale cache entry (M3b then refuses a
    runnable test). Directories contribute their ``*.py`` files, nodeids
    their file part; missing targets contribute nothing (their path
    string already keys them, and collection fails loudly). Ancestor
    conftest/config files ride along: pytest loads them above the target,
    so editing one must rekey just like editing the target itself.
    """
    files: list[Path] = []
    for target in targets:
        candidate = Path(target.split("::", 1)[0])
        try:
            if candidate.is_dir():
                files.extend(p for p in candidate.rglob("*.py") if p.is_file())
                anchor = candidate
            elif candidate.is_file():
                files.append(candidate)
                anchor = candidate.parent
            else:
                continue
            resolved_anchor = anchor.resolve()
        except OSError:
            continue
        for directory in (resolved_anchor, *resolved_anchor.parents):
            for name in _COLLECTION_CONFIG_NAMES:
                conf = directory / name
                if conf.is_file():
                    files.append(conf)
    return files


def _iter_config_flag_files(args: list[str]) -> list[Path]:
    """Config files named by -c/--config-file flags (R22-2).

    Mirrors argparse store semantics: `-c PATH`, `-cPATH`, `-c=PATH`,
    `--config-file PATH`, `--config-file=PATH`, plus combined shorts
    with a c-taking-value (`-qc PATH`, `-qcPATH`; R23-2). Deliberately
    overcollects (a -k value resembling a flag only adds harmless key
    material, never a stale hit); combined forms never consume the next
    token, so a `-kc`-style false positive cannot swallow a real flag.
    Missing files contribute nothing (collection fails loudly before
    anything is cached). Long-flag prefix abbreviations (`--config …`)
    are not covered (vanishingly rare in practice).
    """
    files: list[Path] = []
    index = 0
    while index < len(args):
        arg = args[index]
        values: list[str] = []
        if arg == "-c" or arg == "--config-file":
            if index + 1 < len(args):
                values.append(args[index + 1])
                index += 1
        elif arg.startswith("--config-file="):
            values.append(arg.split("=", 1)[1])
        elif arg.startswith("-") and not arg.startswith("--") and len(arg) > 2:
            pos = arg.find("c", 1)
            if pos != -1:
                rest = arg[pos + 1 :]
                if rest:
                    values.append(rest[1:] if rest.startswith("=") else rest)
                elif index + 1 < len(args):
                    values.append(args[index + 1])
        for value in values:
            if value:
                candidate = Path(value)
                if candidate.is_file():
                    files.append(candidate)
        index += 1
    return files


def _collection_inputs_digest(
    targets: list[str],
    pytest_args: list[str],
    data_dir_override: str | None = None,
    pytest_addopts: str = "",
) -> str | None:
    """Digest every input that affects collection, or None to bypass the cache.

    `data_dir_override` is the collecting child's PKCS11_CHECK_DATA_DIR: the
    digest runs in the parent while collection runs in the child, so without
    it two children with different data dirs would alias to one cache entry
    (stale fetch-then-test ordering). The override string itself is digested
    so distinct-but-empty dirs still key apart. `pytest_addopts` is the
    child's PYTEST_ADDOPTS for the same reason (it injects -k/-m/-c and
    more); its -c file's contents ride along, since flag text alone would
    miss an edited config (R22-2). Unparseable addopts bypass the cache.
    """
    try:
        addopts_args = shlex.split(pytest_addopts) if pytest_addopts else []
    except ValueError:
        return None
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
            f"addopts={pytest_addopts}",
        ]
        stats: list[str] = []
        for path in _iter_input_files(data_dir_override):
            st = path.stat()
            stats.append(f"{path}:{st.st_mtime_ns}:{st.st_size}")
        for path in _iter_target_files(targets):
            resolved = path.resolve()
            st = resolved.stat()
            stats.append(f"{resolved}:{st.st_mtime_ns}:{st.st_size}")
        for path in _iter_config_flag_files([*pytest_args, *addopts_args]):
            resolved = path.resolve()
            st = resolved.stat()
            stats.append(f"config:{resolved}:{st.st_mtime_ns}:{st.st_size}")
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


@dataclass(frozen=True)
class CollectedSkip:
    """A collector (usually a module) skipped during ``--collect-only``."""

    nodeid: str
    reason: str


def save_collection_manifest(
    path: Path,
    items: list[CollectedPytestItem],
    skips: Sequence[CollectedSkip] = (),
) -> None:
    """Persist collected pytest item metadata as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "items": [asdict(item) for item in items],
        "collection_skips": [asdict(skip) for skip in skips],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_collection_manifest(path: Path) -> list[CollectedPytestItem]:
    """Load collected pytest item metadata from JSON.

    Strict (F-016): any malformed entry raises ValueError. For the cache that
    reads as a miss and triggers fresh collection; for fresh helper output it
    fails collection visibly. Unknown extra keys stay tolerated for
    forward compatibility.
    """
    items, _ = load_collection_manifest_with_skips(path)
    return items


def load_collection_manifest_with_skips(
    path: Path,
) -> tuple[list[CollectedPytestItem], list[CollectedSkip]]:
    """Load collected items plus collection-skip records from JSON.

    Items stay strict (F-016); skips are advisory and fail just as
    loudly when malformed, but a missing ``collection_skips`` key (old
    manifests and cache entries) simply means no skips.
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
    skips: list[CollectedSkip] = []
    if isinstance(raw, dict) and "collection_skips" in raw:
        raw_skips = raw["collection_skips"]
        if not isinstance(raw_skips, list):
            msg = f"invalid collection manifest skips in {path}"
            raise ValueError(msg)
        for index, skip in enumerate(raw_skips):
            if not isinstance(skip, dict):
                raise ValueError(
                    f"invalid collection manifest skip #{index} in {path}: "
                    f"expected an object, got {type(skip).__name__}"
                )
            skip_nodeid = skip.get("nodeid")
            reason = skip.get("reason")
            if not isinstance(skip_nodeid, str):
                raise ValueError(
                    f"invalid collection manifest skip #{index} in {path}: "
                    f"nodeid must be a string, got {type(skip_nodeid).__name__}"
                )
            if not isinstance(reason, str):
                raise ValueError(
                    f"invalid collection manifest skip #{index} in {path}: "
                    f"reason must be a string, got {type(reason).__name__}"
                )
            skips.append(CollectedSkip(nodeid=skip_nodeid, reason=reason))
    return items, skips


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
    items, _ = collect_pytest_items_with_skips(targets, pytest_args, env=env)
    return items


def collect_pytest_items_with_skips(
    targets: list[str],
    pytest_args: list[str],
    *,
    env: dict[str, str] | None = None,
) -> tuple[list[CollectedPytestItem], list[CollectedSkip]]:
    """Collect pytest item metadata plus collection-skip records.

    Same cache contract as :func:`collect_pytest_item_metadata`; a cache
    hit carries no skips (only non-empty collections are cached, and
    skips only matter when nothing was collected).
    """
    effective_env = env if env is not None else os.environ
    cache_enabled = effective_env.get("PKCS11_CHECK_NO_COLLECTION_CACHE") not in {"1", "true"}
    # F2: the digest walks data dirs resolved from the parent environment when the
    # effective env carries no PKCS11_CHECK_DATA_DIR. An explicit env that drops a
    # parent override would hash tree A while the child collects tree B -- bypass
    # the cache rather than serve a manifest collected from another tree.
    drops_data_override = (
        env is not None
        and not effective_env.get("PKCS11_CHECK_DATA_DIR")
        and bool(os.environ.get("PKCS11_CHECK_DATA_DIR"))
    )
    # R2b/R3b: same class for the home-derived fallback root. Path.home()
    # honors HOME (POSIX) / USERPROFILE, else HOMEDRIVE+HOMEPATH (Windows), so
    # an explicit env that changes or drops any of these inputs walks a
    # different tree than the parent digest hashed. An explicit
    # PKCS11_CHECK_DATA_DIR fixes the identity and keeps the cache.
    shifts_home_root = (
        env is not None
        and not effective_env.get("PKCS11_CHECK_DATA_DIR")
        and any(
            effective_env.get(var) != os.environ.get(var)
            for var in ("HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH")
        )
    )
    cache_usable = cache_enabled and not drops_data_override and not shifts_home_root
    cache_dir = _collection_cache_dir() if cache_usable else None
    digest = (
        _collection_inputs_digest(
            targets,
            pytest_args,
            effective_env.get("PKCS11_CHECK_DATA_DIR"),
            effective_env.get("PYTEST_ADDOPTS", ""),
        )
        if cache_dir is not None
        else None
    )
    cache_path = cache_dir / f"{digest}.json" if (cache_dir is not None and digest) else None
    if cache_path is not None:
        cached = _read_collection_cache(cache_path)
        if cached is not None:
            return cached, []

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
            env=dict(env if env is not None else os.environ),
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
            return [], []

        items, skips = load_collection_manifest_with_skips(output_path)
        if cache_path is not None and items:
            _write_collection_cache(cache_path, items)
        return items, skips
    finally:
        input_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)


def _ignore_hookcall(hook_name: str, hook_impls: Any, kwargs: Any) -> None:
    """No-op before-tracer (monitoring requires both callbacks)."""


def _stamp_make_collect_report(result: Any, hook_name: str, hook_impls: Any, kwargs: Any) -> None:
    """Stamp a made collect report with its collector's path (R24-1).

    Registered via pluggy hook-call monitoring, so it observes the FINAL
    result -- whatever wrappers ran, in whatever order or priority,
    including replacements. Only make_collect_report calls are stamped;
    the stamp rides the report object into pytest_collectreport, pairing
    exactly what no hook-order reasoning can misattribute. Unstamped
    reports (paths that never route through make, e.g. default-rootdir
    files) fall through to pairing/longrepr.
    """
    if hook_name != "pytest_make_collect_report":
        return
    report = result.get_result()
    if report is None:
        return
    collector_path = getattr(kwargs.get("collector"), "path", None)
    if collector_path is not None:
        report._p11c_nodeid = str(collector_path)


def _skip_path_from_longrepr(longrepr: object) -> str:
    """Resolve an empty skip nodeid to the raising file, else "".

    A target outside rootpath gets nodeid "" by pytest design
    (cross-drive on Windows); the report then carries nothing else
    (fspath/location derive from the nodeid too). But a module-level
    skip's longrepr is (path, lineno, message) naming the file that
    raised it -- usually the skipped module itself. Validated is-file:
    anything else stays empty rather than misattributing. (Pairing via
    pytest_make_collect_report cannot work: that hook never fires for
    File collectors -- verified -- and start/report pairing breaks when
    exact-node selection prunes intermediate reports.)
    """
    try:
        if not (
            isinstance(longrepr, tuple)
            and len(longrepr) == 3
            and isinstance(longrepr[0], str)
            and longrepr[0]
        ):
            return ""
        candidate = Path(longrepr[0])
        return str(candidate) if candidate.is_file() else ""
    except (OSError, ValueError):
        return ""


class _CollectionPlugin:
    """Collect marker metadata for each pytest item, plus collection skips."""

    def __init__(self) -> None:
        self.items: list[CollectedPytestItem] = []
        self.skips: list[CollectedSkip] = []
        self._skip_keys: set[tuple[str, str]] = set()
        self._file_starts: list[str] = []
        self._deselected_files: set[str] = set()
        self._pending: list[tuple[str, int, object]] = []

    def pytest_collectstart(self, collector: pytest.Collector) -> None:
        try:
            is_file = Path(collector.path).is_file()
        except (OSError, ValueError):
            is_file = False
        if is_file:
            self._file_starts.append(str(collector.path))

    def pytest_deselected(self, items: list[pytest.Item]) -> None:
        for item in items:
            item_path = getattr(item, "path", None)
            if item_path is not None:
                self._deselected_files.add(os.path.normcase(str(item_path)))

    def pytest_configure(self, config: pytest.Config) -> None:
        # Hook-call monitoring (not a wrapper): it observes the FINAL
        # result of every make_collect_report call, so no wrapper
        # ordering or priority tie can discard the stamp (R27-1).
        config.pluginmanager.add_hookcall_monitoring(_ignore_hookcall, _stamp_make_collect_report)

    def pytest_collectreport(self, report: pytest.CollectReport) -> None:
        if report.outcome != "skipped":
            return
        nodeid = str(report.nodeid)
        if nodeid:
            self._record_skip(nodeid, report.longrepr)
        else:
            # Empty nodeids (cross-rootpath targets) resolve at finish,
            # when the final item set disambiguates them (R23-1).
            marked = str(getattr(report, "_p11c_nodeid", "") or "")
            self._pending.append((marked, len(self._file_starts), report.longrepr))

    def _record_skip(self, nodeid: str, longrepr: object) -> None:
        if isinstance(longrepr, tuple):
            reason = str(longrepr[-1])
        else:
            reason = str(longrepr)
        if reason.startswith("Skipped:"):
            reason = reason[len("Skipped:") :].strip()
        key = (nodeid, reason)
        if key in self._skip_keys:
            return
        self._skip_keys.add(key)
        self.skips.append(CollectedSkip(nodeid=nodeid, reason=reason))

    def _resolve_pending(self) -> None:
        """Attribute deferred empty-nodeid skips (called at finish).

        Reports alone cannot tell two same-helper skips apart (R22-3);
        eager pairing misattributes once exact-node selection prunes an
        intermediate passed report (R20-4/R23-1), because items may arrive
        after the skip. With the FINAL item set the pairing is exact: each
        pending skip belongs to the nearest preceding file start with no
        collected or deselected items (a skipped file is always barren;
        anything completed is a stale top). Unmatched skips fall through
        to the longrepr path.
        """
        completed = {os.path.normcase(item.file_path) for item in self.items}
        completed |= self._deselected_files
        consumed: set[int] = set()
        for marked, seen_count, longrepr in self._pending:
            if marked:
                self._record_skip(marked, longrepr)
                continue
            paired = ""
            for index in range(min(seen_count, len(self._file_starts)) - 1, -1, -1):
                if index in consumed:
                    continue
                if os.path.normcase(self._file_starts[index]) in completed:
                    continue
                paired = self._file_starts[index]
                consumed.add(index)
                break
            self._record_skip(paired or _skip_path_from_longrepr(longrepr), longrepr)
        self._pending.clear()

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
        self._resolve_pending()


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
    save_collection_manifest(Path(args.output), plugin.items, plugin.skips)
    raise SystemExit(int(exit_code))


if __name__ == "__main__":
    main()
