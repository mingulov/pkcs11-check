"""Regression tests for the marshal-backed vector JSON cache.

Lever 3 of docs/findings/test-execution-speedup-gap-analysis-2026-06-04.md:
load_json_cached must return data identical to json.load, persist a cache, and
transparently fall back to the JSON source on any cache miss/staleness/corruption
(the JSON stays the source of truth — the cache must never hide a vector change).
"""

from __future__ import annotations

import ast
import json
import os
import time
from pathlib import Path

from pkcs11_check.testcases import data as data_mod
from pkcs11_check.testcases.data import load_json_cached

_TESTCASE_ROOT = Path(__file__).resolve().parents[1] / "src" / "pkcs11_check" / "testcases"
_DIRECT_JSON_LOAD_EXCEPTIONS = {
    "data/__init__.py",
    "_raw_subprocess.py",
    "_subprocess_preamble.py",
}


def _write(tmp_path: Path, obj: object) -> Path:
    p = tmp_path / "vec.json"
    p.write_text(json.dumps(obj))
    return p


def test_identical_to_json_load(tmp_path: Path) -> None:
    obj = {"testGroups": [{"tests": [{"tcId": 1, "msg": "ab"}], "type": "x"}], "n": 3.5}
    src = _write(tmp_path, obj)
    assert load_json_cached(src) == obj == json.loads(src.read_text())


def test_cache_file_created_and_reused(tmp_path: Path) -> None:
    src = _write(tmp_path, {"a": [1, 2, 3]})
    cache = data_mod._vector_cache_path(src)
    assert cache is not None, "expected a private vector cache dir in the test env"
    cache.unlink(missing_ok=True)
    first = load_json_cached(src)
    assert cache.exists()
    # Second read returns identical data (served from cache).
    assert load_json_cached(src) == first


def test_stale_cache_invalidated_on_content_change(tmp_path: Path) -> None:
    src = _write(tmp_path, {"v": 1})
    assert load_json_cached(src) == {"v": 1}
    # Rewrite with different content + bump mtime; cache must NOT hide the change.
    time.sleep(0.01)
    src.write_text(json.dumps({"v": 2}))
    os.utime(src, None)
    assert load_json_cached(src) == {"v": 2}


def test_corrupt_cache_falls_back_to_json(tmp_path: Path) -> None:
    src = _write(tmp_path, {"ok": True})
    cache = data_mod._vector_cache_path(src)
    assert cache is not None
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(b"\x00not-a-valid-marshal-stream\xff")
    # Must not raise; falls back to parsing the JSON and rewrites the cache.
    assert load_json_cached(src) == {"ok": True}


def test_missing_source_raises_like_json_load(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    try:
        load_json_cached(missing)
    except FileNotFoundError:
        return
    raise AssertionError("expected FileNotFoundError for a missing source file")


def test_vector_loaders_use_cached_json_loader() -> None:
    offenders: list[str] = []
    for path in sorted(_TESTCASE_ROOT.rglob("*.py")):
        rel = path.relative_to(_TESTCASE_ROOT).as_posix()
        if rel in _DIRECT_JSON_LOAD_EXCEPTIONS:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "json"
                and node.func.attr == "load"
            ):
                offenders.append(f"{rel}:{node.lineno}")

    assert offenders == []
