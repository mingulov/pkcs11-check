"""Regression tests for the content-addressed collection-metadata cache.

The collection-metadata cache must be correct-by-construction -- a hit returns collection identical
to a fresh --collect-only, and ANY change to a collection-affecting input (source
file, vendor data, collection args, versions) must change the digest so a stale
cache can never drop or alter a test.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pkcs11_check.core import collection as col
from pkcs11_check.core.collection import (
    _collection_cache_dir,
    _collection_inputs_digest,
    _digest_args,
    collect_pytest_item_metadata,
)

_SMALL_TARGET = ["src/pkcs11_check/testcases/test_session_info.py"]
_ARGS = ["-p", "no:cacheprovider"]


# -- volatile-arg handling --


def test_digest_args_drops_manifest_pair() -> None:
    args = ["--p11-module", "/x.so", "--p11-manifest", "/tmp/run123.json", "-m", "slow"]
    assert _digest_args(args) == ["--p11-module", "/x.so", "-m", "slow"]


def test_digest_args_drops_manifest_equals_form() -> None:
    args = ["--p11-manifest=/tmp/run123.json", "-k", "rsa"]
    assert _digest_args(args) == ["-k", "rsa"]


# -- digest sensitivity --


def test_digest_stable_for_same_inputs() -> None:
    d1 = _collection_inputs_digest(_SMALL_TARGET, _ARGS)
    d2 = _collection_inputs_digest(_SMALL_TARGET, _ARGS)
    assert d1 is not None and d1 == d2


def test_digest_changes_with_args() -> None:
    base = _collection_inputs_digest(_SMALL_TARGET, _ARGS)
    other = _collection_inputs_digest(_SMALL_TARGET, [*_ARGS, "-m", "slow"])
    assert base != other


def test_digest_changes_with_targets() -> None:
    base = _collection_inputs_digest(_SMALL_TARGET, _ARGS)
    other = _collection_inputs_digest(["src/pkcs11_check/testcases/test_init.py"], _ARGS)
    assert base != other


def test_digest_changes_when_input_file_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text("x = 1\n")
    monkeypatch.setattr(col, "_iter_input_files", lambda: [probe])
    before = _collection_inputs_digest(_SMALL_TARGET, _ARGS)
    probe.write_text("x = 2  # changed size + mtime\n")
    after = _collection_inputs_digest(_SMALL_TARGET, _ARGS)
    assert before is not None and before != after


# -- round-trip correctness --


def test_cache_hit_matches_fresh_collection() -> None:
    cache_dir = _collection_cache_dir()
    assert cache_dir is not None, "expected a private collection cache dir in the test env"
    shutil.rmtree(cache_dir, ignore_errors=True)
    cold = collect_pytest_item_metadata(_SMALL_TARGET, _ARGS)  # populates cache
    warm = collect_pytest_item_metadata(_SMALL_TARGET, _ARGS)  # served from cache
    assert cold == warm
    assert len(cold) > 0


def test_env_bypass_recollects(monkeypatch: pytest.MonkeyPatch) -> None:
    fresh = collect_pytest_item_metadata(_SMALL_TARGET, _ARGS)
    monkeypatch.setenv("PKCS11_CHECK_NO_COLLECTION_CACHE", "1")
    bypassed = collect_pytest_item_metadata(_SMALL_TARGET, _ARGS)
    assert fresh == bypassed
