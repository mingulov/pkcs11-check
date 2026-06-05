"""Tests for the private (owner-only) cache directory helper.

Caches must never live under a world-writable path; secure_cache_dir returns a
0o700 owner-only directory (or None) so a local attacker cannot plant a file
that alters another user's run. See src/pkcs11_check/core/cache_paths.py.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from pkcs11_check.core.cache_paths import secure_cache_dir


def test_dir_under_xdg_cache_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    d = secure_cache_dir("collection")
    assert d == tmp_path / "pkcs11-check" / "collection"
    assert d.is_dir()


def test_created_mode_is_owner_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    d = secure_cache_dir("vectors")
    assert d is not None
    assert stat.S_IMODE(d.stat().st_mode) & 0o077 == 0  # no group/other bits


def test_loose_permissions_are_tightened(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    pre = tmp_path / "pkcs11-check" / "collection"
    pre.mkdir(parents=True)
    os.chmod(pre, 0o777)  # world-writable -> must be refused or tightened
    d = secure_cache_dir("collection")
    assert d is not None
    assert stat.S_IMODE(d.stat().st_mode) & 0o077 == 0
