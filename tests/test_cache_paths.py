"""Tests for the private (owner-only) cache directory helper.

Caches must never live under a world-writable path, so a local attacker cannot plant a
file that alters another user's run -- which for a conformance tool means silently
dropping tests, i.e. hiding findings. See src/pkcs11_check/core/cache_paths.py.

The GUARANTEE is "only this user can write here". Its MECHANISM is platform-specific, so
the assertions are too:

* POSIX -- an XDG cache dir created 0o700, with group/other bits actively tightened.
* Windows -- the per-user ``%LOCALAPPDATA%`` profile directory, whose NTFS default ACL is
  the boundary. ``os.chmod`` cannot express an owner-only ACL there, so POSIX mode bits
  are meaningless (a fresh directory reads back 0o777) and asserting them would be
  asserting nothing.

Both platforms are asserted below. Skipping one side rather than replacing it would leave
the shipped Windows policy untested, which is how the cp1252 class of bug reached users.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from pkcs11_check.core.cache_paths import secure_cache_dir

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX mode-bit semantics; Windows uses the %LOCALAPPDATA% ACL"
)
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows %LOCALAPPDATA% policy")


@pytest.fixture
def cache_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the cache root at the env var the current platform actually reads.

    Without the Windows branch the helper would resolve to the real profile directory and
    the test would litter the developer's actual cache.
    """
    monkeypatch.setenv(
        "LOCALAPPDATA" if sys.platform == "win32" else "XDG_CACHE_HOME", str(tmp_path)
    )
    return tmp_path


@posix_only
def test_dir_under_xdg_cache_home(cache_root: Path) -> None:
    d = secure_cache_dir("collection")
    assert d == cache_root / "pkcs11-check" / "collection"
    assert d.is_dir()


@windows_only
def test_dir_under_localappdata(cache_root: Path) -> None:
    d = secure_cache_dir("collection")
    assert d == cache_root / "pkcs11-check" / "cache" / "collection"
    assert d.is_dir()


@posix_only
def test_created_mode_is_owner_only(cache_root: Path) -> None:
    d = secure_cache_dir("vectors")
    assert d is not None
    assert stat.S_IMODE(d.stat().st_mode) & 0o077 == 0  # no group/other bits


@windows_only
def test_created_dir_is_inside_the_per_user_profile(cache_root: Path) -> None:
    """The Windows stand-in for the mode-bit check: containment IS the guarantee."""
    d = secure_cache_dir("vectors")
    assert d is not None
    assert d.is_dir()
    # Resolve both sides: the boundary claim is about the real location, and a substring
    # comparison on unresolved paths would pass for a symlink/junction pointing elsewhere.
    assert cache_root.resolve() in d.resolve().parents


@posix_only
def test_loose_permissions_are_tightened(cache_root: Path) -> None:
    pre = cache_root / "pkcs11-check" / "collection"
    pre.mkdir(parents=True)
    os.chmod(pre, 0o777)  # world-writable -> must be refused or tightened
    d = secure_cache_dir("collection")
    assert d is not None
    assert stat.S_IMODE(d.stat().st_mode) & 0o077 == 0
