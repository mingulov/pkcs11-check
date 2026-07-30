"""Private, owner-only cache directories for regenerable on-disk caches.

Caches (parsed vectors, collection metadata) must never live under a
world-writable location such as /tmp: another local user could plant a file
that alters what a different user's run collects or parses -- silently dropping
tests, which for a conformance/bug-finding tool means hiding findings. These
helpers return a per-user cache dir created mode 0o700 and refuse to use it
unless it is owned by the current user and not group/other-accessible. On any
failure the caller bypasses caching (and recomputes from source).

On Windows the owner-only guarantee rests on the per-user ``%LOCALAPPDATA%``
profile directory (NTFS default ACL), not on POSIX mode bits: ``os.chmod`` cannot
set an owner-only ACL there, so the mode-bit tightening below is a harmless
near-noop on Windows and the profile directory is the trust boundary.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


def _cache_root() -> Path:
    if sys.platform == "win32":
        # Windows has no XDG cache dir; %LOCALAPPDATA% is the per-user, NTFS-ACL-
        # protected profile location (owner-only by OS default). See module docstring.
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
        return root / "pkcs11-check" / "cache"
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base else Path.home() / ".cache"
    return root / "pkcs11-check"


def secure_cache_dir(name: str) -> Path | None:
    """Return a private (owner-only, 0o700) cache subdirectory, or None if one
    cannot be created and verified private."""
    target = _cache_root() / name
    try:
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = target.stat()
    except OSError:
        return None

    getuid = getattr(os, "getuid", None)
    if getuid is not None and st.st_uid != getuid():
        return None  # someone else owns it -- do not trust its contents

    if stat.S_IMODE(st.st_mode) & 0o077:
        # Pre-existing dir is group/other-accessible; tighten it or refuse.
        try:
            os.chmod(target, 0o700)
        except OSError:
            return None
    return target
