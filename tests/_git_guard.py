"""Availability gate for meta-tests that enumerate git-TRACKED files.

Several guards ask "of the files this repo tracks, does any violate rule X?" and use
``git ls-files`` to answer. That needs both a ``git`` binary and a real work tree, and
neither is guaranteed: an sdist install has no ``.git``, and the win-ctr lane ships the
framework as a tarball with ``.git`` excluded on purpose. There the guards raised
``FileNotFoundError: [WinError 2]`` -- an error that says nothing about the codebase.

Skipping is the honest outcome, but a guard that skips silently has stopped guarding, and
this project has already been bitten by finding-hiding tests. So the skip is opt-out:
export ``PKCS11_CHECK_REQUIRE_GIT_GUARDS=1`` (CI does) and an unavailable git becomes a
hard failure instead, which means CI can never quietly lose this coverage.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

_REQUIRE_ENV = "PKCS11_CHECK_REQUIRE_GIT_GUARDS"


def _unavailable_reason() -> str | None:
    """Return why git-tracked enumeration is impossible here, or None if it works."""
    if shutil.which("git") is None:
        return "no git binary on PATH"
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"git rev-parse failed: {type(exc).__name__}: {exc}"
    if proc.returncode != 0 or proc.stdout.strip() != "true":
        return f"{REPO_ROOT} is not a git work tree (rc={proc.returncode})"
    return None


_REASON = _unavailable_reason()

if _REASON is not None and os.environ.get(_REQUIRE_ENV):
    msg = (
        f"{_REQUIRE_ENV} is set but the git-tracked-file guards cannot run: {_REASON}. "
        "These guards enumerate tracked files; losing them silently would drop real "
        "coverage, so this is a hard failure rather than a skip."
    )
    raise RuntimeError(msg)

#: Apply as ``pytestmark`` in any module whose tests need ``git ls-files``.
requires_git_tracked_files = pytest.mark.skipif(
    _REASON is not None,
    reason=f"git-tracked file enumeration unavailable: {_REASON}",
)
