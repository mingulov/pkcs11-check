"""Assemble a structured provenance record for a test run.

Records what was tested (provider + crypto backend + downloaded data) and by which
test client (the framework version), plus a compact preflight environment summary.
All IO (running git, reading the build-baked file) is funnelled through injectable
parameters so the assembler is unit-testable without a real environment. Every field
is optional: an absent source yields an absent key, never a fabricated value.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from pkcs11_check import __version__

GitRunner = Callable[[list[str], Path], "str | None"]


def _run_git(args: list[str], cwd: Path) -> str | None:
    """Run a git subcommand in ``cwd``; return stripped stdout or None on any failure."""
    try:
        result = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def _version_dict(version: str, source: str) -> dict[str, Any]:
    return {"version": version, "dirty": version.endswith("-dirty"), "source": source}


def framework_version(
    *, env: Mapping[str, str], repo_root: Path | None, run_git: GitRunner = _run_git
) -> dict[str, Any]:
    """Resolve the framework version: env override -> git describe -> package version.

    ``env[PKCS11_CHECK_FRAMEWORK_VERSION]`` wins (set host-side for docker runs where the
    framework .git is not in the container). Otherwise ``git describe`` against
    ``repo_root`` (direct runs from a checkout). Otherwise the static ``__version__``.
    """
    pinned = env.get("PKCS11_CHECK_FRAMEWORK_VERSION")
    if pinned:
        return _version_dict(pinned, "env")
    if repo_root is not None and (repo_root / ".git").exists():
        described = run_git(["describe", "--tags", "--always", "--dirty"], repo_root)
        if described:
            return _version_dict(described, "git-describe")
    return _version_dict(__version__, "package")


def read_build_provenance(path: Path) -> dict[str, Any]:
    """Load the build-baked provenance JSON (provider + crypto), or {} if absent/bad."""
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}
