"""Static gate (Phase 5.2): forbid raw ``pytest.xfail(``/``pytest.fail(`` under
``testcases/`` except in sanctioned modules, via a shrinking allowlist.

The allowlist (``tests/_raw_site_allowlist.py``) lists files not yet migrated to
``classify()``; it shrinks to empty during Phase 7, after which the gate is fully hard.
"""

from __future__ import annotations

import pathlib
import subprocess

from tests._raw_site_allowlist import ALLOWLIST

ROOT = "src/pkcs11_check/testcases"
SANCTIONED = {"conftest.py", "_ckr_spec.py"}


def _files_with_raw_sites() -> set[str]:
    out = subprocess.run(
        ["grep", "-rlE", r"pytest\.(xfail|fail)\(", ROOT, "--include=*.py"],
        capture_output=True,
        text=True,
    ).stdout.split()
    return {f for f in out if pathlib.Path(f).name not in SANCTIONED}


def test_no_raw_sites_outside_allowlist() -> None:
    offenders = _files_with_raw_sites() - set(ALLOWLIST)
    assert not offenders, f"raw pytest.xfail/fail must use classify(): {sorted(offenders)}"


def test_allowlist_has_no_stale_entries() -> None:
    stale = set(ALLOWLIST) - _files_with_raw_sites()
    assert not stale, f"migrated files still in allowlist — remove them: {sorted(stale)}"
