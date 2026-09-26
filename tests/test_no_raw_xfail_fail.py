"""Static gate (Phase 5.2): forbid raw ``pytest.xfail(``/``pytest.fail(`` under
``testcases/`` except in sanctioned modules, via a shrinking allowlist.

The allowlist (``tests/_raw_site_allowlist.py``) lists files not yet migrated to
``classify()``; it shrinks to empty during Phase 7, after which the gate is fully hard.
"""

from __future__ import annotations

import ast
import pathlib
import re

from tests._raw_site_allowlist import ALLOWLIST

# Anchored at this file, NOT the process CWD. These scans used to shell out to `grep` with
# a CWD-relative root, which made them (a) silently vacuous whenever pytest ran from
# anywhere but the repo root -- a scan of a nonexistent path finds no offenders and the
# gate PASSES -- and (b) impossible on Windows, where there is no `grep`: the tests died
# with FileNotFoundError [WinError 2]. Scanning in-process is portable and CWD-independent.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
ROOT = "src/pkcs11_check/testcases"
ROOT_DIR = REPO_ROOT / ROOT
SANCTIONED = {"conftest.py", "_ckr_spec.py"}

_RAW_SITE_RE = re.compile(r"pytest\.(xfail|fail)\(")


def _py_files() -> list[pathlib.Path]:
    files = sorted(ROOT_DIR.rglob("*.py"))
    # A scan that matches nothing because it looked nowhere is the failure mode this guard
    # is most vulnerable to, so make an empty tree impossible to mistake for "all clean".
    assert files, f"no .py files under {ROOT_DIR}; the scan would be vacuous"
    return files


def _rel(path: pathlib.Path) -> str:
    """Repo-relative POSIX path -- the form ALLOWLIST entries are written in."""
    return path.relative_to(REPO_ROOT).as_posix()


def _files_with_raw_sites() -> set[str]:
    return {
        _rel(path)
        for path in _py_files()
        if path.name not in SANCTIONED and _RAW_SITE_RE.search(path.read_text(encoding="utf-8"))
    }


def test_no_raw_sites_outside_allowlist() -> None:
    offenders = _files_with_raw_sites() - set(ALLOWLIST)
    assert not offenders, f"raw pytest.xfail/fail must use classify(): {sorted(offenders)}"


def test_allowlist_has_no_stale_entries() -> None:
    stale = set(ALLOWLIST) - _files_with_raw_sites()
    assert not stale, f"migrated files still in allowlist — remove them: {sorted(stale)}"


def test_no_test_site_emits_reserved_unclassified_reason() -> None:
    """``unclassified`` is the plugin's synthetic migration-backlog marker; no test or
    helper under ``testcases/`` may emit it, or it would corrupt the backlog metric."""
    hits = [
        f"{_rel(path)}:{lineno}:{line}"
        for path in _py_files()
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if "unclassified" in line
    ]
    assert not hits, (
        "'unclassified' is reserved for the plugin runtime gate; remove from testcases/:\n"
        + "\n".join(hits)
    )


def test_no_raw_ckr_literals_in_field_size_expected_sets() -> None:
    """Field-size expected-CKR tuples must use symbolic ``CKR_*`` names (HSK-P11C-002).

    Every module-level ``*_RVS`` tuple in
    ``testcases/security/test_field_size_boundary.py`` must be built only from
    generated ``CKR_*`` symbols. Raw ``CK_RV`` int literals previously carried
    misleading comments (``0x23``, ``0x10``, ``0x0d``, ``0x70``, ``0x31`` are
    not the CKRs the comments claimed) and silently accepted unrelated codes.
    """
    path = REPO_ROOT / "src/pkcs11_check/testcases/security/test_field_size_boundary.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
    checked: dict[str, int] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        names = [
            target.id
            for target in node.targets
            if isinstance(target, ast.Name) and target.id.endswith("_RVS")
        ]
        if not names:
            continue
        literals = [
            sub.value
            for sub in ast.walk(node.value)
            if isinstance(sub, ast.Constant)
            and isinstance(sub.value, int)
            and not isinstance(sub.value, bool)
        ]
        symbols = [
            sub.id
            for sub in ast.walk(node.value)
            if isinstance(sub, ast.Name) and sub.id.startswith("CKR_")
        ]
        for name in names:
            assert not literals, (
                f"{name}: raw CK_RV literal(s) "
                f"{[hex(v) for v in literals]}; use generated CKR_* symbols"
            )
            assert symbols, f"{name}: no symbolic CKR_* entries; expected-set guard vacuous"
            checked[name] = len(symbols)
    assert checked, "guard is vacuous: no *_RVS tuples found in test_field_size_boundary.py"


def test_allowlist_is_empty() -> None:
    """Migration complete: no files remain in the raw-site allowlist, so the static
    gate is fully hard — any new raw pytest.xfail/fail under testcases/ now fails CI."""
    from tests._raw_site_allowlist import ALLOWLIST

    assert not ALLOWLIST, (
        f"migration incomplete — files remain in the allowlist: {sorted(ALLOWLIST)}"
    )
