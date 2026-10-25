"""Census: sim patch table, sim file list, and Windows-contracts file list.

Three pinned lists, one failure mode each:

1. **Patch census.** The sentinel-value sim's ``PATCH_SITES`` must equal
   every platform-sentinel binding in the production seam modules plus
   every sim-listed contract file. Classification is name-blind (Slice-1
   review M1): a binding is a patch candidate when it derives from the
   seam constant (any local name) or folds to a width literal via the S4
   folder -- a renamed ``_SENT = 0xFFFFFFFFFFFFFFFF`` is caught, not
   skipped for failing a name pattern.
2. **Sim list.** Every ``tests/test_*contract*.py`` is either in
   ``tests/_llp64_sim_files.txt`` (rerun with the collapsed sentinel) or
   in ``_SIM_EXCLUSIONS`` with a reason. A file whose sentinel lives in a
   ctypes field value rather than a Python int constant cannot be
   simulated soundly and stays real-ABI-CI-only.
3. **Windows-contracts list.** ``tests/_windows_contract_files.txt``
   (run by the fast ``windows-contracts`` CI job) covers every contract
   file plus the platform guard/golden files, exactly.

Nothing here claims real LLP64 ABI coverage; the sim varies Python int
constants only, and real Windows timing/behaviour is CI-only evidence.
"""

from __future__ import annotations

import ast
from pathlib import Path

from tests._llp64_sim_plugin import PATCH_SITES
from tests.test_platform_width_guard import _simple_value, s4_bindings_in_source

_ROOT = Path(__file__).resolve().parents[1]
_S32 = 0xFFFFFFFF
_SPLAT = 0xFFFFFFFFFFFFFFFF
_PLAT_NAME = "CK_UNAVAILABLE_INFORMATION"
_S32_NAME = "CK_UNAVAILABLE_INFORMATION_32"
_SIM_LIST = _ROOT / "tests" / "_llp64_sim_files.txt"
_WINDOWS_LIST = _ROOT / "tests" / "_windows_contract_files.txt"

#: Production seam modules -> the module name their bindings live under.
_SEAM_FILES: dict[str, str] = {
    "src/pkcs11_check/raw/types_std.py": "pkcs11_check.raw.types_std",
    "src/pkcs11_check/raw/recipes.py": "pkcs11_check.raw.recipes",
    "src/pkcs11_check/testcases/test_sensitivity.py": "pkcs11_check.testcases.test_sensitivity",
}

#: Folded width literals in censused files that are NOT sentinel spellings
#: (e.g. a stimulus max): excluded from the patch set with a reason,
#: stale-checked. Empty today -- every literal in the censused files is a
#: sentinel spelling.
_NON_SENTINEL_LITERALS: dict[tuple[str, str], str] = {}

#: Contract files the value-level sim must not run, with reasons.
_SIM_EXCLUSIONS: dict[str, str] = {
    "tests/test_signature_width_contract.py": (
        "fakes write ctypes.c_ulong(-1).value into ulValueLen fields; that "
        "sentinel is a host-type field value, not a patchable int constant "
        "-- value patch unsound, real-ABI CI only"
    ),
}

#: Non-contract files the windows-contracts job must also run.
_WINDOWS_REQUIRED: frozenset[str] = frozenset(
    {
        "tests/test_ckr_ctypes_abi.py",
        "tests/test_llp64_sim_census.py",
        "tests/test_no_implicit_text_encoding.py",
        "tests/test_no_literal_width_ulong_params.py",
        "tests/test_platform_width_guard.py",
        "tests/test_raw_constants.py",
        "tests/test_sentinel_width_invariant.py",
    }
)


def _names(node: ast.AST) -> set[str]:
    out = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
    out |= {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
    return out


def _listed(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _contract_files() -> list[str]:
    return sorted(
        p.relative_to(_ROOT).as_posix() for p in (_ROOT / "tests").glob("test_*contract*.py")
    )


def census_in_source(source: str, module: str) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """(platform-sentinel sites, already-32-bit sites) bound in one source.

    Name-blind: a binding classifies by what its value derives from (the
    seam constants, transitively) or folds to (a width literal) -- never by
    matching an expected identifier pattern.
    """
    tree = ast.parse(source)
    folded = s4_bindings_in_source(source)
    plat: set[tuple[str, str]] = set()
    pre32: set[tuple[str, str]] = set()
    plat_names: set[str] = {_PLAT_NAME}
    s32_names: set[str] = {_S32_NAME}
    bindings: list[tuple[str, ast.expr]] = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound = alias.asname or alias.name
                if alias.name == _PLAT_NAME:
                    plat.add((module, bound))
                    plat_names.add(bound)
                elif alias.name == _S32_NAME:
                    pre32.add((module, bound))
                    s32_names.add(bound)
        elif isinstance(node, ast.Assign):
            bindings.extend((t.id, node.value) for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                bindings.append((node.target.id, node.value))
    classified: set[str] = set()
    changed = True
    while changed:  # fixpoint: alias/derivation chains of any length resolve
        changed = False
        for name, value in bindings:
            if name in classified or not _simple_value(value):
                # Marks and other computed objects that merely *mention* the
                # sentinel (a skipif condition) are not sentinel bindings.
                continue
            refs = _names(value)
            if name in plat_names or refs & plat_names or "_CK_ULONG_MAX" in refs:
                plat.add((module, name))
                plat_names.add(name)
            elif name in s32_names or refs & s32_names:
                pre32.add((module, name))
                s32_names.add(name)
            elif folded.get(name) == _SPLAT:
                plat.add((module, name))
                plat_names.add(name)
            elif folded.get(name) == _S32:
                pre32.add((module, name))
                s32_names.add(name)
            else:
                continue
            classified.add(name)
            changed = True
    return plat, pre32


def _census_files() -> dict[str, str]:
    files = dict(_SEAM_FILES)
    for rel in _listed(_SIM_LIST):
        files[rel] = Path(rel).stem
    return files


def _census() -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    plat: set[tuple[str, str]] = set()
    pre32: set[tuple[str, str]] = set()
    for rel, module in _census_files().items():
        p, t = census_in_source((_ROOT / rel).read_text(encoding="utf-8"), module)
        plat |= p
        pre32 |= t
    return plat, pre32


def test_census_detector_fires() -> None:
    """Synthetic: seam-derived, renamed and computed bindings are visible."""
    plat, pre32 = census_in_source(
        "from pkcs11_check.raw.types_std import CK_UNAVAILABLE_INFORMATION\n"
        "_UNAVAILABLE_64 = int(CK_UNAVAILABLE_INFORMATION)\n"
        "_UNAVAILABLE_32 = 0xFFFFFFFF\n",
        "m",
    )
    assert plat == {("m", "CK_UNAVAILABLE_INFORMATION"), ("m", "_UNAVAILABLE_64")}
    assert pre32 == {("m", "_UNAVAILABLE_32")}

    # M1/E10: no name pattern -- renamed, computed and long-chain spellings.
    plat, pre32 = census_in_source(
        "_SENT = 0xFFFFFFFFFFFFFFFF\n"
        "_COMPUTED = (1 << 64) - 1\n"
        "_A1 = _SENT\n_A2 = _A1\n_A3 = _A2\n_A4 = _A3\n_A5 = _A4\n_A6 = _A5\n"
        "_PLAIN32 = 0xFFFFFFFF\n",
        "m",
    )
    assert plat == {
        ("m", "_SENT"),
        ("m", "_COMPUTED"),
        ("m", "_A1"),
        ("m", "_A2"),
        ("m", "_A3"),
        ("m", "_A4"),
        ("m", "_A5"),
        ("m", "_A6"),
    }
    assert pre32 == {("m", "_PLAIN32")}


def test_sim_files_list_covers_contract_files_or_reasoned_exclusion() -> None:
    listed = _listed(_SIM_LIST)
    assert listed == sorted(listed), "sim list must stay sorted"
    contracts = set(_contract_files())
    assert set(listed) | set(_SIM_EXCLUSIONS) == contracts, (
        "every contract file must be sim-listed or excluded with a reason.\n"
        f"  unaccounted: {sorted(contracts - set(listed) - set(_SIM_EXCLUSIONS))}\n"
        f"  stale: {sorted((set(listed) | set(_SIM_EXCLUSIONS)) - contracts)}"
    )
    assert not set(listed) & set(_SIM_EXCLUSIONS), "file both sim-listed and excluded"
    for rel in listed:
        assert (_ROOT / rel).is_file(), rel


def test_patch_sites_equal_census() -> None:
    plat, _pre32 = _census()
    expected = plat - set(_NON_SENTINEL_LITERALS)
    assert set(PATCH_SITES) == expected, (
        "sim PATCH_SITES drifted from the censused sentinel bindings.\n"
        f"  in census, not patched: {sorted(expected - set(PATCH_SITES))}\n"
        f"  patched, not in census: {sorted(set(PATCH_SITES) - expected)}\n"
        "Route the new binding through CK_UNAVAILABLE_INFORMATION, extend "
        "PATCH_SITES if it is a sentinel spelling, or pin it in "
        "_NON_SENTINEL_LITERALS with a reason."
    )
    stale = set(_NON_SENTINEL_LITERALS) - plat
    assert not stale, f"stale _NON_SENTINEL_LITERALS entries (no longer folded literals): {stale}"


def test_windows_contract_files_cover_contracts_and_platform_guards() -> None:
    listed = _listed(_WINDOWS_LIST)
    windows_abi = {
        p.relative_to(_ROOT).as_posix() for p in (_ROOT / "tests").glob("test_windows_abi*.py")
    }
    expected = sorted(set(_contract_files()) | _WINDOWS_REQUIRED | windows_abi)
    assert listed == expected, (
        "windows-contracts list drifted (contracts + platform guards, sorted).\n"
        f"  missing: {sorted(set(expected) - set(listed))}\n"
        f"  unexpected: {sorted(set(listed) - set(expected))}"
    )
    for rel in listed:
        assert (_ROOT / rel).is_file(), rel
