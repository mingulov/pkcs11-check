"""Census: the sentinel-value sim patch table must cover its whole file set.

Slice 1 simulates exactly one contract file
(``tests/test_protected_component_contract.py``, pinned in
``tests/_llp64_sim_files.txt``). This census AST-collects every sentinel
binding in that file plus the production modules on its sentinel path
(``types_std``, ``recipes``, ``test_sensitivity``) and asserts the sim
plugin's ``PATCH_SITES`` equals that set exactly. A new consumer that
bypasses the single seam therefore fails on plain Linux CI instead of
silently making the simulation partial.

Scope note: this census is deliberately restricted to the Slice-1 file's
patch set. Broadening the sim file list (Slice 2) must broaden this census
in the same change. Nothing here claims real LLP64 ABI coverage; the sim
varies Python int constants only.
"""

from __future__ import annotations

import ast
from pathlib import Path

from tests._llp64_sim_plugin import PATCH_SITES

_ROOT = Path(__file__).resolve().parents[1]
_S32 = 0xFFFFFFFF
_SPLAT = 0xFFFFFFFFFFFFFFFF
_PLAT_NAME = "CK_UNAVAILABLE_INFORMATION"
_S32_NAME = "CK_UNAVAILABLE_INFORMATION_32"

#: Censused files -> the module name their bindings live under at runtime.
_CENSUS_FILES: dict[str, str] = {
    "src/pkcs11_check/raw/types_std.py": "pkcs11_check.raw.types_std",
    "src/pkcs11_check/raw/recipes.py": "pkcs11_check.raw.recipes",
    "src/pkcs11_check/testcases/test_sensitivity.py": "pkcs11_check.testcases.test_sensitivity",
    "tests/test_protected_component_contract.py": "test_protected_component_contract",
}


def _names(node: ast.AST) -> set[str]:
    out = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
    out |= {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
    return out


def _ints(node: ast.AST) -> set[int]:
    return {
        n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, int)
    }


def census_in_source(source: str, module: str) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """(platform-sentinel sites, already-32-bit sites) bound in one source."""
    tree = ast.parse(source)
    plat: set[tuple[str, str]] = set()
    pre32: set[tuple[str, str]] = set()
    s32_names: set[str] = {_S32_NAME}
    plat_names: set[str] = {_PLAT_NAME}
    bindings: list[tuple[str, ast.expr]] = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound = alias.asname or alias.name
                if alias.name == _PLAT_NAME:
                    plat.add((module, bound))
                elif alias.name == _S32_NAME:
                    pre32.add((module, bound))
        elif isinstance(node, ast.Assign):
            bindings.extend((t.id, node.value) for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                bindings.append((node.target.id, node.value))
    for _ in range(4):  # fixpoint over int()/alias spellings
        for name, value in bindings:
            if not (
                name.startswith("_UNAVAILABLE") or name in {"_U64", "_U32", _PLAT_NAME, _S32_NAME}
            ):
                continue
            ints, refs = _ints(value), _names(value)
            if _S32 in ints or refs & s32_names:
                s32_names.add(name)
                pre32.add((module, name))
            elif _SPLAT in ints or refs & plat_names or "_CK_ULONG_MAX" in refs:
                plat_names.add(name)
                plat.add((module, name))
    return plat, pre32


def _census() -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    plat: set[tuple[str, str]] = set()
    pre32: set[tuple[str, str]] = set()
    for rel, module in _CENSUS_FILES.items():
        p, t = census_in_source((_ROOT / rel).read_text(encoding="utf-8"), module)
        plat |= p
        pre32 |= t
    return plat, pre32


def test_census_detector_fires() -> None:
    """Synthetic: an unpatched new binding is visible to the census."""
    plat, pre32 = census_in_source(
        "from pkcs11_check.raw.types_std import CK_UNAVAILABLE_INFORMATION\n"
        "_UNAVAILABLE_64 = int(CK_UNAVAILABLE_INFORMATION)\n"
        "_UNAVAILABLE_32 = 0xFFFFFFFF\n",
        "m",
    )
    assert plat == {("m", "CK_UNAVAILABLE_INFORMATION"), ("m", "_UNAVAILABLE_64")}
    assert pre32 == {("m", "_UNAVAILABLE_32")}


def test_sim_files_list_is_exactly_the_slice1_contract_file() -> None:
    listed = [
        line.strip()
        for line in (_ROOT / "tests" / "_llp64_sim_files.txt")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert listed == ["tests/test_protected_component_contract.py"]
    for rel in listed:
        assert (_ROOT / rel).is_file(), rel


def test_patch_sites_equal_census() -> None:
    plat, _pre32 = _census()
    assert set(PATCH_SITES) == plat, (
        "sim PATCH_SITES drifted from the censused sentinel bindings.\n"
        f"  in census, not patched: {sorted(plat - set(PATCH_SITES))}\n"
        f"  patched, not in census: {sorted(set(PATCH_SITES) - plat)}\n"
        "Route the new binding through CK_UNAVAILABLE_INFORMATION or extend "
        "PATCH_SITES (and this census scope) in the same change."
    )
