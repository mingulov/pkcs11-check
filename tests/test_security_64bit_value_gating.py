"""Guard: a security probe passing a hardcoded >2^32 CK_ULONG value must be gated.

A CK_ULONG length/count/size value in (2^32, 2^64] is unrepresentable on a 32-bit
CK_ULONG ABI (Win64 LLP64). Passing it either truncates -- ``0x8000000000000000``
becomes ``0`` in the low 32 bits, so the module sees a tiny/zero length and
"accepts invalid" -- or overflows the ctypes call (the demand-zero honeypot then
crashes too, since Windows mmap lacks ``MAP_ANONYMOUS``). Such probes only make
sense for a 64-bit CK_ULONG caller, so every test that uses one MUST carry
``requires_64bit_ck_ulong`` (as a module ``pytestmark``, a class decorator, or a
test decorator), exactly like the truncation/oversize modules already do.

This guard parses every ``testcases/security/test_*.py`` on a 64-bit dev box and
fails if any un-gated test references such a value -- so the gap is caught here,
once, instead of as a flood of spurious failures the first time the suite runs
under Wine / Win64.

Scope: only literals in (2^32, 2^64] count. Larger literals are crypto material
(RSA moduli, EC curve orders), never CK_ULONG arguments, and are excluded by the
upper bound. The two files that embed 33-to-64-bit *crypto* constants -- ROCA
fingerprint bitmasks and the P-256 group order -- are allowlisted below.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SECURITY = Path(__file__).resolve().parents[1] / "src" / "pkcs11_check" / "testcases" / "security"
_GATE = "requires_64bit_ck_ulong"
_LOW = 0xFFFFFFFF  # 32-bit CK_ULONG max; a CK_ULONG arg above this is unrepresentable there
_HIGH = 0xFFFFFFFFFFFFFFFF  # 64-bit CK_ULONG max; anything larger is crypto material, not a length

# Files whose >2^32 literals are cryptographic constants (modulus fingerprints,
# curve orders), never passed as a CK_ULONG argument.
_CRYPTO_CONSTANT_FILES = {"test_cve_regression.py", "test_ecdsa_low_s.py"}


def _is_unhonorable_literal(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, int)
        and _LOW < node.value <= _HIGH
    )


def _names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _references_unhonorable(node: ast.AST, bad_names: set[str]) -> bool:
    for sub in ast.walk(node):
        if _is_unhonorable_literal(sub):
            return True
        if isinstance(sub, ast.Name) and sub.id in bad_names:
            return True
    return False


def _gated(decorators: list[ast.expr]) -> bool:
    return any(_GATE in _names(d) for d in decorators)


def _module_bad_names(tree: ast.Module) -> set[str]:
    """Module-level names bound (transitively) to an un-honorable value."""
    bad: set[str] = set()
    for _ in range(4):  # fixpoint: constants, then lists/params referencing them
        for node in tree.body:
            if isinstance(node, ast.Assign) and _references_unhonorable(node.value, bad):
                bad |= {t.id for t in node.targets if isinstance(t, ast.Name)}
    return bad


def _module_gated(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = {t.id for t in node.targets if isinstance(t, ast.Name)}
            if "pytestmark" in targets and _GATE in _names(node.value):
                return True
    return False


def test_unhonorable_ck_ulong_probes_are_64bit_gated() -> None:
    offenders: list[str] = []
    for path in sorted(_SECURITY.glob("test_*.py")):
        if path.name in _CRYPTO_CONSTANT_FILES:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if _module_gated(tree):
            continue
        bad_names = _module_bad_names(tree)

        def check(fn: ast.FunctionDef | ast.AsyncFunctionDef, cls_gated: bool, cls: str) -> None:
            if not fn.name.startswith("test_"):
                return
            if _references_unhonorable(fn, bad_names) and not (
                cls_gated or _gated(fn.decorator_list)
            ):
                where = f"{cls}::{fn.name}" if cls else fn.name
                offenders.append(f"{path.name}::{where}")

        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                cg = _gated(node.decorator_list)
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        check(item, cg, node.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                check(node, False, "")

    assert offenders == [], (
        "security probe(s) pass a hardcoded >2^32 value as a CK_ULONG argument but are not\n"
        "gated requires_64bit_ck_ulong -- they truncate/overflow on a 32-bit CK_ULONG caller\n"
        "(Win64) and will spuriously fail under Wine. Add @requires_64bit_ck_ulong to the\n"
        "test/class (or requires_64bit_ck_ulong to the module pytestmark):\n  "
        + "\n  ".join(offenders)
    )
