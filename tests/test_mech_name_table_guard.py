"""Guard: every has_mechanism("LITERAL") names a resolvable mechanism.

Regression test for mingulov/pkcs11-check#22 (a skip on an unresolvable
name is indistinguishable in reports from genuine lack of support).
Only string literals are checked; computed names are out of scope.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from pkcs11_check.raw.metadata_std import MECHANISM_NAMES

_LITERAL_RE = re.compile(r"[A-Za-z0-9_]+")


def _find_has_mechanism_literals(source: str) -> list[tuple[str, int]]:
    """Find (literal, lineno) for every has_mechanism("LIT") call, any layout.

    AST-based: multi-line calls (which the old line-regex missed) are found.
    Only string-literal first args are reported; computed names stay out of
    scope. Both bare `has_mechanism(..)` and `rs.has_mechanism(..)` forms
    are covered.
    """
    found: list[tuple[str, int]] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            name: str | None = func.attr
        elif isinstance(func, ast.Name):
            name = func.id
        else:
            name = None
        if name != "has_mechanism" or not node.args:
            continue
        first = node.args[0]
        if (
            isinstance(first, ast.Constant)
            and isinstance(first.value, str)
            and _LITERAL_RE.fullmatch(first.value)
        ):
            found.append((first.value, node.lineno))
    return found


# Documented unresolvable literals. Each entry needs either a code point,
# a vendor-retention decision, or test deletion — do not extend this set
# silently. The stale-entry assertion below fails if a listed literal
# disappears from the corpus, so fixed entries must be removed here.
KNOWN_UNRESOLVED = frozenset(
    {
        "AES_GCM_SIV",  # acvp/aes/test_gcm.py — availability gate, always skips
        "RSA_PKCS_NULL",  # test_remaining_gaps.py — availability gate, always skips
        "SHAKE_128",  # test_remaining_gaps.py — only KEY_DERIVE variants exist
        "SHAKE_256",  # test_remaining_gaps.py — only KEY_DERIVE variants exist
        "PKCS12_PBE_EXPORT",  # test_remaining_gaps.py — no constant in tree
        "PKCS12_PBE_IMPORT",  # test_remaining_gaps.py — no constant in tree
    }
)
# KMAC_128/KMAC_256 were removed from the set above: the KMAC tests now resolve
# through require_mechanism_or_skip + --p11-vendor-mechanism instead of a bare
# has_mechanism() literal, so the skips distinguish "no code point known" from
# genuine lack of support (no stale-entry trip: no such literals remain).


def _resolvable_names() -> set[str]:
    import pkcs11_check.raw.types_std as ts

    names: set[str] = set()
    for mname in MECHANISM_NAMES.values():
        names.add(mname)
        if mname.startswith("CKM_"):
            names.add(mname[4:])
    for attr in dir(ts):
        if attr.startswith("CKM_"):
            names.add(attr)
            names.add(attr[4:])
    return names


def test_all_has_mechanism_literals_resolve() -> None:
    import pkcs11_check.testcases as tc_pkg

    root = Path(tc_pkg.__file__).resolve().parent
    resolvable = _resolvable_names()
    bad: list[str] = []
    found: set[str] = set()
    for path in sorted(root.rglob("*.py")):
        for lit, lineno in _find_has_mechanism_literals(path.read_text(encoding="utf-8")):
            found.add(lit)
            if lit not in resolvable and lit not in KNOWN_UNRESOLVED:
                bad.append(f"{path.relative_to(root)}:{lineno}: {lit}")
    stale = KNOWN_UNRESOLVED - found
    assert not stale, "KNOWN_UNRESOLVED entries no longer present — remove them:\n" + "\n".join(
        sorted(stale)
    )
    assert not bad, "has_mechanism() literals with no resolvable code point:\n" + "\n".join(bad)


def test_scanner_finds_multiline_has_mechanism_literal() -> None:
    source = 'x = has_mechanism(\n    "CKM_AES_GCM"\n)\n'
    assert ("CKM_AES_GCM", 1) in _find_has_mechanism_literals(source)


def test_scanner_ignores_non_literal_first_arg() -> None:
    source = "x = has_mechanism(name)\n"
    assert _find_has_mechanism_literals(source) == []


def test_scanner_finds_single_line_and_reports_lineno() -> None:
    source = 'a = 1\ny = has_mechanism("CKM_SHA256")\n'
    assert _find_has_mechanism_literals(source) == [("CKM_SHA256", 2)]


def test_scanner_finds_method_call_form() -> None:
    source = 'ok = rs.has_mechanism("CKM_RSA_PKCS")\n'
    assert _find_has_mechanism_literals(source) == [("CKM_RSA_PKCS", 1)]
