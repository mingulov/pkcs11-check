"""Guard: every has_mechanism("LITERAL") names a resolvable mechanism.

Regression test for mingulov/pkcs11-check#22 (a skip on an unresolvable
name is indistinguishable in reports from genuine lack of support).
Only string literals are checked; computed names are out of scope.
"""

from __future__ import annotations

import re
from pathlib import Path

from pkcs11_check.raw.metadata_std import MECHANISM_NAMES

_CALL_RE = re.compile(r"""has_mechanism\(\s*["']([A-Za-z0-9_]+)["']\s*\)""")

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
        "KMAC_128",  # vendor-range KMAC, tests retained (user decision 2026-09-18)
        "KMAC_256",  # vendor-range KMAC, tests retained (user decision 2026-09-18)
    }
)


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
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for lit in _CALL_RE.findall(line):
                found.add(lit)
                if lit not in resolvable and lit not in KNOWN_UNRESOLVED:
                    bad.append(f"{path.relative_to(root)}:{lineno}: {lit}")
    stale = KNOWN_UNRESOLVED - found
    assert not stale, "KNOWN_UNRESOLVED entries no longer present — remove them:\n" + "\n".join(
        sorted(stale)
    )
    assert not bad, "has_mechanism() literals with no resolvable code point:\n" + "\n".join(bad)
