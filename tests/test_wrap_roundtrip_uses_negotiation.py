"""Regression guard: positive key-material wrap/unwrap roundtrip tests must route
their C_UnwrapKey through the negotiating helper, not a raw ``unwrap_key`` call.

Background
----------
``unwrap_key_for_mechanism_roundtrip`` (testcases/conftest.py) negotiates the
accepted unwrap template provider-generally: on a clean template-shape reject it
retries a variant that drops only the *policy* attributes
(CKA_EXTRACTABLE / CKA_SENSITIVE) which some modules reject in an unwrap template
(opencryptoki -> CKR_ATTRIBUTE_READ_ONLY) while lenient modules (softhsm2) need
CKA_EXTRACTABLE for the unwrapped value to be readable.

A *positive roundtrip* test (wrap a key, unwrap it, assert the recovered material
matches / the key works) that calls the **raw** ``unwrap_key`` with a policy attr
in its template hard-fails on a strict module instead of negotiating. That is a
harness bug (triage H1, 2026-06-09): the behavioral-adaptation refactor applied
the negotiation to some wrap suites but left these roundtrip tests on raw unwrap,
so opencryptoki failed 12 positive roundtrips with CKR_ATTRIBUTE_READ_ONLY.

This guard pins the fix: any raw ``unwrap_key(attrs={... CKA_EXTRACTABLE/SENSITIVE
...})`` site must be on the allowlist below (tests whose *premise* is the policy
attribute itself, or negative tests that deliberately drive an explicit template).
A new positive roundtrip must use the negotiating helper or justify an allowlist
entry. The allowlist is keyed by path under ``testcases/`` with the reason.
"""

from __future__ import annotations

import ast
from pathlib import Path

_TESTCASES = Path(__file__).resolve().parents[1] / "src" / "pkcs11_check" / "testcases"
_POLICY_ATTRS = {"CKA_EXTRACTABLE", "CKA_SENSITIVE"}

# Raw policy-attr unwrap sites that are intentional and must stay raw.
_ALLOWED_RAW_POLICY_UNWRAP: dict[str, str] = {
    # The whole point is that the unwrapped key PRESERVES the extractability it was
    # given — negotiating CKA_EXTRACTABLE away would defeat the security assertion.
    "security/test_cve_regression.py": (
        "Tookan attribute-preservation regression: asserts CKA_EXTRACTABLE survives unwrap"
    ),
    # Type-confusion negative test: deliberately drives one explicit unwrap template
    # and discriminates the security effect; it must not be silently relaxed.
    "security/test_tookan.py": "type-confusion negative test drives an explicit template",
    # RO-session write-restriction tests: the unwrap template is incidental; the test
    # asserts read-only-session semantics, not wrap roundtrip correctness.
    "test_ro_session_restrictions.py": "RO-session restriction test; unwrap is incidental",
}


def _raw_policy_unwrap_sites() -> list[tuple[str, int]]:
    sites: list[tuple[str, int]] = []
    for path in _TESTCASES.rglob("*.py"):
        rel = path.relative_to(_TESTCASES).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                continue
            if node.func.id != "unwrap_key":
                continue
            for kw in node.keywords:
                if kw.arg == "attrs" and isinstance(kw.value, ast.Dict):
                    keys = {k.id for k in kw.value.keys if isinstance(k, ast.Name)}
                    if keys & _POLICY_ATTRS:
                        sites.append((rel, node.lineno))
    return sites


def test_positive_roundtrip_unwraps_use_negotiating_helper() -> None:
    """No raw policy-attr ``unwrap_key`` outside the documented allowlist."""
    offenders = [
        f"{rel}:{lineno}"
        for rel, lineno in _raw_policy_unwrap_sites()
        if rel not in _ALLOWED_RAW_POLICY_UNWRAP
    ]
    assert not offenders, (
        "Raw policy-attr unwrap_key sites must use unwrap_key_for_mechanism_roundtrip "
        "(it negotiates CKA_EXTRACTABLE/CKA_SENSITIVE on a template-shape reject) or be "
        "added to _ALLOWED_RAW_POLICY_UNWRAP with a justification. Offending sites:\n  "
        + "\n  ".join(offenders)
    )


def test_allowlisted_raw_unwrap_sites_still_exist() -> None:
    """The allowlist stays honest: every allowlisted file actually has a raw site."""
    files_with_sites = {rel for rel, _ in _raw_policy_unwrap_sites()}
    stale = sorted(set(_ALLOWED_RAW_POLICY_UNWRAP) - files_with_sites)
    assert not stale, f"Allowlist entries no longer have a raw policy-attr unwrap: {stale}"
