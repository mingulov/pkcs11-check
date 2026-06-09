"""Lock the de-identification: no provider-identity branching, no masking shapes.

This guard meta-test exists because the provider-identity quirk registry
(`_module_quirks.py`: `detect_module`, `ModuleId`, `MODULE_QUIRKS`,
`quirk_extras`, `known_quirk_keys`) was deleted. The classification model is
now provider-general: deviations are recorded as `xfail` by the 3-way negative
classifier / `classify_discrimination`, never masked by per-provider config.

These checks genuinely catch reintroductions of the deleted machinery and of
the masking shapes it used to enable. The guard scans every `.py` file under
`src/pkcs11_check/` and `tests/` (excluding this file, which names the banned
symbols inside regex strings, and `__pycache__`).
"""
from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "pkcs11_check"
TESTS = REPO / "tests"
SELF = pathlib.Path(__file__).resolve()


def _files() -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for root in (SRC, TESTS):
        for p in root.rglob("*.py"):
            if "__pycache__" in p.parts or p.resolve() == SELF:
                continue
            out.append(p)
    return out


def _rel(p: pathlib.Path) -> str:
    return str(p.resolve().relative_to(REPO))


def test_no_deleted_quirk_symbols() -> None:
    """The deleted quirk-registry symbols must not reappear anywhere."""
    banned = re.compile(
        r"\b(_module_quirks|quirk_extras|detect_module|ModuleId|MODULE_QUIRKS|known_quirk_keys)\b"
    )
    bad = [_rel(p) for p in _files() if banned.search(p.read_text())]
    assert not bad, f"reintroduced quirk-registry references: {bad}"


def test_no_literal_discrimination_legs() -> None:
    """`classify_discrimination(...)` must receive observed runtime values, not
    literal `valid_accepted=True/False` / `invalid_outcome=True/False` legs --
    a literal leg means the test predetermined the outcome instead of observing
    the module (a masking smell).

    Allowlist: `test_classify_discrimination.py` is the dedicated meta-test for
    the classifier itself; passing literal legs is its entire purpose (it
    exercises the classifier's branches with no module). All product callers
    pass observed values and stay clean.
    """
    allow = {"test_classify_discrimination.py"}
    pat = re.compile(
        r"classify_discrimination\([^)]*\b(valid_accepted|invalid_outcome)\s*=\s*(True|False)\b"
    )
    bad = [_rel(p) for p in _files() if p.name not in allow and pat.search(p.read_text())]
    assert not bad, f"classify_discrimination called with a literal leg (masking smell): {bad}"


def test_no_silent_material_skip() -> None:
    """The `if recovered is not None:` idiom in wrap/unwrap tests silently skips
    material verification when the recovered key material is unavailable, hiding
    a self-contradiction (Type C) instead of failing. It must not appear.
    """
    pat = re.compile(r"if\s+recovered\s+is\s+not\s+None\s*:")
    bad = [_rel(p) for p in _files() if pat.search(p.read_text())]
    assert not bad, f"silent material-skip idiom: {bad}"


def test_no_provider_name_branch_on_module() -> None:
    """No test may branch on a provider name AND the module path -- that is how
    deviations get masked per-provider. Classification is provider-general.

    Allowlist: `test_threading.py` selects a token-provisioning primitive
    (softhsm2-util) by module path; it never masks a deviation, it picks the
    provisioning tool for the concurrency test.
    """
    allow = {"test_threading.py"}
    pat = re.compile(
        r"(if|elif)\b.*\b(softhsm|kryoptic|nss|opencryptoki|tpm2|bouncyhsm|qrypto)\b.*"
        r"(p11_config\.module|module\.lower\(\)|in module)"
    )
    bad = [_rel(p) for p in _files() if p.name not in allow and pat.search(p.read_text())]
    assert not bad, f"provider-name branch on module path: {bad}"
