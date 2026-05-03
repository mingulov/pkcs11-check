"""Meta-tests for the per-module CKR-quirk registry.

Two purposes:

1. Prevent quirk drift: every quirk_key string used in a test file must
   exist in `_module_quirks.MODULE_QUIRKS`. A typo or rename that breaks
   the lookup would otherwise silently return ``()`` and skip the
   fallback — masking the very behaviour the quirk was supposed to
   document.

2. Anti-masking guardrail: each quirk must reference a heading in
   ``docs/module-issues.md`` so that the deviation is documented in one
   place that's part of the project's release reporting.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from pkcs11_check.testcases._module_quirks import (
    MODULE_QUIRKS,
    Quirk,
    detect_module,
    known_quirk_keys,
    quirk_extras,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TESTCASES = _REPO_ROOT / "src" / "pkcs11_check" / "testcases"
_MODULE_ISSUES = _REPO_ROOT / "docs" / "module-issues.md"

_QUIRK_CALL_RE = re.compile(r'quirk_extras\(\s*[^,]+,\s*"([a-zA-Z0-9_]+)"\s*\)')


def _grep_quirk_keys() -> set[str]:
    """Find every quirk_key string used in test files via static regex."""
    keys: set[str] = set()
    for py_file in _TESTCASES.rglob("*.py"):
        if py_file.name == "_module_quirks.py":
            continue
        text = py_file.read_text(encoding="utf-8")
        keys.update(_QUIRK_CALL_RE.findall(text))
    return keys


def test_every_used_quirk_key_is_registered() -> None:
    """Each quirk_extras(p11_config, "key") call must reference a real quirk."""
    used = _grep_quirk_keys()
    declared = known_quirk_keys()
    missing = used - declared
    assert not missing, (
        f"Test files reference quirk_key(s) not registered in MODULE_QUIRKS: "
        f"{sorted(missing)}. Either add the entry to "
        f"src/pkcs11_check/testcases/_module_quirks.py or fix the typo."
    )


def test_every_quirk_has_issue_reference() -> None:
    """Each Quirk.issue_ref must point at a real heading in module-issues.md."""
    if not _MODULE_ISSUES.exists():
        pytest.skip("docs/module-issues.md not present in this checkout")
    issues_text = _MODULE_ISSUES.read_text(encoding="utf-8")

    failures: list[str] = []
    for module_id, quirks in MODULE_QUIRKS.items():
        for quirk_name, quirk in quirks.items():
            # The issue_ref string contains "§<heading>" — the heading must
            # appear somewhere in module-issues.md (not necessarily as an
            # exact `### heading` line, since wording can vary slightly).
            heading_marker = quirk.issue_ref.split("§", 1)[-1].strip()
            if not heading_marker:
                failures.append(f"{module_id.value}/{quirk_name}: issue_ref has no heading")
                continue
            # Take the first 6 words of the heading as the search phrase to
            # tolerate minor wording differences.
            phrase = " ".join(heading_marker.split()[:6])
            if phrase not in issues_text:
                failures.append(
                    f"{module_id.value}/{quirk_name}: issue_ref points at "
                    f'"{heading_marker}" but the phrase "{phrase}" is not '
                    f"in docs/module-issues.md"
                )
    assert not failures, "Quirk registry has unverified issue refs:\n" + "\n".join(failures)


def test_every_quirk_has_extra_ckrs() -> None:
    """A Quirk with no extra CKRs is dead weight — flag it."""
    empty = [
        f"{module_id.value}/{name}"
        for module_id, qs in MODULE_QUIRKS.items()
        for name, quirk in qs.items()
        if not quirk.extra_ckrs
    ]
    assert not empty, f"Quirks with empty extra_ckrs: {empty}"


def test_quirk_dataclass_is_frozen() -> None:
    """Quirks are immutable so they cannot be mutated post-registration."""
    sample = Quirk(
        description="x",
        spec_ref="x",
        issue_ref="x §x",
        extra_ckrs=(0x1,),
    )
    with pytest.raises(Exception):  # FrozenInstanceError
        sample.description = "mutated"  # type: ignore[misc]


def test_unknown_module_returns_no_extras() -> None:
    """An unknown module must get the strictest assertions (no quirk extras)."""

    class _DummyConfig:
        module = "/nonexistent/path/to/unknown_module.so"

    assert quirk_extras(_DummyConfig(), "verify_or_integrity_failure") == ()


def test_detect_module_recognises_known_paths() -> None:
    """Sanity check that the path-based detection actually works."""
    from pkcs11_check.testcases._module_quirks import ModuleId

    cases = [
        ("/usr/lib/softhsm/libsofthsm2.so", ModuleId.SOFTHSM2),
        ("/usr/lib64/libkryoptic_pkcs11.so", ModuleId.KRYOPTIC),
        ("/usr/lib64/libsoftokn3.so", ModuleId.NSS),
        ("/usr/lib64/opencryptoki/libopencryptoki.so", ModuleId.OPENCRYPTOKI),
        ("/usr/lib64/libtpm2_pkcs11.so", ModuleId.TPM2),
        ("/opt/bouncyhsm/libbouncyhsm_pkcs11.so", ModuleId.BOUNCYHSM),
        ("/usr/lib/some-novel-module.so", ModuleId.UNKNOWN),
    ]
    for path, expected in cases:

        class _Cfg:
            module = path

        actual = detect_module(_Cfg())
        assert actual == expected, f"detect_module({path!r}) = {actual} != {expected}"
