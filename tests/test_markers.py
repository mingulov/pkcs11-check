"""Tests for pytest marker definitions and registration."""

from __future__ import annotations

import re
from pathlib import Path

from pkcs11_check.markers import MARKER_DEFINITIONS

_BUILTIN_MARKERS = {"parametrize", "skip", "skipif", "usefixtures", "xfail", "filterwarnings"}
_MARKER_PATTERN = re.compile(r"pytest\.mark\.([A-Za-z_][A-Za-z0-9_]*)")


class TestMarkerDefinitions:
    def test_all_markers_defined(self) -> None:
        names = [m.name for m in MARKER_DEFINITIONS]
        assert "access" in names
        assert "crossverify" in names
        assert "destructive" in names
        assert "pqc" in names
        assert "slow" in names
        assert "stress" in names
        assert "module_session_fast" in names
        assert "wycheproof" in names

    def test_all_testcase_markers_registered(self) -> None:
        names = {m.name for m in MARKER_DEFINITIONS}
        testcases_dir = Path(__file__).resolve().parents[1] / "src" / "pkcs11_check" / "testcases"
        used = {
            marker
            for path in testcases_dir.glob("test_*.py")
            for marker in _MARKER_PATTERN.findall(path.read_text(encoding="utf-8"))
            if marker not in _BUILTIN_MARKERS
        }
        assert used <= names


def test_no_testcase_uses_interface_version_markers() -> None:
    """Capability gating is provider-general: no test may gate on interface version.
    Any future requires_v30/v31/v32 reintroduces the silent-skip bug this refactor fixed."""
    import pkcs11_check.testcases as testcases_pkg

    root = Path(testcases_pkg.__file__).parent
    # Match the MARKER form, not a bare substring — the inverse-test method name
    # `test_authenticated_wrap_requires_v32` is intentionally retained and must not trip this.
    pattern = re.compile(r"mark\.requires_v3[012]")
    offenders = [
        str(p.relative_to(root))
        for p in root.rglob("test_*.py")
        if pattern.search(p.read_text(encoding="utf-8"))
    ]
    assert offenders == [], f"interface-version markers must not be used: {offenders}"


def test_requires_version_markers_are_unregistered() -> None:
    """The requires_v30/v31/v32 markers are gone from the registry."""
    names = {m.name for m in MARKER_DEFINITIONS}
    assert "requires_v30" not in names
    assert "requires_v32" not in names
    assert "needs_function" in names
