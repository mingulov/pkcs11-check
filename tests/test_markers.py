"""Tests for pytest marker definitions and version-check logic."""

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
