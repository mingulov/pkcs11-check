"""Tests for pytest marker definitions and version-check logic."""

from __future__ import annotations

import re
from pathlib import Path

from p11test.markers import MARKER_DEFINITIONS, should_skip_for_version

_BUILTIN_MARKERS = {"parametrize", "skipif"}
_MARKER_PATTERN = re.compile(r"pytest\.mark\.([A-Za-z_][A-Za-z0-9_]*)")


class TestVersionSkipLogic:
    def test_v30_test_skipped_on_v240(self) -> None:
        assert should_skip_for_version("requires_v30", "2.40") is True

    def test_v30_test_runs_on_v30(self) -> None:
        assert should_skip_for_version("requires_v30", "3.0") is False

    def test_v30_test_runs_on_v32(self) -> None:
        assert should_skip_for_version("requires_v30", "3.2") is False

    def test_v32_test_skipped_on_v30(self) -> None:
        assert should_skip_for_version("requires_v32", "3.0") is True

    def test_v32_test_runs_on_v32(self) -> None:
        assert should_skip_for_version("requires_v32", "3.2") is False

    def test_unknown_marker_never_skips(self) -> None:
        assert should_skip_for_version("unknown", "2.40") is False


class TestMarkerDefinitions:
    def test_all_markers_defined(self) -> None:
        names = [m.name for m in MARKER_DEFINITIONS]
        assert "access" in names
        assert "crossverify" in names
        assert "requires_v30" in names
        assert "requires_v32" in names
        assert "destructive" in names
        assert "pqc" in names
        assert "slow" in names
        assert "stress" in names
        assert "wycheproof" in names

    def test_all_testcase_markers_registered(self) -> None:
        names = {m.name for m in MARKER_DEFINITIONS}
        testcases_dir = Path(__file__).resolve().parents[1] / "src" / "p11test" / "testcases"
        used = {
            marker
            for path in testcases_dir.glob("test_*.py")
            for marker in _MARKER_PATTERN.findall(path.read_text(encoding="utf-8"))
            if marker not in _BUILTIN_MARKERS
        }
        assert used <= names
