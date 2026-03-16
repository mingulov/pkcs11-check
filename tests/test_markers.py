"""Tests for pytest marker definitions and version-check logic."""

from __future__ import annotations

from p11test.markers import MARKER_DEFINITIONS, should_skip_for_version


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
        assert "requires_v30" in names
        assert "requires_v32" in names
        assert "destructive" in names
        assert "pqc" in names
        assert "slow" in names
