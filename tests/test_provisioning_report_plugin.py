"""Tests for _build_provisioning_report helper in the pytest plugin."""

from __future__ import annotations

from collections import Counter

from pkcs11_check.plugin import _build_provisioning_report


class TestBuildProvisioningReportEmpty:
    def test_empty_counter_returns_empty_by_class(self) -> None:
        result = _build_provisioning_report(Counter())
        assert result["by_class"] == {}

    def test_empty_counter_totals_all_zero(self) -> None:
        result = _build_provisioning_report(Counter())
        assert result["totals"] == {
            "ran_via_create": 0,
            "ran_via_unwrap": 0,
            "ran_via_external": 0,
            "skipped_no_path": 0,
        }

    def test_empty_counter_has_all_four_total_keys(self) -> None:
        result = _build_provisioning_report(Counter())
        assert set(result["totals"].keys()) == {
            "ran_via_create",
            "ran_via_unwrap",
            "ran_via_external",
            "skipped_no_path",
        }


class TestBuildProvisioningReportPopulated:
    def setup_method(self) -> None:
        counts: Counter[tuple[str, str]] = Counter(
            {
                ("secret", "ran_via_create"): 3,
                ("private", "ran_via_unwrap"): 2,
                ("secret", "skipped_no_path"): 1,
            }
        )
        self.result = _build_provisioning_report(counts)

    def test_by_class_secret_contents(self) -> None:
        assert self.result["by_class"]["secret"] == {
            "ran_via_create": 3,
            "skipped_no_path": 1,
        }

    def test_by_class_private_contents(self) -> None:
        assert self.result["by_class"]["private"] == {"ran_via_unwrap": 2}

    def test_total_ran_via_create(self) -> None:
        assert self.result["totals"]["ran_via_create"] == 3

    def test_total_ran_via_unwrap(self) -> None:
        assert self.result["totals"]["ran_via_unwrap"] == 2

    def test_total_skipped_no_path(self) -> None:
        assert self.result["totals"]["skipped_no_path"] == 1

    def test_total_ran_via_external_zero(self) -> None:
        assert self.result["totals"]["ran_via_external"] == 0

    def test_totals_sum_correctly(self) -> None:
        totals = self.result["totals"]
        assert totals["ran_via_create"] + totals["ran_via_unwrap"] + totals["skipped_no_path"] == 6

    def test_only_two_obj_classes_present(self) -> None:
        assert set(self.result["by_class"].keys()) == {"secret", "private"}
