from pkcs11_check.core.compare_results import ResultsComparison, compare_results, status_class


def test_status_class_known_unit_statuses() -> None:
    assert status_class("passed") == "pass"
    for s in ("failed", "crashed", "timeout"):
        assert status_class(s) == "failure"
    for s in ("empty", "crash_limited", "escalated"):
        assert status_class(s) == "skipped"


def test_status_class_unknown_is_not_silently_pass() -> None:
    # The latent bug being fixed: an unrecognized status must NOT map to "pass".
    assert status_class("totally-new-status") == "unknown"


def _cmp(
    base_map: dict[str, str],
    base_sum: dict[str, int],
    curr_map: dict[str, str],
    curr_sum: dict[str, int],
) -> ResultsComparison:
    return compare_results(base_map, base_sum, curr_map, curr_sum)


def test_failure_count_increase_inside_red_files_is_regression() -> None:
    base = {"summary": {"failed": 3}, "map": {"f.py": "failed"}}
    curr = {"summary": {"failed": 50}, "map": {"f.py": "failed"}}
    c = _cmp(base["map"], base["summary"], curr["map"], curr["summary"])  # type: ignore[arg-type]
    assert c.has_regressions is True


def test_failure_count_decrease_is_no_regression() -> None:
    c = _cmp({"f.py": "failed"}, {"failed": 50}, {"f.py": "failed"}, {"failed": 3})
    assert c.has_regressions is False


def test_lost_coverage_previously_passing_target_now_absent_is_regression() -> None:
    c = _cmp({"a.py": "passed"}, {"passed": 1}, {}, {})
    assert "a.py" in c.lost_coverage
    assert c.has_regressions is True


def test_new_failure_crossing_is_regression() -> None:
    c = _cmp({"a.py": "passed"}, {"passed": 1}, {"a.py": "crashed"}, {"crashed": 1})
    assert "a.py" in c.new_failures
    assert c.has_regressions is True


def test_unknown_status_in_current_is_flagged_not_hidden() -> None:
    c = _cmp({"a.py": "passed"}, {"passed": 1}, {"a.py": "weird"}, {})
    assert ("a.py", "weird") in c.unknown_statuses
    assert c.has_regressions is True  # conservative: never silently pass
