from pkcs11_check.core.run_metrics import (
    RESULT_OUTCOME_KEYS,
    compute_child_subprocess_counts,
)


def test_outcome_keys_include_crash_limited_after_legacy_eight():
    assert RESULT_OUTCOME_KEYS == (
        "passed",
        "failed",
        "skipped",
        "xfailed",
        "xpassed",
        "error",
        "crashed",
        "timeout",
        "crash_limited",
    )


def test_child_counts_only_failed_with_markers():
    units = [
        {
            "tests": [
                {"outcome": "failed", "longrepr": "C_X: module crashed with signal 11"},
                {
                    "outcome": "failed",
                    "longrepr": "subprocess.TimeoutExpired: timed out after 15 seconds",
                },
                {"outcome": "failed", "longrepr": "plain assertion, no marker"},
                {
                    "outcome": "passed",
                    "longrepr": "module crashed with signal 11",
                },  # not failed -> ignored
            ]
        },
        {"tests": [{"outcome": "failed", "longrepr": "subprocess crashed with signal 6"}]},
        {"counts": {"skipped": 3}},  # no tests key -> ignored
    ]
    assert compute_child_subprocess_counts(units) == (2, 1)


def test_reload_cycle_crash_variant_is_counted_as_child_crash():
    # The subprocess-safety probe phrases it "Reload cycle crashed with signal (rc=...)"; the
    # child-crash marker must catch every "<what> crashed with signal <n>" variant, not just
    # the "module"/"subprocess" prefixes.
    units = [
        {
            "tests": [
                {"outcome": "failed", "longrepr": "Reload cycle crashed with signal (rc=-11)"},
            ]
        },
    ]
    assert compute_child_subprocess_counts(units) == (1, 0)
