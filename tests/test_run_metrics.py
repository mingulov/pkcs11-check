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
