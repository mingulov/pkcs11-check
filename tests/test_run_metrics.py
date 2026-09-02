from pkcs11_check.core.process_observation import build_process_observation
from pkcs11_check.core.run_metrics import (
    RESULT_OUTCOME_KEYS,
    compute_child_subprocess_counts,
    run_is_incomplete,
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


def test_run_is_incomplete_accepts_one_shot_unit_iterable() -> None:
    units = iter([{"incomplete": True}])

    assert run_is_incomplete({}, units) is True


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


def test_structured_child_crash_requires_failed_parent() -> None:
    probe = build_process_observation("probe", "probe", 0, -11, parent_nodeid="t.py::test_pass")
    units = [
        {
            "tests": [{"nodeid": "t.py::test_pass", "outcome": "passed"}],
            "executions": [probe],
        }
    ]

    assert compute_child_subprocess_counts(units) == (0, 0)


def test_legacy_marker_is_kept_when_structured_probe_belongs_to_passing_test() -> None:
    probe = build_process_observation("probe", "probe", 0, -11, parent_nodeid="t.py::test_pass")
    units = [
        {
            "tests": [
                {"nodeid": "t.py::test_pass", "outcome": "passed"},
                {
                    "nodeid": "t.py::test_legacy",
                    "outcome": "failed",
                    "longrepr": "module crashed with signal 11",
                },
            ],
            "executions": [probe],
        }
    ]

    assert compute_child_subprocess_counts(units) == (1, 0)


def test_structured_retries_count_once_per_failed_test() -> None:
    parent = "t.py::test_failed"
    first = build_process_observation("probe", "probe", 0, -11, parent_nodeid=parent)
    last = build_process_observation(
        "probe", "probe", 1, None, timed_out=True, parent_nodeid=parent
    )
    units = [
        {
            "tests": [{"nodeid": parent, "outcome": "failed"}],
            "executions": [first, last],
        }
    ]

    assert compute_child_subprocess_counts(units) == (0, 1)


def test_structured_native_windows_exception_counts_as_child_crash() -> None:
    parent = "t.py::test_failed"
    observation = build_process_observation(
        "probe", "probe", 0, 0xC0000005, platform="win32", parent_nodeid=parent
    )
    units = [{"tests": [{"nodeid": parent, "outcome": "failed"}], "executions": [observation]}]

    assert compute_child_subprocess_counts(units) == (1, 0)


def test_legacy_windows_child_exception_requires_same_parent_traceback() -> None:
    parent = "t.py::test_failed"
    observation = build_process_observation(
        "probe", "probe", 0, 1, platform="win32", parent_nodeid=parent
    )
    units = [
        {
            "tests": [
                {
                    "nodeid": parent,
                    "outcome": "failed",
                    "longrepr": (
                        "Failed: child subprocess failed\n"
                        "stderr:\nOSError: exception: access violation reading 0"
                    ),
                }
            ],
            "executions": [observation],
        }
    ]

    assert compute_child_subprocess_counts(units) == (1, 0)


def test_direct_or_generic_exit_does_not_count_as_child_exception() -> None:
    direct = build_process_observation("probe", "probe", 0, 1, platform="win32")
    generic = build_process_observation(
        "probe", "probe", 0, 1, platform="win32", parent_nodeid="t.py::test_generic"
    )
    units = [
        {
            "tests": [
                {
                    "nodeid": "t.py::test_direct",
                    "outcome": "failed",
                    "longrepr": "OSError: generic provider error",
                },
                {
                    "nodeid": "t.py::test_generic",
                    "outcome": "failed",
                    "longrepr": "the words access violation appeared in a note",
                },
            ],
            "executions": [direct, generic],
        }
    ]

    assert compute_child_subprocess_counts(units) == (0, 0)
