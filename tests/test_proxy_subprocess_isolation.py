from __future__ import annotations

import inspect

from pkcs11_check.testcases.test_remaining_gaps import (
    TestLegacyParallelFunctions as _TestLegacyParallelFunctions,
)
from pkcs11_check.testcases.test_v30_session import TestSessionCancel as _TestSessionCancel


def test_subprocess_only_tests_do_not_open_parent_raw_session() -> None:
    methods = [
        _TestLegacyParallelFunctions.test_get_function_status_returns_not_parallel,
        _TestLegacyParallelFunctions.test_cancel_function_returns_not_parallel,
        _TestSessionCancel.test_cancel_after_digest_init_subprocess,
    ]

    for method in methods:
        assert "p11_raw_session" not in inspect.signature(method).parameters
