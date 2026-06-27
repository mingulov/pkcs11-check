"""Regression test: file_runner entry function default must match the CLI default (10).

The authoritative default is defined in src/pkcs11_check/cli/test_cmd.py
(the --max-crashes-per-file option, default=10).  The runner entry function
must carry the same default so callers that bypass the CLI also get the
expected behaviour.
"""

import inspect

from pkcs11_check.core import file_runner


def test_max_crashes_per_file_runner_default_matches_cli() -> None:
    sig = inspect.signature(file_runner.run_isolated_pytest_units)
    default = sig.parameters["max_crashes_per_file"].default
    assert default == 10, (
        f"file_runner.run_isolated_pytest_units max_crashes_per_file default is {default!r}, "
        f"expected 10 (must match the CLI --max-crashes-per-file default)"
    )
