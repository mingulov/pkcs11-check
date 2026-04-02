# Audit 00: Pre-Audit Baseline

**Date:** 2026-04-01

## Baseline Meta-Test Results

- **Passed:** 604
- **Failed:** 2 (pre-existing: `test_raw_header_parity.py` function count regression)
- **Skipped:** 1
- **Excluded:** `test_cli.py` (pre-existing exit code mismatch)

## Pre-Existing Failures (not introduced by audit)

1. `tests/test_cli.py::TestTestCommand::test_test_file_isolation_invokes_runner` — exit code 2 != 7
2. `tests/test_raw_header_parity.py::TestMetadataParity::test_all_reference_functions_present` — function count mismatch
3. `tests/test_raw_header_parity.py::TestMetadataParity::test_function_count_not_regressed` — function count regression

## Environment

- Branch: `dev`
- OASIS spec files: 107 available
- PKCS#11 v3.2 header: `third_party/pkcs11-headers/3.2/pkcs11.h`
