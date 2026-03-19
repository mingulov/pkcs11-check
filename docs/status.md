# pkcs11-check Current Status

Last updated: 2026-03-19

## What Works

- **22,800+ tests** passing on SoftHSM2 2.7.0 and Kryoptic 1.5.0+PQC
- **802/802 CKR spec entries** — every function-specific CKR from OASIS spec documented
- **148+ CKR error tests** with raw ctypes bypass for wrapper-blocked conditions
- **v3.0/v3.2 interface negotiation** — tested on Kryoptic
- **PQC support** — ML-KEM, ML-DSA, SLH-DSA tested on Kryoptic
- **Adaptive isolated runner** — `pkcs11-check test` now defaults to `--isolation auto`; `auto|file|test` survive crashes, escalate crashing files in-run, and remember crash-prone files per backend
- **JSON/JUnit isolated reports** — `--output json` or `--output junit`
- **State inspection command** — `pkcs11-check state` summarizes saved isolation state and policy files
- **Marker-aware isolation planning** — `auto` learns `subprocess` and `subprocess_per_test` from collected pytest metadata, not source-text scans
- **10 local build providers** — SoftHSM2, Kryoptic, NSS, pkcs11-mock, qryptotoken, tpm2-pkcs11, BouncyHSM, OpenCryptoki, swtpm, tpm2-swtpm
- **12 Docker test targets** for CI validation
- **CI workflow** — GitHub Actions with lint, typecheck, tests, strict markers, smoke

## What's Partial

- **JSON report** — non-isolated mode still uses `pytest-json-report`; isolated mode uses an aggregated runner report
- **Unsafe fast path still exists** — `--isolation none` still runs in-process
- **Per-target validation** — SoftHSM2 + Kryoptic fully validated, others need re-run post CKR changes
- **Fault injection proxy** — works for v2.40 functions, v3.0+ not yet intercepted
- **v3.0 message-based tests** — 6 tests proven on Kryoptic, more possible
- **Crash-prone Docker paths** — now use `pkcs11-check test`, but the full matrix still needs a fresh pass

## What's Planned

- **Per-target re-validation** — 11 targets need fresh validation runs
- **Docker final pass** — rebuild all images, one clean pass
- **pyproject.toml polish** — URLs, classifiers for PyPI
- **Interface negotiation negative tests** — invalid names, unsupported versions
- **Baseline regression workflow** — structured result diffs per module
