# p11test Current Status

Last updated: 2026-03-19

## What Works

- **22,800+ tests** passing on SoftHSM2 2.7.0 and Kryoptic 1.5.0+PQC
- **802/802 CKR spec entries** — every function-specific CKR from OASIS spec documented
- **148+ CKR error tests** with raw ctypes bypass for wrapper-blocked conditions
- **v3.0/v3.2 interface negotiation** — tested on Kryoptic
- **PQC support** — ML-KEM, ML-DSA, SLH-DSA tested on Kryoptic
- **Adaptive isolated runner** — `--isolation auto|file|test` survives crashes, escalates crashing files in-run, and remembers crash-prone files per backend
- **JSON/JUnit report output** — `--output json` or `--output junit`
- **10 local build providers** — SoftHSM2, Kryoptic, NSS, pkcs11-mock, qryptotoken, tpm2-pkcs11, BouncyHSM, OpenCryptoki, swtpm, tpm2-swtpm
- **12 Docker test targets** for CI validation
- **CI workflow** — GitHub Actions with lint, typecheck, tests, strict markers, smoke

## What's Partial

- **JSON report** — uses pytest-json-report plugin, works but large output
- **Per-target validation** — SoftHSM2 + Kryoptic fully validated, others need re-run post CKR changes
- **Fault injection proxy** — works for v2.40 functions, v3.0+ not yet intercepted
- **v3.0 message-based tests** — 6 tests proven on Kryoptic, more possible

## What's Planned

- **Per-target re-validation** — 11 targets need fresh validation runs
- **Docker final pass** — rebuild all images, one clean pass
- **pyproject.toml polish** — URLs, classifiers for PyPI
- **Interface negotiation negative tests** — invalid names, unsupported versions
- **Baseline regression workflow** — structured result diffs per module
