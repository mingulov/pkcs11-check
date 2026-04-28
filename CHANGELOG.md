# Changelog

## [0.1.0] - 2026-04-01

Initial beta release.

### Features

- **PKCS#11 interface negotiation** — automatic v2.40/v3.0/v3.1/v3.2 detection with `--interface` forcing
- **Crash survival** — per-file subprocess isolation recovers from SIGSEGV in loaded modules
- **Pure ctypes binding** (`pkcs11_check.raw`) — all 68 v2.40 functions + v3.0 message-based + v3.2 KEM, no C compilation
- **75,000+ tests** across 220+ test files covering crypto, compliance, security, and PQC
- **CKR spec compliance** — 802 conditions checked against OASIS PKCS#11 standard
- **Cross-verification** — Wycheproof (C2SP) and ACVP (NIST) test vectors
- **PQC support** — ML-KEM, ML-DSA, SLH-DSA tests for v3.2 modules
- **CVE regression** — 29 tests for known vulnerabilities across 6 module families
- **12 Docker targets** — SoftHSM2, Kryoptic, NSS, OpenCryptoki, TPM2, BouncyHSM, and more
- **Local build system** — 10 provider build scripts for fast iteration
- **pytest plugin** — `pytest --p11-module=...` for custom test suites
- **CLI** — `pkcs11-check test`, `info`, `state`, `compliance-report`

### Supported modules

- SoftHSM2 2.7.0
- Kryoptic 1.5.0+PQC (v3.2)
- NSS 3.120.1 / 3.121.0 PQC
- OpenCryptoki 3.26
- tpm2-pkcs11 1.9.0
- BouncyHSM 2.0.1
- pkcs11-mock 2.0.0
- qryptotoken 0.4.1

### Test Results (2026-04-09)

Tested 6 modules, ~510K total test executions across 237 test files:

| Module | Passed | Failed | Skipped | Xfailed | Total |
|--------|-------:|-------:|--------:|--------:|------:|
| OpenCryptoki (master) | 75,265 | 2,405 | 8,512 | 54 | 86,242 |
| BouncyHSM (v2.0.1) | 66,307 | 22,282 | 8,694 | 59 | 97,345 |
| Kryoptic (main) | 65,674 | 2,831 | 32,218 | 68 | 100,791 |
| SoftHSM2 (main) | 60,820 | 2,697 | 16,943 | 41 | 80,501 |
| NSS (main) | 46,185 | 2,018 | 34,454 | 105 | 82,763 |
| tpm2-pkcs11 (1.9.1) | 8,202 | 5,028 | 47,977 | 2 | 62,242 |

Key findings: 2 CRITICAL (NSS sensitive key exposure, Tookan CKA_EXTRACTABLE escalation),
9 HIGH-severity issues across 4 modules, real SIGSEGV crashes in all 6 modules.
See [docs/release-v0.1.0.md](docs/release-v0.1.0.md) for full breakdown.

### Requirements

- Python 3.13+
- Linux (primary), macOS and Windows where ctypes works
