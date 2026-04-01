# Changelog

## [0.1.0] - 2026-04-01

Initial beta release.

### Features

- **PKCS#11 interface negotiation** — automatic v2.40/v3.0/v3.1/v3.2 detection with `--interface` forcing
- **Crash survival** — per-file subprocess isolation recovers from SIGSEGV in loaded modules
- **Pure ctypes binding** (`pkcs11_check.raw`) — all 68 v2.40 functions + v3.0 message-based + v3.2 KEM, no C compilation
- **75,000+ tests** across 150+ test files covering crypto, compliance, security, and PQC
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

### Requirements

- Python 3.13+
- Linux (primary), macOS and Windows where ctypes works
