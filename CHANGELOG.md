# Changelog

## [0.1.0] - 2026-05-04

First public release.

This release packages the internal beta work into a public CLI-first PKCS#11 test
suite. It includes the command line app, pytest plugin, pure-ctypes raw binding,
provider isolation, security regression coverage, Docker/local provider tooling,
and release-readiness hardening needed for use across multiple projects.

### Features

- **PKCS#11 interface negotiation** - automatic v2.40/v3.0/v3.1/v3.2 detection
  with `--interface` forcing.
- **Crash survival** - per-file subprocess isolation keeps the runner alive when
  loaded modules segfault or abort.
- **Pure ctypes binding** (`pkcs11_check.raw`) - v2.40, v3.0 message-based, and
  v3.2 KEM surfaces without C compilation.
- **Large product test suite** - mechanism, compliance, security, CVE, Wycheproof,
  ACVP, CCTV, X.509, and PQC coverage.
- **pytest plugin** - run project-specific tests with `pytest --p11-module=...`.
- **CLI** - `pkcs11-check test`, `info`, `state`, `compliance-report`,
  `fetch-data`, and related helper commands.
- **Provider tooling** - local and Docker flows for SoftHSM2, Kryoptic, NSS,
  OpenCryptoki, TPM2, BouncyHSM, pkcs11-mock, and related targets.

### Security and Compliance Coverage

- Added regression coverage for known PKCS#11 vulnerability classes, including
  Tookan-style attribute escalation, sensitive/extractable downgrade checks,
  Bleichenbacher/Manger RSA oracle families, CBC padding-oracle patterns, KWP
  error-path behavior, arithmetic/boundary validation, and API state misuse.
- Added hard-fail gates for access-control and attribute-enforcement issues such
  as `CKA_TRUSTED`, `CKA_COPYABLE`, `CKA_DESTROYABLE`,
  `CKA_WRAP_WITH_TRUSTED`, and non-extractable key handling.
- Added authenticated wrap, ECDH AES key wrap, v3.0 message API, multipart state,
  and cross-process isolation checks.
- Added module quirk registry support so provider-specific behavior is explicit,
  documented, and does not silently hide real failures.
- Expanded `docs/module-issues.md` and `docs/cve-regression.md` with findings and
  coverage notes discovered during internal provider validation.

### Release Hardening

- Hardened `fetch-data` by requiring HTTPS downloads and rejecting unsafe archive
  members that could escape the extraction directory.
- Removed shell invocation from OpenSSL interop tests.
- Replaced silent broad `except Exception: pass` patterns with specific handling
  or direct failure paths.
- Annotated intentional legacy PKCS#11 crypto references, including SHA-1 and
  AES-ECB compatibility checks, so scanner output separates deliberate mechanism
  coverage from unsafe application crypto.
- Added release hygiene tests for broad exception swallowing, `shell=True`,
  non-security SHA-1 context, legacy crypto annotations, public-doc path leaks,
  and packaging hygiene.
- Verified the package with linting, formatting, strict mypy, meta-tests,
  product-test collection, SoftHSM2 smoke, dependency audit, Bandit medium/high
  scan, credential-focused secret scan, wheel/sdist build, artifact scrub, and
  isolated wheel install smoke.

### Supported modules

- SoftHSM2 2.7.0
- Kryoptic 1.5.0+PQC (v3.2)
- NSS 3.120.1 / 3.121.0 PQC
- OpenCryptoki 3.26
- tpm2-pkcs11 1.9.0
- BouncyHSM 2.0.1
- pkcs11-mock 2.0.0

### Test Results (2026-04-09)

Internal baseline results before the public release candidate. These numbers are
kept as release evidence from the deliberate provider validation run and should
only be refreshed after another full provider validation pass.

Tested 6 modules, ~510K total test executions across 237 test files:

| Module | Passed | Failed | Skipped | Xfailed | Total |
|--------|-------:|-------:|--------:|--------:|------:|
| OpenCryptoki (master) | 75,265 | 2,405 | 8,512 | 54 | 86,242 |
| BouncyHSM (v2.0.1) | 66,307 | 22,282 | 8,694 | 59 | 97,345 |
| Kryoptic (main) | 65,674 | 2,831 | 32,218 | 68 | 100,791 |
| SoftHSM2 (main) | 60,820 | 2,697 | 16,943 | 41 | 80,501 |
| NSS (main) | 46,185 | 2,018 | 34,454 | 105 | 82,763 |
| tpm2-pkcs11 (1.9.1) | 8,202 | 5,028 | 47,977 | 2 | 62,242 |

Findings are classified under a hardware-token threat model and are not CVE-grade
vulnerability claims against upstream projects. The two CRITICAL rows are
upstream-known properties of NSS softokn (software-only token) rather than
defects; HIGH-severity issues span 4 modules; real SIGSEGV crashes in all 6
modules. See [docs/release-v0.1.0.md](docs/release-v0.1.0.md) for the
severity-model note and full breakdown.

### Requirements

- Python 3.13+
- Linux (primary), macOS and Windows where ctypes works
