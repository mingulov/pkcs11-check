# Changelog

## [0.1.3] - 2026-06-04

Faster, more diagnosable, and a documented contract for tools building on it.
No breaking CLI or API changes (new commands/flags are additive; the default
`pkcs11-check test` still runs the full suite).

- **Faster.** Postprocessing of the per-run report no longer loads the whole
  ~200 MB log into memory (peak ~1.4 GB → ~380 MB), which lets the pooled runner
  pack more containers per host; isolated subprocesses skip unused pytest
  plugins; parsed test vectors and collection metadata are cached; the pooled
  shard balancer isolates the recurring long-pole files; the NSS slot-0 passes
  run only the digest/cipher/KDF files unique to slot 0 instead of the whole
  suite (coverage-neutral); and BouncyHSM starts on a readiness poll instead of
  a fixed sleep.
- **`pkcs11-check doctor`.** A new command that diagnoses the common setup
  problems — wrong slot index (vs the provider's slot ID), wrong/locked PIN,
  uninitialized or unrecognized token, an unloadable library, a crashing module,
  and missing vector data — and prints the exact next step for each.
- **Faster *opt-in* runs.** `--skip-slow` / `--only-slow` select a fast profile
  that omits a small set of individually long-running cases (large-RSA, DSA/DH
  parameter generation, AES multi-block, leak/fuzz loops); the full run is
  unchanged by default.
- **More correct.** tpm2's `C_GenerateKey` returning `CKR_FUNCTION_NOT_SUPPORTED`
  (no symmetric keygen surface) now classifies as `xfail`, not a hard fail;
  session-capacity (`CKR_SESSION_COUNT`) handling and subprocess cleanup were
  standardized so one provider hiccup no longer cascades.
- **For tool builders.** `docs/integration-contract.md` documents the stable
  surface to depend on (exit codes, the results/coverage/quality JSON schemas,
  the shard split→merge round-trip, the reusable raw binding / pytest plugin).
  `test --help` is grouped into Common / Isolation / CK_RV-tracing / Advanced
  panels, and the README has a "first run in 60 seconds" quickstart.

### Supported modules

SoftHSM2 2.7.0 / main · Kryoptic v1.5.0 / main / FIPS · NSS (Fedora softoken,
slots 0 and 1) / main · OpenCryptoki v3.27.0 / master · tpm2-pkcs11 1.10.0 ·
BouncyHSM v2.1.0 · pkcs11-mock v2.0.0

### Test Results

Latest full provider matrix (`docs/matrix/baseline-2026-06-04.json`,
2026-06-04), one row per distinct build. Validated by **two independent full
sweeps** that agree; failures held or decreased on every provider vs the v0.1.2
baseline (PC-6 keygen reclassification + gap-triage), crashes stable.

| Build | Passed | Failed | Skipped | Xfailed | Crashed | Total |
|-------|-------:|-------:|--------:|--------:|--------:|------:|
| SoftHSM2 2.7.0 | 42,050 | 136 | 31,753 | 5,025 | 0 | 78,964 |
| SoftHSM2 main | 42,992 | 135 | 31,506 | 5,110 | 0 | 79,743 |
| Kryoptic v1.5.0 | 48,192 | 171 | 44,687 | 12,419 | 0 | 105,469 |
| Kryoptic main | 48,207 | 162 | 44,686 | 12,414 | 0 | 105,469 |
| Kryoptic FIPS/PQC | 34,524 | 128 | 44,489 | 10,235 | 12 | 89,388 |
| NSS (Fedora, slot 1) | 35,739 | 168 | 53,117 | 815 | 3 | 89,842 |
| NSS (Fedora, slot 0) | 1,425 | 29 | 671 | 173 | 3 | 2,301 |
| NSS main (slot 1) | 34,870 | 145 | 53,396 | 734 | 4 | 89,149 |
| OpenCryptoki v3.27.0 | 59,732 | 357 | 32,877 | 1,256 | 0 | 94,222 |
| OpenCryptoki master | 59,732 | 357 | 32,877 | 1,256 | 0 | 94,222 |
| tpm2-pkcs11 1.10.0 | 6,596 | 182 | 67,058 | 4,375 | 0 | 78,211 |
| BouncyHSM v2.1.0 | 52,626 | 8,143 | 36,204 | 8,006 | 3 | 104,982 |
| pkcs11-mock v2.0.0 | 230 | 104 | 29,135 | 58 | 0 | 29,527 |

~1.04M total test executions across these 13 builds (~1.21M across the full
17-target matrix, including variants). The **NSS slot-0 row drops to ~2.3k**:
the `*-slot0` passes are now scoped to the slot-0-unique digest/cipher/KDF files
instead of re-running the whole slot-1 suite (coverage-neutral). Real SIGSEGV
crash findings remain on NSS (3-4, including a `C_FindObjectsInit(ULONG_MAX)`
overflow) and BouncyHSM (3); the 12 Kryoptic FIPS/PQC "crashes" are debug-build
`abort()`s on internal assertions, not release segfaults. See
[docs/docker-provider-results.md](docs/docker-provider-results.md) for the full
17-target matrix and [docs/module-issues.md](docs/module-issues.md) for per-module
findings.

## [0.1.2] - 2026-05-31

Maintenance release. The headline is **much faster test runs** and **refreshed
provider results**, plus a handful of reliability improvements and minor fixes.
No breaking CLI or API changes.

- **Faster runs.** Tests that just verify vectors now log in once per file
  instead of once per test, so providers with slow logins speed up dramatically
  — the ECDSA Wycheproof file went from ~42 min to under a minute on OpenCryptoki
  and from ~56 min to ~2 min on BouncyHSM. SoftHSM2, NSS, and Kryoptic (fast
  logins) are unchanged.
- **Steadier under stress.** The harness now recovers from provider/proxy
  restarts and from providers that leave an operation dangling, so one hiccup
  no longer cascades over the rest of a run. A new opt-in call trace + crash
  journal make it easier to pin down the exact call behind a crash.
- **Minor fixes.** Test-result classification cleanups, security-probe hygiene
  (PINs are never written into subprocess scripts), and CI tweaks.

### Supported modules

SoftHSM2 2.7.0 / main · Kryoptic v1.5.0 / main / FIPS · NSS (Fedora softoken,
slots 0 and 1) / main · OpenCryptoki v3.27.0 / master · tpm2-pkcs11 1.10.0 ·
BouncyHSM v2.1.0 · pkcs11-mock v2.0.0

### Test Results

Latest full provider matrix (`artifacts/20260530_3/`, 2026-05-30/31), one row per
distinct build. Failures, crashes, and skips are kept as provider findings — a
crash is a finding, not a hidden result.

| Build | Passed | Failed | Skipped | Xfailed | Crashed | Total |
|-------|-------:|-------:|--------:|--------:|--------:|------:|
| SoftHSM2 2.7.0 | 42,051 | 135 | 31,753 | 5,025 | 0 | 78,964 |
| SoftHSM2 main | 42,994 | 136 | 31,504 | 5,110 | 0 | 79,744 |
| Kryoptic v1.5.0 | 48,195 | 172 | 44,685 | 12,418 | 0 | 105,470 |
| Kryoptic main | 48,209 | 164 | 44,684 | 12,413 | 0 | 105,470 |
| Kryoptic FIPS/PQC | 34,526 | 130 | 44,487 | 10,234 | 12 | 89,389 |
| NSS (Fedora, slot 1) | 35,741 | 183 | 53,115 | 801 | 3 | 89,843 |
| NSS (Fedora, slot 0) | 36,315 | 197 | 52,990 | 822 | 3 | 90,327 |
| NSS main (slot 1) | 34,870 | 164 | 53,394 | 718 | 4 | 89,150 |
| OpenCryptoki v3.27.0 | 59,735 | 357 | 32,875 | 1,256 | 0 | 94,223 |
| OpenCryptoki master | 59,735 | 357 | 32,875 | 1,256 | 0 | 94,223 |
| tpm2-pkcs11 1.10.0 | 6,597 | 188 | 67,056 | 4,371 | 0 | 78,212 |
| BouncyHSM v2.1.0 | 52,628 | 8,144 | 36,202 | 8,006 | 3 | 104,983 |
| pkcs11-mock v2.0.0 | 230 | 117 | 29,123 | 58 | 0 | 29,528 |

~1.13M total test executions across the 13 builds. Real SIGSEGV crash findings
remain on NSS (3-4) and BouncyHSM (3). The 12 "crashes" on the Kryoptic FIPS/PQC
row are **not** release crashes: that build is compiled in debug mode, so its
internal debug assertions `abort()` the process on a check failure rather than
returning an error — they are debug-assertion aborts, not segfaults in a release
build. See [docs/docker-provider-results.md](docs/docker-provider-results.md) for
the full 17-target matrix (including variants) and
[docs/module-issues.md](docs/module-issues.md) for per-module findings.

## [0.1.1] - 2026-05-27

Maintenance and coverage release on top of 0.1.0. Focuses on a consistent
test-outcome classification model, broader cryptographic test vectors, and
raw-binding cleanups. No CLI or public API changes.

### Changed

- **Test-outcome classification** - applied a consistent model across the suite
  that separates provider deviations (`xfail`) from genuine failures (`fail`):
  crypto breaks, self-contradictions, and crashes. Setup and runtime rejects are
  classified against specific CKR codes instead of broad catches.
- **Provider-neutral findings** - failure and skip messages no longer hard-code
  provider names; capability probes drive xfail/skip decisions.
- **Raw binding** - refactored `pkcs11_check.raw` helpers and deduplicated test
  error-set definitions and byte-copy paths.

### Added

- Expanded Wycheproof, ACVP, and negative-vector coverage with structured CKR
  matching and tightened acceptance boundaries.
- SoftHSM2 EdDSA EC-point encoding investigation notes and reproduction files
  under `docs/`.

### Fixed

- Corrected Wycheproof signature and point adaptation: DSA DER signatures, ECDH
  SPKI point extraction, P-521 SHAKE256 digest length, and RSA integer imports.

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
