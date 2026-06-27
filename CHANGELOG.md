# Changelog

## [0.1.6] - 2026-06-25

A bug-fix and documentation release - no CLI or API changes.

- **Fix: full runs from an installed package.** The default full run
  (`pkcs11-check test`, `--isolation auto`) could abort at startup with
  `subprocess_per_test file was not expanded to per-test units` when run from a
  pip/uv-installed package that has no pytest config file above it. pytest's
  `rootdir` was being dragged to `/` by the absolute run-manifest path on its
  command line, so collected nodeids came out slash-less and no longer matched
  their files. Per-test isolation units are now pinned to the resolved absolute
  file path, making the expansion robust to pytest's `rootdir`. (Source-checkout
  and CI runs were unaffected, which is why it only surfaced for installed users.)
  Workaround on 0.1.4 / 0.1.5: `--isolation file`.
- **Fix: spurious pytest cache warning.** The same `rootdir = /` condition made
  pytest's cache provider warn `could not create cache path /.pytest_cache:
  Permission denied`. pkcs11-check tracks its own run state, so pytest's cache is
  now disabled (`-p no:cacheprovider`) and the warning is gone.
- **Docs.** New `docs/getting-started-softhsm2.md` - a complete SoftHSM2
  walkthrough (config, token, run, reading reports, troubleshooting) - and a
  README section on saving machine-readable reports
  (`--output json --output-file`).

### Requirements

- Python 3.12+
- Linux (primary), macOS and Windows where ctypes works

## [0.1.5] - 2026-06-25

Key provisioning and hardening conformance. This release adds an opt-in
key-provisioning layer so capability-limited modules can be exercised on
operations they would otherwise skip, and a cross-provider hardening-conformance
suite (G1-G8) that checks input-validation boundaries and policy invariants by
*verifying the effect* rather than trusting a return code. The validation matrix
grows to **30 provider builds**. No breaking CLI or API changes - new flags and
checks are additive and default to the prior behavior (`--key-inject=off`).

- **Opt-in key provisioning.** When a module cannot itself generate a key a test
  needs, the suite can now provision one through an escalating, provider-general
  chain - `create` → `unwrap` → external tool → `skip` - across secret, private,
  public, certificate, and data objects. It is **off by default**
  (`--key-inject=off`, a clean skip); opt in with `--key-inject=unwrap`. The
  unwrap path bootstraps a wrapping key, auto-negotiates the OAEP hash (probes the
  module, prefers SHA-256, falls back to SHA-1), and selects a wrap strategy
  (RSA-AES-KEY-WRAP / RSA-OAEP / AES-KWP) by key size. An optional external-tool
  tier (`--allow-external-provision` / `--external-provision-cmd`) provisions via a
  user-supplied command and find-by-label. A provisioning report (JSONL sidecar
  plus a dedicated per-class `C_CreateObject`-availability conformance test)
  records what was created, unwrapped, or skipped. This lets import-only and
  signing-only modules be checked on operations that previously mass-skipped,
  without inventing capability they do not have.

- **Cross-provider hardening-conformance checks (G1-G8).** A new family (~25
  checks) probes input-validation boundaries and policy invariants that the spec
  requires but providers often leave unguarded: 64→32-bit length-field handling
  (`C_GenerateRandom`, `AES-KEY-WRAP-PAD`, find-count, KDF parameter lengths) via a
  demand-zero output-length oracle, declared-length mismatches on scalar and
  boolean-overlong attributes, nested-template enforcement, public-session private
  object creation, SO empty-PIN fail-open on an unprovisioned token,
  use-after-free when a key is destroyed mid-operation, required parameter sets
  (ML-DSA `CKA_PARAMETER_SET`, EC `CKA_EC_PARAMS`), and `C_SetAttributeValue`
  attribute-weakening. Every check **verifies the effect** (read-back, derive,
  output-equivalence) instead of trusting the return code - which both surfaces
  real silent-truncation findings and prevents false-accusing compliant modules
  (a DH generator of 0 and a spec-legal RSA-512 keygen are confirmed *not*
  findings, not failed).

- **Sound FFI length probing.** The 64→32-bit truncation probes either back the
  full claimed length with a demand-zero `mmap` or use un-honorable magnitudes
  (2^63, behind a honeypot mapping and a 30-second timeout), so a module that
  correctly honors a 64-bit length is never false-accused by harness undefined
  behavior. Silent truncation fails; an honored large length is a recorded note.

- **Finding integrity.** The finding-leak lint now also catches multi-line
  `assert`, tuple-form `except: pass`, and comment-then-pass evasions; raw
  `pytest.xfail()` / `pytest.fail()` stays blocked in product tests in favor of
  at-source classification, so a real break cannot be quietly downgraded.

- **Honest teardown.** `C_Finalize` now runs on normal per-file teardown to
  release module resources, and a hung isolation subprocess is classified as a
  crash finding instead of leaking a `TimeoutExpired`.

- **Dependencies.** The `cryptography` floor is raised to **≥49.0.0** (ML-KEM /
  ML-DSA primitives); all locked dependencies were refreshed.

### Supported modules

SoftHSM2 2.7.0 / main · Kryoptic v1.5.1 / main / FIPS · NSS (Fedora softoken,
slots 0 and 1, PQC tip) / main · OpenCryptoki v3.27.0 / master · wolfPKCS11
v2.0.0-stable / master / wolfTPM-fwTPM backend · corePKCS11 v3.6.4 / main ·
tpm2-pkcs11 1.10.0 · BouncyHSM v2.1.1 · pkcs11-mock v2.0.0 · Craton HSM · Nitrokey
NetHSM · FreeHSM-C · jCardSim (IsoApplet) · CrypTech · google-kmsp11 · Cosmian KMS
· pico-hsm (sc-hsm emulation) · OP-TEE (heavy target)

New since 0.1.4: **wolfPKCS11 on a wolfTPM firmware-TPM backend** and **pico-hsm**
(sc-hsm emulation via vpcd + OpenSC).

### Test Results

Full provider matrix (baseline dated 2026-06-21), one row per distinct build, from
the pooled `docker/test_pool.py` sweep (30 targets / 67 sharded items, zero
timeouts). The 23 long-standing targets were reconciled per-test-file against the
prior full pool (2026-06-15): no coverage was lost, no crash regressions, and
every good→bad file crossing traces to an intentional post-0.1.4 framework change,
not a provider regression. Failures, errors, crashes, and skips are kept as
provider findings - a crash is a finding, not a hidden result.

| Build | Passed | Failed | Errored | Skipped | Xfailed | Crashed | Total |
|-------|-------:|-------:|--------:|--------:|--------:|--------:|------:|
| SoftHSM2 2.7.0 | 45,034 | 101 | 0 | 60,936 | 6,215 | 3 | 112,289 |
| SoftHSM2 2.7.0 (generated-IV) | 45,039 | 98 | 0 | 60,934 | 6,215 | 3 | 112,289 |
| SoftHSM2 main | 47,276 | 230 | 0 | 59,148 | 5,716 | 3 | 112,373 |
| Kryoptic v1.5.1 | 58,794 | 203 | 0 | 30,520 | 24,595 | 3 | 114,115 |
| Kryoptic main | 58,796 | 202 | 0 | 30,520 | 24,594 | 3 | 114,115 |
| Kryoptic FIPS/PQC | 44,102 | 231 | 0 | 38,462 | 23,706 | 17 | 106,518 |
| NSS (Fedora, slot 1) | 38,188 | 220 | 0 | 71,630 | 2,483 | 9 | 112,530 |
| NSS PQC (slot 1) | 36,730 | 209 | 0 | 73,252 | 2,405 | 9 | 112,605 |
| NSS main (slot 1) | 36,730 | 209 | 0 | 73,252 | 2,405 | 9 | 112,605 |
| NSS (Fedora, slot 0) | 1,565 | 130 | 0 | 908 | 341 | 9 | 2,953 |
| NSS PQC (slot 0) | 1,610 | 130 | 0 | 923 | 358 | 9 | 3,030 |
| NSS main (slot 0) | 1,610 | 130 | 0 | 923 | 358 | 9 | 3,030 |
| OpenCryptoki v3.27.0 | 64,488 | 244 | 0 | 46,544 | 3,021 | 3 | 114,300 |
| OpenCryptoki master | 64,488 | 245 | 0 | 46,544 | 3,020 | 3 | 114,300 |
| wolfPKCS11 v2.0.0-stable | 46,634 | 680 | 0 | 48,023 | 16,314 | 17 | 111,668 |
| wolfPKCS11 master | 48,663 | 494 | 0 | 48,415 | 14,211 | 4 | 111,787 |
| wolfPKCS11 (wolfTPM fwTPM) | 25,820 | 983 | 0 | 63,020 | 20,108 | 6 | 109,937 |
| corePKCS11 v3.6.4 | 9,353 | 441 | 0 | 90,725 | 10,151 | 0 | 110,670 |
| corePKCS11 main | 9,353 | 441 | 0 | 90,725 | 10,151 | 0 | 110,670 |
| tpm2-pkcs11 1.10.0 | 18,145 | 71 | 0 | 67,442 | 25,638 | 2 | 111,298 |
| pkcs11-mock v2.0.0 | 746 | 278 | 0 | 109,603 | 82 | 0 | 110,709 |
| BouncyHSM v2.1.1 | 54,350 | 2,097 | 0 | 42,135 | 16,565 | 8 | 115,155 |
| Craton HSM | 19,945 | 3,213 | 0 | 60,067 | 27,979 | 0 | 111,204 |
| Nitrokey NetHSM | 11,688 | 529 | 16 | 78,946 | 19,895 | 3 | 111,077 |
| FreeHSM-C | 11,940 | 655 | 8 | 96,512 | 2,525 | 6 | 111,646 |
| jCardSim (IsoApplet) | 1,227 | 1,888 | 30 | 103,789 | 4,003 | 0 | 110,937 |
| CrypTech | 10,541 | 250 | 16 | 82,509 | 17,608 | 0 | 110,924 |
| google-kmsp11 | 11,069 | 165 | 0 | 98,774 | 1,019 | 0 | 111,027 |
| Cosmian KMS | 10,473 | 15,136 | 15 | 80,197 | 4,870 | 3 | 110,694 |
| pico-hsm (sc-hsm) | 12,426 | 1,552 | 16 | 58,136 | 1,654 | 11 | 73,795 |

~3.0M test executions across the full 30-build matrix. The large `xfailed` counts
on capability-limited modules (Craton HSM, NetHSM, CrypTech, tpm2, wolfTPM) are the
capability-boundary-honesty model recording advertised-but-not-operational surface
rather than failing it. The large Cosmian KMS failure count is a KMS
key-capability-metadata snapshot still being triaged. Real SIGSEGV crash findings
remain on NSS, BouncyHSM, wolfPKCS11, FreeHSM-C, and pico-hsm; the Kryoptic
FIPS/PQC "crashes" are debug-build `abort()`s on internal assertions, not release
segfaults. See [docs/module-issues.md](docs/module-issues.md) for per-module
findings.

### Requirements

- Python 3.12+
- Linux (primary), macOS and Windows where ctypes works

## [0.1.4] - 2026-06-17

Broader reach and more honest results. The Python floor drops to **3.12**, the
validation matrix grows to **28 provider builds** (adding software, HSM, and KMS
targets), and a capability-boundary-honesty model makes results across limited and
signing-only modules truthful instead of noisy. No breaking CLI or API changes
(new flags/commands are additive; the default `pkcs11-check test` still runs the
full suite).

- **Runs on Python 3.12.** The minimum supported Python drops from 3.13 to
  **3.12** (`requires-python = ">=3.12"`; ruff/mypy targets and trove classifiers
  updated). This widens the set of distributions and CI images the tool installs
  on out of the box; no 3.13-only language features are used.
- **Capability-boundary honesty.** A module is no longer failed for *not* doing
  something it never advertised. The suite probes real capability - verify
  operability, certificate/object storage (`CKF_VERIFY`, cert-storage probe),
  per-operation mechanism gating - and routes an advertised-but-not-operational
  surface to a recorded `xfail`/`skip` with an explicit reason instead of a false
  `fail`. A local cross-verify oracle lets sign-only modules be checked even when
  the module cannot verify its own signatures. Capability-based gating replaces
  version-number skipping, so a mechanism that *is* supported is no longer
  silently skipped on a version heuristic.
- **Parameter fidelity.** New probes recover the *actual* parameter a module used
  (RSA-PSS salt length / MGF, OAEP hash / MGF / label, GCM tag length) and report
  it, catching silent parameter substitution that a plain pass/fail check misses.
- **Much broader coverage.** Hundreds of new vectors and negative cases: legacy
  block ciphers (RC2/RC4/RC5, IDEA, CAST, Blowfish, Twofish, CDMF, Skipjack,
  GOST 28147, Salsa20), protocol KDFs (TLS 1.0/1.2, SSL3, WTLS, IKE/IKEv2,
  SP800-108, X9.42 DH, X3DH, X2Ratchet, CT-KIP), BLAKE2b, KMAC, SHAKE XOF,
  MAC-general and CBC-PAD vectors, ML-DSA/ML-KEM parameter and semantic hardening,
  and registry-driven negatives (malformed/missing parameters, wrong-key,
  permission). At-source verdict emission (a reason × kind taxonomy) now records
  *why* each outcome was reached and is enforced over raw `pytest.xfail/fail`.
- **More targets checked.** The validation matrix grew to 28 provider builds,
  adding software, HSM, and KMS modules - Craton HSM, Nitrokey NetHSM, FreeHSM-C,
  jCardSim (IsoApplet smartcard sim), CrypTech, google-kmsp11, and Cosmian KMS -
  alongside wolfPKCS11 and corePKCS11 (added since 0.1.3) and pooled OP-TEE
  heavy-target support. Existing pins were refreshed (Kryoptic v1.5.1,
  BouncyHSM v2.1.1).
- **Faster, leaner pooled runs.** Report postprocessing now streams the
  per-unit / retry / resume / final report logs instead of buffering them, the
  pooled runner's concurrency and hot-file sharding were tuned, shared-session
  health checks were reduced for vector files, and vector JSON is loaded through a
  cache.
- **Finding integrity.** Several finding-hiding tests (self-contradiction classes
  that had been softened to `xfail`/note) were corrected to surface as `fail`, and
  raw `pytest.xfail()` / `pytest.fail()` in product tests is now blocked in favor
  of at-source classification, so a real break cannot be quietly downgraded.

### Supported modules

SoftHSM2 2.7.0 / main · Kryoptic v1.5.1 / main / FIPS · NSS (Fedora softoken,
slots 0 and 1) / main · OpenCryptoki v3.27.0 / master · wolfPKCS11 v2.0.0-stable /
master · corePKCS11 v3.6.4 · tpm2-pkcs11 1.10.0 · BouncyHSM v2.1.1 ·
pkcs11-mock v2.0.0 · Craton HSM · Nitrokey NetHSM · FreeHSM-C · jCardSim
(IsoApplet) · CrypTech · google-kmsp11 · Cosmian KMS · OP-TEE (heavy target)

### Test Results

Latest full provider matrix (baseline dated 2026-06-17), one row per distinct
build, from the pooled `docker/test_pool.py` sweep. The run was reconciled
test-id-by-test-id against the prior baseline: no findings disappeared and no test
stopped running. Failures, crashes, and skips are kept as provider findings - a
crash is a finding, not a hidden result.

| Build | Passed | Failed | Skipped | Xfailed | Crashed | Total |
|-------|-------:|-------:|--------:|--------:|--------:|------:|
| SoftHSM2 2.7.0 | 44,972 | 69 | 60,858 | 6,197 | 0 | 112,096 |
| SoftHSM2 main | 47,212 | 199 | 59,071 | 5,698 | 0 | 112,180 |
| Kryoptic v1.5.1 | 58,700 | 160 | 30,483 | 24,579 | 0 | 113,922 |
| Kryoptic main | 58,700 | 160 | 30,483 | 24,579 | 0 | 113,922 |
| Kryoptic FIPS/PQC | 44,006 | 189 | 38,425 | 23,691 | 14 | 106,325 |
| NSS (Fedora, slot 1) | 38,400 | 142 | 71,588 | 2,196 | 9 | 112,335 |
| NSS (Fedora, slot 0) | 1,545 | 79 | 878 | 316 | 9 | 2,827 |
| NSS main (slot 1) | 36,944 | 130 | 73,209 | 2,118 | 9 | 112,410 |
| OpenCryptoki v3.27.0 | 64,574 | 216 | 46,467 | 2,860 | 0 | 114,117 |
| wolfPKCS11 v2.0.0-stable | 46,645 | 609 | 47,958 | 16,241 | 18 | 111,471 |
| wolfPKCS11 master | 48,772 | 434 | 48,351 | 14,031 | 4 | 111,592 |
| corePKCS11 v3.6.4 | 9,500 | 643 | 90,573 | 9,759 | 0 | 110,475 |
| tpm2-pkcs11 1.10.0 | 18,145 | 47 | 67,342 | 25,569 | 0 | 111,103 |
| BouncyHSM v2.1.1 | 54,348 | 2,043 | 42,065 | 16,511 | 5 | 114,972 |
| pkcs11-mock v2.0.0 | 758 | 267 | 109,408 | 81 | 0 | 110,514 |
| Craton HSM | 20,230 | 3,174 | 59,951 | 27,654 | 0 | 111,009 |
| Nitrokey NetHSM | 11,668 | 514 | 78,808 | 19,872 | 0 | 110,883 |
| FreeHSM-C | 11,916 | 617 | 96,439 | 2,466 | 5 | 111,451 |
| jCardSim (IsoApplet) | 1,212 | 1,865 | 103,636 | 3,999 | 0 | 110,742 |
| CrypTech | 10,516 | 253 | 82,357 | 17,587 | 0 | 110,729 |
| google-kmsp11 | 11,066 | 173 | 98,641 | 952 | 0 | 110,832 |
| Cosmian KMS 5.23.0 | 10,465 | 15,142 | 80,035 | 4,844 | 0 | 110,501 |

~2.8M total test executions across the full 28-target matrix (including the
`*-main` / `*-master` / FIPS / slot variants not all shown above). The large
`xfailed` counts on capability-limited modules (Craton HSM, NetHSM, CrypTech,
tpm2) are the capability-boundary-honesty model recording advertised-but-not-
operational surface rather than failing it; Cosmian KMS is a first-sweep snapshot
whose failures are largely key-capability metadata gaps still to be triaged. Real
SIGSEGV crash findings remain on NSS, BouncyHSM, wolfPKCS11, and FreeHSM-C; the 14
Kryoptic FIPS/PQC "crashes" are debug-build `abort()`s on internal assertions, not
release segfaults. See [docs/module-issues.md](docs/module-issues.md) for
per-module findings.

### Requirements

- Python 3.12+
- Linux (primary), macOS and Windows where ctypes works

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
  problems - wrong slot index (vs the provider's slot ID), wrong/locked PIN,
  uninitialized or unrecognized token, an unloadable library, a crashing module,
  and missing vector data - and prints the exact next step for each.
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

Latest full provider matrix (baseline dated 2026-06-04), one row per distinct
build. Validated by **two independent full
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
  - the ECDSA Wycheproof file went from ~42 min to under a minute on OpenCryptoki
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
distinct build. Failures, crashes, and skips are kept as provider findings - a
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
returning an error - they are debug-assertion aborts, not segfaults in a release
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
modules. See the v0.1.0 release notes for the severity-model note and full
breakdown.

### Requirements

- Python 3.13+
- Linux (primary), macOS and Windows where ctypes works
