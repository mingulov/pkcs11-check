# Docker Provider Validation Snapshot

This document records the Docker provider matrix evidence for the next release
article/report. It is evidence from the current artifact set, not a live
dashboard.

For the size of the test suite itself, see [test-universe.md](test-universe.md).
For focused crash, timeout, and broad failure classification, see
[provider-crash-failure-findings.md](provider-crash-failure-findings.md).

> **Status (2026-05-30): refreshed to the 2026-05-30 POST-FIX full sweep.** This is the
> first full matrix run with the `CKR_OPERATION_ACTIVE` recovery in place across **all**
> providers — the prior 2026-05-27/05-29 snapshots had cascade-inflated failures (matrix
> total `failed` 49,592 → 11,103; `CKR_OPERATION_ACTIVE` failures 38,808 → 39). Reference
> implementations (softhsm2, opencryptoki) are unchanged vs the prior run; the remaining
> failures are genuine provider findings. Combined baseline:
> `docs/matrix/baseline-2026-05-30.json` (supersedes `baseline-2026-05-29.json`).
>
> **Re-confirmed for the v0.1.2 release (2026-05-31, `artifacts/20260530_3/`):** SoftHSM2
> was re-run after the threading conformance test was switched to the spec-valid
> `CKF_OS_LOCKING_OK` contract and temporarily disabled (the earlier intermittent
> `test_threading.py` SIGSEGV was harness-induced undefined behavior — concurrent access
> after a single-threaded `C_Initialize(NULL)` — not a SoftHSM2 defect; see
> [module-issues.md](module-issues.md)). SoftHSM2 is crash-free in the re-run; all other
> rows are numerically equivalent to the 2026-05-30 sweep (single-digit flaky variance).
>
> **Refreshed for the v0.1.3 release (2026-06-04, `docs/matrix/baseline-2026-06-04.json`).**
> Re-run on the post-review-fix code (the runner no longer drops a crashed shard's findings,
> mis-reports a crash as a timeout, or hides an unattributed timeout; a zero-collection run now
> fails instead of passing green). **Two independent full sweeps agree — no genuine regression:**
> failures held or **decreased** on every provider (PC-6 `CKR_FUNCTION_NOT_SUPPORTED` keygen
> reclassification + gap-triage), crashes are stable, totals unchanged **except the NSS `*-slot0`
> targets**, which are now scoped to the slot-0-unique files (~90k → ~2.3k, coverage-neutral: the
> slot-1 pass already covers the dropped files). The only non-slot0 cross-run deltas are the
> probabilistic security probes (the NSS `C_FindObjectsInit(ULONG_MAX)` SIGSEGV and the softhsm2
> AES-CBC-PAD Vaudenay oracle — real, near-deterministic module findings the suite surfaces, not
> pkcs11-check regressions).

## Snapshot Metadata

| Field | Value |
| --- | --- |
| Report generated | 2026-06-10/11 (Matrix Results refreshed from the validated full pool; metadata/source rows below remain the 2026-06-04/06 pin set) |
| Source manifest | `docker/provider-sources.toml` |
| Source manifest observed at | `2026-06-06T07:33:21Z` |
| Current release pin refresh | 2026-06-06: Kryoptic `v1.5.1` and BouncyHSM `v2.1.1` pins updated; wolfPKCS11 `v2.0.0-stable` / `master` Docker targets added with wolfSSL `v5.9.1-stable` / `master`; corePKCS11 `v3.6.4` Docker target added with focused build/run smoke only; wolfPKCS11 rows are 2026-06-06 single-target full validations, while the rest of the matrix rows remain the 2026-06-04 artifact set |
| Provider summary artifact | `docs/matrix/baseline-2026-06-04.json` (supersedes `baseline-2026-05-30.json`) |
| Provider summary generated at | `2026-06-04` (combined from per-provider `artifacts/<target>-pooled/results.json`) |
| Cascade-fix status | POST-fix — `CKR_OPERATION_ACTIVE` recovery active for all providers |
| Artifact source | per-provider `artifacts/<target>-pooled/results.json` summaries (pooled/sharded run) |
| Matrix command family | `docker/test_pool.py` full pooled sweep |
| Runner mode | pooled Docker target runs with per-file/mixed subprocess isolation |

Failures, errors, crashes, and timeouts are retained as provider findings unless
a section explicitly identifies a pkcs11-check issue that was fixed after the
artifact was produced.

## Resolved Source Inputs

The release-tag refresh checked non-RC/non-test semantic release tags and the
tracked branch tips. OpenSSL policy is to use OpenSSL 4.0.0 when the provider
builds and runs against it, and OpenSSL 3.6.2 otherwise.

| Component | Selector | Commit | Date | Notes |
| --- | --- | --- | --- | --- |
| OpenSSL | `openssl-4.0.0` | `11b7b6ea3b65a584e1d31408ed1bdb139465cffd` | 2026-04-14T12:04:16Z | preferred |
| OpenSSL | `openssl-3.6.2` | `fe686e15d84334b284f883118ed92f64b409b3aa` | 2026-04-07T12:17:57Z | fallback |
| OpenSSL | `master` | `83ef5622a64d34885a7d6da866accf2281879c7d` | 2026-05-21T09:13:07Z | branch tip |
| Kryoptic FIPS OpenSSL | `simo5/openssl:kryoptic_ossl40` | `2d0c89dff0e3a41ad8a83bd6389fedfff8279c7b` | 2026-05-04T15:24:41Z | custom branch required for current FIPS target |
| wolfSSL | `v5.9.1-stable` | `1d363f3adceba9d1478230ede476a37b0dcdef24` | 2026-04-08T17:40:06Z | wolfPKCS11 release support |
| wolfSSL | `master` | `8fca95ce651d6e370d91f5598786de4bc66aa2c2` | 2026-06-05T21:27:00Z | wolfPKCS11 master support |
| SoftHSM2 | `2.7.0` | `13e6e86b83748fef74046dbf0c91f664b7acc1c3` | 2026-01-20T06:25:10Z | release |
| SoftHSM2 | `main` | `679f33d1b325cca8f5eb1a8febcc7630654a34de` | 2026-05-23T10:20:01Z | branch tip |
| Kryoptic | `v1.5.1` | `b0d6ee212495244b25d5ac196c6204d22153a31c` | 2026-06-04T18:04:30Z | release pin updated; full Docker result refresh pending |
| Kryoptic | `main` | `b59babefe229bddeb3a14f8c0d13031bb5060a5f` | 2026-06-04T18:14:15Z | branch tip refreshed; full Docker result refresh pending |
| wolfPKCS11 | `v2.0.0-stable` | `6b76537e4cc5bea0358b7059fda26d1872584be4` | 2025-08-26T17:00:48Z | release target; 2026-06-06 full Docker result in `artifacts/wolfpkcs11/results.json` |
| wolfPKCS11 | `master` | `3be61e1d9a6487460dfff5df82d0301e2be2fa30` | 2026-05-20T21:50:11Z | master target with PKCS#11 v3.2 ML-DSA/ML-KEM enabled; 2026-06-06 full Docker result in `artifacts/wolfpkcs11-master/results.json` |
| corePKCS11 | `v3.6.4` | `ccc78afee1716436cca832dd3d9388ead2ba05b0` | 2026-02-24T05:23:57Z | target added; focused Docker build/run smoke passed, full result refresh pending |
| OpenCryptoki | `v3.27.0` | `583d0128bb5ebfac263496bc8fe32d4aef440178` | 2026-05-13T11:19:05Z | release |
| OpenCryptoki | `master` | `583d0128bb5ebfac263496bc8fe32d4aef440178` | 2026-05-13T11:19:05Z | same as release |
| NSS | `NSS_3_124_RTM` | `089afe88dd219cf4b1516fd04f3b1c1fda3b7b61` | 2026-05-15T14:57:13Z | official RTM tag |
| NSPR | `NSPR_4_39_RTM` | `54e7c1b0803d151e142e30dc0d05f12e1ec67a13` | 2026-05-05T12:48:55Z | official RTM tag |
| NSS | `tip` | `1a02ab2a26b719d5a2ba23aed6e7b06b5d3e9370` | 2026-05-19T16:33:46Z | Mercurial tip for `nss-main` comparison |
| NSPR | `tip` | `764a204fce9a069633c2eb75890f8194f0c54853` | 2026-05-05T12:49:29Z | Mercurial tip for `nss-main` comparison |
| BouncyHSM | `v2.1.1` | `3bfd53943fdc298bee8cd04ba6ac1a8663e8cc0c` | 2026-06-03T16:39:08Z | release pin updated; full Docker result refresh pending |
| BouncyHSM | `main` | `331308f0b210ef331e4c5499c393271e0f76e68c` | 2026-06-06T06:47:25Z | branch tip refreshed; no separate Docker target |
| tpm2-pkcs11 | `1.10.0` | `a95465ce672c5fda92a2d34bc5cbeda4b0511c80` | 2026-05-19T20:44:58Z | release and master |
| libtpms | `v0.10.2` | `03ff2481e133540be3b3ffe3daa1483d2a73d967` | 2026-01-02T15:56:41Z | TPM support |
| swtpm | `v0.10.1` | `53841482b0a9a1dfe63a120b00283acfe588ee72` | 2025-04-30T12:32:33Z | TPM support |
| pkcs11-mock | `v2.0.0` | `ac5f15adb92e15926825fa93e78a1995db1a32f8` | 2025-01-29T06:48:36Z | release and master |

## Docker Target Configuration

| Docker target | Provider/source | OpenSSL or build policy |
| --- | --- | --- |
| `test-softhsm2` | SoftHSM2 2.7.0 | OpenSSL 3.6.2; OpenSSL 4.0.0 does not build this release |
| `test-softhsm2-generated-iv` | SoftHSM2 2.7.0 plus local generated-IV patch | OpenSSL 3.6.2 |
| `test-softhsm2-main` | SoftHSM2 main | OpenSSL 4.0.0 |
| `test-kryoptic` | Kryoptic v1.5.1 | OpenSSL 4.0.0 |
| `test-kryoptic-main` | Kryoptic main | OpenSSL 4.0.0 |
| `test-kryoptic-fips` | Kryoptic FIPS/PQC | custom `simo5/openssl:kryoptic_ossl40`; official OpenSSL 4.0.0 compiled Kryoptic but `hmacify` failed because `.rodata1` was absent |
| `test-nss` | Fedora 44 NSS softoken package `nss-3.123.1-1.fc44` | not OpenSSL-based; slot 1 |
| `test-nss-pqc` | NSS/NSPR official RTM tags | not OpenSSL-based; slot 1 |
| `test-nss-main` | NSS/NSPR source tips, comparison only | not OpenSSL-based; slot 1 |
| `test-opencryptoki` | OpenCryptoki v3.27.0 SWToken | OpenSSL 4.0.0 |
| `test-opencryptoki-master` | OpenCryptoki master SWToken | OpenSSL 4.0.0 |
| `test-wolfpkcs11` | wolfPKCS11 v2.0.0-stable with wolfSSL v5.9.1-stable | wolfSSL-backed; optional AES key wrap/CTR/CCM/ECB/CTS/CMAC and PBKDF2 enabled |
| `test-wolfpkcs11-master` | wolfPKCS11 master with wolfSSL master | wolfSSL-backed; optional AES features, PBKDF2, PKCS#11 v3.2, ML-DSA, and ML-KEM enabled |
| `test-corepkcs11` | corePKCS11 v3.6.4 MbedTLS software mock | not OpenSSL-based; custom config raises capacity, adapter exposes upstream RSA/ECDSA/SHA-256 plus SHA256-HMAC and AES-CMAC sign/verify mechanism metadata |
| `test-bouncyhsm` | BouncyHSM v2.1.1 | .NET/BouncyCastle provider; not OpenSSL-based |
| `test-tpm2` | source-built tpm2-pkcs11 1.10.0 | Fedora OpenSSL development package; TPM stack uses libtpms/swtpm |
| `test-pkcs11-mock` | pkcs11-mock v2.0.0 | mock provider; not OpenSSL-based |

## Matrix Results

> **Refreshed 2026-06-10/11 from the validated full pooled sweep** (`artifacts/<target>-pooled/`,
> backed up to `artifacts3/`). This is the post-merge run carrying the advertised-capability
> honesty package, vacuous-reject downgrade, ECDH-H9, and capability-gating retirement; it is
> **VALIDATED** against the prior pool (`artifacts2/`) — see
> [findings/pool-2026-06-10-comparison.md](findings/pool-2026-06-10-comparison.md). The dominant
> shifts are the intended fail→xfail/pass reclassifications (notably the wolfPKCS11 CTS
> operability flip and the wycheproof_ecdsa capability-gating retirement that converts large
> skip blocks into pass). `corepkcs11`/`corepkcs11-main` now have full pooled results and are
> included. NSS `*-slot0` crash counts reflect the per-pool exit-time scheduling (a known wolf
> /NSS teardown pattern), not new crash targets.

| Docker target | Source | Status | Total | Passed | Failed | Skipped | Xfailed | Errors | Crashed | Timeout |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `softhsm2` | SoftHSM2 2.7.0, OpenSSL 3.6.2 | full | 82,472 | 44,900 | 65 | 32,483 | 5,024 | 0 | 0 | 0 |
| `softhsm2-generated-iv` | SoftHSM2 2.7.0 + generated-IV patch, OpenSSL 3.6.2 | full | 82,472 | 44,903 | 64 | 32,481 | 5,024 | 0 | 0 | 0 |
| `softhsm2-main` | SoftHSM2 main, OpenSSL 4.0.0 | full | 83,401 | 47,064 | 63 | 31,786 | 4,488 | 0 | 0 | 0 |
| `kryoptic` | Kryoptic v1.5.1, OpenSSL 4.0.0 | full | 109,127 | 58,614 | 137 | 37,762 | 12,614 | 0 | 0 | 0 |
| `kryoptic-main` | Kryoptic main, OpenSSL 4.0.0 | full | 109,127 | 58,613 | 138 | 37,762 | 12,614 | 0 | 0 | 0 |
| `kryoptic-fips` | Kryoptic FIPS/PQC + custom OpenSSL branch | full diagnostic | 93,046 | 43,939 | 176 | 37,565 | 11,354 | 0 | 12 | 0 |
| `nss` | Fedora NSS softoken package (slot 1) | full | 93,498 | 38,220 | 130 | 53,323 | 1,819 | 0 | 6 | 0 |
| `nss-pqc` | NSS/NSPR RTM tags (slot 1; near-identical to `nss-main`, differs only by a flaky overflow-crash case) | full | 92,655 | 36,750 | 119 | 54,052 | 1,727 | 0 | 7 | 0 |
| `nss-main` | NSS/NSPR source tips (slot 1) | full | 92,655 | 36,752 | 117 | 54,052 | 1,727 | 0 | 7 | 0 |
| `nss-slot0` | Fedora NSS softoken, slot 0 (Internal Crypto Services); scoped to the slot-0-unique files (coverage-neutral, see note) | slot-0-scoped | 2,391 | 1,440 | 61 | 693 | 191 | 0 | 6 | 0 |
| `nss-pqc-slot0` | NSS/NSPR RTM tags, slot 0; scoped | slot-0-scoped | 2,442 | 1,470 | 61 | 710 | 194 | 0 | 7 | 0 |
| `nss-main-slot0` | NSS/NSPR source tips, slot 0; scoped | slot-0-scoped | 2,442 | 1,470 | 61 | 710 | 194 | 0 | 7 | 0 |
| `opencryptoki` | OpenCryptoki v3.27.0, OpenSSL 4.0.0 | full | 97,880 | 64,438 | 212 | 31,982 | 1,248 | 0 | 0 | 0 |
| `opencryptoki-master` | OpenCryptoki master, OpenSSL 4.0.0 | full | 97,880 | 64,439 | 211 | 31,982 | 1,248 | 0 | 0 | 0 |
| `wolfpkcs11` | wolfPKCS11 v2.0.0-stable, wolfSSL v5.9.1-stable | full | 97,546 | 46,524 | 879 | 44,798 | 5,329 | 0 | 15 | 1 |
| `wolfpkcs11-master` | wolfPKCS11 master, wolfSSL master, PKCS#11 v3.2/PQC enabled | full | 98,573 | 49,028 | 482 | 43,588 | 5,471 | 0 | 4 | 0 |
| `corepkcs11` | corePKCS11 v3.6.4 MbedTLS software mock | full | 61,833 | 10,950 | 142 | 49,679 | 1,059 | 3 | 0 | 0 |
| `corepkcs11-main` | corePKCS11 main MbedTLS software mock | full | 61,833 | 10,950 | 142 | 49,679 | 1,059 | 3 | 0 | 0 |
| `tpm2` | source-built tpm2-pkcs11 1.10.0 | full | 81,719 | 18,146 | 112 | 58,825 | 4,636 | 0 | 0 | 0 |
| `pkcs11-mock` | pkcs11-mock v2.0.0 | full mock baseline | 32,945 | 737 | 288 | 31,850 | 70 | 0 | 0 | 0 |
| `bouncyhsm` | BouncyHSM v2.1.1 | full (monolithic) | 108,640 | 54,196 | 2,132 | 36,448 | 15,858 | 0 | 6 | 0 |

**NSS `*-slot0` scoping (v0.1.3):** NSS exposes the digest / bulk-cipher / KDF
mechanisms only on slot 0 (Internal Cryptographic Services); the default slot-1
(cert/key DB) pass skips them. The `*-slot0` targets used to re-run the **whole**
suite on slot 0 — byte-identical re-runs of the slot-1 pass for every file with
no slot-0-unique node. They are now scoped to just the files that have a test
node which runs on slot 0 but skips on slot 1 (`docker/test_pool.py`
`SLOT0_UNIQUE_FILES`, guarded by `tests/test_slot0_scope.py`), so their totals
drop from ~90k to ~2.3k. This is **coverage-neutral** — every slot-0-unique
finding is retained; the dropped files are already covered identically by the
slot-1 pass. A missing slot-0-unique file falls back to the full suite rather
than silently dropping coverage.

Skip composition (why skipped counts are large): a large share of skips are
not-applicable rather than untested. Per provider, roughly **~18k skips are
duplicate upstream vectors** — Wycheproof ECDH and NIST ACVP key-generation
inputs whose provider-visible parameters are already covered by another vector
(`Duplicate PKCS#11 ECDH operation input; covered by ecdh_*.json:tcNNN`,
`Duplicate ACVP RSA/ML-KEM/ML-DSA KeyGen input`). Further skips come from
non-selected AES-CTS CS1/CS2/CS3 variants (~7k) and unsupported
mechanisms/curves (KWP, AES_KEY_WRAP, CCM, GMAC, secp224r1, secp256k1).

Archived comparison row, not the current TPM2 headline result:

| Docker target | Source | Status | Total | Passed | Failed | Skipped | Xfailed | Errors | Crashed | Timeout |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `tpm2-fedora-package-20260525` | Fedora tpm2-pkcs11 1.9.1 package | archived full | 64,084 | 8,433 | 5,067 | 49,727 | 6 | 851 | 0 | 0 |

## Run Time

Per-target test execution time, summed from each unit's `duration_s` in
`results.json` (per-file subprocess isolation). These exclude Docker image build
and token setup.

| Target | Test execution (summed unit time) |
| --- | ---: |
| `pkcs11-mock` | ~3 min |
| `nss-main`, `nss-main-slot0` | ~7-8 min |
| `softhsm2`/`-main`/`-generated-iv`, `nss-pqc`/`-slot0`, `nss-slot0` | ~8-10 min |
| `nss`, `tpm2` | ~10 min |
| `opencryptoki`, `opencryptoki-master` | ~13 min |
| `kryoptic-main`, `kryoptic-fips`, `kryoptic` | ~14-16 min |
| `wolfpkcs11` | ~85 min |
| `wolfpkcs11-master` | ~90 min |
| `bouncyhsm` | ~98 min |
| **2026-05-30 baseline targets only (summed)** | **~4.4 hours** |
| **wolfPKCS11 2026-06-06 single-target additions (summed)** | **~2.9 hours** |

These are the sum of per-unit `duration_s` (per-file subprocess isolation), **not**
wall-clock — the pooled runner (`docker/test_pool.py`) executes targets in parallel,
so the real sweep wall-clock is far shorter. The large drop vs the 2026-05-27 snapshot
(opencryptoki ~89-128 → ~13 min, bouncyhsm ~237 → ~98 min, tpm2 ~25 → ~10 min) is the
module-scoped `p11_module_session` fixture. BouncyHSM remains the slow outlier (AES
vector tail).

## BouncyHSM Segmented Evidence

> Superseded: the matrix row above is the 2026-05-30 monolithic BouncyHSM full run
> (`artifacts/bouncyhsm-pooled/`, total 104,980, 8,142 failed). The segmented
> breakdown below is retained as **2026-05-27 diagnostic detail** for the per-group
> failure attribution (Wycheproof ECDH, AES-CCM), not as the current headline statistic.

BouncyHSM is reachable and configured, but one monolithic full-suite run was
not used as the headline statistic because AES vector execution entered a
pathological timeout tail. The current evidence is the sum of completed bounded
segments:

| Segment | Total | Passed | Failed | Skipped | Xfailed | Crashed | Timeout |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| AES-CCM | 8,398 | 1,028 | 7,370 | 0 | 0 | 0 | 0 |
| AES-CFB1 | 2,138 | 2,088 | 50 | 0 | 0 | 0 | 0 |
| AES-CFB128 non-multiblock | 2,138 | 2,138 | 0 | 0 | 0 | 0 | 0 |
| AES-CFB128 multiblock | 6 | 0 | 6 | 0 | 0 | 0 | 0 |
| Remaining ACVP AES | 11,718 | 4,357 | 10 | 7,320 | 30 | 1 | 0 |
| ACVP non-AES | 5,309 | 3,042 | 1,931 | 306 | 30 | 0 | 0 |
| Core Wycheproof | 20,472 | 19,196 | 748 | 528 | 0 | 0 | 0 |
| Wycheproof ECDH | 13,128 | 1,183 | 11,945 | 0 | 0 | 0 | 0 |
| Wycheproof ECDSA brainpool | 6,398 | 6,398 | 0 | 0 | 0 | 0 | 0 |
| Wycheproof ECDSA secp160/secp192 | 3,390 | 3,390 | 0 | 0 | 0 | 0 | 0 |
| Wycheproof ECDSA secp224 | 5,810 | 5,810 | 0 | 0 | 0 | 0 | 0 |
| Wycheproof ECDSA secp256 | 7,569 | 7,569 | 0 | 0 | 0 | 0 | 0 |
| Wycheproof ECDSA secp384/secp521 | 5,748 | 5,748 | 0 | 0 | 0 | 0 | 0 |
| Security | 267 | 169 | 35 | 57 | 3 | 3 | 0 |
| General non-vector/non-security | 5,580 | 2,908 | 208 | 2,440 | 24 | 0 | 0 |
| CCTV/stress/fuzz/slow | 2,425 | 2,413 | 5 | 6 | 1 | 0 | 0 |

Important BouncyHSM article points:

- Wycheproof ECDSA passed cleanly across all split curve shards:
  28,915/28,915.
- CCTV Ed25519, CCTV ML-DSA, and X.509 limbo stress were clean in the marker
  slice.
- Broad ECDH failure appears in both ACVP and Wycheproof, so it is not an ACVP
  data artifact.
- AES-CFB8/CFB128/OFB multiblock behavior includes crash or timeout findings;
  those are provider findings, not skipped tests.
- The five fuzz failures were operation-state findings:
  `CKR_OPERATION_ACTIVE` after repeated digest/HMAC single-part operations.

## Article Notes By Provider

- SoftHSM2 2.7.0 needs OpenSSL 3.6.2 for this release build. SoftHSM2 main
  builds with OpenSSL 4.0.0. DES/DES3 direct operations required enabling both
  OpenSSL default and legacy providers.
- Kryoptic release and main build with official OpenSSL 4.0.0. Kryoptic
  FIPS/PQC currently needs the custom OpenSSL branch because official OpenSSL
  4.0.0 produced a Kryoptic shared object without `.rodata1`, causing
  `hmacify` to fail.
- NSS stable uses the Fedora 44 `nss-3.123.1-1.fc44` package; the current PQC
  source target uses official NSS and NSPR RTM tags, while `nss-main` is an
  opt-in Mercurial tip comparison target. Use `nss-pqc` for the source-built
  NSS article/release row. The published `nss-pqc` result row above is from the
  earlier source-tip artifact and must be rerun before using it as RTM-tag
  result evidence. The existing source-built artifacts remove the stable ML-DSA
  failure cluster but still show ML-KEM, ECDH, DSA, HMAC/general, NULL pointer,
  and security-boundary findings.
- OpenCryptoki release and master currently resolve to the same commit and
  both build with OpenSSL 4.0.0. Remaining large clusters look provider-side
  after pkcs11-check validation-order and optional-function fixes.
- TPM2 headline result is the source-built upstream tpm2-pkcs11 1.10.0 target.
  The old Fedora package result is retained only as archived comparison data.
- pkcs11-mock is useful as a mock/diagnostic baseline, not a provider
  conformance result.
