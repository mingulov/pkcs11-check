# Docker Provider Validation Snapshot

This document records the Docker provider matrix evidence for the next release
article/report. It is evidence from the current artifact set, not a live
dashboard.

For the size of the test suite itself, see [test-universe.md](test-universe.md).
For focused crash, timeout, and broad failure classification, see
[provider-crash-failure-findings.md](provider-crash-failure-findings.md).

> **Current status (2026-06-11): latest full Docker pool in `artifacts/` is complete and in good shape.**
> All 21 pooled Docker targets have `results.json`, `quality.json`, and `report.jsonl`; all
> latest target timeout counts are zero. The statistics below are generated from the latest
> full `docker/test_pool.py --all` artifact set. The validation pass compared this pool with
> the older local artifact snapshots before backup rotation; `artifacts2/` now mirrors the
> current `artifacts/` backup and is not an independent comparison baseline. Known provider
> findings remain visible as failures/crashes; they are not filtered from the headline matrix.
> Current baseline artifact: `docs/matrix/baseline-2026-06-11.json`.

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
| Report generated | 2026-06-11 (Matrix Results refreshed from the latest full pool in `artifacts/`) |
| Source manifest | `docker/provider-sources.toml` |
| Source manifest observed at | `2026-06-06T07:33:21Z` |
| Current release pin refresh | 2026-06-06: Kryoptic `v1.5.1` and BouncyHSM `v2.1.1` pins updated; wolfPKCS11 `v2.0.0-stable` / `master` Docker targets added with wolfSSL `v5.9.1-stable` / `master`; corePKCS11 `v3.6.4` Docker target added. The latest `artifacts/` pool now contains full pooled results for all 21 Docker targets. |
| Provider summary artifact | `docs/matrix/baseline-2026-06-11.json` (supersedes `baseline-2026-06-04.json`) |
| Provider summary generated at | `2026-06-11` (combined from per-provider `artifacts/<target>-pooled/results.json` and `quality.json`) |
| Cascade-fix status | POST-fix — `CKR_OPERATION_ACTIVE` recovery active for all providers |
| Artifact source | latest full `docker/test_pool.py --all` output in `artifacts/<target>-pooled/`; validated against older local snapshots before backup rotation |
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
| Kryoptic | `v1.5.1` | `b0d6ee212495244b25d5ac196c6204d22153a31c` | 2026-06-04T18:04:30Z | release pin updated; full pooled result included in the 2026-06-11 matrix |
| Kryoptic | `main` | `b59babefe229bddeb3a14f8c0d13031bb5060a5f` | 2026-06-04T18:14:15Z | branch tip refreshed; full pooled result included in the 2026-06-11 matrix |
| wolfPKCS11 | `v2.0.0-stable` | `6b76537e4cc5bea0358b7059fda26d1872584be4` | 2025-08-26T17:00:48Z | release target; 2026-06-11 full pooled result in `artifacts/wolfpkcs11-pooled/results.json` |
| wolfPKCS11 | `master` | `3be61e1d9a6487460dfff5df82d0301e2be2fa30` | 2026-05-20T21:50:11Z | master target with PKCS#11 v3.2 ML-DSA/ML-KEM enabled; 2026-06-11 full pooled result in `artifacts/wolfpkcs11-master-pooled/results.json` |
| corePKCS11 | `v3.6.4` | `ccc78afee1716436cca832dd3d9388ead2ba05b0` | 2026-02-24T05:23:57Z | target added; full pooled result included in the 2026-06-11 matrix |
| OpenCryptoki | `v3.27.0` | `583d0128bb5ebfac263496bc8fe32d4aef440178` | 2026-05-13T11:19:05Z | release |
| OpenCryptoki | `master` | `583d0128bb5ebfac263496bc8fe32d4aef440178` | 2026-05-13T11:19:05Z | same as release |
| NSS | `NSS_3_124_RTM` | `089afe88dd219cf4b1516fd04f3b1c1fda3b7b61` | 2026-05-15T14:57:13Z | official RTM tag |
| NSPR | `NSPR_4_39_RTM` | `54e7c1b0803d151e142e30dc0d05f12e1ec67a13` | 2026-05-05T12:48:55Z | official RTM tag |
| NSS | `tip` | `1a02ab2a26b719d5a2ba23aed6e7b06b5d3e9370` | 2026-05-19T16:33:46Z | Mercurial tip for `nss-main` comparison |
| NSPR | `tip` | `764a204fce9a069633c2eb75890f8194f0c54853` | 2026-05-05T12:49:29Z | Mercurial tip for `nss-main` comparison |
| BouncyHSM | `v2.1.1` | `3bfd53943fdc298bee8cd04ba6ac1a8663e8cc0c` | 2026-06-03T16:39:08Z | release pin updated; full pooled result included in the 2026-06-11 matrix |
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

> **Refreshed 2026-06-11 from the latest full pooled sweep** (`artifacts/<target>-pooled/`).
> The result was checked against the previous local full-pool snapshots before backup rotation.
> Those comparison roots had the same 21 provider targets; the latest `artifacts/` has
> `results.json`, `quality.json`, and `report.jsonl` for every pooled target. The current pool
> has **zero timeouts**. Failure counts mostly hold or decrease versus the previous good pool;
> the material exception is `corepkcs11`/`corepkcs11-main`, where the test universe grew by
> ~48k outcomes and exposed additional provider findings. `softhsm2` is +1 failed, while
> `bouncyhsm` and release `wolfpkcs11` record a small crash-count increase but no timeout.

| Docker target | Source | Status | Shards | Files | Total | Passed | Failed | Skipped | Xfailed | Errors | Crashed | Timeout | File-skipped units |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `softhsm2` | SoftHSM2 2.7.0, OpenSSL 3.6.2 | full | 1 | 254 | 111,284 | 44,887 | 66 | 60,290 | 6,041 | 0 | 0 | 0 | 17 |
| `softhsm2-generated-iv` | SoftHSM2 2.7.0 + generated-IV patch, OpenSSL 3.6.2 | full | 1 | 254 | 111,284 | 44,892 | 63 | 60,288 | 6,041 | 0 | 0 | 0 | 17 |
| `softhsm2-main` | SoftHSM2 main, OpenSSL 4.0.0 | full | 1 | 254 | 111,319 | 47,052 | 63 | 58,699 | 5,505 | 0 | 0 | 0 | 13 |
| `kryoptic` | Kryoptic v1.5.1, OpenSSL 4.0.0 | full | 1 | 254 | 112,594 | 58,613 | 119 | 29,615 | 24,247 | 0 | 0 | 0 | 3 |
| `kryoptic-main` | Kryoptic main, OpenSSL 4.0.0 | full | 1 | 254 | 112,594 | 58,614 | 119 | 29,615 | 24,246 | 0 | 0 | 0 | 3 |
| `kryoptic-fips` | Kryoptic FIPS/PQC + custom OpenSSL branch | full diagnostic | 1 | 254 | 105,125 | 43,939 | 155 | 37,637 | 23,382 | 0 | 12 | 0 | 8 |
| `nss` | Fedora NSS softoken package (slot 1) | full | 1 | 254 | 111,694 | 38,221 | 121 | 71,257 | 2,089 | 0 | 6 | 0 | 7 |
| `nss-pqc` | NSS/NSPR RTM tags (slot 1) | full | 1 | 254 | 111,745 | 36,752 | 109 | 72,880 | 1,997 | 0 | 7 | 0 | 11 |
| `nss-main` | NSS/NSPR source tips (slot 1) | full | 1 | 254 | 111,745 | 36,750 | 110 | 72,880 | 1,998 | 0 | 7 | 0 | 11 |
| `nss-slot0` | Fedora NSS softoken, slot 0 (Internal Crypto Services); scoped to slot-0-unique files | slot-0-scoped | 1 | 39 | 2,391 | 1,441 | 59 | 693 | 192 | 0 | 6 | 0 | 0 |
| `nss-pqc-slot0` | NSS/NSPR RTM tags, slot 0; scoped | slot-0-scoped | 1 | 39 | 2,442 | 1,471 | 59 | 710 | 195 | 0 | 7 | 0 | 0 |
| `nss-main-slot0` | NSS/NSPR source tips, slot 0; scoped | slot-0-scoped | 1 | 39 | 2,442 | 1,471 | 59 | 710 | 195 | 0 | 7 | 0 | 0 |
| `opencryptoki` | OpenCryptoki v3.27.0, OpenSSL 4.0.0 | full | 3 | 254 | 112,622 | 64,438 | 199 | 45,611 | 2,374 | 0 | 0 | 0 | 8 |
| `opencryptoki-master` | OpenCryptoki master, OpenSSL 4.0.0 | full | 3 | 254 | 112,622 | 64,437 | 199 | 45,611 | 2,375 | 0 | 0 | 0 | 8 |
| `wolfpkcs11` | wolfPKCS11 v2.0.0-stable, wolfSSL v5.9.1-stable | full | 8 | 254 | 110,792 | 46,544 | 876 | 47,438 | 15,916 | 0 | 18 | 0 | 15 |
| `wolfpkcs11-master` | wolfPKCS11 master, wolfSSL master, PKCS#11 v3.2/PQC enabled | full | 8 | 254 | 110,889 | 48,627 | 464 | 47,812 | 13,982 | 0 | 4 | 0 | 11 |
| `corepkcs11` | corePKCS11 v3.6.4 MbedTLS software mock | full | 1 | 254 | 110,142 | 11,088 | 680 | 88,553 | 9,818 | 3 | 0 | 0 | 23 |
| `corepkcs11-main` | corePKCS11 main MbedTLS software mock | full | 1 | 254 | 110,142 | 11,088 | 680 | 88,553 | 9,818 | 3 | 0 | 0 | 23 |
| `tpm2` | source-built tpm2-pkcs11 1.10.0 | full | 1 | 254 | 110,580 | 18,134 | 49 | 66,905 | 25,492 | 0 | 0 | 0 | 20 |
| `pkcs11-mock` | pkcs11-mock v2.0.0 | full mock baseline | 1 | 254 | 110,173 | 737 | 267 | 109,098 | 71 | 0 | 0 | 0 | 25 |
| `bouncyhsm` | BouncyHSM v2.1.1 | full | 16 | 254 | 113,340 | 54,186 | 2,129 | 41,160 | 15,858 | 0 | 7 | 0 | 4 |

**NSS `*-slot0` scoping (v0.1.3 and later):** NSS exposes the digest / bulk-cipher / KDF
mechanisms only on slot 0 (Internal Cryptographic Services); the default slot-1
(cert/key DB) pass skips them. The `*-slot0` targets are scoped to just the files that have
a test node which runs on slot 0 but skips on slot 1 (`docker/test_pool.py`
`SLOT0_UNIQUE_FILES`, guarded by `tests/test_slot0_scope.py`). This is **coverage-neutral**:
every slot-0-unique finding is retained; the dropped files are already covered identically by
the slot-1 pass. A missing slot-0-unique file falls back to the full suite rather than
silently dropping coverage.

File-skipped unit counts come from each target's `quality.json`. They are nonzero in the latest
pool for applicable providers because static file-skip accounting is now preserved in the
pooled artifact, whereas the previous good comparison pool recorded zero file-skipped units.
These are capability/selection skips, not missing artifact files.

Skip composition (why skipped counts are large): a large share of skips are not-applicable
rather than untested. Per provider, many skips are duplicate upstream vectors — Wycheproof
ECDH and NIST ACVP key-generation inputs whose provider-visible parameters are already covered
by another vector. Further skips come from non-selected AES-CTS CS1/CS2/CS3 variants and
unsupported mechanisms/curves (KWP, AES_KEY_WRAP, CCM, GMAC, secp224r1, secp256k1).

Archived comparison row, not the current TPM2 headline result:

| Docker target | Source | Status | Total | Passed | Failed | Skipped | Xfailed | Errors | Crashed | Timeout |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `tpm2-fedora-package-20260525` | Fedora tpm2-pkcs11 1.9.1 package | archived full | 64,084 | 8,433 | 5,067 | 49,727 | 6 | 851 | 0 | 0 |
## Run Time

Per-target test execution time, summed from each unit's `duration_s` in `results.json`
(per-file subprocess isolation). These exclude Docker image build and token setup. The pooled
runner executes targets and shards in parallel, so summed unit time is not wall-clock time.

| Target | Shards | Files | Summed unit time | Longest unit | Longest status |
| --- | ---: | ---: | ---: | --- | --- |
| `softhsm2` | 1 | 254 | 13m 3s | `test_wrap.py` (2m 33s) | passed |
| `softhsm2-generated-iv` | 1 | 254 | 13m 16s | `test_wrap.py` (2m 20s) | passed |
| `softhsm2-main` | 1 | 254 | 13m 36s | `test_wrap.py` (2m 22s) | passed |
| `kryoptic` | 1 | 254 | 39m 12s | `test_wycheproof_ecdsa.py` (9m 19s) | passed |
| `kryoptic-main` | 1 | 254 | 39m 13s | `test_wycheproof_ecdsa.py` (9m 17s) | passed |
| `kryoptic-fips` | 1 | 254 | 40m 21s | `test_wycheproof_ecdsa.py` (8m 14s) | passed |
| `nss` | 1 | 254 | 19m 50s | `test_wycheproof_hkdf.py` (5m 16s) | passed |
| `nss-pqc` | 1 | 254 | 19m 3s | `test_wycheproof_hkdf.py` (5m 25s) | passed |
| `nss-main` | 1 | 254 | 19m 17s | `test_wycheproof_hkdf.py` (5m 33s) | passed |
| `nss-slot0` | 1 | 39 | 2m 7s | `test_ffi_length_boundary.py` (1m 2s) | failed |
| `nss-pqc-slot0` | 1 | 39 | 2m 1s | `test_ffi_length_boundary.py` (58s) | failed |
| `nss-main-slot0` | 1 | 39 | 2m 7s | `test_ffi_length_boundary.py` (1m 12s) | failed |
| `opencryptoki` | 3 | 254 | 15m 37s | `test_wycheproof_ecdsa.py` (2m 11s) | passed |
| `opencryptoki-master` | 3 | 254 | 15m 26s | `test_wycheproof_ecdsa.py` (2m 16s) | passed |
| `wolfpkcs11` | 8 | 254 | 1h 26m 37s | `test_wycheproof_ecdsa.py` (8m 19s) | passed |
| `wolfpkcs11-master` | 8 | 254 | 1h 25m 52s | `test_wycheproof_ecdsa.py` (7m 51s) | failed |
| `corepkcs11` | 1 | 254 | 16m 28s | `test_wycheproof_ecdsa.py` (9m 56s) | passed |
| `corepkcs11-main` | 1 | 254 | 16m 32s | `test_wycheproof_ecdsa.py` (10m 4s) | passed |
| `tpm2` | 1 | 254 | 37m 8s | `test_wycheproof_ecdsa.py` (12m 19s) | passed |
| `pkcs11-mock` | 1 | 254 | 4m 7s | `test_parameter_validation.py` (19s) | passed |
| `bouncyhsm` | 16 | 254 | 2h 3m 3s | `test_cfb128.py` (18m 28s) | failed |

The current long poles are provider-specific findings rather than pool failures: BouncyHSM
still spends about 18 minutes each in AES CFB/OFB vector files, and wolfPKCS11 HKDF now
records a roughly 4-minute crash unit instead of a timeout-length long pole.

## BouncyHSM Segmented Evidence

> Archived: the matrix row above is now the 2026-06-11 16-shard BouncyHSM full pool
> (`artifacts/bouncyhsm-pooled/`, total 113,340, 2,129 failed, 7 crashed, 0 timeouts).
> The segmented breakdown below is retained as **2026-05-27 diagnostic detail** for
> per-group failure attribution (Wycheproof ECDH, AES-CCM), not as the current headline
> statistic.

BouncyHSM is reachable and configured. Earlier segmented evidence is preserved here
only to show where the old per-group findings came from; the current headline evidence
is the latest full pooled/sharded run above:

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
