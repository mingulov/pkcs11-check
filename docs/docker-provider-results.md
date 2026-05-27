# Docker Provider Validation Snapshot

This document records the Docker provider matrix evidence for the next release
article/report. It is evidence from the current artifact set, not a live
dashboard.

For the size of the test suite itself, see [test-universe.md](test-universe.md).
For focused crash, timeout, and broad failure classification, see
[provider-crash-failure-findings.md](provider-crash-failure-findings.md).

## Snapshot Metadata

| Field | Value |
| --- | --- |
| Report generated | 2026-05-27 |
| Source manifest | `docker/provider-sources.toml` |
| Source manifest observed at | `2026-05-25T08:21:09Z` |
| Provider summary artifact | `artifacts/_matrix/provider-summary.json` |
| Provider summary generated at | `2026-05-27` (regenerated from the artifact set via `artifacts/_matrix/provider-summary.json`) |
| Artifact source | per-provider `artifacts/<target>/quality.json` summaries; BouncyHSM is now a single monolithic full run |
| Matrix command family | `bash docker/test-all.sh --all --rebuild` plus targeted follow-up slices |
| Runner mode | isolated Docker target runs with per-file/mixed subprocess isolation |

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
| SoftHSM2 | `2.7.0` | `13e6e86b83748fef74046dbf0c91f664b7acc1c3` | 2026-01-20T06:25:10Z | release |
| SoftHSM2 | `main` | `679f33d1b325cca8f5eb1a8febcc7630654a34de` | 2026-05-23T10:20:01Z | branch tip |
| Kryoptic | `v1.5.0` | `f3a4ead8baa7568cf99d6dcb6e260b16d69cf010` | 2026-03-03T17:55:36Z | release |
| Kryoptic | `main` | `41abd4e3b3d3e77887ad25cc8ecfdb0d3a9664e2` | 2026-05-08T20:55:41Z | branch tip |
| OpenCryptoki | `v3.27.0` | `583d0128bb5ebfac263496bc8fe32d4aef440178` | 2026-05-13T11:19:05Z | release |
| OpenCryptoki | `master` | `583d0128bb5ebfac263496bc8fe32d4aef440178` | 2026-05-13T11:19:05Z | same as release |
| NSS | `NSS_3_124_RTM` | `089afe88dd219cf4b1516fd04f3b1c1fda3b7b61` | 2026-05-15T14:57:13Z | official RTM tag |
| NSPR | `NSPR_4_39_RTM` | `54e7c1b0803d151e142e30dc0d05f12e1ec67a13` | 2026-05-05T12:48:55Z | official RTM tag |
| NSS | `tip` | `1a02ab2a26b719d5a2ba23aed6e7b06b5d3e9370` | 2026-05-19T16:33:46Z | Mercurial tip for `nss-main` comparison |
| NSPR | `tip` | `764a204fce9a069633c2eb75890f8194f0c54853` | 2026-05-05T12:49:29Z | Mercurial tip for `nss-main` comparison |
| BouncyHSM | `v2.1.0` | `3bfedeec38d10f69cf43a98a864ea4d519266d94` | 2026-05-04T15:25:36Z | release and main |
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
| `test-kryoptic` | Kryoptic v1.5.0 | OpenSSL 4.0.0 |
| `test-kryoptic-main` | Kryoptic main | OpenSSL 4.0.0 |
| `test-kryoptic-fips` | Kryoptic FIPS/PQC | custom `simo5/openssl:kryoptic_ossl40`; official OpenSSL 4.0.0 compiled Kryoptic but `hmacify` failed because `.rodata1` was absent |
| `test-nss` | Fedora 44 NSS softoken package `nss-3.123.1-1.fc44` | not OpenSSL-based; slot 1 |
| `test-nss-pqc` | NSS/NSPR official RTM tags | not OpenSSL-based; slot 1 |
| `test-nss-main` | NSS/NSPR source tips, comparison only | not OpenSSL-based; slot 1 |
| `test-opencryptoki` | OpenCryptoki v3.27.0 SWToken | OpenSSL 4.0.0 |
| `test-opencryptoki-master` | OpenCryptoki master SWToken | OpenSSL 4.0.0 |
| `test-bouncyhsm` | BouncyHSM v2.1.0 | .NET/BouncyCastle provider; not OpenSSL-based |
| `test-tpm2` | source-built tpm2-pkcs11 1.10.0 | Fedora OpenSSL development package; TPM stack uses libtpms/swtpm |
| `test-pkcs11-mock` | pkcs11-mock v2.0.0 | mock provider; not OpenSSL-based |

## Matrix Results

| Docker target | Source | Status | Total | Passed | Failed | Skipped | Xfailed | Errors | Crashed | Timeout |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `softhsm2` | SoftHSM2 2.7.0, OpenSSL 3.6.2 | full | 82,105 | 44,878 | 85 | 32,267 | 4,875 | 0 | 0 | 0 |
| `softhsm2-main` | SoftHSM2 main, OpenSSL 4.0.0 | full | 82,884 | 46,301 | 97 | 31,526 | 4,960 | 0 | 0 | 0 |
| `kryoptic` | Kryoptic v1.5.0, OpenSSL 4.0.0 | full | 108,611 | 51,645 | 115 | 44,756 | 12,095 | 0 | 0 | 0 |
| `kryoptic-main` | Kryoptic main, OpenSSL 4.0.0 | full | 108,611 | 51,660 | 106 | 44,755 | 12,090 | 0 | 0 | 0 |
| `kryoptic-fips` | Kryoptic FIPS/PQC + custom OpenSSL branch | full diagnostic | 92,534 | 37,071 | 70 | 44,558 | 10,823 | 0 | 12 | 0 |
| `nss` | Fedora NSS softoken package | full | 92,972 | 38,271 | 151 | 53,184 | 1,363 | 0 | 3 | 0 |
| `nss-pqc` | NSS/NSPR RTM tags (currently byte-identical to `nss-main` — confirm/rerun before citing separately) | full | 92,276 | 36,916 | 119 | 53,957 | 1,280 | 0 | 4 | 0 |
| `nss-main` | NSS/NSPR source tips | full | 92,276 | 36,916 | 119 | 53,957 | 1,280 | 0 | 4 | 0 |
| `opencryptoki` | OpenCryptoki v3.27.0, OpenSSL 4.0.0 | full | 97,356 | 63,262 | 270 | 32,922 | 902 | 0 | 0 | 0 |
| `opencryptoki-master` | OpenCryptoki master, OpenSSL 4.0.0 | full | 97,356 | 63,261 | 271 | 32,922 | 902 | 0 | 0 | 0 |
| `tpm2` | source-built tpm2-pkcs11 1.10.0 | full | 81,357 | 8,306 | 213 | 68,534 | 4,304 | 0 | 0 | 0 |
| `pkcs11-mock` | pkcs11-mock v2.0.0 | full mock baseline | 32,590 | 1,320 | 1,353 | 28,866 | 1,051 | 0 | 0 | 0 |
| `bouncyhsm` | BouncyHSM v2.1.0 | full (now monolithic) | 108,118 | 55,485 | 7,692 | 36,233 | 8,703 | 0 | 5 | 0 |

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

| Target | Test execution |
| --- | ---: |
| `pkcs11-mock` | ~3 min |
| `nss`, `nss-main`, `nss-pqc` | ~9-10 min |
| `softhsm2`, `softhsm2-main` | ~9-10 min |
| `kryoptic`, `kryoptic-main`, `kryoptic-fips` | ~15-18 min |
| `tpm2` | ~25 min |
| `opencryptoki-master` | ~89 min |
| `opencryptoki` | ~128 min |
| `bouncyhsm` | ~237 min |
| **All 13 targets combined** | **~9.6 hours** |

The OpenCryptoki release vs master gap (~128 vs ~89 min) is run-to-run variance
on the same suite. BouncyHSM is the slow outlier because of an AES vector
timeout tail (see the segmented evidence below).

## BouncyHSM Segmented Evidence

> Superseded for the 2026-05-27 snapshot: the matrix row above is now a single
> monolithic BouncyHSM full run (`artifacts/bouncyhsm/`, total 108,118). The
> segmented breakdown below is retained as earlier diagnostic detail and for the
> per-group findings, not as the current headline statistic.

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
