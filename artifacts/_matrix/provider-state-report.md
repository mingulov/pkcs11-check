# Current PKCS#11 Provider State Under pkcs11-check

Draft report from the 2026-05-24/25 Docker provider matrix. Raw console output
is in `artifacts/_matrix/console.log`; detailed working notes are in
`artifacts/_matrix/analysis-notes.md`; a compact artifact-derived summary is in
`artifacts/_matrix/provider-summary.json`; per-provider artifacts are under
`artifacts/<provider>/`.

This is release/article evidence, not a marketing summary. Some providers have
valid full statistics, some have partial or build-only evidence, and several
findings are explicitly classified as pkcs11-check test-selection fixes or
provider/Docker configuration fixes rather than provider bugs.

## Scope And Version Policy

The target state is:

- Use latest available external test data packages and record their commits.
- Use latest released provider tags where possible.
- Also test latest main/master branch heads where a Docker target exists.
- Prefer OpenSSL `openssl-4.0.0`; use `openssl-3.6.2` only where OpenSSL 4.0.0
  is not build-compatible.
- Treat crashes, security boundary failures, and unexpected CKR values as
  findings. Do not skip or suppress provider failures unless evidence shows a
  missing capability, an invalid pkcs11-check probe, or a bad provider build
  configuration.

Data sources recorded in
`src/pkcs11_check/testcases/data/sources.toml`:

- Wycheproof: `878e5366008753df2064d40c49f8e2f50f9c6af7`,
  `2026-05-12T17:59:25Z`.
- CCTV: `67c1397af2a57f935cc96ee112b446c051cdb68a`,
  `2026-04-27T01:58:58Z`.
- ACVP-Server: `15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0`,
  `2026-04-16T20:41:44Z`.
- x509-limbo: `feb7caccc1afaa9d7e63ee8d7f81e6ce8b199510`,
  `2026-05-22T00:33:27Z`.

Provider source manifest: `docker/provider-sources.toml`, observed
`2026-05-24T17:52:49Z`, with later build-evidence updates for TPM2 and
qryptotoken on `2026-05-25`.

## Top-Level Findings

- SoftHSM2, Kryoptic, NSS, OpenCryptoki, TPM2, pkcs11-mock, and qryptotoken are
  all reachable enough to classify their state, but not all have complete
  latest-source statistics yet.
- The most important pkcs11-check improvements found during analysis are
  validation-order tolerant CKR expectations, optional-function gating,
  generated-IV authenticated-wrap capability handling, AES-CTS flag gating, and
  better build-unavailable handling for qryptotoken.
- SoftHSM2 release needs OpenSSL 3.6.2 for build compatibility; SoftHSM2 main
  builds against OpenSSL 4.0.0. DES/DES3 direct operations require OpenSSL
  legacy provider configuration in the Docker image.
- Kryoptic release/main build against official OpenSSL 4.0.0. Kryoptic FIPS/PQC
  is a custom-reference-OpenSSL target: official OpenSSL 4.0.0 builds and
  Kryoptic compiles, but the FIPS HMAC embedding step fails because the final
  shared object lacks `.rodata1`; the custom branch image contains `.rodata1`.
- OpenCryptoki release and master currently resolve to the same commit. A few
  OpenCryptoki failures were pkcs11-check validity issues and have been fixed;
  the remaining large clusters still look provider-side.
- TPM2 now has a completed latest-upstream source-built full run for
  `tpm2-pkcs11 1.10.0`. The earlier Fedora package result is retained as an
  archived comparison, not the headline result.
- qryptotoken `v0.4.1` does not currently build a PKCS#11 module on the tested
  Fedora/Rust/bindgen stack. The Docker runner now records `build.log` and
  returns nonzero for build-unavailable.
- BouncyHSM was configured and reachable, but the full provider run was
  intentionally stopped after AES ACVP tests entered a pathological timeout
  tail. Segmented ACVP reruns, bounded core/ECDH/partial-ECDSA Wycheproof
  runs, a bounded security run, and a bounded general run now provide useful
  partial evidence; the row below is not a full-suite provider statistic.

## Result Snapshot

| Target | Source | Status | Total | Passed | Failed | Skipped | Error | Crash/Timeout |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| softhsm2 | SoftHSM2 2.7.0, OpenSSL 3.6.2 | full | 82,147 | 60,181 | 2,609 | 19,316 | 0 | 0/0 |
| softhsm2-generated-iv | SoftHSM2 2.7.0 + local generated-IV patch | full | 82,147 | 60,185 | 2,607 | 19,314 | 0 | 0/0 |
| softhsm2-main | SoftHSM2 main, OpenSSL 4.0.0 | full | 82,926 | 61,538 | 2,702 | 18,645 | 0 | 0/0 |
| kryoptic | Kryoptic v1.5.0, OpenSSL 4.0.0 | full | 103,789 | 67,487 | 2,853 | 33,378 | 0 | 0/0 |
| kryoptic-main | Kryoptic main, OpenSSL 4.0.0 | full | 103,789 | 67,503 | 2,839 | 33,376 | 0 | 0/0 |
| kryoptic-fips | Kryoptic FIPS/PQC + custom OpenSSL branch | full diagnostic | 87,712 | 53,404 | 4,733 | 29,490 | 0 | 12/0 |
| nss | Fedora NSS softoken packages | full | 85,515 | 48,928 | 2,111 | 34,372 | 0 | 3/0 |
| nss-pqc | NSS/NSPR source tips | full | 84,819 | 47,548 | 2,019 | 35,147 | 0 | 4/0 |
| nss-main | NSS/NSPR source tips | full | 84,819 | 47,549 | 2,018 | 35,147 | 0 | 4/0 |
| opencryptoki | OpenCryptoki v3.27.0, OpenSSL 4.0.0 | full | 89,899 | 78,656 | 2,593 | 8,593 | 0 | 0/0 |
| opencryptoki-master | OpenCryptoki master, OpenSSL 4.0.0 | full | 89,899 | 78,657 | 2,589 | 8,595 | 0 | 0/0 |
| bouncyhsm | BouncyHSM v2.1.0 | partial + segmented ACVP + Wycheproof core/ECDH/partial ECDSA + security + general | 84,752 focused | 51,707 focused | 22,303 focused | 10,651 focused | 0 | 4/0, plus timeout failures |
| tpm2 source | upstream tpm2-pkcs11 1.10.0 | full | 81,400 | 9,847 | 6,825 | 64,696 | 0 | report has subprocess crashes |
| tpm2 package | Fedora tpm2-pkcs11 1.9.1 package | archived full | 64,084 | 8,433 | 5,067 | 49,727 | 851 | report has subprocess crashes |
| pkcs11-mock | pkcs11-mock v2.0.0 | full mock baseline | 32,633 | 2,560 | 3,546 | 26,517 | 0 | 0/0 |
| qryptotoken | qryptotoken v0.4.1 | build failed | n/a | n/a | n/a | n/a | n/a | n/a |

`kryoptic-fips` uses a custom OpenSSL branch in the full diagnostic artifact.
The older TPM2 Fedora-package artifact is archived separately from the
source-built upstream result. `bouncyhsm` is segmented ACVP plus core/ECDH/
partial-ECDSA Wycheproof, security, and general evidence, not a full-suite
statistic.

## SoftHSM2

SoftHSM2 release `2.7.0` was built with OpenSSL `3.6.2` because OpenSSL
`4.0.0` rejects the release source at build time. SoftHSM2 main
`679f33d1b325cca8f5eb1a8febcc7630654a34de` builds with OpenSSL `4.0.0`.

Release 2.7.0 results are stable enough for article statistics: 82,147 total,
60,181 passed, 2,609 failed, 19,316 skipped, 41 xfailed. The largest clusters
are ACVP ECDH, Wycheproof RSA-OAEP, Wycheproof RSA-PSS, Wycheproof ECDH, and
Wycheproof HMAC. CKR classification is dominated by `CKR_GENERAL_ERROR` and
`CKR_ARGUMENTS_BAD`.

Security/crash findings include signal 11 in extreme template-count probes,
signal 11 in `C_EncryptInit(AES_GCM, pIv=NULL, ulIvLen=12)`, Tookan-sensitive
unwrap boundary failures, AES-unwrapped-as-DES3 key-type confusion, and an
AES-CBC-PAD padding oracle.

The generated-IV patch removes the SoftHSM2 GCM null-IV crash and one explicit
security failure, but does not change the broad failure shape. SoftHSM2 main
adds ML-DSA coverage and still has the same crash/security classes.

DES/DES3 required separate configuration analysis: direct DES/DES3 operations
passed once OpenSSL default and legacy providers were enabled in the runtime
configuration. Wrap/derive DES/3DES still fail despite advertised mechanisms,
so those remain provider-behavior or mechanism-flag findings rather than a
plain Docker misconfiguration.

## Kryoptic

Kryoptic release `v1.5.0` and main both build against official OpenSSL
`4.0.0`. Release `v1.5.0` produced 103,789 total, 67,487 passed, 2,853 failed,
33,378 skipped, and 71 xfailed. Main produced 103,789 total, 67,503 passed,
2,839 failed, 33,376 skipped, and 71 xfailed.

The largest release/main clusters are ACVP ECDH, ECDSA, AES CTS, ML-DSA, AES,
generic sign mechanism tests, SLH-DSA, and EdDSA. Most release failures
classified as `CKR_DEVICE_ERROR`, followed by `CKR_MECHANISM_PARAM_INVALID`.

Important provider findings include NULL-template and NULL-parameter crashes,
Rust aborts on capacity overflow, bus errors on boundary lengths, Tookan
unwrap boundary failures, USER ability to set `CKA_TRUSTED`, and AES-CBC-PAD
oracle behavior. Main improves a small number of HKDF/raw/trusted cases but
does not change the main failure picture.

Several apparent release failures were pkcs11-check validation-order issues:
raw NULL-mechanism probes used zero handles and needed to accept
handle-validation CKRs, and trusted-wrap rejection needed to accept
`CKR_WRAPPING_KEY_HANDLE_INVALID`. Those checks were fixed in the test suite.

The FIPS/PQC artifact is a custom-reference-OpenSSL result: it uses Kryoptic
with `--features fips,pqc` and the `simo5/openssl` `kryoptic_ossl40` branch
`2d0c89dff0e3a41ad8a83bd6389fedfff8279c7b`, dated
`2026-05-04T15:24:41Z`. It produced 87,712 total, 53,404 passed, 4,733 failed,
29,490 skipped, 73 xfailed, and 12 crashes.

An official OpenSSL `openssl-4.0.0` build check was run on `2026-05-25`.
OpenSSL built and Kryoptic compiled, but `./misc/hmacify.sh` failed with
`objcopy: error: .rodata1 not found, can't be updated`. The existing
custom-branch image has `.rodata1` in `/usr/lib64/libkryoptic_pkcs11.so`.
Therefore the custom OpenSSL branch is part of the current FIPS/PQC
configuration and this target should not be described as an official OpenSSL
4.0.0 result.

## NSS Softoken

The stable NSS run used Fedora packages, slot 1. It produced 85,515 total,
48,928 passed, 2,111 failed, 34,372 skipped, 101 xfailed, and 3 crashes.

The source-tip PQC/main targets used NSS tip
`1a02ab2a26b719d5a2ba23aed6e7b06b5d3e9370` and NSPR tip
`764a204fce9a069633c2eb75890f8194f0c54853`. PQC produced 84,819 total,
47,548 passed, 2,019 failed, 35,147 skipped, 101 xfailed, and 4 crashes. Main
was nearly identical: one additional pass and one fewer failure.

Stable failures are dominated by `CKR_TEMPLATE_INCONSISTENT`,
`CKR_ARGUMENTS_BAD`, `CKR_MECHANISM_PARAM_INVALID`, and `CKR_DATA_LEN_RANGE`.
The main functional clusters are ECDH, DSA, AES-KWP, HMAC, raw NULL-pointer
probes, and security boundary tests.

The source-tip targets remove stable ACVP ML-DSA failures, but still show ML-KEM
failures. Security/crash findings include non-extractable wrapping behavior,
NULL mechanism/template/data pointer signal 11 cases, Tookan boundary failures,
RSA-OAEP and AES-CBC-PAD oracle behavior, and non-copyable/trusted/
non-destroyable attribute enforcement failures. One USER `CKA_TRUSTED` case was
classified as a pkcs11-check accepted-CKR issue and has been fixed.

## OpenCryptoki

OpenCryptoki release `v3.27.0` and master both resolve to
`583d0128bb5ebfac263496bc8fe32d4aef440178`, dated
`2026-05-13T11:19:05Z`. Both targets build with OpenSSL `4.0.0` and use
SWToken slot 0.

The release artifact produced 89,899 total, 78,656 passed, 2,593 failed,
8,593 skipped, and 57 xfailed. Master produced 89,899 total, 78,657 passed,
2,589 failed, 8,595 skipped, and 58 xfailed.

Largest clusters are ACVP ECDH, RSA-PSS, AES-XTS, ML-DSA, AES, multipart
tests, KEM, and sign tests. CKR classification is dominated by
`CKR_FUNCTION_FAILED` and `CKR_MECHANISM_PARAM_INVALID`.

Security/crash findings include signal 7 bus errors in `C_FindObjectsInit` with
extreme template counts and `C_Sign`/`C_Digest` boundary probes, private RSA
exponent readability, Tookan extractability preservation, RSA-OAEP oracle
behavior, and AES-CBC-PAD padding oracle behavior.

pkcs11-check fixes from this provider include AES-CTS flag gating, optional
v3 function gating, generated-IV authenticated-wrap capability handling, KEM
validation-order tolerance, and v3.2 raw decapsulation validation-order
tolerance.

## BouncyHSM

BouncyHSM release and main resolve to `v2.1.0`,
`3bfedeec38d10f69cf43a98a864ea4d519266d94`. The Docker build applied only the
local GetAttributeValue patch; the upstream partial-read/write fix is already
present in v2.1.0.

The provider configured and initialized, so this is not a module-load failure.
The full run was intentionally stopped because ACVP AES reached a pathological
timeout tail. Segmented reruns then completed the worst affected AES files,
the remaining ACVP AES targets, all non-AES ACVP targets, core/ECDH/partial
ECDSA Wycheproof segments, the security family, and the
non-vector/non-security general family under bounded targets:

- ACVP AES-CCM: 8,398 total, 1,028 passed, 7,370 failed.
- ACVP AES-CFB1: 2,138 total, 2,088 passed, 50 failed.
- ACVP AES-CFB128: 2,144 total, 2,138 passed, 6 failed via pytest-timeout in
  multiblock `C_Encrypt`/`C_Decrypt` calls.
- ACVP AES remaining segment: 11,718 total, 4,357 passed, 10 failed, 7,320
  skipped, 30 xfailed, 1 crashed.
  - CFB8: 2,138 passed, 4 failed via pytest-timeout, 1 confirmed segfault in
    `C_Encrypt`, and one decrypt multiblock case passed in isolation after the
    crash triage pass.
  - CTS detector: 1 passed.
  - GCM: 80 passed, 120 skipped, 30 xfailed.
  - OFB: 2,138 passed and 6 multiblock timeout failures.
  - AES wrap/KWP: 7,200 skipped because the module does not support
    `AES_KEY_WRAP` or `AES_KEY_WRAP_KWP`.
  - XTS: file-skipped because the module does not support `AES_XTS`; the file
    skip is recorded in console output but not counted in the summary totals.
- ACVP non-AES segment: 5,309 total, 3,042 passed, 1,931 failed, 306 skipped,
  30 xfailed, no crashes or timeouts.
  - ECDH: 1,736 failed; 1,403 returned `CKR_GENERAL_ERROR` and 333 returned
    `CKR_MECHANISM_PARAM_INVALID`.
  - ECDSA: 70 passed, 30 xfailed.
  - EdDSA: 10 passed, 10 skipped, 9 failed; failures split into 5 signature
    mismatches and 4 valid-key import rejections with `CKR_ATTRIBUTE_VALUE_INVALID`.
  - Hash/SHA3: 237 passed, 1 skipped, 3 failed with `CKR_ARGUMENTS_BAD`.
  - HMAC: 1,183 passed, 295 skipped.
  - ML-DSA: 289 passed, 171 failed; most failures are generated signatures
    that fail verification, plus valid-signature rejection cases.
  - ML-KEM: 180 passed.
  - RSA: 932 passed, 6 failed; failures are valid RSA-PSS/SHA3-256 signature
    rejections.
  - RSA key generation: 63 passed.
  - SLH-DSA: 78 passed, 6 failed; failures are valid signature rejections.
- Core Wycheproof segment, excluding the known large ECDH/ECDSA tails: 20,472
  total, 19,196 passed, 748 failed, 528 skipped, no crashes or timeouts. ECDH
  is covered by the standalone segment below.
  - Clean or skipped/pass-only areas: ChaCha, DSA file skip, Ed25519 skips,
    HKDF, ML-KEM, PBES2/PBKDF2 file skips, RSA decrypt, and X25519.
  - Main failure buckets: AES 414, HMAC 180, RSA-OAEP 54, plain RSA signature
    verification 30, ML-DSA signing 27, RSA-PSS 17, RSA PKCS#1 signature
    generation 10, ML-DSA verification 9, and generic HMAC/RSA 7.
- Wycheproof ECDH standalone segment: 13,128 total, 1,183 passed, 11,945
  failed, no skips/crashes/timeouts. The failure traces are dominated by
  `CKR_MECHANISM_PARAM_INVALID`, matching the ACVP ECDH shape.
- Wycheproof ECDSA split segments completed so far:
  - Brainpool: 6,398 total, 6,398 passed, no skips/failures/crashes/timeouts.
  - secp160/secp192: 3,390 total, 3,390 passed, no skips/failures/crashes/
    timeouts.
  - secp224: 5,810 total, 5,810 passed, no skips/failures/crashes/timeouts.
  - Remaining ECDSA shards are secp256 (7,569 vectors) and secp384/secp521
    (5,748 vectors).
- Security segment: 267 total, 169 passed, 35 failed, 57 skipped, 3 xfailed,
  3 crashed, no timeouts.
  - Failed buckets: arithmetic overflow 16, padding oracle 7, FFI length
    boundary 5, API security 4, CVE regression 2, API boundary 1.
  - Crash buckets: repeated `C_GenerateKeyPair` segfaults for weak RSA public
    exponent validation, signal 7 length/arithmetic boundary crashes, signal
    11 template-count crashes, and one `C_VerifyInit(mechanism=NULL)` crash.
  - Clean or mostly clean slices: KWP error-path skipped as unsupported, RSA
    error-path passed, FFI NULL pointer passed, handle reuse passed, nonce
    quality passed, and Tookan finished with 3 passed, 2 skipped, 1 xfailed.
- General segment, excluding vector/security/stress/fuzz/slow/CCTV markers:
  5,580 total, 2,908 passed, 208 failed, 2,440 skipped, 24 xfailed, no crashes
  or timeouts.
  - Largest failed-file buckets: mechanism sign 33, mechanism digest 31,
    mechanism attribute 16, mechanism multipart 12, hash ML-DSA 11, mechanism
    wrap 11, mechanism keygen 8, session state machine 8, access levels 7,
    mechanism encrypt 6.
  - Clean or mostly clean slices include mechanism flags/probe/KEM/lifecycle,
    init/interface/interop, object lifecycle/search/size, RSA extended/import/
    wrapping/OAEP, X.509 import/search/identity/lifecycle, token flags, surface
    audit, and several unsupported protocol families that skipped cleanly.

Failure classification in the focused units:

- CCM: 3,161 `CKR_ENCRYPTED_DATA_INVALID`, 2,518 `CKR_GENERAL_ERROR`,
  1,268 plaintext mismatches, and 423 invalid-tag accepts.
- CFB1: 26 plaintext mismatches and 24 ciphertext mismatches, concentrated in
  short bit-length payloads.
- CFB8: one confirmed segfault in `C_Encrypt` and four pytest-timeout failures
  in multiblock calls; one decrypt multiblock vector passed in isolation after
  crash triage.
- CFB128: all 2,138 non-multiblock vectors passed; all 6 multiblock vectors
  timed out inside provider calls.
- OFB: all ordinary vectors passed; all 6 multiblock vectors timed out inside
  provider calls.
- GCM: ordinary coverage mostly passed; unsupported or known-disabled lanes
  were skipped/xfailed.
- Wrap/KWP and XTS: unsupported by the module in this configuration.
- Non-AES ACVP: ML-KEM, RSA keygen, HMAC, and ECDSA are clean or mostly clean;
  ECDH is a broad failure cluster, and ML-DSA/EdDSA/RSA-PSS/SHA3/SLH-DSA have
  narrower signature or parameter-validation failures.
- Core Wycheproof: X25519, HKDF, ChaCha, ML-KEM, and RSA decrypt are clean in
  this bounded segment; AES, HMAC, RSA-OAEP/PSS/signature, and ML-DSA signing
  or verification remain the important failure clusters.
- Wycheproof ECDH: broad standalone failure cluster, with 11,945 failures out
  of 13,128 vectors and no crash/timeout. This reinforces that BouncyHSM's ECDH
  problem is not an ACVP-only artifact.
- Wycheproof ECDSA: the first three split shards passed cleanly,
  15,598/15,598, covering brainpool, secp160/secp192, and secp224 vectors.
  This should be reported by curve-family shard rather than inferred from the
  earlier stopped monolithic Wycheproof run.
- Security: key material and attribute boundaries fail in several places
  (`CKA_PRIVATE_EXPONENT` readable, `CKA_EXTRACTABLE` escalation,
  `CKA_SENSITIVE` downgrade, copy-based sensitive downgrade), and RSA/AES
  padding or timing oracle findings remain. Several boundary probes crash
  instead of returning a CKR, which is a provider finding rather than a skipped
  capability.
- General: the largest clusters are advertised mechanism behaviors rather than
  load/config failures. BLAKE2 keygen/HMAC and digest behavior, AES/Salsa/
  ChaCha encryption KATs, ML-DSA hash/multipart signing, EXTRACT_KEY_FROM_KEY,
  session login/logout visibility, read-only session semantics, and
  `CKA_PUBLIC_KEY_INFO` certificate import need follow-up if BouncyHSM should
  claim full v3.x coverage.

Current classification: reachable provider with broad AES-CCM incompatibility,
mostly working CFB1 with short bit-length mismatches, and apparent CFB8,
CFB128, and OFB multiblock crash/timeout tail behavior. Beyond AES, BouncyHSM
has strong ML-KEM, HMAC, RSA keygen, ACVP ECDSA, split Wycheproof ECDSA so
far, X25519, HKDF, ChaCha, and RSA decrypt results, plus solid
init/interface/interop/object/RSA/X.509 import general coverage. Broad ECDH,
ML-DSA, HMAC/BLAKE2, AES, RSA-OAEP/PSS/signature, session-state, and
security-boundary clusters remain. Official full-suite statistics still need
the remaining Wycheproof ECDSA shards plus intentionally excluded
CCTV/stress/fuzz/slow families if they are in scope for the final number.

## TPM2

The Docker target now source-builds upstream `tpm2-pkcs11 1.10.0` at
`a95465ce672c5fda92a2d34bc5cbeda4b0511c80`. The source build needed PyPI
`python-pkcs11 0.9.4` for the configure-time `pkcs11` module and completed the
full matrix into `artifacts/tpm2-source`.

The source-built run produced 81,400 total, 9,847 passed, 6,825 failed, 64,696
skipped, and 32 xfailed, with no harness errors. The largest clusters were ACVP
AES-CFB128 (2,144), ACVP ECDH (1,734), generic Wycheproof (856), Wycheproof
RSA-PSS (813), ACVP HMAC (444), and Wycheproof HMAC (198).

The dominant source-built failure causes were `CKR_GENERAL_ERROR` (3,188),
`CKR_ATTRIBUTE_VALUE_INVALID` (2,414), `CKR_MECHANISM_PARAM_INVALID` (813), and
`CKR_FUNCTION_NOT_SUPPORTED` (329). AES/HMAC failures repeatedly reported
missing `CKA_ALLOWED_MECHANISMS`. EC object creation is limited, RSA-PSS rejects
many valid parameter sets, and three raw digest/boundary subprocess probes hit
signal 11. Fork-after-initialize timed out. X.509 import/stress and selected
Wycheproof lanes are good counterexamples: X.509 limbo import passed 645,
X.509 stress passed 1,009, ECDH Wycheproof passed 1,040, plain RSA Wycheproof
passed 3,224, and X25519 Wycheproof passed 108.

The earlier Fedora package full run is archived as
`artifacts/tpm2-fedora-package-20260525`. It used
`tpm2-pkcs11-1.9.1-7.fc44`, produced 64,084 total, 8,433 passed, 5,067 failed,
49,727 skipped, 851 setup errors, and 6 xfailed, and should be treated as
package comparison evidence rather than the current upstream headline.

## pkcs11-mock

pkcs11-mock `v2.0.0` and master resolve to
`ac5f15adb92e15926825fa93e78a1995db1a32f8`, dated
`2025-01-29T06:48:36Z`.

The mock baseline produced 32,633 total, 2,560 passed, 3,546 failed, 26,517
skipped, and 10 xfailed, with no errors or crashes. Largest failure buckets are
X.509 limbo stress, Wycheproof generic, Wycheproof RSA-OAEP, X.509 limbo
import, ACVP RSA, and Wycheproof RSA decrypt.

This target should be treated as a diagnostic/mock baseline, not a provider
conformance result. Many failures come from dummy `Hello world!` attribute
values, constant/duplicate random output, unsupported real mechanisms, and
session-count limits.

## qryptotoken

qryptotoken `v0.4.1` and main resolve to
`24fae88227d6d04331fb599327db83c24d5ae955`, dated
`2026-01-28T13:02:59Z`.

The provider does not currently produce a module in this Docker environment.
Rust stable `1.95.0` and bindgen `0.72.0` generate PKCS#11 structs such as
`CK_ATTRIBUTE` and `CK_FUNCTION_LIST_3_0` as opaque one-byte placeholders. The
build then fails with size-layout assertions and missing fields such as
`type_`, `pValue`, and `ulValueLen`.

The runner now records `artifacts/qryptotoken/build.log` and
`build-status.json`, and exits nonzero for build-unavailable. Do not include
qryptotoken in conformance statistics until the upstream binding generation
issue is fixed or the Docker image pins a compatible build stack with evidence.

## pkcs11-check Fixes Captured During The Run

- Accept handle-validation CKRs in raw NULL-mechanism probes where the probe
  also supplies zero object handles.
- Accept trusted-wrap rejection CKRs that are specific and defensible.
- Accept USER `C_SetAttributeValue(CKA_TRUSTED=True)` rejection variants seen
  in NSS.
- Gate AES-CTS vector tests on advertised encrypt/decrypt flags, not just
  mechanism presence.
- Gate optional PKCS#11 v3 functions that return `CKR_FUNCTION_NOT_SUPPORTED`.
- Treat generated-IV authenticated-wrap configuration rejection as missing
  capability only for specific CKRs, while still failing crashes and
  `CKR_FUNCTION_FAILED`/`CKR_DEVICE_ERROR`.
- Accept template-validation order for KEM garbage-ciphertext and raw v3.2
  decapsulation probes where the deliberately invalid probe supplies multiple
  invalid inputs.
- Make qryptotoken build-unavailable an explicit nonzero matrix result with
  preserved build logs.
- Build TPM2 from latest upstream source rather than silently using the older
  Fedora package. This is now implemented and backed by `artifacts/tpm2-source`.

Focused reruns after those fixes are stored under `artifacts/_focused/`:

- SoftHSM DES/DES3 direct CBC-PAD round trips: 2 passed.
- Kryoptic raw argument and trusted-wrap fixes: 8 passed, 1 skipped.
- OpenCryptoki authenticated-wrap/KEM/v3.2 raw fixes: 14 passed, 7 skipped.
- BouncyHSM segmented reruns: ACVP CCM 1,028 passed/7,370 failed; CFB1 2,088
  passed/50 failed; CFB128 2,138 passed/6 timed out in multiblock calls; the
  remaining AES segment added 4,357 passed, 10 failed, 7,320 skipped, 30
  xfailed, and 1 confirmed CFB8 segfault; non-AES ACVP added 3,042 passed,
  1,931 failed, 306 skipped, and 30 xfailed with no crashes or timeouts; core
  Wycheproof added 19,196 passed, 748 failed, and 528 skipped with no crashes
  or timeouts; Wycheproof ECDH added 1,183 passed and 11,945 failed with no
  crashes or timeouts; Wycheproof ECDSA brainpool added 6,398 passed,
  secp160/secp192 added 3,390 passed, and secp224 added 5,810 passed, all with
  no crashes or timeouts; security added 169 passed, 35 failed, 57 skipped, 3
  xfailed, and 3 crashes with no timeouts; general added 2,908 passed, 208
  failed, 2,440 skipped, and 24 xfailed with no crashes or timeouts.

## Remaining Work Before Final Article

- Run the remaining BouncyHSM Wycheproof ECDSA shards (`secp256` and
  `secp384 or secp521`) and any intentionally excluded CCTV/stress/fuzz/slow
  families that should count in the final full-suite statistic. A broad
  Wycheproof run was stopped after completed generic/AES/ChaCha/DSA/ECDH state
  and an ECDSA file-level timeout retry; it has no final `results.json` and is
  planning evidence only.
