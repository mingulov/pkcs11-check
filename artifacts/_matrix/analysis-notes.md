# Docker Matrix Analysis Notes

Run started after `docker buildx prune --all --force` on 2026-05-24. The
console stream is in `artifacts/_matrix/console.log`; per-provider artifacts
are under `artifacts/<provider>/`.

## Current Scope

- Keep the full Docker matrix running to collect all provider results.
- While later providers run, analyze completed provider artifacts immediately.
- Improve `pkcs11-check` and Docker/provider setup where evidence shows a real
  harness, test-selection, or provider-configuration issue.
- Classify findings as provider behavior, likely test issue, build/config issue,
  or unresolved and needing follow-up. Provider failures remain findings unless
  the evidence shows the test or provider build/configuration is wrong.
- Preserve exact statistics and source/build evidence for an article/report
  about the current state of PKCS#11 providers under `pkcs11-check`.

## Version Coverage

The configured Docker matrix covers released tags plus branch heads where a
target exists.

- SoftHSM2 release: tag `2.7.0`, commit
  `13e6e86b83748fef74046dbf0c91f664b7acc1c3`, commit date
  `2026-01-20T06:25:10Z`.
- SoftHSM2 branch: `main`, commit
  `679f33d1b325cca8f5eb1a8febcc7630654a34de`, commit date
  `2026-05-23T10:20:01Z`.
- OpenSSL preferred: tag `openssl-4.0.0`, commit
  `11b7b6ea3b65a584e1d31408ed1bdb139465cffd`, commit date
  `2026-04-14T12:04:16Z`.
- OpenSSL fallback: tag `openssl-3.6.2`, commit
  `fe686e15d84334b284f883118ed92f64b409b3aa`, commit date
  `2026-04-07T12:17:57Z`.
- Other configured provider targets covered later in these notes: Kryoptic
  `v1.5.0` and `main`, Kryoptic FIPS, NSS stable/PQC/main, OpenCryptoki
  `v3.27.0` and `master`, BouncyHSM `v2.1.0`, tpm2-pkcs11 `1.10.0`,
  pkcs11-mock `v2.0.0`, qryptotoken `v0.4.1`.

## Collected Test Universe

Collection command:

```bash
uv run pytest --collect-only -q src/pkcs11_check/testcases
```

The command was inspected through pytest's collection API so parametrized
vector tests are counted as individual product-test items. Current raw
generated node count: 109,608. Current active baseline collection after
collection-time AES-CTS deselection with no module available: 102,109 items.
This is before runtime provider capability skips, xfails, crashes, timeouts,
or focused target selection.

The 7,499 collection-time deselected items are mutually exclusive AES-CTS
CS-variant vectors:

- 2,635: CS1 variant vectors.
- 2,386: CS2 variant vectors.
- 2,478: CS3 variant vectors.

For a provider that supports AES-CTS, pkcs11-check probes the CTS variant and
keeps one matching variant. The provider-facing maximum is therefore 104,744
items for CS1, 104,495 for CS2, or 104,587 for CS3. The raw 109,608 node count
should not be presented as a single-provider pass target because it includes
mutually exclusive CTS variants.

Grouped by suite/function:

- 28,915: Wycheproof ECDSA vectors.
- 25,599: ACVP AES vectors before CTS variant add-on.
- 23,986: Wycheproof other vectors.
- 13,128: Wycheproof ECDH vectors.
- 5,309: ACVP non-AES vectors.
- 2,266: General conformance / interop tests.
- 1,365: CCTV vectors.
- 1,046: Stress tests.
- 274: Security regression tests.
- 178: Raw CKR/API negative tests.
- 43: Fuzz tests.

Top-level collection buckets:

- 66,029: `wycheproof/`.
- 30,908: `acvp/`.
- 1,687: `x509/`.
- 1,363: root CCTV files.
- 274: `security/`.
- 178: `ckr/`.

Overlapping marker counts are useful for article framing but should not be
summed: `wycheproof` 66,029, `kat` 31,383, `acvp` 30,908, `security` 2,368,
`cctv` 1,365, `stress` 1,046, `access` 349, `subprocess` 241,
`destructive` 46, `fuzz` 14.

## SoftHSM2 2.7.0

Artifacts: `artifacts/softhsm2/`.

Build/config evidence:

- Target: `test-softhsm2`.
- Built from SoftHSM2 tag `2.7.0`.
- Uses OpenSSL `3.6.2` fallback. OpenSSL `4.0.0` was previously rejected by
  this release because SoftHSM2 2.7.0 uses OpenSSL APIs that are opaque in 4.0.0
  (`OSSLUtil.cpp` / `ASN1_PRINTABLESTRING` access).

Aggregate results from `artifacts/softhsm2/results.json`:

- Total: 82,147
- Passed: 60,181
- Failed: 2,609
- Skipped: 19,316
- Xfailed: 41
- Xpassed: 0
- Harness errors: 0
- Harness crashes: 0
- Timeouts: 0
- Units/files: 242
- Mechanisms available: 80
- Mechanisms invoked: 78

Largest failed-file buckets:

- 1,403 failures: `src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py`
- 668 failures: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_oaep.py`
- 435 failures: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py`
- 32 failures: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py`
- 24 failures: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_hmac.py`
- 9 failures: `src/pkcs11_check/testcases/test_mech_multipart.py`
- 8 failures: `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py`

Failure classification by failed test record:

- 1,423: `CKR_GENERAL_ERROR`
- 1,107: `CKR_ARGUMENTS_BAD`
- 30: `CKR_KEY_SIZE_RANGE`
- 15: `CKR_FUNCTION_FAILED`
- 11: `CKR_MECHANISM_INVALID`
- 11: other pytest assertion failures
- 9: signal 11 subprocess crashes
- 3: explicit security pytest failures

Security/crash findings that look like provider findings, not test invalidity:

- Signal 11 in template-count overflow probes:
  `C_CreateObject`, `C_GenerateKey`, and `C_GenerateKeyPair` with extreme
  `CK_ULONG` counts.
- Signal 11 in `C_EncryptInit(AES_GCM, pIv=NULL, ulIvLen=12)`.
- Tookan sensitive-key unwrap boundary breach: unwrap with
  `CKA_SENSITIVE=False` produced a non-sensitive copy of a sensitive key.
- Tookan key-type confusion: AES-wrapped blob unwrapped as `CKK_DES3`.
- AES-CBC-PAD padding oracle: distinct outcomes on corrupted ciphertext probes.

Main functionality failure clusters:

- Valid ECDH shared-secret vectors often return `CKR_GENERAL_ERROR`.
- Valid RSA-OAEP ciphertexts often return `CKR_ARGUMENTS_BAD`.
- Valid RSA-PSS signatures often return `CKR_ARGUMENTS_BAD`.
- Valid short HMAC keys return `CKR_KEY_SIZE_RANGE`.
- DES/DES3 mechanisms appear advertised enough for tests to run but operations
  return `CKR_MECHANISM_INVALID` or `CKR_FUNCTION_FAILED`.
- Four ACVP EdDSA invalid-key verification vectors were accepted.

Current assessment:

- The crash/security findings should be treated as provider findings.
- ECDH/OAEP/PSS/HMAC failures also look provider-side because the tests use
  external ACVP/Wycheproof vectors and fail with concrete CKR values.
- DES/DES3 failures need a config/advertisement check: if mechanisms are
  advertised but unusable, provider finding; if tests infer support too broadly,
  pkcs11-check selection logic may need refinement.

## SoftHSM2 2.7.0 Generated-IV Variant

Artifacts: `artifacts/softhsm2-generated-iv/`.

Build/config evidence:

- Target: `test-softhsm2-generated-iv`.
- Built from SoftHSM2 tag `2.7.0`.
- Applies local patch
  `docker/softhsm2/patches/0001-simulate-aes-gcm-generated-iv.patch`.
- Uses OpenSSL `3.6.2` fallback.

Aggregate results from `artifacts/softhsm2-generated-iv/results.json`:

- Total: 82,147
- Passed: 60,185
- Failed: 2,607
- Skipped: 19,314
- Xfailed: 41
- Xpassed: 0
- Harness errors: 0
- Harness crashes: 0
- Timeouts: 0

Largest failed-file buckets match SoftHSM2 2.7.0 except:

- The generated-IV variant has 8 signal 11 crash failed records instead of 9.
- It removes the `security/test_ffi_length_boundary.py::test_gcm_null_iv`
  signal 11 failure seen in unpatched SoftHSM2.
- It also has 2 explicit security pytest failures rather than 3.

Current assessment:

- The generated-IV patch is useful for isolating the GCM generated-IV/null-IV
  test behavior.
- It does not materially change broader SoftHSM2 findings: ECDH, RSA-OAEP,
  RSA-PSS, HMAC short-key, DES/DES3, template-count crashes, and Tookan
  findings remain.

## SoftHSM2 Main

Artifacts: `artifacts/softhsm2-main/`.

Build/config evidence:

- Target: `test-softhsm2-main`.
- Built from SoftHSM2 `main`.
- Built and ran successfully with OpenSSL `4.0.0`; console shows
  `OpenSSL 4.0.0 14 Apr 2026`.

Aggregate results from `artifacts/softhsm2-main/results.json`:

- Total: 82,926
- Passed: 61,538
- Failed: 2,702
- Skipped: 18,645
- Xfailed: 41
- Xpassed: 0
- Harness errors: 0
- Harness crashes: 0
- Timeouts: 0

Largest failed-file buckets:

- 1,403 failures: `src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py`
- 668 failures: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_oaep.py`
- 435 failures: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py`
- 93 failures: `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py`
- 32 failures: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py`
- 24 failures: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_hmac.py`
- 10 failures: `src/pkcs11_check/testcases/test_mech_multipart.py`
- 8 failures: `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py`

Failure classification by failed test record:

- 1,423: `CKR_GENERAL_ERROR`
- 1,107: `CKR_ARGUMENTS_BAD`
- 104: other pytest assertion failures
- 30: `CKR_KEY_SIZE_RANGE`
- 15: `CKR_FUNCTION_FAILED`
- 11: `CKR_MECHANISM_INVALID`
- 9: signal 11 subprocess crashes
- 3: explicit security pytest failures

Notable deltas versus SoftHSM2 2.7.0:

- SoftHSM2 main builds and runs against OpenSSL 4.0.0; release 2.7.0 needs the
  OpenSSL 3.6.2 fallback.
- ACVP ECDH shows the same heavy `CKR_GENERAL_ERROR` pattern.
- ACVP ML-DSA now runs because SoftHSM2 main advertises ML-DSA. It produced
  93 failed records in `test_acvp_mldsa.py`.
- CCTV ML-DSA passed 449 vectors.
- Template-count signal 11 crashes still reproduce.
- GCM null-IV signal 11 still reproduces.
- Tookan sensitive-key unwrap, Tookan key-type confusion, and CBC-PAD padding
  oracle findings still reproduce.
- Multipart signing now includes an ML-DSA multipart failure in addition to the
  ECDSA/EdDSA multipart failures.

Current assessment:

- SoftHSM2 main fixes the OpenSSL 4.0.0 build compatibility problem seen in
  release 2.7.0.
- The early behavioral/security failure classes are not fixed in main.
- ML-DSA needs careful classification after full artifact parse because the
  mixed ACVP failure plus CCTV pass result may indicate a specific parameter,
  randomized/deterministic signing, or test-vector selection mismatch rather
  than a blanket ML-DSA implementation failure.

## SoftHSM2 DES/OpenSSL Legacy Provider

Root-cause check:

- The original `docker-test-softhsm2` image used OpenSSL 3.6.2 with only the
  `default` provider active.
- Mounting a temporary OpenSSL config with both `default` and `legacy`
  providers activated made direct DES/DES3 CBC-PAD roundtrip tests pass.
- The same focused run still had generic DES/DES3 wrap and derive failures:
  DES/DES3 wrap returned `CKR_MECHANISM_INVALID`; DES/DES3 ECB derive returned
  `CKR_FUNCTION_FAILED`.
- The generic wrap/derive tests are selected from the provider's actual
  `C_GetMechanismInfo` flags (`CKF_WRAP`, `CKF_UNWRAP`, `CKF_DERIVE`), not
  from pkcs11-check's static DES registry expectations. The static DES registry
  intentionally does not require wrap flags for block ciphers.

Classification:

- Direct DES/DES3 encryption needed a provider-runtime configuration fix.
- DES/DES3 wrap and derive remain provider findings because SoftHSM advertises
  the relevant operation flags and then rejects or fails the operation.

Implementation note:

- `docker/softhsm2/Dockerfile.main` now writes `/opt/openssl/ssl/openssl.cnf`
  activating both default and legacy providers and exports `OPENSSL_CONF`.
- This affects all source-built SoftHSM targets that use `Dockerfile.main`;
  previous full SoftHSM statistics above are pre-fix and should be refreshed or
  labeled as pre-legacy-provider-config in the final report.

## pkcs11-check Test Validity Fixes Found During Kryoptic

Raw NULL-mechanism CKR tests:

- Kryoptic returned `CKR_OBJECT_HANDLE_INVALID` from
  `test_ckr_raw_args_bad.py::test_wrap_key_null_mechanism` and
  `test_ckr_raw_args_bad.py::test_derive_key_null_mechanism`.
- These probes intentionally pass zero object handles while checking NULL
  mechanism-pointer handling. The test already allowed `CKR_KEY_HANDLE_INVALID`
  for that validation order, but not `CKR_OBJECT_HANDLE_INVALID`.
- This is a pkcs11-check test-validity issue, not a provider failure.
- `src/pkcs11_check/testcases/ckr/test_ckr_raw_args_bad.py` now includes
  `CKR_OBJECT_HANDLE_INVALID` in the specific accepted return-code set for
  those two probes.
- The live Kryoptic full-run statistics were collected before this source
  patch reached the running container; rerun the focused tests, and either
  adjust the Kryoptic article count by two known-invalid failures or refresh
  the full Kryoptic run.

Trusted wrapping rejection:

- Kryoptic returned `CKR_WRAPPING_KEY_HANDLE_INVALID` from
  `test_access_levels.py::TestTrustedAttribute::test_wrap_with_trusted_rejects_untrusted`.
- The test's security property is that wrapping a `CKA_WRAP_WITH_TRUSTED=True`
  target with a non-`CKA_TRUSTED` wrapping key must fail. This CKR is a
  specific rejection of the wrapping-key path, not `CKR_OK`.
- `src/pkcs11_check/testcases/test_access_levels.py` now accepts
  `CKR_WRAPPING_KEY_HANDLE_INVALID` as an allowed rejection for this test.
- The live Kryoptic release full-run artifact was collected before this patch
  reached the running container; rerun the focused test and account for this
  as one known-invalid release failure if the full run is not refreshed.

AES-CTS capability gating:

- OpenCryptoki advertises `CKM_AES_CTS`, but `test_mech_flags.py` reports that
  the mechanism is missing `CKF_ENCRYPT` and `CKF_DECRYPT`.
- ACVP AES-CTS vector tests and the CTS variant detector were still attempting
  encrypt/decrypt probes because they only checked mechanism presence.
- That is a pkcs11-check test-selection issue: the provider flag bug should be
  captured by `test_mech_flags.py`, while vector tests should skip when the
  mechanism does not advertise the operation they need.
- `src/pkcs11_check/testcases/acvp/aes/base_cts.py` and
  `src/pkcs11_check/testcases/acvp/aes/test_cts_detect.py` now skip AES-CTS
  vector probing unless `C_GetMechanismInfo(CKM_AES_CTS)` advertises both
  `CKF_ENCRYPT` and `CKF_DECRYPT`.

ML-KEM wrong-key negative test:

- OpenCryptoki returned `CKR_KEY_FUNCTION_NOT_PERMITTED` for the ML-KEM
  encapsulation test that deliberately supplies an AES key.
- The test's property is that an AES key must not be usable for ML-KEM; a
  provider may reject based on permitted key function before reporting
  `CKR_KEY_TYPE_INCONSISTENT`.
- `src/pkcs11_check/testcases/test_kem.py` now accepts
  `CKR_KEY_FUNCTION_NOT_PERMITTED` for this specific negative test.

PKCS#11 v3 optional function exposure:

- OpenCryptoki exposes `C_GetSessionValidationFlags` and `C_LoginUser`, but
  returned `CKR_FUNCTION_NOT_SUPPORTED` from the exercised calls.
- This is not a cryptographic operation failure; it is an optional v3 function
  support/advertisement issue.
- `src/pkcs11_check/testcases/test_session_validation_flags.py` now skips when
  `C_GetSessionValidationFlags` returns `CKR_FUNCTION_NOT_SUPPORTED`.
- `src/pkcs11_check/testcases/test_v30_session.py` now treats
  `CKR_FUNCTION_NOT_SUPPORTED` from `C_LoginUser` like the existing known v3
  login deviation path.

Authenticated-wrap generated-IV capability gating:

- OpenCryptoki returned `CKR_FUNCTION_NOT_SUPPORTED` from
  `C_WrapKeyAuthenticated` in the generated-IV AES-GCM authenticated-wrap test.
- The test is about generated IV/tag writeback when authenticated wrapping is
  supported; `CKR_FUNCTION_NOT_SUPPORTED` is missing function capability, not
  a failed cryptographic result.
- `src/pkcs11_check/testcases/test_authenticated_wrap.py` now skips the
  generated-IV authenticated-wrap case only for specific unsupported/rejected
  configuration CKRs (`CKR_FUNCTION_NOT_SUPPORTED`, mechanism/parameter
  rejection, arguments bad, or key function not permitted). It still fails on
  `CKR_FUNCTION_FAILED`, `CKR_DEVICE_ERROR`, crashes, or incorrect IV/tag
  writeback.

ML-KEM CKR-priority tests:

- OpenCryptoki returned `CKR_TEMPLATE_INCOMPLETE` from a
  `C_DecapsulateKey(garbage_ciphertext)` negative test before reporting an
  encrypted-data error. The probe used an empty output-key template, so template
  validation may legitimately win the CKR priority race.
- `src/pkcs11_check/testcases/ckr/_ckr_spec.py` now includes
  `CKR_TEMPLATE_INCOMPLETE` in the compatibility set for this negative test;
  strict mode still records the spec-preferred encrypted-data return code.
- OpenCryptoki also returned a non-`CKR_ARGUMENTS_BAD` error from the raw v3.2
  `C_DecapsulateKey` NULL `phKey` probe, where the test also passed an invalid
  AES mechanism and zero key handle. `src/pkcs11_check/testcases/ckr/test_ckr_v32_raw.py`
  now allows the specific mechanism/key/template validation CKRs for that
  malformed raw probe.

## Kryoptic v1.5.0

Artifacts: `artifacts/kryoptic/`.

Build/config evidence:

- Target: `test-kryoptic`.
- Built from Kryoptic tag `v1.5.0`, commit
  `f3a4ead8baa7568cf99d6dcb6e260b16d69cf010`, commit date
  `2026-03-03T17:55:36Z`.
- Built with OpenSSL `4.0.0` in the Docker target.
- This full-run artifact was produced before the pkcs11-check
  `CKR_OBJECT_HANDLE_INVALID` raw NULL-mechanism fix reached the container.

Aggregate results from `artifacts/kryoptic/results.json`:

- Total: 103,789
- Passed: 67,487
- Failed: 2,853
- Skipped: 33,378
- Xfailed: 71
- Xpassed: 0
- Harness errors: 0
- Harness crashes: 0
- Timeouts: 0
- Units/files: 243

Largest failed-file buckets:

- 1,403 failures: `src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py`
- 467 failures: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py`
- 405 failures: `src/pkcs11_check/testcases/acvp/aes/test_cts.py`
- 249 failures: `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py`
- 123 failures: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py`
- 66 failures: `src/pkcs11_check/testcases/test_mech_sign.py`
- 35 failures: `src/pkcs11_check/testcases/acvp/test_acvp_slhdsa.py`
- 13 failures: `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py`

Failure classification by failed test record:

- 2,650: `CKR_DEVICE_ERROR`
- 126: `CKR_MECHANISM_PARAM_INVALID`
- 24: other pytest assertion failures, including one known-invalid trusted-wrap
  rejection that was fixed after this run
- 15: `CKR_ARGUMENTS_BAD`
- 10: `CKR_ATTRIBUTE_VALUE_INVALID`
- 8: signal 11 subprocess crashes
- 5: signal 6 Rust abort/panic crashes
- 4: signal 7 bus-error crashes
- 3: explicit security pytest failures
- 2: `CKR_OBJECT_HANDLE_INVALID` from the now-fixed raw NULL-mechanism test
- 2: `CKR_GENERAL_ERROR`
- 2: `CKR_FUNCTION_NOT_SUPPORTED`
- 1: subprocess timeout
- 1: `CKR_DATA_LEN_RANGE`

Security/crash findings that look like provider findings, not test invalidity:

- Signal 11 on NULL template with nonzero count for `C_CreateObject`,
  `C_FindObjectsInit`, and `C_GenerateKey`.
- Signal 11 on several NULL pointer/parameter boundary tests, including
  `C_GenerateRandom(buf=NULL, buf_len=32)`, `C_SetOperationState(state=NULL,
  state_len=32)`, `CKM_SHA256_HMAC_GENERAL` NULL parameter, TLS KDF NULL label,
  and SP800-108 NULL data params.
- Signal 6 Rust abort/panic on extreme template counts and extreme
  `CKA_VALUE_LEN`; stderr reports capacity overflow or huge allocation failure.
- Signal 7 bus errors on `C_Sign` and `C_Digest` with isize-boundary input
  lengths.
- Tookan sensitive-key unwrap boundary breach reproduced.
- USER session could set `CKA_TRUSTED=True` on a freshly generated key.
- AES-CBC-PAD padding oracle reproduced with distinct corrupted-ciphertext
  outcomes.

Main functionality failure clusters:

- Heavy `CKR_DEVICE_ERROR` clusters in ACVP ECDH, Wycheproof ECDSA, ACVP
  AES-CBC-CTS, ACVP/Wycheproof ML-DSA, Wycheproof AES-CCM, EdDSA, SLH-DSA,
  and several generic sign/verify probes.
- `CKR_MECHANISM_PARAM_INVALID` clusters are concentrated in AES-CCM paths.
- HKDF/PBKDF key generation and derived-key attribute reads return
  `CKR_ATTRIBUTE_VALUE_INVALID` or `CKR_ARGUMENTS_BAD` in several tests.
- `CKM_EXTRACT_KEY_FROM_KEY` returns derived bytes that do not match the
  requested offset.

Current assessment:

- Most Kryoptic release failures look provider-side: advertised mechanisms are
  exercised and return concrete CKR failures or abort/crash under boundary
  inputs.
- The two raw NULL-mechanism failures are known pkcs11-check false positives
  fixed in source after this run; keep them out of the provider-blame count.
- The trusted-wrap rejection failure is also a known pkcs11-check false
  positive fixed in source after this run.
- A focused rerun should verify these pkcs11-check fixes against Kryoptic.

## Kryoptic Main

Artifacts: `artifacts/kryoptic-main/`.

Build/config evidence:

- Target: `test-kryoptic-main`.
- Built from Kryoptic main, commit
  `41abd4e3b3d3e77887ad25cc8ecfdb0d3a9664e2`, commit date
  `2026-05-08T20:55:41Z`.
- Built with OpenSSL `4.0.0` in the Docker target.
- This run includes the pkcs11-check raw NULL-mechanism and trusted-wrap
  rejection fixes made during this matrix.

Aggregate results from `artifacts/kryoptic-main/results.json`:

- Total: 103,789
- Passed: 67,503
- Failed: 2,839
- Skipped: 33,376
- Xfailed: 71
- Xpassed: 0
- Harness errors: 0
- Harness crashes: 0
- Timeouts: 0

Largest failed-file buckets:

- 1,403 failures: `src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py`
- 467 failures: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py`
- 405 failures: `src/pkcs11_check/testcases/acvp/aes/test_cts.py`
- 249 failures: `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py`
- 123 failures: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py`
- 66 failures: `src/pkcs11_check/testcases/test_mech_sign.py`
- 35 failures: `src/pkcs11_check/testcases/acvp/test_acvp_slhdsa.py`
- 13 failures: `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py`

Failure classification by failed test record:

- 2,650: `CKR_DEVICE_ERROR`
- 125: `CKR_MECHANISM_PARAM_INVALID`
- 28: other pytest assertion failures
- 12: `CKR_ARGUMENTS_BAD`
- 5: signal 6 Rust abort/panic crashes
- 5: signal 11 subprocess crashes
- 4: signal 7 bus-error crashes
- 3: explicit security pytest failures
- 2: `CKR_GENERAL_ERROR`
- 2: `CKR_FUNCTION_NOT_SUPPORTED`
- 1: subprocess timeout
- 1: `CKR_TEMPLATE_INCONSISTENT`
- 1: `CKR_DATA_LEN_RANGE`

Notable deltas versus Kryoptic v1.5.0:

- The raw NULL-mechanism false positives are gone in main's live run.
- The trusted-wrap rejection false positive is gone in main's live run.
- HKDF extended tests improved from one failure in release to all expected
  pass/skip/xfail in main.
- Crash/security classes remain: Rust capacity-overflow aborts, bus errors for
  isize-boundary digest/sign inputs, Tookan unwrap, trusted-key creation by
  USER, and CBC-PAD padding oracle.

Current assessment:

- Kryoptic main is slightly better in aggregate after both provider changes and
  pkcs11-check test-validity fixes, but the dominant functionality and security
  clusters remain.

## Kryoptic FIPS/PQC

Source/config caveat:

- The current `test-kryoptic-fips` Dockerfile uses
  `https://github.com/simo5/openssl.git` branch `kryoptic_ossl40`, not an
  official OpenSSL tag or upstream OpenSSL branch.
- The branch resolves to commit `2d0c89dff0e3a41ad8a83bd6389fedfff8279c7b`,
  commit date `2026-05-04T15:24:41Z`.
- `2026-05-25` official OpenSSL test:
  `docker compose -f docker/docker-compose.test.yml build --build-arg
  OPENSSL_REPO=https://github.com/openssl/openssl.git --build-arg
  OPENSSL_REF=openssl-4.0.0 test-kryoptic-fips`.
- Official OpenSSL `openssl-4.0.0` built successfully and Kryoptic compiled
  with `--features "fips,pqc"`, but the image failed at
  `./misc/hmacify.sh target/debug/libkryoptic_pkcs11.so`:
  `objcopy: error: .rodata1 not found, can't be updated`.
- The existing custom-branch image contains both `.rodata` and `.rodata1` in
  `/usr/lib64/libkryoptic_pkcs11.so`, verified with `readelf -S`.
- Current classification: the custom OpenSSL branch is part of the current
  Kryoptic FIPS/PQC Docker configuration; the official OpenSSL tag is not a
  drop-in replacement for this FIPS HMAC embedding flow.
- Kryoptic source is `main` with `--no-default-features --features "fips,pqc"`.
- `docker/kryoptic/Dockerfile.fips` now accepts `OPENSSL_REPO` and
  `OPENSSL_REF` build args so an official OpenSSL tag can be tested without
  losing the current reference configuration. Default is still the Kryoptic
  reference fork.

Summary from `artifacts/kryoptic-fips/results.json`:

- Total: 87,712
- Passed: 53,404
- Failed: 4,733
- Skipped: 29,490
- Xfailed: 73
- Xpassed: 0
- Error: 0
- Crashed: 12
- Timeout: 0

Largest failed buckets:

- 1,403: ACVP ECDH
- 1,080: Wycheproof PBES2
- 467: Wycheproof ECDSA
- 405: ACVP AES CTS
- 268: ACVP RSA
- 255: Wycheproof RSA-PSS
- 249: ACVP ML-DSA
- 177: Wycheproof PBKDF2
- 124: Wycheproof RSA decrypt
- 88: Wycheproof Ed25519
- 60: generic sign mechanism tests
- 41: Wycheproof AES

Failure classification by message:

- 4,301: `CKR_DEVICE_ERROR`
- 220: `CKR_ATTRIBUTE_VALUE_INVALID`
- 141: `CKR_MECHANISM_PARAM_INVALID`
- 29: signal 6 abort/Rust panic
- 16: other pytest failures
- 12: `CKR_ARGUMENTS_BAD`
- 5: explicit security pytest failures
- 2: signal 7 bus-error crashes
- 2: `CKR_GENERAL_ERROR`
- 2: `CKR_FUNCTION_NOT_SUPPORTED`
- 1: subprocess timeout
- 1: `CKR_TEMPLATE_INCONSISTENT`
- 1: `CKR_DATA_LEN_RANGE`

Security/crash findings:

- Signal 6 aborts dominate arithmetic-overflow, NULL-pointer, and FFI
  boundary tests, including template count overflow, huge data lengths,
  `C_SeedRandom`/`C_GenerateRandom` NULL buffers, `C_SetOperationState` NULL
  buffer, HMAC general NULL parameter, AES-CCM NULL nonce, TLS KDF NULL label,
  and SP800-108 NULL data parameters.
- Signal 7 bus errors remain on isize-boundary sign/digest paths.
- The OOM allocation guard timed out on `CKA_VALUE_LEN` key generation.
- Tookan sensitive-key unwrap still fails.
- USER session can set `CKA_TRUSTED=True`.
- RSA PKCS#1 v1.5 padding-oracle checks and AES-CBC-PAD padding-oracle checks
  still report distinguishable error behavior.

Functional clusters:

- Dominant provider-level pattern is `CKR_DEVICE_ERROR` across ECDH, ECDSA,
  AES-CTS, ML-DSA, RSA signature, RSA-PSS, PBES2/PBKDF2, and EdDSA vectors.
- RSA-OAEP is an important contrast point: the FIPS run passed
  `wycheproof/test_wycheproof_rsa_oaep.py` with 953 passed and 120 skipped.
- SLH-DSA ACVP is skipped in this FIPS target because the mechanism is not
  advertised/supported.
- Raw NULL-mechanism tests pass with the pkcs11-check accepted-code fix.

Current assessment:

- The current FIPS artifact is useful diagnostic evidence for Kryoptic
  FIPS/PQC behavior, but it should be presented as a custom-reference-OpenSSL
  configuration rather than an official OpenSSL 4.0.0 result.

## NSS Softoken Stable

Source/config:

- Docker target `test-nss` uses Fedora 44 packages, not an NSS source checkout.
- Build evidence in `artifacts/_matrix/console.log` reports
  `nss-3.123.1-1.fc44.x86_64` and `nss-softokn-3.123.1-1.fc44.x86_64`.
- `PKCS11_CHECK_SLOT=1` is configured, matching the NSS certificate DB slot.

Summary from `artifacts/nss/results.json`:

- Total: 85,515
- Passed: 48,928
- Failed: 2,111
- Skipped: 34,372
- Xfailed: 101
- Xpassed: 0
- Error: 0
- Crashed: 3
- Timeout: 0

Largest failed buckets:

- 1,403: ACVP ECDH
- 296: Wycheproof DSA
- 93: ACVP ML-DSA
- 77: Wycheproof AES
- 50: ACVP ML-KEM
- 39: generic sign mechanism tests
- 39: mechanism attribute tests
- 30: mechanism key-generation tests
- 29: mechanism multipart tests
- 15: ACVP EdDSA

Failure classification by message:

- 1,405: `CKR_TEMPLATE_INCONSISTENT`
- 296: `CKR_ARGUMENTS_BAD`
- 266: other pytest failures
- 74: `CKR_MECHANISM_PARAM_INVALID`
- 22: `CKR_DATA_LEN_RANGE`
- 14: signal 11 crash messages
- 11: `CKR_MECHANISM_INVALID`
- 8: `CKR_DEVICE_ERROR`
- 7: explicit security pytest failures
- 6: `CKR_KEY_TYPE_INCONSISTENT`
- 1: `CKR_FUNCTION_NOT_SUPPORTED`
- 1: `CKR_ATTRIBUTE_VALUE_INVALID`

Security/crash findings:

- Non-extractable key wrapping returned `CKR_OK`.
- NULL mechanism/template and NULL data pointer probes hit signal 11 crashes,
  including `C_DigestInit(NULL)`, nonzero NULL templates for object/key
  creation/search, sign/verify update NULL buffers, random NULL buffers,
  `C_SetOperationState(NULL)`, one-shot sign/verify NULL data, isize-boundary
  sign, and AES-GCM NULL inner IV.
- Tookan sensitive-key unwrap still fails.
- RSA-OAEP and AES-CBC-PAD padding-oracle checks report distinguishable
  outcomes.
- Non-copyable, trusted, and non-destroyable attribute enforcement checks fail.

Functional clusters:

- ACVP ECDH returns mostly template-related failures, not crashes.
- Wycheproof DSA valid vectors return `CKR_ARGUMENTS_BAD`.
- AES-KWP Wycheproof valid vectors produce mismatched wrapped output.
- HMAC-general multipart/sign and MAC-general parameter handling have
  mechanism parameter/key type issues.
- ML-KEM mostly works, but NSS rejects the `semi_expanded` seed-format private
  key import with `CKR_ATTRIBUTE_VALUE_INVALID`.
- RSA signature, RSA-OAEP, RSA-PSS, PBES2, PBKDF2, X25519, HKDF, and X.509
  suites are comparatively strong in this run.

Known pkcs11-check issue found from this artifact:

- `test_user_cannot_setattr_trusted` treated
  `CKR_ATTRIBUTE_TYPE_INVALID` as a failure during a USER-session
  `C_SetAttributeValue(CKA_TRUSTED=True)` escalation attempt. That return code
  is a valid rejection path, so the test now accepts it. The create-time
  `CKA_TRUSTED=True` security failure remains valid.

## NSS Softoken PQC Source Tip

Source/config:

- Docker target `test-nss-pqc` builds NSS from Mercurial source tip with
  `ARG NSS_TAG=tip`.
- Build evidence reports NSS tip `1a02ab2a26b7`:
  `Bug 2027325 - Reject empty nickname in PK11_TraverseCertsForNicknameInSlot`.
- NSPR is cloned from Mercurial source tip as a sibling checkout.
- `PKCS11_CHECK_SLOT=1` is configured.

Summary from `artifacts/nss-pqc/results.json`:

- Total: 84,819
- Passed: 47,548
- Failed: 2,019
- Skipped: 35,147
- Xfailed: 101
- Xpassed: 0
- Error: 0
- Crashed: 4
- Timeout: 0

Largest failed buckets:

- 1,403: ACVP ECDH
- 296: Wycheproof DSA
- 77: Wycheproof AES
- 50: ACVP ML-KEM
- 39: generic sign mechanism tests
- 39: mechanism attribute tests
- 31: mechanism multipart tests
- 30: mechanism key-generation tests
- 15: ACVP EdDSA

Failure classification by message:

- 1,405: `CKR_TEMPLATE_INCONSISTENT`
- 296: `CKR_ARGUMENTS_BAD`
- 174: other pytest failures
- 74: `CKR_MECHANISM_PARAM_INVALID`
- 22: `CKR_DATA_LEN_RANGE`
- 14: signal 11 crash messages
- 11: `CKR_MECHANISM_INVALID`
- 8: `CKR_DEVICE_ERROR`
- 7: explicit security pytest failures
- 6: `CKR_KEY_TYPE_INCONSISTENT`
- 1: `CKR_FUNCTION_NOT_SUPPORTED`
- 1: `CKR_ATTRIBUTE_VALUE_INVALID`

Notable comparison to stable NSS:

- ACVP ML-DSA failures disappeared from the top failure buckets; this target
  has lower failed count and higher skip count overall.
- The same dominant ECDH/DSA/AES-KWP/HMAC-general and NULL-pointer/security
  clusters remain.
- Source-tip PQC still fails ML-KEM encapsulation ACVP vectors and rejects one
  Wycheproof `semi_expanded` seed-format private-key import.
- The `test_user_cannot_setattr_trusted` false positive described in the stable
  NSS section is also present in this artifact because the source fix was made
  after this run started.

## NSS Softoken Main Source Tip

Source/config:

- Docker target `test-nss-main` builds NSS and NSPR from Mercurial source tip.
- The Dockerfile currently does not print the final NSS/NSPR revision during
  build; use `docker/provider-sources.toml` for the intended observed source
  revisions until the Dockerfile logging is improved.
- The build ran after the `CKR_ATTRIBUTE_TYPE_INVALID` SetAttribute fix, so
  this artifact has one fewer `test_access_levels.py` failure than
  `nss-pqc`.

Summary from `artifacts/nss-main/results.json`:

- Total: 84,819
- Passed: 47,549
- Failed: 2,018
- Skipped: 35,147
- Xfailed: 101
- Xpassed: 0
- Error: 0
- Crashed: 4
- Timeout: 0

Largest failed buckets:

- 1,403: ACVP ECDH
- 296: Wycheproof DSA
- 77: Wycheproof AES
- 50: ACVP ML-KEM
- 39: generic sign mechanism tests
- 39: mechanism attribute tests
- 31: mechanism multipart tests
- 30: mechanism key-generation tests
- 15: ACVP EdDSA

Failure classification by message:

- 1,405: `CKR_TEMPLATE_INCONSISTENT`
- 296: `CKR_ARGUMENTS_BAD`
- 159: other pytest failures
- 74: `CKR_MECHANISM_PARAM_INVALID`
- 22: `CKR_DATA_LEN_RANGE`
- 14: signal 11 crash messages
- 11: `CKR_MECHANISM_INVALID`
- 8: `CKR_DEVICE_ERROR`
- 7: explicit security pytest failures
- 7: `CKR_OPERATION_NOT_INITIALIZED`
- 7: `CKR_ENCRYPTED_DATA_LEN_RANGE`
- 6: `CKR_KEY_TYPE_INCONSISTENT`
- 1: `CKR_FUNCTION_NOT_SUPPORTED`
- 1: `CKR_ATTRIBUTE_VALUE_INVALID`

Notable comparison to `nss-pqc`:

- Overall totals are identical and failed count differs by one due to the
  pkcs11-check trusted SetAttribute fix.
- The same source-tip failure shape remains: ECDH template import failures,
  DSA valid-vector `CKR_ARGUMENTS_BAD`, AES-KWP output mismatch,
  HMAC-general multipart/sign issues, ML-KEM encapsulation failures, and NULL
  pointer crashes.
- Additional message/HKDF behavior is visible in the classification:
  multipart finalization returns `CKR_OPERATION_NOT_INITIALIZED` or
  `CKR_ENCRYPTED_DATA_LEN_RANGE`, HKDF lifecycle reports
  `CKR_MECHANISM_INVALID`, and generated-IV message encryption does not write
  back the IV.

## OpenCryptoki SWToken v3.27.0

Source/config:

- Docker target `test-opencryptoki` builds OpenCryptoki from source with
  `OPENCRYPTOKI_BRANCH=v3.27.0`.
- `docker/provider-sources.toml` resolves both the release tag and current
  master to commit `583d0128bb5ebfac263496bc8fe32d4aef440178`, commit date
  `2026-05-13T11:19:05Z`.
- Built against OpenSSL `4.0.0`.
- The SWToken was initialized in slot 0. Build output shows source build rather
  than Fedora package install.
- Coverage from `artifacts/opencryptoki/results.json`: 104 functions
  available, 74 called; 169 mechanisms available, 167 invoked; 242 unit files.

Summary from `artifacts/opencryptoki/results.json`:

- Total: 89,899
- Passed: 78,656
- Failed: 2,593
- Skipped: 8,593
- Xfailed: 57
- Xpassed: 0
- Harness errors: 0
- Harness crashes: 0
- Timeouts: 0

Largest failed buckets:

- 1,403: ACVP ECDH
- 435: Wycheproof RSA-PSS
- 382: ACVP AES-XTS
- 164: ACVP ML-DSA
- 107: Wycheproof AES
- 10: generic multipart mechanism tests
- 10: ML-KEM tests
- 8: generic sign mechanism tests
- 7: AES mode tests
- 6: ACVP RSA

Failure classification by message:

- 1,414: `CKR_FUNCTION_FAILED`
- 593: other pytest failures
- 521: `CKR_MECHANISM_PARAM_INVALID`
- 14: `CKR_TEMPLATE_INCONSISTENT`
- 12: `CKR_ATTRIBUTE_READ_ONLY`
- 10: `CKR_MECHANISM_INVALID`
- 9: `CKR_KEY_TYPE_INCONSISTENT`
- 7: signal 7 bus-error subprocess crashes
- 3: explicit security pytest failures
- 3: `CKR_FUNCTION_NOT_SUPPORTED`
- 3: `CKR_DATA_LEN_RANGE`
- 2: `CKR_ATTRIBUTE_VALUE_INVALID`
- 2: `CKR_ARGUMENTS_BAD`

Security/crash findings:

- Signal 7 bus errors in boundary subprocess tests:
  `C_FindObjectsInit` with extreme template counts, `C_Sign` with
  isize-boundary input lengths, and `C_Digest` with isize-boundary input
  lengths.
- Private RSA exponent was readable from a generated private key.
- Tookan extractability preservation failed: unwrap allowed a template to make
  key material extractable.
- RSA-OAEP padding-oracle check reported non-uniform errors.
- AES-CBC-PAD padding-oracle check reported distinguishable corrupted
  ciphertext behavior.

Functional clusters:

- ACVP ECDH import/derive path returns `CKR_FUNCTION_FAILED`.
- Wycheproof RSA-PSS rejects valid signatures with
  `CKR_MECHANISM_PARAM_INVALID`, especially mixed hash/MGF and salt-length
  combinations. RSA raw/signature, RSA decrypt, and RSA-OAEP vectors passed in
  contrast.
- ACVP AES-XTS and Wycheproof AES show ciphertext/output mismatches and
  selected AES/KWP issues.
- ACVP ML-DSA has generated-signature and signature-verification disagreement
  failures, while Wycheproof ML-DSA and ML-DSA sign vectors passed.
- ML-KEM is advertised enough to run, but several decapsulation paths return
  `CKR_TEMPLATE_INCONSISTENT`; Wycheproof `semi_expanded` decapsulation fails
  for 512/768/1024.
- RSA/AES unwrap paths return `CKR_ATTRIBUTE_READ_ONLY` in several generic
  wrap/unwrap lifecycle tests.
- DES CFB/OFB and some generic sign/multipart mechanisms return
  key-type/mechanism errors despite advertised mechanism coverage.

Known pkcs11-check issues in this artifact:

- This full artifact was produced before the ML-KEM wrong-key accepted-code
  fix, so one `test_kem.py::test_kem_mechanisms_with_wrong_key_type` failure is
  a known test-validity issue.
- This artifact was produced before the v3 optional-function gating fixes, so
  the `C_GetSessionValidationFlags` and `C_LoginUser`
  `CKR_FUNCTION_NOT_SUPPORTED` failures should not be counted as provider
  operation failures.
- This artifact was produced before the generated-IV authenticated-wrap
  gating fix, so the `C_WrapKeyAuthenticated` `CKR_FUNCTION_NOT_SUPPORTED`
  failure should be treated as missing capability, not failed wrap behavior.

Notable passes:

- ACVP AES CFB128/CFB8/OFB/wrap and AES-GCM suites largely passed.
- Wycheproof ECDSA, HMAC, RSA, RSA decrypt, RSA-OAEP, RSA signature
  generation, X25519, and X.509 suites passed or skipped cleanly.

## OpenCryptoki Master

Source/build context:

- Matrix target: `opencryptoki-master`.
- `docker/provider-sources.toml` resolves current master to the same commit as
  v3.27.0: `583d0128bb5ebfac263496bc8fe32d4aef440178`, commit date
  `2026-05-13T11:19:05Z`.
- Built against OpenSSL `4.0.0`.
- This run includes the CTS mechanism-flag gating, ML-KEM wrong-key accepted
  code, and v3 optional-function gating fixes, but it was produced before the
  later generated-IV authenticated-wrap, KEM template-validation, and raw v3.2
  decapsulation NULL-pointer fixes.

Summary from `artifacts/opencryptoki-master/results.json`:

- Total: 89,899
- Passed: 78,657
- Failed: 2,589
- Skipped: 8,595
- Xfailed: 58
- Xpassed: 0
- Harness errors: 0
- Harness crashes: 0
- Timeouts: 0

Largest failed buckets:

- 1,403: ACVP ECDH
- 435: Wycheproof RSA-PSS
- 382: ACVP AES-XTS
- 164: ACVP ML-DSA
- 107: Wycheproof AES
- 10: generic multipart mechanism tests
- 9: ML-KEM tests
- 8: generic sign mechanism tests
- 7: AES mode tests
- 6: ACVP RSA

Failure classification by message:

- 1,414: `CKR_FUNCTION_FAILED`
- 592: other pytest failures
- 521: `CKR_MECHANISM_PARAM_INVALID`
- 14: `CKR_TEMPLATE_INCONSISTENT`
- 12: `CKR_ATTRIBUTE_READ_ONLY`
- 9: `CKR_MECHANISM_INVALID`
- 9: `CKR_KEY_TYPE_INCONSISTENT`
- 7: signal 7 bus-error subprocess crashes
- 3: explicit security pytest failures
- 3: `CKR_DATA_LEN_RANGE`
- 2: `CKR_ATTRIBUTE_VALUE_INVALID`
- 2: `CKR_ARGUMENTS_BAD`
- 1: `CKR_FUNCTION_NOT_SUPPORTED`

Security/crash findings:

- The same bus-error boundary findings remain as in the release artifact:
  `C_FindObjectsInit` with extreme template counts and `C_Sign`/`C_Digest`
  with isize-boundary lengths.
- Private RSA exponent readability, Tookan extractability preservation,
  RSA-OAEP oracle behavior, and AES-CBC-PAD padding-oracle behavior remain.

Functional clusters:

- ECDH, RSA-PSS, AES-XTS, Wycheproof AES, and ML-DSA are unchanged in shape
  from the release-target run.
- The CTS vector false-positive cluster is gone because pkcs11-check now skips
  CTS vectors unless `CKM_AES_CTS` advertises encrypt/decrypt flags.
- `C_GetSessionValidationFlags` and `C_LoginUser` no longer appear as v3
  optional-function failures after the gating fix.
- Wycheproof ML-KEM `semi_expanded` decapsulation still fails for all three
  parameter sets.

Known pkcs11-check issues still present in this artifact:

- One generated-IV authenticated-wrap failure is a missing-capability
  classification issue fixed after this run.
- One KEM garbage-ciphertext failure is a validation-order issue fixed after
  this run by accepting `CKR_TEMPLATE_INCOMPLETE` for the deliberately empty
  output template.
- One raw v3.2 decapsulation NULL-pointer failure is a validation-order issue
  fixed after this run; the probe also supplies an invalid mechanism and zero
  key handle.

## BouncyHSM

Source/build context:

- Matrix target: `bouncyhsm`.
- `docker/provider-sources.toml` resolves release and main to tag `v2.1.0`,
  commit `3bfedeec38d10f69cf43a98a864ea4d519266d94`, commit date
  `2026-05-04T15:25:36Z`.
- The Docker build applied
  `patches/bouncyhsm/0001-fix-getattributevalue-rvmethod.patch`.
- The runner created a token in slot 1 and reported 206 mechanisms.

Run status:

- The full provider run was intentionally stopped after the third AES ACVP
  unit entered a pathological timeout tail. This preserved the remaining matrix
  run for TPM2, pkcs11-mock, and qryptotoken.
- No final monolithic `artifacts/bouncyhsm/results.json` exists for this
  target. Segmented ACVP, core/ECDH/ECDSA Wycheproof, security, general, and
  CCTV/stress/fuzz/slow reruns below have their own complete `results.json`
  files.
- `test_cfb128.py` was rerun in two bounded parts: all 2,138 non-multiblock
  vectors passed, while all 6 multiblock vectors timed out inside provider
  `C_Encrypt`/`C_Decrypt` calls.
- The remaining ACVP AES segment completed under a 20-second per-test timeout:
  11,718 total, 4,357 passed, 10 failed, 7,320 skipped, 30 xfailed, and 1
  crashed.
- The ACVP non-AES segment completed under the same 20-second per-test timeout:
  5,309 total, 3,042 passed, 1,931 failed, 306 skipped, 30 xfailed, and no
  crashes or timeouts.
- The bounded core Wycheproof segment completed under the same 20-second
  per-test timeout: 20,472 total, 19,196 passed, 748 failed, 528 skipped, and
  no crashes or timeouts. It excludes the known large ECDH/ECDSA tails; ECDH
  is covered by the standalone segment below.
- The standalone Wycheproof ECDH segment completed under the same 20-second
  per-test timeout: 13,128 total, 1,183 passed, 11,945 failed, and no crashes
  or timeouts. It needed adaptive timeout retry but produced a final
  `results.json`.
- Split Wycheproof ECDSA completed cleanly under the same 20-second per-test
  timeout and three-hour outer wall-clock wrapper where needed: 28,915 total,
  28,915 passed, no skipped, failed, crashed, or timeout results.
  - Brainpool: 6,398 passed.
  - secp160/secp192: 3,390 passed.
  - secp224: 5,810 passed.
  - secp256: 7,569 passed.
  - secp384/secp521: 5,748 passed.
- The security segment completed under the same 20-second per-test timeout:
  267 total, 169 passed, 35 failed, 57 skipped, 3 xfailed, 3 crashed, and no
  timeouts.
- The general segment completed under the same 20-second per-test timeout with
  marker filter `not (wycheproof or acvp or cctv or stress or fuzz or slow or
  security)`: 5,580 total, 2,908 passed, 208 failed, 2,440 skipped, 24 xfailed,
  no crashes, and no timeouts.
- The CCTV/stress/fuzz/slow marker segment completed under the same 20-second
  per-test timeout with marker filter `cctv or stress or fuzz or slow`: 2,425
  total, 2,413 passed, 5 failed, 6 skipped, 1 xfailed, no crashes, and no
  timeouts.
- A broad Wycheproof segment was started but stopped before final result
  synthesis because the huge ECDSA file entered file-level timeout retries.
  Its partial `state.json` is useful for planning split reruns, but it has no
  final `results.json` and is not included in official totals.

Focused artifacts:

- `artifacts/_focused/bouncyhsm-ccm`: 8,398 total, 1,028 passed, 7,370
  failed, no skipped/error/crashed/harness-timeout results.
- `artifacts/_focused/bouncyhsm-cfb1`: 2,138 total, 2,088 passed, 50 failed,
  no skipped/error/crashed/harness-timeout results.
- `artifacts/bouncyhsm-cfb128-nonmultiblock`: 2,138 total, 2,138 passed,
  no failed/skipped/error/crashed/harness-timeout results.
- `artifacts/bouncyhsm-cfb128-multiblock`: 6 total, 6 failed via
  pytest-timeout in multiblock provider calls.
- `artifacts/bouncyhsm-acvp-aes-rest`: 11,718 total, 4,357 passed, 10 failed,
  7,320 skipped, 30 xfailed, and 1 crashed.
- `artifacts/bouncyhsm-acvp-nonaes`: 5,309 total, 3,042 passed, 1,931 failed,
  306 skipped, 30 xfailed, no crashes or timeouts.
- `artifacts/bouncyhsm-wycheproof-core`: 20,472 total, 19,196 passed, 748
  failed, 528 skipped, no crashes or timeouts.
- `artifacts/bouncyhsm-wycheproof-ecdh`: 13,128 total, 1,183 passed, 11,945
  failed, no skipped/error/crashed/timeout results.
- `artifacts/bouncyhsm-wycheproof-ecdsa-brainpool`: 6,398 total, 6,398
  passed, no skipped/failed/error/crashed/timeout results.
- `artifacts/bouncyhsm-wycheproof-ecdsa-secp160-192`: 3,390 total, 3,390
  passed, no skipped/failed/error/crashed/timeout results.
- `artifacts/bouncyhsm-wycheproof-ecdsa-secp224`: 5,810 total, 5,810
  passed, no skipped/failed/error/crashed/timeout results.
- `artifacts/bouncyhsm-wycheproof-ecdsa-secp256`: 7,569 total, 7,569
  passed, no skipped/failed/error/crashed/timeout results.
- `artifacts/bouncyhsm-wycheproof-ecdsa-secp384-521`: 5,748 total, 5,748
  passed, no skipped/failed/error/crashed/timeout results.
- `artifacts/bouncyhsm-security`: 267 total, 169 passed, 35 failed, 57
  skipped, 3 xfailed, 3 crashed, no timeouts.
- `artifacts/bouncyhsm-general`: 5,580 total, 2,908 passed, 208 failed, 2,440
  skipped, 24 xfailed, no crashes or timeouts.
- `artifacts/bouncyhsm-cctv-stress-fuzz-slow`: 2,425 total, 2,413 passed,
  5 failed, 6 skipped, 1 xfailed, no crashes or timeouts.

Failure classification for focused units:

- CCM: 3,161 `CKR_ENCRYPTED_DATA_INVALID`, 2,518 `CKR_GENERAL_ERROR`,
  1,268 plaintext mismatches, and 423 invalid-tag accepts.
- CFB1: 26 plaintext mismatches and 24 ciphertext mismatches, concentrated in
  short bit-length payloads.
- CFB128: all 2,138 non-multiblock vectors passed; all 6 multiblock vectors
  timed out in provider calls; no crash.
- CFB8: 2,138 passed, four pytest-timeout failures in multiblock calls, one
  confirmed segfault in `C_Encrypt`, and one decrypt multiblock vector that
  passed in isolation after crash triage.
- GCM: 80 passed, 120 skipped, and 30 xfailed.
- OFB: 2,138 passed and 6 multiblock timeout failures.
- Wrap/KWP: 7,200 skipped because `AES_KEY_WRAP` and `AES_KEY_WRAP_KWP` are not
  supported by the module.
- XTS: file-skipped because `AES_XTS` is not supported by the module; this is
  visible in console output but not counted in the `results.json` summary.
- ACVP ECDH: all 1,736 vectors failed; 1,403 with `CKR_GENERAL_ERROR` and
  333 with `CKR_MECHANISM_PARAM_INVALID`.
- ACVP ECDSA: 70 passed and 30 xfailed.
- ACVP EdDSA: 10 passed, 10 skipped, and 9 failed; the failures are 5
  signature mismatches and 4 valid-key import rejections with
  `CKR_ATTRIBUTE_VALUE_INVALID`.
- ACVP hash/SHA3: 237 passed, 1 skipped, and 3 failed with
  `CKR_ARGUMENTS_BAD`.
- ACVP HMAC: 1,183 passed and 295 skipped.
- ACVP ML-DSA: 289 passed and 171 failed; most failures are generated
  signatures that fail verification, plus valid-signature rejection cases.
- ACVP ML-KEM: 180 passed.
- ACVP RSA: 932 passed and 6 failed; failures are valid RSA-PSS/SHA3-256
  signature rejections.
- ACVP RSA key generation: 63 passed.
- ACVP SLH-DSA: 78 passed and 6 valid-signature rejection failures.
- Core Wycheproof: failures clustered in AES (414), HMAC (180), RSA-OAEP
  (54), plain RSA signature verification (30), ML-DSA signing (27), RSA-PSS
  (17), RSA PKCS#1 signature generation (10), ML-DSA verification (9), and
  generic HMAC/RSA tests (7). ChaCha, DSA file skip, Ed25519 skips, HKDF,
  ML-KEM, PBES2/PBKDF2 file skips, RSA decrypt, and X25519 completed without
  failed records.
- Wycheproof ECDH: 11,945 failed and 1,183 passed, with no crashes or
  timeouts. Failure traces are dominated by `CKR_MECHANISM_PARAM_INVALID`, so
  this is a broad mechanism-parameter/correctness cluster rather than an
  isolated curve or vector issue.
- Wycheproof ECDSA: all split shards passed cleanly, 28,915/28,915 total, with
  no skips, failures, crashes, or timeouts. This is evidence-backed across
  brainpool, secp160/secp192, secp224, secp256, and secp384/secp521.
- Security: failures clustered in arithmetic overflow (16), padding oracle
  (7), FFI length boundary (5), API security (4), CVE regression (2), and API
  boundary (1). The segment recorded 3 crashes for
  `test_parameter_validation.py` after adaptive isolation repeatedly reproduced
  a `C_GenerateKeyPair` segfault in weak RSA public exponent validation. Other
  crash findings included signal 7 arithmetic/length-boundary crashes, signal
  11 template-count crashes, and `C_VerifyInit(mechanism=NULL)` signal 11.
  API-security failures showed readable `CKA_PRIVATE_EXPONENT`,
  `CKA_EXTRACTABLE` escalation, `CKA_SENSITIVE` downgrade, and copy-based
  sensitive downgrade. Padding-oracle tests reported non-uniform RSA PKCS#1
  v1.5/OAEP errors, AES-CBC-PAD oracle behavior, and RSA decrypt timing ratio
  7.0x. KWP error-path, RSA error-path, FFI NULL pointer, handle reuse, nonce
  quality, and Tookan slices were clean or skipped/xfailed in expected ways.
- General: failures clustered in mechanism sign (33), mechanism digest (31),
  mechanism attribute (16), mechanism multipart (12), hash ML-DSA (11),
  mechanism wrap (11), mechanism keygen (8), session state machine (8), access
  levels (7), and mechanism encrypt (6). Dominant CKR text in failures was
  `CKR_TEMPLATE_INCONSISTENT`, `CKR_ARGUMENTS_BAD`, `CKR_GENERAL_ERROR`,
  `CKR_MECHANISM_PARAM_INVALID`, and session/read-only/login CKRs. Clean or
  mostly clean counterexamples included mechanism flags/probe/KEM/lifecycle,
  init/interface/interop, object lifecycle/search/size, RSA extended/import/
  wrapping/OAEP, X.509 import/search/identity/lifecycle, token flags, surface
  audit, and clean skips for unsupported protocol families.
- CCTV/stress/fuzz/slow: CCTV Ed25519 passed 914/914, CCTV ML-DSA passed
  449/449, CCTV RFC6979 had 1 pass and 1 xfail, and X.509 limbo stress passed
  1,009/1,009. Resource, OpenSSL interop, stateful, subprocess safety, stress,
  and threading slices were clean or skipped where expected. The only failed
  unit was `test_fuzz.py`: 5 failed, 6 passed. All failures returned
  `CKR_OPERATION_ACTIVE` from repeated digest/HMAC single-part operations
  (`sha256_deterministic`, `sha256_cross_verify`, `sha512_cross_verify`,
  `hmac_sha256_cross_verify`, and `hmac_deterministic`).

Current classification:

- BouncyHSM was configured and reachable; this is not a module-load or token
  initialization failure.
- AES-CFB1 mostly works, but short bit-length vectors expose output mismatch
  behavior.
- AES-CCM is broadly incompatible with the ACVP vector set in this run,
  including many `CKR_GENERAL_ERROR` and `CKR_ENCRYPTED_DATA_INVALID` returns,
  result mismatches, and invalid-tag accepts.
- AES-CFB8, AES-CFB128, and AES-OFB have apparent multiblock
  crash/timeout/pathological-tail behavior, while ordinary CFB128/OFB vectors
  pass.
- Non-AES ACVP shows a mixed shape: ML-KEM, RSA key generation, HMAC, and
  ECDSA are strong or mostly clean; ECDH is a broad failure cluster; ML-DSA,
  EdDSA, RSA-PSS/SHA3, hash/SHA3, and SLH-DSA have narrower correctness or
  validation failures.
- Split Wycheproof ECDSA is complete and clean across brainpool,
  secp160/secp192, secp224, secp256, and secp384/secp521.
- Core Wycheproof shows clean X25519, HKDF, ChaCha, ML-KEM, and RSA decrypt
  coverage in this bounded segment; AES, HMAC, RSA-OAEP/PSS/signature, and
  ML-DSA signing or verification remain important failure clusters.
- Wycheproof ECDH independently confirms the broad ECDH weakness already seen
  in ACVP.
- Security shows useful clean counterexamples in RSA error-path, FFI
  NULL-pointer handling, handle reuse, nonce quality, and Tookan slices, but
  key-attribute boundaries, padding/timing oracles, and boundary-input crash
  handling remain reportable findings.
- General shows BouncyHSM is healthy enough across init/interface/interop,
  objects, RSA, and X.509 import, while advertised mechanism details remain
  uneven: BLAKE2 keygen/HMAC/digest, AES/Salsa/ChaCha KATs, ML-DSA hash and
  multipart signing, EXTRACT_KEY_FROM_KEY, session-state semantics, and v3
  certificate `CKA_PUBLIC_KEY_INFO` import all need follow-up.
- CCTV/stress/fuzz/slow coverage is now complete in bounded mode. The clean
  CCTV and X.509 limbo stress results are useful counterexamples to the slower
  ACVP/Wycheproof tails. The fuzz failures deserve focused follow-up because
  they look like operation-state leakage after repeated single-part digest/HMAC
  calls rather than module load or timeout failures.
- BouncyHSM now has complete segmented evidence for the planned slices, but the
  article should still label it as segmented evidence rather than one
  monolithic full-suite run.

## TPM2

Source/build context:

- Matrix target: `tpm2`.
- Initial full matrix artifact was produced by the Fedora package image:
  `tpm2-pkcs11-1.9.1-7.fc44`, `swtpm-0.10.1-3.fc44`,
  `tpm2-abrmd-3.0.0-9.fc44`, TPM family 2.0.
- `docker/provider-sources.toml` resolves the latest upstream
  `tpm2-pkcs11` release and master branch to tag `1.10.0`, commit
  `a95465ce672c5fda92a2d34bc5cbeda4b0511c80`, commit date
  `2026-05-19T20:44:58Z`.
- The Docker target has now been corrected to build upstream
  `tpm2-pkcs11` from source at that commit. The source build needs the
  Python module imported as `pkcs11`; Fedora 44 does not package that module
  under a `python3-pkcs11` name, so the image installs PyPI
  `python-pkcs11 0.9.4` for Python 3.14 before `./configure`.

Source-built latest-upstream full run:

- `2026-05-25 docker compose -f docker/docker-compose.test.yml run --rm -e
  PKCS11_CHECK_ARTIFACT_DIR=/artifacts/tpm2-source --build test-tpm2`
  source-built the image, initialized an swtpm token, loaded
  `/usr/lib64/libtpm2_pkcs11.so`, and completed the full pkcs11-check matrix.
- Artifact: `artifacts/tpm2-source`.
- Source-build dependency evidence printed by the runner:
  `swtpm-0.10.1-3.fc44`, `tpm2-abrmd-3.0.0-9.fc44`,
  `tpm2-tools-5.7-5.fc44`, `tpm2-tss-4.1.3-9.fc44`,
  `python-pkcs11 0.9.4`.
- Summary:
  - Total: 81,400.
  - Passed: 9,847.
  - Failed: 6,825.
  - Skipped: 64,696.
  - Xfailed: 32.
  - Errors: 0.
  - Crashed/timeouts in summary: 0/0; three subprocess signal-11 crashes and
    one subprocess timeout are captured as normal failed tests.

Largest failing buckets in the source-built run:

- 2,144: ACVP AES-CFB128.
- 1,734: ACVP ECDH.
- 856: generic Wycheproof.
- 813: Wycheproof RSA-PSS.
- 444: ACVP HMAC.
- 198: Wycheproof HMAC.
- 63: ACVP RSA.
- 53: generic sign mechanism tests.

Failure classification by message in the source-built run:

- 3,188: `CKR_GENERAL_ERROR`.
- 2,414: `CKR_ATTRIBUTE_VALUE_INVALID`.
- 813: `CKR_MECHANISM_PARAM_INVALID`.
- 329: `CKR_FUNCTION_NOT_SUPPORTED`.
- 69: other pytest failures.
- 8: `CKR_HOST_MEMORY`.
- 3: signal 11 subprocess crashes.
- 1: subprocess timeout.

Observed source-built behavior:

- AES-CFB128 failed all 2,144 ACVP vectors with `CKR_GENERAL_ERROR`; provider
  stderr repeatedly reported `ERROR: Expected object to have:
  CKA_ALLOWED_MECHANISMS`.
- HMAC failures share the same `CKA_ALLOWED_MECHANISMS` root cause.
- EC import/generation is constrained: EC public/private creation often returns
  `CKR_ATTRIBUTE_VALUE_INVALID` with messages such as "Can only create RSA
  Public key objects or data objects"; one ECDH path exposed malformed EC-point
  data that pkcs11-check rejected as a truncated DER OCTET STRING.
- P-521 ECDSA/keygen paths hit `CKR_HOST_MEMORY` with ASN.1 decode errors.
- RSA-PSS valid signatures are frequently rejected with
  `CKR_MECHANISM_PARAM_INVALID`, while plain RSA Wycheproof had a large working
  lane: 3,224 passed and 2,089 skipped in `test_wycheproof_rsa.py`.
- ECDH Wycheproof had a narrow working lane: 1,040 passed and 12,088 skipped.
- X25519 Wycheproof produced 108 passes and 4,068 skips.
- X.509 object import/stress tests are mostly healthy: limbo import passed 645
  and limbo stress passed 1,009. One X.509 lifecycle test showed that a
  non-modifiable certificate label could still be changed.
- `C_DigestInit(mechanism=NULL)` and two isize-boundary digest probes produced
  signal-11 subprocess crashes. Fork-after-initialize timed out in a child
  process.
- Threaded random generation failed with ESYS bad-sequence errors, indicating
  TPM/ESAPI ordering/thread-safety limitations under concurrent calls.

Current source-built classification:

- The latest upstream `tpm2-pkcs11 1.10.0` Docker target is now correctly
  configured, builds from source, initializes, and completes the matrix.
- The provider has narrow working lanes for interface, RNG, selected RSA
  verify, ECDH Wycheproof, X25519 Wycheproof, and X.509 object import/stress.
- Broad software-token assumptions fail against TPM-backed keys: AES/HMAC
  operations require or expect `CKA_ALLOWED_MECHANISMS`, AES key generation is
  often reported unsupported, EC object creation is limited, RSA-PSS parameter
  handling is incomplete for many valid vectors, and several raw boundary probes
  still crash in subprocess.

Archived package-run caveat:

- The complete statistics below are archived in
  `artifacts/tpm2-fedora-package-20260525`; they are useful provider evidence
  but are not the latest-upstream `tpm2-pkcs11 1.10.0` full run.

Summary from the Fedora package full run:

- Total: 64,084.
- Passed: 8,433.
- Failed: 5,067.
- Skipped: 49,727.
- Errors: 851.
- Xfailed: 6.
- Crashed: 0 in the summary, but one call-phase subprocess crash was observed
  in report-log classification.

Largest failing buckets:

- 2,144: ACVP AES-CFB128.
- 871: Wycheproof generic vectors.
- 813: Wycheproof RSA-PSS.
- 444: ACVP HMAC.
- 198: Wycheproof HMAC.
- 53: generic sign mechanism tests.
- 31: ACVP RSA.

Failure classification by message:

- 3,138: `CKR_GENERAL_ERROR`.
- 813: `CKR_MECHANISM_PARAM_INVALID`.
- 669: `CKR_ATTRIBUTE_VALUE_INVALID`.
- 329: `CKR_FUNCTION_NOT_SUPPORTED`.
- 106: other pytest failures.
- 8: `CKR_HOST_MEMORY`.
- 2: signal 7 bus-error subprocess crashes.
- 1: timeout.
- 1: signal 11 subprocess crash.

Observed behavior:

- AES-CFB128 failed all 2,144 ACVP vectors in the package run with
  `CKR_GENERAL_ERROR`; provider stderr repeatedly reported
  `ERROR: Expected object to have: CKA_ALLOWED_MECHANISMS`.
- RSA and ECDSA setup failures were dominated by TPM context exhaustion during
  login/key setup, including `Esys_Load` "out of memory for object contexts"
  and "Error unsealing wrapping key" messages.
- `C_DigestInit(mechanism=NULL)` produced a signal 11 subprocess crash.
- AES key generation commonly returned `CKR_FUNCTION_NOT_SUPPORTED`; RSA key
  generation often returned `CKR_ATTRIBUTE_VALUE_INVALID` with a public/private
  attribute mismatch message.
- X.509 object import/stress tests mostly passed, so the package target is
  reachable and not simply misinitialized.

Archived package-run classification:

- The previous full run is valid as Fedora package evidence and shows real
  limited-mechanism/resource-limit behavior, but it must not be presented as
  the latest upstream release run.
- Source-built `tpm2-pkcs11 1.10.0` supersedes it for article statistics, while
  the package run remains useful for comparing Fedora packaging behavior.

## pkcs11-mock

Source/build context:

- Matrix target: `pkcs11-mock`.
- `docker/provider-sources.toml` resolves release and master to tag `v2.0.0`,
  commit `ac5f15adb92e15926825fa93e78a1995db1a32f8`, commit date
  `2025-01-29T06:48:36Z`.
- The Docker image builds the upstream C mock provider into
  `/usr/lib64/libpkcs11-mock.so`.

Summary:

- Total: 32,633.
- Passed: 2,560.
- Failed: 3,546.
- Skipped: 26,517.
- Xfailed: 10.
- Errors/crashes/timeouts: 0.

Largest failing buckets:

- 1,009: X.509 limbo stress.
- 729: Wycheproof generic vectors.
- 700: Wycheproof RSA-OAEP.
- 169: X.509 limbo import.
- 162: ACVP RSA.
- 124: Wycheproof RSA decrypt.
- 30: ACVP RSA keygen.

Failure classification by message:

- 1,323: other pytest failures.
- 1,127: `CKR_MECHANISM_INVALID`.
- 991: `CKR_KEY_TYPE_INCONSISTENT`.
- 74: `CKR_SESSION_COUNT`.
- 14: fixed dummy `Hello world!` data returned where imported data was expected.
- 9: constant or duplicate random-output findings.
- 6: `CKR_ARGUMENTS_BAD`.
- 2: `CKR_ATTRIBUTE_VALUE_INVALID`.

Current classification:

- `pkcs11-mock` is a diagnostic/mock baseline, not a comparable crypto
  provider.
- The results are useful for pkcs11-check harness breadth because the target
  is stable and crash-free, but many failures reflect the mock returning fixed
  dummy data, constant/random-looking placeholders, unsupported real
  mechanisms, and session-count limits.
- X.509 and cryptographic vector failures should be treated as expected mock
  limitations rather than provider conformance findings.

## qryptotoken

Source/build context:

- Matrix target: `qryptotoken`.
- `docker/provider-sources.toml` resolves release and main to tag `v0.4.1`,
  commit `24fae88227d6d04331fb599327db83c24d5ae955`, commit date
  `2026-01-28T13:02:59Z`.
- The Docker build installed Rust stable `rustc 1.95.0 (59807616e
  2026-04-14)` during the matrix run.

Matrix-run status:

- No PKCS#11 module was produced.
- The old runner incorrectly returned success when the module was unavailable;
  that is now fixed so future matrix runs classify this target as
  build-unavailable instead of passed.
- `2026-05-25 bash docker/test.sh qryptotoken` rebuilt the target, left
  `artifacts/qryptotoken/build.log` and
  `artifacts/qryptotoken/build-status.json`, and exited nonzero.

Build failure:

- `cargo build --release` failed with exit code 101.
- The root problem is generated PKCS#11 bindings: `CK_ATTRIBUTE` and related
  structs were generated as opaque one-byte placeholders, so later Rust code
  has no fields such as `type_`, `pValue`, or `ulValueLen`.
- The build log also includes layout-assertion failures such as integer
  underflow while checking expected C struct sizes.
- This is a qryptotoken/bindgen/header-generation build issue, not a
  pkcs11-check runtime result.

Current classification:

- Build unavailable on the current Fedora/Rust/bindgen stack.
- Do not include qryptotoken in provider conformance statistics until the
  upstream binding generation issue is fixed or the Docker image pins a
  compatible build stack with evidence.

## Focused Rerun Evidence

These reruns are intentionally stored under `artifacts/_focused/` so they do
not overwrite full provider statistics.

- `artifacts/_focused/softhsm2-des`: after enabling OpenSSL default and legacy
  providers in `docker/softhsm2/Dockerfile.main`,
  `test_des.py::TestDESEncryption::test_des_cbc_pad_roundtrip` and
  `test_des.py::TestDES3Encryption::test_des3_cbc_pad_roundtrip` both passed.
  This confirms direct DES/DES3 CBC-PAD failures were runtime OpenSSL-provider
  configuration, while wrap/derive DES/3DES findings remain separate.
- `artifacts/_focused/kryoptic-fixes`: Kryoptic release rerun passed
  `ckr/test_ckr_raw_args_bad.py` with 7 passed/1 skipped and passed
  `TestTrustedAttribute::test_wrap_with_trusted_rejects_untrusted`. The earlier
  raw NULL-mechanism and trusted-wrap artifacts were pkcs11-check
  validation-order/accepted-CKR issues, not provider findings.
- `artifacts/_focused/opencryptoki-fixes`: OpenCryptoki master rerun passed
  `test_authenticated_wrap.py` with 2 passed/7 skipped, passed
  `ckr/test_ckr_kem.py` with 4 passed, and passed
  `ckr/test_ckr_v32_raw.py` with 8 passed. The previously noted
  generated-IV authenticated-wrap, KEM template-order, and v3.2 raw
  decapsulation entries are fixed in pkcs11-check.
- `artifacts/_focused/bouncyhsm-ccm`: BouncyHSM completed the full AES-CCM
  file with 1,028 passed and 7,370 failed. Failures split into 3,161
  `CKR_ENCRYPTED_DATA_INVALID`, 2,518 `CKR_GENERAL_ERROR`, 1,268 plaintext
  mismatches, and 423 invalid-tag accepts.
- `artifacts/_focused/bouncyhsm-cfb1`: BouncyHSM completed the full AES-CFB1
  file with 2,088 passed and 50 failed: 26 plaintext mismatches and 24
  ciphertext mismatches.
- `artifacts/bouncyhsm-cfb128-nonmultiblock`: BouncyHSM passed all 2,138
  ordinary CFB128 encrypt/decrypt vectors.
- `artifacts/bouncyhsm-cfb128-multiblock`: BouncyHSM timed out on all 6
  CFB128 multiblock vectors inside provider calls.
- `artifacts/bouncyhsm-acvp-aes-rest`: BouncyHSM completed the remaining ACVP
  AES segment with 4,357 passed, 10 failed, 7,320 skipped, 30 xfailed, and one
  confirmed CFB8 `C_Encrypt` segfault. CFB8 and OFB multiblock cases produced
  pytest-timeout failures; wrap/KWP and XTS were unsupported in this module
  configuration.
- `artifacts/bouncyhsm-acvp-nonaes`: BouncyHSM completed all non-AES ACVP
  files with 3,042 passed, 1,931 failed, 306 skipped, and 30 xfailed. It had
  no crashes or timeouts. ECDH failed broadly; ML-KEM and RSA key generation
  passed completely.
- `artifacts/bouncyhsm-wycheproof-core`: BouncyHSM completed the bounded core
  Wycheproof segment with 19,196 passed, 748 failed, and 528 skipped. It had
  no crashes or timeouts. Failures cluster in AES, HMAC, RSA-OAEP/PSS/signature,
  and ML-DSA signing/verification; X25519, HKDF, ChaCha, ML-KEM, and RSA
  decrypt were clean in this segment.
- `artifacts/bouncyhsm-wycheproof-ecdh`: BouncyHSM completed the standalone
  Wycheproof ECDH segment with 1,183 passed and 11,945 failed. It had no
  crashes or timeouts. Failure traces are dominated by
  `CKR_MECHANISM_PARAM_INVALID`.
- `artifacts/bouncyhsm-wycheproof-ecdsa-brainpool`: BouncyHSM completed the
  brainpool Wycheproof ECDSA shard with 6,398 passed and no
  skipped/failed/error/crashed/timeout results.
- `artifacts/bouncyhsm-wycheproof-ecdsa-secp160-192`: BouncyHSM completed the
  secp160/secp192 Wycheproof ECDSA shard with 3,390 passed and no
  skipped/failed/error/crashed/timeout results.
- `artifacts/bouncyhsm-wycheproof-ecdsa-secp224`: BouncyHSM completed the
  secp224 Wycheproof ECDSA shard with 5,810 passed and no
  skipped/failed/error/crashed/timeout results.
- `artifacts/bouncyhsm-wycheproof-ecdsa-secp256`: BouncyHSM completed the
  secp256 Wycheproof ECDSA shard with 7,569 passed and no
  skipped/failed/error/crashed/timeout results.
- `artifacts/bouncyhsm-wycheproof-ecdsa-secp384-521`: BouncyHSM completed the
  secp384/secp521 Wycheproof ECDSA shard with 5,748 passed and no
  skipped/failed/error/crashed/timeout results.
- `artifacts/bouncyhsm-security`: BouncyHSM completed the security family with
  169 passed, 35 failed, 57 skipped, 3 xfailed, and 3 crashes. It had no
  timeouts. Findings include weak-RSA-exponent keygen segfaults, arithmetic and
  FFI length-boundary crashes, readable/downgradable private key attributes,
  RSA/AES padding-oracle behavior, and RSA decrypt timing spread. RSA
  error-path, FFI NULL-pointer, nonce quality, handle reuse, and Tookan slices
  were clean or skipped/xfailed as expected.
- `artifacts/bouncyhsm-general`: BouncyHSM completed the non-vector,
  non-security, non-stress/fuzz/slow/CCTV general family with 2,908 passed,
  208 failed, 2,440 skipped, and 24 xfailed. It had no crashes or timeouts.
  Failures cluster in mechanism sign/digest/attribute/multipart/wrap/keygen,
  hash ML-DSA, session-state semantics, access levels, AES/Salsa/ChaCha
  behavior, and BLAKE2. Init/interface/interop/object/RSA/X.509 import slices
  are useful clean counterexamples.
- `artifacts/bouncyhsm-cctv-stress-fuzz-slow`: BouncyHSM completed the
  remaining marker family with 2,413 passed, 5 failed, 6 skipped, and 1 xfailed.
  It had no crashes or timeouts. CCTV Ed25519, CCTV ML-DSA, X.509 limbo stress,
  resource, OpenSSL interop, stateful, subprocess safety, stress, and threading
  slices are clean or skipped as expected. The five failures are all
  `CKR_OPERATION_ACTIVE` returns in fuzz digest/HMAC repeated single-part
  operation tests.
- `artifacts/bouncyhsm-wycheproof`: broad run intentionally stopped after
  generic/AES/ChaCha/DSA/ECDH state and an ECDSA file-level timeout retry. No
  final `results.json` was produced, so this artifact is planning evidence for
  split Wycheproof reruns, not an official provider statistic.

## Follow-Up Checks To Run

- Parse completed provider artifacts into a compact machine-readable summary
  after each provider completes.
- If BouncyHSM should become an official monolithic full-suite provider
  statistic, rerun the whole provider despite the runtime cost. Otherwise use
  the complete segmented evidence and state that large ECDH/ECDSA files make a
  monolithic target inefficient and prone to file-level timeout retry behavior.
- For SoftHSM2 main ML-DSA, inspect exact failed vector groups and CKR/result
  messages before assigning blame to provider or test.
- Deep-dive TPM2 source-built failures into provider limitations versus
  pkcs11-check assumptions, especially `CKA_ALLOWED_MECHANISMS`, EC object
  import/generation, RSA-PSS parameter handling, and raw boundary crashes.
- For every provider, record:
  provider version/tag/commit/date, dependency versions, build status, test
  summary, failure clusters, crash/security findings, and likely classification.
