# Module Issues

Known issues, quirks, and compliance deviations per PKCS#11 module.
Updated as Docker targets are analyzed.

Current May 2026 provider matrix results, source revisions, and article-facing
statistics are in [docker-provider-results.md](docker-provider-results.md).
Older sections below preserve issue detail from earlier runs and may name older
provider package versions where the finding was first recorded.

---

## SoftHSM2 2.7.0 (v2.40)

**Status: 22,622 passed, 0 failed, 6,287 skipped, 658 xfailed**

### xfail breakdown (658 total)
| Count | File | Reason |
|-------|------|--------|
| 624 | test_wycheproof_rsa_oaep.py | RSA-OAEP with non-SHA1 hash/MGF — SoftHSM2 only supports SHA-1 for OAEP |
| 24 | test_wycheproof_hmac.py | HMAC truncated output variants not supported |
| 9 | test_wycheproof.py | AES-GCM edge cases (SoftHSM2 2.6.1 has no GCM; 2.7.0 has it but some edge cases fail) |
| 1 | test_wycheproof_ecdh.py | ECDH with invalid curve point handling |

### Known bugs
- **RSA-OAEP only supports SHA-1**: SoftHSM2 only supports `CKM_SHA_1` for OAEP hash algorithm and `CKG_MGF1_SHA1` for MGF. Returns `CKR_ARGUMENTS_BAD` with error message "hashAlg must be CKM_SHA_1" or "mgf must be CKG_MGF1_SHA1" (SoftHSM.cpp:13723-13732). RFC 8017 and PKCS#11 allow SHA-224/256/384/512 for OAEP, but SoftHSM2 is hardcoded to SHA-1 only. Affects Wycheproof OAEP vectors with non-SHA1 hash algorithms. Detected by: `test_wycheproof_rsa_oaep.py` (tc364, tc365, and other parameterized tests with SHA-224/256/384/512).
- **RSA-PSS with distinct hash/MGF not supported**: SoftHSM2 (both 2.7.0 and main/dev branch) rejects RSA-PSS signatures when the message hash algorithm differs from the MGF hash algorithm (e.g., SHA-384 for hash with MGF1-SHA512). Returns `CKR_ARGUMENTS_BAD` with error message "Hash and MGF don't match" (SoftHSM.cpp:4303-4306). RFC 8017 allows distinct hashes, but SoftHSM2 enforces identical hashes. Affects Wycheproof vectors with "DistinctHash" flag. Detected by: `test_wycheproof_rsa_pss.py` (tc116 and other parameterized tests).
- **ECDSA_SHA* accepts invalid signatures (ACVP SigVer)**: `C_Verify` with `CKM_ECDSA_SHA256`, `CKM_ECDSA_SHA384`, `CKM_ECDSA_SHA512` accepts NIST ACVP `testPassed=False` vectors (modified r, modified s, zero r, zero s, modified message, modified key). 17/17 invalid vectors in `test_acvp_ecdsa.py` return `CKR_OK` instead of `CKR_SIGNATURE_INVALID`. Only valid vectors (tc54, tc62, tc103) produce the correct result. Detected by: `test_acvp_ecdsa_sigver`.
- **EDDSA accepts invalid signatures (ACVP SigVer)**: `C_Verify` with `CKM_EDDSA` accepts NIST ACVP `testPassed=False` vectors for both Ed25519 and Ed448. 8/8 invalid vectors return `CKR_OK` instead of `CKR_SIGNATURE_INVALID`. Detected by: `test_acvp_eddsa_sigver`.
- **DES_CBC_PAD / DES3_CBC_PAD wrap advertised but not operational**: SoftHSM2 advertises
  `CKF_WRAP` and `CKF_UNWRAP` for `CKM_DES_CBC_PAD` and `CKM_DES3_CBC_PAD`, but `C_WrapKey`
  returns `CKR_MECHANISM_INVALID` even when called with matching DES-family wrapping keys and
  DES-family target keys. Detected by: `test_mech_wrap.py`.
- **Lenient wrong-key-type at `C_SignInit`/`C_VerifyInit` (ECDSA + RSA key), but SAFE at the
  operation**: `C_SignInit(CKM_ECDSA, RSA private key)` returns `CKR_OK` (PKCS#11 §5.2 prefers
  `CKR_KEY_TYPE_INCONSISTENT` at init); the subsequent `C_Sign` then safely refuses with
  `CKR_GENERAL_ERROR` (and `C_Verify` with `CKR_SIGNATURE_LEN_RANGE`) — **no signature is
  produced and there is no crash**. SoftHSM2 is the only one of softhsm2/kryoptic/NSS/opencryptoki
  that defers the key-type check this way (the others reject at init). Because the operation leaves
  no usable result behind, this is a recorded **deviation (xfail)**, not a forgery: the
  `test_ckr_wrong_key_type_hardening.py::TestWrongAsymmetricKeyTypeContinuation` continuation probe
  classifies by *effect* — a produced signature (`BREAK`) would `fail`, a crash would `fail`, and a
  safe late refusal `xfail`s. Note: the first-line init-only checks (`test_mech_negative.py::
  TestWrongKeyType::test_ecdsa_with_rsa_key_rejected`, `test_ckr_sign.py::TestSignInitErrors`,
  `test_ckr_verify.py::TestVerifyInitErrors`) still hard-`fail` SoftHSM2 here because they assert
  rejection at the init stage without continuing to the operation — a stricter first-line check
  whose fail-vs-xfail classification for lenient-but-safe init is a flagged decision (the
  continuation probe is the authoritative safety verifier).
- **HIGH — SIGSEGV on integer-overflow `template_count` (NEW 2026-04-29)**: Calling
  `C_CreateObject`, `C_GenerateKey`, or `C_GenerateKeyPair` with `ulCount` set to extreme
  values such as `0xffffffffffffffff` (UINT64_MAX), `0xaaaaaaaaaaaaaab`
  (sizeof(CK_ATTRIBUTE)-overflow boundary), or `0x100000000` (4 GiB) crashes the module
  with `SIGSEGV` instead of returning `CKR_ARGUMENTS_BAD`. 8/8 overflow inputs across
  the three function entry points reproduce the crash. Caller-controlled-count→DoS via
  process termination. Affects `softhsm2-main` (HEAD on 2026-04-29). Detected by:
  `test_arithmetic_overflow.py::TestTemplateCountOverflow` and
  `TestGenerateKeyPairCountOverflow`. Likely missing length validation in
  `SoftHSM.cpp`'s template parser before allocating / iterating. Reportable upstream.
  **Update 2026-05-27:** a focused current-source stock SoftHSM2 2.7.0 rerun
  confirms the same eight signal-11 template/keypair count rows in
  `artifacts/_focused/softhsm2-arithmetic-overflow-current-20260527/`. The same
  file also reports one abnormal positive child exit for
  `C_EncryptInit(CKM_AES_CBC, ulParameterLen=ULONG_MAX)`. That row is not a
  signal crash, but it is still a failed malformed-boundary probe and should
  remain visible.
- **GCM null-IV SIGSEGV (UPDATED 2026-05-26)**:
  `test_ffi_length_boundary.py::TestMechanismNullInnerParams::test_gcm_null_iv`
  calls `C_EncryptInit(CKM_AES_GCM, pIv=NULL, ulIvLen=12)` in a crash-isolated
  child. A focused current-source stock SoftHSM2 2.7.0 rerun confirms signal 11
  in `artifacts/_focused/softhsm2-ffi-length-current-20260526/`. This is a
  provider crash finding: a malformed inner mechanism pointer should produce a
  CKR such as `CKR_ARGUMENTS_BAD` or `CKR_MECHANISM_PARAM_INVALID`, not terminate
  the process. The local `softhsm2-generated-iv` Docker target avoids this path
  with a simulator patch that returns `CKR_MECHANISM_PARAM_INVALID` when
  `pIv == NULL_PTR`; that patch is not stock SoftHSM2 evidence.
- **GCM null-AAD-pointer-with-nonzero-length SIGSEGV (NEW 2026-05-27)**:
  `test_parameter_validation.py::TestGcmAadNullWithLength::test_gcm_null_aad_pointer_nonzero_length`
  calls `C_EncryptInit(CKM_AES_GCM, pAAD=NULL, ulAADLen=16)` (NULL pointer with a
  non-zero AAD length) in a crash-isolated child. Stock SoftHSM2 2.7.0 (local
  `/usr/lib/softhsm/libsofthsm2.so`, 2026-05-27) terminates with **signal 11**;
  a NULL AAD pointer with non-zero length must yield a CKR (e.g.
  `CKR_ARGUMENTS_BAD`/`CKR_MECHANISM_PARAM_INVALID`), not segfault. **This finding
  was previously masked:** the probe assigned a raw ctypes array to the
  `CK_AES_GCM_PARAMS.pIv` pointer field, raising in the subprocess before
  `C_EncryptInit`, so it reported a uniform setup failure on every provider
  instead of the real crash. Fixed 2026-05-27 (cast `pIv` correctly; regression
  test `tests/test_parameter_validation_gcm_probe.py`). A full provider rerun is
  pending to record which other modules crash here.
- **Malformed huge data-length child exits (NEW 2026-05-26)**: the same focused
  `test_ffi_length_boundary.py` run reports positive child exit code 5, with no
  stdout/stderr, for `C_Sign(HMAC_SHA256)` and `C_Digest(SHA256)` when
  `ulDataLen` is `0x7fffffffffffffff` or `0x8000000000000000`. These are not
  signal crashes, but they are still abnormal subprocess failures from the
  malformed-boundary probes and should remain visible.
- **GCM huge-AAD-length child exit (NEW 2026-06-09)**:
  `test_ffi_length_boundary.py::TestGcmAadLengthBoundary::test_gcm_aad_length_boundary`
  calls `C_EncryptInit(CKM_AES_GCM)` with a valid 12-byte IV and a tiny real
  `pAAD` buffer but `ulAADLen` set to `0x7fffffffffffffff` / `0x8000000000000000`.
  Stock SoftHSM2 2.7.0 abnormally terminates the child (positive exit code 5, no
  stdout/stderr — dies inside `C_EncryptInit` before any return) instead of
  rejecting the impossible AAD length with a CKR. Kryoptic rejects cleanly (the
  probe passes there), confirming the test is sound. Same abnormal-exit class as
  the huge data-length `C_Sign`/`C_Digest` rows above; caller-controlled length →
  abnormal process termination. Reportable upstream.
- **CKA_TOKEN scalar-length validation missing on key generation (NEW 2026-06-08)**:
  `C_GenerateKey(CKM_AES_KEY_GEN)` and
  `C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN)` accept a `CKA_TOKEN` template
  attribute whose `pValue` points to `CK_ULONG` storage and whose `ulValueLen`
  is `sizeof(CK_ULONG)`, returning `CKR_OK` and creating keys. `CKA_TOKEN` is a
  `CK_BBOOL` attribute, so the malformed scalar length should be rejected with a
  template or attribute error. Detected by
  `test_ckr_keygen.py::TestGenerateKeyErrors::test_token_bool_overlong_length`
  and
  `test_ckr_keygen.py::TestGenerateKeyPairErrors::test_public_token_bool_overlong_length`
  /
  `test_ckr_keygen.py::TestGenerateKeyPairErrors::test_private_token_bool_overlong_length`.
  The same issue is also visible on EC P-256 public-key and private-key
  templates via
  `test_ckr_keygen.py::TestGenerateKeyPairErrors::test_ec_token_bool_overlong_length`.
- **Wrong asymmetric key type accepted by operation init (NEW 2026-06-08)**:
  `C_SignInit(CKM_ECDSA, RSA private key)` returns `CKR_OK` instead of rejecting
  the mismatched key/mechanism combination, then the subsequent `C_Sign` returns
  `CKR_GENERAL_ERROR`. `C_VerifyInit(CKM_ECDSA, RSA public key)` similarly
  returns `CKR_OK`, and the subsequent `C_Verify` returns
  `CKR_SIGNATURE_LEN_RANGE` for a fake ECDSA signature. This is a
  self-contradiction: once operation init accepts the key, the provider has
  claimed the operation is valid. Detected by
  `test_ckr_wrong_key_type_hardening.py::TestWrongAsymmetricKeyTypeContinuation`.
- **EC public-key import accepts an unknown curve OID (Type-A, NEW 2026-06-11)**:
  `C_CreateObject` of a `CKO_PUBLIC_KEY` / `CKK_EC` with
  `CKA_EC_PARAMS = 06 05 DE AD BE EF 00` (a syntactically-valid DER OBJECT
  IDENTIFIER that resolves to **no known curve**) and a bogus uncompressed point
  (`04 || 01×64`) returns **`CKR_OK`** instead of rejecting the unknown domain
  parameters. rv-trace: `C_CreateObject → CKR_OK`, `C_DestroyObject → CKR_OK`. A
  public key with no valid curve must be rejected with `CKR_CURVE_NOT_SUPPORTED`,
  `CKR_DOMAIN_PARAMS_INVALID`, `CKR_ATTRIBUTE_VALUE_INVALID`, or
  `CKR_TEMPLATE_INCONSISTENT`; accepting it admits an unverifiable/garbage key
  object into the store (CVE-2021-3798 missing-EC-curve-validation pattern), a
  crypto-correctness break. **softhsm2-specific:** in the fresh 2026-06-11 pool,
  softhsm2 and softhsm2-main are the **only** modules that accept it — kryoptic
  (all variants), NSS, opencryptoki, bouncyhsm, and tpm2 all reject (pass), and
  wolfpkcs11 / corepkcs11 reject with a non-spec clean code (xfail). Affects
  SoftHSM2 2.7.0 and main. Detected by:
  `test_cve_regression.py::TestInvalidECCurve::test_import_ec_key_with_bad_oid`.
  Reportable upstream.

### Known quirks
- `C_GetObjectSize` returns `CK_UNAVAILABLE_INFORMATION` (not implemented)
- `C_SeedRandom` succeeds silently (no-op, RNG is OpenSSL-based)
- v2.40 only — no `C_GetInterface`, no v3.0+ mechanisms
- Session objects visible across concurrent sessions (spec says they shouldn't be)

### Threading & concurrency — NOT a SoftHSM2 bug (harness methodology)
- **Concurrent `C_*` after `C_Initialize(NULL)` segfaults — but that is undefined behavior, not a module defect.** Per PKCS#11 v3.2 §5.4, passing `NULL` `pInitArgs` is the application *promising single-threaded use*; the library "need not perform any synchronization." pkcs11-check's shared-session fixtures initialize with `C_Initialize(None)`, so running `ThreadPoolExecutor` concurrency on the shared session (as the old `test_threading.py` did) is the *harness* breaking its own contract. Under that misuse SoftHSM2 crashes ~always: **32 threads × 200 `C_GenerateKey` = 6/6 (100%) SIGSEGV; 16 × 100 ≈ 88%; 4 threads ≈ 7% flaky** — the source of intermittent `crashed=1` for `test_threading.py` in the matrix.
- **Initialized correctly, SoftHSM2 is thread-safe.** The *same* concurrent workloads under `C_Initialize(CKF_OS_LOCKING_OK)` are rock-solid: **0/6 crashes at 32 × 200, 0/8 at 16 × 100.** So the finding is a harness bug (wrong init mode for the threading test), not a SoftHSM2 conformance violation.
- **Secondary effect:** a crash mid-`C_GenerateKey` corrupts the file-backed token (`CKR_TOKEN_NOT_RECOGNIZED` for every later test) — a poison-the-shared-token cascade. This is why the threading test isolates its token (below).
- **The misuse is documented here, not exercised as a test.** We do NOT add a test that deliberately mis-initializes (`C_Initialize(NULL)` + threads) to provoke the crash — provoking documented undefined behavior is not a conformance finding. The only threading test, `test_threading.py::TestConcurrentUnderOSLocking`, always initializes with `CKF_OS_LOCKING_OK` and then hammers concurrent keygen/digest/random in a child subprocess against a disposable throwaway token ([destructive-token-isolation.md](destructive-token-isolation.md), Tier 1). A crash or hang there *is* a genuine module thread-safety FAIL; `CKR_CANT_LOCK` skips (capability absent). SoftHSM2 passes.

---

## Kryoptic 1.5.0 (v3.2)

**Status: 21,503 passed, 0 failed, 7,687 skipped, 377 xfailed**

### xfail breakdown
- Primarily RSA-OAEP with non-SHA1 hash/MGF and AES edge cases
- DH parameter generation not supported (skips, not xfails)

### Known bugs
- **CKR_DEVICE_ERROR on verify failure**: `C_Verify` returns `CKR_DEVICE_ERROR` (0x30) instead of `CKR_SIGNATURE_INVALID` (0xC0) when signature verification fails. Affects ALL mechanisms (RSA, ECDSA, ML-DSA, SLH-DSA). SoftHSM2 correctly returns `CKR_SIGNATURE_INVALID`. This is a Kryoptic bug — PKCS#11 spec requires `CKR_SIGNATURE_INVALID`.
- **EDDSA accepts invalid signatures (ACVP SigVer)**: `C_Verify` with `CKM_EDDSA` accepts NIST ACVP `testPassed=False` vectors for Ed25519 (Ed448 is skipped). 4/4 tested invalid Ed25519 vectors return `CKR_OK` instead of `CKR_SIGNATURE_INVALID`. Detected by: `test_acvp_eddsa_sigver`.
- **SLH_DSA accepts invalid signatures (ACVP SigVer)**: `C_Verify` with `CKM_SLH_DSA` accepts NIST ACVP `testPassed=False` vectors for SLH-DSA-SHA2-128f and SLH-DSA-SHA2-192f. 15/15 tested invalid vectors return `CKR_OK`. Detected by: `test_acvp_slhdsa` (`test_slhdsa_sigver`).
- **ML-DSA sign seed mismatch**: Wycheproof `mldsa_*_sign_seed_test.json` vectors use a 32-byte private seed to derive full ML-DSA keys. Kryoptic does not support seed-based key derivation via `CKA_VALUE` import, so derived signatures differ from expected. 173+ vectors affected. Detected by: `test_wycheproof_mldsa_sign.py`.
- **C_SessionCancel crash via function list**: Calling `C_SessionCancel` through the `CK_FUNCTION_LIST_3_0` function pointer table causes a crash (segfault or hang). The function is listed in the v3.0+ function list but does not work when invoked via ctypes `get_func()` on the function list pointer. Calling it through the python-pkcs11 wrapper (which may use a different invocation path) may behave differently. Detected by: `test_v30_session.py`. Workaround: xfail the direct function-list call test.
- **AttributeValueInvalid on v3.0+ cert attributes**: Creating `CKO_CERTIFICATE` objects with standard v3.0+ attributes (`CKA_PUBLIC_KEY_INFO`, `CKA_SKID`, `CKA_AKID`) returns `CKR_ATTRIBUTE_VALUE_INVALID` (0x13). This persists even when the attribute values are correct SPKI or OctetStrings. Reverting to v2.40 interface or removing these attributes fixes the import.
- **C_SetPIN with NULL new-PIN pointer mutates/corrupts the user PIN (NEW 2026-05-27)**: `C_SetPIN(hSession, pOldPin="1234" (the valid user PIN), ulOldLen=4, pNewPin=NULL, ulNewLen=8)` does **not** reject the malformed NULL `pNewPin` (nonzero length). Per PKCS#11 a NULL pointer with nonzero length must yield `CKR_ARGUMENTS_BAD`; instead Kryoptic accepts the valid old PIN and proceeds, leaving the stored user PIN no longer equal to `1234`. Every subsequent `C_Login(CKU_USER, "1234")` then returns `CKR_PIN_INCORRECT`, and after ~8 attempts Kryoptic's retry counter trips `CKR_PIN_LOCKED`, permanently bricking the shared token for the rest of the run. SoftHSM2 does **not** exhibit this (`PIN_LOCKED=0` on the same suite — it rejects the NULL new PIN safely). Reproduces identically on both Kryoptic v1.5.0 (release) and `kryoptic-main`. Detected by: `test_ffi_null_pointer.py::TestNullPinBuffer::test_set_pin_null_new_pin` (now `@destructive`). Evidence: the lockout cascade begins in `[60/267]` immediately after `TestNullPinBuffer`, and the only `C_SetPIN` call supplying the correct old PIN is the NULL-new-PIN one; the call only began reaching the module after commit `1406e01` corrected the old-PIN ctypes cast (`c_void_p` → `CK_UTF8CHAR_PTR`) — before that the call raised a Python `ArgumentError` and never executed. Recommended confirmation: a focused single-call repro capturing the `C_SetPIN` return value (CKR_OK = silent corruption vs error-with-mutation) against a throwaway token. Reportable upstream.
- **C_CreateObject accepts malformed CKA_ALLOWED_MECHANISMS pointer (NEW 2026-06-08)**:
  `C_CreateObject` for an AES secret key accepts a template where
  `CKA_ALLOWED_MECHANISMS.pValue == NULL_PTR` while `ulValueLen` is nonzero,
  returning `CKR_OK` and creating the key. Input templates are not
  `C_GetAttributeValue` size queries; a NULL value pointer with a nonzero
  length must be rejected cleanly. Detected by
  `test_ckr_object.py::TestCreateObjectErrors::test_allowed_mechanisms_null_pointer_nonzero_length`.
- **Type-A — C_UnwrapKey(CKM_AES_KEY_WRAP) accepts an empty / non-multiple-of-8 wrapped blob (NEW
  2026-06-11)**: `C_UnwrapKey` with `CKM_AES_KEY_WRAP` and a **zero-length** (`b""`) wrapped blob
  returns `CKR_OK` and creates a key object (rv-trace: `C_CreateObject→CKR_OK`,
  `C_UnwrapKey→CKR_OK`). RFC 3394 AES-KW requires the wrapped data to be a multiple of 64 bits with a
  minimum of two semiblocks (16 bytes); an empty (and any non-multiple-of-8) ciphertext is malformed
  and MUST be rejected (`CKR_WRAPPED_KEY_LEN_RANGE` / `CKR_DATA_LEN_RANGE`). Accepting it unwraps a
  garbage/zero key into the store as if recovered — a crypto-correctness break (Type-A). 27 Wycheproof
  `aes_wrap_test.json` `WrongDataSize`/`InvalidWrappingSize` vectors (tc14–22, 56–64, 111–119 across
  AES-128/192/256, each with empty `ct`) are accepted. **kryoptic-specific**: all three variants
  (v1.5.0 / kryoptic-main / kryoptic-fips) return `CKR_OK`; softhsm2 (both), nss (all), opencryptoki
  (both), wolfpkcs11 (both) all reject (bouncyhsm/tpm2/corepkcs11 don't advertise the mechanism).
  Detected by: `test_wycheproof_aes.py::test_aes_key_wrap`. Classified Type-A per
  [classification-model-design.md](classification-model-design.md) (negative op: `CKR_OK` on a
  must-reject malformed input + crypto-correctness break → `fail`). Reportable upstream. Full
  determination: [findings/issues-triage.md](findings/issues-triage.md) (kryoptic 2026-06-11 section).

### Known quirks
- v3.2 interface — supports `C_GetInterface`, PQC mechanisms
- `C_GetObjectSize` works correctly
- No P-224 EC curve support
- AES-GCM parameter format differs from some other modules
- **Automatic v3.0+ Attribute Extraction**: Kryoptic automatically extracts `CKA_SUBJECT`, `CKA_ISSUER`, and `CKA_SERIAL_NUMBER` from `CKA_VALUE` during `C_CreateObject`, even when they are not provided in the template. This is highly compliant but conflicts with modules that require explicit population.

---

## NSS 3.120.1 (v3.0)

**Status: 20,723 passed, 362 failed, 8,147 skipped, 335 xfailed**

### Known bugs (2026-06-09)
- **Output-buffer overrun: ignores the caller-declared `*pulCount`/`*pulBufLen`**: with a
  deliberately small declared output buffer, NSS softoken writes the FULL result past the
  declared boundary instead of returning `CKR_BUFFER_TOO_SMALL`. Probed via guard bytes over an
  over-allocation: `C_GetSlotList` (declared 1 entry, NSS found 2 → **8 guard bytes overwritten**),
  `C_GetMechanismList`, `C_GetAttributeValue`, `C_WrapKey`, and `C_Decrypt`/`C_DecryptFinal`
  AES-CBC-PAD. PKCS#11 §5.x two-call convention requires `CKR_BUFFER_TOO_SMALL` + setting the
  required length WITHOUT writing. A real 1-entry caller buffer would be overflowed. Detected by:
  `test_ckr_raw_buffer.py` (6 F on nss, fresh). Contrast `C_Digest`, where NSS returns `CKR_OK`
  but writes **0** bytes past the boundary — a benign return-code deviation (xfail), not an
  overflow; the probe now distinguishes the two via the guard-byte count.

- **Type-A — ML-DSA verify accepts over-long (non-fixed-length) signatures and public keys**: NSS
  softoken `C_Verify(CKM_ML_DSA, …)` returns `CKR_OK` on a signature that is **+1 byte longer** than
  the FIPS-204 fixed length, and `C_CreateObject`/import **accepts a public key +1 byte over** the
  fixed length and then verifies against it as valid. FIPS-204 (Alg. 3 ML-DSA.Verify via
  `sigDecode`/`pkDecode`) operates only on byte strings of the fixed length — pk =
  1312/1952/2592, sig = 2420/3309/4627 for ML-DSA-44/65/87 — so any other length is malformed and
  MUST be rejected (`CKR_SIGNATURE_LEN_RANGE`/`CKR_SIGNATURE_INVALID`, or key-import rejection).
  Accepting the over-long encoding is a **non-malleability break**: appending a trailing byte to a
  valid signature still validates. 8/8 Wycheproof verify vectors flagged `IncorrectSignatureLength`
  (6: `mldsa_{44,65,87}_verify` tc7 "long signature" + tc144/tc157/tc170 "one trailing zero byte")
  and `IncorrectPublicKeyLength` (2: tc65/tc70 "long public key") — all `result: invalid`,
  `bugType: BASIC` — are accepted. NSS is otherwise correct on this file: it rejects 380/388 invalid
  vectors and accepts 227/227 valid ones, so this is a specific fixed-length-malformation gap (NSS
  ignores trailing bytes past the spec length), not a blanket verify-always-true bug. Affects the
  base `nss` variant (advertises + operates `CKM_ML_DSA`); the `nss-pqc` variant does not advertise
  `CKM_ML_DSA` here and collection-skips the file. Stable and pre-existing (identical 8 across three
  pool snapshots), independent of the ML-DSA ctx-skip/malformed-key fixes. Detected by:
  `test_wycheproof_mldsa.py::test_mldsa_verify`. Classified Type-A per
  [classification-model-design.md](classification-model-design.md) (negative op: `CKR_OK` on a
  must-reject malformed input + crypto-correctness break → `fail`). Reportable upstream. Full
  determination: [findings/issues-triage.md](findings/issues-triage.md) (2026-06-11 section).

### Failure breakdown (362 total)
| Count | Area | Reason |
|-------|------|--------|
| 296 | DSA Wycheproof | Historical pkcs11-check loader issue, not an NSS finding. Follow-up found that DER DSA signatures were passed directly to `C_Verify` and then converted with the encoded length of `q`, including leading zero bytes. The loader now converts DER signatures to fixed-width PKCS#11/P1363 form; focused NSS validation passes this file. Full matrix counts still need rerun. |
| 8 | ML-DSA verify (Type-A) | NSS accepts over-long (+1 byte) ML-DSA signatures and public keys as valid — FIPS-204 fixed-length violation (non-malleability break). See the Type-A entry above. |
| ~16 | Session/access tests | NSS returns `CKR_USER_TYPE_INVALID` instead of `CKR_USER_ALREADY_LOGGED_IN` — PKCS#11 spec compliance deviation |
| ~16 | KEM/PQC | ML-KEM not supported in NSS 3.120.1 (expected skips, showing as errors) |
| ~2 | AES-XCBC-MAC | NSS returns CKR_KEY_TYPE_INCONSISTENT on verify despite CKA_VERIFY=True |
| ~27 | Other | AEAD, key flags, mechanism fuzz, etc. — per-file analysis needed |

### Slot architecture — digest/crypto coverage gap (not an NSS bug)

NSS softoken (`libsoftokn3.so`) exposes **two** slots with split responsibilities,
and the harness pins `PKCS11_CHECK_SLOT=1`, which silently omits the slot-0-only
mechanisms (standalone hashes, some bulk ciphers):

| slot index | slot_id | token / description | login | digest (SHA-1/224/256) | keys+certs |
|---|---|---|---|---|---|
| 0 | 1 | NSS Internal Cryptographic Services | none | **yes** (232 mechs) | session-only / imported |
| 1 | 2 | NSS User Private Key and Certificate Services | required | **no** (179 mechs) | persistent token objects |

Per the NSS PKCS#11 FAQ, slot 1 (Internal Crypto Services) "does not require login
and supports public key operations and all bulk ciphers and hashes ... no token
storage", while slot 2 (User Private Key and Certificate Services) "requires a
login ... can store Private Keys and Certs as token objects". So standalone
`C_Digest` (CKM_SHA*) is advertised only on slot index 0.

**Effect:** `test_operation_termination.py::test_c_digest_terminates_after_each_call`
(and any digest test) **skips** under the default slot-1 config because slot 1 does
not advertise SHA digest mechanisms — not because NSS lacks them. Running the same
test with `PKCS11_CHECK_SLOT=0` makes NSS digest **pass** (verified: RSA+ECDSA+digest
all pass on slot 0). Slot 1 remains the right slot for persistent
key/cert/token-object tests. Source:
<https://nss-crypto.org/reference/security/nss/legacy/pkcs11/faq/index.html>.

**Coverage:** each NSS target now has a dedicated slot-0 second pass —
`test-nss-slot0`, `test-nss-pqc-slot0`, `test-nss-main-slot0` (same images with
`PKCS11_CHECK_SLOT=0`, separate artifact dirs). `test_pool.py` runs `nss-slot0` /
`nss-pqc-slot0` in the default set and `nss-main-slot0` under `--all`, so NSS's
slot-0-only mechanisms (digest, hashes, bulk ciphers) are exercised alongside the
slot-1 key/cert pass.

### Multipart `C_EncryptFinal` does not terminate the operation (slot 0)

Surfaced by the slot-0 pass + `test_operation_termination.py::test_c_encrypt_terminates_after_multipart`:
after a multipart encrypt (`C_EncryptInit`+`C_EncryptUpdate`+`C_EncryptFinal`) that
returns `CKR_OK`, NSS leaves the encryption operation **active** — the next
`C_EncryptInit` returns `CKR_OPERATION_ACTIVE`. The spec says "a call to
`C_EncryptFinal` always terminates the active encryption operation unless it
returns `CKR_BUFFER_TOO_SMALL`". This affects **~15 symmetric mechanisms**
(AES-CBC/CTR/CTS/ECB, DES/DES3, Camellia, CDMF, ChaCha20, RC2, RC4) on NSS
3.120.1 / nss-pqc / nss-main; compliant modules (softhsm2, opencryptoki) pass all,
kryoptic fails 1.

This is the same Type-C lifecycle class as the `C_Verify` non-termination, on the
encrypt path. On the **shared** module-scoped session the recovery
(`_init_or_recover`) masked it to one collateral failure (`DES3_CBC`, see
[provider-verify-operation-not-terminated.md](findings/provider-verify-operation-not-terminated.md));
the **fresh-session** conformance test exposes the full scope. NSS does expose
`C_SessionCancel` (it usually clears the stale op, which is why the shared-session
cascade stays bounded), but `C_EncryptFinal` itself not terminating is the bug.

### Known crash findings
- **AES-MAC-GENERAL sign flag probe segfault**: focused current-source runs for
  Fedora NSS, `nss-pqc` (`NSS_3_124_RTM`/`NSPR_4_39_RTM`), and `nss-main` all
  crash in
  `test_mech_flags.py::TestMechFlagBehavioralConformance::test_sign_flag_callable[AES_MAC_GENERAL]`.
  pkcs11-check calls `C_SignInit(CKM_AES_MAC_GENERAL, key=0)` because NSS
  advertises `CKF_SIGN`. The expected outcome is any suitable CKR rejecting the
  dummy key or mechanism parameters, not a segfault.
- **MAC mechanism with RSA key segfault (root cause confirmed 2026-05-27)**: focused
  current-source runs for `nss-pqc` and `nss-main` crash in
  `test_mech_negative.py::TestWrongKeyType::test_hmac_sha256_with_rsa_key_rejected`.
  The test calls `C_SignInit(CKM_SHA256_HMAC, RSA private key)`; the provider should
  return `CKR_KEY_TYPE_INCONSISTENT` (as `C_SignInit(CKM_ECDSA, RSA)` already does),
  not crash.
  **Upstream root cause (NSS softoken):** `NSC_SignInit`/`NSC_VerifyInit` do not
  validate key type before dispatching to the MAC path (RSA/ECDSA sign paths do, at
  `pkcs11c.c:3023,4059`, but the HMAC/AES-CMAC branches dispatch straight into
  `sftk_doMACInit`). `sftk_MAC_Create` allocates `sftk_MACCtx` with `PORT_New`
  (uninitialized) in `sftkhmac.c:228`; MAC init fails for an RSA key (no `CKA_VALUE`),
  and the error path `sftk_MAC_DestroyContext` dereferences the uninitialized
  `destroy_func` → jumps to a garbage address. **Heap-state dependent:** if the
  allocation lands on zero-filled memory, `destroy_func` is NULL and it returns
  `CKR_KEY_SIZE_RANGE` (0x62, still wrong) instead of crashing — which is why the
  Fedora `nss` package variant does not always crash on this file.
  **Also affects:** `C_VerifyInit(CKM_SHA256_HMAC, RSA pub)` and
  `C_SignInit(CKM_AES_CMAC, RSA priv)` (same MAC dispatch). Suggested upstream fix:
  (1) key-type validation in `NSC_SignInit`/`NSC_VerifyInit` before MAC dispatch;
  (2) `PORT_ZNew(sftk_MACCtx)` instead of `PORT_New` in `sftkhmac.c:228`. An ~80-line
  ctypes reproducer (heap-warm + `C_SignInit(0x251, RSA)`) reproduces reliably.
  **Status:** reported upstream and acknowledged, but assessed as **not
  security-important** — outside the NSS softoken threat model, since the wrong-key-type
  MAC path is not reachable through Firefox (a malicious local PKCS#11 caller is out of
  scope). Not prioritized upstream; retained here as a documented robustness finding.
  pkcs11-check keeps the existing `C_SignInit(CKM_SHA256_HMAC, RSA)` probe as the
  representative case; `C_VerifyInit` and `CKM_AES_CMAC` are the same `sftk_doMACInit`
  dispatch family and are not separately tested (low value for a declined finding).

### Known quirks
- **Read-only crypto services token**: NSS's default slot ("NSS Generic Crypto Services") is read-only. Cannot create objects, generate keys, or store tokens. Tests requiring RW access should skip.
- **No PIN/login on crypto services slot**: The default slot does not support `C_Login` — returns `CKR_USER_TYPE_INVALID` when login is attempted. This is correct behavior for a public token that doesn't have login semantics.
- **Two slots**: NSS exposes 2 slots. Slot 0 is the crypto services slot (read-only), slot 1 may be an NSS internal database slot.
- **Needs configDir for full functionality**: `libsoftokn3.so` must be loaded with `configDir='sql:/path/to/db'` NSS init args to access the writable database slot. Without this, only the read-only crypto services slot is available. Use the NSS setup in `local-builds/providers/nss-softokn.sh` or the NSS Docker targets as reference configurations.
- **RSA keypair requires CKA_PUBLIC_EXPONENT**: NSS requires `CKA_PUBLIC_EXPONENT` in the public key template for `CKM_RSA_PKCS_KEY_PAIR_GEN`. Kryoptic and SoftHSM2 are more lenient and accept the default (65537). The recipe now includes this attribute for cross-module compatibility.
- **CKM_RSA_X_509 unwrap takes the wrong end of the raw RSA block**: For raw RSA unwrap,
  PKCS#11 requires the key bytes to be taken from the trailing end of the decrypted modulus-sized
  block. NSS softoken instead appears to derive the unwrapped key from the leading bytes, which
  yields the wrong AES key value and breaks roundtrip decrypt in `test_mech_wrap.py`.
- **EdDSA sign/verify rejects CK_EDDSA_PARAMS**: NSS softoken returns `CKR_MECHANISM_PARAM_INVALID`
  when `CK_EDDSA_PARAMS` is provided for `CKM_EDDSA`. NSS requires NULL mechanism params for pure
  EdDSA, contrary to PKCS#11 v3.0 which mandates explicit `CK_EDDSA_PARAMS`. Tests in
  `test_eddsa.py` xfail with a descriptive message on both NSS 3.120.1 and NSS-PQC 3.121.0.
- **AES-XCBC-MAC verification**: NSS returns `CKR_KEY_TYPE_INCONSISTENT` on verify operations even with `CKA_VERIFY=True` key attribute. XCBC-MAC sign works but verify fails. This is an NSS softoken quirk.
- **AES-KEY-WRAP unwrap into a generic secret requires `CKA_VALUE_LEN`**: unwrapping with
  `CKM_AES_KEY_WRAP` into a `CKK_GENERIC_SECRET` is rejected with `CKR_TEMPLATE_INCONSISTENT`
  unless the recovered length is stated explicitly. softhsm2/opencryptoki instead *reject*
  `CKA_VALUE_LEN` here as `CKR_ATTRIBUTE_READ_ONLY` (they derive the length from the blob), so
  there is no single template that satisfies every module. `test_wycheproof_aes.py` now unwraps
  adaptively: it tries the minimal template first and, only on a template-shape reject for a
  **valid** vector, retries once with `CKA_VALUE_LEN`. The retry is never applied to invalid
  (forged) vectors, so a too-short/empty wrapped blob is still rejected on its own merits. NSS
  still refuses the oversized 384-byte `CounterOverflow` vectors (a clean operational deviation,
  recorded as xfail; softhsm2 and kryoptic unwrap them).
- **NULL-buffer size probe does not set output length (AES-GCM / AES-KEY-WRAP-KWP)**:
  NSS softoken returns `CKR_OK` from the standard PKCS#11 size-query call
  (output buffer `NULL`, `*pulLen=0`) but does not write the required size
  to `*pulLen`. The follow-up call with the allocated buffer then either
  fails or under-reports size; some mechanisms (KWP) also consume operation
  state on the NULL pass, making retry impossible. Worked around in the
  recipes via the ``output_size_hint`` parameter on ``encrypt_single``,
  ``decrypt_single``, ``sign_single``, ``wrap_key``, and
  ``wrap_key_authenticated`` — callers supply the expected output length
  and the recipes skip the NULL probe entirely. Affected paths in this
  project: ``test_aead.py`` (AEAD), ``test_aead_wrap_outputs.py`` (wrap).

---

## NSS-PQC (3.121.0)

**Library:** `libsoftokn3.so` (NSS 3.121.0 with PQC support)
**Interface version:** v3.0
**Docker target:** `test-nss-pqc`
**Baseline (2026-03-27):** 35,292 passed / 415 failed / 31,947 skipped / 598 xfailed (68,252 total)
**Post-fix (Phases 1-11):** 35,327 passed / 296 failed / 31,984 skipped / 645 xfailed (68,252 total)

Inherits all quirks from NSS 3.120.1 above. Additional findings below.

### Improvements over NSS 3.120.1

- 203 fewer failures (415 vs 618) — RSA operations significantly improved
- PQC mechanisms available: CKM_ML_KEM (encapsulate/decapsulate), ML-KEM key generation
- ML-DSA/SLH-DSA mechanisms NOT yet supported (all tests skip)

### PQC Issues

- **ML-KEM buffer sizing:** C_EncapsulateKey/C_DecapsulateKey return CKR_BUFFER_TOO_SMALL on the NULL-buffer size query — valid two-call PKCS#11 behavior, handled by the recipes.
- **ML-KEM-512 raw private-key import:** rejected with `CKR_ATTRIBUTE_VALUE_INVALID`. The Wycheproof "semi_expanded" vectors carry only the decapsulation key `dk` (the *full* FIPS 203 form — **not** a seed, despite the old note here); PKCS#11 v3.2 (ML-KEM private key) permits a token to require both `CKA_SEED` and `CKA_VALUE`, so a dk-only import rejection is a **spec-permitted operational deviation → xfail**, not a failure. 768/1024 import and decapsulate fine.

### Security Findings

> **NSS softokn is a software-only PKCS#11 token.** Severities below use
> pkcs11-check's hardware-token threat model — they describe what each behavior
> would mean if NSS softokn claimed to be a hardware secure element resistant
> to key extraction. Upstream does not aim to enforce that boundary in softokn,
> so the CRITICAL / HIGH attribute-enforcement rows are upstream-known
> properties of the software-token design rather than defects to be fixed.
> They are recorded here so the same checks reuse against any module that
> does claim the harder boundary.

**CRITICAL: Sensitive key material readable (CKR_OK instead of CKR_ATTRIBUTE_SENSITIVE)**

- `CKA_VALUE` readable on `CKA_SENSITIVE=True` AES keys via `C_GetAttributeValue`
- `CKA_PRIVATE_EXPONENT` readable on `CKA_SENSITIVE=True` RSA private keys
- NSS softoken returns `CKR_OK` and fills the attribute buffer instead of `CKR_ATTRIBUTE_SENSITIVE`
- Ref: PKCS#11 v3.1 Sec.4.9.2: "sensitive attributes cannot be revealed in plaintext"
- Affected tests: `test_sensitivity.py::TestSensitiveKeyValue::test_sensitive_aes_value_not_readable`,
  `test_sensitivity.py::TestSensitiveKeyValue::test_sensitive_rsa_private_exponent_not_readable`
- Impact: Private key material and symmetric key values extractable despite `CKA_SENSITIVE=True`

**CRITICAL: CKA_EXTRACTABLE escalation via C_CopyObject (Tookan vulnerability)**

- `C_CopyObject` allows changing `CKA_EXTRACTABLE` from `False` to `True` on a copy
- OASIS PKCS#11 spec explicitly states this MUST NOT be permitted (only `True`→`False` allowed)
- Confirmed by both `test_tookan.py` and `test_api_security.py`
- Ref: PKCS#11 v3.1 Sec.4.9.4; Bortolozzo et al. "Attacking and Fixing PKCS#11 Security Tokens"
  (CCS 2010); Tookan paper (CCS 2020)
- Affected tests: `test_tookan.py::TestSensitivePreservation::test_extractable_cannot_escalate_on_copy`,
  `test_api_security.py::TestAttributeLaunderingViaCopy::test_copy_cannot_escalate_extractable`
- Impact: Non-extractable keys can be copied as extractable, bypassing key protection policy

**HIGH: Wrap-decrypt oracle possible (CKA_WRAP + CKA_DECRYPT on same key)**

- NSS allows creating a key with both `CKA_WRAP=True` and `CKA_DECRYPT=True`
- This enables the classic wrap-then-decrypt attack: wrap a target key under the dual-purpose key,
  then decrypt the wrapped blob to recover raw key material
- Ref: PKCS#11 v3.1 Sec.4.9.4: "for secret keys, at most one of CKA_WRAP/CKA_ENCRYPT";
  Clulow "On the Security of PKCS#11" (CHES 2003)
- Affected test: `test_api_security.py::TestWrapDecryptOracle::test_wrap_decrypt_combination_prevented`
- Impact: Enables wrap-then-decrypt attack to extract key material from the token

**HIGH: Non-extractable key is wrappable (CKA_EXTRACTABLE=False bypass)**

- `C_WrapKey` succeeds on a key that reads back `CKA_EXTRACTABLE=False`, so key
  material leaves the token despite the non-extractable flag (Type-B).
- Ref: PKCS#11 C_WrapKey / CKA_EXTRACTABLE; expected `CKR_KEY_NOT_WRAPPABLE`.
- Affected test: `test_rsa_key_wrapping.py::TestWrappedKeyUsability::test_non_extractable_key_cannot_be_wrapped`
- Note: this test previously xfailed the violation; it now fails it (consistent
  with the sensitive-value / Tookan security tests). Verified failing on the NSS
  softokn Docker targets; compliant software tokens (e.g. softhsm2) pass.

**HIGH: CKA_WRAP_WITH_TRUSTED not enforced**

- A key that reads back `CKA_WRAP_WITH_TRUSTED=True` is still wrapped by an
  untrusted (non-`CKA_TRUSTED`) wrapping key (Type-B). Expected
  `CKR_KEY_NOT_WRAPPABLE`.
- Affected test: `test_access_levels.py::TestTrustedAttribute::test_wrap_with_trusted_rejects_untrusted`
- Note: previously xfail-hidden; now fails. Verified on the NSS softokn Docker
  targets; softhsm2 enforces it and passes.

**HIGH: ML-KEM permission flags not enforced (CKA_ENCAPSULATE / CKA_DECAPSULATE)**

- A v3.2 ML-KEM keypair created with `CKA_ENCAPSULATE=False` (public key) or
  `CKA_DECAPSULATE=False` (private key) still completes `C_EncapsulateKey` /
  `C_DecapsulateKey` — the key reads the flag back as `False` and the module
  performs the operation anyway (Type-B self-contradiction).
- Ref: PKCS#11 v3.2 Sec.5.14.7 / Sec.5.14.8 require `CKR_KEY_FUNCTION_NOT_PERMITTED`
  when the corresponding flag is `False`.
- Affected tests: `test_kem.py::TestMLKEMNegative::test_encapsulate_missing_permission_flag`,
  `test_kem.py::TestMLKEMNegative::test_decapsulate_missing_permission_flag`
- Note: the encapsulate case was previously masked — the test only did a
  `pCiphertext=NULL` size query, which this module answers with
  `CKR_BUFFER_TOO_SMALL` before reaching the permission check, and the old
  assertion tolerated `CKR_OK`. The test now drives the full operation, so the
  flag is actually exercised (kryoptic enforces it and passes; this module does
  not and fails as a finding).
- Impact: KEM key-usage policy not enforced; a key marked encapsulate/decapsulate-disabled can still be used.

**MEDIUM: RSA-OAEP padding oracle (non-uniform error codes)**

- Different CKR codes returned for different invalid OAEP ciphertexts
  (observed: `CKR_ARGUMENTS_BAD` and `CKR_ENCRYPTED_DATA_INVALID` mixed)
- A uniform error code (`CKR_ENCRYPTED_DATA_INVALID`) must be returned for all decryption failures
  to prevent information leakage about ciphertext structure
- Ref: Manger "A Chosen Ciphertext Attack on RSA Optimal Asymmetric Encryption Padding" (CRYPTO 2001);
  PKCS#11 v3.1 Sec.6.1.8
- Affected test: `test_padding_oracle.py::TestRSAPaddingOracle::test_oaep_error_uniformity`
- Impact: Potential plaintext recovery via error oracle (~O(log n) queries for 2048-bit RSA)

**CORRECTION (2026-06-08): "C_VerifySignatureInit accepts mismatched key" is NOT a finding**

- Earlier triage rows (Group 9 / xfail tables below) recorded a suspected NSS
  security bug where `C_VerifySignatureInit` returns `CKR_OK` for a signature
  created with a different key. This was a TEST ARTIFACT: in PKCS#11 v3.2 the
  verification verdict is produced by `C_VerifySignature`, not by
  `C_VerifySignatureInit` (for same-size RSA keys the signature length matches
  the modulus, so the mismatch is only detectable once the data is supplied).
  The corrected `test_verify_signature.py::test_verify_signature_wrong_key`
  drives the operation through `C_VerifySignature` and confirms NSS softokn
  correctly **rejects** the forgery (test passes on nss-pqc). No NSS security
  bug here. Kryoptic rejects with a non-clean code (honest xfail).

### Spec Deviations

Findings from Phases 2-3 investigation and ongoing testing. All references are to PKCS#11 v3.1
unless noted.

#### Key Attribute Defaults (Phase 2)

- **CKA_PRIVATE defaults to False for secret and private keys**: PKCS#11 v3.1 Sec.4.7 Table 4
  specifies `CKA_PRIVATE` defaults to `CK_TRUE` for private and secret key objects. NSS softoken
  generates AES secret keys and RSA private keys with `CKA_PRIVATE=False` unless explicitly set.
  Affected tests in `test_attributes.py` are marked `xfail` (2 secret-key tests + 2 RSA private-key
  tests). Impact: private key objects accessible in read-only sessions without prior login.

- **CKA_LOCAL not set on generated keys**: PKCS#11 v3.1 Sec.4.7 requires `CKA_LOCAL=True` for
  keys whose raw material was generated on the token (via `C_GenerateKey`/`C_GenerateKeyPair`).
  NSS softoken returns `CKA_LOCAL=False` for all generated AES, RSA public, and RSA private keys.
  Affected: 3 xfails in `test_attributes.py` (one per key class). Ref: Sec.10.7 (secret keys),
  Sec.10.1 (RSA keys).

- **CKA_EXTRACTABLE defaults to True for RSA private keys**: PKCS#11 v3.1 Sec.10.1 recommends
  `CKA_EXTRACTABLE` default `CK_FALSE` for private keys to prevent inadvertent export. NSS softoken
  defaults to `CKA_EXTRACTABLE=True`. Affected: 1 xfail in `test_attributes.py`.

- **CKA_NEVER_EXTRACTABLE inconsistent**: When `CKA_EXTRACTABLE` is explicitly set to `True` at
  creation, `CKA_NEVER_EXTRACTABLE` must be `False` (Sec.4.9.4). NSS softoken behavior is
  inconsistent with this rule in combination with the default-extractable deviation above.
  The *derived-attribute invariant* of Sec.4.9.4 — a key created `CKA_EXTRACTABLE=False` and never
  modified must read back `CKA_NEVER_EXTRACTABLE=True`, and a key created `CKA_SENSITIVE=True` and
  never modified must read back `CKA_ALWAYS_SENSITIVE=True` — is now enforced as a Type-D
  self-contradiction in `test_attribute_invariants.py`: violating it on a suite-generated,
  never-modified key is a `fail` (the module contradicts its own derived value), while an
  unsupported/absent derived attribute remains an `xfail` (honest non-support).

#### Missing/Unsupported Attributes (Phase 2)

- **CKA_COPYABLE not enforced**: Setting `CKA_COPYABLE=False` at key creation should prevent
  `C_CopyObject` from succeeding. NSS softoken ignores this attribute — `C_CopyObject` succeeds
  on non-copyable objects. Ref: PKCS#11 v3.1 Sec.4.9.1. Affected: 1 xfail in `test_attributes.py`.

- **CKA_DESTROYABLE not enforced**: Setting `CKA_DESTROYABLE=False` should cause `C_DestroyObject`
  to return `CKR_ACTION_PROHIBITED`. NSS softoken ignores this attribute. Ref: Sec.4.9.1. Affected:
  1 xfail in `test_attributes.py`.

- **CKA_KEY_GEN_MECHANISM not supported**: NSS softoken does not set `CKA_KEY_GEN_MECHANISM` on
  generated keys (returns `CKR_ATTRIBUTE_TYPE_INVALID`). PKCS#11 v3.1 Sec.10.7 lists this as a
  required attribute for secret keys. Covered by attribute-default tests.

- **CKA_ALWAYS_AUTHENTICATE not supported**: NSS softoken does not implement the
  `CKA_ALWAYS_AUTHENTICATE` attribute (Sec.4.7). Private key objects cannot require per-operation
  authentication. Tests that set this attribute skip.

#### Session and Login Behavior (Phase 3)

- **CKR_PIN_INCORRECT instead of CKR_USER_ALREADY_LOGGED_IN**: When a session is already logged
  in and `C_Login` is called again with a wrong PIN, NSS softoken returns `CKR_PIN_INCORRECT` rather
  than `CKR_USER_ALREADY_LOGGED_IN`. PKCS#11 v3.1 Sec.5.6 requires `CKR_USER_ALREADY_LOGGED_IN`
  when the token is already authenticated. This is the `CKR_USER_TYPE_INVALID` / `CKR_PIN_INCORRECT`
  quirk; handled in fixture login logic.

- **NSS auto-initializes after C_Finalize (CKR_OK instead of CKR_CRYPTOKI_NOT_INITIALIZED)**:
  Calling any PKCS#11 function after `C_Finalize` should return `CKR_CRYPTOKI_NOT_INITIALIZED`
  (Sec.5.4). NSS softoken instead auto-reinitializes the library transparently and returns `CKR_OK`.
  This is a vendor extension. Affected: 1 xfail in `test_attributes.py` / `test_api_state.py`.

- **C_CloseSession returns CKR_OK on already-closed session**: PKCS#11 v3.1 Sec.5.7 requires
  `CKR_SESSION_HANDLE_INVALID` when the handle is invalid (including already-closed sessions). NSS
  softoken returns `CKR_OK`. Covered by CKR tests.

- **CKR ordering — template checks before session-type checks**: NSS validates template
  completeness (`CKR_TEMPLATE_INCOMPLETE`) before checking whether the session is read-only
  (`CKR_SESSION_READ_ONLY`). For example, `C_GenerateKeyPair` in a RO session with an incomplete
  template returns `CKR_TEMPLATE_INCOMPLETE` rather than `CKR_SESSION_READ_ONLY`. The PKCS#11
  spec does not mandate a specific validation order; this is a documented NSS ordering quirk.
  Ref: Token Write-Protection section below.

#### Mechanism Parameter Handling (Phase 3)

- **NULL mechanism pointer returns CKR_MECHANISM_INVALID (not CKR_ARGUMENTS_BAD)**: PKCS#11 v3.1
  Sec.5.2 lists `CKR_ARGUMENTS_BAD` as the return when a required pointer argument is NULL.
  NSS softoken returns `CKR_MECHANISM_INVALID` when a NULL `CK_MECHANISM_PTR` is passed to
  `C_EncryptInit`, `C_SignInit`, etc. Both are acceptable per the spec's "may also return" clause;
  documented as NSS behavior in CKR raw-args tests.

#### Trust and Wrapping Policy (Phase 2)

- **CKA_WRAP_WITH_TRUSTED not enforced**: A key with `CKA_WRAP_WITH_TRUSTED=True` should only
  be wrappable by a key with `CKA_TRUSTED=True` (Sec.4.9.4). NSS softoken permits wrapping
  regardless of the wrapping key's trust status. Affected: 1 xfail in `test_api_security.py`
  (`TestWrapWithTrusted`).

#### EdDSA and DSA (Phases 2, 5)

- **EdDSA rejects CK_EDDSA_PARAMS (CKR_MECHANISM_PARAM_INVALID)**: NSS softoken returns
  `CKR_MECHANISM_PARAM_INVALID` when `CK_EDDSA_PARAMS` is provided for `CKM_EDDSA` sign/verify,
  even for pure-mode EdDSA with `phFlag=0` and no context data. PKCS#11 v3.0 Sec.2.3.13 mandates
  explicit `CK_EDDSA_PARAMS` for the `CKM_EDDSA` mechanism. NSS softoken instead requires NULL
  params (no mechanism parameter struct at all). This is a spec deviation — pure-mode EdDSA should
  accept explicit params with `phFlag=CK_FALSE` and empty context. Affected tests in
  `test_eddsa.py` are marked `xfail` (7 tests: all sign/verify tests in `TestEdDSASignVerify`
  and `TestEdDSACrossVerify`). This same deviation affects NSS 3.120.1 and NSS-PQC 3.121.0.

- **Historical DSA Wycheproof note superseded**: the old 296-failure NSS DSA
  entry was a pkcs11-check loader problem. Wycheproof's non-P1363 DSA vectors
  use DER signatures, but PKCS#11 DSA verification expects fixed-width raw
  `r || s`. The loader now converts valid DER signatures and strips leading
  zero encoding from `q` when calculating the raw component width. A focused
  NSS Docker run of `test_wycheproof_dsa.py` after the fix reported 1,055
  passed and 901 skipped with no failures. Treat the old DSA row as invalid
  article evidence until the full matrix is rerun.

### Token Write-Protection (Phase 1 findings)

NSS cert DB slot (slot 1) has `CKF_WRITE_PROTECTED` set in `CK_TOKEN_INFO.flags`.
This is normal NSS behavior — the certificate database slot does not support creating
arbitrary objects via `C_CreateObject`, `C_GenerateKey`, or `C_GenerateKeyPair` with
`CKA_TOKEN=True`.

- **CKR_TOKEN_WRITE_PROTECTED** returned for: `gen_aes_key(CKA_TOKEN=True)`,
  `gen_rsa_keypair(CKA_TOKEN=True)`, `C_DestroyObject` on token objects,
  `C_SetAttributeValue` on token objects, `C_CopyObject` to token objects,
  `C_UnwrapKey` with `CKA_TOKEN=True`
- **CKR_ATTRIBUTE_VALUE_INVALID** returned for: `C_CreateObject` with `CKO_DATA`
  and `CKA_TOKEN=True` (data objects not supported on cert DB slot)
- **CKR_ATTRIBUTE_VALUE_INVALID** also for: `CKO_DATA` with `CKA_PRIVATE=True`
  even on session objects — NSS does not support private data objects
- **CKR ordering:** NSS validates template completeness before checking session
  type — `C_GenerateKeyPair` in RO session with incomplete template returns
  `CKR_TEMPLATE_INCOMPLETE` instead of `CKR_SESSION_READ_ONLY`

Tests requiring token object creation skip with "Token is write-protected" on NSS.

### Known Limitations

- ML-DSA (FIPS 204) not supported — all ML-DSA tests skip
- SLH-DSA (FIPS 205) not supported — all SLH-DSA tests skip
- Same DSA Wycheproof rejections as NSS 3.120.1 (296 failures — see Spec Deviations)
- EdDSA CKR_MECHANISM_PARAM_INVALID: 7 sign/verify tests in `test_eddsa.py` now xfailed (see Spec Deviations)

### Xfail Triage (Phases 9-11) — 645 xfails categorized

This is a historical triage snapshot. Current follow-up found that the
AES-KWP row below was a pkcs11-check mechanism-selection bug, not an NSS
provider issue. The remaining non-stale xfails still represent NSS limitations
or spec deviations unless a focused rerun says otherwise.

#### xfail breakdown by root cause

| Count | % | Category | Root Cause | Files |
|------:|--:|----------|-----------|-------|
| 256 | 40% | ChaCha20-Poly1305 param mismatch | NSS softoken | `test_wycheproof_chacha.py` |
| 232 | 36% | HKDF output correctness | NSS softoken | `test_wycheproof_hkdf.py` |
| 77 | 12% | AES-KWP output format | stale pkcs11-check mechanism-selection bug | `test_wycheproof_aes.py` |
| 16 | 3% | IKE derive param invalid | NSS softoken | `test_ike.py` |
| 13 | 2% | Security policy violations | NSS softoken | various |
| 7 | 1% | EdDSA CK_EDDSA_PARAMS rejection | NSS spec deviation | `test_eddsa.py` |
| 7 | 1% | SP800-108 KDF param invalid | NSS softoken | `test_sp800_108_kdf.py` |
| 25 | 4% | Attribute/spec deviations | NSS softoken | various |
| 3 | 0% | HKDF_DATA CKR_TEMPLATE_INCONSISTENT | NSS softoken | `test_hkdf_extended.py` |
| 3 | 0% | Miscellaneous | mixed | 3 files |

---

#### Group 1: ChaCha20-Poly1305 Wycheproof (256 xfails)

**File:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_chacha.py`

**Root cause:** NSS softoken advertises `CKM_CHACHA20_POLY1305` but fails at `C_EncryptInit` for
all 256 valid Wycheproof vectors. The test uses the standard PKCS#11 v3.0
`CK_SALSA20_CHACHA20_POLY1305_PARAMS` struct (`pNonce`, `ulNonceLen`, `pAAD`, `ulAADLen`).
NSS softoken's internal ChaCha20-Poly1305 implementation uses a non-standard parameter format
(historically `CK_NSS_AEAD_PARAMS` with an additional `ulTagLen` field). All test vectors use
the correct 12-byte nonce and valid key sizes — the parameter struct mismatch is the only
consistent explanation for the uniform failure across all 256 valid vectors.

**Verdict:** NSS softoken spec deviation. The test correctly uses the PKCS#11 v3.0 standard
struct. Not a test bug.

**Status of xfail:** Legitimate. `C_EncryptInit` raises `AssertionError` (via `expect_rv`) when
NSS rejects the standard AEAD param, triggering `pytest.xfail`.

---

#### Group 2: HKDF Wycheproof (232 xfails)

**File:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_hkdf.py`

**Root cause:** NSS softoken advertises `CKM_HKDF_DERIVE` and correctly rejects the 107 invalid
Wycheproof vectors (those pass). However, all 232 valid vectors xfail. The derive operation
either fails outright or produces incorrect output that does not match the RFC 5869 expected OKM.
This is consistent across all four hash variants (SHA-1: 59, SHA-256: 59, SHA-384: 57,
SHA-512: 57).

Basic HKDF functionality works (7 tests pass in `test_kdf.py`) because those tests only check
output length, not value correctness. Wycheproof vectors test exact output, exposing an NSS HKDF
implementation bug: either `C_DeriveKey` returns a wrong-length key (causing `AssertionError` on
`okm == okm_expected`), or the IKM key import fails for the non-standard key material sizes used
in Wycheproof vectors (e.g., 11-byte or 22-byte IKM). The failure pattern is consistent across
all hash functions, suggesting a systematic issue in NSS's `CK_HKDF_PARAMS` processing.

**Verdict:** NSS softoken HKDF implementation limitation. Not a test bug.

**Status of xfail:** Legitimate. `AssertionError` or `TypeError` in derivation triggers `pytest.xfail`.

---

#### Group 3: AES-KWP Wycheproof (77 xfails)

**File:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py`

**Update 2026-05-26:** this old NSS finding is stale for current source. The
Wycheproof KWP test was using deprecated `CKM_AES_KEY_WRAP_PAD` with
`C_WrapKey`, while `aes_kwp_test.json` is an RFC 5649 raw-data KWP vector set.
The local OASIS spec tree says `CKM_AES_KEY_WRAP_KWP` is the RFC 5649 mechanism
and `CKM_AES_KEY_WRAP_PAD` is deprecated. Current source now uses
`CKM_AES_KEY_WRAP_KWP` with `C_Encrypt`; focused `nss` and `nss-pqc` reruns both
report 724 passed, 1,095 skipped, and 0 failed for the Wycheproof AES file.
Do not use the old 77-row KWP bucket as an NSS provider finding.

**Historical interpretation:** these rows were previously attributed to NSS
AES-KWP non-conformance because the output was longer, different, or rejected.
That conclusion was based on the wrong PKCS#11 mechanism. The rows are now
classified as stale harness evidence, not an NSS provider issue.

---

#### Group 4: IKE Derive Mechanisms (16 xfails)

**File:** `src/pkcs11_check/testcases/test_ike.py`

**Root cause:** NSS softoken advertises all four IKE derivation mechanisms
(`CKM_IKE2_PRF_PLUS_DERIVE`, `CKM_IKE_PRF_DERIVE`, `CKM_IKE1_PRF_DERIVE`,
`CKM_IKE1_EXTENDED_DERIVE`) but returns `CKR_MECHANISM_PARAM_INVALID` for all operational
parameter combinations. Four tests pass (mechanism availability and error-path tests); the
16 derivation operation tests all xfail.

The mechanisms are advertised in the `CK_MECHANISM_INFO` list but NSS softoken does not
implement the full IKE key derivation operations — it rejects the `CK_PRF_DATA_PARAMS` or
mechanism parameter structs that the operations require.

**Verdict:** NSS softoken IKE mechanism stubs (advertised but not operationally implemented).
Not a test bug.

**Status of xfail:** Legitimate. `CKR_MECHANISM_PARAM_INVALID` triggers `xfail_if_known_ckr`.

---

#### Group 5: SP800-108 KDF Mechanisms (7 xfails)

**File:** `src/pkcs11_check/testcases/test_sp800_108_kdf.py`

**Root cause:** NSS softoken advertises `CKM_SP800_108_COUNTER_KDF`, `CKM_SP800_108_FEEDBACK_KDF`,
and `CKM_SP800_108_DOUBLE_PIPELINE_KDF` but returns `CKR_MECHANISM_PARAM_INVALID` for
derivation operations with standard `CK_SP800_108_KDF_PARAMS`. Seven tests pass; 7 operational
tests xfail:

- `CKM_SP800_108_FEEDBACK_KDF`: 4 xfails (basic, with-IV, and two variants)
- `CKM_SP800_108_DOUBLE_PIPELINE_KDF`: 2 xfails (basic and 256-bit)
- `CKM_SP800_108_COUNTER_KDF` passes (7 passed) — NSS correctly implements counter mode

The feedback and double-pipeline variants are advertised but NSS softoken rejects the
`CK_SP800_108_FEEDBACK_KDF_PARAMS`/`CK_SP800_108_DKM_LENGTH_FORMAT` parameter structs.

**Verdict:** NSS softoken SP800-108 partial implementation (counter works, feedback/pipeline
advertised but not operational). Not a test bug.

**Status of xfail:** Legitimate. `CKR_MECHANISM_PARAM_INVALID` triggers `xfail_if_known_ckr`.

---

#### Group 6: HKDF_DATA CKR_TEMPLATE_INCONSISTENT (3 xfails)

**File:** `src/pkcs11_check/testcases/test_hkdf_extended.py`

**Root cause:** NSS softoken advertises `CKM_HKDF_DATA` but returns `CKR_TEMPLATE_INCONSISTENT`
when `C_DeriveKey` is called with a `CKO_DATA` template (to derive a data object rather than a
key). The three tests cover: basic derivation, determinism verification, and info-parameter
sensitivity. All fail at the `C_DeriveKey` call.

The `CKM_HKDF_DATA` mechanism is intended to produce raw data output (not a key object), but
NSS softoken does not support deriving `CKO_DATA` objects via HKDF. The mechanism is advertised
but only partial: NSS likely supports HKDF as a key derivation mechanism (`CKM_HKDF_DERIVE`)
but not the data-extraction variant.

**Verdict:** NSS softoken CKM_HKDF_DATA not operational for data-object derivation. Not a test bug.

**Status of xfail:** Legitimate. `CKR_TEMPLATE_INCONSISTENT` triggers `xfail_if_known_ckr`.

---

#### Group 7: EdDSA CK_EDDSA_PARAMS Rejection (7 xfails)

**File:** `src/pkcs11_check/testcases/test_eddsa.py`

**Root cause:** See Spec Deviations section. NSS softoken rejects `CK_EDDSA_PARAMS` even for
pure-mode EdDSA (`phFlag=CK_FALSE`, no context), violating PKCS#11 v3.0 Sec.2.3.13.

**Verdict:** NSS spec deviation. Not a test bug.

---

#### Group 8: Attribute & Spec Deviations (25 xfails)

These are individually documented NSS softoken bugs and spec violations:

| Tests | Reason | Category |
|-------|--------|---------|
| 3 | `CKA_LOCAL=False` for generated keys (AES, RSA pub, RSA priv) | Spec violation |
| 2 | `CKA_PRIVATE=False` for secret keys (default) | Spec violation |
| 2 | `CKA_PRIVATE=False` for RSA private key (default) | Spec violation |
| 2 | XCBC-MAC verify fails (`CKR_KEY_TYPE_INCONSISTENT`) | NSS bug |
| 2 | `C_SessionCancel` non-conformant return / `C_LoginUser` error | NSS v3.0 bug |
| 1 | `CKA_EXTRACTABLE=True` default for RSA private key | Spec violation |
| 1 | `CKA_COPYABLE=False` ignored | Spec violation |
| 1 | `CKA_DESTROYABLE=False` ignored | Spec violation |
| 1 | `CKA_WRAP_WITH_TRUSTED` not enforced | Security policy gap |
| 1 | `CKM_AES_CMAC_GENERAL` param error | NSS mechanism limitation |
| 1 | `CKM_PBA_SHA1_WITH_SHA1_HMAC` returns wrong key type | NSS quirk |
| 1 | `C_GenerateRandom` rejects 100KB request | NSS size limit |
| 1 | `C_GenerateRandom` rejects 1MB request | NSS size limit |
| 1 | `C_GenerateRandom` with stale session → CKR_OK | Spec violation |
| 1 | `C_SignRecover` accepts short data | Non-standard permissiveness |
| 1 | `C_VerifyRecover` wrong data / accepts zero signature | NSS bug |
| 1 | `C_VerifySignatureInit` accepts mismatched key | Security bug |
| 1 | Auto-initialize after `C_Finalize` returns CKR_OK | NSS vendor extension |
| 1 | `ML_KEM_512` parameter set not supported | PQC limitation |

All 25 are NSS softoken bugs, spec violations, or known vendor extensions. None are test bugs.

---

#### Group 9: Security Findings as Xfails (13 xfails)

These are findings confirmed as xfails (not just noted in documentation).
Severities use the hardware-token threat model described under
[Security Findings](#security-findings); CRITICAL rows are upstream-known
properties of NSS softokn rather than defects.

| Tests | Security Finding | Severity |
|-------|-----------------|---------|
| 3 | Sensitive key material readable (`CKR_OK` instead of `CKR_ATTRIBUTE_SENSITIVE`) | CRITICAL |
| 2 | `CKA_EXTRACTABLE` escalation `False→True` via `C_CopyObject` (Tookan vulnerability) | CRITICAL |
| 2 | `C_WrapKey` on `CKA_EXTRACTABLE=False` key succeeds (expected `CKR_KEY_UNEXTRACTABLE`) | HIGH |
| 1 | Wrap-decrypt oracle: key has both `CKA_WRAP` and `CKA_DECRYPT` | HIGH |
| 1 | RSA-OAEP non-uniform error codes (Manger 2001 padding oracle) | MEDIUM |
| 1 | `C_Digest` with 1-byte buffer returns `CKR_OK` (potential buffer overflow) | HIGH |
| 1 | `C_WrapKey_WITH_TRUSTED` not enforced | MEDIUM |
| 1 | `C_VerifySignatureInit` silently accepts mismatched public key | MEDIUM |
| 1 | `CKA_COPYABLE` escalation `False→True` | HIGH |

All 13 are xfailed with descriptive security messages. See Security Findings section for details.

---

#### Group 10: Miscellaneous (3 xfails)

| Test | Reason | Analysis |
|------|--------|---------|
| `test_cctv_rfc6979.py` | ECDSA nonce is random, not RFC 6979 deterministic | Expected; xfail is correct for non-deterministic modules |
| `test_wycheproof_pbkdf2.py::tc4` | `pbkdf2_hmacsha1_test.json:tc4` fails — 16,777,216 iterations | NSS may have an iteration count limit or timeout for PBKDF2 with extreme iteration counts |
| `test_remaining_gaps.py` | `CKM_AES_CMAC_GENERAL` returns `CKR_MECHANISM_PARAM_INVALID` | NSS does not support the `CKM_AES_CMAC_GENERAL` mechanism (general MAC with variable length), only fixed-length `CKM_AES_CMAC` |

---

#### Triage conclusion

All 645 xfails (final post-Phase-11 count) are verified as legitimate NSS softoken limitations.
Distribution:

- **NSS softoken implementation gaps** (mechanisms advertised but broken): 595 (92%)
  — ChaCha20-Poly1305, HKDF output, AES-KWP, IKE, SP800-108 feedback/pipeline, HKDF_DATA
- **NSS spec deviations** (non-conformant behavior): 37 (6%)
  — EdDSA params, attribute defaults (CKA_PRIVATE, CKA_LOCAL, CKA_EXTRACTABLE),
  CKA_COPYABLE/DESTROYABLE not enforced, session/cancel behavior, auto-init, CKA_WRAP_WITH_TRUSTED
- **Security policy violations** (PKCS#11 security model broken): 13 (2%)
  — Tookan, sensitive reads, key extraction, padding oracle

No xfails should be removed or converted to skips. These are the findings pkcs11-check
exists to report. The xfail annotations serve as a permanent record that the behavior is
known, documented, and not a test defect.

### Coverage & Skip Analysis (Phases 10-11)

**Final (post-Phase-11):** 35,327 passed / 296 failed / 31,984 skipped / 645 xfailed (68,252 total)

#### Function Coverage

64 / 104 PKCS#11 functions called (61%).

Uncalled functions fall into three groups:

- **Lifecycle** (not called by design — framework handles init/finalize): `C_Initialize`, `C_Finalize`,
  `C_GetFunctionList`, `C_GetInterface`
- **Destructive / PIN management** (skipped — no PIN configured, destructive flag not set):
  `C_InitToken`, `C_InitPIN`, `C_SetPIN`
- **Multi-part streaming** (no streaming tests yet): `C_EncryptUpdate`, `C_EncryptFinal`,
  `C_DecryptUpdate`, `C_DecryptFinal`, `C_SignFinal`, `C_VerifyFinal`, `C_VerifyUpdate`,
  `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate`, `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`
- **Message-based API** (v3.0 message interface not yet fully tested): `C_EncryptMessage`,
  `C_EncryptMessageBegin`, `C_EncryptMessageNext`, `C_MessageEncryptFinal`,
  `C_MessageDecryptInit`, `C_DecryptMessage`, `C_DecryptMessageBegin`, `C_DecryptMessageNext`,
  `C_MessageDecryptFinal`, `C_SignMessage`, `C_SignMessageBegin`, `C_SignMessageNext`,
  `C_MessageSignFinal`, `C_VerifyMessage`, `C_VerifyMessageBegin`, `C_VerifyMessageNext`,
  `C_MessageVerifyFinal`, `C_VerifySignatureFinal`, `C_VerifySignatureUpdate`
- **Deprecated/obsolete**: `C_GetFunctionStatus`, `C_CancelFunction`
- **Authenticated unwrap** (no test coverage yet): `C_UnwrapKeyAuthenticated`

#### Mechanism Coverage

107 / 140 advertised mechanisms exercised (76%).

**Not invoked (33 mechanisms):**

| Group | Mechanisms |
|-------|-----------|
| Legacy PBE/RC2 | `CKM_RC2_KEY_GEN`, `CKM_RC2_ECB`, `CKM_RC2_CBC`, `CKM_RC2_CBC_PAD`, `CKM_RC2_MAC`, `CKM_RC2_MAC_GENERAL`, `CKM_PBE_MD2_DES_CBC`, `CKM_PBE_MD5_DES_CBC`, `CKM_PBE_SHA1_RC2_128_CBC`, `CKM_PBE_SHA1_RC2_40_CBC`, `CKM_PBE_SHA1_RC4_128`, `CKM_PBE_SHA1_RC4_40` |
| CDMF (obsolete DES variant) | `CKM_CDMF_KEY_GEN`, `CKM_CDMF_ECB`, `CKM_CDMF_CBC`, `CKM_CDMF_CBC_PAD`, `CKM_CDMF_MAC`, `CKM_CDMF_MAC_GENERAL` |
| MD2/MD5 (deprecated hash) | `CKM_MD2_HMAC`, `CKM_MD2_HMAC_GENERAL`, `CKM_MD2_RSA_PKCS`, `CKM_MD5_HMAC`, `CKM_MD5_HMAC_GENERAL`, `CKM_MD5_RSA_PKCS` |
| ECDSA aliases | `CKM_ECDSA_KEY_PAIR_GEN` (alias for `CKM_EC_KEY_PAIR_GEN`), `CKM_ECDSA_SHA384`, `CKM_ECDSA_SHA512` |
| HMAC _GENERAL variants | `CKM_SHA_1_HMAC_GENERAL`, `CKM_SHA224_HMAC_GENERAL`, `CKM_SHA256_HMAC_GENERAL`, `CKM_SHA384_HMAC_GENERAL`, `CKM_SHA512_HMAC_GENERAL`, `CKM_SHA3_224_HMAC_GENERAL`, `CKM_SHA3_256_HMAC_GENERAL`, `CKM_SHA3_384_HMAC_GENERAL`, `CKM_SHA3_512_HMAC_GENERAL`, `CKM_AES_MAC` |
| PQC (present but untested) | `CKM_ML_KEM` (encapsulate/decapsulate combined mechanism — tests only use `CKM_ML_KEM_KEY_PAIR_GEN` + `C_EncapsulateKey`/`C_DecapsulateKey` directly) |

#### Skip Reason Breakdown (31,984 total skips)

| Count | % | Category | Root Cause |
|------:|--:|----------|-----------|
| 20,062 | 63% | EC unsupported curves | `CKR_DOMAIN_PARAMS_INVALID` on secp256k1, secp224r1, secp192r1, secp160r1/r2/k1, secp192k1, secp224k1, brainpoolP224/256/320/384/512r1 — NSS only supports NIST prime curves P-256/384/521 |
| 5,105 | 16% | ECDH private key import | `CKR_DOMAIN_PARAMS_INVALID` on ECDH test vectors for unsupported curves (subset of above, affects `test_wycheproof_ecdh.py`) |
| 1,993 | 6% | Montgomery / X448 import | `Cannot import Montgomery private key` / `X448 keygen not supported` — NSS supports X25519 keygen but not import of raw private key bytes |
| 1,919 | 6% | SHA-3 based mechanisms | `SHA3_*_RSA_PKCS not supported`, `SHA3_*_HMAC not supported` — NSS-PQC has SHA3 HMAC (advertised) but SHA3-RSA-PKCS and SHAKE/KMAC are absent |
| 1,097 | 3% | AES non-standard modes | `AES_CCM`, `AES_GMAC`, `AES_XTS`, `AES_CFB8/64/128`, `AES_OFB` not advertised |
| 711 | 2% | Miscellaneous | ~120 distinct reasons: ARIA, GOST, BLAKE2b, Camellia CTR, TLS KDF, WTLS, X9.42, Signal-protocol, HSS/XMSS/XMSSMT, etc. |
| 530 | 2% | ML-DSA (PQC) | `ML_DSA not supported` — FIPS 204 / ML-DSA not in NSS 3.121.0 |
| 236 | 1% | Ed25519/Ed448 key import | Public key import fails — NSS EdDSA requires keygen, not `C_CreateObject` import |
| 110 | 0% | RSA OAEP private key import | `Cannot import RSA private key for OAEP` — Wycheproof OAEP vectors need raw private key import |
| 84 | 0% | Hash-ML-DSA / Hash-SLH-DSA | `CKM_HASH_ML_DSA_*` / `CKM_HASH_SLH_DSA_*` (22 variants × 4) not supported |
| 64 | 0% | XDH vector decode errors | Wycheproof XDH vectors with unsupported key formats (`ValueError`, `UnsupportedAlgorithm`) |
| 41 | 0% | No PIN configured | Tests needing PIN-based login skipped (NSS crypto-services slot uses slot 0 with no PIN) |
| 35 | 0% | Destructive tests disabled | `--p11-destructive` not passed |
| 31 | 0% | Token write-protected | Cert DB slot (slot 1) `CKF_WRITE_PROTECTED` — 31 tests needing token-object creation skip |
| 22 | 0% | SLH-DSA (PQC) | `SLH_DSA not supported` — FIPS 205 / SLH-DSA not in NSS 3.121.0 |
| 14 | 0% | Infrastructure absent | fault-proxy not built, pkcs11-provider/p11-kit not installed, x509-limbo data not fetched |

**Summary:** 79% of skips (25,160) are due to NSS's restricted EC curve support — only P-256, P-384,
and P-521 are accepted. The remaining 21% span missing mechanisms (SHA-3/RSA, AES CCM/XTS/GMAC,
ML-DSA, SLH-DSA), key import limitations (Montgomery, Ed, RSA-OAEP), and test infrastructure gaps.
All skips are legitimate capability-based skips; none hide broken behavior.

---

## BouncyHSM 2.0.1 (v3.2)

**Status: Segfault on stale-handle attribute read (BouncyHSM PKCS#11 shim bug)**

### Known bugs
- **AES-CCM decrypt does not authenticate (tag-auth bypass, Type A)**: fresh 2026-06-09
  (`test_ccm.py` with the H2 operability probe): **423×** "module accepted CCM ciphertext
  with invalid tag" and ~1,268× plaintext mismatches where the returned plaintext is the
  expected one **plus the unstripped tag bytes** — i.e. BouncyHSM's CCM decrypt path
  decrypts without verifying or stripping the tag. Its CCM single-shot is otherwise
  largely non-operational (canonical known-answer encrypt → `CKR_GENERAL_ERROR`; 5,679
  vectors xfail "advertised but not operational"); the ops that DO complete expose the
  missing authentication. AES-GCM is unaffected (80 passed / 30 xfailed, clean).
- **Segfault on `C_GetAttributeValue` after `C_DestroyObject`**: reproduced on `key.destroy(); key[Attribute.LABEL]` and also via a direct `ctypes` call to `libbouncyhsm_pkcs11.so`. Root cause is in BouncyHSM's native PKCS#11 shim (`src/Src/BouncyHsm.Pkcs11Lib/bouncy-pkcs11.c`): `C_GetAttributeValue()` stores the real PKCS#11 return value in `rvMethod`, but checks `if (rv == CKR_OK || ...)` using the RPC transport status instead. Because `rv` is `0` on RPC success, the shim always enters the response-processing block and dereferences `envelope.Data` even when the method return is `CKR_OBJECT_HANDLE_INVALID`.
- **Correct shim fix**: change the condition to use `rvMethod`, not `rv`, and guard `envelope.Data != NULL` before dereferencing it. The server side already reports `CKR_OBJECT_HANDLE_INVALID` correctly.

### Known quirks
- .NET server + native PKCS#11 shim (TCP proxy architecture)
- 206 mechanisms supported
- Requires .NET 10.0 SDK for building
- InMemory or LiteDb storage modes
- `get_slots(token_present=True)` works in the current Docker setup
- Reading `CKA_ENCAPSULATE` / `CKA_DECAPSULATE` from an AES key now returns `CKR_ATTRIBUTE_TYPE_INVALID` cleanly

---

## tpm2-pkcs11 1.9.0 (hardware TPM)

**Status: 33 passed, 61 failed (core tests only) — limited mechanism support**

### Known limitations (hardware TPM)
- **26 mechanisms only**: AES-ECB/CBC/CBC-PAD/CFB/CTR, RSA-PKCS/OAEP/X509, ECDSA (P-256 only), SHA-1/256/384/512, SHA-HMAC
- **No EdDSA, DH, PQC, AES-GCM, AES-KW**: hardware doesn't support these
- **Keys always SENSITIVE**: TPM-backed keys can't export private material (by design)
- **CKA_PRIVATE_EXPONENT not readable**: RSA private key components not accessible
- **DA lockout**: Wrong PIN attempts lock the TPM. Clear with `tpm2_dictionarylockout --clear-lockout`
- **Needs `tss` group**: Use `sg tss -c "command"` or add user to `tss` group

---

## tpm2-pkcs11 1.10.0 (source Docker target, swtpm)

### Wycheproof RSA-PSS semantic failures

Focused current-source evidence:
`artifacts/_focused/tpm2-rsapss-current-20260526/`.

`test_wycheproof_rsa_pss.py` reports 788 passed, 943 skipped, 689 xfailed,
and 82 hard failures against the source-built tpm2-pkcs11 1.10.0 target
(`a95465ce672c5fda92a2d34bc5cbeda4b0511c80`).

The hard failures split into:

- 43 valid RSA-PSS signatures rejected by advertised PSS mechanisms.
- 39 invalid RSA-PSS signatures accepted after `CKR_OK`.

The accepted-invalid rows are Wycheproof salt-length mutation cases such as
`s_len changed to 0`. A local control check verifies those signatures fail when
the vector's `CK_RSA_PKCS_PSS_PARAMS.sLen` is enforced, but pass when
verification uses automatic PSS salt-length detection.

Source review matches the finding: tpm2-pkcs11 validates PSS params in
`src/lib/mech.c`, routes RSA public-key verification through software OpenSSL
in `src/lib/sign.c`, and sets RSA-PSS padding plus signature digest in
`src/lib/ssl_util.c`, but does not set the expected PSS salt length or MGF
digest on the verification context. This is provider behavior, not a
pkcs11-check vector-loader issue.

### No symmetric-keygen surface → CKR_FUNCTION_NOT_SUPPORTED (PC-6)

tpm2-pkcs11 does not expose a symmetric key-generation surface, so
`C_GenerateKey(CKM_AES_KEY_GEN)` returns `CKR_FUNCTION_NOT_SUPPORTED` — the whole
function is unavailable. A *negative* keygen probe (invalid key size,
inconsistent or bogus-type template) therefore cannot exercise its parameter and
can only get `CKR_FUNCTION_NOT_SUPPORTED`. This is an honest missing-capability
deviation, so pkcs11-check classifies it as **xfail** (the negative `genkey_*`
expectations in `ckr/_ckr_spec.py` accept `CKR_FUNCTION_NOT_SUPPORTED` in their
`compat_tuple`), not a hard fail. A provider that *does* support keygen would
return the specific size/template error instead, so this widening only relaxes
providers that genuinely lack the surface. A wrong-accept (`CKR_OK`) on a
non-permissive negative keygen probe remains a hard fail.

### ACVP RSA SHA-1 PKCS#1 SigVer rejects valid signatures

Focused current-source evidence:
`artifacts/_focused/tpm2-acvp-rsa-current-20260526/`.

`test_acvp_rsa.py` reports 279 passed, 390 skipped, 194 xfailed, and
27 hard failures against the same source-built 1.10.0 Docker target. Every
hard failure is a valid ACVP `CKM_SHA1_RSA_PKCS` signature-verification row
rejected by the provider after setup succeeds.

The representative failed vectors verify with `cryptography`. The failing set
includes FIPS186-2 vectors with small public exponents (`e = 3` and `e = 17`),
FIPS186-2/FIPS186-4 vectors with `e = 65537`, and FIPS186-4 vectors with larger
public exponents. This currently looks like advertised SHA-1 PKCS#1
verification behavior, not ACVP loader projection or RSA integer-padding noise.

### Session and object lifecycle findings after setup cleanup

Focused current-source evidence:
`artifacts/_focused/tpm2-setup-classifiers-current-20260526-r3/`.

After setup classifiers were applied to buffer, digest, generic error,
access-level, CVE-regression, mechanism-sign, multipart-streaming, session,
RO-session, object-visibility, and object-attribute files, the selected TPM2
batch reports 112 passed, 39 skipped, 117 xfailed, and 5 hard failures.

The hard failures are all post-setup semantic findings:

- `test_session_state_machine.py::TestLoginStateTransitions::test_open_session_is_public`
  finds private keys visible in a public session before login.
- `test_ro_session_restrictions.py` has two RO-session object-creation rows
  returning `CKR_SESSION_READ_ONLY`, even though PKCS#11 permits session-object
  creation and session-key crypto in RO sessions.
- `test_object_visibility.py` has two rows where session objects survive their
  owning session close.

The old setup failures in the same selected area should not be used as final
TPM2 counts; use the focused artifact above or a newer full matrix rerun.

### Remaining-gap and subprocess-safety focused rerun

Focused current-source evidence:
`artifacts/_focused/tpm2-remaining-sign-safety-r2-20260527/`.

The selected `test_remaining_gaps.py`, `test_sign_recover.py`, and
`test_subprocess_safety.py` slice now reports 6 passed, 23 skipped, 8 xfailed,
and 1 hard failure.

The old hard rows for template-constraint attributes, legacy parallel
functions, and sign-recover setup are stale on current source:

- AES template and CMAC setup now use the shared advertised-keygen classifier.
- `C_GetFunctionStatus` / `C_CancelFunction` still prefer
  `CKR_FUNCTION_NOT_PARALLEL`, but `CKR_FUNCTION_NOT_SUPPORTED` is documented
  as a non-clean compatibility note because the general function-list section
  permits unsupported API stubs.
- RSA sign-recover setup rejects are visible xfail evidence, not hard
  sign-recover semantic failures.
- Cross-process session-object isolation xfails parent `C_CreateObject` setup
  rejection before the isolation condition can be tested.

The remaining hard row is `test_fork_after_initialize`: the child
re-initialize/finalize path times out after 15 seconds. Keep that as a TPM2
subprocess-safety/daemon behavior finding unless a later focused run proves it
is only an environment timeout.

The fork harness now records explicit `CHILD_EXIT` / `CHILD_SIGNAL` status and
fails the pytest row if the child exits non-zero or is killed by a signal. A
focused pkcs11-mock check in
`artifacts/_focused/pkcs11-mock-fork-safety-current-20260527/` reports 1 passed
and 0 failed for the fork row, so this tighter status check does not change the
clean provider path.

### Raw CKR NULL-mechanism findings

Focused current-source evidence:
`artifacts/_focused/tpm2-ckr-raw-fault-r3-20260527/`.

After raw CKR subprocess setup classification was tightened, the selected
raw/fault/general CKR slice reports 28 passed, 14 xfailed, and 3 hard failures.
The retained false "Crash:" setup rows for raw attribute, buffer, state, fault,
and `C_GetInterfaceList` probes are stale.

The remaining hard rows are:

- `C_DigestInit(NULL)` exits with signal 11 instead of returning a CKR.
- `C_GenerateKey(NULL)` returns `CKR_FUNCTION_NOT_SUPPORTED` (`0x54`) instead
  of `CKR_ARGUMENTS_BAD`. Unlike operation-init calls such as `C_EncryptInit`,
  `C_GenerateKey` has no NULL-mechanism cancellation success path.
- `C_WrapKey(NULL)` returns `CKR_FUNCTION_NOT_SUPPORTED` (`0x54`) instead of
  a specific argument, mechanism, or handle error.

---

## OpenCryptoki 3.26 (v3.0)

### Known bugs (fresh 2026-06-09, triage H5)
- **CKM_AES_CTR accepts out-of-range ulCounterBits**: `C_EncryptInit` returns `CKR_OK`
  for `ulCounterBits=0` and `ulCounterBits=129` (OASIS spec range: 1-128). Detected by:
  `test_aes_modes.py::TestAESCTR::test_aes_ctr_counter_bits_{zero,129}_rejected`
  (3-way `classify_negative_rv`: acceptance of invalid -> fail).
- **CKM_AES_CTR rejects spec-valid payloads with `CKR_DATA_LEN_RANGE`** (32B and 17B
  inputs; CTR is a stream cipher per NIST SP 800-38A) and **CKM_AES_CTS is advertised but
  `C_EncryptInit` returns `CKR_MECHANISM_INVALID`** -- both clean deviations, xfailed via
  `CIPHER_OP_RUNTIME_REJECT_RVS`.
- **RSA-OAEP SHA-512/224|256 + MGF1-SHA1 not operational**: valid Wycheproof vectors
  rejected with `CKR_ENCRYPTED_DATA_INVALID`; the RFC 8017 canonical probe for those
  combos is also cleanly rejected -> advertised-but-not-operational xfail (26 vectors).

**Status: 468 passed, 24 failed, 312 skipped, 1 xfailed, 28,762 errors**

### Root cause of 28K errors
`pkcsslotd` daemon dies during the full test run, causing `FunctionFailed` for all subsequent tests. When run individually with the daemon alive, tests pass. This is a daemon stability issue under sustained load — needs investigation in task 2.4.

> **Update 2026-04-29:** No longer reproduces. The 2026-04-29 phase 1 run
> against opencryptoki-master (commit unpinned, `--depth 1` HEAD) recorded
> 0 crashed tests across 84,026 total — vs 6 crashed in the 2026-04-09
> baseline. Either upstream OpenCryptoki master fixed the daemon stability
> issue between Apr 8 and Apr 29, or the larger 19,684-entry
> `data/disabled-tests.txt` baseline now pre-skips the load pattern
> that triggered it. Worth cross-checking against the
> `test-opencryptoki` (Fedora 44 RPM, version 3.26.0) image, which is
> still pinned to 3.26.

### Known quirks
- Requires `pkcsslotd` daemon running
- Software token (`swtok`) only
- `C_SeedRandom` not supported (`RandomSeedNotSupported`)

---

## BouncyHSM 2.0.1 (v3.0)

### Crashes on large data (>1MB)
- `test_blake2b.py::test_large_data` - segfault on 1MB+ digest
- `test_buffers.py::TestEncryptBufferSizes::test_1mb` - segfault
- `test_buffers.py::TestDigestBufferSizes::test_large_input` - segfault
- `test_digest.py::TestDigestProperties::test_digest_large_data` - segfault
- `test_large_objects.py::TestLargeEncryption::test_encrypt_1mb_aes_cbc` - segfault
- 2 additional large-data tests crash

**Root cause:** BouncyHSM's internal buffer management segfaults on data > ~1MB.
This is a BouncyHSM bug, not a pkcs11-check issue.

---

## SoftHSM2 main (dev branch)

### EC regression - 4,715 crashes
All Wycheproof ECDSA (3,418 vectors) and ECDH (1,297 vectors) crash with segfault.
This is a regression in the SoftHSM2 dev branch compared to the stable 2.7.0 release.

**Root cause:** Development branch EC code regression. Not a pkcs11-check issue.

### Accepts undersized AES wrap key, returns CKR_GENERAL_ERROR (NEW 2026-04-30)
`test_ckr_wrap.py::test_wrapping_key_size_range` — SoftHSM2 accepts a 64-bit
"AES" key on `C_CreateObject` (AES requires 128/192/256 bits per FIPS 197).
When the undersized key is then used for `C_WrapKey` with `CKM_AES_KEY_WRAP`,
the module returns `CKR_GENERAL_ERROR` (0x05) instead of the
spec-conformant `CKR_WRAPPING_KEY_SIZE_RANGE` (0x114) or
`CKR_KEY_SIZE_RANGE` (0x62).

**Severity:** MEDIUM (conformance — two issues: lax import-time validation
and wrong CKR on wrap).
**Root cause:** SoftHSM2 does not validate AES key sizes on import; its
wrap path catches the failure too late and returns a generic error.

### Wrong CKR on tampered AES-KEY-WRAP ciphertext (NEW iter-47 2026-04-30)
`test_authenticated_wrap.py::TestWrapIntegrity::test_aes_key_wrap_bit_flip_detected`
— when the ICV-protected (RFC 3394 §2.2.2 A6A6A6A6 magic) AES-KEY-WRAP
ciphertext is bit-flipped and submitted to `C_UnwrapKey`, SoftHSM2
returns `CKR_GENERAL_ERROR` (0x05) instead of the spec-conformant
`CKR_WRAPPED_KEY_INVALID` (0x110) or `CKR_ENCRYPTED_DATA_INVALID` (0x40).
The integrity check **is** happening (the unwrap is rejected), only the
reported code is wrong. Unmasked by the iter-46 anti-masking commit
(`ce29ab1`) which removed `CKR_GENERAL_ERROR` from the test's global
accepted set; the prior CKR-tolerant version had been silently absorbing
this deviation since iter 44.

**Severity:** MEDIUM (conformance — wrong CKR; still rejects).
**Root cause:** SoftHSM2's AES-KEY-WRAP unwrap path uses a generic
exception → CKR_GENERAL_ERROR translation rather than mapping the
RFC-3394 ICV mismatch to a specific code. Reportable upstream.

This is NOT masked: the undersized-wrap test classifies the reject
with the 3-way negative classifier (spec `CKR_WRAPPING_KEY_SIZE_RANGE`
→ pass, any other clean code → xfail), so SoftHSM2's
`CKR_GENERAL_ERROR` surfaces as an honest **xfail** (a recorded
deviation) — never accepted as a pass. `CKR_GENERAL_ERROR` is too
generic to ever treat as the expected code, and the deviation keeps
surfacing in CI until SoftHSM2 fixes it upstream.

### Vaudenay 2002 / POODLE channel on AES-CBC-PAD (NEW iter-48 2026-04-30)
`test_padding_oracle.py::TestAESPaddingOracle::test_cbc_pad_all_last_block_positions`
— SoftHSM2 returns `CKR_OK` with **mismatched plaintext** when a
bit-flipped CBC-PAD ciphertext happens to produce accidentally-valid
PKCS#7 padding (~6/256 of random corruptions). Distinguishable from
`CKR_ENCRYPTED_DATA_INVALID` on rejected probes — the canonical
Vaudenay 2002 padding-oracle leak channel.

Concrete observation across 20 trials × 16 byte positions = 320
chosen-ciphertext probes: `{CKR_ENCRYPTED_DATA_INVALID: 319,
CKR_OK_DIFFERENT: 1}`. The CKR_OK_DIFFERENT outcome (audit-driven
classification added in the iter-48 audit fix) precisely identifies
the leak path: `C_Decrypt` returned CKR_OK but the recovered
plaintext does not match the original — exactly Vaudenay's signal.

This is an INHERENT property of PKCS#7 padding without an integrity
layer. An attacker with chosen-ciphertext access can recover plaintext
byte-by-byte via ~256 oracle queries per byte (CVE-2014-3566 POODLE
attack pattern).

**Severity:** MEDIUM (well-known channel — applications using bare
CBC-PAD are vulnerable; mitigation is application-level). Reportable
in the sense of "users SHOULD prefer AES-GCM"; not a SoftHSM2 bug per
se, since the spec permits the distinguishable response.
**Mitigation:** RFC 7366 encrypt-then-MAC, or AES-GCM. SoftHSM2 is
not at fault for following the spec; the spec itself accepts the leak.

### Positive finding: Kryoptic defeats the Vaudenay channel (NEW iter-48 2026-04-30)
The same Vaudenay test passes Kryoptic-main reliably across 20 trials
with a uniform outcome `{CKR_ENCRYPTED_DATA_INVALID: 320}`. The
audit-fix CKR_OK_DIFFERENT classifier rules out the alternative
explanation that Kryoptic silently accepts all bit-flipped ciphertexts
as CKR_OK with garbage plaintext (which would have shown
CKR_OK_DIFFERENT in the tally). Kryoptic genuinely returns
`CKR_ENCRYPTED_DATA_INVALID` even when random corruption happens to
produce a valid PKCS#7 byte pattern — an active mitigation against
the Vaudenay channel.

Worth investigating Kryoptic's source to learn how — likely a
constant-time padding check that always returns the rejection code
regardless of the validity bit, or an integrity layer beyond bare
PKCS#7. This is the kind of CBC-PAD behaviour TLS 1.3 / RFC 7366
mandates at the protocol level; Kryoptic providing it at the module
level is a notable security posture choice.

### Tookan §3.3 — CKA_SENSITIVE downgrade on unwrap (NEW 2026-04-30)
`test_cve_regression.py::TestTookanUnwrapAttrs::test_unwrapped_key_cannot_unset_sensitive`
— SoftHSM2 honours an attacker-supplied `CKA_SENSITIVE=False` in the
unwrap template, even when the original wrapped key was `CKA_SENSITIVE=True`.
The unwrapped copy has `CKA_SENSITIVE=False` and the key value can then be
read via `C_GetAttributeValue(CKA_VALUE)`.

**Severity:** **HIGH (security — known attack class)**. This is the
canonical Tookan paper §3.3 attack pattern from 2010. Anyone with wrap +
unwrap permission can clone any sensitive secret key into a non-sensitive
copy and exfiltrate the key bytes. Reportable upstream as a security
finding.
**Root cause:** SoftHSM2's unwrap path applies the attacker's template
without enforcing the "sensitive can never be unset" rule from
PKCS#11 v3.1 Sec.4.7.

### Tookan §3.2 — key-type confusion on unwrap (NEW 2026-04-30)
`test_tookan.py::TestKeyTypeConfusionOnUnwrap::test_unwrap_aes_as_des3_rejected`
— SoftHSM2 unwraps an AES-wrapped blob as `CKK_DES3` (Triple-DES) when
the attacker requests it via the unwrap template. The wrap blob carries
an AES-128 key (16 bytes), which the module reinterprets as a DES3 key
without size validation, parity adjustment, or weak-key checking. The
attacker can then run DES3 operations on bytes that were originally an
AES key, creating a side-channel that bypasses the type-based key
isolation PKCS#11 relies on.

**Severity:** **HIGH (security — known attack class)**. Tookan paper
§3.2 attack from 2010. Combines well with §3.3 (sensitive-flag
downgrade): an attacker with wrap + unwrap permission can both
extract the bytes and reinterpret them under different cryptographic
primitives, making it strictly easier to mount cross-algorithm
side-channel and integrity attacks.
**Root cause:** SoftHSM2's unwrap path does not validate the
relationship between the wrap mechanism, the wrapped-blob length,
and the requested CKA_KEY_TYPE.

Kryoptic correctly rejects this attack — its unwrap path enforces
type-and-size matching against the mechanism.

### Wrong CKR on tampered AES-KEY-WRAP — confirmed by iter-54 Phase 1 (CONFIRMED 2026-04-30)
The iter-47 finding for `test_aes_key_wrap_bit_flip_detected` reproduces
in the iter-54 Phase 1 re-run: SoftHSM2 returns `CKR_GENERAL_ERROR` on
a bit-flipped AES-KEY-WRAP ciphertext. No additional information.

---

## Qryptotoken 0.4.1 (Rust PQC)

### abort() instead of CKR error codes - 218 crashes
Module calls `abort()` (SIGABRT) instead of returning PKCS#11 error codes for
unsupported operations. This kills the test process instead of allowing graceful
error handling.

**Root cause:** Missing error handling in the Rust implementation. Not a pkcs11-check issue.

---

## OpenCryptoki master (3.27 dev branch, iter-42+ findings)

> The earlier `## OpenCryptoki 3.26 (v3.0)` section above (line 652)
> covers the v0.1.0 Phase 1 release-tested behaviour against the
> Fedora 3.26.0 RPM image. This section covers the unfiltered Phase 1
> work against the OpenCryptoki master branch (`--depth 1` HEAD)
> exercised in iters 42-63. Some entries below may also reproduce on
> 3.26 — they're documented here because that's where they were
> surfaced.

### SSL3 master key derive crash
- `test_ssl3.py::TestSSL3MasterKeyDerive::test_derive_master_secret` - segfault on
  C_DeriveKey with CKM_SSL3_MASTER_KEY_DERIVE. The SW token crashes instead of
  returning an error.

**Root cause:** OpenCryptoki SW token bug. Not a pkcs11-check issue.

### ECDH P-384/P-521 ACVP bucket reclassified (UPDATED 2026-05-26)
The earlier 2026-04-30 note for `test_acvp_ecdh.py` reported a 1,403-row
OpenCryptoki P-384/P-521 ECDH failure bucket and attributed it to an
OpenCryptoki SW-token curve-width limitation. Current evidence no longer
supports that conclusion.

**Corrected root cause:** pkcs11-check was extracting the peer EC point from
DER SubjectPublicKeyInfo by searching for the first `0x04` byte. That happened
to work for P-256 vectors, but the P-384 and P-521 curve OIDs contain an
earlier `0x04`, so pkcs11-check passed malformed peer public data into the
provider.

The current ACVP ECDH loader parses the SubjectPublicKeyInfo structure and
extracts the BIT STRING EC point explicitly. Current retained OpenCryptoki
artifacts for `test_acvp_ecdh.py` no longer support a hard P-384/P-521
OpenCryptoki derive-failure finding. Any future ECDH issue should be based on
a refreshed provider run and should distinguish setup/import limitations from
derive-time failures after a valid private key and peer public point were
accepted.

### AES-XTS ACVP bucket reclassified (UPDATED 2026-05-26)
The older 2026-04-30 note for `test_xts.py` reported ACVP AES-XTS
encrypt/decrypt failures and treated them as an OpenCryptoki ciphertext
mismatch. A focused current-source rerun after fixing the ACVP loader no longer
supports that conclusion.

**Corrected root cause:** pkcs11-check was not preserving the ACVP XTS vector
shape. ACVP `tweakMode: number` rows use `sequenceNumber`, which must be
converted to the little-endian 16-byte `CKM_AES_XTS` data-unit sequence number.
The loader also lost group-level `payloadLen`, so bit-level ACVP vectors were
sent through PKCS#11 as ordinary byte strings.

Current source keeps the parametrized XTS rows collected, converts
`sequenceNumber`, chunks multi-data-unit inputs, and skips only ACVP bit-level
vectors that PKCS#11 `CKM_AES_XTS` cannot express as byte-string input. The
focused OpenCryptoki artifact
`artifacts/_focused/opencryptoki-xts-after-loader-fix-20260526/` records the
corrected classification. Older artifacts that list the `ACVP AES-XTS` bucket
are stale.

### ML-DSA ACVP/context findings (UPDATED 2026-05-26)
The older 2026-04-30 note for `test_acvp_mldsa.py::test_mldsa_siggen`
treated generated-signature verification failures as a broken OpenCryptoki
signing primitive. Focused current-source reruns narrowed that conclusion.

**Corrected pkcs11-check root cause:** non-empty-context SigGen and Wycheproof
ML-DSA verification rows were missing `CK_SIGN_ADDITIONAL_CONTEXT` on the
follow-up verify call. Current source passes the same context into verification,
and the focused Wycheproof ML-DSA rerun records no hard failures for that
context-propagation bug.

**Remaining OpenCryptoki finding:** a small set of context-empty ACVP SigVer
rows still reject valid pure `CKM_ML_DSA` signatures. The local OASIS text says
`CKM_ML_DSA` receives the message `M`, and absent mechanism parameters mean
`CKH_HEDGE_PREFERRED`, `ulContextLen=0`, and `pContext=NULL`; the current
pkcs11-check call shape matches that rule. Focused evidence is in
`artifacts/_focused/opencryptoki-acvp-mldsa-current-20260526/`.

**Additional crash finding:** OpenCryptoki swtok aborts when verification uses
an explicit `CK_SIGN_ADDITIONAL_CONTEXT` whose `pContext` is non-NULL and
`ulContextLen=0`. Source review points to the mechanism-parameter copy/free
path: `verify_mgr.c` first copies the caller's struct, `ml_dsa_dup_param()`
returns early for zero-length context without clearing the copied pointer, and
`ml_dsa_free_param()` later frees that caller pointer during cleanup. The
subprocess probe
`TestMlDsaExplicitEmptyContext::test_mldsa_verify_empty_context_nonnull_pointer`
keeps this abort discoverable.

### Template-count C_FindObjectsInit signal 7 (NEW 2026-05-27)
A focused current-source OpenCryptoki 3.27.0 build with OpenSSL 4.0.0 reports
three signal-7 crashes in
`artifacts/_focused/opencryptoki-arithmetic-overflow-current-20260527/`.
All three rows call `C_FindObjectsInit` with extreme `ulCount` values:
`0xffffffffffffffff`, `0xaaaaaaaaaaaaaab`, and `0x100000000`.

This is current provider-side crash evidence, not a pkcs11-check setup
classification issue. The malformed API call is reached after setup, and the
module terminates instead of returning a CKR such as `CKR_ARGUMENTS_BAD`.

### FFI length-boundary signal crashes (UPDATED 2026-05-27)
A focused current-source OpenCryptoki 3.27.0 build with OpenSSL 4.0.0 reports
five hard FFI boundary findings in
`artifacts/_focused/opencryptoki-ffi-length-current-20260527-r2/`: four
signal-7 rows for `C_Sign(HMAC_SHA256)` / `C_Digest(SHA256)` with
`ulDataLen` at `isize::MAX` and `isize::MAX + 1`, plus the separate
`C_Verify(ML-DSA, pContext non-NULL, ulContextLen=0)` signal-6 abort already
described in the ML-DSA section.

The pre-fix EdDSA null-context setup row from the first 2026-05-27 FFI rerun is
not an OpenCryptoki finding. pkcs11-check was using generic
`CKM_EC_KEY_PAIR_GEN` for Ed25519 setup; current source uses
`CKM_EC_EDWARDS_KEY_PAIR_GEN`.

### AES-CBC-PAD accepts invalid PKCS#5 padding — 144 (NEW 2026-06-11, Type A)
`test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5` — **144 failed /
72 passed** on both the 3.26 RPM pool (`opencryptoki-pooled`) and the master pool
(`opencryptoki-master-pooled`) — identical failing tcId set. `CKM_AES_CBC_PAD` decrypts
Wycheproof `result:invalid` vectors and returns `CKR_OK` instead of rejecting with
`CKR_ENCRYPTED_DATA_INVALID`. The 144 invalid vectors break down as **`BadPadding` ×141**
(last block uses non-PKCS#5 padding: zero-byte, `0xff`, ISO/IEC 7816-4, ANSI X.923,
ISO 10126, over-length count) and **`NoPadding` ×3** (tc25/97/169 "empty ciphertext").

**Determination — GENUINE module finding, `fail` is correct (Type A, not a strictness
call).** Per the classification-model design doc (`docs/classification-model-design.md`,
Type A): "a wrong-length or **malformed ciphertext decrypts**" is a crypto-correctness
break → `fail` on acceptance, no claim-check. A non-PKCS#5-padded ciphertext IS a malformed
ciphertext for `CKM_AES_CBC_PAD`; stripping it and returning a plaintext is precisely that
case (and the classic padding-oracle attack surface). This **supersedes the earlier
"flagged deliberate-strictness" note** in the wolfpkcs11 section below — the model already
classifies it.

**Cross-check evidence (fresh 2026-06-11 from the validated pools):**
- opencryptoki-pooled == opencryptoki-master-pooled == wolfpkcs11-pooled (stable): all fail
  the **byte-identical 144-tcId set** (set difference empty in both directions). So
  opencryptoki's deviation is structurally the *same* lax-PKCS#5 acceptance as wolfpkcs11
  stable — not merely a matching count.
- Strict providers reject all 144 → **softhsm2 216P, kryoptic 216P** (live-confirmed:
  local softhsm2 run = `216 passed`). The test is provider-general and effect-gated
  (line 503-504 fails unconditionally on an `invalid` vector decrypting), so strict modules
  pass and lax modules fail with no provider keying.
- Graded structure across providers: **wolfpkcs11-master** and **bouncyhsm** each fail
  *only* the 3 `NoPadding` empty-ciphertext vectors (tc25/97/169) — i.e. they fixed
  BadPadding enforcement but still accept empty ciphertext. opencryptoki accepts both
  classes (all 144). This grading confirms a real, providers-differ validation deviation,
  not a harness artifact.

**Severity:** MEDIUM (conformance — `CKM_AES_CBC_PAD` does not validate PKCS#5 padding on
decrypt: malformed ciphertext is accepted and a stripped plaintext returned, a
crypto-correctness break with unvalidated-malleability / interop consequences. Note this
module accepts *all* invalid-padding vectors, so on its own it exposes no distinguishable
padding oracle — the harm is malformed-ciphertext acceptance, not an oracle channel.).
**Action:** documentation only; the test classification is already correct. Report upstream
against OpenCryptoki SW token.

### RSA-PSS distinct hash and MGF rejected (NEW 2026-04-30)
`test_wycheproof_rsa_pss.py` — **435 failures**. RSA-PSS signatures where
the message hash (e.g. SHA-256) differs from the MGF1 hash (e.g. SHA-1) are
rejected with `CKR_MECHANISM_PARAM_INVALID`. RFC 8017 / FIPS 186-4 explicitly
allow distinct hash and MGF — a common, conformant configuration in TLS 1.2
and RFC 5756. SoftHSM2 has the same restriction (already documented above).

**Severity:** MEDIUM (conformance — interop with peers that use distinct
hash/MGF impossible).
**Root cause:** OpenCryptoki RSA-PSS limited to matched hash/MGF only.

### AES-KWP wraps to wrong length (NEW 2026-04-30)
**Update 2026-05-26:** this old OpenCryptoki finding is stale for current
source. The Wycheproof KWP test was using deprecated `CKM_AES_KEY_WRAP_PAD`
with `C_WrapKey`, while `aes_kwp_test.json` is an RFC 5649 raw-data KWP vector
set. Current source now uses `CKM_AES_KEY_WRAP_KWP` with `C_Encrypt`; a focused
OpenCryptoki rerun reports 726 passed, 1,013 skipped, 80 xfailed, and 0 failed
for the Wycheproof AES file. The remaining xfails are AES-XTS runtime rejects,
not AES-KWP rows.

**Corrected root cause:** pkcs11-check selected the wrong PKCS#11 mechanism for
the Wycheproof KWP vectors. Do not report the old 107-row KWP bucket upstream as
an OpenCryptoki AES-KWP interop bug.

### AES-KWP corrupted decrypt writes past minimal output buffer (NEW 2026-05-26)
`security/test_error_path_kwp.py::TestCorruptedUnwrap::test_corrupted_unwrap`
— corrected guarded-output-buffer probes fail for the 8 corrupted
`CKM_AES_KEY_WRAP_KWP` `C_Decrypt` cases when OpenCryptoki master is built with
OpenSSL 4.0.0. `C_Decrypt` returns `CKR_GENERAL_ERROR`, but the guard bytes
immediately after the minimal `len(input) - 8` output buffer are overwritten.
Current focused evidence is in
`artifacts/_focused/opencryptoki-master-error-path-current-20260527/`: the
selected KWP/RSA error-path slice reports 42 passed and 8 failed, with all 8
failures in the KWP decrypt path and all RSA error-path rows passing.

This is not fixed by OpenCryptoki PR #932. That PR fixed OpenCryptoki's common
fallback `aeskw_unwrap_pad()` cleanup length. The swtok path still registers
`token_specific_aes_key_wrap`, calls `openssl_specific_aes_key_wrap()`, and
maps `CKM_AES_KEY_WRAP_KWP` to OpenSSL `EVP_aes_*_wrap_pad()`. OpenSSL PR
#30663 remains the relevant upstream fix for the OpenSSL path.

**Severity:** HIGH (memory safety on corrupted AES-KWP input).
**Root cause:** OpenSSL AES-KWP unwrap-pad error cleanup is still reachable
through OpenCryptoki swtok.

### AES-CBC-PAD ciphertext malleability — no padding validation (NEW iter-58 2026-04-30 — CRITICAL)
`test_padding_oracle.py::test_cbc_pad_all_last_block_positions` — across
20 trials × 16 byte positions = 320 corruption probes, OpenCryptoki
returns the tally `{CKR_OK_DIFFERENT: 319, CKR_OK_MATCH: 1}`. **NONE** of
the 320 probes return `CKR_ENCRYPTED_DATA_INVALID`. The module silently
accepts ALL bit-flipped CBC-PAD ciphertexts and returns CKR_OK with
whatever plaintext bytes result from the corrupted ciphertext.

This is **strictly worse than the Vaudenay 2002 channel** observed on
SoftHSM2 / Kryoptic — those modules at least reject the ~94% of
corruptions that produce invalid PKCS#7 padding. OpenCryptoki has no
padding validation at all on the decrypt path, exposing a CIPHERTEXT
MALLEABILITY surface: an attacker who can submit chosen-ciphertext
queries can flip arbitrary bits in the ciphertext and the module
silently produces the corresponding plaintext modification. No
oracle queries needed — direct manipulation works.

The single CKR_OK_MATCH out of 320 is a coincidence: a random
corruption that happens to invert to its original (statistically
expected at ~1/256 / 2^N probability for N flipped bits in random
content).

**Severity:** **CRITICAL (security — silent ciphertext malleability)**.
This is significantly worse than a padding oracle. Reportable upstream
as an urgent fix. The iter-51 audit-fix classifier (CKR_OK_MATCH /
CKR_OK_DIFFERENT) introduced for the silent-failure-hunter was
exactly what surfaced this finding — a less-strict test that just
checked for "more than one outcome class" would have flagged it
identically to SoftHSM2's Vaudenay finding, missing the
"no rejections at all" pattern.
**Root cause:** OpenCryptoki's AES-CBC-PAD decrypt path appears to
skip PKCS#7 padding validation entirely on the decrypted block.

### RSA-OAEP padding oracle — Manger 2001 (NEW iter-58 2026-04-30 — HIGH)
`test_padding_oracle.py::TestRSAPaddingOracle::test_oaep_error_uniformity`
— OpenCryptoki returns non-uniform CKRs for invalid OAEP ciphertexts:
`{CKR_FUNCTION_FAILED, CKR_ENCRYPTED_DATA_INVALID}`. The Manger 2001
attack distinguishes "valid prefix, bad content" from "invalid prefix"
via this CKR difference. The same channel as the NSS finding above,
but with a different CKR set (NSS uses `CKR_ARGUMENTS_BAD` instead of
`CKR_FUNCTION_FAILED`).

**Severity:** HIGH (security — known attack class). Reportable upstream.
**Root cause:** OpenCryptoki's OAEP decrypt path emits different
CKRs depending on which validation step failed, leaking the boundary
the Manger attack exploits.

### Unwrap-template attribute rejection (CKR_ATTRIBUTE_READ_ONLY, NEW iter-63 2026-04-30 — LOW)
`C_UnwrapKey` returns `CKR_ATTRIBUTE_READ_ONLY` (0x10) when the unwrap
template includes `CKA_CLASS` or `CKA_KEY_TYPE`, before any
cryptographic check is performed. PKCS#11 v3.1 Sec.5.14.4 explicitly
shows examples of unwrap templates that include these two attributes
(they identify the type of key being unwrapped); other modules
(SoftHSM2, Kryoptic, NSS) accept the template without complaint.

Surfaced during iter-58 / iter-61 by tests in `test_tookan.py` and
`test_authenticated_wrap.py` whose unwrap templates pre-fill
CKA_CLASS / CKA_KEY_TYPE — a pattern aligned with the spec examples.

**Severity:** LOW (conformance — restrictive template parsing; rejects
spec-allowed templates). The behaviour is consistent and prevents
the test from reaching its security assertion, but no security gap
is opened: every cryptographic primitive on OC is still gated by
the regular checks once a working template is supplied.
**Root cause:** OpenCryptoki's unwrap-template parser appears to mark
CKA_CLASS / CKA_KEY_TYPE as read-only-after-creation rather than
treating them as type-identification hints permitted in unwrap
templates. Reportable upstream.

This is absorbed provider-generally (no module identity): the
mechanism-level unwrap helper `unwrap_key_for_mechanism_roundtrip`
negotiates the template — it tries the canonical template first and,
on a clean template-shape reject, retries a variant dropping only
CKA_CLASS (CKA_KEY_TYPE is spec-mandatory and kept). A module that
rejects the CKA_CLASS-bearing template thus still completes the
roundtrip; one that rejects every spec-equivalent template routes the
positive leg to xfail. No per-module quirk registry is involved.

---

## Kryoptic v1.5.0 / main (v3.2)

### C_SessionCancel crash (kryoptic-main)
`test_v30_session.py::test_cancel_after_digest_init_subprocess` - the module
aborts when C_SessionCancel is called with an active digest operation.
Documented in Kryoptic issue tracker.

### AES-CTS not operational
CKM_AES_CTS is advertised in the mechanism list but returns CKR_DEVICE_ERROR
when used. The mechanism is recognized but not implemented.

### Arithmetic-overflow panics and segfaults (NEW 2026-05-27)
A focused current-source Kryoptic main rerun reports five hard boundary
findings in `artifacts/_focused/kryoptic-main-arithmetic-overflow-current-20260527/`:
three `C_FindObjectsInit` extreme-template-count rows abort with Rust panic or
allocation failure, `C_UnwrapKey(template_count=ULONG_MAX)` exits with signal
11, and `C_GenerateKey(CKM_AES_KEY_GEN, CKA_VALUE_LEN=ULONG_MAX)` aborts with a
capacity-overflow panic.

These are provider process-survival findings from malformed boundary inputs.
They are not skips and not setup xfails: the test reaches the intended
malformed PKCS#11 entry point and the provider terminates instead of returning
a CKR error.

### FFI length-boundary crashes and timeout (UPDATED 2026-05-27)
A focused current-source Kryoptic main rerun reports seven hard FFI boundary
findings in `artifacts/_focused/kryoptic-main-ffi-length-current-20260527-r2/`:
four signal-7 rows for `C_Sign(HMAC_SHA256)` / `C_Digest(SHA256)` with
`ulDataLen` at `isize::MAX` and `isize::MAX + 1`, a timeout in
`C_GenerateKey(CKM_AES_KEY_GEN, CKA_VALUE_LEN=0x7fffffff)`, and signal-11
crashes in the TLS KDF NULL-label and SP800-108 NULL-data-params probes.

The pre-fix EdDSA null-context setup row from the first 2026-05-27 FFI rerun is
not a Kryoptic finding. pkcs11-check was using generic `CKM_EC_KEY_PAIR_GEN`
for Ed25519 setup; current source uses `CKM_EC_EDWARDS_KEY_PAIR_GEN`.

### FIPS mode crashes (kryoptic-fips)
Crashes on CKM_EXTRACT_KEY_FROM_KEY and certain AES-CCM vectors.
FIPS mode correctly rejects non-approved operations but aborts instead of
returning CKR_MECHANISM_INVALID.

**Note — these are debug-build aborts, not release crashes.** The
`kryoptic-fips` target is compiled in **debug mode** (against a custom OpenSSL
FIPS branch), so an internal debug assertion calls `abort()` (SIGABRT) on a
check failure rather than returning an error. The recorded `crashed` count for
this target therefore reflects debug-assertion aborts, *not* segfaults/UB in a
release build. The underlying policy issue (a non-approved op should return a
clean CKR rather than terminate) is still a real finding.

### Type-confusion: generic-secret accepted as AES wrap key (NEW 2026-04-30)
`test_ckr_wrap.py::test_wrapping_key_type_inconsistent` — Kryoptic accepts a
`CKK_GENERIC_SECRET` key as the wrap-key argument to `C_WrapKey` with
`CKM_AES_KEY_WRAP`, returning `CKR_OK` and producing wrap output. PKCS#11
v3.1 Sec.5.14.3 explicitly requires `CKR_WRAPPING_KEY_TYPE_INCONSISTENT`
when "the type of the key specified to wrap another key is not consistent
with the mechanism."

**Severity:** **HIGH (security)**. Type-confusion in the wrap path opens a
key-misuse attack vector — any secret material (HMAC keys, KDF outputs,
import-attacker-supplied generic-secret blobs) becomes wrap-eligible. An
attacker who can place a generic secret into the token can then re-package
sensitive keys against it, bypassing the type-based access controls that
PKCS#11 relies on for key isolation. Reportable upstream as a security
finding, not a generic conformance issue.

**Root cause:** Kryoptic's wrap-mechanism dispatcher does not check the
wrap-key's `CKA_KEY_TYPE` against the mechanism's required type before
invoking the underlying AES primitive. The output is whatever the AES
primitive produces when fed the generic-secret bytes as if they were an
AES key.

### Tookan §3.3 — CKA_SENSITIVE downgrade on unwrap (NEW 2026-04-30)
`test_cve_regression.py::TestTookanUnwrapAttrs::test_unwrapped_key_cannot_unset_sensitive`
— Kryoptic, like SoftHSM2, honours an attacker-supplied `CKA_SENSITIVE=False`
in the unwrap template, downgrading a `CKA_SENSITIVE=True` key to a
non-sensitive copy whose value can be read via `C_GetAttributeValue(CKA_VALUE)`.

**Severity:** **HIGH (security — known attack class)**. Canonical Tookan
paper §3.3 attack pattern from 2010. Any caller with wrap + unwrap
permission can clone a sensitive secret key into a non-sensitive copy
and exfiltrate the key bytes. Reportable upstream as a security finding.
**Root cause:** Kryoptic applies the attacker's CKA_SENSITIVE in the
unwrap template without enforcing the "sensitive can never be unset"
invariant from PKCS#11 v3.1 Sec.4.7.

### CKA_TRUSTED escalation by USER session (NEW iter-54 2026-04-30)
`test_access_levels.py::TestTrustedAttribute::test_user_cannot_set_trusted`
— Kryoptic accepts CKA_TRUSTED=True on a freshly-generated key from a
USER (CKU_USER) session. PKCS#11 v3.1 Sec.4.7 designates CKA_TRUSTED
as SO-only: only a Security Officer (CKU_SO) is allowed to mark a key
as trusted. A USER-session caller who can create CKA_TRUSTED keys
bypasses the `CKA_WRAP_WITH_TRUSTED` policy gate that protects sensitive
wrap operations.

**Severity:** **HIGH (security — privilege escalation)**. The TRUSTED
flag is the SO-trust boundary for `CKA_WRAP_WITH_TRUSTED` enforcement.
A USER session creating TRUSTED keys can wrap any
`CKA_WRAP_WITH_TRUSTED=True` key, defeating the attribute's purpose.
**Root cause:** Kryoptic's create-object path does not authorise the
CKA_TRUSTED attribute against the session's user type. Reportable
upstream as a security finding.

### Vaudenay 2002 channel on AES-CBC-PAD — present (REVISED iter-54 2026-04-30)
**Update from iter-48's claim that "Kryoptic defeats Vaudenay":**
the iter-54 Phase 1 re-run on `test_cbc_pad_all_last_block_positions`
shows Kryoptic also has the channel, just at a much lower hit rate
than SoftHSM2. Tally: `{CKR_ENCRYPTED_DATA_INVALID: 319,
CKR_OK_DIFFERENT: 1}` across the 320 probes — 1 / 320 ≈ 0.3% leak rate
vs SoftHSM2's similar rate. The earlier iter-48 / iter-51 claim that
Kryoptic defeats the channel was based on lucky runs where no probe
hit the rare accidentally-valid-padding case. The Vaudenay channel
is real on Kryoptic too — same caveats and mitigation as the SoftHSM2
note in the SoftHSM2 section.

**Severity:** MEDIUM (well-known channel; spec permits the
distinguishable response). Same as SoftHSM2's entry — applications
should use AES-GCM or RFC 7366 encrypt-then-MAC instead of bare
CBC-PAD. The earlier "positive finding" claim is retracted.

---

## NSS main (3.121 dev branch, iter-54 findings)

### Tookan §3.3 — CKA_SENSITIVE downgrade on unwrap (NEW iter-54 2026-04-30)
`test_cve_regression.py::TestTookanUnwrapAttrs::test_unwrapped_key_cannot_unset_sensitive`
— NSS softoken, like SoftHSM2 and Kryoptic, honours an attacker-
supplied `CKA_SENSITIVE=False` in the unwrap template. A
`CKA_SENSITIVE=True` key, once wrapped and unwrapped under attacker
control, becomes a non-sensitive copy whose value is readable via
`C_GetAttributeValue(CKA_VALUE)`.

**Severity:** **HIGH (security — known attack class)**. Tookan paper
§3.3 attack from 2010. The same canonical attack now confirmed
present on **all three major open-source PKCS#11 providers**
(SoftHSM2 + Kryoptic + NSS). A 2010-era key-extraction attack is
universally effective in 2026 against open-source PKCS#11
implementations. Reportable upstream.
**Root cause:** NSS softoken's unwrap path applies the attacker's
template without enforcing the "sensitive can never be unset"
invariant from PKCS#11 v3.1 Sec.4.7.

### CKA_TRUSTED escalation by USER session (NEW iter-54 2026-04-30)
`test_access_levels.py::TestTrustedAttribute::test_user_cannot_set_trusted`
— NSS softoken accepts CKA_TRUSTED=True on a freshly-generated key
from a USER (CKU_USER) session, same shape as the Kryoptic finding
above. The TRUSTED-flag SO-trust boundary used by
`CKA_WRAP_WITH_TRUSTED` is breached.

**Severity:** **HIGH (security — privilege escalation)**. Same
attack class and same reportability as the Kryoptic entry above.
Two independent providers exhibiting the same defect suggests a
shared incorrect mental model of CKA_TRUSTED's authorisation rule
in mainstream PKCS#11 implementations.
**Root cause:** NSS softoken's create-object path does not
authorise CKA_TRUSTED against the session's user type.

### FFI length-boundary crashes (UPDATED 2026-05-27)
A focused current-source NSS main rerun reports three hard FFI boundary
findings in `artifacts/_focused/nss-main-ffi-length-current-20260527-r2/`:
two signal-11 rows for `C_Sign(HMAC_SHA256)` with `ulDataLen` at `isize::MAX`
and `isize::MAX + 1`, plus a signal-11 crash for
`C_EncryptInit(CKM_AES_GCM, pIv=NULL, ulIvLen=12)`.

The pre-fix EdDSA null-context setup row from the first 2026-05-27 FFI rerun is
not an NSS finding. pkcs11-check was using generic `CKM_EC_KEY_PAIR_GEN` for
Ed25519 setup; current source uses `CKM_EC_EDWARDS_KEY_PAIR_GEN`.

### RSA-OAEP padding oracle confirmed and surfaced (CONFIRMED iter-54 2026-04-30)
`test_padding_oracle.py::TestRSAPaddingOracle::test_oaep_error_uniformity`
— NSS RSA-OAEP returns non-uniform CKRs for invalid ciphertexts:
`{CKR_ENCRYPTED_DATA_INVALID, CKR_ARGUMENTS_BAD}`. This is the
documented Manger 2001 leak channel and was previously tracked via
`pytest.xfail` (suppressive pattern). Iter-45 upgraded the test to
`pytest.fail`; the iter-54 Phase 1 re-run is the first time NSS-main
exercises the upgraded version, surfacing the long-known leak as a
hard CI failure. Not a NEW finding — the bug has been public since at
least the v0.1.0 release report. Reportable upstream as a security
finding (already in upstream NSS Bugzilla per the v0.1.0 report).

## OpenCryptoki 3.27.0 (v3.2)

**Library:** `libopencryptoki.so` (soft token) · **Docker targets:** `test-opencryptoki` (v3.27.0), `test-opencryptoki-master`

### ML-KEM output template requires `CKA_VALUE_LEN` (strict-but-conformant)

OpenCryptoki advertises full **standard** PQC since 3.27 (`CKM_ML_DSA`, `CKM_ML_KEM`,
`CKM_HASH_ML_DSA` family) and its ML-KEM encapsulate/decapsulate are **fully operational**.

`C_EncapsulateKey`/`C_DecapsulateKey` require the output-key template to declare
**`CKA_VALUE_LEN`**; without it OpenCryptoki returns `CKR_TEMPLATE_INCONSISTENT`. This is a
defensible strict reading of PKCS#11 v3.2 — for `CKM_ML_KEM` the spec says the mechanism
contributes `CKA_VALUE` but *"other attributes required by the key type must be specified in
the template."* Lenient modules (kryoptic, NSS) infer the 32-byte length; OpenCryptoki does not.

This was previously **mis-reported by the harness as "ML-KEM encapsulate not operational"**:
`testcases/test_kem.py::_encap_attrs` and `wycheproof/test_wycheproof_mlkem.py` omitted
`CKA_VALUE_LEN`, so every `_encap_attrs`-based op false-xfailed (16 in `test_kem`) and the
Wycheproof decaps false-failed (3) on OpenCryptoki, while `test_decapsulate_aes_key_sizes`
(which *does* pass `CKA_VALUE_LEN`) passed. Fixed by always supplying `CKA_VALUE_LEN=32` (the
ML-KEM shared-secret size, FIPS 203) in the KEM output template; OpenCryptoki now passes
ML-KEM encaps/decaps cleanly with no module change. The harness fix is locked by
`tests/test_kem_output_template.py`.

> Provider-general lesson: a KEM/derive output template must declare the length attribute the
> key type requires; relying on a module to infer it (kryoptic's leniency) masks working PQC on
> strict-but-conformant modules.

### AES-KEY-WRAP unwrap rejects `CKA_VALUE_LEN` as read-only

In contrast to ML-KEM, OpenCryptoki's `CKM_AES_KEY_WRAP` unwrap *rejects* `CKA_VALUE_LEN`
(`CKR_ATTRIBUTE_READ_ONLY`) for some key sizes — it derives the recovered length from the
wrapped blob, like softhsm2 — while NSS *requires* it (see the NSS section). The adaptive
unwrap in `test_wycheproof_aes.py` tries the minimal template first and only restates the
length for valid vectors when the module asks; where the module cannot create the
generic-secret object either way (larger AES-KW payloads here), that valid vector is recorded
as a clean operational-deviation xfail rather than a failure.

### `C_UnwrapKey` template: rejects policy attributes, requires `CKA_CLASS` (probed 2026-06-09)

A direct template-ladder probe (stable + master, identical) established OpenCryptoki's
`C_UnwrapKey` template rules for `CKM_AES_KEY_WRAP` into `CKK_AES`:

| template | result |
|---|---|
| `{CKA_CLASS, CKA_KEY_TYPE}` (± `CKA_VALUE_LEN`, `CKA_ENCRYPT/DECRYPT`, `CKA_TOKEN`) | **OK** (default key is readable) |
| drop `CKA_CLASS` | `CKR_TEMPLATE_INCOMPLETE` (CKA_CLASS is required) |
| add `CKA_EXTRACTABLE` / `CKA_SENSITIVE` | **`CKR_ATTRIBUTE_READ_ONLY`** |

So OpenCryptoki rejects the *policy* attributes (`CKA_EXTRACTABLE`/`CKA_SENSITIVE`) in an
unwrap template and requires `CKA_CLASS`. softhsm2 is the mirror: it *needs* `CKA_EXTRACTABLE`
for the unwrapped value to be readable. This is handled provider-generally by
`unwrap_key_for_mechanism_roundtrip`, which keeps `CKA_CLASS`/`CKA_KEY_TYPE` in every variant
and, on a clean shape reject, drops only the policy attributes — so OpenCryptoki's
authenticated-wrap / ECDH-AES-KW forgery detection is actually exercised. (An earlier
mis-attribution blamed `CKA_CLASS`/`CKA_KEY_TYPE` for this `READ_ONLY`; the probe shows the
real cause is the policy attributes.) OpenCryptoki does not implement AES-GCM authenticated
wrap (`CKR_FUNCTION_NOT_SUPPORTED`), so those forgery tests xfail on a genuine capability gap.

## corePKCS11 3.6.4 (FreeRTOS, mbedTLS port, docker target with generic in-memory PAL)

Minimal embedded implementation; storage-oriented object model. Root-caused 2026-06-09
(triage H6) by in-container probing + v3.6.4 source reading (`core_pkcs11_mbedtls.c`).

### Storage-model traits (negotiated by the harness, not bugs to hard-fail)
- **`CKA_LABEL` is mandatory on every key object**: `C_CreateObject` without a label returns
  `CKR_ARGUMENTS_BAD` (`prvCreateECKey`/`prvCreateRsaKey`: "Received a NULL label pointer").
  The spec makes CKA_LABEL optional → deviation; the harness's
  `create_object_negotiated` retries with a unique label.
- **Token objects only**: `CKA_TOKEN=False` in a key template returns
  `CKR_ATTRIBUTE_VALUE_INVALID` ("Expected token type to be true"). Session objects are
  spec-mandatory → deviation; negotiated to `CKA_TOKEN=TRUE` (objects are destroyed in test
  cleanup).
- **Public/private keys share one label slot**: importing one after the other merges them
  (`prvGetExistingKeyComponent`); the harness uses unique per-import labels.

### Crypto constraints (xfail-classified deviations)
- **P-256 only**: `CKA_EC_PARAMS` must equal the P-256 OID, else `CKR_TEMPLATE_INCONSISTENT`
  (skip via `_EC_PUBLIC_IMPORT_UNSUPPORTED_CKRS`). Curves whose OID length differs bypass the
  check (see Known bugs below); curves with different coordinate sizes fail at point parse
  (`CKR_FUNCTION_FAILED` → skip).

### Known bugs
- **Silent curve rebind on EC public key import (Type-C self-contradiction)**: the
  `CKA_EC_PARAMS` check only runs when the supplied OID has the same DER length as the
  P-256 OID (`prvEcKeyAttParse` compares only on equal `ulValueLen`), and
  `mbedtls_ecp_point_read_binary` performs no curve-membership check. A secp256k1 or
  brainpoolP256r1 public key (32-byte coordinates) is therefore accepted with `CKR_OK` —
  but the object is unusable: `C_GetAttributeValue` → `CKR_OBJECT_HANDLE_INVALID`,
  `C_Verify` → `CKR_KEY_HANDLE_INVALID`. Claimed success, not honored → **fail** per the
  classification model. Detected by: `test_ec_import_coherence.py` (2 failures, fresh
  2026-06-09). KAT suites skip such curves via the same effect check
  (`ec_public_key_binding_defect`) so the bug is reported once, not 22k times.
- **CKM_ECDSA digest length pinned to 32 bytes**: `C_Verify` returns `CKR_DATA_LEN_RANGE`
  unless `ulDataLen == 32`, and `CKR_SIGNATURE_LEN_RANGE` unless `ulSignatureLen == 64`.
  PKCS#11 §2.3.1 requires accepting any hash length (truncated to the group order bit
  length) → deviation, xfailed via `_ECDSA_RUNTIME_REJECT_CKRS` /
  `NON_CLEAN_SIGNATURE_REJECT_RVS`.
- **Imported secret keys (AES-CMAC / SHA256-HMAC) are advertised but not operational**:
  `C_CreateObject` for a `CKO_SECRET_KEY` returns `CKR_OK` and a handle, but the key cannot
  then be used — `C_Sign` returns `CKR_KEY_TYPE_INCONSISTENT` and `C_GetAttributeValue` on the
  just-returned handle returns `CKR_OBJECT_HANDLE_INVALID`. **Verified consistent** (2026-06-09)
  across the corePKCS11-native configured label (`"HMAC Key"`) and arbitrary labels, so it is a
  stable corePKCS11 secret-key-use limitation rather than a per-vector handle bug; the KAT clean
  error returns are model-conformant xfails (advertised-but-not-operational). **Caveat: the
  `CKR_OK`-create-then-invalid-handle readback is a Type-C self-contradiction, but its root cause
  (corePKCS11's own object-list handling vs the docker target's generic in-memory PAL storing a
  raw, non-DER secret blob) is not yet isolated — so it is documented here, not asserted as a
  module `fail`, pending a stock-PAL repro.** (Contrast the EC silent-curve-rebind bug above,
  which is in corePKCS11's native `mbedtls_ecp_point_read_binary` path and IS asserted as a fail.)
- ECDSA verify itself is correct for the supported shape: valid P-256/SHA-256 signature →
  `CKR_OK`; corrupted signature → clean verify-False (probed in-container).

### Docker-target deployment notes
- The stock posix demo PAL stores only the 8 labels fixed in `core_pkcs11_config.h`; any
  other label fails `PKCS11_PAL_SaveObject` → `C_CreateObject` = `CKR_DEVICE_MEMORY`. The
  docker target replaces it with a generic in-memory PAL
  (`docker/corepkcs11/corepkcs11_pal_generic.c`): arbitrary labels, honest `isPrivate`
  (DER-shape discrimination), real `PKCS11_PAL_DestroyObject`. The PAL is corePKCS11's
  designated porting point — corePKCS11's own PKCS#11 logic is untouched.
- The adapter shim (`corepkcs11_adapter.c`) only overrides GetInfo/SlotInfo/TokenInfo/
  MechanismList/MechanismInfo/Digest; C_CreateObject and C_Verify pass straight through.

## wolfpkcs11 (wolfSSL in-process C library)

Pool baseline 3,067. The fix-pass cleared `test_cts` 2,079 (H2 operability probe → xfail) and
`wycheproof_rsa` 21 → 0. The remaining failures are **genuine wolfpkcs11 findings + flagged UB
probes**. **Correction (2026-06-10 re-verify):** two files the prior summary listed as "cleared → 0"
were NOT cleared — fresh targeted runs on dev still show `wycheproof_rsa_oaep` **209 failed** (stable)
/ **210** (master) and `wycheproof.py::TestAESCBCPKCS5Wycheproof` **144 failed**. Both are genuine
deviations (see below), not harness artifacts. The H3 combo probe only clears *combo-dead* OAEP
(e.g. opencryptoki's 26 SHA-512/224 vectors → xfail); wolfpkcs11's combos are operational, so its
valid-vector rejections are correctness findings (fail) by the deliberate H3 design. (The earlier
`400 failed` total was thus understated; per project policy exact counts are tracked only at release,
so no precise total is asserted here.)

### Known bugs
- **Digest path leaks a raw wolfSSL error as the CK_RV (H7)**: `C_Digest`/`C_DigestFinal` for
  SHA-2/SHA-3 return `0xfffffffffffffff7c` (= -132 sign-extended, a raw negative wolfSSL internal
  error) instead of a defined `CKR_*`. The whole digest path is affected: `test_acvp_hash` ~161,
  `test_acvp_sha3` ~81, `test_digest`/`test_mech_digest`/`test_mech_multipart`/`test_sha3` ~67
  (~309 total). Returning a non-`CKR_*` value violates the spec; the suite surfaces it as a clean
  (non-crash) return.
- **RSA-OAEP decrypt rejects valid edge-case vectors despite an operational combo (209/210)**:
  `test_wycheproof_rsa_oaep` — wolfpkcs11 decrypts typical OAEP messages correctly (the canonical
  per-(sha,mgf) combo probe is OPERATIONAL) but returns `CKR_ENCRYPTED_DATA_INVALID` on valid
  vectors at the input edges. Fresh 2026-06-10 cross-checked against the pool: **209 failed** (stable),
  **210** (master). Breakdown (all clean rejects, no wrong output): **empty-message OAEP `msglen=0`
  ~125** (softhsm2/kryoptic/opencryptoki all decrypt empty-message OAEP fine), **3-prime RSA keys 54**
  (`rsa_three_primes_oaep_*`; softhsm2 66P, kryoptic/opencryptoki 110P each — so the harness's
  multi-prime import is correct and this is wolfpkcs11-specific), **near-max message length ~15**,
  scattered ~15. Classified `fail` (operational combo + rejected valid vector = correctness finding,
  per the deliberate H3 design); the inconsistency (decrypts 16-byte but not 0-byte same-combo) is a
  real wolfpkcs11 OAEP decoder edge-case bug, not an "advertised but not operational" deviation.
- **AES-CBC-PAD accepts invalid PKCS#5 padding (144)**: `test_wycheproof.py::
  TestAESCBCPKCS5Wycheproof` — also NOT cleared by the fix-pass (fresh 2026-06-10: **144 failed**).
  The Wycheproof "invalid" vectors carry genuinely non-PKCS#5 padding (`BadPadding` ×141: zero-byte,
  0xff, ISO/IEC 7816-4, ANSI X.923, ISO 10126, over-length; `NoPadding` ×3), which `CKM_AES_CBC_PAD`
  should reject with `CKR_ENCRYPTED_DATA_INVALID`; wolfpkcs11 decrypts them (`CKR_OK`). **Shared with
  opencryptoki** (both 72P/144F), whereas softhsm2 and kryoptic reject correctly (216P) and bouncyhsm
  rejects all but 3 — so this is a real lax-padding-validation deviation, not a harness artifact.
  ⚖️ **Decision RESOLVED (2026-06-11) — `fail` is correct (Type A), not a strictness call.** The
  earlier "neither crypto-correctness nor self-contradiction" framing was an incomplete reading of the
  model: `docs/classification-model-design.md` Type A explicitly lists "a wrong-length or **malformed
  ciphertext decrypts**" as a crypto-correctness break → `fail`. A non-PKCS#5-padded ciphertext is a
  malformed ciphertext for `CKM_AES_CBC_PAD`, so decrypting it (returning a plaintext) is the Type-A
  case directly (and the padding-oracle attack surface). Provider-general/effect-gated: strict modules
  (softhsm2/kryoptic 216P) pass, lax modules fail, no provider keying. Cross-check 2026-06-11:
  wolfpkcs11-stable and opencryptoki fail the **byte-identical 144-tcId set**; wolfpkcs11-master and
  bouncyhsm fail only the 3 `NoPadding` empty-ciphertext vectors (tc25/97/169). See the OpenCryptoki
  master section for the full determination.
- **AES-CCM decrypt accepts an invalid tag (tag-auth bypass, Type A)**: `test_ccm` -- "accepted
  invalid (CKR_OK) -- must reject" (same no-authentication class as bouncyhsm CCM). CCM is also
  partly non-operational (the H2 operability probe xfails those vectors); the ops that complete
  expose the missing authentication.
- **Output-buffer size-protocol violations** (`test_ckr_raw_buffer`, fresh): `C_GetMechanismList`
  returns `CKR_BUFFER_TOO_SMALL` but reports required count **1 when the real count is 65** (caller
  can never size the buffer); `C_GetAttributeValue` **writes 13 bytes past a declared 1-byte buffer**
  (real OOB write); `C_WrapKey` reports a **garbage required length (isize_max / 0x7FFF...FF)**.
  PKCS#11 §5.2 requires the true required length with no write on `CKR_BUFFER_TOO_SMALL`.
- **Crashes (genuine, on normal input)**: `test_wycheproof_hkdf` SIGABRT after 10 valid vectors;
  `test_ckr_keygen` SIGSEGV. wolfpkcs11-master fixed most crashes (4 vs stable's 18) -- report
  against current master.

---

## pkcs11-mock v2.0.0 (Pkcs11Interop stub)

**Library:** `libpkcs11-mock.so` (single-file C stub, <https://github.com/Pkcs11Interop/pkcs11-mock>)
**Docker target:** `test-pkcs11-mock`
**Interface:** v3.1 (stub; most operations return `CKR_FUNCTION_NOT_SUPPORTED`)

pkcs11-mock is a minimal conformance-testing stub. It accepts any `C_CreateObject` call and
returns `CKR_OK`, but it does not actually store the caller-supplied data — it serves back its
own hardcoded canned values for every `C_GetAttributeValue` query.

### Known bugs

- **Canned `CKA_VALUE` on certificate objects (Type-C self-contradiction)**: `C_CreateObject`
  for a `CKO_CERTIFICATE` object returns `CKR_OK` regardless of the supplied DER bytes, but a
  subsequent `C_GetAttributeValue(CKA_VALUE)` returns the 12-byte string `"Hello world!"` instead
  of the imported DER. The stored size never matches the sent size: the pool baseline shows all
  175 `test_limbo_import.py` certificate-import tests fail with the message
  `"CKA_VALUE mismatch (12B stored vs <N>B sent)"`, where `N` is the real DER length (hundreds of
  bytes). This is a **Type-C lifecycle self-contradiction**: `C_CreateObject` claims success, but
  the readback contradicts the stored value — the module did not honour what it said it had
  stored. Classification: **correctly FAILs** — this is a genuine finding, not a harness bug.

  **Source evidence:** the canned value is `PKCS11_MOCK_CK_OBJECT_CKA_VALUE "Hello world!"`
  defined in the upstream `pkcs11-mock.h` header; the `C_GetAttributeValue` implementation in
  `pkcs11-mock.c` returns it unconditionally for all non-certificate-type objects and falls through
  to `mock_certificate` (a fixed DER blob, not the caller-supplied bytes) for certificate objects.
  Neither path stores nor returns the caller-supplied `CKA_VALUE`.

  **Count context:** the pool baseline recorded ~88 failures on an earlier run; the count grew to
  ~175 after the portable-label fix allowed more `C_CreateObject` calls to succeed (previously
  some imports were rejected before reaching the value-storage path). Both counts reflect the same
  underlying canned-value behaviour — more successful imports expose more readback contradictions.

  **Report upstream?** The behaviour is by design for a stub library: pkcs11-mock is intended as
  a minimal no-op stub, not a compliant token. Worth noting upstream as documentation — a stub
  that returns `CKR_FUNCTION_NOT_SUPPORTED` from `C_CreateObject` would be a cleaner contract
  than a silent-discard that returns `CKR_OK` and then lies on readback. pkcs11-check correctly
  surfaces the contradiction as a hard fail; callers testing against pkcs11-mock should not rely
  on round-tripping certificate bytes through `CKA_VALUE`.

  Detected by: `test_limbo_import.py::test_import_limbo_failure_cert_raw` (175 failures,
  pool baseline `artifacts2/pkcs11-mock-pooled/report.jsonl`). Determination: 2026-06-10
  triage session.
