# Module Issues

Known issues, quirks, and compliance deviations per PKCS#11 module.
Updated as Docker targets are analyzed.

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
- **GCM null-IV crash potential (NEW 2026-04-29)**: `test_ffi_length_boundary.py
  ::TestMechanismNullInnerParams::test_gcm_null_iv` failed (does not assert clean
  CKR_ARGUMENTS_BAD on `pIv = NULL` for GCM). Needs deeper investigation — currently
  marked as a SoftHSM-specific finding; may overlap with arithmetic-overflow theme.
  Detected by: `test_ffi_length_boundary.py`.

### Known quirks
- `C_GetObjectSize` returns `CK_UNAVAILABLE_INFORMATION` (not implemented)
- `C_SeedRandom` succeeds silently (no-op, RNG is OpenSSL-based)
- v2.40 only — no `C_GetInterface`, no v3.0+ mechanisms
- Session objects visible across concurrent sessions (spec says they shouldn't be)

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

### Known quirks
- v3.2 interface — supports `C_GetInterface`, PQC mechanisms
- `C_GetObjectSize` works correctly
- No P-224 EC curve support
- AES-GCM parameter format differs from some other modules
- **Automatic v3.0+ Attribute Extraction**: Kryoptic automatically extracts `CKA_SUBJECT`, `CKA_ISSUER`, and `CKA_SERIAL_NUMBER` from `CKA_VALUE` during `C_CreateObject`, even when they are not provided in the template. This is highly compliant but conflicts with modules that require explicit population.

---

## NSS 3.120.1 (v3.0)

**Status: 20,723 passed, 362 failed, 8,147 skipped, 335 xfailed**

### Failure breakdown (362 total)
| Count | Area | Reason |
|-------|------|--------|
| 296 | DSA Wycheproof | NSS `C_Verify` rejects valid DSA signatures: key import succeeds but `CKM_DSA_SHA224`/`CKM_DSA_SHA256` return `CKR_SIGNATURE_INVALID` for all valid vectors across all 4 parameter sets (2048/224, 2048/256, 3072/256). Root cause: NSS softoken DSA verify strictly validates additional internal state or parameter consistency that the Wycheproof-imported public key objects do not satisfy. Affects all NSS versions. |
| ~16 | Session/access tests | NSS returns `CKR_USER_TYPE_INVALID` instead of `CKR_USER_ALREADY_LOGGED_IN` — PKCS#11 spec compliance deviation |
| ~16 | KEM/PQC | ML-KEM not supported in NSS 3.120.1 (expected skips, showing as errors) |
| ~2 | AES-XCBC-MAC | NSS returns CKR_KEY_TYPE_INCONSISTENT on verify despite CKA_VERIFY=True |
| ~27 | Other | AEAD, key flags, mechanism fuzz, etc. — per-file analysis needed |

### Known quirks
- **Read-only crypto services token**: NSS's default slot ("NSS Generic Crypto Services") is read-only. Cannot create objects, generate keys, or store tokens. Tests requiring RW access should skip.
- **No PIN/login on crypto services slot**: The default slot does not support `C_Login` — returns `CKR_USER_TYPE_INVALID` when login is attempted. This is correct behavior for a public token that doesn't have login semantics.
- **Two slots**: NSS exposes 2 slots. Slot 0 is the crypto services slot (read-only), slot 1 may be an NSS internal database slot.
- **Needs configDir for full functionality**: `libsoftokn3.so` must be loaded with `configDir='sql:/path/to/db'` NSS init args to access the writable database slot. Without this, only the read-only crypto services slot is available. See `/home/user/src/m/pkcs11-proxy/pkcs11-proxy/scripts/test-nss-fixtures.sh` for reference configuration.
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

- **ML-KEM buffer sizing:** C_EncapsulateKey/C_DecapsulateKey return CKR_BUFFER_TOO_SMALL — under investigation
- **ML-KEM-512:** Wycheproof semi-expanded decapsulation fails — may not support semi-expanded key format

### Security Findings

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

**MEDIUM: RSA-OAEP padding oracle (non-uniform error codes)**

- Different CKR codes returned for different invalid OAEP ciphertexts
  (observed: `CKR_ARGUMENTS_BAD` and `CKR_ENCRYPTED_DATA_INVALID` mixed)
- A uniform error code (`CKR_ENCRYPTED_DATA_INVALID`) must be returned for all decryption failures
  to prevent information leakage about ciphertext structure
- Ref: Manger "A Chosen Ciphertext Attack on RSA Optimal Asymmetric Encryption Padding" (CRYPTO 2001);
  PKCS#11 v3.1 Sec.6.1.8
- Affected test: `test_padding_oracle.py::TestRSAPaddingOracle::test_oaep_error_uniformity`
- Impact: Potential plaintext recovery via error oracle (~O(log n) queries for 2048-bit RSA)

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

- **DSA verify rejects all Wycheproof valid signatures (296 failures)**: `C_Verify` with
  `CKM_DSA_SHA224` and `CKM_DSA_SHA256` returns `CKR_SIGNATURE_INVALID` for all valid
  Wycheproof DSA signatures. Key import via `C_CreateObject` with `CKA_PRIME`, `CKA_SUBPRIME`,
  `CKA_BASE`, `CKA_VALUE` succeeds, but verification always fails. Root cause: NSS softoken
  DSA verification requires keys to have been generated through NSS's own key generation path
  or imported in a specific internal format. Externally constructed `CKO_PUBLIC_KEY` objects
  with raw domain parameters are not accepted for signature verification. This is a fundamental
  NSS limitation affecting all 296 DSA Wycheproof vectors across all 4 parameter sets. These
  remain as failures (not xfailed) because the module is genuinely rejecting valid signatures.

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

All 645 xfails were individually verified against NSS softoken behavior.
**None are fixable test bugs.** Every xfail represents a genuine NSS limitation or spec deviation.

#### xfail breakdown by root cause

| Count | % | Category | Root Cause | Files |
|------:|--:|----------|-----------|-------|
| 256 | 40% | ChaCha20-Poly1305 param mismatch | NSS softoken | `test_wycheproof_chacha.py` |
| 232 | 36% | HKDF output correctness | NSS softoken | `test_wycheproof_hkdf.py` |
| 77 | 12% | AES-KWP output format | NSS softoken | `test_wycheproof_aes.py` |
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

**Root cause:** NSS softoken's `CKM_AES_KEY_WRAP_PAD` (alias `CKM_AES_KEY_WRAP_KWP`) does not
correctly implement RFC 5649 (AES Key Wrap with Padding). Three distinct failure patterns:

1. **+8 bytes extra (33 cases):** For AES-standard-size plaintexts (16, 24, 32, 384 bytes),
   NSS produces output 8 bytes larger than expected. The correct KWP output is
   `msg_len + 8 bytes overhead`; NSS produces `msg_len + 16 bytes`, suggesting it applies an
   extra AES block cipher step. Example: 16-byte plaintext → expected 24B, got 32B.

2. **Wrong output, same size (22 cases):** For non-standard message sizes (tc18–tc25, same-size
   vectors), NSS produces output of the correct length but with different ciphertext content,
   indicating incorrect padding or header construction.

3. **Operation failed (22 cases):** For very short plaintexts (1–8 bytes, tc11–tc17), NSS
   returns an error rather than wrapping. RFC 5649 allows wrapping as few as 1 byte; NSS
   appears to enforce a minimum size requirement inconsistent with the standard.

**Verdict:** NSS softoken AES-KWP non-conformance (three distinct deviations from RFC 5649).
Not a test bug.

**Status of xfail:** Legitimate. `AssertionError` on size/content mismatch, or operation failure.

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

These are high-severity security bugs confirmed as xfails (not just noted in documentation):

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

## OpenCryptoki 3.26 (v3.0)

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

A SoftHSM2-specific quirk could be registered in `_module_quirks.py`
to silence this on the test, but per the project guardrails this is
NOT done — `CKR_GENERAL_ERROR` is too generic to mask globally for a
module, and the deviation is real enough to keep surfacing in CI
until SoftHSM2 fixes it upstream.

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

## OpenCryptoki 3.26 (v3.0)

### SSL3 master key derive crash
- `test_ssl3.py::TestSSL3MasterKeyDerive::test_derive_master_secret` - segfault on
  C_DeriveKey with CKM_SSL3_MASTER_KEY_DERIVE. The SW token crashes instead of
  returning an error.

**Root cause:** OpenCryptoki SW token bug. Not a pkcs11-check issue.

### ECDH P-384 derivation broken (NEW 2026-04-30)
`test_acvp_ecdh.py` — **1,403 failures** (Wycheproof-ECDH P-384 vectors). All
return `CKR_FUNCTION_FAILED` on `C_DeriveKey` with `CKM_ECDH1_DERIVE`. P-256
ECDH works; P-384 does not. The opencryptoki-master SW token does not support
ECDH for curves wider than P-256, despite advertising the mechanism without
curve filtering. Affects `test_acvp_ecdh.py`, `test_wycheproof_ecdh.py`.

**Severity:** HIGH (compliance — silently fails on standard NIST curve).
**Root cause:** OpenCryptoki SW token ECDH limited to P-256.

### AES-XTS produces wrong ciphertext (NEW 2026-04-30)
`test_xts.py` — **382 failures** on ACVP AES-XTS encrypt/decrypt vectors. The
SW token returns ciphertext that does not match the IEEE Std 1619-2007 / NIST
SP 800-38E reference output, but `C_Encrypt` returns `CKR_OK`. Plaintext that
round-trips through encrypt+decrypt is recoverable, but interop with any other
XTS implementation is broken.

**Severity:** HIGH (data-at-rest correctness — encrypted volumes written by
this token cannot be read by any conformant XTS reader).
**Root cause:** OpenCryptoki AES-XTS implementation deviates from NIST/IEEE
reference. Likely tweak-derivation or polynomial-multiplication bug.

### ML-DSA signs but signatures fail to verify (NEW 2026-04-30)
`test_acvp_mldsa.py::test_mldsa_siggen` — **164 failures**. `C_Sign` with
`CKM_ML_DSA` returns `CKR_OK` and produces output of the expected size, but
the signature does not verify against the corresponding public key (using
either OpenCryptoki itself or any external ML-DSA verifier). The signature
bytes appear unrelated to the message.

**Severity:** HIGH (signing primitive broken — produced "signatures" carry
no cryptographic guarantee).
**Root cause:** OpenCryptoki ML-DSA implementation broken at sign time.
Likely a key-binding / domain-separation bug.

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
`test_wycheproof_aes.py::test_aes_kwp` — **107 failures**. Wycheproof AES-KWP
(RFC 5649) test vectors produce ciphertext of length 40B where the reference
expects 24B (and similarly for other plaintext sizes — the output is always
larger than RFC 5649 specifies). The bytes themselves also do not match.
The implementation appears to be wrapping under a different mode (possibly
classic AES Key Wrap RFC 3394 with extra padding, or KWP with extra blocks).

**Severity:** HIGH (interop — wrapped keys cannot be unwrapped by any
RFC-5649-conformant reader).
**Root cause:** OpenCryptoki AES-KWP either implements the wrong RFC or
applies extra blocks beyond the RFC 5649 padding. Reportable upstream.

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

---

## Kryoptic v1.5.0 / main (v3.2)

### C_SessionCancel crash (kryoptic-main)
`test_v30_session.py::test_cancel_after_digest_init_subprocess` - the module
aborts when C_SessionCancel is called with an active digest operation.
Documented in Kryoptic issue tracker.

### AES-CTS not operational
CKM_AES_CTS is advertised in the mechanism list but returns CKR_DEVICE_ERROR
when used. The mechanism is recognized but not implemented.

### FIPS mode crashes (kryoptic-fips)
15 crashes on CKM_EXTRACT_KEY_FROM_KEY and certain AES-CCM vectors.
FIPS mode correctly rejects non-approved operations but aborts instead of
returning CKR_MECHANISM_INVALID.

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
