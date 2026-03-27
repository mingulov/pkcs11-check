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
- **ECDSA_SHA* accepts invalid signatures (ACVP SigVer)**: `C_Verify` with `CKM_ECDSA_SHA256`, `CKM_ECDSA_SHA384`, `CKM_ECDSA_SHA512` accepts NIST ACVP `testPassed=False` vectors (modified r, modified s, zero r, zero s, modified message, modified key). 17/17 invalid vectors in `test_acvp_ecdsa.py` return `CKR_OK` instead of `CKR_SIGNATURE_INVALID`. Only valid vectors (tc54, tc62, tc103) produce the correct result. Detected by: `test_acvp_ecdsa_sigver`.
- **EDDSA accepts invalid signatures (ACVP SigVer)**: `C_Verify` with `CKM_EDDSA` accepts NIST ACVP `testPassed=False` vectors for both Ed25519 and Ed448. 8/8 invalid vectors return `CKR_OK` instead of `CKR_SIGNATURE_INVALID`. Detected by: `test_acvp_eddsa_sigver`.

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

### Coverage & Skip Analysis (Phase 10)

**Baseline (post-Phase-9):** 35,327 passed / 302 failed / 31,984 skipped / 639 xfailed (68,252 total)

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
