# PKCS#11 OASIS Spec Compliance — Gap Analysis

**Date:** 2026-03-20
**Source:** OASIS PKCS#11 spec (`/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/`, 95 files, 27,382 lines)
**Target:** pkcs11-check test suite (149 test files, ~29K tests)

---

## Executive Summary

| Domain | Spec Items | Tested | Coverage | Status |
|--------|-----------|--------|----------|--------|
| **Mechanisms** | ~370 | 70 | 19% | Major gaps in legacy/regional/protocol ciphers |
| **API Functions** | ~68 core | ~45 | 66% | Gaps in state mgmt, recovery, async |
| **Object Types** | 12 | 6 | 50% | 6 types completely untested |
| **Attributes** | 190+ | ~58 | 30% | Template/constraint attrs missing |
| **CKR Return Codes** | 802 entries | 802 | 100% | Documented; 148+ with active tests |

The test suite has **strong cryptographic coverage** (RSA, AES, EC, PQC, HMAC, SHA) but significant gaps in **legacy mechanisms** (DES, GOST, Camellia, ARIA), **protocol mechanisms** (TLS/SSL/WTLS/IKE), **specialized object types** (OTP, Trust, Validation, HW Feature), and **attribute constraint enforcement**.

---

## Domain 1: Mechanism Coverage

### What's Tested (70 mechanisms across 30+ families)

**AES (11 mechanisms):** AES_ECB, AES_CBC, AES_CBC_PAD, AES_GCM, AES_CCM, AES_CMAC, AES_GMAC, AES_KEY_GEN, AES_KEY_WRAP, AES_KEY_WRAP_PAD, AES_XTS

**RSA (20+ mechanisms):** RSA_PKCS, RSA_PKCS_OAEP, RSA_PKCS_PSS, SHA1/224/256/384/512_RSA_PKCS, SHA1/224/256/384/512_RSA_PKCS_PSS, SHA3_224/256/384/512_RSA_PKCS, SHA3_224/256/384/512_RSA_PKCS_PSS

**Hash/Digest (9):** SHA_1, SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512

**HMAC (11):** SHA_1_HMAC, SHA224_HMAC, SHA256_HMAC, SHA384_HMAC, SHA512_HMAC, SHA512_224_HMAC, SHA512_256_HMAC, SHA3_224_HMAC, SHA3_256_HMAC, SHA3_384_HMAC, SHA3_512_HMAC

**EC/ECDSA (6):** ECDSA, ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512, EC_EDWARDS_KEY_PAIR_GEN, ECDH1_DERIVE

**PQC (6):** ML_DSA, ML_DSA_KEY_PAIR_GEN, ML_KEM, ML_KEM_KEY_PAIR_GEN, SLH_DSA, SLH_DSA_KEY_PAIR_GEN

**Other (7):** EDDSA, DSA_SHA224, DSA_SHA256, CHACHA20_POLY1305, HKDF_DERIVE, PKCS5_PBKD2, RSA_PKCS_KEY_PAIR_GEN

### What's NOT Tested (~300 mechanisms)

#### Tier 1: Widely-Deployed, Should Be Tested (est. 40-50 mechanisms)

| Family | Gap | OASIS Mechanisms |
|--------|-----|-----------------|
| **RSA keygen/wrap** | No RSA_X_509, no RSA_PKCS_TPM_1_1 | ~5 variants |
| **AES modes** | No AES_CTR, AES_CFB*, AES_OFB, AES_CTS | ~6 variants |
| **AES key derivation** | No AES_CBC_ENCRYPT_DATA, AES_ECB_ENCRYPT_DATA | 2 variants |
| **ECDSA prehash** | Missing ECDSA_SHA1, ECDSA_SHA224 | 2 variants |
| **ECDH variants** | No cofactor ECDH, X9.42 DH variants | ~5 variants |
| **DH (Diffie-Hellman)** | Only PKCS variant; missing X9.42 DH | ~5 variants |
| **DSA** | Only SHA224/256; missing keygen, SHA1, SHA384/512 | ~8 variants |
| **HKDF** | Only DERIVE; missing HKDF_DATA, HKDF_KEY_GEN | 2 variants |
| **SP800-108 KDF** | Completely missing | ~6 variants (counter/feedback/pipeline) |
| **Generic secret** | Missing GENERIC_SECRET_KEY_GEN | 1 mechanism |

#### Tier 2: Modern/Important but Less Common (est. 50-60 mechanisms)

| Family | Gap | OASIS Mechanisms |
|--------|-----|-----------------|
| **PQC hash variants** | No HASH_ML_DSA_SHA*, HASH_SLH_DSA_SHA* | ~25 variants |
| **HSS/XMSS** | Completely missing (stateful hash sigs) | ~6 mechanisms |
| **KMAC** | Completely missing | 2 mechanisms |
| **BLAKE2** | Completely missing | ~4 mechanisms |
| **SHAKE** | Completely missing (XOF) | ~4 mechanisms |
| **TLS 1.2** | Completely missing (PRF, MAC) | ~8 mechanisms |
| **Poly1305** | Missing standalone (only via ChaCha20) | 1 mechanism |
| **Salsa20** | Completely missing | 2 mechanisms |
| **Double Ratchet** | Completely missing (Signal/MLS) | ~4 mechanisms |
| **X3DH** | Completely missing (Signal) | ~2 mechanisms |

#### Tier 3: Legacy/Regional/Specialized (est. 200+ mechanisms)

| Family | Gap | OASIS Mechanisms |
|--------|-----|-----------------|
| **DES/DES3** | Completely missing | ~22 mechanisms |
| **Camellia** | Completely missing | ~8 mechanisms |
| **ARIA** | Completely missing | ~8 mechanisms |
| **SEED** | Completely missing | ~8 mechanisms |
| **Blowfish** | Completely missing | ~4 mechanisms |
| **Twofish** | Completely missing | ~4 mechanisms |
| **GOST** | Completely missing (Russian crypto) | ~12 mechanisms |
| **SSL3** | Completely missing | ~8 mechanisms |
| **WTLS** | Completely missing (wireless TLS) | ~6 mechanisms |
| **IKE** | Completely missing (IPsec) | ~4 mechanisms |
| **CMS** | Completely missing | ~1 mechanism |
| **OTP** | Completely missing (HOTP/TOTP) | ~6 mechanisms |
| **CT-KIP** | Completely missing | ~3 mechanisms |
| **PBE (PKCS#5/12)** | Only PBKD2; missing PKCS5/12 variants | ~4 mechanisms |
| **Key derivation by encryption** | Missing ARIA/Camellia/SEED/DES variants | ~8 mechanisms |
| **NULL mechanism** | Missing | 1 mechanism |
| **Miscellaneous KDF** | Missing concatenation, XOR derivation | ~4 mechanisms |

### Mechanism Coverage Summary

```
Tested:     70 mechanisms (19%)
Tier 1 gap: ~45 mechanisms (widely deployed, high priority)
Tier 2 gap: ~55 mechanisms (modern/important)
Tier 3 gap: ~200 mechanisms (legacy/regional/specialized)
Total spec: ~370 mechanisms
```

---

## Domain 2: API Function Coverage

### What's Tested (~45 of 68 core functions)

**Fully covered categories:**
- Encryption: C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal
- Signing: C_SignInit, C_Sign, C_SignUpdate, C_SignFinal
- Verification: C_VerifyInit, C_Verify, C_VerifyUpdate, C_VerifyFinal
- Digesting: C_DigestInit, C_Digest, C_DigestUpdate, C_DigestFinal
- Key management: C_GenerateKey, C_GenerateKeyPair, C_WrapKey, C_DeriveKey
- KEM: C_EncapsulateKey, C_DecapsulateKey (v3.2)
- RNG: C_GenerateRandom
- Init: C_Initialize, C_Finalize, C_GetFunctionList

**Partially covered:**
- Object management: C_CreateObject, C_DestroyObject, C_GetAttributeValue, C_SetAttributeValue (tested via test_object.py, test_set_attribute.py, test_api_security.py), C_FindObjects* (tested via test_search.py), C_GetObjectSize (tested via test_object_size.py), but C_CopyObject has minimal coverage
- Session: C_OpenSession, C_CloseSession, C_Login, C_Logout tested; C_GetSessionInfo partial
- Slot/Token: C_GetSlotList, C_GetMechanismList, C_GetMechanismInfo tested; C_GetTokenInfo partial

### What's NOT Tested (~23 functions)

| Function | Version | Why It Matters |
|----------|---------|----------------|
| **C_GetInfo** | v2.40 | Library version info — basic but untested |
| **C_GetInterface / C_GetInterfaceList** | v3.0 | Interface negotiation (tested at loader level, not function level) |
| **C_GetSlotInfo** | v2.40 | Slot hardware/firmware info |
| **C_GetTokenInfo** | v2.40 | Token capabilities, flags, memory |
| **C_WaitForSlotEvent** | v2.40 | Hot-plug detection |
| **C_CloseAllSessions** | v2.40 | Bulk session teardown |
| **C_GetOperationState** | v2.40 | Save crypto operation state |
| **C_SetOperationState** | v2.40 | Restore crypto operation state |
| **C_LoginUser** | v3.0 | Context-specific login |
| **C_SessionCancel** | v3.0 | Cancel active operation |
| **C_CopyObject** | v2.40 | Clone objects with attribute changes |
| **C_SignRecoverInit / C_SignRecover** | v2.40 | RSA raw signature (data recovery) |
| **C_VerifyRecoverInit / C_VerifyRecover** | v2.40 | RSA raw verify (data recovery) |
| **C_DecryptInit (single-part path)** | v2.40 | Single-shot decrypt (multi-part covered) |
| **C_DigestKey** | v2.40 | Digest a key's value |
| **C_UnwrapKey** | v2.40 | Decrypt + import wrapped keys |
| **C_SeedRandom** | v2.40 | RNG seeding |
| **Message-based finalizers** | v3.0 | C_MessageEncryptFinal, etc. (4 functions) |
| **Async operations** | v3.0 | C_AsyncComplete, C_AsyncJoin, etc. (4 functions) |
| **Parallel functions** | v2.40 | C_GetFunctionStatus, C_CancelFunction (legacy) |

### API Function Summary

```
Tested:     ~45 functions (66%)
Gap:        ~23 functions (34%)
  Critical: C_GetOperationState/C_SetOperationState (state preservation)
  Critical: C_UnwrapKey (key import workflow)
  Important: Recovery functions (C_SignRecover, C_VerifyRecover)
  Important: v3.0+ functions (C_LoginUser, C_SessionCancel, async)
  Low:      Legacy parallel functions, C_WaitForSlotEvent
```

---

## Domain 3: Object Types & Attributes

### Object Type Coverage

| Object Type | CKO_ Code | Version | Tested | Coverage | Notes |
|-------------|-----------|---------|--------|----------|-------|
| CKO_DATA | 0x00 | v2.40 | YES | 60% | Basic CRUD tested |
| CKO_CERTIFICATE | 0x01 | v2.40 | YES | 31% | X.509 tested; WTLS and X.509-AC not tested |
| CKO_PUBLIC_KEY | 0x02 | v2.40 | YES | 40% | Missing VERIFY_RECOVER, ENCAPSULATE, templates |
| CKO_PRIVATE_KEY | 0x03 | v2.40 | YES | 31% | Missing SIGN_RECOVER, DECAPSULATE, templates |
| CKO_SECRET_KEY | 0x04 | v2.40 | YES | 64% | Best coverage; missing CHECK_VALUE, templates |
| CKO_DOMAIN_PARAMETERS | 0x06 | v2.40 | YES | 8% | Minimal — 1 reference only |
| CKO_HW_FEATURE | 0x05 | v2.40 | NO | 0% | Clock, monotonic counter, UI — untested |
| CKO_MECHANISM | 0x38 | v3.0 | NO | 0% | Parameter set probing — untested |
| CKO_PROFILE | 0x39 | v3.0 | YES | 100% | Complete |
| CKO_TRUST | — | v2.40 | NO | 0% | Trust binding — untested |
| CKO_VALIDATION | 0x3A | v3.1 | NO | 0% | CMVP/CC metadata — untested |
| CKO_OTP_KEY | 0x08 | v2.40 | NO | 0% | OTP token — untested |

### Attribute Coverage Highlights

**Well-tested attributes (>20 uses):** CKA_TOKEN (210), CKA_CLASS (178), CKA_VALUE (171), CKA_LABEL (140), CKA_SENSITIVE (133), CKA_EXTRACTABLE (103), CKA_KEY_TYPE (99), CKA_EC_PARAMS (53), CKA_ENCRYPT/DECRYPT/SIGN/VERIFY (46-49 each)

**Never-tested attribute categories (48+ attributes):**
- Template constraint attrs: CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE, CKA_DERIVE_TEMPLATE
- Recovery attrs: CKA_VERIFY_RECOVER, CKA_SIGN_RECOVER
- KEM attrs: CKA_ENCAPSULATE, CKA_DECAPSULATE (v3.2)
- Key provenance: CKA_KEY_GEN_MECHANISM, CKA_ALLOWED_MECHANISMS
- Date attrs: CKA_START_DATE, CKA_END_DATE (on keys)
- Security: CKA_WRAP_WITH_TRUSTED, CKA_ALWAYS_AUTHENTICATE
- Checksum: CKA_CHECK_VALUE (KCV)
- All OTP attrs (15), all HW Feature attrs (15+), all Trust attrs (11), all Validation attrs (11)
- Certificate attrs: CKA_CERTIFICATE_CATEGORY, CKA_URL, CKA_HASH_OF_SUBJECT_PUBLIC_KEY

### Attribute Enforcement Gaps

These attributes have **spec-defined behavior** that isn't verified:

| Enforcement Rule | Tested? | Impact |
|-----------------|---------|--------|
| CKA_COPYABLE can't go from FALSE to TRUE | NO | Copy protection bypass |
| CKA_DESTROYABLE prevents C_DestroyObject when FALSE | NO | Object lifecycle |
| CKA_SENSITIVE can't go from TRUE to FALSE | Partial | Key extraction protection |
| CKA_EXTRACTABLE can't go from FALSE to TRUE | Partial | Key export protection |
| CKA_ALWAYS_SENSITIVE reflects history | NO | Key provenance audit |
| CKA_NEVER_EXTRACTABLE reflects history | NO | Key provenance audit |
| CKA_LOCAL reflects generation origin | NO | Key provenance audit |
| CKA_ALLOWED_MECHANISMS restricts operations | NO | Mechanism restriction |
| CKA_WRAP_WITH_TRUSTED requires CKA_TRUSTED wrapping key | NO | Trusted key hierarchy |
| CKA_ALWAYS_AUTHENTICATE requires C_Login per operation | NO | Per-operation auth |

---

## Domain 4: Session & Token Semantics

### Tested

- Session open/close lifecycle
- Login/logout (USER, SO)
- UserAlreadyLoggedIn handling
- RW vs RO session distinction
- Token PIN management (C_InitPIN, C_SetPIN)
- Token initialization (C_InitToken)

### Not Tested

| Semantic | Spec Section | Impact |
|----------|-------------|--------|
| **Object visibility across sessions** | session_mgmt_functions.md | Session vs token objects |
| **RO session object restrictions** | session_mgmt_functions.md | Can't create token objects in RO |
| **Operation state save/restore** | C_GetOperationState / C_SetOperationState | Mid-operation migration |
| **Concurrent session limits** | Token-specific | Resource exhaustion |
| **Context-specific login** | C_LoginUser (v3.0) | Fine-grained access |
| **Session cancel semantics** | C_SessionCancel (v3.0) | Mid-operation abort |
| **Slot event notification** | C_WaitForSlotEvent | Hot-plug/remove |

---

## Domain 5: Return Code Compliance

**Status: STRONG** — 802/802 CKR spec entries documented, 148+ with active tests. This is the most complete domain. The existing `testcases/ckr/` directory (21 files, 102 tests) provides systematic CKR verification including raw ctypes bypass for wrapper-blocked conditions.

**Remaining gap:** CKR tests verify the return code IS correct, but don't systematically verify that ALL specified return codes for each function ARE testable. Some CKR conditions require specific hardware states (e.g., CKR_TOKEN_NOT_PRESENT, CKR_DEVICE_REMOVED) that can't be triggered in software.

---

## Proposed Sub-Project Decomposition

Given the scale (~300 mechanism gaps, ~23 function gaps, 6 untested object types, 48+ untested attributes), this decomposes into **8 sub-projects** ordered by impact:

### Phase A: Core API Completeness (est. 2-3 weeks)
- Missing API functions: C_UnwrapKey, C_CopyObject, C_GetOperationState/C_SetOperationState
- Recovery functions: C_SignRecover, C_VerifyRecover
- Discovery: C_GetInfo, C_GetSlotInfo, C_GetTokenInfo
- v3.0+ functions: C_LoginUser, C_SessionCancel, async lifecycle
- **Deliverable:** ~23 functions tested, API coverage → 100%

### Phase B: Object & Attribute Enforcement (est. 2-3 weeks)
- Untested object types: CKO_MECHANISM, CKO_TRUST, CKO_VALIDATION, CKO_HW_FEATURE
- Attribute enforcement: CKA_COPYABLE/DESTROYABLE, CKA_ALLOWED_MECHANISMS, template constraints
- Attribute provenance: CKA_LOCAL, CKA_KEY_GEN_MECHANISM, CKA_ALWAYS_SENSITIVE/NEVER_EXTRACTABLE
- Date attributes, CKA_CHECK_VALUE, CKA_ALWAYS_AUTHENTICATE
- **Deliverable:** 12/12 object types covered, attribute coverage → 60%+

### Phase C: Tier 1 Mechanism Gaps (est. 3-4 weeks)
- AES modes: CTR, CFB, OFB, CTS + key derivation by encryption
- ECDSA/ECDH variants: missing hash prehash, cofactor, X9.42
- DSA completeness: keygen, SHA1/384/512 variants
- DH/X9.42: full Diffie-Hellman coverage
- SP800-108 KDF: counter/feedback/pipeline
- HKDF remaining: DATA, KEY_GEN
- **Deliverable:** ~45 mechanisms added, coverage → 31%

### Phase D: PQC Hash Variants & Stateful Signatures (est. 2-3 weeks)
- HASH_ML_DSA_SHA* (10 variants)
- HASH_SLH_DSA_SHA* (10 variants)
- HSS/LMS stateful hash signatures (6 mechanisms)
- XMSS/XMSS-MT (6 mechanisms)
- KMAC, BLAKE2, SHAKE XOFs
- **Deliverable:** ~40 mechanisms added, coverage → 42%

### Phase E: Legacy & Regional Ciphers (est. 3-4 weeks)
- DES/DES3: all modes (ECB, CBC, OFB, CFB, MAC, key derivation)
- Camellia: all modes
- ARIA: all modes
- SEED: all modes
- Blowfish, Twofish
- GOST (28147-89, R 34.10-2001, R 34.11-94)
- **Deliverable:** ~80 mechanisms added, coverage → 63%

### Phase F: Protocol Mechanisms (est. 2-3 weeks)
- TLS 1.2 PRF and key material
- SSL3 key derivation
- WTLS mechanisms
- IKE mechanisms
- CMS signature
- PBE (PKCS#5 and PKCS#12 variants)
- **Deliverable:** ~30 mechanisms added, coverage → 71%

### Phase G: Specialized & Emerging (est. 2-3 weeks)
- OTP mechanisms (HOTP, TOTP, SecurID)
- CT-KIP
- Double Ratchet (Signal/MLS)
- Extended Triple DH (X3DH)
- NULL mechanism
- Salsa20, standalone Poly1305
- Miscellaneous KDFs (concatenation, XOR)
- **Deliverable:** ~25 mechanisms added, coverage → 78%

### Phase H: Session Semantics & Compliance Hardening (est. 2-3 weeks)
- Object visibility across sessions
- RO session restrictions
- Operation state save/restore
- Concurrent session limits
- Multi-level compliance reporting
- CKR coverage hardening (systematic per-function verification)
- **Deliverable:** Full session state machine coverage, compliance report generation

---

## Prioritization Recommendation

```
Month 1:  Phase A (API) + Phase B (Objects)     → Foundation complete
Month 2:  Phase C (Tier 1 Mechanisms)            → Core crypto covered
Month 3:  Phase D (PQC) + Phase F (Protocols)    → Modern + protocol coverage
Month 4:  Phase E (Legacy Ciphers)               → Regional/legacy coverage
Month 5:  Phase G (Specialized) + Phase H (Compliance) → Full spec coverage
```

After Month 2, pkcs11-check would be a **credible PKCS#11 compliance tool**. After Month 5, it would have **comprehensive OASIS spec coverage**.

---

## Test Pattern Recommendations

Each mechanism test should include (where applicable):

1. **Mechanism availability check** — skip cleanly if not supported
2. **Key generation** — verify keygen mechanism works
3. **Basic operation** — encrypt/decrypt, sign/verify, derive, wrap/unwrap round-trip
4. **Cross-verification** — compare against Python `cryptography` library
5. **Error paths** — wrong mechanism, wrong key type, invalid parameters
6. **Compliance notes** — document deviations via `compliance.note()`
7. **ACVP/Wycheproof vectors** — where available, test against known-answer vectors

Each object type test should include:

1. **Creation with mandatory attributes** — C_CreateObject succeeds
2. **Missing mandatory attribute rejection** — C_CreateObject fails correctly
3. **Read-only attribute enforcement** — C_SetAttributeValue rejects modification
4. **Default value verification** — unset optional attributes have spec-defined defaults
5. **Modifiability rules** — one-way flags (SENSITIVE, EXTRACTABLE) enforced
6. **Search by attributes** — C_FindObjects with various attribute filters
