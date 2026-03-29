# ACVP to PKCS#11 v3.2 Gap Analysis Report

**Date:** 2025-03-29  
**Scope:** Analysis of 160 ACVP test directories vs. PKCS#11 v3.2 mechanisms  
**Objective:** Identify which ACVP test vectors can be tested with standard PKCS#11 v3.2

---

## Executive Summary

| Status | Count | Percentage |
|--------|-------|------------|
| **Fully Mappable** | 126 | 78.8% |
| **Partially Mappable** | 18 | 11.2% |
| **Not Mappable** | 16 | 10.0% |
| **Total** | **160** | **100%** |

**Recommendation:** Focus implementation on the 126 fully mappable directories (~80% coverage), with selective implementation of partially mappable cases where feasible.

---

## Categories Not Mappable to PKCS#11 v3.2 (16 directories)

### 1. Format Preserving Encryption (FPE) - 2 directories

**Directories:**
- `ACVP-AES-FF1-1.0` - FF1 format-preserving encryption
- `ACVP-AES-FF3-1-1.0` - FF3 format-preserving encryption

**Reason:** Format Preserving Encryption (FPE) algorithms like FF1 and FF3 are **not standardized in PKCS#11 v3.2**. These are specialized algorithms for encrypting data while preserving its format (e.g., encrypting a credit card number to another valid-looking credit card number). FPE is primarily used in payment card industry and database tokenization.

**PKCS#11 Gap:** No `CKM_AES_FF1` or similar mechanism exists in the standard.

**Alternative:** Some modules may support FPE through vendor extensions, but no standard mechanism exists.

---

### 2. Lightweight Cryptography (Ascon) - 4 directories

**Directories:**
- `Ascon-AEAD128-SP800-232` - Ascon authenticated encryption
- `Ascon-CXOF128-SP800-232` - Ascon customizable XOF
- `Ascon-Hash256-SP800-232` - Ascon hash function
- `Ascon-XOF128-SP800-232` - Ascon extendable output function

**Reason:** Ascon is NIST's selected lightweight cryptographic standard (FIPS 232) but is **not yet in PKCS#11 v3.2**. Lightweight crypto is designed for constrained devices (IoT, embedded systems).

**PKCS#11 Gap:** No `CKM_ASCON_*` mechanisms defined. Ascon was standardized by NIST after PKCS#11 v3.2 release.

**Future:** May be added in PKCS#11 v3.3 or later.

---

### 3. Advanced Extendable Output Functions (XOFs) - 4 directories

**Directories:**
- `ParallelHash-128-1.0` - Parallelized hash construction
- `ParallelHash-256-1.0`
- `TupleHash-128-1.0` - Tuple hashing (fixed-size input sets)
- `TupleHash-256-1.0`

**Reason:** These are advanced XOF constructions from NIST SP 800-185 that are **not in PKCS#11 v3.2**. They support parallel processing and structured input hashing.

**PKCS#11 Gap:** Only basic SHAKE-128/256 are standardized. cSHAKE, ParallelHash, and TupleHash are absent.

**Note:** cSHAKE-128/256 (2 directories) are partially mappable but with customization string limitations.

---

### 4. Entropy Source & Conditioning - 5 directories

**Directories:**
- `safePrimes-keyGen-1.0` - Safe prime generation (for DH/SRP)
- `safePrimes-keyVer-1.0` - Safe prime verification
- `ConditioningComponent-AES-CBC-MAC-Sp800-90B` - Entropy conditioning
- `ConditioningComponent-BlockCipher_DF-Sp800-90B` - Block cipher derivation function
- `ConditioningComponent-Hash_DF-Sp800-90B` - Hash-based derivation function

**Reason:** These are related to **entropy source validation and conditioning** per NIST SP 800-90B. PKCS#11 is a cryptographic token interface, not an entropy source validation toolkit.

**PKCS#11 Gap:** 
- No safe prime generation mechanisms
- No entropy conditioning functions
- `C_SeedRandom` exists but doesn't provide entropy validation

**Scope Issue:** These are testing RNG entropy sources, not the cryptographic operations themselves.

---

### 5. Protocol Layer Tests - 1 directory

**Directory:**
- `KAS-KC-Sp800-56` - Key Confirmation (KC) tests

**Reason:** Key Confirmation is a **protocol-layer verification** that confirms both parties have derived the same key. It's part of key agreement protocols but is implemented at the protocol level, not as a standalone cryptographic primitive.

**PKCS#11 Gap:** No `CKM_KEY_CONFIRMATION` mechanism. Key confirmation is done by using the derived key (e.g., MAC calculation), not as a separate cryptographic operation.

---

## Categories Partially Mappable (18 directories)

These have PKCS#11 mechanisms but with significant limitations:

### DRBG/Random Number Generation - 3 directories

**Directories:**
- `ctrDRBG-1.0` - Counter mode DRBG
- `hashDRBG-1.0` - Hash-based DRBG
- `hmacDRBG-1.0` - HMAC-based DRBG

**PKCS#11 Mechanism:** `CKM_RANDOM_GENERATE`, `CKM_RANDOM_SEED`

**Limitation:** PKCS#11 provides **output** of the RNG but not **direct DRBG control**. ACVP tests require:
- Internal state manipulation (re-seeding, prediction resistance)
- Known-answer tests on DRBG internals
- Entropy input validation

**Workaround:** Can test that `C_GenerateRandom` produces correct-length output with expected statistical properties, but cannot test DRBG-specific features like reseeding counters or internal state.

**Recommendation:** Mark as "Partial - RNG output only, no DRBG internals"

---

### Key Agreement with RSA (IFC) - 3 directories

**Directories:**
- `KAS-IFC-Sp800-56Br2` - RSA-based key agreement
- `KAS-IFC-SSC-Sp800-56Br2` - RSA secret component transport
- `KTS-IFC-Sp800-56Br2` - RSA key transport scheme

**PKCS#11 Mechanism:** `CKM_RSA_PKCS_OAEP` (key transport/wrapping)

**Limitation:** PKCS#11 supports **key transport** (encrypting a key with RSA) but not true **key agreement** with RSA. Key agreement requires both parties to contribute entropy; RSA transport is one-way.

**Note:** SP 800-56B Rev 2 defines RSA-KEM (Key Encapsulation Method) which is supported via `CKM_RSA_PKCS_OAEP`, but full key agreement validation requires protocol-layer tests.

**Recommendation:** Test what we can (key transport/encapsulation) with clear documentation of limitations.

---

### KDF Variants - 6 directories

**Directories:**
- `KDA-OneStep-Sp800-56Cr1` - One-step KDF
- `KDA-OneStep-Sp800-56Cr2`
- `KDA-OneStepNoCounter-Sp800-56Cr2`
- `KDA-TwoStep-Sp800-56Cr1` - Two-step KDF
- `KDA-TwoStep-Sp800-56Cr2`
- `KDF-1.0` - Generic KDF

**PKCS#11 Mechanism:** Primarily `CKM_HKDF_DERIVE`, some vendor variants

**Limitation:** PKCS#11 has **HKDF** but SP 800-56Cr1/Cr2 defines multiple KDF variants (one-step, two-step, with/without counters). These differ in:
- PRF selection
- Counter handling
- Salt/IV management
- Output length derivation

**Workaround:** Many one-step/two-step KDFs are similar enough to HKDF for basic testing, but exact compliance may vary.

**Recommendation:** Implement with clear documentation of KDF variant mapping.

---

### cSHAKE (customizable SHAKE) - 2 directories

**Directories:**
- `cSHAKE-128-1.0` - Customizable SHAKE-128
- `cSHAKE-256-1.0` - Customizable SHAKE-256

**PKCS#11 Mechanism:** `CKM_SHAKE_128`, `CKM_SHAKE_256`

**Limitation:** cSHAKE allows a **customization string** (function name + customization) that modifies the hash output. Standard `CKM_SHAKE_*` doesn't expose the customization string parameter.

**Impact:** ACVP vectors with customization strings cannot be tested. Only basic SHAKE (no customization) is testable.

**Recommendation:** Test basic SHAKE, skip cSHAKE variants with customization.

---

### Protocol-Specific KDFs - 4 directories

**Directories:**
- `kdf-components-ansix9.42-1.0` - ANSI X9.42 DH KDF
- `kdf-components-ansix9.63-1.0` - ANSI X9.63 ECDH KDF
- `kdf-components-snmp-1.0` - SNMP KDF
- `kdf-components-tpm-1.0` - TPM-specific KDF

**PKCS#11 Mechanism:** Various `CKM_*_DERIVE` mechanisms

**Limitation:** These are **legacy or niche protocol-specific KDFs**. While PKCS#11 supports the underlying DH/ECDH operations, the specific KDF constructions may differ.

**Status:**
- ANSI X9.42: Similar to `CKM_X9_42_DH_DERIVE`
- ANSI X9.63: Similar to `CKM_ECDH1_DERIVE`
- SNMP: Not standardized in PKCS#11
- TPM: Vendor-specific (IBM CKM_IBM_* mechanisms exist)

**Recommendation:** Implement ANSI variants, skip SNMP and TPM (vendor-specific).

---

## Detailed Gap List (16 Not Mappable)

| Directory | Category | Reason | Future PKCS#11? |
|-----------|----------|--------|-----------------|
| ACVP-AES-FF1-1.0 | FPE | FPE not in v3.2 | Possible in v3.3 |
| ACVP-AES-FF3-1-1.0 | FPE | FPE not in v3.2 | Possible in v3.3 |
| Ascon-AEAD128-SP800-232 | Lightweight | Ascon not in v3.2 | Likely in v3.3+ |
| Ascon-CXOF128-SP800-232 | Lightweight | Ascon not in v3.2 | Likely in v3.3+ |
| Ascon-Hash256-SP800-232 | Lightweight | Ascon not in v3.2 | Likely in v3.3+ |
| Ascon-XOF128-SP800-232 | Lightweight | Ascon not in v3.2 | Likely in v3.3+ |
| ConditioningComponent-AES-CBC-MAC-Sp800-90B | Entropy | Entropy conditioning not in PKCS#11 | Unlikely |
| ConditioningComponent-BlockCipher_DF-Sp800-90B | Entropy | Entropy conditioning not in PKCS#11 | Unlikely |
| ConditioningComponent-Hash_DF-Sp800-90B | Entropy | Entropy conditioning not in PKCS#11 | Unlikely |
| KAS-KC-Sp800-56 | Protocol | Key confirmation is protocol-layer | Unlikely |
| ParallelHash-128-1.0 | Advanced XOF | ParallelHash not in PKCS#11 | Possible |
| ParallelHash-256-1.0 | Advanced XOF | ParallelHash not in PKCS#11 | Possible |
| TupleHash-128-1.0 | Advanced XOF | TupleHash not in PKCS#11 | Possible |
| TupleHash-256-1.0 | Advanced XOF | TupleHash not in PKCS#11 | Possible |
| safePrimes-keyGen-1.0 | Specialized | Safe primes not in PKCS#11 | Possible |
| safePrimes-keyVer-1.0 | Specialized | Safe primes not in PKCS#11 | Possible |

---

## Recommendations for Implementation Plan

### Immediate Implementation (126 Fully Mappable)
- **High Priority:** AES, HMAC, ECDSA, EdDSA, RSA Sign/Verify, PQC (ML-DSA, ML-KEM, SLH-DSA), SHA3, CMAC, KMAC
- **Medium Priority:** TLS KDF, SSH KDF, IKE KDF, ECDH, DH, PBKDF2
- **Low Priority:** TDES/3DES, DSA, RSA KeyGen, ECDH KeyGen

### Selective Implementation (18 Partially Mappable)
- **Worth Implementing:** SSH KDF, IKE KDF, SRTP KDF, cSHAKE (basic mode), ANSI X9.42/X9.63 KDFs
- **Document Limitations:** DRBG tests (RNG output only), RSA key transport (not true key agreement), KDF variants
- **Skip:** SNMP KDF, TPM KDF (too vendor-specific)

### Explicitly Exclude (16 Not Mappable)
- **Do Not Implement:** FPE (FF1/FF3), Ascon, ParallelHash, TupleHash, conditioning components, safe primes, KAS-KC
- **Document in Plan:** Explain why these are skipped with reference to this gap analysis
- **Future Consideration:** Ascon may be added when PKCS#11 v3.3 is released

---

## Updated Implementation Scope

**Original Plan:** 160 ACVP directories  
**Revised Plan:** ~144 directories (126 fully + ~18 selective partially)

**Efficiency Gain:** Focus resources on 90% of directories that provide value, avoid wasted effort on 10% that cannot be tested.

---

## Appendix: Why These Gaps Exist

1. **Timing:** PKCS#11 v3.2 was finalized in 2023. Newer algorithms (Ascon, FPE) hadn't been standardized yet.

2. **Scope:** PKCS#11 is a cryptographic token interface, not a protocol implementation toolkit. Protocol-layer tests (KAS-KC, some KDFs) are out of scope.

3. **Specialization:** Some tests (entropy conditioning, safe primes) are specialized validation suites for RNG certification, not general cryptographic operations.

4. **Complexity:** Advanced constructions (ParallelHash, TupleHash) add complexity that may not justify their use cases for hardware security modules.

5. **Hardware Constraints:** Lightweight crypto (Ascon) is designed for constrained devices; HSMs typically don't need it.

---

**Next Steps:**
1. Update implementation plan to reflect these gaps
2. Mark excluded directories in plan with reasons
3. Proceed with 126 fully mappable + selective partial implementation
4. Document limitations in test file docstrings
