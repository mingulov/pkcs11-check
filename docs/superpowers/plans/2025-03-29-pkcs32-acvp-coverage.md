# PKCS#11 v3.2 ACVP Test Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create comprehensive ACVP test coverage for all PKCS#11 v3.2 mechanisms across ~110 ACVP test vector directories

**Architecture:** 
- Expand existing ACVP tests (aes, hmac, ecdsa, eddsa, slhdsa) to cover all related ACVP directories
- Create new test files following the established pattern in `src/pkcs11_check/testcases/acvp/`
- Each test file corresponds to a PKCS#11 mechanism family (RSA, ECDH, CMAC, etc.)
- Tests skip gracefully when mechanisms not available in target module

**Tech Stack:** Python 3.11+, pytest, pkcs11_check.raw API, ACVP JSON test vectors

**Reference:** See existing `src/pkcs11_check/testcases/acvp/test_acvp_*.py` for patterns

---

## Overview

This plan implements test coverage for 160 ACVP data directories, of which ~110 map to PKCS#11 v3.2 mechanisms. Tests are organized into 3 phases by priority.

### Phase 1: High Priority (Core Cryptography)
Covers the most commonly used mechanisms across all PKCS#11 modules.

### Phase 2: Medium Priority (Extended Features)
Covers widely supported but less common mechanisms.

### Phase 3: Low Priority (Specialized/Legacy)
Covers legacy algorithms and specialized use cases.

---

## Phase 1: High Priority Tests

### Task 1.1: Expand AES ACVP Coverage

**Goal:** Add all remaining AES modes to existing `test_acvp_aes.py`

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_aes.py`
- Test vectors: `src/pkcs11_check/testcases/data/acvp/gen-val/json-files/ACVP-AES-*`

**ACVP Directories to Cover:**
- ACVP-AES-CBC-1.0 (already covered)
- ACVP-AES-CCM-1.0
- ACVP-AES-CCM-ECMA-1.0
- ACVP-AES-CTR-1.0 (already covered)
- ACVP-AES-ECB-1.0 (already covered)
- ACVP-AES-GCM-1.0 (already covered)
- ACVP-AES-GCM-SIV-1.0
- ACVP-AES-GMAC-1.0
- ACVP-AES-KW-1.0
- ACVP-AES-KWP-1.0
- ACVP-AES-OFB-1.0
- ACVP-AES-XTS-1.0
- ACVP-AES-XTS-2.0
- ACVP-AES-CFB1-1.0
- ACVP-AES-CFB8-1.0
- ACVP-AES-CFB128-1.0
- ACVP-AES-CBC-CS1-1.0
- ACVP-AES-CBC-CS2-1.0
- ACVP-AES-CBC-CS3-1.0
- ACVP-AES-XPN-1.0

**PKCS#11 Mechanisms:**
- CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_CTS (CS modes)
- CKM_AES_CCM, CKM_AES_GCM, CKM_AES_GCM_SIV
- CKM_AES_CTR, CKM_AES_CFB1, CKM_AES_CFB8, CKM_AES_CFB64, CKM_AES_CFB128, CKM_AES_OFB
- CKM_AES_XTS, CKM_AES_GMAC
- CKM_AES_KW, CKM_AES_KWP

**Implementation Pattern:**
```python
# Load vectors from ACVP-AES-{MODE}-1.0 directories
# Test both encrypt and decrypt where applicable
# Skip if mechanism not available
```

**Testing:**
- Run: `uv run python -m pytest src/pkcs11_check/testcases/acvp/test_acvp_aes.py -v`
- Verify all 20 directories produce passing or skipping tests

---

### Task 1.2: Create RSA Sign/Verify ACVP Tests

**Goal:** Create new test file for RSA signature operations

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_rsa.py`
- Test vectors: `src/pkcs11_check/testcases/data/acvp/gen-val/json-files/RSA-Sig*` and `RSA-sig*` directories

**ACVP Directories:**
- RSA-SigGen-FIPS186-4
- RSA-SigGen-FIPS186-5
- RSA-SigVer-FIPS186-2
- RSA-SigVer-FIPS186-4
- RSA-SigVer-FIPS186-5

**PKCS#11 Mechanisms:**
- CKM_RSA_PKCS (raw RSA sign/verify)
- CKM_SHA1_RSA_PKCS, CKM_SHA224_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS
- CKM_SHA1_RSA_PKCS_PSS, CKM_SHA224_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS

**Implementation Steps:**
- [ ] Step 1: Create test file structure with proper imports
- [ ] Step 2: Implement test_rsa_pkcs_sign_verify for raw RSA PKCS#1 v1.5
- [ ] Step 3: Implement test_rsa_pkcs_sign_verify_hashed for SHA*+RSA variants
- [ ] Step 4: Implement test_rsa_pss_sign_verify for RSA-PSS variants
- [ ] Step 5: Load ACVP vectors and validate expected results
- [ ] Step 6: Add proper skip logic for unsupported mechanisms/key sizes
- [ ] Step 7: Run tests and verify against multiple modules (SoftHSM2, NSS, etc.)
- [ ] Step 8: Document any module-specific findings in docs/module-issues.md
- [ ] Step 9: Commit

**Testing:**
- Run: `uv run python -m pytest src/pkcs11_check/testcases/acvp/test_acvp_rsa.py -v`

---

### Task 1.3: Expand ECDSA ACVP Coverage

**Goal:** Add key generation and verification tests to existing `test_acvp_ecdsa.py`

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py`
- Test vectors: ECDSA-KeyGen*, ECDSA-KeyVer*, DetECDSA-SigGen* directories

**ACVP Directories:**
- ECDSA-KeyGen-1.0
- ECDSA-KeyGen-FIPS186-5
- ECDSA-KeyVer-1.0
- ECDSA-KeyVer-FIPS186-5
- ECDSA-SigGen-1.0 (already covered)
- ECDSA-SigGen-FIPS186-5
- ECDSA-SigVer-1.0 (already covered)
- ECDSA-SigVer-FIPS186-5
- DetECDSA-SigGen-FIPS186-5

**PKCS#11 Mechanisms:**
- CKM_EC_KEY_PAIR_GEN
- CKM_ECDSA, CKM_ECDSA_SHA1, CKM_ECDSA_SHA224, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512

**Implementation Steps:**
- [ ] Step 1: Add key generation tests using ACVP vectors
- [ ] Step 2: Add key verification tests
- [ ] Step 3: Add deterministic ECDSA tests (DetECDSA)
- [ ] Step 4: Verify all curve types work (P-256, P-384, P-521)
- [ ] Step 5: Update documentation
- [ ] Step 6: Commit

---

### Task 1.4: Expand EdDSA ACVP Coverage

**Goal:** Add key generation and verification to existing `test_acvp_eddsa.py`

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py`
- Test vectors: EDDSA-KeyGen*, EDDSA-KeyVer* directories

**ACVP Directories:**
- EDDSA-KeyGen-1.0
- EDDSA-KeyVer-1.0
- EDDSA-SigGen-1.0 (already covered)
- EDDSA-SigVer-1.0 (already covered)

**PKCS#11 Mechanisms:**
- CKM_EDDSA

**Implementation Steps:**
- [ ] Step 1: Add Ed25519 and Ed448 key generation tests
- [ ] Step 2: Add key verification tests
- [ ] Step 3: Ensure tests work with both pure and prehash modes
- [ ] Step 4: Commit

---

### Task 1.5: Expand SLH-DSA ACVP Coverage

**Goal:** Add key generation and verification to existing `test_acvp_slhdsa.py`

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_slhdsa.py`
- Test vectors: SLH-DSA-* directories

**ACVP Directories:**
- SLH-DSA-keyGen-FIPS205
- SLH-DSA-sigGen-FIPS205
- SLH-DSA-sigVer-FIPS205

**PKCS#11 Mechanisms:**
- All 13 SLH-DSA variants (SHA2 and SHAKE, S and F variants)

**Implementation Steps:**
- [ ] Step 1: Add key generation tests for all parameter sets
- [ ] Step 2: Expand signature tests to cover all variants
- [ ] Step 3: Commit

---

### Task 1.6: Create ML-DSA ACVP Tests

**Goal:** Create comprehensive ML-DSA (FIPS 204) tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py`
- Test vectors: ML-DSA-* directories

**ACVP Directories:**
- ML-DSA-keyGen-FIPS204
- ML-DSA-sigGen-FIPS204
- ML-DSA-sigVer-FIPS204

**PKCS#11 Mechanisms:**
- CKM_ML_DSA, CKM_ML_DSA_44, CKM_ML_DSA_65, CKM_ML_DSA_87
- CKM_HASH_ML_DSA_44, CKM_HASH_ML_DSA_65, CKM_HASH_ML_DSA_87

**Implementation Steps:**
- [ ] Step 1: Create test file with imports
- [ ] Step 2: Implement key generation tests (ML-DSA-44, 65, 87)
- [ ] Step 3: Implement sign/verify tests
- [ ] Step 4: Implement hash-ML-DSA variant tests
- [ ] Step 5: Verify against Kryoptic (main PQC module)
- [ ] Step 6: Document findings
- [ ] Step 7: Commit

---

### Task 1.7: Create ML-KEM ACVP Tests

**Goal:** Create ML-KEM (FIPS 203) encapsulation/decapsulation tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py`
- Test vectors: ML-KEM-* directories

**ACVP Directories:**
- ML-KEM-keyGen-FIPS203
- ML-KEM-encapDecap-FIPS203

**PKCS#11 Mechanisms:**
- CKM_ML_KEM, CKM_ML_KEM_512, CKM_ML_KEM_768, CKM_ML_KEM_1024

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement key generation tests
- [ ] Step 3: Implement encapsulation/decapsulation tests
- [ ] Step 4: Test against Kryoptic/NSS-PQC
- [ ] Step 5: Commit

---

### Task 1.8: Create RSA Key Generation ACVP Tests

**Goal:** Create RSA key generation tests per FIPS 186-4/5

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_rsa_keygen.py`
- Test vectors: RSA-KeyGen* directories

**ACVP Directories:**
- RSA-KeyGen-FIPS186-4
- RSA-KeyGen-FIPS186-5

**PKCS#11 Mechanisms:**
- CKM_RSA_PKCS_KEY_PAIR_GEN

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement key generation tests with ACVP vectors
- [ ] Step 3: Verify generated keys meet ACVP criteria
- [ ] Step 4: Test various key sizes
- [ ] Step 5: Commit

---

## Phase 2: Medium Priority Tests

### Task 2.1: Expand HMAC ACVP Coverage

**Goal:** Add all HMAC-SHA* and HMAC-SHA3* variants to `test_acvp_hmac.py`

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_hmac.py`
- Test vectors: HMAC-* directories

**ACVP Directories:**
- All 22 HMAC directories (SHA1, SHA2-224/256/384/512, SHA2-512/224, SHA2-512/256, SHA3 variants)

**PKCS#11 Mechanisms:**
- CKM_SHA_1_HMAC, CKM_SHA224_HMAC, CKM_SHA256_HMAC, CKM_SHA384_HMAC, CKM_SHA512_HMAC
- CKM_SHA3_224_HMAC, CKM_SHA3_256_HMAC, CKM_SHA3_384_HMAC, CKM_SHA3_512_HMAC

**Implementation Steps:**
- [ ] Step 1: Add missing HMAC-SHA2 variants
- [ ] Step 2: Add all HMAC-SHA3 variants
- [ ] Step 3: Add truncated output tests
- [ ] Step 4: Commit

---

### Task 2.2: Create SHA/Hash ACVP Tests

**Goal:** Create SHA-3 and SHAKE hash function tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_hash.py`
- Test vectors: SHA3-*, SHAKE-* directories

**ACVP Directories:**
- SHA3-224-2.0, SHA3-256-2.0, SHA3-384-2.0, SHA3-512-2.0
- SHAKE-128-1.0, SHAKE-128-FIPS202, SHAKE-256-1.0, SHAKE-256-FIPS202

**PKCS#11 Mechanisms:**
- CKM_SHA3_224, CKM_SHA3_256, CKM_SHA3_384, CKM_SHA3_512
- CKM_SHAKE_128, CKM_SHAKE_256

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement SHA3 digest tests
- [ ] Step 3: Implement SHAKE XOF tests
- [ ] Step 4: Commit

---

### Task 2.3: Create CMAC ACVP Tests

**Goal:** Create AES-CMAC and TDES-CMAC tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_cmac.py`
- Test vectors: CMAC-* directories

**ACVP Directories:**
- CMAC-AES-1.0
- CMAC-TDES-1.0

**PKCS#11 Mechanisms:**
- CKM_AES_CMAC, CKM_AES_CMAC_GENERAL

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement CMAC-AES tests
- [ ] Step 3: Implement CMAC-TDES tests
- [ ] Step 4: Commit

---

### Task 2.4: Create KMAC ACVP Tests

**Goal:** Create KMAC-128 and KMAC-256 tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_kmac.py`
- Test vectors: KMAC-* directories

**ACVP Directories:**
- KMAC-128-1.0
- KMAC-256-1.0

**PKCS#11 Mechanisms:**
- CKM_KMAC_128, CKM_KMAC_256

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement KMAC tests
- [ ] Step 3: Commit

---

### Task 2.5: Create ECDH ACVP Tests

**Goal:** Create Elliptic Curve Diffie-Hellman key agreement tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py`
- Test vectors: KAS-ECC* directories

**ACVP Directories:**
- KAS-ECC-1.0
- KAS-ECC-CDH-Component-1.0
- KAS-ECC-Sp800-56Ar3
- KAS-ECC-CDH-Component-Sp800-56Ar3

**PKCS#11 Mechanisms:**
- CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement ECDH key agreement tests
- [ ] Step 3: Test with various curves (P-256, P-384, P-521)
- [ ] Step 4: Commit

---

## Phase 3: Low Priority Tests

### Task 3.1: Create TDES/3DES ACVP Tests

**Goal:** Create Triple DES tests (legacy support)

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_tdes.py`
- Test vectors: ACVP-TDES-* directories

**ACVP Directories:**
- All 13 TDES directories (CBC, ECB, CFB, OFB, CTR, KW, CI variants)

**PKCS#11 Mechanisms:**
- All CKM_DES3_* variants

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement all TDES mode tests
- [ ] Step 3: Commit

---

### Task 3.2: Create DSA ACVP Tests

**Goal:** Create DSA tests (legacy digital signature algorithm)

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_dsa.py`
- Test vectors: DSA-* directories

**ACVP Directories:**
- DSA-KeyGen-1.0
- DSA-PQGGen-1.0
- DSA-PQGVer-1.0
- DSA-SigGen-1.0
- DSA-SigVer-1.0

**PKCS#11 Mechanisms:**
- CKM_DSA, CKM_DSA_SHA1, CKM_DSA_SHA224, CKM_DSA_SHA256, CKM_DSA_SHA384, CKM_DSA_SHA512

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement DSA key generation
- [ ] Step 3: Implement DSA parameter generation/validation
- [ ] Step 4: Implement DSA sign/verify
- [ ] Step 5: Commit

---

### Task 3.3: Create RSA Primitives ACVP Tests

**Goal:** Create RSA raw operation tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_rsa_primitives.py`
- Test vectors: RSA-*Primitive* directories

**ACVP Directories:**
- RSA-decryptionPrimitive-1.0
- RSA-DecryptionPrimitive-Sp800-56Br2
- RSA-signaturePrimitive-1.0
- RSA-SignaturePrimitive-2.0

**PKCS#11 Mechanisms:**
- CKM_RSA_X_509

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement raw RSA decrypt/encrypt primitives
- [ ] Step 3: Implement raw RSA sign/verify primitives
- [ ] Step 4: Commit

---

### Task 3.4: Create LMS ACVP Tests

**Goal:** Create LMS (Leighton-Micali Signature) tests - stateful hash-based

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_lms.py`
- Test vectors: LMS-* directories

**ACVP Directories:**
- LMS-keyGen-1.0
- LMS-sigGen-1.0
- LMS-sigVer-1.0

**PKCS#11 Mechanisms:**
- CKM_LMS (if supported)

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement LMS tests (note: stateful - may need special handling)
- [ ] Step 3: Commit

---

### Task 3.5: Create KDF Protocol Tests (SSH/IKE/SNMP)

**Goal:** Create protocol-specific KDF tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_protocol_kdf.py`
- Test vectors: kdf-components-* directories

**ACVP Directories:**
- kdf-components-ssh-1.0
- kdf-components-IKEv1-1.0
- kdf-components-ikev2-1.0
- kdf-components-snmp-1.0
- kdf-components-srtp-1.0
- kdf-components-tls-1.0
- kdf-components-tpm-1.0
- kdf-components-ansix9.42-1.0
- kdf-components-ansix9.63-1.0

**PKCS#11 Mechanisms:**
- CKM_NSS_IKE_DERIVE and various vendor-specific KDFs

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement SSH KDF tests
- [ ] Step 3: Implement IKEv1/v2 KDF tests
- [ ] Step 4: Implement SNMP KDF tests
- [ ] Step 5: Commit

---

### Task 3.6: Create TLS KDF ACVP Tests

**Goal:** Create TLS 1.2 and 1.3 KDF tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_tls_kdf.py`
- Test vectors: TLS-v1.* directories

**ACVP Directories:**
- TLS-v1.2-KDF-RFC7627
- TLS-v1.3-KDF-RFC8446

**PKCS#11 Mechanisms:**
- CKM_TLS12_MASTER_KEY_DERIVE
- CKM_TLS12_KEY_MAT_DERIVE
- CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement TLS 1.2 KDF tests
- [ ] Step 3: Implement TLS 1.3 KDF tests (if supported)
- [ ] Step 4: Commit

---

### Task 3.7: Create DH/FFC ACVP Tests

**Goal:** Create Finite Field Cryptography (DH) key agreement tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_dh.py`
- Test vectors: KAS-FFC* directories

**ACVP Directories:**
- KAS-FFC-1.0
- KAS-FFC-Sp800-56Ar3

**PKCS#11 Mechanisms:**
- CKM_DH_PKCS_DERIVE
- CKM_DH_PKCS_KEY_PAIR_GEN

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement DH key agreement tests
- [ ] Step 3: Commit

---

### Task 3.8: Create RSA Key Agreement ACVP Tests

**Goal:** Create RSA-based key agreement tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_rsa_ka.py`
- Test vectors: KAS-IFC*, KTS-IFC* directories

**ACVP Directories:**
- KAS-IFC-Sp800-56Br2
- KAS-IFC-SSC-Sp800-56Br2
- KTS-IFC-Sp800-56Br2

**PKCS#11 Mechanisms:**
- CKM_RSA_PKCS_OAEP (for key transport)

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement RSA key agreement tests
- [ ] Step 3: Commit

---

### Task 3.9: Create DRBG ACVP Tests

**Goal:** Create Deterministic Random Bit Generator tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_drbg.py`
- Test vectors: *DRBG-1.0 directories

**ACVP Directories:**
- ctrDRBG-1.0
- hashDRBG-1.0
- hmacDRBG-1.0

**PKCS#11 Mechanisms:**
- CKM_RANDOM_SEED
- CKM_RANDOM_GENERATE

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement DRBG tests (note: may not map directly to PKCS#11)
- [ ] Step 3: Commit

---

### Task 3.10: Create PBKDF ACVP Tests

**Goal:** Create Password-Based Key Derivation Function tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_pbkdf.py`
- Test vectors: PBKDF-1.0 directory

**ACVP Directories:**
- PBKDF-1.0

**PKCS#11 Mechanisms:**
- CKM_PKCS5_PBKD2

**Implementation Steps:**
- [ ] Step 1: Create test file
- [ ] Step 2: Implement PBKDF2 tests
- [ ] Step 3: Commit

---

## Cross-Cutting Concerns

### Task X.1: Create Shared ACVP Utilities

**Goal:** Extract common ACVP test utilities to reduce duplication

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/_acvp_common.py`

**Utilities Needed:**
- ACVP JSON vector loading
- Hex string conversion helpers
- Mechanism availability checking
- Test result validation
- Skip decorators for ACVP-specific conditions

**Implementation Steps:**
- [ ] Step 1: Create utility module
- [ ] Step 2: Refactor existing tests to use utilities
- [ ] Step 3: Ensure all new tests import from common module
- [ ] Step 4: Commit

---

### Task X.2: Create ACVP conftest.py

**Goal:** Add ACVP-specific pytest configuration and fixtures

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/conftest.py`

**Fixtures Needed:**
- `acvp_data_dir` - Path to ACVP test vectors
- `acvp_vector_loader` - Helper to load ACVP JSON files
- Module-specific skip markers

**Implementation Steps:**
- [ ] Step 1: Create conftest.py
- [ ] Step 2: Add ACVP-specific fixtures
- [ ] Step 3: Add markers for ACVP test categories
- [ ] Step 4: Commit

---

### Task X.3: Update Module Documentation

**Goal:** Document any new findings in module-issues.md

**Files:**
- Modify: `docs/module-issues.md`

**As each test file is created/verified:**
- Document any mechanism limitations found
- Add xfail markers for known module issues
- Update pass/fail statistics after full test runs

**Implementation Steps:**
- [ ] Step 1: Run full ACVP test suite against each module
- [ ] Step 2: Document findings per module
- [ ] Step 3: Commit

---

## Implementation Order Summary

### Week 1-2: Phase 1 (Core)
1. Task 1.1: Expand AES
2. Task 1.2: Create RSA Sign/Verify
3. Task 1.3: Expand ECDSA
4. Task 1.4: Expand EdDSA
5. Task 1.5: Expand SLH-DSA
6. Task 1.6: Create ML-DSA
7. Task 1.7: Create ML-KEM
8. Task 1.8: Create RSA KeyGen

### Week 3-4: Phase 2 (Extended)
1. Task 2.1: Expand HMAC
2. Task 2.2: Create Hash/SHA
3. Task 2.3: Create CMAC
4. Task 2.4: Create KMAC
5. Task 2.5: Create ECDH

### Week 5-6: Phase 3 (Specialized)
1. Task 3.1-3.10: All remaining tests
2. Task X.1-3: Shared utilities and documentation

---

## Success Criteria

- [ ] All 160 ACVP directories analyzed and mapped
- [ ] ~110 mappable directories have test coverage
- [ ] All PKCS#11 v3.2 mechanisms have ACVP tests where applicable
- [ ] Tests pass on at least 3 modules (SoftHSM2, Kryoptic, NSS-PQC)
- [ ] Proper skip logic for unsupported mechanisms
- [ ] Module-specific findings documented
- [ ] Code follows existing patterns (follow `test_acvp_aes.py` as reference)

---

## Notes for Implementers

1. **Pattern to Follow:** Study `src/pkcs11_check/testcases/acvp/test_acvp_aes.py` for:
   - How to load ACVP JSON vectors
   - How to use `p11_raw_session` fixture
   - How to check mechanism availability with `rs.has_mechanism()`
   - How to use `pytest.skip()` for unsupported features
   - How to structure test classes

2. **Test Organization:** Each test file should:
   - Have a docstring explaining what ACVP vectors it tests
   - Use parametrized tests for multiple test vectors
   - Include both positive (valid) and negative (invalid) test cases
   - Handle edge cases (empty input, large input, etc.)

3. **Module Compatibility:**
   - Tests must work across different PKCS#11 modules
   - Use mechanism availability checks to skip unsupported features
   - Document module-specific quirks in `docs/module-issues.md`

4. **Performance:**
   - Large vector sets should use efficient loading patterns
   - Consider caching vector loading between tests
   - Use fixtures for expensive setup operations

5. **Error Handling:**
   - Validate expected return codes (CKR_OK for success)
   - Handle module-specific error code differences
   - Use specific CKR constants, not generic Exception catching
