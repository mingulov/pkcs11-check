# ACVP Test Implementation Plan - Phase 1 (High Priority)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
> 
> **Review Policy:** Each task requires review and approval before proceeding to the next task.

**Goal:** Implement comprehensive ACVP test coverage for 126 fully mappable directories across PKCS#11 v3.2 mechanisms

**Architecture:** 
- Create/expand test files in `src/pkcs11_check/testcases/acvp/`
- Each file uses ACVP JSON vectors from `src/pkcs11_check/testcases/data/acvp/`
- Tests validate against Kryoptic, SoftHSM2, and NSS-PQC modules
- Pattern follows existing `test_acvp_aes.py` structure

**Tech Stack:** Python 3.11+, pytest, pkcs11_check.raw API, ACVP test vectors

**Multi-Module Testing Strategy:**
- **Kryoptic:** Primary PQC testing (ML-DSA, ML-KEM, SLH-DSA)
- **SoftHSM2:** Primary legacy testing (RSA, ECDSA, AES, HMAC)
- **NSS-PQC:** Secondary PQC validation

---

## Implementation Phases

### Phase 1: Core Cryptography (Weeks 1-2)
- AES expansion (Task 1)
- RSA Sign/Verify (Task 2)
- ECDSA expansion (Task 3)
- EdDSA expansion (Task 4)

### Phase 2: Post-Quantum Crypto (Week 3)
- ML-DSA (Task 5)
- ML-KEM (Task 6)
- SLH-DSA expansion (Task 7)

### Phase 3: Extended Features (Week 4)
- HMAC expansion (Task 8)
- Hash/SHA3 (Task 9)
- RSA KeyGen (Task 10)
- ECDH (Task 11)

---

## Task 1: Expand AES ACVP Coverage

**Goal:** Add all remaining AES modes to `test_acvp_aes.py`

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_aes.py`

**ACVP Directories to Add:**
- ACVP-AES-CCM-1.0, ACVP-AES-CCM-ECMA-1.0
- ACVP-AES-GCM-SIV-1.0
- ACVP-AES-GMAC-1.0
- ACVP-AES-KW-1.0, ACVP-AES-KWP-1.0
- ACVP-AES-XTS-1.0, ACVP-AES-XTS-2.0
- ACVP-AES-CFB1-1.0, ACVP-AES-CFB8-1.0, ACVP-AES-CFB128-1.0
- ACVP-AES-OFB-1.0
- ACVP-AES-CBC-CS1-1.0, ACVP-AES-CBC-CS2-1.0, ACVP-AES-CBC-CS3-1.0
- ACVP-AES-XPN-1.0

**New PKCS#11 Mechanisms to Test:**
- CKM_AES_CCM, CKM_AES_GCM_SIV, CKM_AES_GMAC
- CKM_AES_KW, CKM_AES_KWP
- CKM_AES_XTS
- CKM_AES_CFB1, CKM_AES_CFB8, CKM_AES_CFB128
- CKM_AES_OFB, CKM_AES_CTS (CBC-CS modes)

---

### Subtask 1.1: Add CCM Mode Tests

**Steps:**

- [ ] **Step 1: Load ACVP-AES-CCM-1.0 vectors**

```python
# In test_acvp_aes.py, add CCM vector loading
ccm_files = [
    "ACVP-AES-CCM-1.0/internalProjection.json",
    # Load all CCM test files
]
```

- [ ] **Step 2: Create TestAesCcm class**

```python
class TestAesCcm:
    """AES-CCM tests per ACVP-AES-CCM-1.0"""
    
    def test_ccm_encrypt(self, p11_raw_session, vec):
        # Test CCM encryption with ACVP vectors
        pass
        
    def test_ccm_decrypt(self, p11_raw_session, vec):
        # Test CCM decryption with ACVP vectors  
        pass
```

- [ ] **Step 3: Test against SoftHSM2**

```bash
# Run specific CCM tests
bash local-builds/test.sh softhsm2 -v src/pkcs11_check/testcases/acvp/test_acvp_aes.py::TestAesCcm
```

- [ ] **Step 4: Document findings**

Check if SoftHSM2 supports CKM_AES_CCM. Document in `docs/module-issues.md` if:
- Mechanism advertised but fails
- Returns unexpected CKR codes
- Has implementation quirks

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/testcases/acvp/test_acvp_aes.py
git commit -m "feat(acvp): add AES-CCM tests from ACVP vectors

- Load ACVP-AES-CCM-1.0 test vectors
- Implement encrypt/decrypt tests
- Add skip logic for modules without CCM support
- Tested against: [list modules]"
```

---

### Subtask 1.2: Add XTS Mode Tests

**Steps:**

- [ ] **Step 1: Load ACVP-AES-XTS vectors**

```python
xts_files = [
    "ACVP-AES-XTS-1.0/internalProjection.json",
    "ACVP-AES-XTS-2.0/internalProjection.json",
]
```

- [ ] **Step 2: Create TestAesXts class**

```python
class TestAesXts:
    """AES-XTS tests per ACVP-AES-XTS-1.0/2.0"""
    
    def test_xts_encrypt(self, p11_raw_session, vec):
        # XTS requires two keys (data + tweak)
        pass
```

- [ ] **Step 3: Test against SoftHSM2 and Kryoptic**

```bash
bash local-builds/test.sh softhsm2 -v -k test_xts
bash local-builds/test.sh kryoptic -v -k test_xts
```

**Note:** SoftHSM2 advertises CKM_AES_CTS but it's not fully implemented. Expect skips.

- [ ] **Step 4: Commit**

---

### Subtask 1.3: Add Key Wrap Tests (KW/KWP)

**Steps:**

- [ ] **Step 1: Load ACVP-AES-KW and ACVP-AES-KWP vectors**

- [ ] **Step 2: Create TestAesKeyWrap class**

```python
class TestAesKeyWrap:
    """AES Key Wrap per RFC 3394/5649"""
    
    def test_kw_wrap(self, p11_raw_session, vec):
        # Test CKM_AES_KW
        pass
        
    def test_kwp_wrap(self, p11_raw_session, vec):
        # Test CKM_AES_KWP (with padding)
        pass
```

- [ ] **Step 3: Test against SoftHSM2**

SoftHSM2 has known issues with AES-KWP - may produce wrong output. Document findings.

- [ ] **Step 4: Commit**

---

### Subtask 1.4: Add CFB and OFB Mode Tests

**Steps:**

- [ ] **Step 1: Load CFB1, CFB8, CFB128, OFB vectors**

- [ ] **Step 2: Create TestAesCfbOfb class**

```python
class TestAesCfbOfb:
    """AES-CFB and AES-OFB modes"""
    
    def test_cfb1_encrypt(self, p11_raw_session, vec):
        # 1-bit CFB mode
        pass
        
    def test_cfb8_encrypt(self, p11_raw_session, vec):
        # 8-bit CFB mode
        pass
        
    def test_cfb128_encrypt(self, p11_raw_session, vec):
        # 128-bit CFB mode
        pass
        
    def test_ofb_encrypt(self, p11_raw_session, vec):
        # OFB mode
        pass
```

- [ ] **Step 3: Test against SoftHSM2**

- [ ] **Step 4: Commit**

---

### Task 1 Review Checkpoint

**Before proceeding to Task 2:**

1. **Code Review:**
   - Review `test_acvp_aes.py` changes
   - Verify all 12 new AES modes covered
   - Check skip logic works correctly

2. **Test Results Review:**
   - SoftHSM2: Run full suite, document failures
   - Kryoptic: Verify XTS behavior
   - NSS: Check AES-GCM support

3. **Documentation Review:**
   - Update `docs/module-issues.md` with AES findings
   - Add any new quirks discovered

4. **Commit Review:**
   - Ensure clean commit history
   - Verify no debug code left

**Approval Gate:** Get user approval before Task 2

---

## Task 2: Create RSA Sign/Verify ACVP Tests

**Goal:** Create comprehensive RSA signature tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_rsa.py`

**ACVP Directories:**
- RSA-SigGen-FIPS186-4
- RSA-SigGen-FIPS186-5
- RSA-SigVer-FIPS186-2
- RSA-SigVer-FIPS186-4
- RSA-SigVer-FIPS186-5

**PKCS#11 Mechanisms:**
- CKM_RSA_PKCS (raw RSA)
- CKM_SHA1_RSA_PKCS through CKM_SHA512_RSA_PKCS
- CKM_SHA1_RSA_PKCS_PSS through CKM_SHA512_RSA_PKCS_PSS
- CKM_SHA3_*_RSA_PKCS and CKM_SHA3_*_RSA_PKCS_PSS

---

### Subtask 2.1: Create Test File Structure

**Steps:**

- [ ] **Step 1: Create file with imports and docstring**

```python
"""NIST ACVP RSA signature test vectors.

Tests RSA-PKCS#1 v1.5 and RSA-PSS signatures using official NIST
ACVP vectors. Covers key sizes 2048/3072/4096 with various hash
algorithms.

Requires: scripts/fetch-optional-data.sh acvp

Vector files:
  - RSA-SigGen-FIPS186-4: RSA signature generation
  - RSA-SigGen-FIPS186-5: Updated FIPS 186-5 vectors
  - RSA-SigVer-FIPS186-2/4/5: RSA signature verification
"""

from __future__ import annotations
import json
from typing import Any
import pytest
from pkcs11_check.raw.recipes import (
    gen_rsa_keypair,
    sign_single,
    verify_single,
    import_rsa_public_key,
    import_rsa_private_key,
    destroy_quietly,
)
from pkcs11_check.raw.types_std import (
    CKA_SIGN, CKA_VERIFY,
    CKM_RSA_PKCS,
    CKM_SHA1_RSA_PKCS, CKM_SHA224_RSA_PKCS, CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
    CKM_SHA1_RSA_PKCS_PSS, CKM_SHA224_RSA_PKCS_PSS,
    CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512_RSA_PKCS_PSS,
)

# Map hash names to PKCS#11 mechanisms
_RSA_PKCS_MECHANISMS = {
    "SHA-1": CKM_SHA1_RSA_PKCS,
    "SHA2-224": CKM_SHA224_RSA_PKCS,
    "SHA2-256": CKM_SHA256_RSA_PKCS,
    "SHA2-384": CKM_SHA384_RSA_PKCS,
    "SHA2-512": CKM_SHA512_RSA_PKCS,
}

_RSA_PSS_MECHANISMS = {
    "SHA-1": CKM_SHA1_RSA_PKCS_PSS,
    "SHA2-224": CKM_SHA224_RSA_PKCS_PSS,
    "SHA2-256": CKM_SHA256_RSA_PKCS_PSS,
    "SHA2-384": CKM_SHA384_RSA_PKCS_PSS,
    "SHA2-512": CKM_SHA512_RSA_PKCS_PSS,
}
```

- [ ] **Step 2: Add vector loading function**

```python
def _load_rsa_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load RSA signature vectors from ACVP files."""
    vectors = []
    # Load from RSA-SigGen* and RSA-SigVer* directories
    return vectors
```

- [ ] **Step 3: Commit skeleton**

```bash
git add src/pkcs11_check/testcases/acvp/test_acvp_rsa.py
git commit -m "feat(acvp): create RSA signature test skeleton

- Add test file structure
- Define mechanism mappings
- Add vector loading infrastructure"
```

---

### Subtask 2.2: Implement PKCS#1 v1.5 Signature Tests

**Steps:**

- [ ] **Step 1: Create TestRsaPkcs15 class**

```python
class TestRsaPkcs15:
    """RSA-PKCS#1 v1.5 signature tests"""
    
    @pytest.mark.parametrize("vec_id,vec", _load_rsa_vectors())
    def test_rsa_pkcs15_sign_verify(self, p11_raw_session, vec_id, vec):
        # Test sign and verify with ACVP vectors
        pass
```

- [ ] **Step 2: Implement test logic**

```python
def test_rsa_pkcs15_sign_verify(self, p11_raw_session: Any, vec_id: str, vec: dict) -> None:
    rs = p11_raw_session
    hash_alg = vec["hashAlg"]
    mechanism = _RSA_PKCS_MECHANISMS.get(hash_alg)
    
    if not mechanism:
        pytest.skip(f"Hash algorithm {hash_alg} not supported")
    
    if not rs.has_mechanism(mechanism):
        pytest.skip(f"Mechanism {mechanism} not available")
    
    # Load or generate RSA key
    # Sign message from vector
    # Verify signature
    # Compare with expected result
```

- [ ] **Step 3: Test against SoftHSM2**

```bash
bash local-builds/test.sh softhsm2 -v src/pkcs11_check/testcases/acvp/test_acvp_rsa.py::TestRsaPkcs15
```

- [ ] **Step 4: Document findings**

Known issue: SoftHSM2 RSA-OAEP only supports SHA-1. Document RSA-PKCS#1 v1.5 findings.

- [ ] **Step 5: Commit**

---

### Subtask 2.3: Implement RSA-PSS Signature Tests

**Steps:**

- [ ] **Step 1: Create TestRsaPss class**

```python
class TestRsaPss:
    """RSA-PSS signature tests per FIPS 186-4/5"""
    
    def test_rsa_pss_sign_verify(self, p11_raw_session, vec_id, vec):
        # Test PSS with various salt lengths
        pass
```

- [ ] **Step 2: Implement with PSS parameters**

```python
from pkcs11_check.raw.pack import mech_pss

# Build PSS params from vector
pss_param = mech_pss(
    mechanism,
    hash_mech=hash_mech,
    mgf=mgf,
    salt_len=s_len
)
```

- [ ] **Step 3: Test against SoftHSM2**

**CRITICAL:** SoftHSM2 has known limitation - requires hashAlg == mgf (no distinct hashes).
Document this finding.

- [ ] **Step 4: Test against Kryoptic**

Kryoptic should support full RSA-PSS with distinct hashes.

- [ ] **Step 5: Commit**

---

### Subtask 2.4: Implement Signature Verification Tests

**Steps:**

- [ ] **Step 1: Load verification vectors**

These include both valid and invalid signatures for negative testing.

- [ ] **Step 2: Create TestRsaSigVer class**

```python
class TestRsaSigVer:
    """RSA signature verification with valid/invalid vectors"""
    
    def test_rsa_verify_valid(self, p11_raw_session, vec):
        # Valid signatures should verify
        pass
        
    def test_rsa_verify_invalid(self, p11_raw_session, vec):
        # Invalid signatures should fail with CKR_SIGNATURE_INVALID
        pass
```

- [ ] **Step 3: Test error handling**

Verify modules return correct CKR codes for:
- Invalid signature
- Modified message
- Wrong key

- [ ] **Step 4: Commit**

---

### Task 2 Review Checkpoint

**Before proceeding to Task 3:**

1. **Multi-Module Testing:**
   - SoftHSM2: Document RSA-PSS limitations
   - Kryoptic: Verify full PSS support
   - NSS: Check RSA support

2. **Documentation:**
   - Update `docs/module-issues.md` with RSA findings
   - Document distinct hash limitation in SoftHSM2

3. **Code Review:**
   - Verify PSS parameter handling
   - Check error code validation

**Approval Gate:** Get user approval before Task 3

---

## Task 3: Expand ECDSA ACVP Coverage

**Goal:** Add key generation and verification to `test_acvp_ecdsa.py`

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py`

**ACVP Directories to Add:**
- ECDSA-KeyGen-1.0
- ECDSA-KeyGen-FIPS186-5
- ECDSA-KeyVer-1.0
- ECDSA-KeyVer-FIPS186-5
- ECDSA-SigGen-FIPS186-5
- DetECDSA-SigGen-FIPS186-5

---

### Subtask 3.1: Add Key Generation Tests

**Steps:**

- [ ] **Step 1: Load ECDSA-KeyGen vectors**

- [ ] **Step 2: Create TestEcdsaKeyGen class**

```python
class TestEcdsaKeyGen:
    """ECDSA key generation per FIPS 186-4/5"""
    
    def test_ecdsa_keygen(self, p11_raw_session, vec):
        # Generate key pair
        # Verify it matches expected parameters
        pass
```

- [ ] **Step 3: Test curves P-256, P-384, P-521**

- [ ] **Step 4: Test against SoftHSM2**

- [ ] **Step 5: Commit**

---

### Subtask 3.2: Add Deterministic ECDSA Tests

**Steps:**

- [ ] **Step 1: Load DetECDSA-SigGen vectors**

- [ ] **Step 2: Create TestDetEcdsa class**

RFC 6979 deterministic signatures

- [ ] **Step 3: Verify deterministic output**

Same input should produce same signature

- [ ] **Step 4: Test against Kryoptic**

Check if Kryoptic supports deterministic ECDSA

- [ ] **Step 5: Commit**

---

### Task 3 Review Checkpoint

**Approval Gate:** Get user approval before Task 4

---

## Task 4: Expand EdDSA ACVP Coverage

**Goal:** Add key generation and verification to `test_acvp_eddsa.py`

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py`

**ACVP Directories to Add:**
- EDDSA-KeyGen-1.0
- EDDSA-KeyVer-1.0

---

### Subtask 4.1: Add EdDSA Key Generation Tests

**Steps:**

- [ ] **Step 1: Load EDDSA-KeyGen vectors**

- [ ] **Step 2: Test Ed25519 key generation**

- [ ] **Step 3: Test Ed448 key generation**

- [ ] **Step 4: Test against Kryoptic**

- [ ] **Step 5: Document NSS findings**

NSS requires NULL params for EdDSA - document this quirk

- [ ] **Step 6: Commit**

---

### Task 4 Review Checkpoint

**Approval Gate:** Get user approval before Task 5 (PQC)

---

## Task 5: Create ML-DSA ACVP Tests

**Goal:** Create comprehensive ML-DSA (FIPS 204) tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py`

**ACVP Directories:**
- ML-DSA-keyGen-FIPS204
- ML-DSA-sigGen-FIPS204
- ML-DSA-sigVer-FIPS204

---

### Subtask 5.1: Create ML-DSA Test Structure

**Steps:**

- [ ] **Step 1: Create file with imports**

```python
"""NIST ACVP ML-DSA (FIPS 204) test vectors.

Tests Module-Lattice-Based Digital Signature Algorithm with
parameter sets 44, 65, and 87. Both standard and hash variants.
"""

from pkcs11_check.raw.types_std import (
    CKM_ML_DSA, CKM_ML_DSA_44, CKM_ML_DSA_65, CKM_ML_DSA_87,
    CKM_HASH_ML_DSA_44, CKM_HASH_ML_DSA_65, CKM_HASH_ML_DSA_87,
)
```

- [ ] **Step 2: Define parameter set mappings**

```python
_ML_DSA_PARAMS = {
    "ML-DSA-44": CKM_ML_DSA_44,
    "ML-DSA-65": CKM_ML_DSA_65,
    "ML-DSA-87": CKM_ML_DSA_87,
}
```

- [ ] **Step 3: Commit skeleton**

---

### Subtask 5.2: Implement ML-DSA Key Generation Tests

**Steps:**

- [ ] **Step 1: Load ML-DSA-keyGen vectors**

- [ ] **Step 2: Test all three parameter sets**

- [ ] **Step 3: Test against Kryoptic**

Kryoptic is primary module for ML-DSA support

- [ ] **Step 4: Verify key format compliance**

- [ ] **Step 5: Commit**

---

### Subtask 5.3: Implement ML-DSA Sign/Verify Tests

**Steps:**

- [ ] **Step 1: Load ML-DSA-sigGen and sigVer vectors**

- [ ] **Step 2: Test standard ML-DSA signatures**

- [ ] **Step 3: Test Hash-ML-DSA variants**

- [ ] **Step 4: Verify deterministic signatures**

- [ ] **Step 5: Test against NSS-PQC**

NSS 3.121.0+ has ML-DSA support

- [ ] **Step 6: Document findings**

- [ ] **Step 7: Commit**

---

### Task 5 Review Checkpoint

**Approval Gate:** Get user approval before Task 6

---

## Task 6: Create ML-KEM ACVP Tests

**Goal:** Create ML-KEM (FIPS 203) tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py`

**ACVP Directories:**
- ML-KEM-keyGen-FIPS203
- ML-KEM-encapDecap-FIPS203

---

### Subtask 6.1: Implement ML-KEM Tests

**Steps:**

- [ ] **Step 1: Create test structure**

```python
class TestMlKem:
    """ML-KEM tests per FIPS 203"""
    
    def test_mlkem_keygen(self, p11_raw_session, vec):
        # Test key generation for 512/768/1024
        pass
        
    def test_mlkem_encapsulate(self, p11_raw_session, vec):
        # Test encapsulation
        pass
        
    def test_mlkem_decapsulate(self, p11_raw_session, vec):
        # Test decapsulation
        pass
```

- [ ] **Step 2: Test against Kryoptic**

Kryoptic has best ML-KEM support

- [ ] **Step 3: Test against NSS-PQC**

- [ ] **Step 4: Document any buffer sizing issues**

- [ ] **Step 5: Commit**

---

### Task 6 Review Checkpoint

**Approval Gate:** Get user approval before Task 7

---

## Task 7: Expand SLH-DSA ACVP Coverage

**Goal:** Complete SLH-DSA coverage

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_slhdsa.py`

**ACVP Directories:**
- SLH-DSA-keyGen-FIPS205 (add if not present)
- SLH-DSA-sigGen-FIPS205 (expand to all variants)
- SLH-DSA-sigVer-FIPS205 (expand to all variants)

---

### Subtask 7.1: Add All SLH-DSA Parameter Sets

**Steps:**

- [ ] **Step 1: Ensure all 13 variants tested**

SHA2-S, SHA2-F, SHAKE-S, SHAKE-F variants for 128/192/256

- [ ] **Step 2: Test key generation**

- [ ] **Step 3: Test sign/verify**

- [ ] **Step 4: Test against Kryoptic**

- [ ] **Step 5: Document findings**

- [ ] **Step 6: Commit**

---

### Task 7 Review Checkpoint

**Approval Gate:** Get user approval before Phase 3

---

## Task 8: Expand HMAC ACVP Coverage

**Goal:** Add all HMAC-SHA* and HMAC-SHA3* variants

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_hmac.py`

**ACVP Directories:** All 22 HMAC directories

---

### Subtask 8.1: Add Truncated HMAC Tests

**Steps:**

- [ ] **Step 1: Load HMAC-SHA2-512/224 and HMAC-SHA2-512/256 vectors**

These test truncated HMAC output

- [ ] **Step 2: Add truncated output tests**

- [ ] **Step 3: Test against SoftHSM2**

- [ ] **Step 4: Commit**

---

### Task 8 Review Checkpoint

**Approval Gate:** Continue to Task 9

---

## Task 9: Create SHA3/Hash ACVP Tests

**Goal:** Create SHA-3 and SHAKE tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_hash.py`

**ACVP Directories:** SHA3-*, SHAKE-*

---

### Subtask 9.1: Implement SHA3 and SHAKE Tests

**Steps:**

- [ ] **Step 1: Create test file**

- [ ] **Step 2: Test SHA3-224/256/384/512**

- [ ] **Step 3: Test SHAKE-128/256**

- [ ] **Step 4: Note cSHAKE limitation**

cSHAKE customization strings not supported

- [ ] **Step 5: Test against SoftHSM2**

- [ ] **Step 6: Commit**

---

## Task 10: Create RSA KeyGen ACVP Tests

**Goal:** RSA key generation per FIPS 186-4/5

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_rsa_keygen.py`

---

### Subtask 10.1: Implement RSA KeyGen Tests

**Steps:**

- [ ] **Step 1: Load RSA-KeyGen vectors**

- [ ] **Step 2: Test various key sizes**

- [ ] **Step 3: Validate generated keys meet ACVP criteria**

- [ ] **Step 4: Test against SoftHSM2**

- [ ] **Step 5: Commit**

---

## Task 11: Create ECDH ACVP Tests

**Goal:** Elliptic Curve Diffie-Hellman tests

**Files:**
- Create: `src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py`

---

### Subtask 11.1: Implement ECDH Tests

**Steps:**

- [ ] **Step 1: Load KAS-ECC vectors**

- [ ] **Step 2: Test ECDH key agreement**

- [ ] **Step 3: Test with P-256, P-384, P-521**

- [ ] **Step 4: Test against SoftHSM2**

- [ ] **Step 5: Commit**

---

## Final Review and Documentation

### Task 12: Comprehensive Testing

**Steps:**

- [ ] **Step 1: Run full ACVP suite against all three modules**

```bash
# Kryoptic
bash local-builds/test.sh kryoptic -m acvp

# SoftHSM2
bash local-builds/test.sh softhsm2 -m acvp

# NSS-PQC
bash local-builds/test.sh nss-pqc -m acvp
```

- [ ] **Step 2: Document results in docs/module-issues.md**

For each module:
- Which ACVP tests pass
- Which are skipped (mechanism not supported)
- Which fail (module bugs)
- Any quirks discovered

- [ ] **Step 3: Update test counts**

- [ ] **Step 4: Create summary report**

---

### Task 13: Final Review and Cleanup

**Steps:**

- [ ] **Step 1: Code review all new files**

- [ ] **Step 2: Verify ruff/mypy compliance**

```bash
uv run ruff check src/pkcs11_check/testcases/acvp/
uv run mypy src/pkcs11_check/testcases/acvp/
```

- [ ] **Step 3: Final commit**

```bash
git commit -m "feat(acvp): complete PKCS#11 v3.2 ACVP test coverage

- 126 fully mappable ACVP directories now covered
- Tests for all core PKCS#11 v3.2 mechanisms
- Validated against Kryoptic, SoftHSM2, and NSS-PQC
- Comprehensive documentation of module capabilities"
```

---

## Testing Commands Reference

**Per-module testing:**
```bash
# Test specific file against Kryoptic
bash local-builds/test.sh kryoptic -v src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py

# Test specific class against SoftHSM2
bash local-builds/test.sh softhsm2 -v -k TestRsaPss

# Test specific method against NSS-PQC
bash local-builds/test.sh nss-pqc -v -k test_mlkem_keygen
```

**Full suite testing:**
```bash
# All ACVP tests
bash local-builds/test.sh kryoptic -m acvp

# With coverage report
bash local-builds/test.sh softhsm2 -m acvp --cov=src/pkcs11_check
```

**Docker testing:**
```bash
# Final validation
docker compose -f docker/docker-compose.test.yml run --rm test-kryoptic
```

---

## Success Criteria

- [ ] All 126 fully mappable directories have test coverage
- [ ] Tests pass on at least 2 of 3 target modules
- [ ] Proper skip logic for unsupported mechanisms
- [ ] Module-specific findings documented
- [ ] Code passes ruff and mypy checks
- [ ] No regressions in existing tests

---

## Review Schedule

| Task | Review Required | Focus Areas |
|------|----------------|-------------|
| 1 (AES) | Yes | CCM, XTS, KW/KWP coverage |
| 2 (RSA) | Yes | PSS handling, error codes |
| 3 (ECDSA) | Yes | KeyGen, DetECDSA |
| 4 (EdDSA) | Yes | KeyGen, NSS compatibility |
| 5 (ML-DSA) | Yes | All parameter sets |
| 6 (ML-KEM) | Yes | Encapsulation/Decapsulation |
| 7 (SLH-DSA) | Yes | All 13 variants |
| 8-11 | Optional | Extended features |
| 12-13 | Yes | Final validation |

---

**Total Estimated Time:** 4-6 weeks  
**Test Files to Create/Modify:** ~15  
**Directories Covered:** 126 fully mappable + selective partial
