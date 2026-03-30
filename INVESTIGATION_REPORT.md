# pkcs11-check Docker Results Analysis
## Deep Investigation: Test Failures Across All Providers

**Date:** 2026-03-29
**Providers Analyzed:** 5 (bouncyhsm, kryoptic-main, nss-pqc, opencryptoki-master, softhsm2-main)
**Total Tests:** 15,321

---

## Executive Summary

- **Real Failures:** 15,189 (99.1%) - Tests that FAILED on at least one provider
- **Known Issues (XFailed):** 131 (0.9%) - Documented expected failures
- **Universal Failures:** Tests failing on ALL providers they ran on

The analysis reveals that the vast majority of "failures" are actually tests being skipped due to missing mechanisms/capabilities on specific providers. However, there are patterns of tests that fail across multiple providers that warrant investigation.

---

## 🔴 Critical Findings - Likely pkcs11_check Issues

### 1. **EDDSA KAT Test Failures (All 5 Providers)**
```
test_mech_sign.py::TestMechSignKAT::test_kat_vector[EDDSA]
```
**Failures:**
- bouncyhsm: CKR_ATTRIBUTE_VALUE_INVALID
- kryoptic-main: CKR_ATTRIBUTE_VALUE_INVALID  
- nss-pqc: CKR_KEY_TYPE_INCONSISTENT
- opencryptoki-master: CKR_CURVE_NOT_SUPPORTED
- softhsm2-main: CKR_KEY_TYPE_INCONSISTENT

**Analysis:** Different error codes on every provider suggests the test may be using incorrect key templates or EdDSA parameters. This is likely a pkcs11_check test bug.

### 2. **RSA_X_509 Encrypt/Decrypt Mismatch (4 Providers)**
```
test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[RSA_X_509]
test_mech_wrap.py::TestMechWrapRoundtrip::test_wrap_unwrap_aes_key[RSA_X_509]
```
**Analysis:** Decrypt mismatch errors suggest the test data may not be properly formatted for raw RSA_X_509 (no padding). This is a test issue - raw RSA requires proper padding handling.

### 3. **EDDSA Multipart Sign Failures (4 Providers)**
```
test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[EDDSA]
```
**Failures:**
- kryoptic-main: CKR_DEVICE_ERROR
- nss-pqc: CKR_MECHANISM_PARAM_INVALID
- opencryptoki-master: CKR_MECHANISM_INVALID
- softhsm2-main: CKR_OPERATION_NOT_INITIALIZED

**Analysis:** EdDSA is not designed for multipart signing (EdDSA processes whole messages). This test should skip for EdDSA or use proper streaming mechanisms.

### 4. **ML-DSA/HASH_ML-DSA Failures (3 Providers)**
```
test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[ML_DSA]
test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[ML_DSA]
test_mech_sign.py::TestMechSignRoundtrip::test_tampered_data_fails_verify[ML_DSA]
```
**Analysis:** Consistent CKR_MECHANISM_INVALID suggests providers don't support ML-DSA yet (PQC). These should be marked as expected skips, not failures.

### 5. **RSA_PKCS Tampered Data Verification (3 Providers)**
```
test_mech_sign.py::TestMechSignRoundtrip::test_tampered_data_fails_verify[RSA_PKCS]
```
**Analysis:** Test expects tampered data to fail verification with proper error codes, but providers return CKR_DEVICE_ERROR or CKR_DATA_INVALID. Test expectations may be too strict.

---

## 🟡 Provider-Specific Issues (Not pkcs11_check Bugs)

### Security Issues (Documented as XFailed)
1. **NSS Sensitive Key Exposure** - NSS returns CKR_OK for reading sensitive attributes (universal xfail)
2. **NSS Wrap-Decrypt Oracle** - NSS allows keys with both CKA_WRAP and CKA_DECRYPT (security issue)
3. **Kryoptic CKA_PRIVATE defaults** - Module defaults CKA_PRIVATE=False (spec violation)

### Known Capability Gaps
1. **Curve Support** - secp224r1, secp256k1, brainpool curves not supported on most providers
2. **DSA Support** - DSA mechanisms largely unsupported
3. **PQC Support** - ML-DSA, SLH-DSA, HASH_ML_DSA not supported on most providers
4. **v3.0/v3.2 Functions** - C_LoginUser, C_SessionCancel not supported on many providers

---

## 🔧 Recommended Actions

### Immediate (pkcs11_check fixes)

1. **Fix EDDSA KAT Test:**
   - Investigate correct EdDSA key template
   - Check CK_EDDSA_PARAMS handling
   - Verify curve OID encoding

2. **Fix RSA_X_509 Tests:**
   - Ensure proper data padding for raw RSA
   - Or skip these tests with clear documentation

3. **Fix EDDSA Multipart Test:**
   - Skip EdDSA for multipart tests (EdDSA doesn't support streaming)
   - Or document that EdDSA requires single-part operations

4. **Fix ML-DSA Test Expectations:**
   - Skip ML-DSA tests on providers that don't advertise support
   - Don't expect CKR_OK if mechanism not in mechanism list

### Medium-term (provider investigation)

1. **Document provider-specific security findings** in module-issues.md
2. **Add mechanism availability checks** before running algorithm-specific tests
3. **Improve error message analysis** to distinguish test bugs from provider bugs

---

## 📊 Failure Patterns by Category

### Wycheproof Test Failures (14,000+ failures)
Mostly due to:
- Missing curve support (secp224r1, secp256k1, brainpool curves)
- Missing hash algorithms (SHA3 variants)
- AES-GCM IV size limitations (257B IV rejected)
- RSA-PSS salt length mismatches

### Core Mechanism Failures (500+ failures)
1. **AES-CCM** - Parameter handling issues
2. **AES-KEY-WRAP** - Streaming vs single-part differences  
3. **ECDSA** - Domain parameter handling varies by provider
4. **ChaCha20-Poly1305** - Ciphertext mismatches (likely test data issue)

### CKR Return Code Mismatches
Tests fail because providers return different error codes than expected:
- CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID
- CKR_GENERAL_ERROR instead of CKR_MECHANISM_INVALID
- CKR_TEMPLATE_INCONSISTENT instead of CKR_ATTRIBUTE_VALUE_INVALID

**Recommendation:** Tests should accept a range of valid error codes per PKCS#11 spec, not expect exact codes.

---

## 🧪 Tests Requiring Deep Investigation

These tests fail on 3+ providers and need code review:

1. `test_mech_sign.py::TestMechSignKAT::test_kat_vector[EDDSA]` - Key template issue?
2. `test_mech_encrypt.py::test_roundtrip[RSA_X_509]` - Padding issue?
3. `test_mech_multipart.py::test_multipart_sign_verify[EDDSA]` - Should skip?
4. `test_mech_sign.py::test_tampered_data_fails_verify[RSA_PKCS]` - Expectation issue?
5. `test_aes_modes.py::TestAESCTR::test_aes_ctr_*` - BouncyHSM vs OpenCryptoKI differences

---

## Conclusion

**Most failures are NOT pkcs11_check bugs** - they represent legitimate provider capability differences or missing mechanisms. However, there are ~20-30 test cases that consistently fail across multiple providers with different error codes, suggesting test bugs in:

1. Key template construction
2. Test data preparation
3. Error code expectations
4. Mechanism capability checking

**Priority:** Focus on fixing the 5 critical findings identified above first, as these are clearly test issues affecting multiple providers.
