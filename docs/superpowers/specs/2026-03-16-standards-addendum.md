# pkcs11-check Comprehensive Testing Design — Standards Addendum

**Date:** 2026-03-16
**Status:** Draft
**Supplements:** `2026-03-16-comprehensive-testing-design.md`
**Depends on:** `2026-03-16-pkcs11-check-design.md` (Phase 1 spec)

---

## 1. Overview

This addendum supplements the main comprehensive testing design specification
(`2026-03-16-comprehensive-testing-design.md`). That document defines the overall
test architecture, cross-verification strategy, Wycheproof integration, v3.x function
coverage, and PQC test cases targeting ~2,400+ total tests.

The present document addresses **OASIS PKCS#11 specification-grounded standards
conformance gaps** not covered by the main spec. Specifically it covers:

1. Key derivation and key establishment functions (HKDF, SP 800-108, PBKDF2, TLS PRF,
   X9.63 KDF, cofactor ECDH, ECMQV) with cross-verification against the Python
   `cryptography` library.
2. SHA-3, SHAKE, KMAC, and XOF operations including FIPS 202 known-answer test vectors,
   XOF variable-length output, and combinations with PQC algorithms.
3. Template and provenance attributes (CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE,
   CKA_DERIVE_TEMPLATE, CKA_LOCAL, CKA_KEY_GEN_MECHANISM, CKA_PUBLIC_KEY_INFO,
   CKA_CHECK_VALUE) and the enforcement rules the OASIS spec places on them.
4. C_Initialize threading models, fork safety, and the legacy parallel-function stubs
   that PKCS#11 section 5.4 (General-purpose functions) requires to exist.
5. CK_TOKEN_INFO.flags lifecycle transitions, including all PIN-lockout bits and the
   consistency invariants the spec mandates.
6. The two-call (NULL-output) buffer management convention required by OASIS sections
   5.10 (C_Encrypt) through 5.16 (C_WrapKey) and the equivalent v3.0 message-based
   variants.
7. Non-key object classes: CKO_DATA, CKO_DOMAIN_PARAMETERS, CKO_HW_FEATURE,
   CKO_OTP_KEY, and their lifecycle and attribute requirements.
8. Expanded FIPS compliance: service indicators, pairwise consistency self-tests,
   conditional self-tests, role separation, and algorithm restriction verification.
9. Extended protocol signing: COSE, WebAuthn/FIDO2, SSH key signing, JWS, JWE,
   OCSP, and PKCS#12 round-trips.
10. Race condition extensions covering object destruction during active operations,
    handle reuse, login races, and session close during streaming operations.

All tests added by this addendum follow the same conventions as the main spec:
subprocess isolation per test, auto-skip via `@pytest.mark.requires_v30` /
`@pytest.mark.requires_v32` when appropriate, and cross-verification against
independent implementations where the operation has a well-defined external form.

The new test files introduced by this addendum are listed in Section 13. The running
total with the main spec is given there as well.

---

## 2. Standards References Update

The main spec's standards table references FIPS 186-4 and SP 800-56 family documents
that have since been superseded or significantly revised. This section records the
authoritative versions that test vectors, expected behaviors, and compliance claims
must be based on.

### 2.1 Digital Signature Standards

| Standard | Status | Notes |
|----------|--------|-------|
| **FIPS 186-5** (Feb 2023) | Current | Replaces FIPS 186-4 (withdrawn July 2023). Adds EdDSA (Ed25519, Ed448). Retains ECDSA over P-256/P-384/P-521. DSA generation no longer approved for new applications (verification of existing signatures only). RSA signature generation approved with 2048-bit minimum. All KAT vectors for RSA and ECDSA in `test_sign.py` and `test_kat.py` must use FIPS 186-5 vectors where available. |
| FIPS 186-4 | Withdrawn July 2023 | Do not use as normative reference. Existing vectors may still be used for backward-compatibility tests tagged `@pytest.mark.fips186_4_legacy`. |

### 2.2 Hash Standards

| Standard | Status | Notes |
|----------|--------|-------|
| **FIPS 180-4** (Aug 2015) | Current | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256. Referenced by test_digest.py and test_kat.py. |
| **FIPS 202** (Aug 2015) | Current | SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256. KAT vectors for test_sha3.py sourced from the NIST CAVP SHA-3 byte-oriented test vectors package. |

### 2.3 Elliptic Curve Definitions

| Standard | Status | Notes |
|----------|--------|-------|
| **SP 800-186** (Feb 2023) | Current | Replaces the curve appendices in FIPS 186-4. Defines approved curves: P-224, P-256, P-384, P-521 (NIST prime curves); K-163, K-233, K-283, K-409, K-571 (Koblitz curves — restricted use); B-163, B-233, B-283, B-409, B-571 (binary curves — restricted use); Curve25519/X25519, Curve448/X448, Ed25519, Ed448 (Edwards/Montgomery). Tests in test_sign.py and test_kdf.py reference SP 800-186 for curve OID correctness. |

### 2.4 Key Establishment

| Standard | Status | Notes |
|----------|--------|-------|
| **SP 800-56A Rev. 3** (Apr 2018) | Current | Pair-wise key establishment schemes using DL and EC. Covers ECDH, ECMQV, DH, MQV. Cofactor ECDH defined in Section 5.7.1.2. Referenced by test_kdf.py cofactor ECDH tests. |
| **SP 800-56B Rev. 2** (Mar 2019) | Current | Pair-wise key establishment using integer factorization (RSA). RSA-KEM defined here. Referenced by test_kdf.py. |
| **SP 800-56C Rev. 2** (Aug 2020) | Current | Recommendation for key-derivation methods in key-establishment schemes. Covers one-step and two-step KDFs used after raw key agreement. Referenced by test_kdf.py HKDF and X9.63 tests. |

### 2.5 Key Derivation

| Standard | Status | Notes |
|----------|--------|-------|
| **SP 800-108 Rev. 1** (Aug 2022) | Current | Recommendation for KDF using pseudorandom functions. Defines counter mode, feedback mode, double-pipeline mode KDFs. CKM_SP800_108_COUNTER_KDF, CKM_SP800_108_FEEDBACK_KDF, CKM_SP800_108_DOUBLE_PIPELINE_KDF map directly to the three modes. Referenced by test_kdf.py SP 800-108 section. |
| **SP 800-132** (Dec 2010) | Current | Recommendation for password-based key derivation (PBKDF). Defines PBKDF2. Referenced by test_kdf.py PBKDF2 section. |

### 2.6 Symmetric Key Algorithms

| Standard | Status | Notes |
|----------|--------|-------|
| **SP 800-38F** (Dec 2012) | Current | Recommendation for block cipher modes of operation: methods for key wrapping. Defines AES Key Wrap (KW) and AES Key Wrap with Padding (KWP) — which PKCS#11 maps to CKM_AES_KEY_WRAP and CKM_AES_KEY_WRAP_PAD. KAT vectors for test_keymgmt.py sourced from this document. |
| **SP 800-185** (Dec 2016) | Current | SHA-3 derived functions: cSHAKE, KMAC, TupleHash, ParallelHash. KAT vectors for KMAC128/256 in test_sha3.py sourced from the appendix. |

### 2.7 PKCS#11 Specification

All section references in this document are to the **OASIS PKCS#11 v3.2** specification
unless stated otherwise. Where backward compatibility is tested the v2.40 (OASIS
Committee Specification 01, June 2015) wording is cited explicitly.

| Spec version | Used for |
|---|---|
| OASIS PKCS#11 v3.2 | Primary normative reference for all new tests |
| OASIS PKCS#11 v3.0 | Message-based APIs, C_LoginUser, C_SessionCancel |
| OASIS PKCS#11 v2.40 | Backward-compatibility baseline; legacy parallel functions |

---

## 3. KDF & Key Establishment (`test_kdf.py`) — ~50 tests

**File:** `src/pkcs11-check/testcases/test_kdf.py`
**Marker:** `@pytest.mark.requires_v30` where HKDF or SP 800-108 mechanisms are used;
`@pytest.mark.requires_v32` for mechanisms first defined in v3.2.
**Cross-verification library:** `cryptography` (PyCA), `hkdf` reference vectors,
SP 800-108 reference implementation output.

### 3.1 HKDF (CKM_HKDF_DERIVE, CKM_HKDF_DATA, CKM_HKDF_KEY_GEN)

OASIS PKCS#11 v3.0 section 2.42 defines three HKDF mechanisms. The CK_HKDF_PARAMS
structure controls salt type (null/data/key), whether to extract, whether to expand,
and the PRF hash algorithm.

**Test matrix:**

| Test | Salt type | Mode | Hash | Notes |
|------|-----------|------|------|-------|
| hkdf_derive_null_salt_extract_expand | CKF_HKDF_SALT_NULL | extract+expand | SHA-256 | RFC 5869 Test Case 2 vector |
| hkdf_derive_data_salt_extract_expand | CKF_HKDF_SALT_DATA | extract+expand | SHA-256 | RFC 5869 Test Case 1 vector |
| hkdf_derive_key_salt | CKF_HKDF_SALT_KEY | extract+expand | SHA-256 | salt is another PKCS#11 key object |
| hkdf_extract_only | CKF_HKDF_SALT_DATA, expand=false | extract only | SHA-256 | output is PRK; compare to Python `hmac` |
| hkdf_expand_only | CKF_HKDF_SALT_NULL, extract=false | expand only | SHA-256 | input is already PRK; compare to Python |
| hkdf_sha384_derive | CKF_HKDF_SALT_DATA | extract+expand | SHA-384 | verify hash agility |
| hkdf_sha512_derive | CKF_HKDF_SALT_DATA | extract+expand | SHA-512 | verify hash agility |
| hkdf_sha1_derive | CKF_HKDF_SALT_DATA | extract+expand | SHA-1 | legacy hash, skip if module rejects |
| hkdf_zero_length_info | CKF_HKDF_SALT_DATA | extract+expand | SHA-256 | zero-length info field → CKR_OK |
| hkdf_max_output_length | CKF_HKDF_SALT_DATA | expand only | SHA-256 | output length = 255 * hashlen (RFC 5869 maximum) |
| hkdf_over_max_output_length | CKF_HKDF_SALT_DATA | expand only | SHA-256 | output length = 256 * hashlen → CKR_MECHANISM_PARAM_INVALID |
| hkdf_data_output | CKM_HKDF_DATA | extract+expand | SHA-256 | result is CKO_DATA, not a key object |
| hkdf_key_gen | CKM_HKDF_KEY_GEN | extract+expand | SHA-256 | generates symmetric key directly |
| hkdf_cross_verify_sha256 | CKF_HKDF_SALT_DATA | extract+expand | SHA-256 | compare output bytes to Python `cryptography.hazmat.primitives.kdf.hkdf.HKDF` |
| hkdf_cross_verify_sha512 | CKF_HKDF_SALT_DATA | extract+expand | SHA-512 | same |

**Cross-verification pattern:**
```
1. Import IKM (input key material) as CKO_SECRET_KEY into PKCS#11
2. Call C_DeriveKey(CKM_HKDF_DERIVE, params, ikm_handle, output_template)
3. Export derived key bytes (CKA_VALUE, only if CKA_EXTRACTABLE=True)
4. Derive same bytes via Python cryptography.HKDF
5. Assert bytes are identical
```

### 3.2 SP 800-108 KDF Modes

PKCS#11 maps NIST SP 800-108 Rev. 1 to:
- `CKM_SP800_108_COUNTER_KDF` (counter mode, section 4.1 of SP 800-108)
- `CKM_SP800_108_FEEDBACK_KDF` (feedback mode, section 4.2)
- `CKM_SP800_108_DOUBLE_PIPELINE_KDF` (double-pipeline mode, section 4.3)

The CK_SP800_108_KDF_PARAMS structure specifies PRF (typically CKM_AES_CMAC or
CKM_HMAC_SHA256), data segments (label, context, counter), counter bit length, and
additional derived key handles for chained derivations.

| Test | Mechanism | PRF | Counter bits | Notes |
|------|-----------|-----|------|-------|
| sp800_108_counter_hmac_sha256 | COUNTER_KDF | HMAC-SHA256 | 32 | compare to SP 800-108 Rev. 1 Appendix B test vectors |
| sp800_108_counter_aes_cmac | COUNTER_KDF | AES-CMAC | 32 | AES-128 key |
| sp800_108_counter_counter_bits_8 | COUNTER_KDF | HMAC-SHA256 | 8 | minimum counter size |
| sp800_108_counter_counter_bits_16 | COUNTER_KDF | HMAC-SHA256 | 16 | |
| sp800_108_feedback_no_iv | FEEDBACK_KDF | HMAC-SHA256 | 32 | feedback with zero IV |
| sp800_108_feedback_with_iv | FEEDBACK_KDF | HMAC-SHA256 | 32 | feedback with random IV |
| sp800_108_double_pipeline | DOUBLE_PIPELINE_KDF | HMAC-SHA256 | 32 | compare output |
| sp800_108_multiple_outputs | COUNTER_KDF | HMAC-SHA256 | 32 | derive 3 keys simultaneously via CK_DERIVED_KEY array |
| sp800_108_cross_verify | COUNTER_KDF | HMAC-SHA256 | 32 | Python reference implementation → compare OKM bytes |

### 3.3 PBKDF2 PRF Matrix

PKCS#11 CKM_PKCS5_PBKD2 uses CK_PKCS5_PBKD2_PARAMS2 which specifies the PRF via
CKP_PKCS5_PBKD2_HMAC_SHA1 / HMAC_SHA224 / HMAC_SHA256 / HMAC_SHA384 / HMAC_SHA512.
Test vectors from NIST SP 800-132 and RFC 6070.

| Test | PRF | Iterations | Key length | Vector source |
|------|-----|-----------|------------|--------------|
| pbkdf2_sha1_rfc6070_c1 | HMAC-SHA1 | 1 | 20 | RFC 6070 section 2 test case 1 |
| pbkdf2_sha1_rfc6070_c4096 | HMAC-SHA1 | 4096 | 20 | RFC 6070 test case 3 |
| pbkdf2_sha1_rfc6070_long_password | HMAC-SHA1 | 4096 | 25 | RFC 6070 test case 5 |
| pbkdf2_sha256 | HMAC-SHA256 | 4096 | 32 | RFC 7914 Appendix B |
| pbkdf2_sha384 | HMAC-SHA384 | 1000 | 48 | cross-verify with Python `hashlib.pbkdf2_hmac` |
| pbkdf2_sha512 | HMAC-SHA512 | 1000 | 64 | cross-verify with Python |
| pbkdf2_salt_zero_length | HMAC-SHA256 | 1000 | 32 | empty salt → CKR_OK or CKR_MECHANISM_PARAM_INVALID (record) |
| pbkdf2_cross_verify_sha256 | HMAC-SHA256 | 10000 | 32 | compare to Python `cryptography` PBKDF2HMAC |

### 3.4 TLS PRF and Related Mechanisms

| Test | Mechanism | Notes |
|------|-----------|-------|
| tls12_prf_sha256 | CKM_TLS12_KEY_AND_MAC_DERIVE | TLS 1.2 PRF with SHA-256 (RFC 5246 section A.1) |
| tls12_prf_sha384 | CKM_TLS12_KEY_AND_MAC_DERIVE | TLS 1.2 PRF with SHA-384 (RFC 5246 Annex C) |
| tls12_master_secret_derive | CKM_TLS12_MASTER_KEY_DERIVE | pre-master → master secret derivation |
| tls12_master_secret_dh | CKM_TLS12_MASTER_KEY_DERIVE_DH | DH-based variant |
| tls_prf_generic | CKM_TLS_PRF | generic label/seed → compare to Python `tls_prf` reference |
| tls12_finished_client | CKM_TLS_MAC | client Finished message MAC label |
| tls12_finished_server | CKM_TLS_MAC | server Finished message MAC label |
| tls_key_material_export | CKM_TLS12_KEY_AND_MAC_DERIVE | verify output objects: client/server write key + MAC key + IVs |

### 3.5 X9.63 KDF

ANSI X9.63 KDF is the hash-based KDF used in ECIES and SEC1 standards. PKCS#11 defines
CKM_ECDH1_DERIVE with CKM_SHA1_KDF, CKM_SHA256_KDF, CKM_SHA384_KDF, CKM_SHA512_KDF
variants in the CK_ECDH1_DERIVE_PARAMS.kdf field.

| Test | KDF | Curve | Notes |
|------|-----|-------|-------|
| x963_kdf_sha1_p256 | CKD_SHA1_KDF | P-256 | ECDH derive + SHA-1 X9.63 KDF |
| x963_kdf_sha256_p256 | CKD_SHA256_KDF | P-256 | cross-verify with Python `eciespy` or manual X9.63 |
| x963_kdf_sha384_p384 | CKD_SHA384_KDF | P-384 | hash size matches curve security level |
| x963_kdf_sha512_p521 | CKD_SHA512_KDF | P-521 | |
| x963_kdf_with_sharedinfo | CKD_SHA256_KDF | P-256 | non-empty shared info (CK_ECDH1_DERIVE_PARAMS.pSharedData) |
| x963_kdf_cross_verify | CKD_SHA256_KDF | P-256 | compare derived key bytes to Python reference |

### 3.6 Cofactor ECDH (CKM_ECDH1_COFACTOR_DERIVE)

SP 800-56A Rev. 3 section 5.7.1.2 defines cofactor ECDH (also called ECCDH) as the
variant where each party's static private key is multiplied by the cofactor before use,
preventing small-subgroup attacks. PKCS#11 exposes this as CKM_ECDH1_COFACTOR_DERIVE.
For NIST prime curves the cofactor is 1, so cofactor and plain ECDH produce identical
results — the test must verify the mechanism is accepted and produces correct output.
For Koblitz curves (K-163, K-233) the cofactor is 2 or 4, and results differ from
plain ECDH.

| Test | Curve | Cofactor | Notes |
|------|-------|----------|-------|
| cofactor_ecdh_p256 | P-256 | 1 | result must equal CKM_ECDH1_DERIVE |
| cofactor_ecdh_p384 | P-384 | 1 | same |
| cofactor_ecdh_k233 | K-233 | 4 | if supported; result must differ from plain ECDH |
| cofactor_ecdh_cross_verify | P-256 | 1 | compare shared secret bytes to `cryptography` ECDH |

### 3.7 ECMQV (if supported)

ECMQV (Elliptic Curve Menezes-Qu-Vanstone) is a two-pass authenticated key agreement
scheme defined in SP 800-56A Rev. 3 section 6. PKCS#11 maps this to CKM_ECMQV_DERIVE
with CK_ECMQV_DERIVE_PARAMS. Given ECMQV support is rare in software tokens, all tests
carry `@pytest.mark.skip_if_mechanism_absent("CKM_ECMQV_DERIVE")`.

| Test | Notes |
|------|-------|
| ecmqv_basic_p256 | Both parties hold static + ephemeral EC keypairs; derive shared secret |
| ecmqv_cross_verify | Derive in PKCS#11, verify with SP 800-56A Appendix D test vector |
| ecmqv_invalid_ephemeral_key | Pass wrong curve ephemeral key → CKR_KEY_TYPE_INCONSISTENT |

---

## 4. SHA-3, SHAKE, KMAC & XOF (`test_sha3.py`) — ~40 tests

**File:** `src/pkcs11-check/testcases/test_sha3.py`
**Standards:** FIPS 202 (SHA-3/SHAKE), SP 800-185 (KMAC/cSHAKE)
**KAT vector source:** NIST CAVP SHA-3 byte-oriented byte message test (BMT) files;
SP 800-185 Appendix A (KMAC examples)

### 4.1 SHA-3 Digest KAT Vectors

FIPS 202 defines four fixed-output SHA-3 hash functions. PKCS#11 maps them to
CKM_SHA3_224, CKM_SHA3_256, CKM_SHA3_384, CKM_SHA3_512.

| Test | Mechanism | Input | Expected output | Source |
|------|-----------|-------|-----------------|--------|
| sha3_224_empty | CKM_SHA3_224 | `b""` | `6b4e03423667dbb7...` | FIPS 202 Appendix A |
| sha3_224_abc | CKM_SHA3_224 | `b"abc"` | known vector | CAVP BMT |
| sha3_256_empty | CKM_SHA3_256 | `b""` | known vector | FIPS 202 Appendix A |
| sha3_256_abc | CKM_SHA3_256 | `b"abc"` | known vector | CAVP BMT |
| sha3_384_empty | CKM_SHA3_384 | `b""` | known vector | FIPS 202 |
| sha3_384_1mb | CKM_SHA3_384 | 1 MiB of `b"\x00"` | computed via hashlib | regression |
| sha3_512_empty | CKM_SHA3_512 | `b""` | known vector | FIPS 202 |
| sha3_512_abc | CKM_SHA3_512 | `b"abc"` | known vector | CAVP BMT |
| sha3_256_multipart | CKM_SHA3_256 | chunked identical input | must match single-shot | |
| sha3_256_cross_verify | CKM_SHA3_256 | random 256-byte input | compare to Python `hashlib.sha3_256` | |

All SHA-3 tests carry `@pytest.mark.skip_if_mechanism_absent("CKM_SHA3_256")` (or
the relevant variant) so they auto-skip on SoftHSM2 which does not implement SHA-3.

### 4.2 SHAKE128/256 (XOF) with Variable Output Lengths

SHAKE128 and SHAKE256 are extendable-output functions (XOFs) defined in FIPS 202
sections 6.1 and 6.2. PKCS#11 exposes them as CKM_SHAKE_128 and CKM_SHAKE_256.
The output length is controlled via the mechanism parameter
(CK_SHAKE_PARAMS or equivalent per token implementation) or by the output buffer
length passed to C_DigestFinal.

| Test | Mechanism | Output length | Notes |
|------|-----------|---------------|-------|
| shake128_16_bytes | CKM_SHAKE_128 | 16 | minimum useful output |
| shake128_32_bytes | CKM_SHAKE_128 | 32 | SHA-256 equivalent length |
| shake128_128_bytes | CKM_SHAKE_128 | 128 | |
| shake128_1000_bytes | CKM_SHAKE_128 | 1000 | non-power-of-two length |
| shake256_32_bytes | CKM_SHAKE_256 | 32 | |
| shake256_64_bytes | CKM_SHAKE_256 | 64 | SHA-512 equivalent length |
| shake256_512_bytes | CKM_SHAKE_256 | 512 | |
| shake128_cross_verify | CKM_SHAKE_128 | 32 | compare to Python `hashlib.shake_128(data).digest(32)` |
| shake256_cross_verify | CKM_SHAKE_256 | 64 | compare to Python |
| shake128_empty_input | CKM_SHAKE_128 | 32 | empty message → known FIPS 202 vector |

### 4.3 C_DigestXofInit / C_DigestXofUpdate / C_DigestXofExtract / C_DigestXofFinal (v3.2)

PKCS#11 v3.2 section 5.10.6 introduces four new XOF digest functions that allow
callers to drive the squeeze phase explicitly, producing arbitrary-length outputs
and (for stateful XOFs) interleaving absorb and squeeze operations.

All tests in this section carry `@pytest.mark.requires_v32`.

| Test | Description |
|------|-------------|
| xof_init_update_extract | DigestXofInit(SHAKE128) → DigestXofUpdate(data) → DigestXofExtract(32) → compare to hashlib |
| xof_multi_extract | DigestXofInit(SHAKE128) → DigestXofUpdate(data) → DigestXofExtract(16) → DigestXofExtract(16) → concatenation must equal single 32-byte extract |
| xof_extract_then_final | DigestXofInit → Update → Extract(32) → DigestXofFinal: verify no more output after Final |
| xof_shake256_variable | DigestXofInit(SHAKE256) → Update → Extract(1) through Extract(512) in a loop → compare each output to Python reference |
| xof_extract_without_init | DigestXofExtract without DigestXofInit → CKR_OPERATION_NOT_INITIALIZED |
| xof_update_after_extract | DigestXofUpdate after DigestXofExtract on a non-interleave-capable implementation → CKR_OPERATION_ACTIVE or CKR_OPERATION_NOT_INITIALIZED (record behavior) |
| xof_state_reset | DigestXofFinal → DigestXofInit again on same session → must succeed (state resets cleanly) |

### 4.4 KMAC128 and KMAC256

SP 800-185 section 4 defines KMAC128 and KMAC256 as keyed variants of cSHAKE.
PKCS#11 maps them to CKM_KMAC_128 and CKM_KMAC_256 with CK_KMAC_PARAMS controlling
the key, customization string, and output length.

| Test | Mechanism | Output length | KAT source |
|------|-----------|---------------|------------|
| kmac128_sample_1 | CKM_KMAC_128 | 32 | SP 800-185 Appendix A, Sample #1 |
| kmac128_sample_2 | CKM_KMAC_128 | 32 | SP 800-185 Appendix A, Sample #2 (non-empty customization) |
| kmac128_sample_3 | CKM_KMAC_128 | 32 | SP 800-185 Appendix A, Sample #3 (200-byte data) |
| kmac256_sample_4 | CKM_KMAC_256 | 64 | SP 800-185 Appendix A, Sample #4 |
| kmac256_sample_5 | CKM_KMAC_256 | 64 | SP 800-185 Appendix A, Sample #5 |
| kmac256_sample_6 | CKM_KMAC_256 | 64 | SP 800-185 Appendix A, Sample #6 |
| kmac128_variable_output_64 | CKM_KMAC_128 | 64 | output length = 2× default → verify bytes extend correctly |
| kmac128_empty_customization | CKM_KMAC_128 | 32 | zero-length customization string → CKR_OK |
| kmac128_cross_verify | CKM_KMAC_128 | 32 | compare to Python `cshake` reference |

### 4.5 KMACXOF128 and KMACXOF256

SP 800-185 section 4.3 defines KMACXOF as the XOF variant of KMAC where the
output domain is not explicitly length-encoded, allowing arbitrary truncation.
PKCS#11 maps these to CKM_KMACXOF_128 and CKM_KMACXOF_256.

| Test | Notes |
|------|-------|
| kmacxof128_basic | Produce 32-byte output, compare to SP 800-185 example |
| kmacxof256_basic | Produce 64-byte output |
| kmacxof128_vs_kmac128 | Outputs must differ (different domain separation) |
| kmacxof_variable_length | Request 1, 32, 128, 1000 bytes — all must succeed |

### 4.6 RSA-PSS/OAEP with SHA-3 Hash and MGF1-SHA-3 Combinations

PKCS#11 v3.0+ allows CKM_RSA_PKCS_PSS and CKM_RSA_PKCS_OAEP to be parameterized
with SHA-3 as the hash and MGF1-SHA-3 as the mask generation function.

| Test | Hash | MGF | Notes |
|------|------|-----|-------|
| rsa_pss_sha3_256 | SHA3-256 | MGF1-SHA3-256 | sign 2048-bit key → verify |
| rsa_pss_sha3_384 | SHA3-384 | MGF1-SHA3-384 | sign 3072-bit key → verify |
| rsa_pss_sha3_512 | SHA3-512 | MGF1-SHA3-512 | sign 4096-bit key → verify |
| rsa_oaep_sha3_256 | SHA3-256 | MGF1-SHA3-256 | encrypt → decrypt round-trip |
| rsa_oaep_sha3_512 | SHA3-512 | MGF1-SHA3-512 | encrypt → decrypt round-trip |
| rsa_pss_sha3_256_cross_verify | SHA3-256 | MGF1-SHA3-256 | sign in PKCS#11 → verify with `cryptography` PSS |

### 4.7 ML-DSA and SLH-DSA with SHA-3/SHAKE Variants

FIPS 204 (ML-DSA) uses SHAKE internally. PKCS#11 v3.2 exposes combined hash-then-sign
mechanisms as CKM_HASH_ML_DSA_* and CKM_HASH_SLH_DSA_* where the hash is applied
before the signing operation (analogous to CKM_SHA256_RSA_PKCS for classical RSA).

| Test | Mechanism | Hash | Notes |
|------|-----------|------|-------|
| hash_ml_dsa_sha3_256 | CKM_HASH_ML_DSA | SHA3-256 pre-hash | `@pytest.mark.requires_v32` |
| hash_ml_dsa_shake128 | CKM_HASH_ML_DSA | SHAKE128 pre-hash | |
| hash_slh_dsa_sha3_256 | CKM_HASH_SLH_DSA | SHA3-256 pre-hash | |
| hash_slh_dsa_shake256 | CKM_HASH_SLH_DSA | SHAKE256 pre-hash | |
| hash_ml_dsa_cross_verify | CKM_HASH_ML_DSA | SHA3-256 | sign in PKCS#11 → verify with liboqs |

---

## 5. Template & Provenance Attributes (`test_attrs.py`) — ~35 tests

**File:** `src/pkcs11-check/testcases/test_attrs.py`
**OASIS references:** PKCS#11 v3.2 sections 4.2 (Attribute types), 4.4.2
(CKA_WRAP_TEMPLATE), 4.4.3 (CKA_UNWRAP_TEMPLATE), 4.4.4 (CKA_DERIVE_TEMPLATE),
4.3.3 (CKA_LOCAL), 4.3.4 (CKA_KEY_GEN_MECHANISM), 4.3.6 (CKA_PUBLIC_KEY_INFO).

### 5.1 CKA_WRAP_TEMPLATE

When a wrapping key has CKA_WRAP_TEMPLATE set, any key unwrapped using that wrapping
key must conform to the template. The OASIS spec section 4.4.2 states: "If a key's
CKA_WRAP_TEMPLATE attribute is set, any key that is to be wrapped by that wrapping key
must satisfy the template."

Importantly, the template is enforced at **wrap time** (before the wrapping occurs):
C_WrapKey must fail if the key-to-be-wrapped does not satisfy the template.

| Test | Description |
|------|-------------|
| wrap_template_enforced_at_wrap | Wrapping key has CKA_WRAP_TEMPLATE={CKA_EXTRACTABLE: True}. Attempt to wrap a non-extractable key → CKR_KEY_NOT_WRAPPABLE |
| wrap_template_permits_wrap | Wrapping key has CKA_WRAP_TEMPLATE={CKA_EXTRACTABLE: True}. Wrap an extractable key → succeeds |
| wrap_template_sensitive_constraint | Wrapping key has CKA_WRAP_TEMPLATE={CKA_SENSITIVE: True}. Wrap a non-sensitive key → CKR_KEY_NOT_WRAPPABLE |
| wrap_template_multiple_attributes | Template with both CKA_EXTRACTABLE=True AND CKA_DECRYPT=False. Wrap a key where CKA_DECRYPT=True → CKR_KEY_NOT_WRAPPABLE |
| wrap_template_no_template | Wrapping key without CKA_WRAP_TEMPLATE → wrapping succeeds for any compatible key |

### 5.2 CKA_UNWRAP_TEMPLATE

CKA_UNWRAP_TEMPLATE is applied to newly created key objects resulting from C_UnwrapKey.
OASIS section 4.4.3: "If a key's CKA_UNWRAP_TEMPLATE attribute is set, any key that
is to be unwrapped by that key is created with the attributes in the template applied."
Attributes in CKA_UNWRAP_TEMPLATE take precedence over attributes specified by the
caller's template argument to C_UnwrapKey.

| Test | Description |
|------|-------------|
| unwrap_template_applies | Unwrapping key has CKA_UNWRAP_TEMPLATE={CKA_SENSITIVE: True}. Caller template has CKA_SENSITIVE=False. Unwrap → resulting key must have CKA_SENSITIVE=True |
| unwrap_template_sets_extractable | CKA_UNWRAP_TEMPLATE={CKA_EXTRACTABLE: False}. Caller asks CKA_EXTRACTABLE=True → resulting key must have CKA_EXTRACTABLE=False |
| unwrap_template_preserves_other_attrs | Attributes not in CKA_UNWRAP_TEMPLATE are taken from caller's template |
| unwrap_template_attack | Attacker provides template CKA_SENSITIVE=False, CKA_EXTRACTABLE=True. Unwrapping key has CKA_UNWRAP_TEMPLATE={CKA_SENSITIVE: True, CKA_EXTRACTABLE: False}. Resulting key must honor the key's template, not the attacker's. |
| unwrap_template_no_template | No CKA_UNWRAP_TEMPLATE set → caller's template is used as-is |

### 5.3 CKA_DERIVE_TEMPLATE

CKA_DERIVE_TEMPLATE constrains the attributes of keys derived using the owning key.
OASIS section 4.4.4.

| Test | Description |
|------|-------------|
| derive_template_sensitive | Derive key has CKA_DERIVE_TEMPLATE={CKA_SENSITIVE: True}. Caller requests CKA_SENSITIVE=False → derived key must be sensitive |
| derive_template_key_type | CKA_DERIVE_TEMPLATE={CKA_KEY_TYPE: CKK_AES}. Derive → verify key type |
| derive_template_overrides_caller | Template wins over caller on conflicting attributes |
| derive_template_chain | Derive a key, use derived key as parent for another derivation with its own template → verify chain |

### 5.4 CKA_LOCAL

OASIS section 4.3.3: CKA_LOCAL is True if the key was generated on the token using
C_GenerateKey or C_GenerateKeyPair, and False if it was imported with C_CreateObject
or derived via C_UnwrapKey. CKA_LOCAL cannot be set by the application.

| Test | Description |
|------|-------------|
| local_true_after_generate | C_GenerateKey → C_GetAttributeValue(CKA_LOCAL) → True |
| local_true_after_generate_pair | C_GenerateKeyPair → CKA_LOCAL=True on both public and private |
| local_false_after_import | C_CreateObject(raw key bytes) → CKA_LOCAL=False |
| local_false_after_unwrap | C_UnwrapKey → CKA_LOCAL=False on resulting key |
| local_cannot_be_set | C_CreateObject with CKA_LOCAL=True → CKR_ATTRIBUTE_READ_ONLY |
| local_preserved_through_copy | C_CopyObject of locally generated key → CKA_LOCAL still True |

### 5.5 CKA_KEY_GEN_MECHANISM

OASIS section 4.3.4: records the mechanism used to generate the key object.
Set automatically on generate; CKK_VENDOR_DEFINED for imported keys; cannot be
set by the application (read-only).

| Test | Description |
|------|-------------|
| key_gen_mechanism_aes_keygen | C_GenerateKey(CKM_AES_KEY_GEN) → CKA_KEY_GEN_MECHANISM=CKM_AES_KEY_GEN |
| key_gen_mechanism_rsa | C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN) → private key CKA_KEY_GEN_MECHANISM=CKM_RSA_PKCS_KEY_PAIR_GEN |
| key_gen_mechanism_ec | C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN) → CKA_KEY_GEN_MECHANISM=CKM_EC_KEY_PAIR_GEN |
| key_gen_mechanism_imported | C_CreateObject(AES key) → CKA_KEY_GEN_MECHANISM=CK_UNAVAILABLE_INFORMATION |
| key_gen_mechanism_derived | C_DeriveKey(HKDF) → CKA_KEY_GEN_MECHANISM=CKM_HKDF_DERIVE |
| key_gen_mechanism_read_only | C_CreateObject with explicit CKA_KEY_GEN_MECHANISM → CKR_ATTRIBUTE_READ_ONLY |

### 5.6 CKA_PUBLIC_KEY_INFO

OASIS section 4.3.6: for asymmetric keys, CKA_PUBLIC_KEY_INFO contains the
SubjectPublicKeyInfo (SPKI) DER encoding of the public key as defined in RFC 5480.

| Test | Description |
|------|-------------|
| spki_encoding_rsa | Generate RSA key → parse CKA_PUBLIC_KEY_INFO → verify AlgorithmIdentifier OID = rsaEncryption (1.2.840.113549.1.1.1) and BIT STRING contains N and e |
| spki_encoding_ec_p256 | Generate P-256 key → parse SPKI → OID = id-ecPublicKey (1.2.840.10045.2.1), named curve = prime256v1 (1.2.840.10045.3.1.7) |
| spki_encoding_ed25519 | Generate Ed25519 key → SPKI OID = id-EdDSA (1.3.101.112) |
| spki_matches_ec_point | CKA_PUBLIC_KEY_INFO EC_POINT field must match CKA_EC_POINT attribute |
| spki_absent_on_secret_key | AES key → CKA_PUBLIC_KEY_INFO must return CKR_ATTRIBUTE_TYPE_INVALID |

### 5.7 CKA_ID and Keypair Pairing

| Test | Description |
|------|-------------|
| keypair_matching_id | C_GenerateKeyPair → public key CKA_ID matches private key CKA_ID (both set via template) |
| find_by_id | C_FindObjects(CKA_ID=x) → returns both public and private key with matching IDs |
| id_mismatch_detection | Import pubkey with ID "A", privkey with ID "B" → test helper identifies unpaired keys |

### 5.8 CKA_CHECK_VALUE

OASIS section 4.2: for secret keys, CKA_CHECK_VALUE is the first 3 bytes of the
result of encrypting an all-zero block with the key. This field is informational and
must not be used as a key identity oracle.

| Test | Description |
|------|-------------|
| check_value_present | Generate AES-128 key → CKA_CHECK_VALUE is 3 bytes, not empty |
| check_value_stable | Read CKA_CHECK_VALUE twice on same key → identical bytes |
| check_value_different_keys | Generate two different AES-128 keys → check values are typically different (probabilistic, not asserting equality) |
| check_value_known_key | Import all-zero AES-128 key → check value must be 66-E9-4B (first 3 bytes of AES(0x000...0, 0x000...0)) |
| check_value_not_oracle | Two keys with accidentally identical check values → the check value does not uniquely identify a key (test informs, does not fail on collision) |

### 5.9 Provenance Chain

| Test | Description |
|------|-------------|
| provenance_generate | Generate → CKA_LOCAL=True, CKA_KEY_GEN_MECHANISM=<mechanism>, CKA_ALWAYS_SENSITIVE=True if CKA_SENSITIVE=True |
| provenance_import | Import → CKA_LOCAL=False, CKA_KEY_GEN_MECHANISM=CK_UNAVAILABLE_INFORMATION, CKA_ALWAYS_SENSITIVE=False |
| provenance_unwrap | Wrap then unwrap → CKA_LOCAL=False, CKA_ALWAYS_SENSITIVE depends on original and wrap key |
| provenance_derive | Derive via HKDF → CKA_LOCAL=False, CKA_KEY_GEN_MECHANISM=CKM_HKDF_DERIVE |
| provenance_copy | C_CopyObject of generated key → CKA_LOCAL still True, CKA_ALWAYS_SENSITIVE preserved |

---

## 6. Cryptoki Init & Threading (`test_init.py`) — ~25 tests

**File:** `src/pkcs11-check/testcases/test_init.py`
**OASIS references:** PKCS#11 v3.2 section 5.4 (C_Initialize, C_Finalize),
section 5.4.4 (threading model), section 9.4 (C_GetFunctionStatus, C_CancelFunction).

Each test in this file runs in a freshly spawned subprocess (extra isolation layer)
because the tests deliberately call C_Initialize and C_Finalize in non-standard ways
that could corrupt module state for subsequent tests.

### 6.1 C_Initialize Argument Models

OASIS section 5.4.1 defines three valid argument patterns for C_Initialize:

1. NULL_PTR — application will not use multiple threads
2. Pointer to CK_C_INITIALIZE_ARGS with pCreateMutex=NULL and CKF_OS_LOCKING_OK —
   Cryptoki uses OS threading primitives
3. Pointer to CK_C_INITIALIZE_ARGS with all four mutex callbacks populated —
   Cryptoki uses application-supplied mutex functions

| Test | Args | Expected |
|------|------|----------|
| init_null_args | NULL_PTR | CKR_OK; module must work in single-threaded mode |
| init_os_locking | CKF_OS_LOCKING_OK, no callbacks | CKR_OK or CKR_CANT_LOCK if OS locking unavailable |
| init_custom_mutex | All four callbacks (CreateMutex/DestroyMutex/LockMutex/UnlockMutex) | CKR_OK; verify callbacks are invoked during multi-threaded operations |
| init_reserved_nonzero | CK_C_INITIALIZE_ARGS.pReserved != NULL | CKR_ARGUMENTS_BAD (reserved must be NULL) |
| init_partial_callbacks | Only two of four callbacks set, others NULL | CKR_ARGUMENTS_BAD (must be all or none) |
| init_os_locking_and_callbacks | CKF_OS_LOCKING_OK AND all callbacks set | CKR_OK (both are acceptable per spec) |

### 6.2 Double-Init and Error Codes

| Test | Description |
|------|-------------|
| double_init | C_Initialize → C_Initialize again → CKR_CRYPTOKI_ALREADY_INITIALIZED |
| double_init_with_os_locking | C_Initialize(CKF_OS_LOCKING_OK) → C_Initialize again → CKR_CRYPTOKI_ALREADY_INITIALIZED |
| init_after_finalize | C_Initialize → C_Finalize → C_Initialize → CKR_OK (valid reinit) |
| cant_lock | If module cannot provide requested locking → CKR_CANT_LOCK |
| need_threads | If threading needed by app but not granted → CKR_NEED_TO_CREATE_THREADS (record if encountered) |

### 6.3 C_Finalize Cycle (Stress)

| Test | Description |
|------|-------------|
| init_finalize_1000_cycles | Loop C_Initialize → C_Finalize 1000 times in a single subprocess; monitor RSS before and after; fail if growth exceeds 5 MB |
| finalize_with_open_sessions | C_Initialize → C_OpenSession → C_Finalize without closing session → per spec CKR_SESSION_HANDLE_INVALID on subsequent use; verify no crash |
| finalize_null_arg | C_Finalize(NULL) → CKR_OK (NULL is the only valid argument per OASIS section 5.4.2) |
| finalize_nonzero_arg | C_Finalize(non-NULL) → CKR_ARGUMENTS_BAD |

### 6.4 Init/Finalize Race Across Threads

| Test | Description |
|------|-------------|
| init_finalize_race_10_threads | 10 threads simultaneously call C_Initialize; exactly one must get CKR_OK, rest must get CKR_CRYPTOKI_ALREADY_INITIALIZED; no crash |
| init_finalize_concurrent | Thread A: C_Initialize loop. Thread B: C_Finalize loop. Run 100 iterations. No crash, error codes must be CKR_OK or CKR_CRYPTOKI_ALREADY_INITIALIZED or CKR_CRYPTOKI_NOT_INITIALIZED (no other values) |

### 6.5 Fork Safety

POSIX mandates that the child process after fork() has only one thread. A PKCS#11
module that uses background threads must either document its fork behavior or disable
those threads in the child. This test verifies the module does not crash when the
pattern is used.

| Test | Description |
|------|-------------|
| init_before_fork | C_Initialize → fork() → child calls C_Initialize again → child runs a simple sign test → exits. Parent waits for child exit code 0. |
| init_in_child_only | fork() before C_Initialize → child initializes and operates → parent never initializes → no cross-contamination |

### 6.6 Legacy Parallel Functions

OASIS section 9.4 (v2.40) and section 5.9 (v3.2) state that C_GetFunctionStatus
and C_CancelFunction are legacy functions retained for backward compatibility and
**must** return CKR_FUNCTION_NOT_PARALLEL. Modules must export these function pointers;
they may not be NULL.

| Test | Description |
|------|-------------|
| get_function_status | C_GetFunctionStatus(session) → must return CKR_FUNCTION_NOT_PARALLEL (not CKR_FUNCTION_NOT_SUPPORTED, not a crash) |
| cancel_function | C_CancelFunction(session) → must return CKR_FUNCTION_NOT_PARALLEL |
| legacy_function_pointers_not_null | Inspect CK_FUNCTION_LIST: pC_GetFunctionStatus and pC_CancelFunction must not be NULL |

---

## 7. Token Info Flags Matrix (`test_token_flags.py`) — ~20 tests

**File:** `src/pkcs11-check/testcases/test_token_flags.py`
**OASIS references:** PKCS#11 v3.2 section 5.5.1 (CK_TOKEN_INFO structure),
table of CKF_* flag values and their semantics.
**Note:** Tests that trigger PIN lockout require `@pytest.mark.destructive`.

### 7.1 User PIN Flags

| Test | Description |
|------|-------------|
| user_pin_count_low | Enter wrong PIN (retryMax - 2) times. C_GetTokenInfo → CKF_USER_PIN_COUNT_LOW must be set. `@pytest.mark.destructive` |
| user_pin_final_try | Enter wrong PIN (retryMax - 1) times. CKF_USER_PIN_FINAL_TRY must be set. `@pytest.mark.destructive` |
| user_pin_locked | Exhaust all retries. CKF_USER_PIN_LOCKED must be set. CKF_USER_PIN_FINAL_TRY must be cleared. `@pytest.mark.destructive` |
| user_pin_flags_clear_after_so_reset | Lock user PIN. SO logs in, calls C_InitPIN. CKF_USER_PIN_LOCKED must be cleared. `@pytest.mark.destructive` |

### 7.2 SO PIN Flags

| Test | Description |
|------|-------------|
| so_pin_count_low | Enter wrong SO PIN (retryMax - 2) times. CKF_SO_PIN_COUNT_LOW must be set. `@pytest.mark.destructive` |
| so_pin_final_try | Enter wrong SO PIN (retryMax - 1) times. CKF_SO_PIN_FINAL_TRY must be set. `@pytest.mark.destructive` |
| so_pin_locked | Exhaust SO PIN retries. CKF_SO_PIN_LOCKED must be set. `@pytest.mark.destructive` |

### 7.3 Login and Initialization Flags

| Test | Description |
|------|-------------|
| login_required_set | If token is configured to require login, CKF_LOGIN_REQUIRED=1. Verify by attempting C_Sign without login on a CKA_PRIVATE=True object → CKR_USER_NOT_LOGGED_IN. |
| user_pin_initialized | Fresh token with no user PIN: CKF_USER_PIN_INITIALIZED=0. After C_InitPIN: CKF_USER_PIN_INITIALIZED=1. `@pytest.mark.destructive` |
| token_initialized_flag | After C_InitToken: CKF_TOKEN_INITIALIZED=1. `@pytest.mark.destructive` |
| protected_auth_path_report | If token has CKF_PROTECTED_AUTHENTICATION_PATH=1 (hardware PIN pad), report the flag in the test output and skip PIN-based tests with appropriate skip message. |

### 7.4 RNG and Device Error Flags

| Test | Description |
|------|-------------|
| rng_flag_consistency | If CKF_RNG=1 in token info, then C_GenerateRandom must succeed. If CKF_RNG=0, C_GenerateRandom should return CKR_RANDOM_NO_RNG or CKR_FUNCTION_NOT_SUPPORTED. |
| device_error_zero_after_success | Perform a successful AES encrypt. C_GetTokenInfo → ulDeviceError must be 0. |
| device_error_reported_after_failure | On modules that set ulDeviceError (hardware tokens), record the value after an induced hardware error (if testable). This test is marked `@pytest.mark.hardware_only` and skipped in CI. |

### 7.5 Flag Consistency Invariants

The OASIS spec section 5.5.1 implies that token flags must not change during a session
unless an explicit action (login attempt, token initialization, PIN change) triggers
the change. The following tests verify this invariant.

| Test | Description |
|------|-------------|
| flags_stable_during_session | Open session. Read token flags. Perform 100 generate/sign/verify operations. Read flags again. Flags must be identical (no spurious changes). |
| flags_no_count_low_without_failed_login | Fresh session with correct login. CKF_USER_PIN_COUNT_LOW must remain 0 after successful operations. |
| flags_mutual_exclusion | CKF_USER_PIN_LOCKED and CKF_USER_PIN_FINAL_TRY must not both be set simultaneously. Same for SO variants. |

---

## 8. Buffer Management (`test_buffers.py`) — ~30 tests

**File:** `src/pkcs11-check/testcases/test_buffers.py`
**OASIS references:** PKCS#11 v3.2 section 5.2 (Conventions for functions returning
data) defines the two-call convention: first call with NULL output pointer returns
required length in the length parameter; second call with allocated buffer of at least
that size returns the data.

This is one of the most commonly misimplemented aspects of PKCS#11. Tests in this
file exercise the NULL-buffer pattern for every API family.

### 8.1 Encryption and Decryption (OASIS section 5.10)

| Test | Function | Pattern |
|------|----------|---------|
| encrypt_null_output_returns_length | C_Encrypt | C_EncryptInit, then C_Encrypt(NULL, &len) → CKR_OK, len > 0 |
| encrypt_allocate_and_retry | C_Encrypt | allocate len bytes, C_Encrypt(buf, &len) → CKR_OK, len = actual ciphertext length |
| encrypt_undersized_fails | C_Encrypt | provide len-1 bytes → CKR_BUFFER_TOO_SMALL |
| encrypt_zero_size_fails | C_Encrypt | provide 0 bytes → CKR_BUFFER_TOO_SMALL with correct len |
| decrypt_null_output_returns_length | C_Decrypt | same pattern for decryption |
| decrypt_undersized_fails | C_Decrypt | len-1 → CKR_BUFFER_TOO_SMALL |
| decrypt_retry_after_too_small | C_Decrypt | CKR_BUFFER_TOO_SMALL → retry with returned length → CKR_OK |
| encrypt_final_null_output | C_EncryptFinal | same pattern for finalization step |

### 8.2 Sign and Verify (OASIS section 5.12)

| Test | Function | Pattern |
|------|----------|---------|
| sign_null_output_returns_length | C_Sign | C_SignInit, then C_Sign(NULL, &len) → CKR_OK, len > 0 |
| sign_exact_size_succeeds | C_Sign | provide exactly len bytes → CKR_OK |
| sign_undersized_fails | C_Sign | provide len-1 bytes → CKR_BUFFER_TOO_SMALL |
| sign_retry_after_too_small | C_Sign | CKR_BUFFER_TOO_SMALL → retry → CKR_OK |
| sign_final_null_output | C_SignFinal | same pattern for multi-part sign |

### 8.3 Key Wrapping (OASIS section 5.15)

| Test | Function | Pattern |
|------|----------|---------|
| wrap_null_output_returns_length | C_WrapKey | C_WrapKey(NULL, &len) → CKR_OK, len > 0 |
| wrap_exact_size_succeeds | C_WrapKey | provide exactly len bytes → CKR_OK |
| wrap_undersized_fails | C_WrapKey | provide len-1 bytes → CKR_BUFFER_TOO_SMALL |
| wrap_retry_after_too_small | C_WrapKey | retry with reported length → succeeds |

### 8.4 Attribute Retrieval (OASIS section 5.7.5)

C_GetAttributeValue also follows a length-probe pattern: pass a template with
ulValueLen=0 and pValue=NULL to discover the required lengths.

| Test | Description |
|------|-------------|
| get_attr_null_value_returns_length | CK_ATTRIBUTE with pValue=NULL → C_GetAttributeValue sets ulValueLen, returns CKR_OK |
| get_attr_allocate_and_retry | allocate ulValueLen bytes, retry → CKR_OK, data populated |
| get_attr_undersized | pValue allocated to ulValueLen-1 → CKR_BUFFER_TOO_SMALL, ulValueLen set to required size |
| get_attr_multi_attribute_probe | Probe for multiple attributes in one call (some NULL, some not) → lengths for all attributes returned |

### 8.5 Slot and Mechanism Lists (OASIS sections 5.5.1, 5.5.2)

| Test | Function | Pattern |
|------|----------|---------|
| get_slot_list_null_returns_count | C_GetSlotList(NULL, &count) → CKR_OK, count >= 1 |
| get_slot_list_allocate_and_retry | allocate count slots → C_GetSlotList(buf, &count) → CKR_OK |
| get_slot_list_undersized | allocate count-1 → CKR_BUFFER_TOO_SMALL |
| get_mechanism_list_null_returns_count | C_GetMechanismList(slot, NULL, &count) → CKR_OK, count >= 1 |
| get_mechanism_list_allocate_and_retry | allocate count mechanisms → succeeds |
| get_mechanism_list_undersized | allocate count-1 → CKR_BUFFER_TOO_SMALL |

### 8.6 Interface List (OASIS v3.0 section 5.4.3)

`@pytest.mark.requires_v30`

| Test | Function | Pattern |
|------|----------|---------|
| get_interface_list_null_returns_count | C_GetInterfaceList(NULL, &count) → CKR_OK, count >= 1 |
| get_interface_list_allocate_and_retry | allocate count → succeeds |
| get_interface_list_undersized | allocate count-1 → CKR_BUFFER_TOO_SMALL |

### 8.7 Message-Based API Buffers (v3.0)

`@pytest.mark.requires_v30`

| Test | Description |
|------|-------------|
| encrypt_message_null_output | C_EncryptMessage(NULL, &len) → CKR_OK, len set |
| encrypt_message_undersized | len-1 → CKR_BUFFER_TOO_SMALL |
| decrypt_message_null_output | same for decryption |

### 8.8 NULL_PTR Init to Terminate Active Operation

OASIS section 5.2 paragraph 3 specifies: "If a function that initializes an operation
is called with a NULL mechanism pointer, it terminates any active operation of the same
type." This is the clean-cancel pattern.

| Test | Description |
|------|-------------|
| terminate_encrypt_via_null_init | C_EncryptInit(mech) → C_EncryptInit(NULL) → operation terminated → C_Encrypt returns CKR_OPERATION_NOT_INITIALIZED |
| terminate_sign_via_null_init | C_SignInit(mech) → C_SignInit(NULL) → C_Sign returns CKR_OPERATION_NOT_INITIALIZED |
| terminate_digest_via_null_init | C_DigestInit(mech) → C_DigestInit(NULL) → C_DigestFinal returns CKR_OPERATION_NOT_INITIALIZED |
| terminate_then_new_init_succeeds | Terminate with NULL init → new C_EncryptInit(mech) → C_Encrypt succeeds |

---

## 9. Non-Key Object Classes (`test_objects.py`) — ~25 tests

**File:** `src/pkcs11-check/testcases/test_objects.py`
**OASIS references:** PKCS#11 v3.2 section 4.5 (CKO_DATA), section 4.6
(CKO_HW_FEATURE), section 4.8 (CKO_DOMAIN_PARAMETERS), section 6.16 (CKO_OTP_KEY).

### 9.1 CKO_DATA Objects

CKO_DATA objects are the simplest PKCS#11 objects: opaque byte blobs with an
application label, an object ID, and a value. They have no cryptographic meaning
but are used for storing certificates, policy blobs, or protocol state.

| Test | Description |
|------|-------------|
| data_create_and_read | C_CreateObject(CKO_DATA, CKA_VALUE=b"hello") → C_GetAttributeValue(CKA_VALUE) → compare |
| data_with_application_label | CKA_APPLICATION="my-app" → C_FindObjects(CKA_APPLICATION="my-app") → found |
| data_visibility_session | CKA_TOKEN=False → close session → C_FindObjects → not found |
| data_visibility_token | CKA_TOKEN=True → close/reopen session → C_FindObjects → found. `@pytest.mark.destructive` |
| data_modify | C_SetAttributeValue(CKA_VALUE=b"updated") → C_GetAttributeValue → new value |
| data_read_only | C_CreateObject with CKA_MODIFIABLE=False → C_SetAttributeValue → CKR_ATTRIBUTE_READ_ONLY |
| data_destroy | C_CreateObject → C_DestroyObject → C_GetAttributeValue → CKR_OBJECT_HANDLE_INVALID. `@pytest.mark.destructive` |
| data_search_by_value | C_FindObjects(CKA_VALUE=b"hello") → finds the object |
| data_search_multiple | Create 10 CKO_DATA objects with different labels → C_FindObjects(CKO_DATA) → 10 results |

### 9.2 HKDF Data Output (CKM_HKDF_DATA → CKO_DATA)

CKM_HKDF_DATA is a special HKDF mechanism variant that produces a CKO_DATA object
rather than a key object. This allows HKDF to be used to derive arbitrary byte strings
(not just keys) within the token's storage.

| Test | Description |
|------|-------------|
| hkdf_data_creates_cko_data | C_DeriveKey(CKM_HKDF_DATA) → result object class is CKO_DATA |
| hkdf_data_value_readable | C_GetAttributeValue(CKA_VALUE) on result → bytes match Python HKDF output |
| hkdf_data_length | Verify CKA_VALUE length = requested output length |

### 9.3 CKO_DOMAIN_PARAMETERS

Domain parameter objects store the public parameters for DH or DSA operations and
allow multiple keys to share a common parameter set stored once on the token.

| Test | Description |
|------|-------------|
| domain_params_dsa_create | C_CreateObject(CKO_DOMAIN_PARAMETERS, CKA_KEY_TYPE=CKK_DSA, CKA_PRIME=p, CKA_SUBPRIME=q, CKA_BASE=g) → CKR_OK |
| domain_params_dsa_read | Create → C_GetAttributeValue(CKA_PRIME, CKA_SUBPRIME, CKA_BASE) → values match |
| domain_params_dh_create | C_CreateObject(CKO_DOMAIN_PARAMETERS, CKA_KEY_TYPE=CKK_DH, CKA_PRIME=p, CKA_BASE=g) → CKR_OK |
| domain_params_generate_dsa | C_GenerateDomainParameters(CKM_DSA_PARAMETER_GEN, template with key size) → produces CKO_DOMAIN_PARAMETERS object |
| domain_params_use_in_keygen | Use generated domain params object → C_GenerateKeyPair with CKA_PRIME/CKA_SUBPRIME/CKA_BASE taken from params object → succeeds |

### 9.4 CKO_HW_FEATURE

Hardware feature objects expose physical token capabilities. CKH_CLOCK reads the
token's real-time clock; CKH_MONOTONIC_COUNTER reads a counter that never decreases.
These are discovery tests that report present or absent rather than pass/fail.

| Test | Description |
|------|-------------|
| hw_feature_enumerate | C_FindObjects(CKO_HW_FEATURE) → list all hardware feature objects; record types found |
| hw_feature_clock | If CKH_CLOCK present: C_GetAttributeValue(CKA_VALUE) → 16-byte BCD time string; parse and verify format (YYYYMMDDHHMMSS\0\0 per OASIS section 4.6.2) |
| hw_feature_monotonic_counter_read | If CKH_MONOTONIC_COUNTER present: read CKA_VALUE → non-zero bytes; verify length = CKA_VALUE_LEN |
| hw_feature_monotonic_counter_increment | Read counter, perform operation, read again → value must not have decreased. `@pytest.mark.destructive` |
| hw_feature_user_interface | If CKH_USER_INTERFACE present: record CKA_VALUE format; test is informational |

### 9.5 CKO_OTP_KEY

One-time password key objects (HOTP/TOTP) are defined in PKCS#11 section 6.16.
Given limited software token support, all tests carry
`@pytest.mark.skip_if_mechanism_absent("CKM_HOTP_KEY_GEN")`.

| Test | Description |
|------|-------------|
| otp_key_create | C_CreateObject(CKO_OTP_KEY) with CKA_OTP_FORMAT, CKA_OTP_LENGTH, CKA_VALUE → CKR_OK |
| otp_key_attributes | Read CKA_OTP_FORMAT, CKA_OTP_LENGTH, CKA_OTP_COUNTER → values match template |
| otp_key_generate | C_GenerateKey(CKM_HOTP_KEY_GEN) → CKO_OTP_KEY object created |

### 9.6 Object Lifecycle Summary Test

| Test | Description |
|------|-------------|
| full_lifecycle | For each non-key class (DATA, DOMAIN_PARAMETERS, HW_FEATURE where supported): create → find → get attributes → modify (if modifiable) → copy → destroy → verify gone |

---

## 10. FIPS Compliance Expanded (`test_fips.py` expanded) — ~15 tests

**File:** `src/pkcs11-check/testcases/test_fips.py`
**Note:** Tests that require FIPS-mode token behavior are marked
`@pytest.mark.fips_mode_required` and auto-skip on non-FIPS tokens.

### 10.1 Service Indicators

FIPS 140-3 Implementation Guidance section 2.4.C requires approved modules to provide
a service indicator that distinguishes approved from non-approved operations. Some tokens
expose this via a vendor extension or a specific attribute on key objects or session.

| Test | Description |
|------|-------------|
| service_indicator_approved_aes_cbc | Perform AES-256-CBC encrypt. If token supports service indicator retrieval, verify indicator = APPROVED. `@pytest.mark.fips_mode_required` |
| service_indicator_non_approved_des | Perform 3DES-CBC encrypt (non-approved in FIPS 140-3 after 2023). If service indicator available, verify indicator = NON_APPROVED. Record result. |
| service_indicator_vendor_mechanism | Perform vendor-specific operation. Service indicator must indicate non-approved if the mechanism is not on the approved algorithm list. |

### 10.2 Mode Transitions

| Test | Description |
|------|-------------|
| approved_only_mode_rejects_des | If module supports an APPROVED-ONLY mode and it is active, C_EncryptInit(CKM_DES3_CBC) must return CKR_MECHANISM_INVALID. `@pytest.mark.fips_mode_required` |
| approved_only_mode_rejects_md5 | C_DigestInit(CKM_MD5) in approved-only mode → CKR_MECHANISM_INVALID. `@pytest.mark.fips_mode_required` |
| approved_only_mode_accepts_aes | C_EncryptInit(CKM_AES_CBC) in approved-only mode → CKR_OK. `@pytest.mark.fips_mode_required` |

### 10.3 Pairwise Consistency Self-Test

FIPS 140-3 standard section 9.9 requires a pairwise consistency self-test (PCST) to
be performed when an asymmetric key pair is generated. The test verifies sign+verify
(or encrypt+decrypt for RSA) round-trips successfully.

| Test | Description |
|------|-------------|
| pcst_rsa_implicit | C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN) → module performs implicit PCST; verify by immediately signing and verifying → success means PCST was not triggered as a failure |
| pcst_ec_p256_implicit | C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN, P-256) → same pattern |
| pcst_failure_simulation | If module provides a way to inject a PCST failure (vendor test interface), trigger it → module must enter error state and refuse operations. `@pytest.mark.hardware_only` |

### 10.4 Conditional Self-Tests

FIPS 140-3 section 10.3.A requires conditional self-tests on key generation and import.

| Test | Description |
|------|-------------|
| cst_on_key_generation | Generate RSA-2048 key pair. Module must not generate a key that fails its own self-test (verifiable only if module exposes self-test results). |
| cst_on_key_import | Import raw RSA key material. Module must validate key parameters (e.g., e > 65536 if required). Attempt to import key with invalid exponent (e=1) → CKR_ATTRIBUTE_VALUE_INVALID. |
| cst_on_aes_key_import | Import AES key of unsupported size (e.g., 24 bytes on FIPS-strict token that only allows 128/256) → CKR_TEMPLATE_INCONSISTENT or CKR_MECHANISM_PARAM_INVALID. |

### 10.5 Role Separation

| Test | Description |
|------|-------------|
| so_cannot_do_crypto | Log in as SO. Attempt C_EncryptInit → must return CKR_USER_TYPE_INVALID or CKR_USER_NOT_LOGGED_IN. |
| user_cannot_init_token | Log in as User. Attempt C_InitToken → must return CKR_USER_TYPE_INVALID. |
| so_can_init_pin | Log in as SO. Call C_InitPIN → CKR_OK (SO role: PIN management only). `@pytest.mark.destructive` |

### 10.6 Algorithm Restrictions in FIPS Mode

| Test | Description |
|------|-------------|
| fips_no_des | In FIPS mode: C_GetMechanismInfo(CKM_DES_CBC) → CKR_MECHANISM_INVALID or mechanism absent from list. `@pytest.mark.fips_mode_required` |
| fips_no_md5 | C_GetMechanismInfo(CKM_MD5) → not in mechanism list. `@pytest.mark.fips_mode_required` |
| fips_no_rc2 | C_GetMechanismInfo(CKM_RC2_CBC) → not in mechanism list. `@pytest.mark.fips_mode_required` |
| fips_no_rc4 | C_GetMechanismInfo(CKM_RC4) → not in mechanism list. `@pytest.mark.fips_mode_required` |

---

## 11. Extended Protocol Suite (`test_protocol.py` expanded) — ~15 tests

**File:** `src/pkcs11-check/testcases/test_protocol.py`
**Python dependencies:** `python-cose` (COSE), `webauthn` or `fido2` (FIDO2),
`paramiko` or `cryptography` (SSH), `joserfc` or `python-jose` (JWS/JWE),
`pyopenssl` or `cryptography` (OCSP), `pyhanko` (PKCS#12).
All protocol tests are `@pytest.mark.requires_mechanism` and skip gracefully when
the required algorithm is absent.

### 11.1 COSE Signing (CBOR Object Signing and Encryption)

COSE (RFC 9052) is used in FIDO2/WebAuthn, IETF attestation, and IoT protocols.

| Test | Algorithm | Notes |
|------|-----------|-------|
| cose_sign1_es256 | ES256 (P-256 + SHA-256) | Generate EC keypair → COSE_Sign1 → verify with `python-cose` |
| cose_sign1_es384 | ES384 (P-384 + SHA-384) | same |
| cose_sign1_eddsa | EdDSA (Ed25519) | same |
| cose_mac0_hmac_sha256 | HMAC-SHA256 | Generate HMAC key → COSE_Mac0 → verify |

### 11.2 WebAuthn / FIDO2 Attestation Format

| Test | Description |
|------|-------------|
| webauthn_packed_attestation | Sign a WebAuthn authenticatorData + clientDataHash using PKCS#11 ECDSA P-256. Construct packed attestation statement. Verify using `fido2` library. |
| webauthn_self_attestation | Self-attestation (aaguid=zeros, no attestation cert) → verify with `fido2.attestation` |

### 11.3 SSH Key Signing

SSH uses its own signature format (RFC 4253 section 6.6). The `ssh-keysign` format
wraps EC or RSA signatures in a length-prefixed binary structure.

| Test | Description |
|------|-------------|
| ssh_rsa_sign_pkcs1 | Generate RSA-2048 key → sign SSH-formatted message → parse and verify with `cryptography` |
| ssh_ecdsa_p256_sign | Generate P-256 key → sign → verify with `cryptography` (RFC 5656 format) |
| ssh_ed25519_sign | Generate Ed25519 key → sign → verify with `cryptography` (RFC 8709 format) |

### 11.4 JSON Web Signature (JWS)

JWS (RFC 7515) is the JSON representation of a signed message.

| Test | Algorithm | Notes |
|------|-----------|-------|
| jws_rs256 | RS256 (RSA-PKCS#1 + SHA-256) | Sign → compact serialization → verify with `joserfc` |
| jws_es256 | ES256 (P-256 + SHA-256) | Sign → compact serialization → verify |
| jws_eddsa | EdDSA (Ed25519) | Sign → compact serialization → verify |

### 11.5 JWE Key Wrapping

JWE (RFC 7516) encrypts a content encryption key using an asymmetric or symmetric
key wrapping algorithm.

| Test | Algorithm | Notes |
|------|-----------|-------|
| jwe_rsa_oaep | RSA-OAEP | Wrap 256-bit AES key → JWE compact → unwrap with `cryptography` |
| jwe_a256kw | A256KW (AES-256 Key Wrap) | Wrap AES key → JWE → unwrap |

### 11.6 OCSP Response Signing

OCSP (RFC 6960) responses are signed by a CA or delegated responder.

| Test | Description |
|------|-------------|
| ocsp_response_sign_verify | Generate RSA-2048 key → sign minimal OCSP BasicResponse DER (constructed manually) → verify signature with `cryptography.x509.ocsp` |

### 11.7 PKCS#12 Import/Export

PKCS#12 (RFC 7292) is a container format for private key + certificate chain.

| Test | Description |
|------|-------------|
| pkcs12_export_private_key | Generate RSA-2048 key on token (extractable) → export as PKCS#12 PFX with password → parse with `cryptography.hazmat.primitives.serialization.pkcs12.load_pkcs12` → verify key material matches |
| pkcs12_import_private_key | Load a known PFX file → import private key and certificate into token → verify key is usable for signing. `@pytest.mark.destructive` |

---

## 12. Race Condition Extensions — ~10 tests

### 12.1 New Tests in `test_fault.py`

| Test | Description |
|------|-------------|
| destroy_during_encrypt | Thread A: C_EncryptInit → C_EncryptUpdate (long data in loop). Thread B: C_DestroyObject(key) concurrently. Expected: Either the encrypt completes successfully (thread B waits) OR thread A gets CKR_KEY_HANDLE_INVALID or CKR_OBJECT_HANDLE_INVALID. Must not crash. |
| handle_reuse_not_allowed | C_GenerateKey → handle = H. C_DestroyObject(H). C_GenerateKey again → new_handle. Assert new_handle != H OR that using H returns CKR_OBJECT_HANDLE_INVALID (no silent reuse of the old handle value for a different object). `@pytest.mark.destructive` |
| session_close_during_message_op | `@pytest.mark.requires_v30`. Thread A: C_MessageEncryptInit → C_EncryptMessageBegin → sleep(100ms). Thread B: C_CloseSession. Thread A wakes and calls C_EncryptMessageNext → must return CKR_SESSION_HANDLE_INVALID or CKR_OPERATION_NOT_INITIALIZED (no crash). |
| c_initialize_while_sessions_exist | C_Initialize → C_OpenSession → do NOT close session → C_Finalize → C_Initialize again. Verify old session handle returns CKR_SESSION_HANDLE_INVALID after re-init. |

### 12.2 New Tests in `test_stress.py`

| Test | Description |
|------|-------------|
| login_race | 10 threads simultaneously call C_Login(CKU_USER, pin) on separate sessions opened on the same slot. All must get CKR_OK or CKR_USER_ALREADY_LOGGED_IN (login is slot-wide in PKCS#11 v2.40+). No other return codes permitted. |
| operation_after_login_race | Thread A: C_Login on shared slot. Thread B: Immediately after C_OpenSession, attempts C_Sign (before or concurrent with login). Thread B must either succeed (login happened first) or get CKR_USER_NOT_LOGGED_IN (login not yet complete). Must not crash or return undefined codes. |
| logout_during_async_join | `@pytest.mark.requires_v32`. Submit async keygen → before join completes, C_Logout. Then C_AsyncJoin → verify clean termination (CKR_USER_NOT_LOGGED_IN or operation completes normally). |
| multi_slot_concurrent_sessions | Open sessions on two different slots simultaneously from 8 threads. Perform sign/verify on each slot concurrently for 10 seconds. Verify no cross-slot handle contamination. |
| find_objects_interleave_stress | 4 threads each run C_FindObjectsInit → C_FindObjects × N → C_FindObjectsFinal concurrently. Sessions are separate. Verify each thread's result set is complete and correct. |
| object_search_while_creating | Thread A: continuously creates and destroys session objects. Thread B: continuously calls C_FindObjects. Verify B never returns a handle that does not exist (no time-of-check/time-of-use issue in find results). |

---

## 13. Test Count Addendum

The following table records all new test files and estimated test counts introduced by
this addendum. These are in addition to the ~2,400+ tests described in the main spec.

| File | Section | Estimated tests | Notes |
|------|---------|-----------------|-------|
| `test_kdf.py` | 3 | ~50 | HKDF, SP 800-108, PBKDF2, TLS PRF, X9.63, cofactor ECDH, ECMQV |
| `test_sha3.py` | 4 | ~40 | SHA-3 KAT, SHAKE XOF, KMAC, XOF init/extract API, PQC+SHA3 combos |
| `test_attrs.py` | 5 | ~35 | Template attributes, provenance chain, CKA_LOCAL, CKA_PUBLIC_KEY_INFO |
| `test_init.py` | 6 | ~25 | C_Initialize threading models, fork safety, legacy functions |
| `test_token_flags.py` | 7 | ~20 | CK_TOKEN_INFO.flags transitions and consistency |
| `test_buffers.py` | 8 | ~30 | NULL-buffer two-call convention, all API families |
| `test_objects.py` | 9 | ~25 | CKO_DATA, CKO_DOMAIN_PARAMETERS, CKO_HW_FEATURE, CKO_OTP_KEY |
| `test_fips.py` (expanded) | 10 | ~15 | Service indicators, self-tests, role separation, algorithm restrictions |
| `test_protocol.py` (expanded) | 11 | ~15 | COSE, WebAuthn, SSH, JWS, JWE, OCSP, PKCS#12 |
| `test_fault.py` (additions) | 12.1 | ~4 | Race conditions: destroy during encrypt, handle reuse, session close during message op |
| `test_stress.py` (additions) | 12.2 | ~6 | Login race, async join race, multi-slot concurrent, find interleave stress |
| **Addendum subtotal** | | **~265** | |
| Main spec total | | ~2,400+ | From `2026-03-16-comprehensive-testing-design.md` |
| **Combined total** | | **~2,665+** | |

All file paths are under `src/pkcs11-check/testcases/`. New test files added by this
addendum follow the same naming, import, and marker conventions as existing test files
documented in the main spec.

---

## 14. Standards Reference Index

The following table lists all NIST, OASIS, IETF, and ANSI standards referenced in
this addendum, with publication dates, canonical URLs, and the test files where they
are normatively used.

| Standard | Title | Date | URL | Used in |
|----------|-------|------|-----|---------|
| **OASIS PKCS#11 v3.2** | PKCS#11 Cryptographic Token Interface Base Specification Version 3.2 | 2024 | https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html | All test files |
| **OASIS PKCS#11 v3.0** | PKCS#11 Cryptographic Token Interface Base Specification Version 3.0 | 2020 | https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.0/os/pkcs11-spec-v3.0-os.html | test_buffers.py (message API), test_init.py, test_kdf.py |
| **OASIS PKCS#11 v2.40** | PKCS#11 Cryptographic Token Interface Base Specification Version 2.40 | 2015 | https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html | test_init.py (legacy functions), backward-compat tests |
| **FIPS 186-5** | Digital Signature Standard (DSS) | Feb 2023 | https://doi.org/10.6028/NIST.FIPS.186-5 | test_sign.py, test_kat.py |
| **FIPS 202** | SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions | Aug 2015 | https://doi.org/10.6028/NIST.FIPS.202 | test_sha3.py |
| **SP 800-185** | SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, ParallelHash | Dec 2016 | https://doi.org/10.6028/NIST.SP.800-185 | test_sha3.py (KMAC section) |
| **SP 800-186** | Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters | Feb 2023 | https://doi.org/10.6028/NIST.SP.800-186 | test_sign.py, test_kdf.py (curve OID validation) |
| **SP 800-56A Rev. 3** | Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography | Apr 2018 | https://doi.org/10.6028/NIST.SP.800-56Ar3 | test_kdf.py (cofactor ECDH, ECMQV) |
| **SP 800-56B Rev. 2** | Recommendation for Pair-Wise Key-Establishment Using Integer Factorization Cryptography | Mar 2019 | https://doi.org/10.6028/NIST.SP.800-56Br2 | test_kdf.py (RSA-KEM) |
| **SP 800-56C Rev. 2** | Recommendation for Key-Derivation Methods in Key-Establishment Schemes | Aug 2020 | https://doi.org/10.6028/NIST.SP.800-56Cr2 | test_kdf.py (HKDF, X9.63 KDF) |
| **SP 800-108 Rev. 1** | Recommendation for Key Derivation Using Pseudorandom Functions | Aug 2022 | https://doi.org/10.6028/NIST.SP.800-108r1 | test_kdf.py (counter/feedback/double-pipeline modes) |
| **SP 800-132** | Recommendation for Password-Based Key Derivation, Part 1: Storage Applications | Dec 2010 | https://doi.org/10.6028/NIST.SP.800-132 | test_kdf.py (PBKDF2 section) |
| **SP 800-38F** | Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping | Dec 2012 | https://doi.org/10.6028/NIST.SP.800-38F | test_keymgmt.py (AES-KW, AES-KWP) |
| **FIPS 180-4** | Secure Hash Standard (SHS) | Aug 2015 | https://doi.org/10.6028/NIST.FIPS.180-4 | test_digest.py, test_kat.py |
| **FIPS 198-1** | The Keyed-Hash Message Authentication Code (HMAC) | Jul 2008 | https://doi.org/10.6028/NIST.FIPS.198-1 | test_digest.py, test_kat.py |
| **FIPS 203** | Module-Lattice-Based Key-Encapsulation Mechanism Standard | Aug 2024 | https://doi.org/10.6028/NIST.FIPS.203 | test_pqc.py, test_sha3.py (ML-KEM + SHAKE) |
| **FIPS 204** | Module-Lattice-Based Digital Signature Standard | Aug 2024 | https://doi.org/10.6028/NIST.FIPS.204 | test_pqc.py, test_sha3.py (ML-DSA + SHAKE) |
| **FIPS 205** | Stateless Hash-Based Digital Signature Standard | Aug 2024 | https://doi.org/10.6028/NIST.FIPS.205 | test_pqc.py, test_sha3.py (SLH-DSA + SHAKE) |
| **RFC 5869** | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | May 2010 | https://www.rfc-editor.org/rfc/rfc5869 | test_kdf.py (HKDF section), KAT vectors |
| **RFC 6070** | PKCS#5 PBKDF2 Test Vectors | Jan 2011 | https://www.rfc-editor.org/rfc/rfc6070 | test_kdf.py (PBKDF2 KAT vectors) |
| **RFC 3394** | Advanced Encryption Standard (AES) Key Wrap Algorithm | Sep 2002 | https://www.rfc-editor.org/rfc/rfc3394 | test_keymgmt.py, test_buffers.py |
| **RFC 7292** | PKCS #12: Personal Information Exchange Syntax v1.1 | Jul 2014 | https://www.rfc-editor.org/rfc/rfc7292 | test_protocol.py (PKCS#12 section) |
| **RFC 7515** | JSON Web Signature (JWS) | May 2015 | https://www.rfc-editor.org/rfc/rfc7515 | test_protocol.py (JWS section) |
| **RFC 7516** | JSON Web Encryption (JWE) | May 2015 | https://www.rfc-editor.org/rfc/rfc7516 | test_protocol.py (JWE section) |
| **RFC 4253** | The Secure Shell (SSH) Transport Layer Protocol | Jan 2006 | https://www.rfc-editor.org/rfc/rfc4253 | test_protocol.py (SSH section) |
| **RFC 5656** | Elliptic Curve Algorithm Integration in the Secure Shell Transport Layer | Dec 2009 | https://www.rfc-editor.org/rfc/rfc5656 | test_protocol.py (SSH ECDSA section) |
| **RFC 8709** | Ed25519 and Ed448 Public Key Algorithms for the Secure Shell Protocol | Feb 2020 | https://www.rfc-editor.org/rfc/rfc8709 | test_protocol.py (SSH EdDSA section) |
| **RFC 6960** | X.509 Internet Public Key Infrastructure Online Certificate Status Protocol — OCSP | Jun 2013 | https://www.rfc-editor.org/rfc/rfc6960 | test_protocol.py (OCSP section) |
| **RFC 9052** | CBOR Object Signing and Encryption (COSE): Structures and Process | Sep 2022 | https://www.rfc-editor.org/rfc/rfc9052 | test_protocol.py (COSE section) |
| **RFC 5480** | Elliptic Curve Cryptography Subject Public Key Information | Mar 2009 | https://www.rfc-editor.org/rfc/rfc5480 | test_attrs.py (CKA_PUBLIC_KEY_INFO SPKI encoding) |
| **ANSI X9.63-2011** | Public Key Cryptography for the Financial Services Industry: Key Agreement and Key Transport Using Elliptic Curve Cryptography | 2011 | ANSI (purchase required) | test_kdf.py (X9.63 KDF section) |
| **FIDO2 / WebAuthn Level 2** | Web Authentication: An API for accessing Public Key Credentials Level 2 | Apr 2021 | https://www.w3.org/TR/webauthn-2/ | test_protocol.py (WebAuthn section) |
