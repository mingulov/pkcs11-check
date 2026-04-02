# Audit 35: Interoperability & Cross-Verification

**Date:** 2026-04-01
**Files audited:** `test_interop.py`, `test_interop_openssl.py`, `test_crossverify.py`, `test_crossverify_extended.py`, `test_metamorphic.py`

## Findings

### Coverage Status

Cross-verification is strong: AES-ECB/GCM, RSA PKCS/PSS/OAEP, ECDSA, EdDSA, HMAC, digest all cross-verified against Python cryptography library. OpenSSL provider interop tested. Metamorphic property tests validate algebraic relations.

### Coverage Gaps

- [GAP] PQC cross-verification — ML-KEM/ML-DSA/SLH-DSA not cross-verified against external implementation (e.g., pqcrypto, liboqs).
- [GAP] Cross-module differential testing — test infrastructure exists (`scripts/cross-module-diff.sh`) but no test file exercises encrypt-on-A/decrypt-on-B pattern.
- [GAP] Key format interop — no test imports a key from OpenSSL and uses it in PKCS#11 or vice versa (PKCS#8/DER format roundtrip).

## Statistics

- Issues found: 0 fixed, 3 gaps documented
