# Audit 28: Security Audit

**Date:** 2026-04-01
**OASIS specs referenced:** `security_and_privacy_considerations.md`, `random_number_generation_functions.md`
**Files audited:** `test_padding_oracle.py`, `test_nonce_quality.py`, `test_tookan.py`, `test_api_security.py`, `test_fuzz.py`, `test_attribute_fuzz.py`, `test_mechanism_fuzz.py`, `test_cve_regression.py`, `docs/cve-regression.md`

## Findings

### Coverage Status

Security testing is a project strength:
- **Padding oracle**: RSA-OAEP and AES-CBC-PAD error timing/uniformity tested
- **Nonce quality**: RNG output statistical testing (frequency, runs, serial correlation)
- **Tookan**: Full attack vector suite (conflicting usage, SENSITIVE escalation, wrap-decrypt oracle)
- **API security**: NULL parameter handling, buffer overflow probes
- **Fuzzing**: Hypothesis property-based tests for attributes and mechanism parameters
- **CVE regression**: 29 tests across 6 modules (NSS, SoftHSM2, TPM2, OpenCryptoki, BouncyHSM, Kryoptic)

### Coverage Gaps

- [GAP] Timing side-channel tests — padding oracle checks error uniformity but no explicit timing measurement for RSA decrypt or ECDSA sign.
- [GAP] RNG bias detection — statistical tests exist but no NIST SP 800-22 full test suite integration.
- [GAP] ECDSA nonce reuse detection — `test_nonce_quality.py` checks RNG but no specific ECDSA k-value uniqueness test (RFC 6979 deterministic ECDSA not tested).
- [GAP] New CVEs since initial release — `docs/cve-regression.md` may not include latest module CVEs.

## Statistics

- Issues found: 0 fixed, 4 gaps documented
