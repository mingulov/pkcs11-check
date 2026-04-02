# Audit 21: Key Wrapping

**Date:** 2026-04-01
**OASIS specs referenced:** `aes_key_wrap.md`, `wrapping-unwrapping_private_keys.md`
**Files audited:** `test_mech_wrap.py`, `test_authenticated_wrap.py`, `test_rsa_key_wrapping.py`, `acvp/aes/test_wrap.py`

## Findings

### Coverage Status

AES-KW roundtrip, RSA wrap/unwrap, block cipher wraps all tested. v3.2 authenticated wrap with AES-GCM implemented.

### Coverage Gaps

- [GAP] AES-KWP — only Wycheproof vector coverage, no functional roundtrip test in main suite.
- [GAP] Authenticated wrap tag tampering — no test verifies tampered tag/AAD is rejected on unwrap.
- [GAP] Unwrap attribute template enforcement — no test verifies restricted attributes (e.g., CKA_SIGN=False) are honored on unwrapped key.
- [GAP] CKA_SENSITIVE propagation via unwrap — spec restricts SENSITIVE based on wrapping key policy.

## Statistics

- Issues found: 0 fixed, 4 gaps documented
