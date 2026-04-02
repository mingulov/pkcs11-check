# Audit 12: RSA Operations

**Date:** 2026-04-01
**OASIS specs referenced:** `rsa.md`
**Files audited:** `test_rsa_extended.py`, `test_rsa_oaep.py`, `test_rsa_key_import.py`, `test_rsa_key_wrapping.py`, `mechanism_registry/_rsa.py`, ACVP/Wycheproof RSA files

## Findings

### Quality Issues

- [NOTED] `test_rsa_extended.py:185,295,320,589` — hardcoded 256-byte output sizes assume RSA-2048. Correct but not parameterized for 3072/4096-bit keys.

### Spec Deviations

- [NOTED] PSS salt lengths correctly match hash output sizes across all variants (SHA-1 through SHA3).
- [NOTED] OAEP default recipe uses SHA-256/MGF1-SHA256 only. Cross-verify test uses SHA-1/MGF1-SHA1. No SHA-384/512 OAEP coverage.

### Coverage Gaps

- [GAP] RSA OAEP — only SHA-1 and SHA-256 hash/MGF combos tested. Missing SHA-384, SHA-512, SHA3 variants, and mismatched hash/MGF combinations.
- [GAP] RSA key size parameterization — no tests with 3072 or 4096-bit keys.
- [GAP] RSA X.509 raw encrypt — NSS known bug documented but no dedicated test verifying correct behavior on other modules.

## Statistics

- Issues found: 0 fixed, 3 gaps documented, 2 noted
