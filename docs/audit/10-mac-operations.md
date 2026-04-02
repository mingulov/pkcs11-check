# Audit 10: MAC Operations

**Date:** 2026-04-01
**OASIS specs referenced:** `hmac_mechanisms.md`, `hash_based_message_authentication_codes.md`, `aes_cmac.md`, `kmac.md`
**Files audited:** `test_mech_sign.py`, `mechanism_registry/_hmac.py`

## Findings

### Coverage Status

**Well-tested**: SHA-2 and SHA-3 HMAC variants (full-length) via parametrized mechanism tests and ACVP vectors.

### Coverage Gaps

**CORRECTION (2026-04-02):** CKM_KMAC128/KMAC256 and CK_KMAC_PARAMS are NOT in the PKCS#11 v3.2 header. Zero KMAC references exist in pkcs11.h. This was spec-only/future draft content. These gaps are CLOSED as "not in v3.2". Also: CKM_AES_GMAC already has Wycheproof (test_wycheproof_aes.py:348), ACVP (test_gcm.py:203), and message API (test_mech_message.py:210) test coverage — original audit incorrectly stated "zero coverage".

- [CLOSED] ~~`CKM_KMAC128`/`CKM_KMAC256`~~ — NOT in v3.2 header.
- [CLOSED] ~~`CKM_AES_GMAC` no tests~~ — already has 3 test files (Wycheproof, ACVP, message API).
- [GAP] `CKM_AES_MAC` — registered but no functional sign/verify test (fixed 8-byte output variant).
- [GAP] HMAC_GENERAL truncation — no test exercises variable output lengths.
- [GAP] SHA-1 HMAC — absent from ACVP test mapping.
- [GAP] BLAKE2b HMAC — four variants defined, zero ACVP vectors loaded.

## Changes Made

None — analysis-only iteration.

## Statistics

- Files audited: 2 test files + 4 OASIS spec files + 1 registry
- Issues found: 0 fixed, 6 gaps documented
- Lines changed: 0
