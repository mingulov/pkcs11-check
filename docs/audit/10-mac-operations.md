# Audit 10: MAC Operations

**Date:** 2026-04-01
**OASIS specs referenced:** `hmac_mechanisms.md`, `hash_based_message_authentication_codes.md`, `aes_cmac.md`, `kmac.md`
**Files audited:** `test_mech_sign.py`, `mechanism_registry/_hmac.py`

## Findings

### Coverage Status

**Well-tested**: SHA-2 and SHA-3 HMAC variants (full-length) via parametrized mechanism tests and ACVP vectors.

### Coverage Gaps

- [GAP] `CKM_KMAC128`/`CKM_KMAC256` — availability check only, sign roundtrip explicitly skipped: "CK_KMAC_PARAMS mechanism parameter not yet available in pkcs11_check.raw bindings."
- [GAP] HMAC_GENERAL truncation — 18 _GENERAL variants registered but no test specifically exercises variable output lengths or boundary cases (output_len=1, output_len=hash_len).
- [GAP] `CKM_AES_GMAC` — registered but no functional sign/verify test.
- [GAP] `CKM_AES_MAC` — registered but no test coverage.
- [GAP] SHA-1 HMAC — absent from ACVP test mapping despite being in registry.
- [GAP] BLAKE2b HMAC — four variants defined, zero ACVP vectors loaded.

## Changes Made

None — analysis-only iteration.

## Statistics

- Files audited: 2 test files + 4 OASIS spec files + 1 registry
- Issues found: 0 fixed, 6 gaps documented
- Lines changed: 0
