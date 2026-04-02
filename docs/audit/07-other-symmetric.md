# Audit 07: Other Symmetric Ciphers

**Date:** 2026-04-01
**OASIS specs referenced:** `camellia.md`, `aria.md`, `seed.md`, `blowfish.md`, `twofish.md`, `salsa20.md`, `chacha20.md`, `chacha20_salsa20_poly1305.md`
**Files audited:** `test_camellia.py`, `test_aria.py`, `test_seed.py`, `test_blowfish.py`, `test_twofish.py`, `test_salsa20.py`, `mechanism_registry/_ciphers.py`

## Findings

### Quality Issues

- [FIXED] `test_twofish.py:5,40` — comments incorrectly stated Twofish has "8-byte" block/IV. Twofish is a 16-byte block cipher with 16-byte IV per OASIS spec. Test code was correct (uses 16-byte IVs), only comments were wrong.

### Spec Deviations

- [NOTED] Camellia, ARIA, SEED: IV sizes, key sizes, MAC output all match spec. No parameter mismatches.
- [NOTED] Blowfish/Twofish correctly omit ECB/MAC (not in spec). IV sizes correct (Blowfish=8, Twofish=16).

### Coverage Gaps

- [GAP] ChaCha20: only IETF variant (96-bit nonce) tested. Missing original (64-bit) and XChaCha20 (192-bit) nonce variants.
- [GAP] Salsa20: only original variant (64-bit nonce) tested. Missing XSalsa20 (192-bit nonce).
- [GAP] ChaCha20: no `blockCounterBits` variance testing (spec allows 32 or 64 bits).
- [GAP] Blowfish: only tests 128 and 256-bit keys. Missing 448-bit (max) key size test.
- [GAP] Key derivation variants (CBC/ECB_ENCRYPT_DATA) for Camellia/ARIA/SEED — availability check only, no functional roundtrip.

## Changes Made

- Modified: `test_twofish.py` — fixed incorrect block size comments (8 -> 16)

## Statistics

- Files audited: 6 test files + 8 OASIS spec files + 1 registry file
- Issues found: 1 fixed, 5 gaps documented
- Tests added: 0
- Lines changed: +2/-2
