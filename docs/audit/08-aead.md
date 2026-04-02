# Audit 08: AEAD Deep Audit

**Date:** 2026-04-01
**OASIS specs referenced:** `chacha20_salsa20_poly1305.md`, `poly1305.md`, `additional_aes_mechanisms.md`
**Files audited:** `test_aead.py`, `test_authenticated_wrap.py`, `test_salsa20.py`, `test_mech_message.py`

## Findings

### Spec Deviations

- [NOTED] AES-GCM implementation is thorough: cross-verification, roundtrip, AAD, tamper detection, nonce uniqueness all tested.
- [NOTED] Standalone Poly1305 MAC correctly tested: sign/verify, tamper detection, key independence.

**CORRECTION (2026-04-02):** CKM_AES_GMAC already has test coverage in: test_wycheproof_aes.py:348 (Wycheproof), acvp/aes/test_gcm.py:203 (ACVP), test_mech_message.py:210 (message API). Original audit incorrectly stated "zero coverage" for GMAC.

### Coverage Gaps

- [GAP] `CKM_SALSA20_POLY1305` — zero test coverage. No roundtrip, no AAD, no tamper detection. Spec fully defines this mechanism.
- [GAP] `CKM_CHACHA20_POLY1305` — only Wycheproof encrypt vectors. No dedicated roundtrip test, no AAD validation, no tamper detection, no decrypt tests.
- [GAP] No nonce variant tests for ChaCha20-Poly1305 (64-bit original, 96-bit IETF, 192-bit XChaCha20) or Salsa20-Poly1305 (64-bit, 192-bit XSalsa20).
- [GAP] Message-based API only tested for AES-GCM. ChaCha20/Salsa20-Poly1305 message API untested.
- [GAP] Authenticated wrapping only tested for AES-GCM. No ChaCha20/Salsa20-Poly1305 authenticated wrapping tests.
- [GAP] GCM alternative tag sizes untested — tests hardcode 128-bit tag.
- [GAP] Edge cases: empty plaintext + AAD, empty AAD, large messages.

## Changes Made

None — analysis-only iteration.

## Statistics

- Files audited: 4 test files + 3 OASIS spec files
- Issues found: 0 fixed, 7 gaps documented
- Tests added: 0
- Lines changed: 0
