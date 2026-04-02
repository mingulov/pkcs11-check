# Audit 05: AES ACVP Vector Audit

**Date:** 2026-04-01
**OASIS specs referenced:** AES mechanism specs (same as iteration 4)
**Files audited:** `acvp/aes/test_cfb.py`, `test_gcm.py`, `test_ccm.py`, `test_other.py`, `test_wrap.py`, `acvp/aes/base*.py`, `mechanism_registry/_aes.py`, `mechanism_helpers.py`

## Findings

### CCM Nonce Length Analysis (Previously Flagged)

**Not a bug.** The mechanism_registry default (`nonce_len: 7`) and the ACVP fallback default (`13`) are used in different contexts:
- Registry `nonce_len: 7` — used for mechanism-driven parametrized roundtrip tests
- ACVP `13` — fallback when NIST vectors don't specify nonce_len (rare; most vectors include it)
- Both values are valid per PKCS#11 spec (CCM nonce: 7-13 bytes)
- The registry value is intentionally conservative (minimum valid nonce) to maximize compatibility

### CCM tag_bits Conversion Analysis (Previously Flagged)

**Not a bug.** In `mechanism_helpers.py:702`:
```python
tag_bits_ccm = vp.get("tag_bits", d.get("mac_len", 16) * 8)
mac_len = tag_bits_ccm // 8
```
- If `tag_bits` provided (already in bits): `bits // 8` → bytes. Correct.
- If `mac_len` fallback (in bytes): `bytes * 8 // 8` → original bytes. Correct.
- No double-conversion risk exists.

### Quality Issues

- None new (dead code in test_other.py already fixed in iteration 4)

### Spec Deviations

- [NOTED] ACVP CCM-ECMA tag default (8 bytes) differs from regular CCM (16 bytes) — this matches the distinct ECMA-368 spec requirement, not a bug.
- [NOTED] GCM tag lengths in ACVP vectors include 4/8/12/13/14/15/16 bytes — all valid per spec.

### Coverage Gaps

- [GAP] No AES-CTR ACVP vectors — CTR mode tested via roundtrip in `test_aes_modes.py` but has no NIST known-answer test vectors.
- [NOTED] AES-KW/KWP ACVP coverage is present in `acvp/aes/test_wrap.py` — covers both wrap and unwrap.

## Changes Made

None — analysis-only iteration. Previous CCM nonce and tag_bits concerns resolved as non-issues.

## Statistics

- Files audited: 10 test/helper files
- Issues found: 0 fixed, 2 gaps documented
- Tests added: 0
- Lines changed: 0
