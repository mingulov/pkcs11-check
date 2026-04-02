# Audit 09: Hash Functions

**Date:** 2026-04-01
**OASIS specs referenced:** `digests.md`, `message_digesting_functions.md`
**Files audited:** `test_digest.py`, `test_sha3.py`, `test_blake2.py`, `test_mech_digest.py`, `mechanism_registry/_hash.py`

## Findings

### Quality Issues

- [NOTED] Hardcoded SHAKE IDs in `test_mech_digest.py:51-52` and `_hash.py:190,199` — `0x00000418` and `0x00000419` used because SHAKE not in vendored v3.2 header. Appropriate with TODO comment.
- [NOTED] `CKM_SHA512_T` has `param_recipe.style="none"` but spec requires parameter for truncation length. No test exercises this parametrized variant.

### Coverage Status

**Well-tested (18/20 mechanisms):**
- SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 — length validation, cross-verify vs hashlib, C_DigestKey, large data
- SHA-512/224, SHA-512/256 — parametrized in test_mech_digest
- SHA3-224, SHA3-256, SHA3-384, SHA3-512 — FIPS 202 KATs
- BLAKE2b-160, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512 — output length, cross-verify

### Coverage Gaps

**CORRECTION (2026-04-02):** CKM_SHAKE_128/256 as digest mechanisms and C_DigestXof* functions are NOT in the PKCS#11 v3.2 header. Only CKM_SHAKE_128/256_KEY_DERIVE exist. The OASIS spec markdown describes future/draft functionality not yet standardized. These gaps are CLOSED as "not in v3.2".

- [CLOSED] ~~`CKM_SHAKE_128`, `CKM_SHAKE_256` digest~~ — NOT in v3.2 header. Only KEY_DERIVE variants exist.
- [CLOSED] ~~`C_DigestXof*` functions~~ — NOT in v3.2 header.
- [GAP] `CKM_SHA512_T` — no test exercises the truncation parameter.
- [GAP] RIPEMD-128/160 — only covered by parametrized test_mech_digest if module advertises.
- [GAP] Multipart digest streaming — SHAKE variants excluded (correctly, since SHAKE digest not in v3.2).

## Changes Made

None — analysis-only iteration.

## Statistics

- Files audited: 5 test files + 2 OASIS spec files + 1 registry file
- Issues found: 0 fixed, 5 gaps documented, 2 noted
- Tests added: 0
- Lines changed: 0
