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

- [GAP] `CKM_SHAKE_128`, `CKM_SHAKE_256` — permanently skipped. Require `C_DigestXof*` functions which are not in the v3.2 header. ACVP SHAKE vectors exist but `pytest.skip` at load time.
- [GAP] `CKM_SHA512_T` — no test exercises the truncation parameter. Requires `CK_MAC_GENERAL_PARAMS` with desired output length.
- [GAP] `C_DigestXof*` functions — not implemented in raw bindings, blocking all XOF mechanism testing.
- [GAP] RIPEMD-128/160 — only covered by parametrized test_mech_digest if module advertises; no dedicated tests.
- [GAP] Multipart digest streaming — `test_mech_multipart.py` covers this, but SHAKE variants are excluded.

## Changes Made

None — analysis-only iteration.

## Statistics

- Files audited: 5 test files + 2 OASIS spec files + 1 registry file
- Issues found: 0 fixed, 5 gaps documented, 2 noted
- Tests added: 0
- Lines changed: 0
