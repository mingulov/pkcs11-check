# Audit 40: Parameter Consistency Fixes

**Date:** 2026-04-01
**Files audited:** `mechanism_registry/*.py`, `mechanism_helpers.py`, `raw/recipes.py`, `raw/pack.py`, `raw/pack_mechanisms.py`

## Findings

### Previously Flagged Issues — Resolution Status

1. **CCM nonce_len mismatch (registry=7, ACVP=13)** — Resolved in iteration 05: different valid defaults for different contexts. Not a bug.

2. **Hardcoded RSA 256-byte sizes** — Documented in iteration 12. Correct for 2048-bit RSA but not parameterized for other key sizes.

3. **mechanism_helpers.py:702 CCM tag_bits conversion** — Resolved in iteration 05: no double-conversion risk.

4. **SHAKE mechanism IDs hardcoded** — Verified in iteration 09: `0x00000418`/`0x00000419` with TODO comments because not in vendored v3.2 header. Appropriate.

### Quality Issues

- [NOTED] 111 `# type: ignore` comments across the codebase — majority are justified for ctypes dynamic attribute access and intentional wildcard imports. No incorrect suppressions found in spot-check.
- [NOTED] 50 `# noqa` comments — all justified for intentional F401/F403/F405 wildcard imports in raw/ module.

### Coverage Gaps

- [GAP] `null_mechanism.md` — OASIS spec defines CKM_NULL mechanism for testing purposes. No test exercises the null mechanism (CKM 0x00000000).

## Changes Made

None — all previously flagged issues already resolved or documented in earlier iterations.

## Statistics

- Issues found: 0 new, 1 gap documented, all prior flags resolved
