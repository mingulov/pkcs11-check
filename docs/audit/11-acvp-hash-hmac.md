# Audit 11: ACVP Hash/HMAC Audit

**Date:** 2026-04-01
**Files audited:** `acvp/test_acvp_hash.py`, `acvp/test_acvp_hmac.py`, `acvp/test_acvp_sha3.py`

## Findings

### Quality Issues

- [NOTED] ACVP HMAC tests use `CKM_SHA*_HMAC` (full-length) and truncate output post-computation. They do NOT exercise `CKM_SHA*_HMAC_GENERAL` directly even though ACVP vectors include `macLen` for variable output.

### Spec Deviations

- None — vector loading and comparison logic is correct for the mechanisms exercised.

### Coverage Gaps

- [GAP] SHAKE ACVP vectors — loaded but permanently skipped (`pytest.skip` at test load): requires `C_DigestXof*` not in raw bindings.
- [GAP] SHA-1 HMAC ACVP — absent from `_ALG_MAP` mapping. ACVP vectors may exist but are never loaded.
- [GAP] BLAKE2b HMAC ACVP — zero coverage. Not requested from ACVP data source.
- [GAP] No Monte Carlo test implementation observed — ACVP hash vectors may include MCT groups but no special handling found.
- [GAP] HMAC_GENERAL ACVP — variable macLen vectors not exercised against the _GENERAL mechanism.

### Silently Skipped Groups

No evidence of silent group skipping. `load_acvp_vectors()` loads all groups from JSON files. Tests skip only via `pytest.skip()` for unsupported mechanisms (visible in test output).

## Changes Made

None — analysis-only iteration.

## Statistics

- Files audited: 3
- Issues found: 0 fixed, 5 gaps documented
- Lines changed: 0
