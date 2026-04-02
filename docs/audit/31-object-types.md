# Audit 31: Trust, Profile, HW, Validation & Data Objects

**Date:** 2026-04-01
**OASIS specs referenced:** `trust_objects.md`, `profile_objects.md`, `hardware_feature_objects.md`, `validation_objects.md`, `data_objects.md`, `generic_secret_key.md`
**Files audited:** `test_trust_objects.py`, `test_profiles.py`, `test_hw_features.py`, `test_validation_objects.py`, `test_data_objects.py`, `test_large_objects.py`, `test_generic_secret.py`

## Findings

### Coverage Status

All object types have dedicated test files. Trust objects test CKA_WRAP_WITH_TRUSTED policy. Profiles test v3.2 profile compliance. Data objects test create/read/search. Generic secret key tested for generation and usage.

### Coverage Gaps

- [GAP] Hardware feature objects — test_hw_features.py likely only probes for CKO_HW_FEATURE presence. Clock/counter/monotonic counter behavior not deeply tested.
- [GAP] Validation objects — spec defines CK_VALIDATION object for FIPS certificate information. Module support likely very limited.
- [GAP] Profile exhaustiveness — spec defines baseline, extended, authentication, and public cert store profiles. Need to verify all 4 are tested.

## Statistics

- Issues found: 0 fixed, 3 gaps documented
