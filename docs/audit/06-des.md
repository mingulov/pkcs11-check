# Audit 06: DES/3DES

**Date:** 2026-04-01
**OASIS specs referenced:** `double_and_triple-length_des.md`, `double_and_triple-length_des_cmac.md`
**Files audited:** `test_des.py`, `mechanism_registry/_des.py`

## Findings

### Spec Deviations

- [NOTED] `CKM_DES3_CMAC` and `CKM_DES3_CMAC_GENERAL` are tested but not in the main DES spec — they come from `double_and_triple-length_des_cmac.md` which is correct.
- [NOTED] Single-DES mechanisms (CKM_DES_*) are tested alongside DES3 — these are deprecated but modules still advertise them.

### Coverage Gaps

- [GAP] No weak/semi-weak key detection test — spec warns about DES weak keys, no test validates rejection or acceptance behavior.
- [GAP] No CKA_CHECK_VALUE computation test — spec defines it as "first 3 bytes of ECB encrypt of null block".
- [GAP] No DES2 key with DES3 mechanism cross-compatibility test — spec allows DES2 keys to use DES3 mechanisms.
- [GAP] No parity bit validation test — spec requires key parity, no test verifies rejection of invalid parity.
- [GAP] No DES3-CBC-PAD wrap roundtrip test (SoftHSM2 known broken per module-issues.md).

### Quality Issues

- [NOTED] MAC_GENERAL recipes hardcode `mac_len: 8` — should test variable output lengths per MAC_GENERAL semantics.

## Changes Made

None — analysis-only iteration.

## Statistics

- Files audited: 2 test files + 2 OASIS spec files
- Issues found: 0 fixed, 5 gaps documented, 2 noted
- Tests added: 0
- Lines changed: 0
