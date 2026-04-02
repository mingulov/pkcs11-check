# Audit 23: Object Management

**Date:** 2026-04-01
**OASIS specs referenced:** `objects.md`, `object_classification.md`, `creating_objects.md`, `object_mgmt_functions.md`, `common_attributes.md`, `storage_objects.md`
**Files audited:** `test_object*.py` (5 files), `test_search.py`, `test_data_objects.py`, `test_token_objects.py`, `test_validation_objects.py`, `test_set_attribute.py`, `test_attribute_*.py` (3 files)

## Findings

Object management extensively tested: create, find, get/set attribute, visibility, size, search patterns, attribute defaults, enforcement. 11+ test files in this area.

### Coverage Gaps

- [GAP] `CK_UNAVAILABLE_INFORMATION` handling in `C_GetAttributeValue` — spec defines -1 sentinel for unavailable attributes; no explicit test found.
- [GAP] Object class-specific creation rules — `creating_objects.md` defines per-class mandatory attributes; no systematic validation against spec tables.
- [GAP] `C_CopyObject` with CKA_MODIFIABLE=False source — spec says copy should fail.

## Statistics

- Issues found: 0 fixed, 3 gaps documented
