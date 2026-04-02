# Audit 38: Access Control & Visibility

**Date:** 2026-04-01
**OASIS specs referenced:** `objects.md`, `session_mgmt_functions.md`
**Files audited:** `test_access.py`, `test_access_control.py`, `test_access_levels.py`, `test_object_visibility.py`, `test_ro_session.py`, `test_ro_session_restrictions.py`

## Findings

### Coverage Status

R/O session restrictions, CKA_PRIVATE enforcement, object visibility rules, access levels, and SO vs USER separation all have dedicated test files. This is well-covered.

### Coverage Gaps

- [GAP] CKA_PRIVATE on certificate objects — spec says private certs require login; no test specifically creates a private certificate and verifies visibility before/after login.
- [GAP] Multi-session object visibility — no test verifies that a session object created in session A is not visible in session B (same user, different sessions).
- [GAP] CKA_MODIFIABLE enforcement — no test verifies that SetAttributeValue fails on a non-modifiable object.

## Statistics

- Issues found: 0 fixed, 3 gaps documented
