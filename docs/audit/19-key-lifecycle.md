# Audit 19: Key Lifecycle

**Date:** 2026-04-01
**OASIS specs referenced:** `key_objects.md`, `private_key_objects.md`, `public_key_objects.md`, `secret_key_objects.md`, `key_management_functions.md`
**Files audited:** `test_keymgmt.py`, `test_key_lifecycle.py`, `test_key_flags.py`, `test_key_sizes.py`, `test_key_usage_policy.py`, `test_sensitivity.py`, `test_handle_reuse.py`, `test_tookan.py`

## Findings

### Coverage Status

Tookan vulnerability tests comprehensive: conflicting usage detection, SENSITIVE preservation, EXTRACTABLE escalation blocked. Key flags (CKA_LOCAL, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE) tested with NSS xfails documented.

### Coverage Gaps

- [GAP] SENSITIVE write-once enforcement — no test verifies `CKA_SENSITIVE=True` cannot be set back to `False`.
- [GAP] CKA_ALWAYS_SENSITIVE/CKA_NEVER_EXTRACTABLE preservation on `C_CopyObject` — should always remain True on copied keys.
- [GAP] CKA_LOCAL flag on copy — spec requires LOCAL=False for imported/copied keys.

## Statistics

- Issues found: 0 fixed, 3 gaps documented
