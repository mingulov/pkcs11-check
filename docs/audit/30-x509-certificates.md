# Audit 30: X.509 Certificate Handling

**Date:** 2026-04-01
**OASIS specs referenced:** `certificate_objects.md`
**Files audited:** All 8 files in `testcases/x509/`

## Findings

### Coverage Status

X.509 test suite is comprehensive: certificate attributes, core operations, identity verification, lifecycle management, search operations, attribute parity, Limbo vector import, and stress testing. This is a complete subdirectory with its own conftest.py.

### Coverage Gaps

- [GAP] WTLS certificate objects — spec defines CKC_WTLS certificate type but no WTLS certificate tests exist.
- [GAP] Certificate creation with CKA_CERTIFICATE_CATEGORY — spec defines 3 categories (unspecified, token user, authority, other entity) but no test validates category enforcement.
- [GAP] Certificate chain validation — no test imports a full cert chain and validates chain order/completeness.

## Statistics

- Issues found: 0 fixed, 3 gaps documented
