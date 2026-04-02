# Audit 34: Legacy Ciphers

**Date:** 2026-04-01
**Files audited:** `mechanism_registry/_legacy.py`, `test_remaining_gaps.py`

## Findings

### Coverage Status

82 legacy mechanisms registered in _legacy.py covering RC2, RC4, RC5, CAST/CAST3/CAST128, IDEA, CDMF, Skipjack, BATON, JUNIPER, KEA/Fortezza, and misc wrapping. None of these have functional tests — they are registered for mechanism catalog/reporting purposes only.

### Assessment

This is largely acceptable: none of the 12 Docker-tested soft tokens implement these mechanisms. They are deprecated/obsolete by PKCS#11 v3.2. Test coverage would only be useful if a module advertises them.

### Coverage Gaps

- [GAP] RC2/RC4/RC5 — if any tested module advertises these, parametrized mechanism tests would run but no dedicated functional tests exist.
- [GAP] CAST/CAST128 — same as above.
- [NOTED] All 82 mechanisms have correct constant values (verified in iteration 02 — perfect header parity).
- [NOTED] Deprecation status documented in mechanism_registry entries.

## Statistics

- Issues found: 0 fixed, 2 gaps documented (acceptable for deprecated mechanisms)
