# Audit 36: Multipart, Dual-Function & Stateful Operations

**Date:** 2026-04-01
**OASIS specs referenced:** `dual-function_cryptographic_functions.md`, `encryption_functions.md`, `signing_and_macing_functions.md`
**Files audited:** `test_multipart.py`, `test_multipart_streaming.py`, `test_dual_function.py`, `test_mech_multipart.py`, `test_mech_state.py`, `test_stateful_sigs.py`

## Findings

### Coverage Status

Multipart encrypt/decrypt/digest thoroughly tested with various chunk sizes. Mechanism state machine (init -> update -> final) well-covered with error recovery. Stateful signatures (HSS/XMSS state management concept) present.

### Coverage Gaps

- [GAP] Dual-function operations (C_DigestEncryptUpdate, C_DecryptDigestUpdate, C_SignEncryptUpdate, C_DecryptVerifyUpdate) — spec defines 4 dual-function combinations. Need to verify all 4 are tested in test_dual_function.py.
- [GAP] Multipart streaming with very large data (>1MB) — tested for digest but unclear for encrypt/sign.
- [GAP] SHAKE multipart — excluded from test_mech_multipart.py (requires C_DigestXof API).

## Statistics

- Issues found: 0 fixed, 3 gaps documented
