# Audit 27: Async & Operation State

**Date:** 2026-04-01
**OASIS specs referenced:** `asynchronous_function_management_functions.md`, `parallel_function_management_functions.md`
**Files audited:** `test_operation_state.py`, `test_remaining_gaps.py`

## Findings

### Coverage Status

C_GetOperationState/C_SetOperationState tested for digest operations. Basic state save/restore verified.

### Coverage Gaps

- [GAP] Async lifecycle (C_AsyncJoin, C_AsyncGetID, C_AsyncComplete) — TODO at `test_remaining_gaps.py:409`, not implemented.
- [GAP] Operation state for encrypt/sign — only digest state tested. Spec allows state save/restore for encrypt and sign operations too.
- [GAP] Operation state portability across sessions — spec allows state transfer between sessions on same token; not tested.
- [GAP] C_SessionCancel (v3.0+) — referenced in test_v30_session.py but not comprehensive. Should test cancel during active encrypt/sign/digest operations.
- [GAP] Parallel function management (C_GetFunctionStatus, C_CancelFunction) — legacy parallel functions not tested (deprecated but still in spec).

## Statistics

- Issues found: 0 fixed, 5 gaps documented
