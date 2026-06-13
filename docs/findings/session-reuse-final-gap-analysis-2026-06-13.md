# PKCS#11 Session Reuse: Final Gap Analysis (2026-06-13)

This document formalizes the decision to halt the `p11_module_session` migration for the remaining ~170 test files in the `pkcs11-check` suite.

The initial migration (Phase 1) successfully converted 72 high-count vector files (ACVP, Wycheproof, CCTV, X.509 vectors), capturing >95% of the potential execution time savings. The remaining files were evaluated against the project's **Test-Outcome Classification Model** and session lifecycle constraints.

## 1. The "Dangerous" Category (State Pollution & Classification Integrity)

The core principle of the classification model is accurate reporting of self-contradictions (Types A, B, C, and D). Reusing a session across independent tests introduces shared state, which risks generating false findings or masking real ones in specific test categories.

### A. Lifecycle and State-Machine Tests (Type C Risk)
Tests in `ckr/`, `test_operation_state.py`, and `test_session_state_machine.py` explicitly probe the module's handling of active operations, session closures, and login transitions.
*   **The Risk**: If a shared session is used, a prior test might leave an operation active (a common provider bug). While the harness has self-healing (`_init_or_recover`), relying on it during a test *designed* to find state-machine bugs would mask the Type C failure.
*   **Conclusion**: Lifecycle tests absolutely require the strict isolation of `p11_raw_session`.

### B. Session Object Memory Leaks (CKR_DEVICE_MEMORY)
Medium-count protocol files like `test_ssl3.py`, `test_ike.py`, and `test_x942_dh.py` (20-40 tests) heavily utilize `C_DeriveKey`, creating numerous intermediate session objects (base keys, MAC secrets, IVs).
*   **The Risk**: `p11_raw_session` guarantees cleanup because closing the session automatically destroys all session objects. `p11_module_session` requires flawless `C_DestroyObject` calls in every test's `finally` block. A single unhandled exception or missed cleanup leads to object leakage. Across a file, this exhausts hardware token memory, causing spurious `CKR_DEVICE_MEMORY` or `CKR_SESSION_MEMORY` failures. This corrupts the classification model, tagging a crypto test as failed due to harness-induced memory exhaustion.
*   **Conclusion**: Protocol derivation tests are unsafe for shared sessions unless exhaustively audited for perfect manual memory management, which is an unacceptable maintenance burden.

### C. FFI and Security Probes (Memory Corruption)
Tests in `security/` (e.g., `test_ffi_null_pointer.py`, `test_padding_oracle.py`) intentionally pass malformed C-structs, NULL pointers, or invalid lengths to probe the FFI boundary.
*   **The Risk**: Even if a provider survives a malformed FFI probe without a `SIGSEGV`, its internal heap or session context may be corrupted. Executing subsequent cryptographic tests in that same corrupted session invalidates all findings.
*   **Conclusion**: Security and FFI probes require the fail-fast, blast-radius-limited isolation of a fresh `p11_raw_session`.

## 2. The "Too Small" Category (Low ROI)

The primary benefit of `p11_module_session` is amortizing the `C_OpenSession` and `C_Login` latency (approx. 47ms on local SW tokens, 80ms on network HSMs).
*   **The Math**: Over 125 of the remaining 170 files have fewer than 15 tests. For a 10-test file, the maximum theoretical savings is ~800ms.
*   **Conclusion**: A sub-second savings per file does not justify the risk of state pollution or the engineering effort required to audit cleanup paths.

## Final Decision

The `p11_module_session` migration is officially complete.
1.  The 72 migrated files represent the maximum safe threshold for session reuse.
2.  The remaining 170 files **MUST** remain on `p11_raw_session`.
3.  Future test additions should use `p11_raw_session` by default, reserving `p11_module_session` strictly for massive read-only vector replays (>100 iterations) that do not generate persistent session objects.
