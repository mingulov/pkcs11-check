# Audit 17: ML-KEM & ML-DSA

**Date:** 2026-04-01
**OASIS specs referenced:** `ml-kem.md`, `ml_dsa.md`
**Files audited:** `test_kem.py`, `test_pqc_sign.py`, `test_hash_ml_dsa.py`, `test_mech_kem.py`, `acvp/test_acvp_mlkem.py`, `acvp/test_acvp_mldsa.py`, `wycheproof/test_wycheproof_mlkem.py`, `wycheproof/test_wycheproof_mldsa*.py`, `mechanism_registry/_pqc.py`

## Findings

### Coverage Status

**ML-KEM**: Excellent. All 3 parameter sets (512/768/1024) tested. Keygen, encapsulate, decapsulate all covered. Shared secret 32-byte size validated. ACVP + Wycheproof vectors present for all sets.

**ML-DSA**: Good. All 3 parameter sets (44/65/87) tested. All 11 mechanism variants (pure + 10 hash-specific) registered and covered in test_hash_ml_dsa.py.

### Coverage Gaps

- [GAP] ML-DSA ACVP context parameter — `test_acvp_mldsa.py:185,257` has TODO: "pass vec['context'] via CK_SIGN_ADDITIONAL_CONTEXT when mechanism param builder is available." Context is empty for most vectors so tests pass, but context-bearing vectors are not validated with the actual parameter.
- [GAP] ML-DSA signature size validation — no explicit assertions for expected sizes (44→2420B, 65→3293B, 87→4595B). Implicitly validated via ACVP verification success.
- [GAP] Hedge variant testing — no tests for `CKH_HEDGE_PREFERRED`, `CKH_HEDGE_REQUIRED`, `CKH_DETERMINISTIC_REQUIRED` behavior.
- [GAP] External Mu (`CKM_ML_DSA_EXTERNAL_MU_GEN`, `CKM_ML_DSA_EXTERNAL_MU`) — mechanism registered but no test coverage.

## Statistics

- Issues found: 0 fixed, 4 gaps documented
