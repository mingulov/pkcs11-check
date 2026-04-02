# Audit 18: SLH-DSA

**Date:** 2026-04-01
**OASIS specs referenced:** `slh-dsa.md`
**Files audited:** `test_pqc_sign.py`, `test_hash_slh_dsa.py`, `acvp/test_acvp_slhdsa.py`

## Findings

### Coverage Status

All 12 parameter sets (6 SHA2-based + 6 SHAKE-based) have ACVP coverage: keygen (2 vectors/set), siggen (4 vectors/set), sigver (1 vector/set). Hash-SLH-DSA variants covered in test_hash_slh_dsa.py.

### Coverage Gaps

- [GAP] Unit test coverage uneven — test_pqc_sign.py only tests SHA2_128S/128F/256F (3 of 12 sets). Other 9 sets only exercised via ACVP vectors.
- [GAP] No Wycheproof SLH-DSA vectors (Wycheproof doesn't include SLH-DSA yet).
- [GAP] Signature size validation — no explicit assertions per parameter set (sizes vary: SHA2-128s=7856B, SHA2-256f=49856B, etc.).
- [GAP] Hedge variant testing — same gap as ML-DSA.
- [NOTED] Spec line 87 shows "CKP_SLH_DSA_SHAKE_256S" twice — likely spec typo for 256F.

## Statistics

- Issues found: 0 fixed, 4 gaps documented, 1 spec issue noted
