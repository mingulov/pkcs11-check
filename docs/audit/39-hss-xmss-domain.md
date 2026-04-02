# Audit 39: HSS/XMSS, Domain Parameters & Mechanism Objects

**Date:** 2026-04-01
**OASIS specs referenced:** `hss.md`, `xmss_and_xmss-mt.md`, `domain_parameter_objects.md`, `mechanism_objects.md`
**Files audited:** `test_domain_params.py`, `test_mechanism.py`, `test_mechanism_objects.py`, `test_remaining_gaps.py`

## Findings

### Coverage Status

Domain parameters tested for DSA/DH. Mechanism info and mechanism object attributes tested. test_remaining_gaps.py tracks known unimplemented items.

### Coverage Gaps

- [GAP] HSS (CKM_HSS_KEY_PAIR_GEN, CKM_HSS) — spec fully defines Hierarchical Signature Scheme but no module in the test matrix supports it. No test exists.
- [GAP] XMSS/XMSS-MT (CKM_XMSS_KEY_PAIR_GEN, CKM_XMSS, CKM_XMSS_MT_KEY_PAIR_GEN, CKM_XMSS_MT) — spec defines these hash-based stateful signature schemes. No module supports them yet.
- [GAP] Mechanism objects (CKO_MECHANISM) — v3.2 introduces mechanism objects for runtime mechanism querying. test_mechanism_objects.py exists but may only probe availability.
- [NOTED] All remaining TODOs in test_remaining_gaps.py should be reviewed and either implemented or documented with justification.

## Statistics

- Issues found: 0 fixed, 3 gaps documented
