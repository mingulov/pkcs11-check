# Audit 15: EdDSA

**Date:** 2026-04-01
**OASIS specs referenced:** `elliptic_curves.md` (EdDSA section)
**Files audited:** `test_eddsa.py`, `test_cctv_ed25519.py`, `acvp/test_acvp_eddsa.py`, `wycheproof/test_wycheproof_ed25519.py`

## Findings

### Spec Deviations

- [NOTED] NSS softoken rejects CK_EDDSA_PARAMS — documented xfail with clear message. Other modules accept params per spec.

### Coverage Gaps

- [GAP] Ed448 — zero test coverage. Only Ed25519 tested. Ed448 keygen, sign, verify all missing.
- [GAP] Pre-hash EdDSA (Ed25519ph/Ed448ph) — not tested. Spec defines prehash mode via CK_EDDSA_PARAMS.phFlag.
- [GAP] CK_EDDSA_PARAMS context string — tested as NSS xfail but not verified on supporting modules.

## Statistics

- Issues found: 0 fixed, 3 gaps documented
