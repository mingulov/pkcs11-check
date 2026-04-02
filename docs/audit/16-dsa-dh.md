# Audit 16: DSA/DH

**Date:** 2026-04-01
**OASIS specs referenced:** `dsa.md`, `diffie-hellman.md`, `extended_triple_diffie-hellman.md`
**Files audited:** `test_dsa_complete.py`, `test_dh_key_agreement.py`, `test_x3dh.py`, `mechanism_registry/_dsa_dh.py`

## Findings

### Coverage Status

- DSA parameter generation (CKM_DSA_PARAMETER_GEN) tested.
- DSA keygen, sign, verify functional.
- DH key agreement basic flow tested.

### Coverage Gaps

- [GAP] DSA FIPS parameter generation variants (CKM_DSA_PROBABLISTIC_PARAMETER_GEN, CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN, CKM_DSA_FIPS_G_GEN) — registered but no functional tests.
- [GAP] X3DH — only presence/consistency checks. No actual X3DH_INITIALIZE/X3DH_RESPOND derivation flows tested. Comment: "Almost no HSM supports X3DH yet."
- [GAP] DH parameter generation (CKM_DH_PKCS_PARAMETER_GEN) — only creates param object, doesn't test keygen from generated params.
- [GAP] DSA signature format cross-verification — no cross-verify with cryptography library (unlike ECDSA which has this).

## Statistics

- Issues found: 0 fixed, 4 gaps documented
