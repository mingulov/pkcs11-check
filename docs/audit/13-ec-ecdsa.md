# Audit 13: EC/ECDSA

**Date:** 2026-04-01
**OASIS specs referenced:** `elliptic_curves.md`
**Files audited:** `test_ec_curves.py`, `test_ecdsa_extended.py`, `test_ec_import_export.py`, `mechanism_registry/_ec.py`

## Findings

### Coverage Status

- Curves P-224, P-256, P-384, P-521 parametrized with matching hash algorithms. EC point encoding correct (DER OCTET STRING -> 0x04||x||y). ECDSA r||s format correctly split and cross-verified with cryptography library.
- Hash-and-sign variants (CKM_ECDSA_SHA1, SHA3 family) covered in `test_ecdsa_extended.py`.

### Coverage Gaps

- [GAP] secp256k1 — not in parametrized curve list. Used in Bitcoin/Ethereum, some modules support it.
- [GAP] Brainpool curves (brainpoolP256r1, etc.) — not tested.
- [GAP] Compressed EC point format — only uncompressed (0x04) tested.

## Statistics

- Issues found: 0 fixed, 3 gaps documented
