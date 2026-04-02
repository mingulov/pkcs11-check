# Audit 20: KDF Operations

**Date:** 2026-04-01
**OASIS specs referenced:** `hash_based_key_derivations.md`, `hkdf_mechanisms.md`, `sp800-108_key_derivation.md`, `miscellaneous_simple_key_derivation_mechanisms.md`, `password-based_encryption.md`, `pkcs12_password-based_encryption-authentication.md`, `key_derivation_by_data_encryption_aes-des.md`
**Files audited:** `test_kdf.py`, `test_misc_kdf.py`, `test_sp800_108_kdf.py`, `test_hkdf_extended.py`, `test_pbe.py`, `wycheproof/test_wycheproof_hkdf.py`, `wycheproof/test_wycheproof_pbkdf2.py`, `wycheproof/test_wycheproof_pbes2.py`, `mechanism_registry/_kdf.py`

## Findings

### Coverage Status

HKDF, PBKDF2, SP800-108 (all 3 modes) well-tested. PBE mechanisms (SHA1_DES3, PBA_SHA1) covered.

### Coverage Gaps

- [GAP] SHA3-based key derivation (CKM_SHA3_224/256/384/512_KEY_DERIVE) — completely absent from tests AND mechanism registry. These are defined in OASIS spec but not registered or tested.
- [GAP] SHAKE-based key derivation (CKM_SHAKE_128/256_KEY_DERIVE) — not registered or tested.
- [GAP] PBKDF2 minimum iteration count enforcement — no test for rejection of very low iterations.
- [GAP] PBE legacy mechanisms (MD2/MD5-based) — registered in spec but not tested.

## Statistics

- Issues found: 0 fixed, 4 gaps documented
