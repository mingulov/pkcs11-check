# Audit Gap Implementation Design (Revised)

**Date:** 2026-04-02
**Scope:** Implement fixes and new tests for gaps identified in the 42-iteration audit, verified against the actual PKCS#11 v3.2 header.
**Execution:** Ralph-loop autonomous, ~10 iterations
**Prerequisite:** `docs/superpowers/specs/2026-04-01-deep-audit-design.md` (completed audit)

## Header Verification — Critical Corrections

The audit identified 136 gaps. Before implementation, each was verified against the actual vendored `third_party/pkcs11-headers/3.2/pkcs11.h`. Key corrections:

### NOT in v3.2 header (spec-only / future draft — CLOSE these)

| Item | Status | Action |
|------|--------|--------|
| `C_DigestXof*` functions | Not in header — no C_DigestXofInit/Update/Final | Close as "not in v3.2"; update audit report |
| `CK_KMAC_PARAMS` | Not in header — zero KMAC references | Close as "not in v3.2"; update audit report |
| `CKM_KMAC128` / `CKM_KMAC256` | Not in header | Close; update audit report |
| `CKM_SHAKE_128` / `CKM_SHAKE_256` (digest) | Not in header (only KEY_DERIVE variants) | Close digest testing; implement KEY_DERIVE tests |
| `CK_MU_GEN_PARAMS` | Not in header | Close |
| `CKM_ML_DSA_EXTERNAL_MU` | Not in header | Close |

### Already implemented (audit was wrong — REMOVE from plan)

| Item | What already exists | Action |
|------|-------------------|--------|
| AES_GMAC tests | Wycheproof (`test_wycheproof_aes.py:348`), ACVP (`test_gcm.py:203`), message API (`test_mech_message.py:210`) | Remove from iteration 5 |
| HSS/XMSS tests | Comprehensive tests in `test_stateful_sigs.py` + full registry entries in `_pqc.py:397-437` | Remove iteration 8 HSS/XMSS skeleton |
| CKM_NULL registry | Already in `_kdf.py:636` | Remove from iteration 2 |
| `mech_hash_sign_context` | Already exists at `pack_mechanisms.py:781` for CK_HASH_SIGN_ADDITIONAL_CONTEXT | Remove from iteration 3 |
| CKH_DETERMINISTIC_REQUIRED | Already in `types_std.py:2562` | No action needed |
| AES_MAC registry | Already in `_aes.py:302` | No action needed |
| AES_GMAC registry | Already in `_aes.py:270` | No action needed |

### IS in v3.2 header and NEEDS implementation

| Item | Header evidence | What's missing |
|------|----------------|----------------|
| `CK_SIGN_ADDITIONAL_CONTEXT` | struct at header line 1844 | Pack function for PURE (non-hash) ML-DSA/SLH-DSA sign. `mech_hash_sign_context` exists for hash variant only. |
| `CKM_AES_MAC` | 0x00001083 | Registry entry exists, but zero functional tests (sign/verify roundtrip). Only AES_MAC_GENERAL is tested. |
| `CKM_SHA3_224_KEY_DERIVE` | 0x00000398 | No registry entry, no tests |
| `CKM_SHA3_256_KEY_DERIVE` | 0x00000397 | No registry entry, no tests |
| `CKM_SHA3_384_KEY_DERIVE` | 0x00000399 | No registry entry, no tests |
| `CKM_SHA3_512_KEY_DERIVE` | 0x0000039A | No registry entry, no tests |
| `CKM_SHAKE_128_KEY_DERIVE` | 0x0000039B | No registry entry, no tests |
| `CKM_SHAKE_256_KEY_DERIVE` | 0x0000039C | No registry entry, no tests |
| Ed448 tests | CKM_EDDSA (0x1057), CK_EDDSA_PARAMS | Docstring mentions Ed448 but ALL tests are Ed25519-only. Zero Ed448 test functions. |
| `CKM_NULL` | 0x0000400B | In registry but skipped in derive tests. No dedicated behavior test. |

## Decisions

- **Approach:** Fix audit reports, add registry entries, implement tests — all verified against header
- **Execution model:** Ralph-loop autonomous
- **Output:** Report + fixes + new tests committed per iteration
- **Scope:** ~10 iterations (reduced from 12 after removing already-implemented items)

## Iteration Plan

### Iteration 1: Audit Report Corrections

Fix misleading claims in audit reports:
- `docs/audit/09-hash-functions.md` — SHAKE digest is NOT in v3.2; only KEY_DERIVE variants exist. Close C_DigestXof as "not in v3.2".
- `docs/audit/10-mac-operations.md` — KMAC is NOT in v3.2 header at all. Close as "not in v3.2".
- `docs/audit/08-aead.md` — Note that AES_GMAC already has Wycheproof+ACVP+message API coverage (audit said "zero").
- `docs/audit/39-hss-xmss-domain.md` — Note that HSS/XMSS already have comprehensive tests in `test_stateful_sigs.py` (audit said "no tests").
- `docs/audit/00-index.md` — Rewrite Tier 1 "blocking" section: C_DigestXof and KMAC are NOT in v3.2 (not blocking, just absent). CK_SIGN_ADDITIONAL_CONTEXT pure variant IS the real remaining infra work.

### Iteration 2: Mechanism Registry — SHA3/SHAKE KEY_DERIVE

Add 6 missing mechanisms to `mechanism_registry/_hash.py` or `_kdf.py`:
- `CKM_SHA3_224_KEY_DERIVE` (0x398)
- `CKM_SHA3_256_KEY_DERIVE` (0x397)
- `CKM_SHA3_384_KEY_DERIVE` (0x399)
- `CKM_SHA3_512_KEY_DERIVE` (0x39A)
- `CKM_SHAKE_128_KEY_DERIVE` (0x39B)
- `CKM_SHAKE_256_KEY_DERIVE` (0x39C)

These derive a key by hashing a base key with the respective digest. Follow existing `_SHA_*_KEY_DERIVE` pattern from `_kdf.py`.

### Iteration 3: CK_SIGN_ADDITIONAL_CONTEXT Pack Function

Implement in `raw/pack_mechanisms.py`:
- `mech_sign_additional_context()` — packs `CK_SIGN_ADDITIONAL_CONTEXT` (pure variant: hedgeVariant + context)
- This is for `CKM_ML_DSA` and `CKM_SLH_DSA` (pure, non-hash mechanisms)
- `mech_hash_sign_context()` already handles hash variants (CKM_HASH_ML_DSA, CKM_HASH_SLH_DSA)
- Fix ACVP tests (`acvp/test_acvp_mldsa.py:185,257`) to use the new pack function when context is non-empty

### Iteration 4: Hedge Variant Tests

New tests for ML-DSA/SLH-DSA with explicit hedge variants:
- `CKH_HEDGE_PREFERRED` (0x00) — default, already used implicitly
- `CKH_HEDGE_REQUIRED` (0x01) — must use randomization
- `CKH_DETERMINISTIC_REQUIRED` (0x02) — must be deterministic
- All three are in both the v3.2 header AND types_std.py
- Test with CKM_ML_DSA sign using `mech_sign_additional_context`

### Iteration 5: CKM_AES_MAC Functional Tests

CKM_AES_MAC (0x1083) — fixed 8-byte output MAC. Registry entry exists (`_aes.py:302`) but zero functional tests. CKM_AES_MAC_GENERAL is tested but not the fixed-output variant.

Add to `test_aes_modes.py`:
- Sign/verify roundtrip with CKM_AES_MAC
- Verify output is exactly 8 bytes (half AES block)
- Different key sizes (128/192/256)
- Tamper detection (modified data → verify fails)
- Different keys produce different MACs

### Iteration 6: SHA3/SHAKE Key Derivation Tests

New tests for the 6 mechanisms added in iteration 2:
- Derive AES key from generic secret using each SHA3/SHAKE key derivation mechanism
- Verify derived key is functional (can encrypt/decrypt)
- Verify determinism (same input → same derived key)
- These use `CK_KEY_DERIVATION_STRING_DATA` parameter (same as SHA-1/SHA-256 key derive)

### Iteration 7: Ed448 Tests

Ed448 uses the same mechanism (CKM_EDDSA) and keygen (CKM_EC_EDWARDS_KEY_PAIR_GEN) as Ed25519, with different OID (1.3.101.113 for Ed448 vs 1.3.101.112 for Ed25519).

Add to `test_eddsa.py`:
- Ed448 key pair generation with OID 1.3.101.113
- Ed448 sign/verify (114-byte signature vs Ed25519's 64-byte)
- CK_EDDSA_PARAMS with phFlag=True (prehash mode — Ed448ph)
- CK_EDDSA_PARAMS with context data (Ed448 supports context, Ed25519 does not per RFC 8032)
- Cross-verification with Python cryptography library

### Iteration 8: AES-CTR Negative + RSA OAEP Hash Combos

AES-CTR boundary tests:
- `ulCounterBits=0` → expect `CKR_MECHANISM_PARAM_INVALID`
- `ulCounterBits=129` → expect `CKR_MECHANISM_PARAM_INVALID`

RSA OAEP hash/MGF coverage:
- SHA-384 + MGF1-SHA384
- SHA-512 + MGF1-SHA512
- Verify behavior with SHA3 variants if module supports

### Iteration 9: Additional Gaps

Select the highest-value remaining items:
- Authenticated wrap tag tampering detection test
- Message API decrypt (not just encrypt)
- DES weak/semi-weak key detection
- CKM_NULL dedicated behavior test
- CKA_MODIFIABLE=False enforcement test

### Iteration 10: Consolidation

- Update `docs/audit/00-index.md` with final implementation status
- Verify no regressions: `uv run python -m pytest tests/`
- Summary of all changes across both the audit and implementation phases

## Ground Truth

- **Header:** `third_party/pkcs11-headers/3.2/pkcs11.h` — the ONLY source of truth for what's in PKCS#11 v3.2
- **OASIS spec docs:** Reference for behavior/semantics, but mechanism existence MUST be verified against header first
- **Test patterns:** Follow existing `recipes.py`, `mechanism_registry`, `_error_tuples.py` patterns
- **Key lesson:** The OASIS markdown spec docs describe a SUPERSET of what's in v3.2. Always verify against pkcs11.h before claiming something is "missing" or "needs implementation".
