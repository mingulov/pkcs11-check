# Audit Gap Implementation Design

**Date:** 2026-04-02
**Scope:** Implement fixes and new tests for gaps identified in the 42-iteration audit, verified against the actual PKCS#11 v3.2 header.
**Execution:** Ralph-loop autonomous, ~12 iterations
**Prerequisite:** `docs/superpowers/specs/2026-04-01-deep-audit-design.md` (completed audit)

## Header Verification — Critical Corrections

The audit identified 136 gaps. Before implementation, each was verified against the actual vendored `third_party/pkcs11-headers/3.2/pkcs11.h`. Key corrections:

### NOT in v3.2 header (spec-only / future draft)

| Item | Status | Action |
|------|--------|--------|
| `C_DigestXof*` functions | Not in header — no C_DigestXofInit/Update/Final | Close as "not in v3.2"; update audit report |
| `CK_KMAC_PARAMS` | Not in header — zero KMAC references | Close as "not in v3.2"; update audit report |
| `CKM_KMAC128` / `CKM_KMAC256` | Not in header | Close; update audit report |
| `CKM_SHAKE_128` / `CKM_SHAKE_256` (digest) | Not in header (only KEY_DERIVE variants) | Close digest testing; implement KEY_DERIVE tests |

### IS in v3.2 header (implementable now)

| Item | Header evidence | Action |
|------|----------------|--------|
| `CK_SIGN_ADDITIONAL_CONTEXT` | `struct CK_SIGN_ADDITIONAL_CONTEXT` with `hedgeVariant`, `pContext`, `ulContextLen` | Implement param builder; fix ML-DSA/SLH-DSA ACVP |
| `CK_HASH_SIGN_ADDITIONAL_CONTEXT` | `struct CK_HASH_SIGN_ADDITIONAL_CONTEXT` | Implement for hash-sign variants |
| `CK_HEDGE_TYPE` | `CKH_HEDGE_PREFERRED` (0), `CKH_HEDGE_REQUIRED` (1) | Add hedge variant tests |
| `CKM_AES_MAC` | 0x00001083 | Add functional tests |
| `CKM_AES_MAC_GENERAL` | 0x00001084 | Already tested; verify completeness |
| `CKM_AES_GMAC` | 0x0000108E | Add functional tests |
| `CKM_SHA3_224_KEY_DERIVE` | 0x00000398 | Add mechanism_registry + tests |
| `CKM_SHA3_256_KEY_DERIVE` | 0x00000397 | Add mechanism_registry + tests |
| `CKM_SHA3_384_KEY_DERIVE` | 0x00000399 | Add mechanism_registry + tests |
| `CKM_SHA3_512_KEY_DERIVE` | 0x0000039A | Add mechanism_registry + tests |
| `CKM_SHAKE_128_KEY_DERIVE` | 0x0000039B | Add mechanism_registry + tests |
| `CKM_SHAKE_256_KEY_DERIVE` | 0x0000039C | Add mechanism_registry + tests |
| `CKM_EDDSA` | 0x00001057 | Ed448 tests (curve choice, not separate mechanism) |
| `CK_EDDSA_PARAMS` | struct with `phFlag`, `ulContextDataLen`, `pContextData` | Ed448 + prehash tests |
| `CKM_HSS` / `CKM_HSS_KEY_PAIR_GEN` | 0x00004032, 0x00004033 | Skeleton availability tests |
| `CKM_XMSS` / `CKM_XMSS_KEY_PAIR_GEN` | 0x00004034, 0x00004036 | Skeleton availability tests |
| `CKM_XMSSMT` / `CKM_XMSSMT_KEY_PAIR_GEN` | 0x00004035, 0x00004037 | Skeleton availability tests |
| `CKM_NULL` | 0x0000400B | Add mechanism test |

## Decisions

- **Approach:** Fix audit reports, add registry entries, implement tests — all verified against header
- **Execution model:** Ralph-loop autonomous
- **Output:** Report + fixes + new tests committed per iteration
- **Scope:** ~12 iterations covering all header-backed gaps

## Iteration Plan

### Iteration 1: Audit Report Corrections

Fix the 3 misleading "blocking" claims in audit reports:
- `docs/audit/09-hash-functions.md` — SHAKE digest is NOT in v3.2; only KEY_DERIVE variants exist
- `docs/audit/10-mac-operations.md` — KMAC is NOT in v3.2 header at all
- `docs/audit/00-index.md` — update Tier 1 "blocking" section to reflect reality

### Iteration 2: Mechanism Registry Additions

Add missing mechanisms that ARE in v3.2 header to `mechanism_registry/`:
- `_hash.py`: CKM_SHA3_224/256/384/512_KEY_DERIVE, CKM_SHAKE_128/256_KEY_DERIVE
- `_aes.py` or appropriate: Verify CKM_AES_MAC, CKM_AES_GMAC entries are complete
- `_misc.py` or new: CKM_NULL
- `_pqc.py`: HSS/XMSS/XMSSMT mechanism entries

### Iteration 3: CK_SIGN_ADDITIONAL_CONTEXT Param Builder

Implement in `raw/pack_mechanisms.py`:
- `mech_sign_additional_context()` — packs CK_SIGN_ADDITIONAL_CONTEXT struct
- `mech_hash_sign_additional_context()` — packs CK_HASH_SIGN_ADDITIONAL_CONTEXT struct
- Fix ACVP ML-DSA tests (`acvp/test_acvp_mldsa.py:185,257`) to pass context via param builder
- Fix ACVP SLH-DSA tests similarly if applicable

### Iteration 4: Hedge Variant Tests

New tests using CK_SIGN_ADDITIONAL_CONTEXT with hedge variants:
- `CKH_HEDGE_PREFERRED` (default behavior)
- `CKH_HEDGE_REQUIRED` (must hedge)
- `CKH_DETERMINISTIC_REQUIRED` (if in header — verify first)
- Test with ML-DSA and SLH-DSA sign operations

### Iteration 5: AES_MAC + AES_GMAC Functional Tests

New test file or extend `test_aes_modes.py`:
- CKM_AES_MAC: sign/verify roundtrip, 8-byte (half-block) output verification
- CKM_AES_GMAC: sign/verify with GCM params (IV + AAD, no plaintext)
- Different key sizes (128/192/256)
- Tamper detection (modified data → verify fails)

### Iteration 6: SHA3/SHAKE Key Derivation Tests

New tests for 6 mechanisms:
- CKM_SHA3_224_KEY_DERIVE, CKM_SHA3_256_KEY_DERIVE, CKM_SHA3_384_KEY_DERIVE, CKM_SHA3_512_KEY_DERIVE
- CKM_SHAKE_128_KEY_DERIVE, CKM_SHAKE_256_KEY_DERIVE
- Derive from generic secret → verify derived key is usable
- Different derived key lengths

### Iteration 7: Ed448 Tests

New tests using CKM_EDDSA with Ed448 curve:
- Ed448 key pair generation (CKM_EC_EDWARDS_KEY_PAIR_GEN with Ed448 OID)
- Ed448 sign/verify (CKM_EDDSA, 114-byte signature)
- CK_EDDSA_PARAMS with phFlag (prehash mode)
- CK_EDDSA_PARAMS with context data

### Iteration 8: CKM_NULL + HSS/XMSS Skeleton Tests

- CKM_NULL mechanism: test presence, behavior per spec (no-op mechanism for testing)
- HSS: availability probe, keygen if module supports, sign/verify skeleton
- XMSS/XMSSMT: same pattern — availability + skeleton

### Iteration 9: AES-CTR Negative Tests

- `ulCounterBits=0` → expect `CKR_MECHANISM_PARAM_INVALID`
- `ulCounterBits=129` → expect `CKR_MECHANISM_PARAM_INVALID`
- Counter overflow behavior (if testable)

### Iteration 10: RSA OAEP Hash/MGF Combos

- SHA-384 + MGF1-SHA384
- SHA-512 + MGF1-SHA512
- SHA3 variants if module supports
- Mismatched hash/MGF (e.g., SHA-256 hash + MGF1-SHA384) → verify behavior

### Iteration 11: Additional Gaps

- ChaCha20 nonce variants (64-bit, 192-bit XChaCha20)
- Authenticated wrap tag tampering detection
- Message API decrypt/sign/verify (not just encrypt)
- DES weak/semi-weak key detection
- Other medium-priority items from audit

### Iteration 12: Consolidation

- Update `docs/audit/00-index.md` with implementation status
- Verify no regressions: `uv run python -m pytest tests/`
- Summary of all changes

## Ground Truth

- **Header:** `third_party/pkcs11-headers/3.2/pkcs11.h` — the only source of truth for what's in PKCS#11 v3.2
- **OASIS spec docs:** Reference for behavior/semantics, but mechanism existence must be verified against header
- **Test patterns:** Follow existing `recipes.py`, `mechanism_registry`, `_error_tuples.py` patterns
