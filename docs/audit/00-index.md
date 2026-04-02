# pkcs11-check Deep Audit — Master Index

**Date:** 2026-04-01
**Spec:** `docs/superpowers/specs/2026-04-01-deep-audit-design.md`
**Plan:** `docs/superpowers/plans/2026-04-01-deep-audit.md`

## Aggregate Statistics

| Metric | Count |
|--------|-------|
| Iterations completed | 42 |
| Reports generated | 42 |
| Issues fixed | 17 |
| Issues noted | 38 |
| Coverage gaps documented | 136 (see Future Work below) |
| Meta-test regressions | 0 |

## Fixes Applied

| Iter | Fix | File |
|------|-----|------|
| 01 | Bare `except: pass` → `except Exception:` | `test_subprocess_safety.py` |
| 01 | Hardcoded `0x191` → `CKR_CRYPTOKI_ALREADY_INITIALIZED` | 6 files |
| 01 | Hardcoded `0x69` → `CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_NOT_WRAPPABLE` | `test_tls12.py` |
| 01 | Wrong CKR comment (0x69 is KEY_NOT_WRAPPABLE, not KEY_FUNCTION_NOT_PERMITTED) | `test_tls12.py` |
| 01 | Silent `except Exception: pass` documented with cleanup context | `test_mech_state.py` |
| 03 | Bare `except Exception: pass` on C_Logout → `logout_quietly()` | `raw_fixtures.py` |
| 03 | Session handle leak when login_user raises | `fixtures.py` |
| 03 | Raw C_Logout → `logout_quietly()` in both session fixtures | `fixtures.py` |
| 03 | Added missing `requires_v31` marker | `markers.py` |
| 04 | Unreachable dead code (return after raise) | `acvp/aes/test_other.py` |
| 07 | Incorrect Twofish block size comments (8→16) | `test_twofish.py` |

## Iteration Reports

### Phase 1: Foundation & Quality
- [01-code-quality.md](01-code-quality.md) — 10 issues fixed (bare excepts, hardcoded hex, wrong CKR comment)
- [02-raw-bindings.md](02-raw-bindings.md) — Perfect parity: 480 CKM, 160 CKA, 105 CKR, 104 C_ functions
- [03-infrastructure.md](03-infrastructure.md) — 4 fixes (session leak, logout, v3.1 marker)

### Phase 2: Symmetric Crypto
- [04-aes-core-modes.md](04-aes-core-modes.md) — CS1/CS3 correct, 6 gaps (MAC, GMAC, CTR negative)
- [05-aes-acvp-vectors.md](05-aes-acvp-vectors.md) — CCM nonce/tag defaults verified correct
- [06-des.md](06-des.md) — Weak key, parity, check value gaps
- [07-other-symmetric.md](07-other-symmetric.md) — Twofish comment fix, ChaCha20/Salsa20 variant gaps
- [08-aead.md](08-aead.md) — Salsa20-Poly1305 zero coverage, ChaCha20-Poly1305 partial

### Phase 3: Hash & MAC
- [09-hash-functions.md](09-hash-functions.md) — SHAKE/XOF blocked by missing C_DigestXof bindings
- [10-mac-operations.md](10-mac-operations.md) — KMAC blocked by missing CK_KMAC_PARAMS
- [11-acvp-hash-hmac.md](11-acvp-hash-hmac.md) — SHA-1 HMAC and BLAKE2b HMAC missing from ACVP

### Phase 4: Asymmetric Crypto
- [12-rsa.md](12-rsa.md) — OAEP limited hash coverage, hardcoded output sizes
- [13-ec-ecdsa.md](13-ec-ecdsa.md) — secp256k1, Brainpool, compressed points gaps
- [14-ecdh-x25519.md](14-ecdh-x25519.md) — X9.42 DH untested
- [15-eddsa.md](15-eddsa.md) — Ed448 and prehash EdDSA missing
- [16-dsa-dh.md](16-dsa-dh.md) — FIPS param gen, X3DH flows untested

### Phase 5: Post-Quantum
- [17-ml-kem-ml-dsa.md](17-ml-kem-ml-dsa.md) — ML-KEM excellent, ML-DSA context TODO
- [18-slh-dsa.md](18-slh-dsa.md) — ACVP complete, unit tests cover 3/12 sets

### Phase 6: Key Management & Derivation
- [19-key-lifecycle.md](19-key-lifecycle.md) — Tookan comprehensive, SENSITIVE write-once gap
- [20-kdf-operations.md](20-kdf-operations.md) — SHA3/SHAKE key derivation completely absent
- [21-key-wrapping.md](21-key-wrapping.md) — Authenticated wrap tag tampering gap

### Phase 7: Session/Token/Object
- [22-session-management.md](22-session-management.md) — Callbacks untested
- [23-object-management.md](23-object-management.md) — CK_UNAVAILABLE_INFORMATION gap
- [24-token-pin.md](24-token-pin.md) — PIN length boundaries, lockout flags

### Phase 8: Advanced & Protocol
- [25-message-api.md](25-message-api.md) — Only GCM encryption; decrypt/sign/verify missing
- [26-protocol-operations.md](26-protocol-operations.md) — CT-KIP, X3DH, Double Ratchet flows missing
- [27-async-opstate.md](27-async-opstate.md) — Async lifecycle still TODO

### Phase 9: Security & Compliance
- [28-security.md](28-security.md) — Strong: padding oracle, Tookan, RNG, 29 CVEs
- [29-ckr-compliance.md](29-ckr-compliance.md) — 30 test files; error priority ordering gap

### Phase 10: X.509 & Object Types
- [30-x509-certificates.md](30-x509-certificates.md) — Comprehensive with Limbo vectors
- [31-object-types.md](31-object-types.md) — All types have files; HW features limited
- [32-otp-cms.md](32-otp-cms.md) — Availability only; few modules support OTP/CMS

### Phase 11: Legacy & Regional
- [33-gost.md](33-gost.md) — Param structures not in pack.py
- [34-legacy-ciphers.md](34-legacy-ciphers.md) — 82 mechanisms registered, none supported by tested modules

### Phase 12: Cross-Cutting Concerns
- [35-interop-crossverify.md](35-interop-crossverify.md) — PQC cross-verify missing
- [36-multipart-dual.md](36-multipart-dual.md) — SHAKE multipart excluded
- [37-threading-stress.md](37-threading-stress.md) — PQC stress tests missing
- [38-access-control.md](38-access-control.md) — CKA_MODIFIABLE enforcement gap

### Phase 13: Remaining Gaps
- [39-hss-xmss-domain.md](39-hss-xmss-domain.md) — HSS/XMSS: no module support
- [40-parameter-consistency.md](40-parameter-consistency.md) — All prior flags resolved
- [41-surface-scripts.md](41-surface-scripts.md) — Scripts verified correct

## Top-Priority Future Work

**Closed — NOT in PKCS#11 v3.2 header (spec-only / future draft):**
1. ~~C_DigestXof* functions for SHAKE-128/256~~ — NOT in v3.2 pkcs11.h header
2. ~~CK_KMAC_PARAMS for KMAC-128/256~~ — NOT in v3.2 pkcs11.h header (zero KMAC references)
3. ~~CKM_ML_DSA_EXTERNAL_MU~~ — NOT in v3.2 pkcs11.h header

**Audit corrections (items already implemented, audit was wrong):**
- AES_GMAC: already has Wycheproof, ACVP, and message API tests
- HSS/XMSS: already have comprehensive tests in test_stateful_sigs.py + full registry entries
- CKM_NULL: already in mechanism_registry/_kdf.py
- mech_hash_sign_context: already exists in pack_mechanisms.py for CK_HASH_SIGN_ADDITIONAL_CONTEXT

**Implementable (in v3.2 header):**
1. CK_SIGN_ADDITIONAL_CONTEXT pure variant pack function for ML-DSA/SLH-DSA ACVP context
2. CKM_AES_MAC functional tests (fixed 8-byte output — registry exists, zero tests)
3. Ed448 keygen/sign/verify (CKM_EDDSA with Ed448 OID)
4. SHA3/SHAKE key derivation mechanisms (6 mechanisms, 0 registry entries, 0 tests)
5. RSA OAEP with SHA-384/512 hash/MGF combos
6. ML-DSA/SLH-DSA hedge variant tests (CKH_HEDGE_PREFERRED/REQUIRED/DETERMINISTIC_REQUIRED)
7. AES-CTR ulCounterBits boundary validation (0, 129 → CKR_MECHANISM_PARAM_INVALID)
8. PQC cross-verification against external library
9. Authenticated wrap tag tampering detection
10. CKR error priority ordering tests

**Medium-value improvements:**
11. AES-CTR negative tests (ulCounterBits=0, =129)
12. DES weak/semi-weak key detection
13. ChaCha20/Salsa20 nonce variant coverage (64/96/192-bit)
14. secp256k1 and Brainpool curve tests
15. Message-based API for decrypt/sign/verify

## Verification

- **Meta-tests:** 604 passed, 2 failed (pre-existing), 1 skipped — **zero regressions**
- **Ruff (E,F):** No new errors from audit changes
- **Branch:** All work on `dev`

## Implementation Phase (2026-04-02)

**Spec:** `docs/superpowers/specs/2026-04-02-audit-implementation-design.md`

### Completed

| Iter | Change | Files |
|------|--------|-------|
| 01 | Corrected audit reports (SHAKE/KMAC not in v3.2, GMAC/HSS already tested) | 5 audit reports |
| 02 | Added SHA3/SHAKE KEY_DERIVE to mechanism registry (6 mechanisms) | _kdf.py |
| 03 | Added mech_sign_context for CK_SIGN_ADDITIONAL_CONTEXT (pure ML-DSA/SLH-DSA) | pack_mechanisms.py |
| 03b | Fixed SHAKE ACVP NameError (CKM_SHAKE128/256 not in v3.2) | test_acvp_hash.py |
| 04 | Fixed ML-DSA ACVP context passing via mech_sign_context | test_acvp_mldsa.py |
| 05 | Added ML-DSA hedge variant tests (preferred/required/deterministic) | test_pqc_sign.py |
| 06 | Added CKM_AES_MAC functional tests (sign/verify, tamper, key independence) | test_aes_modes.py |
| 07 | Added Ed448 keygen/sign/verify/signature-length tests | test_eddsa.py |
| 08 | Added SHA3/SHAKE key derivation tests (6 mechanisms, determinism) | test_kdf.py |
| 09 | AES-CTR ulCounterBits=0/129 negative tests, RSA OAEP SHA-384/512 | test_aes_modes.py, test_rsa_oaep.py |

### Remaining (lower priority)

- PQC cross-verification against external library
- Authenticated wrap tag tampering detection
- Message-based API decrypt/sign/verify
- DES weak/semi-weak key detection
- CKR error priority ordering tests

### Closed (NOT in PKCS#11 v3.2)

- C_DigestXof* (SHAKE digest) — not in pkcs11.h
- CK_KMAC_PARAMS / CKM_KMAC128/256 — not in pkcs11.h
- CKM_ML_DSA_EXTERNAL_MU — not in pkcs11.h
