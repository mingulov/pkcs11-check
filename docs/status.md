# pkcs11-check Current Status

Last updated: 2026-03-28

## What Works

- **75,000+ tests** across 195+ test files on SoftHSM2 and Kryoptic
- **802/802 CKR spec entries** — every function-specific CKR from OASIS spec documented
- **148+ CKR error tests** with raw ctypes bypass for wrapper-blocked conditions
- **v3.0/v3.2 interface negotiation** — tested on Kryoptic
- **PQC support** — ML-KEM, ML-DSA, SLH-DSA tested with keygen, sign/verify, encapsulate/decapsulate, Wycheproof vectors, ACVP vectors, HASH_ML_DSA/HASH_SLH_DSA variants, HSS/XMSS stateful signatures
- **Adaptive isolated runner** — `pkcs11-check test` defaults to `--isolation auto`; survives crashes, escalates, remembers crash-prone files per backend
- **10 local build providers** — SoftHSM2, Kryoptic, NSS, pkcs11-mock, qryptotoken, tpm2-pkcs11, BouncyHSM, OpenCryptoki, swtpm, tpm2-swtpm
- **12 Docker test targets** for CI validation
- **OASIS spec compliance roadmap** — 8-phase plan (A-H), all phases substantially implemented
- **API function coverage** — ~57/68 core C_* functions with dedicated tests (operation state, sign/verify recovery, dual-function, v3.0 session, KEM)
- **Object type coverage** — 12/12 OASIS object types tested (HW Feature, Mechanism, Trust, Validation, OTP Key, Domain Parameters, Profile, plus standard keys/certs)
- **Attribute enforcement** — COPYABLE, DESTROYABLE, SENSITIVE, EXTRACTABLE one-way flags, KEY_GEN_MECHANISM, CHECK_VALUE, ALLOWED_MECHANISMS, WRAP_WITH_TRUSTED, ALWAYS_AUTHENTICATE, date ranges, defaults
- **Session semantics** — state machine, object visibility, RO restrictions, access levels, concurrent sessions
- **Mechanism breadth** — AES (11 modes), RSA (20+ variants), EC/ECDSA/ECDH/EdDSA, DSA, DH/X9.42, SHA-1/2/3, HMAC, HKDF, SP800-108 KDF, DES/3DES, Camellia, ARIA, SEED, Blowfish, Twofish, GOST, ChaCha20-Poly1305, TLS 1.2, SSL3, WTLS, IKE, PBE, OTP, Salsa20, BLAKE2, misc KDFs
- **Mechanism-driven test system** — 467-entry registry (full MECHANISM_NAMES coverage), MechanismCatalog auto-parametrizes tests from preflight manifest, 12 test_mech_* files covering flags, keygen, encrypt, sign, digest, derive, wrap, lifecycle, multipart, state, negative, message
- **KAT vectors** — Pre-generated known-answer tests for AES-ECB/CBC/CBC-PAD/CTR/GCM, DES3-ECB/CBC, HMAC-SHA256/384/512 (12 JSON vector files)
- **Test vectors** — Wycheproof (ECDSA, RSA, ECDH, DSA, AES, HMAC, Ed25519/448, ChaCha20, X25519/X448, HKDF, ML-DSA, ML-KEM, PBES2, PBKDF2), NIST ACVP (AES-GCM, ECDSA, EdDSA, HMAC, SHA-3, SLH-DSA, ML-DSA), CCTV (RFC 6979, ML-DSA benchmark)
- **X.509 certificate suite** — 8 test files covering CRL, identity, lifecycle, limbo import (9769 certs), attribute parity, core ops, search
- **CVE regression** — 29 tests covering CVEs across NSS, SoftHSM2, TPM2, OpenCryptoki, BouncyHSM, Kryoptic
- **Security tests** — attribute fuzz, Tookan vectors, handle reuse, padding oracle, ECDSA nonce quality, RNG stats
- **Compliance report generator** — machine-readable JSON output via `compliance_report.py`

## What's Partial

- **Remaining API gaps** — C_WaitForSlotEvent success path, C_SignEncryptUpdate, C_DecryptVerifyUpdate, message finalizers, async lifecycle, legacy parallel functions
- **Remaining mechanism gaps** — ML_DSA_EXTERNAL_MU, KMAC, standalone SHAKE, PKCS12_PBE_EXPORT/IMPORT, RSA_PKCS_NULL, a few Tier 1 stragglers
- **Remaining attribute gaps** — CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE, CKA_DERIVE_TEMPLATE, explicit CKO_OTP_KEY object tests
- **Compliance report accounting** — function/mechanism keyword mappings need refresh
- **Per-target validation** — SoftHSM2 + Kryoptic validated; NSS-PQC 3.121.0 fully triaged (Phases 1-11); OpenCryptoki, TPM2, BouncyHSM need fresh runs

## NSS-PQC 3.121.0 (2026-03-27)

Full 11-phase validation against NSS 3.121.0 (softoken with PQC support) completed.

### Final Numbers

| Metric | Baseline | Post-fix | Delta |
|--------|----------|---------|-------|
| Passed | 35,292 | 35,327 | +35 |
| Failed | 415 | 296 | -119 |
| Skipped | 31,947 | 31,984 | +37 |
| Xfailed | 598 | 645 | +47 |
| **Total** | **68,252** | **68,252** | — |

### Test Coverage

- **Function coverage:** 64/104 PKCS#11 functions called (61%)
- **Mechanism coverage:** 107/140 advertised mechanisms exercised (76%)
- **Interface version:** v3.0 (negotiated via `C_GetInterfaceList`)

### Remaining Failures (296)

All 296 remaining failures are Wycheproof DSA vectors (`test_wycheproof_dsa.py`) where NSS
softoken rejects externally imported public keys with raw domain parameters. This is a
fundamental NSS architectural limitation — DSA verification requires keys generated or imported
through NSS's internal format, not raw `CKO_PUBLIC_KEY` objects via `C_CreateObject`. These
remain as failures (not xfailed) because the module is genuinely rejecting valid signatures.

### Xfail Summary (645 total)

All 645 xfails verified as legitimate NSS softoken limitations — none are test bugs:

| Count | Category |
|------:|---------|
| 256 | ChaCha20-Poly1305: non-standard AEAD parameter format |
| 232 | HKDF: incorrect output vs. RFC 5869 expected values |
| 77 | AES-KWP: RFC 5649 non-conformance (size/content/minimum) |
| 16 | IKE derive: mechanisms advertised but not operational |
| 13 | Security bugs: sensitive reads, Tookan, padding oracle, key extraction |
| 7 | EdDSA: rejects standard CK_EDDSA_PARAMS (PKCS#11 v3.0 Sec.2.3.13) |
| 7 | SP800-108 KDF: feedback/pipeline advertised but not operational |
| 25 | Attribute/spec deviations: CKA_PRIVATE, CKA_LOCAL, CKA_EXTRACTABLE, etc. |
| 3 | HKDF_DATA: CKO_DATA object derivation not supported |
| 9 | Miscellaneous NSS quirks and limitations |

### Security Findings

Four high-severity security bugs confirmed in NSS softoken (documented in `docs/module-issues.md`):

1. **CRITICAL:** `CKA_VALUE`/`CKA_PRIVATE_EXPONENT` readable despite `CKA_SENSITIVE=True`
2. **CRITICAL:** `CKA_EXTRACTABLE` escalation `False→True` via `C_CopyObject` (Tookan)
3. **HIGH:** Wrap-decrypt oracle (key with both `CKA_WRAP` and `CKA_DECRYPT`)
4. **MEDIUM:** RSA-OAEP non-uniform error codes (Manger 2001 padding oracle)

### Spec Deviations Discovered

- `CKA_PRIVATE` defaults to False for secret/private keys (spec: True)
- `CKA_LOCAL` not set on generated keys
- `CKA_EXTRACTABLE` defaults to True for RSA private keys (spec recommends False)
- `CKA_COPYABLE` / `CKA_DESTROYABLE` not enforced
- `CKA_KEY_GEN_MECHANISM` / `CKA_ALWAYS_AUTHENTICATE` not supported
- `CKR_PIN_INCORRECT` instead of `CKR_USER_ALREADY_LOGGED_IN` on re-login
- Auto-initialize after `C_Finalize` returns `CKR_OK` (vendor extension)
- `C_CloseSession` returns `CKR_OK` on already-closed session
- Template checks before session-type checks (ordering deviation)
- NULL mechanism pointer returns `CKR_MECHANISM_INVALID` (not `CKR_ARGUMENTS_BAD`)
- `CKA_WRAP_WITH_TRUSTED` wrapping not enforced

### Skip Summary (31,984 total)

79% of skips (25,167) are from NSS's restricted EC curve support — only P-256, P-384, P-521.
Remaining: SHA-3/RSA absent, AES CCM/XTS/GMAC missing, ML-DSA/SLH-DSA not yet in NSS 3.121.0,
Montgomery/Ed/RSA-OAEP key import limitations.

## What's Planned

- **Close Phase A-H remaining gaps** — ~15 specific items identified in gap analysis
- **Vendor extension system** — configurable vendor mechanism support (IBM/OpenCryptoki first), designed and spec'd
- **Per-target re-validation** — fresh runs on remaining Docker targets (SoftHSM2, NSS 3.120.1, OpenCryptoki, TPM2, BouncyHSM)
- **Compliance report hardening** — accurate function/mechanism coverage mapping
