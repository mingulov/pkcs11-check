# pkcs11-check Current Status

Last updated: 2026-03-21

## What Works

- **74,800+ tests** across 194 test files on SoftHSM2 and Kryoptic
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
- **Per-target validation** — SoftHSM2 + Kryoptic validated; OpenCryptoki, TPM2, BouncyHSM need fresh runs

## What's Planned

- **Close Phase A-H remaining gaps** — ~15 specific items identified in gap analysis
- **Vendor extension system** — configurable vendor mechanism support (IBM/OpenCryptoki first), designed and spec'd
- **Per-target re-validation** — fresh runs on all 12 Docker targets
- **Compliance report hardening** — accurate function/mechanism coverage mapping
