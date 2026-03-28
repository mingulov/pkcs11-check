# pkcs11-check — Test Coverage Summary

Run `pytest --co -q` for current counts. Tests auto-skip for unsupported mechanisms.

Low-level PKCS#11 entry-point coverage now shares the `pkcs11_check.raw` substrate. The
generated `pkcs11_check.raw.types_std` and `pkcs11_check.raw.metadata_std` modules back the
common `RawPKCS11` API plus the shared bootstrap, pack, fault, inspect, and extension helpers,
so migrated product tests no longer carry per-file ad hoc `ctypes` function-list walkers.

## Test Categories

### Wycheproof Edge-Case Vectors (18 files)

All Wycheproof tests check mechanism availability at runtime and skip cleanly.

| File | Algorithms |
|------|------------|
| test_wycheproof.py | AES-GCM, AES-CBC-PKCS5, HMAC-SHA256, ECDSA P-256/384 |
| test_wycheproof_aes.py | AES-CMAC, Key Wrap, KWP, CCM, GMAC, XTS |
| test_wycheproof_chacha.py | ChaCha20-Poly1305 AEAD |
| test_wycheproof_dsa.py | DSA 2048/3072 × SHA-224/256 |
| test_wycheproof_ecdh.py | ECDH across secp*r1, secp256k1, brainpool, binary curves, ASN.1/PEM/WebCrypto/ecpoint |
| test_wycheproof_ecdsa.py | ECDSA across secp*k1, secp*r1, brainpool, SHA-2/SHA-3/SHAKE, DER + P1363 |
| test_wycheproof_ed25519.py | Ed25519 + Ed448 signature verification |
| test_wycheproof_hkdf.py | HKDF SHA-1/256/384/512 |
| test_wycheproof_hmac.py | HMAC SHA/SHA-3/SHA-512 truncated |
| test_wycheproof_mldsa.py | ML-DSA verify vectors |
| test_wycheproof_mldsa_sign.py | ML-DSA 44/65/87 sign vectors, seeded + non-seeded |
| test_wycheproof_mlkem.py | ML-KEM decapsulation vectors, including semi-expanded decaps sets |
| test_wycheproof_pbes2.py | PBES2 decrypt via PBKDF2 + AES-CBC-PAD composition |
| test_wycheproof_rsa.py | RSA PKCS#1 v1.5 sigs: 2048-8192 × SHA/SHA-3 |
| test_wycheproof_rsa_decrypt.py | RSA PKCS#1 v1.5 decryption (padding oracle vectors) |
| test_wycheproof_rsa_oaep.py | RSA-OAEP including mixed hash/MGF and three-prime vectors |
| test_wycheproof_rsa_pss.py | RSA-PSS with CK_RSA_PKCS_PSS_PARAMS, mixed MGF, parameterized vectors |
| test_wycheproof_x25519.py | X25519 + X448 via raw, ASN.1, PEM, and JWK encodings |

### Post-Quantum Cryptography (3 files, requires v3.2)

| File | Algorithms |
|------|------------|
| test_kem.py | ML-KEM-512/768/1024 keygen, encapsulate, decapsulate |
| test_pqc_sign.py | ML-DSA-44/65/87, SLH-DSA sign/verify |
| test_profiles.py | CKO_PROFILE object and ProfileID validation |

### Cross-Verification (4 files)

Verify PKCS#11 output against Python `cryptography` library.

- **test_crossverify.py** — AES-ECB/CBC, RSA multi-hash, ECDSA P-256/384, HMAC
- **test_interop.py** — RSA sign→crypto verify, RSA-PSS, ECDSA multi-curve, AES-GCM, HMAC
- **test_aead.py** — AES-GCM cross-verify, tamper detection, AAD integrity
- **test_ec_curves.py** — P-224/256/384/521 keygen + ECDSA cross-verify

### NIST ACVP KAT Vectors (7 files)

Official NIST Automated Cryptographic Validation Protocol vectors. Require `scripts/fetch-optional-data.sh acvp`. Skip gracefully when not cloned.

| File | Algorithms | Security property |
|------|------------|-------------------|
| test_kat.py | SHA-1/224/256/384/512, AES-ECB | Correctness vs SP 800-38A |
| test_sha3.py | SHA3-224/256/384/512 | Cross-verify vs hashlib |
| test_acvp_aes.py | AES-GCM encrypt/decrypt | Correctness + tag auth (invalid tag must be rejected) |
| test_acvp_ecdsa.py | ECDSA P-256/384/521 × SHA-256/384/512 SigVer | FIPS 186-5 §6.4 — invalid sigs must be rejected |
| test_acvp_eddsa.py | Ed25519/Ed448 SigVer + Ed25519 SigGen | RFC 8032 — invalid sigs must be rejected |
| test_acvp_hmac.py | HMAC-SHA-{1,224,256,384,512}, HMAC-SHA3-{256,512} | FIPS 198-1 correctness |
| test_acvp_slhdsa.py | SLH-DSA-SHA2-128f/192f SigVer + SigGen | FIPS 205 — invalid sigs must be rejected |

### CCTV Edge-Case Vectors (2 files)

Cryptographic Compliance Test Vectors for adversarial and edge-case scenarios.
Require `src/pkcs11_check/testcases/data/cctv/` directory.

| File | Algorithms | Purpose |
|------|------------|---------|
| test_cctv_rfc6979.py | ECDSA P-256 | RFC 6979 rejection-sampling path; verify is unconditional, sign is xfail |
| test_cctv_mldsa.py | ML-DSA-44/65/87 | Sign+verify round-trip using CCTV benchmark messages |

### Mechanism-Driven Tests (12 files)

Auto-parametrized from the module's advertised mechanism list. Each test is parametrized
per mechanism via MechanismCatalog (built from preflight manifest). 439-entry registry
covers AES, RSA, EC, DES, SHA, HMAC, HKDF, PQC, and more.

| File | Purpose | KAT |
|------|---------|:---:|
| test_mech_flags.py | Expected flags present, min≤max key size | - |
| test_mech_keygen.py | Key generation, key attributes, local flag | - |
| test_mech_encrypt.py | Encrypt/decrypt roundtrip + KAT vectors | Yes |
| test_mech_sign.py | Sign/verify roundtrip + KAT vectors (HMAC) | Yes |
| test_mech_digest.py | Digest known values + KAT vectors | Yes |
| test_mech_derive.py | Per-family derive (SHA, HKDF, ECDH, CONCAT, AES-ECB) | - |
| test_mech_wrap.py | Wrap/unwrap round-trip, RSA-OAEP wrap | - |
| test_mech_lifecycle.py | Key lifecycle, derive chain, re-derive | - |
| test_mech_multipart.py | Multi-part encrypt/digest/sign | - |
| test_mech_state.py | Operation state save/restore | - |
| test_mech_negative.py | Wrong key type, bad param rejection | - |
| test_mech_message.py | v3.0 message-based AEAD (deferred — needs packer) | - |

KAT vector files (12): AES-ECB/CBC/CBC-PAD/CTR/GCM, DES3-ECB/CBC, HMAC-SHA256/384/512,
SHA (multi-algorithm), HMAC (multi-algorithm).

### Classic KAT (2 files — subsumed by ACVP section above)

### Cryptographic Property Tests (7 files)

- **test_digest.py** — Hash length, determinism, cross-verify all SHA against hashlib, 1 MiB data, C_DigestKey cross-verify
- **test_encrypt.py** — AES roundtrip (ECB/CBC), key sizes, ciphertext properties, RSA PKCS/OAEP
- **test_sign.py** — RSA multi-hash, RSA-PSS, ECDSA multi-curve, determinism, HMAC, DSA
- **test_eddsa.py** — Ed25519 keygen, sign/verify, determinism, cross-verify with cryptography
- **test_rsa_oaep.py** — RSA-OAEP roundtrip, randomness, max plaintext, wrong-key rejection
- **test_fuzz.py** — Hypothesis property tests: AES, RSA, SHA, HMAC, ECDSA cross-verify

### Key Management (3 files)

- **test_keymgmt.py** — Import, export, copy, wrap/unwrap, ECDH derive
- **test_kdf.py** — HMAC-KDF cross-verify, HKDF basic, ECDH shared-secret agreement
- **test_key_sizes.py** — AES 128/192/256, RSA 2048/4096, EC P-256/384/521 keygen

### Security & Robustness (5 files)

- **test_errors.py** — Invalid operations, wrong mechanism, decrypt garbage, key lifecycle
- **test_api_security.py** — Session enforcement, attribute protection, key isolation
- **test_padding_oracle.py** — CBC padding oracle, timing analysis
- **test_nonce_quality.py** — ECDSA nonce reuse, bias detection
- **test_surface_audit.py** — Hidden mechanisms, deprecated detection, mechanism limit probing

### RNG Quality (1 file)

- **test_rng.py** — Uniqueness, lengths, monobit, byte distribution, Shannon entropy, runs test, seed_random

### Standards & Interface (8 files)

- **test_interface.py** — PKCS#11 interface detection, version negotiation
- **test_slot.py** — Slot info, token info, mechanism list
- **test_mechanism.py** — Mechanism flags, info, capabilities
- **test_init.py** — Module load/init, session open/close
- **test_token_flags.py** — Token flags, version validation, flag enumeration, session/memory counters
- **test_operation_state.py** — C_GetOperationState/C_SetOperationState: digest + encrypt state save/restore round-trip via shared `pkcs11_check.raw` helpers
- **test_v30_session.py** — C_LoginUser (v3.0+), CKU_CONTEXT_SPECIFIC, C_SessionCancel via shared `pkcs11_check.raw` helpers
- **test_sign_recover.py** — C_SignRecover/C_VerifyRecover with RSA X.509 (raw RSA), now using shared raw bootstrap/packing helpers

### Data Handling (4 files)

- **test_buffers.py** — Block boundaries, multi-block, empty input, large data
- **test_multipart.py** — Multi-part encrypt/decrypt/digest operations
- **test_dual_function.py** — C_DigestEncryptUpdate, C_DecryptDigestUpdate round-trip via shared `pkcs11_check.raw` helpers
- **test_object.py** — Object create, search, attributes, destroy, key import/export

### Stress & Performance (3 files)

- **test_stress.py** — 1000-cycle operations, multi-session, resource cleanup
- **test_resource.py** — Handle leaks, session limits, parallel sessions
- **test_benchmark.py** — AES-CBC/ECB, RSA sign/verify, ECDSA, SHA-256, RNG, keygen

### Advanced Testing (3 files)

- **test_metamorphic.py** — Metamorphic relation tests (encrypt/decrypt invariants)
- **test_search.py** — Object search, enumeration, attribute-based filtering

## Mechanism Coverage

| Mechanism | Wycheproof | ACVP | Cross-verify | Property | Notes |
|-----------|:---:|:---:|:---:|:---:|-------|
| AES-ECB | - | KAT | Yes | Yes | SP 800-38A KAT + cross-verify |
| AES-CBC | Yes | - | Yes | Yes | PKCS5 padding |
| AES-GCM | Yes | SigVer+Dec | Yes | Yes | IV sizes, AAD; ACVP tag-auth rejection |
| AES-CCM | Yes | - | - | - | Skips if unsupported |
| AES-CMAC | Yes | - | - | - | Tag truncation |
| AES-GMAC | Yes | - | - | - | Authentication-only GCM |
| AES-KW | Yes | - | - | - | RFC 3394 |
| AES-KWP | Yes | - | - | - | RFC 5649 |
| AES-XTS | Yes | - | - | - | Disk encryption mode |
| RSA PKCS#1 v1.5 sign | Yes | - | Yes | Yes | 2048-8192, SHA + SHA-3 |
| RSA PKCS#1 v1.5 decrypt | Yes | - | - | - | Padding oracle vectors |
| RSA-PSS | Yes | - | Yes | Yes | Proper PSS params, mixed MGF, misc salt lengths |
| RSA-OAEP | Yes | - | Yes | Yes | Mixed hash/MGF |
| ECDSA P-224/256/384/521, secp*k1, brainpool | Yes | SigVer | Yes | Yes | FIPS 186-5; invalid sig rejection tested |
| ECDH secp*r1, secp256k1, brainpool, binary curves | Yes | - | - | Yes | Raw secret agreement across multiple encodings |
| X25519 / X448 | Yes | - | - | - | Raw, ASN.1, PEM, JWK |
| Ed25519 | Yes | SigVer+Gen | Yes | Yes | RFC 8032; invalid sig rejection tested |
| Ed448 | Yes | SigVer | - | - | Skips if unsupported |
| DSA 2048/3072 | Yes | - | - | Yes | SHA-224/256 |
| HMAC SHA family | Yes | MAC | Yes | Yes | FIPS 198-1; SHA, SHA-3, SHA-512 truncated |
| ChaCha20-Poly1305 | Yes | - | - | - | Native CK params |
| HKDF | Yes | - | - | - | Skips if unsupported |
| PBES2 | Yes | - | - | - | PBKDF2 + AES-CBC-PAD composition |
| SHA-1/224/256/384/512 | - | KAT | Yes | Yes | SP 800-38A + hashlib cross-verify |
| SHA3-224/256/384/512 | - | KAT | - | - | hashlib cross-verify |
| ML-KEM | Yes | - | - | Yes | v3.2 decapsulation Wycheproof + native KEM tests |
| ML-DSA | Yes | SigGen | - | Yes | FIPS 204; CCTV round-trip; Wycheproof verify + sign |
| SLH-DSA | - | SigVer+Gen | - | Yes | FIPS 205; invalid sig rejection tested (v3.2) |

## Testing Patterns

- **Mechanism availability**: All tests query `slot.get_mechanisms()` before attempting operations. Unsupported mechanisms skip cleanly with descriptive message.
- **Version gating**: `@pytest.mark.requires_v30` skips on v2.40 modules. PQC tests require v3.2.
- **Limit probing**: `test_surface_audit.py` intentionally tests beyond advertised key size limits to find undocumented capabilities.
- **Compliance notes**: Tests log findings via `pkcs11-check.compliance.note()` when modules accept non-standard operations.
- **Cross-module xfail**: AES-KWP uses xfail when wrap output differs across modules (OpenCryptoki vs SoftHSM2).

## Module Compatibility

Tests auto-skip for unsupported mechanisms. Tested against:
- SoftHSM2 2.7.0 (v2.40, primary reference)
- Kryoptic 1.5.0 (v3.2, Rust)
- OpenCryptoki 3.25.0 (v3.0, IBM)
- NSS, tpm2-pkcs11, BouncyHSM (Docker matrix)
