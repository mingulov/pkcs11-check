# pkcs11-check — Test Coverage Summary

Run `pytest --co -q` for current counts. Tests auto-skip for unsupported mechanisms.

## Test Categories

### Wycheproof Edge-Case Vectors (15 files)

All Wycheproof tests check mechanism availability at runtime and skip cleanly.

| File | Algorithms |
|------|------------|
| test_wycheproof.py | AES-GCM, AES-CBC-PKCS5, HMAC-SHA256, ECDSA P-256/384 |
| test_wycheproof_aes.py | AES-CMAC, Key Wrap, KWP, CCM, GMAC, XTS |
| test_wycheproof_chacha.py | ChaCha20-Poly1305 AEAD |
| test_wycheproof_dsa.py | DSA 2048/3072 × SHA-224/256 |
| test_wycheproof_ecdh.py | ECDH P-224/256/384/521 key agreement |
| test_wycheproof_ecdsa.py | ECDSA P-224/256/384/521 × SHA-224/256/384/512 + SHA-3 |
| test_wycheproof_ed25519.py | Ed25519 + Ed448 signature verification |
| test_wycheproof_hkdf.py | HKDF SHA-1/256/384/512 |
| test_wycheproof_hmac.py | HMAC SHA/SHA-3/SHA-512 truncated |
| test_wycheproof_rsa.py | RSA PKCS#1 v1.5 sigs: 2048-8192 × SHA/SHA-3 |
| test_wycheproof_rsa_decrypt.py | RSA PKCS#1 v1.5 decryption (padding oracle vectors) |
| test_wycheproof_rsa_oaep.py | RSA-OAEP: same and mixed hash/MGF combinations |
| test_wycheproof_rsa_pss.py | RSA-PSS with proper CK_RSA_PKCS_PSS_PARAMS |
| test_wycheproof_x25519.py | X25519 + X448 Montgomery curve key exchange |

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

### Known-Answer Tests (2 files)

- **test_kat.py** — SHA-1/224/256/384/512 from NIST vectors, AES-ECB from SP 800-38A
- **test_sha3.py** — SHA3-224/256/384/512 cross-verify against hashlib

### Cryptographic Property Tests (6 files)

- **test_digest.py** — Hash length, determinism, cross-verify all SHA against hashlib, 1 MiB data
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

### Standards & Interface (5 files)

- **test_interface.py** — PKCS#11 interface detection, version negotiation
- **test_slot.py** — Slot info, token info, mechanism list
- **test_mechanism.py** — Mechanism flags, info, capabilities
- **test_init.py** — Module load/init, session open/close
- **test_token_flags.py** — Token flags, RW/RO session, login state

### Data Handling (3 files)

- **test_buffers.py** — Block boundaries, multi-block, empty input, large data
- **test_multipart.py** — Multi-part encrypt/decrypt/digest operations
- **test_object.py** — Object create, search, attributes, destroy, key import/export

### Stress & Performance (3 files)

- **test_stress.py** — 1000-cycle operations, multi-session, resource cleanup
- **test_resource.py** — Handle leaks, session limits, parallel sessions
- **test_benchmark.py** — AES-CBC/ECB, RSA sign/verify, ECDSA, SHA-256, RNG, keygen

### Advanced Testing (3 files)

- **test_metamorphic.py** — Metamorphic relation tests (encrypt/decrypt invariants)
- **test_search.py** — Object search, enumeration, attribute-based filtering

## Mechanism Coverage

| Mechanism | Wycheproof | Cross-verify | Property | Notes |
|-----------|:---:|:---:|:---:|-------|
| AES-ECB | - | Yes | Yes | KAT + cross-verify |
| AES-CBC | Yes | Yes | Yes | PKCS5 padding |
| AES-GCM | Yes | Yes | Yes | IV sizes, AAD |
| AES-CCM | Yes | - | - | Skips if unsupported |
| AES-CMAC | Yes | - | - | Tag truncation |
| AES-GMAC | Yes | - | - | Authentication-only GCM |
| AES-KW | Yes | - | - | RFC 3394 |
| AES-KWP | Yes | - | - | RFC 5649 |
| AES-XTS | Yes | - | - | Disk encryption mode |
| RSA PKCS#1 v1.5 sign | Yes | Yes | Yes | 2048-8192, SHA + SHA-3 |
| RSA PKCS#1 v1.5 decrypt | Yes | - | - | Padding oracle vectors |
| RSA-PSS | Yes | Yes | Yes | Proper PSS params, misc salt lengths |
| RSA-OAEP | Yes | Yes | Yes | Mixed hash/MGF |
| ECDSA P-224/256/384/521 | Yes | Yes | Yes | SHA + SHA-3 multi-hash |
| ECDH P-224/256/384/521 | Yes | - | Yes | Shared secret agreement |
| X25519 / X448 | Yes | - | - | Montgomery curve ECDH |
| Ed25519 | Yes | Yes | Yes | Deterministic sigs |
| Ed448 | Yes | - | - | Skips if unsupported |
| DSA 2048/3072 | Yes | - | Yes | SHA-224/256 |
| HMAC SHA family | Yes | Yes | Yes | SHA, SHA-3, SHA-512 truncated |
| ChaCha20-Poly1305 | Yes | - | - | Native CK params |
| HKDF | Yes | - | - | Skips if unsupported |
| SHA-1/224/256/384/512 | - | Yes | Yes | KAT + hashlib cross-verify |
| ML-KEM | - | - | Yes | v3.2 encapsulate/decapsulate |
| ML-DSA | - | - | Yes | v3.2 sign/verify |
| SLH-DSA | - | - | Yes | v3.2 sign/verify |

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
