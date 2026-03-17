# p11test — Test Coverage Summary

18,023 tests collected | 16,114 passing on SoftHSM2 | 48 test files

## Test Categories

### Wycheproof Edge-Case Vectors (14 files, ~17,000 parametrized tests)

| File | Vectors | Algorithms |
|------|---------|------------|
| test_wycheproof.py | 1,949 | AES-GCM, AES-CBC-PKCS5, HMAC-SHA256, ECDSA P-256/384 |
| test_wycheproof_aes.py | 1,282 | AES-CMAC (311), Key Wrap (165), KWP (254), CCM (552) |
| test_wycheproof_chacha.py | 325 | ChaCha20-Poly1305 AEAD |
| test_wycheproof_dsa.py | 1,432 | DSA 2048/3072 with SHA-224/256 |
| test_wycheproof_ecdh.py | 2,264 | ECDH P-224/256/384/521 key agreement |
| test_wycheproof_ecdsa.py | 3,579 | ECDSA P-224/256/384/521 × SHA-224/256/384/512 |
| test_wycheproof_ed25519.py | 150 | Ed25519 signature verification |
| test_wycheproof_hkdf.py | 339 | HKDF SHA-1/256/384/512 |
| test_wycheproof_hmac.py | 1,038 | HMAC SHA-1/224/384/512, SHA-512/224, SHA-512/256 |
| test_wycheproof_rsa.py | 3,364 | RSA PKCS#1 v1.5 sigs: 2048/3072/4096/8192 × SHA-224/256/384/512 |
| test_wycheproof_rsa_decrypt.py | 201 | RSA PKCS#1 v1.5 decryption (padding oracle vectors) |
| test_wycheproof_rsa_oaep.py | 568 | RSA-OAEP: same and mixed hash/MGF combinations |
| test_wycheproof_rsa_pss.py | 1,153 | RSA-PSS with proper CK_RSA_PKCS_PSS_PARAMS |

### Cross-Verification (4 files)

Verify PKCS#11 output against Python `cryptography` library.

- **test_crossverify.py** (21) — AES-ECB/CBC, RSA 2048/3072/4096 × SHA-1/224/256/384/512, ECDSA P-256/384, HMAC
- **test_interop.py** (11) — RSA sign→crypto verify, RSA-PSS, ECDSA multi-curve, AES-GCM, HMAC-SHA256/SHA1
- **test_aead.py** (7) — AES-GCM cross-verify, tamper detection, AAD integrity
- **test_ec_curves.py** (2) — P-256/384/521 keygen + ECDSA cross-verify

### Known-Answer Tests (2 files)

- **test_kat.py** (7) — SHA-1/224/256/384/512 from NIST vectors, AES-ECB from SP 800-38A
- **test_sha3.py** (3) — SHA3-224/256/384/512 cross-verify against hashlib (skips if unsupported)

### Cryptographic Property Tests (5 files)

- **test_digest.py** (8) — Hash length, determinism, cross-verify all SHA against hashlib, 1 MiB data
- **test_encrypt.py** (12) — AES roundtrip (ECB/CBC), key sizes, ciphertext properties, RSA PKCS/OAEP
- **test_sign.py** (14) — RSA multi-hash, RSA-PSS, ECDSA multi-curve, determinism, HMAC, DSA
- **test_eddsa.py** (10) — Ed25519 keygen, sign/verify, determinism, cross-verify with cryptography
- **test_rsa_oaep.py** (3) — RSA-OAEP roundtrip and cross-verify

### Key Management (3 files)

- **test_keymgmt.py** (10) — Import, export, copy, wrap/unwrap, label management
- **test_kdf.py** (8) — HMAC-KDF cross-verify, HKDF basic, ECDH shared-secret agreement
- **test_key_sizes.py** (6) — AES 128/192/256, RSA 2048/4096, EC P-256/384/521 keygen

### Security & Robustness (5 files)

- **test_errors.py** (17) — Invalid operations, wrong mechanism, decrypt garbage, key lifecycle, use-after-destroy
- **test_api_security.py** (12) — Session enforcement, attribute protection, key isolation
- **test_padding_oracle.py** (4) — CBC padding oracle, timing analysis
- **test_nonce_quality.py** (4) — ECDSA nonce reuse, bias detection
- **test_surface_audit.py** (18) — Hidden mechanisms, deprecated detection, mechanism limit probing (oversize/undersize keys)

### Standards & Interface (5 files)

- **test_interface.py** (5) — PKCS#11 interface detection, version negotiation
- **test_slot.py** (6) — Slot info, token info, mechanism list
- **test_mechanism.py** (8) — Mechanism flags, info, capabilities
- **test_init.py** (9) — Module load/init, session open/close
- **test_token_flags.py** (11) — Token flags, RW/RO session, login state

### Data Handling (3 files)

- **test_buffers.py** (21) — Block boundaries, multi-block, empty input, large data
- **test_multipart.py** (9) — Multi-part encrypt/decrypt/digest operations
- **test_object.py** (7) — Object create, search, attributes, destroy

### Stress & Performance (3 files)

- **test_stress.py** (8) — 1000-cycle operations, multi-session, resource cleanup
- **test_resource.py** (9) — Handle leaks, session limits, parallel sessions
- **test_benchmark.py** (8) — AES-CBC/ECB, RSA sign/verify, ECDSA, SHA-256, RNG, keygen

### Advanced Testing (3 files)

- **test_metamorphic.py** (13) — Metamorphic relation tests (encrypt/decrypt invariants)
- **test_fuzz.py** (5) — Hypothesis property tests: AES roundtrip, SHA-256, RSA sign/verify
- **test_search.py** (9) — Object search, enumeration, attribute-based filtering

## Mechanism Coverage

| Mechanism | Wycheproof | Cross-verify | Property | Notes |
|-----------|:---:|:---:|:---:|-------|
| AES-ECB | - | Yes | Yes | KAT + cross-verify |
| AES-CBC | 216 | Yes | Yes | PKCS5 padding |
| AES-GCM | 316 | Yes | Yes | IV sizes, AAD |
| AES-CCM | 552 | - | - | Skips if unsupported |
| AES-CMAC | 311 | - | - | Tag truncation |
| AES-KW | 165 | - | - | RFC 3394 |
| AES-KWP | 254 | - | - | RFC 5649 |
| RSA PKCS#1 v1.5 sign | 3,364 | Yes | Yes | 2048-8192 bits |
| RSA PKCS#1 v1.5 decrypt | 201 | - | - | Padding oracle vectors |
| RSA-PSS | 1,153 | Yes | Yes | Proper PSS params |
| RSA-OAEP | 568 | Yes | Yes | Mixed hash/MGF |
| ECDSA P-224/256/384/521 | 3,579 | Yes | Yes | Multi-hash |
| ECDH P-224/256/384/521 | 2,264 | - | Yes | Shared secret agreement |
| Ed25519 | 150 | Yes | Yes | Deterministic sigs |
| DSA | 1,432 | - | Yes | 2048/3072 |
| HMAC SHA-1/224/256/384/512 | 1,038 | Yes | Yes | Short key detection |
| ChaCha20-Poly1305 | 325 | - | - | Native params |
| HKDF | 339 | - | - | Skips if unsupported |
| SHA-1/224/256/384/512 | - | Yes | Yes | KAT + hashlib cross-verify |

## Module Compatibility

Tests auto-skip for unsupported mechanisms. Tested against:
- SoftHSM2 2.7.0 (primary, ~16K passing)
- Kryoptic, NSS, OpenCryptoki, tpm2-pkcs11, BouncyHSM (Docker matrix)
