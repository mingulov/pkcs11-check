# p11test — Test Coverage Summary

Run `pytest --co -q` for current counts. Tests auto-skip for unsupported mechanisms.

## Test Categories

### Wycheproof Edge-Case Vectors (15 files)

All Wycheproof tests check mechanism availability at runtime and skip cleanly.

| File | Algorithms |
|------|------------|
| test_wycheproof.py | AES-GCM, AES-CBC-PKCS5, HMAC-SHA256, ECDSA P-256/384 |
| test_wycheproof_aes.py | AES-CMAC, Key Wrap, KWP, CCM, GMAC |
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
| AES-CBC | Yes | Yes | Yes | PKCS5 padding |
| AES-GCM | Yes | Yes | Yes | IV sizes, AAD |
| AES-CCM | Yes | - | - | Skips if unsupported |
| AES-CMAC | Yes | - | - | Tag truncation |
| AES-GMAC | Yes | - | - | Authentication-only GCM |
| AES-KW | Yes | - | - | RFC 3394 |
| AES-KWP | Yes | - | - | RFC 5649 |
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

## Testing Patterns

- **Mechanism availability**: All tests query `slot.get_mechanisms()` before attempting operations. Unsupported mechanisms skip cleanly with descriptive message.
- **Limit probing**: `test_surface_audit.py` intentionally tests beyond advertised key size limits to find undocumented capabilities.
- **Compliance notes**: Tests log findings via `p11test.compliance.note()` when modules accept non-standard operations.

## Module Compatibility

Tests auto-skip for unsupported mechanisms. Tested against:
- SoftHSM2 2.7.0 (primary)
- Kryoptic, NSS, OpenCryptoki, tpm2-pkcs11, BouncyHSM (Docker matrix)
