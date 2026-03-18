# Module Issues

Known issues, quirks, and compliance deviations per PKCS#11 module.
Updated as Docker targets are analyzed.

---

## SoftHSM2 2.7.0 (v2.40)

**Status: 22,622 passed, 0 failed, 6,287 skipped, 658 xfailed**

### xfail breakdown (658 total)
| Count | File | Reason |
|-------|------|--------|
| 624 | test_wycheproof_rsa_oaep.py | RSA-OAEP with non-SHA1 hash/MGF — SoftHSM2 only supports SHA-1 for OAEP |
| 24 | test_wycheproof_hmac.py | HMAC truncated output variants not supported |
| 9 | test_wycheproof.py | AES-GCM edge cases (SoftHSM2 2.6.1 has no GCM; 2.7.0 has it but some edge cases fail) |
| 1 | test_wycheproof_ecdh.py | ECDH with invalid curve point handling |

### Known quirks
- `C_GetObjectSize` returns `CK_UNAVAILABLE_INFORMATION` (not implemented)
- `C_SeedRandom` succeeds silently (no-op, RNG is OpenSSL-based)
- v2.40 only — no `C_GetInterface`, no v3.0+ mechanisms
- Session objects visible across concurrent sessions (spec says they shouldn't be)

---

## Kryoptic 1.5.0 (v3.2)

**Status: 21,503 passed, 0 failed, 7,687 skipped, 377 xfailed**

### xfail breakdown
- Primarily RSA-OAEP with non-SHA1 hash/MGF and AES edge cases
- DH parameter generation not supported (skips, not xfails)

### Known bugs
- **CKR_DEVICE_ERROR on verify failure**: `C_Verify` returns `CKR_DEVICE_ERROR` (0x30) instead of `CKR_SIGNATURE_INVALID` (0xC0) when signature verification fails. Affects ALL mechanisms (RSA, ECDSA, ML-DSA, SLH-DSA). SoftHSM2 correctly returns `CKR_SIGNATURE_INVALID`. This is a Kryoptic bug — PKCS#11 spec requires `CKR_SIGNATURE_INVALID`.

### Known quirks
- v3.2 interface — supports `C_GetInterface`, PQC mechanisms
- `C_GetObjectSize` works correctly
- No P-224 EC curve support
- AES-GCM parameter format differs from some other modules

---

## NSS 3.120.1 (v3.0)

**Status: 20,723 passed, 362 failed, 8,147 skipped, 335 xfailed**

### Failure breakdown (362 total)
| Count | Area | Reason |
|-------|------|--------|
| 296 | DSA Wycheproof | NSS DSA implementation rejects valid 3072-bit DSA vectors — likely NSS strictness on parameter validation |
| ~16 | Session/access tests | NSS returns `CKR_USER_TYPE_INVALID` instead of `CKR_USER_ALREADY_LOGGED_IN` — PKCS#11 spec compliance deviation |
| ~16 | KEM/PQC | ML-KEM not supported in NSS 3.120.1 (expected skips, showing as errors) |
| ~7 | EdDSA | Ed25519 signing failures — needs investigation |
| ~27 | Other | AEAD, key flags, mechanism fuzz, etc. — per-file analysis needed (task 2.3) |

### Known quirks
- **Read-only crypto services token**: NSS's default slot ("NSS Generic Crypto Services") is read-only. Cannot create objects, generate keys, or store tokens. Tests requiring RW access should skip.
- **No PIN/login on crypto services slot**: The default slot does not support `C_Login` — returns `CKR_USER_TYPE_INVALID` when login is attempted. This is correct behavior for a public token that doesn't have login semantics.
- **Two slots**: NSS exposes 2 slots. Slot 0 is the crypto services slot (read-only), slot 1 may be an NSS internal database slot.
- **Needs configDir for full functionality**: `libsoftokn3.so` must be loaded with `configDir='sql:/path/to/db'` NSS init args to access the writable database slot. Without this, only the read-only crypto services slot is available. See `/home/user/src/m/pkcs11-proxy/pkcs11-proxy/scripts/test-nss-fixtures.sh` for reference configuration.

---

## OpenCryptoki 3.25 (v3.0)

**Status: 468 passed, 24 failed, 312 skipped, 1 xfailed, 28,762 errors**

### Root cause of 28K errors
`pkcsslotd` daemon dies during the full test run, causing `FunctionFailed` for all subsequent tests. When run individually with the daemon alive, tests pass. This is a daemon stability issue under sustained load — needs investigation in task 2.4.

### Known quirks
- Requires `pkcsslotd` daemon running
- Software token (`swtok`) only
- `C_SeedRandom` not supported (`RandomSeedNotSupported`)
