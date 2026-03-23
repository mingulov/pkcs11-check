# SoftHSM2: C_SignInit/C_VerifyInit crash with mismatched key type

**Date:** 2026-03-23
**Module:** SoftHSM2 main branch (all OpenSSL versions)
**Fix:** `docker/softhsm2/patches/0001-fix-sign-verify-key-type-crash.patch`
**SoftHSM2 branch:** `fix/sign-init-key-type-crash` in `/home/user/src/m/pkcs11-check-ws/SoftHSMv2/`

## Summary

`C_SignInit` and `C_VerifyInit` in SoftHSM2 do not validate that the key type matches the requested mechanism. Passing an EC key with an RSA mechanism (e.g. `CKM_RSA_X_509`) causes `C_SignInit` to return `CKR_OK`, then the subsequent `C_Sign` crashes (segfault/abort) because OpenSSL receives empty/invalid RSA key material extracted from an EC key object.

## Key findings during investigation

### AES key does NOT reproduce the crash

Using an AES (secret) key with RSA mechanisms does NOT reach the vulnerable code path:
- `isMechanismPermitted()` rejects it with `CKR_MECHANISM_INVALID`
- Secret keys have a restricted mechanism list that excludes asymmetric mechanisms
- The bug was initially misidentified as "AES key + RSA mechanism"

### EC key DOES reproduce the crash

Using an EC (asymmetric) key with RSA mechanisms DOES reach the crash:
- `isMechanismPermitted()` allows it because asymmetric keys have empty `CKA_ALLOWED_MECHANISMS` (= allow all)
- `CKA_SIGN=True` check passes (EC private keys have sign capability)
- The mechanism switch sets `isRSA=true` and proceeds to `getRSAPrivateKey()`
- `getRSAPrivateKey()` reads `CKA_MODULUS`, `CKA_PRIVATE_EXPONENT` etc. from the EC key - all empty
- Empty key material is passed to OpenSSL, which crashes

### Crash behavior varies by OpenSSL version and mechanism

| Mechanism | OpenSSL 3.0 | OpenSSL 3.5+ |
|---|---|---|
| `CKM_RSA_X_509` + C_Sign | **CRASH** (abort) | **CRASH** (segfault) |
| `CKM_SHA256_RSA_PKCS` + C_Sign | `CKR_GENERAL_ERROR` | **CRASH** (segfault) |
| `CKM_RSA_PKCS` + C_Sign | `CKR_GENERAL_ERROR` | **CRASH** (segfault) |

`CKM_RSA_X_509` (raw RSA without padding) crashes on all OpenSSL versions because it directly uses the empty modulus without any intermediate checks.

### The fix

Added key type validation after the mechanism switch in both `AsymSignInit` and `AsymVerifyInit`:

```c
if (isRSA && keyType != CKK_RSA)
    return CKR_KEY_TYPE_INCONSISTENT;
if (isDSA && keyType != CKK_DSA)
    return CKR_KEY_TYPE_INCONSISTENT;
// ... etc for ECDSA, EdDSA, GOST
```

This returns `CKR_KEY_TYPE_INCONSISTENT` per PKCS#11 v3.1 Sec.5.10.1/5.11.1 before any key material extraction occurs.

`AsymEncryptInit` and `AsymDecryptInit` already had per-case key type checks (only 3 RSA mechanisms each). The GOST catch-all `else` branch was also converted to an explicit `else if (isGOST)` with a proper `else { return CKR_MECHANISM_INVALID; }` fallback.

### Regression tests

Tests use cross-matched asymmetric keys to bypass `isMechanismPermitted`:
- EC private key with RSA mechanisms (RSA_PKCS, RSA_X_509, SHA*_RSA_PKCS)
- EC private key with DSA mechanisms
- RSA private key with ECDSA mechanisms
- RSA private key with EdDSA mechanism

Without the fix, `C_SignInit` returns `CKR_OK` for all of these (the bug). With the fix, it returns `CKR_KEY_TYPE_INCONSISTENT`.
