# tpm2-pkcs11: test findings from pkcs11-check

**Date:** 2026-03-23
**Module:** tpm2-pkcs11 1.9.1 with swtpm + tpm2-abrmd (Fedora 44)
**Test tool:** pkcs11-check (dev branch)
**Total tests:** 72,646
**Results:** 6,136 passed, 815 failed, 64,541 skipped, 1,132 xfailed, 22 errors

## Overview

tpm2-pkcs11 has the highest skip rate (89%) due to limited mechanism support -
TPMs support RSA, EC, SHA digests, and limited symmetric operations. AES key
generation, import, most symmetric ciphers, and many PKCS#11 operations are
not available through the TPM2 PKCS#11 interface.

## Errors (22) - pkcs11-check test issues, not TPM2 bugs

- 19 in `test_attribute_defaults.py`: AES keygen with minimal template returns
  `FunctionNotSupported` - TPM2 does not support AES key generation
- 3 in `test_benchmark.py`: RSA/EC keypair generation returns
  `AttributeValueInvalid` - TPM2 requires specific template attributes

Fixed in pkcs11-check by adding `has_mechanism()` checks and try/except
fallback in test fixtures.

## Failures (815)

### CKR_GENERAL_ERROR on advertised mechanisms (37 non-Wycheproof)

tpm2-pkcs11 advertises AES-ECB, AES-CBC, AES-GCM, and HMAC mechanisms but
returns `CKR_GENERAL_ERROR` when they are actually used. This is a spec
compliance issue - the module should either not advertise mechanisms it
cannot perform, or return `CKR_MECHANISM_INVALID` instead of the generic error.

Affected operations:
- AES-ECB encrypt/decrypt (cross-verify, KAT tests)
- AES-CBC encrypt/decrypt
- AES-GCM encrypt/decrypt
- HMAC-SHA256, HMAC-SHA1 (with imported generic secret keys)
- AES-GCM cross-verify
- Key derivation (HKDF, generic extract)
- Multipart streaming operations

Root cause: tpm2-pkcs11 wraps TPM2 commands via the TSS layer. The TPM
hardware supports these algorithms internally, but the PKCS#11 wrapper
does not implement the full key import + operation path for symmetric
keys created via `C_CreateObject`. Keys must be generated on the TPM
itself via `C_GenerateKey` (which is not supported for AES either).

### CKR_GENERAL_ERROR in Wycheproof (296)

ECDSA and HMAC Wycheproof vectors fail with `CKR_GENERAL_ERROR`. Same
root cause as above for HMAC vectors. ECDSA failures may be due to
edge-case signatures that the TPM hardware rejects differently than
software implementations.

### AttributeValueInvalid (160)

TPM2 requires specific template attributes that software HSMs do not:
- `CKA_SENSITIVE=True` (TPM keys are always sensitive)
- `CKA_TOKEN=True` (session-only keys not well supported)
- Specific key sizes only (RSA-2048, RSA-3072, RSA-4096)
- No key import for asymmetric keys (must be generated on TPM)

This is expected TPM2 behavior, not a bug. Tests using minimal templates
designed for software HSMs naturally fail here.

### FunctionNotSupported (300+)

Many PKCS#11 functions are not implemented in tpm2-pkcs11:
- `C_CreateObject` for secret keys and asymmetric keys
- `C_WrapKey` / `C_UnwrapKey`
- `C_DeriveKey` for most KDF mechanisms
- Dual-function operations
- Operation state save/restore

### Subprocess crashes in CKR tests (8)

Several CKR tests that use subprocess (`RawPKCS11`) crash with FAPI
provisioning warnings. The tpm2-pkcs11 module emits
`"fapi:Provisioning was not executed."` warnings that interfere with
subprocess error detection. Not actual TPM2 crashes - the module
returns errors but the subprocess test infrastructure misinterprets
the stderr output.

### Session and access issues (5)

- `UserNotLoggedIn` for operations that should not require login
  (digests should work without login per PKCS#11 spec)
- `SessionReadOnly` when creating session objects on RO sessions
  (spec allows session objects on RO sessions)

These may be genuine tpm2-pkcs11 spec compliance issues.

## Recommendations

1. **Report upstream**: The `CKR_GENERAL_ERROR` for AES/HMAC operations
   on advertised mechanisms - either remove from mechanism list or
   return `CKR_MECHANISM_INVALID`
2. **Report upstream**: Digest operations requiring login (`UserNotLoggedIn`)
3. **Report upstream**: RO session rejecting session objects (`SessionReadOnly`)
4. **pkcs11-check improvement**: Add TPM2-specific expected behavior
   documentation to `docs/module-issues.md`
