# NSS-PQC (softoken): test findings from pkcs11-check

**Date:** 2026-03-23
**Module:** NSS softoken (Fedora Rawhide, v3.2 PQC build)
**Test tool:** pkcs11-check (dev branch)
**Total tests:** 72,646
**Results:** 36,478 passed, 440 failed, 35,354 skipped, 372 xfailed, 2 errors

## Errors (2)

Both in `test_ssl3.py` - pkcs11-check bug (concatenated bytes instead of
tuple for SSL3 mechanism params). Already fixed.

## Bugs

### DSA signature verification failures (296)

`test_wycheproof_dsa.py`: 296 valid DSA signatures rejected by NSS.
All are "valid" Wycheproof vectors that NSS fails to verify. This
suggests NSS softoken has a DSA verification bug with certain
parameter/signature combinations.

Vector files affected: `dsa_2048_224_sha224`, `dsa_2048_256_sha256`,
`dsa_3072_256_sha256`, and others. These are standard DSA parameter
sizes - not edge cases.

### ML-KEM BufferTooSmall (10)

`test_kem.py`: All ML-KEM (Kyber) operations return
`CKR_BUFFER_TOO_SMALL`. NSS PQC build advertises ML-KEM mechanisms
but the encapsulate/decapsulate operations fail. This is likely a
buffer size calculation issue in NSS's ML-KEM implementation -
the output buffer for the ciphertext or shared secret is too small.

### AES-GCM BufferTooSmall (4)

`test_aead.py`: AES-GCM encrypt returns `CKR_BUFFER_TOO_SMALL`.
NSS softoken may require a larger output buffer than the plaintext
size (for the GCM tag). The tests may need to allocate
`plaintext_len + 16` bytes for the tag.

### EdDSA ArgumentsBad (7)

`test_eddsa.py`: All EdDSA sign/verify operations return
`CKR_ARGUMENTS_BAD`. NSS softoken may require specific mechanism
parameters for EdDSA (e.g. Ed25519ctx vs Ed25519ph) that the test
does not provide.

### Object copy not supported (5)

`test_access_control.py`: `C_CopyObject` returns
`CKR_ATTRIBUTE_TYPE_INVALID`. NSS softoken does not support object
copy with `CKA_COPYABLE` attribute.

### Token write-protected (15)

`test_object_visibility.py`: NSS returns `CKR_TOKEN_WRITE_PROTECTED`
for token objects. The test may be running on a read-only NSS database
or the slot 0 (crypto services) which does not support persistent
storage. NSS uses slot 1 (certificate DB) for token objects.

### TLS 1.2 mechanism issues (17)

`test_tls12.py`:
- `ObjectHandleInvalid` on key-and-mac derive (output handle issue)
- `TypeError`/`ValueError` on extended master key derive (python-pkcs11
  param handling issue with the 3-element tuple format)

### pkcs11-check test issues (29 assertions)

Various assertion failures from tests that make assumptions about
attribute defaults or behavior that NSS implements differently.
Not NSS bugs.

## Summary

The most significant findings are:
1. **DSA verification bug** (296 valid signatures rejected) - most impactful
2. **ML-KEM buffer issue** (PQC not functional) - important for PQC adoption
3. **AES-GCM buffer calculation** - may be a test issue (tag size)
4. **EdDSA params required** - may need mechanism-specific parameters
