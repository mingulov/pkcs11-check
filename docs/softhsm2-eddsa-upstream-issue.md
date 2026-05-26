# SoftHSM2 EdDSA CKA_EC_POINT issue draft

Date: 2026-05-26

Status: concise upstream issue draft. This is the short file to review before
filing a SoftHSM2 report. Longer local notes are in:

- `docs/softhsm2-eddsa-public-key-encoding.md`
- `docs/softhsm2-eddsa-upstream-report.md`

## Suggested title

Ed25519 verification requires DER-wrapped `CKA_EC_POINT`, but PKCS#11 Edwards
public keys use raw RFC 8032 bytes

## Summary

`pkcs11-check` found that SoftHSM2 2.7.0 verifies an RFC 8032 Ed25519 test
vector only when the `CKK_EC_EDWARDS` public key object uses a DER OCTET STRING
wrapper in `CKA_EC_POINT`.

The local OASIS PKCS#11 spec checkout says Edwards public-key objects use:

- `CKA_KEY_TYPE = CKK_EC_EDWARDS`
- `CKA_EC_PARAMS` as DER-encoded parameters
- `CKA_EC_POINT` as public-key bytes in little-endian order as defined in
  RFC 8032

That differs from classic Weierstrass `CKK_EC` public keys, where the point is
an encoded ANSI X9.62 EC point.

## Environment

- Provider tested: SoftHSM2 2.7.0
- pkcs11-check Docker target: `test-softhsm2`
- Docker config: `docker/docker-compose.test.yml`
- Focused artifact:
  `artifacts/_focused/softhsm2-eddsa-encoding-current-20260526/`
- Focused test:
  `src/pkcs11_check/testcases/test_eddsa_public_key_encoding.py`

Runtime evidence here is from SoftHSM2 2.7.0. Source inspection also found the
same relevant EdDSA public-key storage pattern in the current SoftHSM2 branch
checked locally, but a focused `test-softhsm2-main` runtime rerun should be used
before claiming that `main` currently reproduces it.

## Reproducer

Run the focused pkcs11-check probe:

```bash
bash docker/test.sh softhsm2 -- src/pkcs11_check/testcases/test_eddsa_public_key_encoding.py
```

The probe creates an Ed25519 public-key object and verifies a known-good
RFC 8032 signature. It tries both provider-visible encodings:

1. raw RFC 8032 public-key bytes in `CKA_EC_POINT`
2. DER OCTET STRING wrapped public-key bytes in `CKA_EC_POINT`

Observed with SoftHSM2 2.7.0:

- raw `CKA_EC_POINT`: does not produce a working verification profile
- DER-wrapped `CKA_EC_POINT`: verification succeeds

The focused pkcs11-check result is therefore marked as an expected failure with
this reason:

```text
EdDSA verifies only with DER-wrapped CKA_EC_POINT; PKCS#11 requires raw RFC 8032 public-key bytes for CKK_EC_EDWARDS
```

## Minimal vector

The focused test uses RFC 8032 Section 7.1, Ed25519 test 1.

```text
CKA_EC_PARAMS:
06032b6570

raw CKA_EC_POINT:
d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a

DER-wrapped CKA_EC_POINT that works in SoftHSM2:
0420d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a

message:
<empty>

signature:
e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
```

`04 20` is a DER OCTET STRING wrapper around the same 32-byte Ed25519 public
key. The raw 32-byte form is the PKCS#11 Edwards public-key form.

## Expected behavior

SoftHSM2 should accept raw RFC 8032 public-key bytes for `CKK_EC_EDWARDS`
`CKA_EC_POINT`.

For compatibility, accepting the DER-wrapped form as an additional input form
may be useful, but it should not be the only form that can verify.

## Likely implementation cause

The SoftHSM2 EdDSA public-key code appears to store the public-key component
internally as a DER OCTET STRING:

- `src/lib/crypto/OSSLEDPublicKey.cpp`
  - `setFromOSSL()` stores extracted raw Ed25519/Ed448 public-key bytes with
    `DERUTIL::raw2Octet(raw)`.
  - `createOSSLKey()` later reads the field with `DERUTIL::octet2Raw(a)`.
- `src/lib/crypto/BotanEDPublicKey.cpp` follows the same storage pattern.
- `src/lib/SoftHSM.cpp`
  - generated EdDSA public keys expose `pub->getA()` as `CKA_EC_POINT`;
    because that value is already DER-wrapped, generated keys expose the
    wrapper.
  - imported EdDSA public keys pass user-supplied `CKA_EC_POINT` directly to
    `publicKey->setA(value)`.

That matches the runtime behavior: the DER-wrapped value fits SoftHSM2's
internal representation, while the raw PKCS#11 Edwards value does not.

## Suggested issue body

SoftHSM2 2.7.0 appears to require a DER OCTET STRING wrapper for
`CKA_EC_POINT` when creating/importing `CKK_EC_EDWARDS` Ed25519 public keys.
PKCS#11 Edwards public-key objects specify `CKA_EC_POINT` as the raw RFC 8032
public-key bytes.

With the RFC 8032 Ed25519 test vector shown above, verification succeeds only
when the public key is supplied as:

```text
0420d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
```

The raw PKCS#11 Edwards value does not produce a working verification profile:

```text
d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
```

Expected result: raw RFC 8032 public-key bytes should be accepted for
`CKK_EC_EDWARDS` `CKA_EC_POINT`. Accepting the DER-wrapped form as compatibility
behavior is fine, but it should not be required.

## Separate finding

The broader EdDSA-focused run also found ACVP KeyVer cases where invalid
Ed25519/Ed448 public keys were accepted as usable. That should be reviewed and
reported separately. It is not the same issue as the `CKA_EC_POINT` encoding
behavior described here.
