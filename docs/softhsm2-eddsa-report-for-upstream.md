# SoftHSM2 EdDSA public-key encoding report

Date: 2026-05-26

Status: draft for review before filing upstream. Runtime evidence below is from
the `pkcs11-check` SoftHSM2 2.7.0 Docker target. The current SoftHSM2 `main`
source still appears to have the same relevant public-key storage pattern, but
`main` should be rerun before claiming a current-branch runtime result.

## Suggested title

Ed25519 verification requires DER-wrapped `CKA_EC_POINT`, but PKCS#11
`CKK_EC_EDWARDS` public keys use raw RFC 8032 bytes

## Summary

`pkcs11-check` found that SoftHSM2 2.7.0 verifies an RFC 8032 Ed25519 test
vector only when the `CKK_EC_EDWARDS` public key object stores
`CKA_EC_POINT` as a DER OCTET STRING wrapper around the public key.

For PKCS#11 Edwards public keys, the local OASIS PKCS#11 spec checkout says
`CKA_EC_POINT` is the public-key bytes in little-endian order as defined in
RFC 8032. That is different from classic Weierstrass `CKK_EC` keys, where
`CKA_EC_POINT` is a DER-encoded ANSI X9.62 EC point.

Observed SoftHSM2 behavior:

- raw RFC 8032 Ed25519 public key in `CKA_EC_POINT`: `C_CreateObject` and
  `C_VerifyInit` return `CKR_OK`, but `C_Verify` returns
  `CKR_SIGNATURE_INVALID` for the known-good RFC 8032 signature
- DER OCTET STRING-wrapped public key in `CKA_EC_POINT`: `C_CreateObject`,
  `C_VerifyInit`, and `C_Verify` all return `CKR_OK`

Expected behavior:

- raw RFC 8032 public-key bytes should work for `CKK_EC_EDWARDS`
  `CKA_EC_POINT`
- accepting the DER-wrapped form as compatibility behavior would be fine, but
  it should not be required

## Environment

- Provider tested: SoftHSM2 2.7.0
- SoftHSM2 tag: `13e6e86b83748fef74046dbf0c91f664b7acc1c3`
- `pkcs11-check` Docker target: `test-softhsm2`
- Docker config: `docker/docker-compose.test.yml`
- OpenSSL in that target: `3.6.2`
- Focused artifact:
  `artifacts/_focused/softhsm2-eddsa-encoding-current-20260526/`
- Focused test:
  `src/pkcs11_check/testcases/test_eddsa_public_key_encoding.py`
- Current SoftHSM2 `main` ref checked with `git ls-remote`:
  `679f33d1b325cca8f5eb1a8febcc7630654a34de`
- Local PKCS#11 spec checkout revision:
  `48fa09240cc64ec1cd4c559b6af6642a2cdd13ae`

## Reproducer

Run the focused `pkcs11-check` probe:

```bash
bash docker/test.sh softhsm2 -- src/pkcs11_check/testcases/test_eddsa_public_key_encoding.py
```

Focused result:

```text
src/pkcs11_check/testcases/test_eddsa_public_key_encoding.py x [100%]
1 xfailed in 0.18s
```

The xfail reason is:

```text
EdDSA verifies only with DER-wrapped CKA_EC_POINT; PKCS#11 requires raw RFC 8032 public-key bytes for CKK_EC_EDWARDS
```

The probe creates a public key with `C_CreateObject`, then calls
`C_VerifyInit` and `C_Verify` against a known-good RFC 8032 signature. It tries
both public-key encodings:

1. raw RFC 8032 bytes in `CKA_EC_POINT`
2. DER OCTET STRING-wrapped bytes in `CKA_EC_POINT`

Manual profile probe against the same Docker target:

```text
profile=raw/null
  C_CreateObject CKR_OK
  C_VerifyInit CKR_OK
  C_Verify CKR_SIGNATURE_INVALID
profile=raw/explicit
  C_CreateObject CKR_OK
  C_VerifyInit CKR_OK
  C_Verify CKR_SIGNATURE_INVALID
profile=der/null
  C_CreateObject CKR_OK
  C_VerifyInit CKR_OK
  C_Verify CKR_OK
profile=der/explicit
  C_CreateObject CKR_OK
  C_VerifyInit CKR_OK
  C_Verify CKR_OK
```

Here `null` means `CKM_EDDSA` with `pParameter = NULL`; `explicit` means
`CKM_EDDSA` with a `CK_EDDSA_PARAMS` structure for pure Ed25519.

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
key.

## Spec basis checked

Local file in the OASIS PKCS#11 working-tree checkout:
`working/doc/spec/elliptic_curves.md`

Relevant local sections:

- Edwards public-key object table: lines 345-356
- Edwards curve parameter forms and RFC 8032/RFC 8410 note: lines 360-377
- EdDSA mechanism table: lines 758-789

The important distinction is that `CKK_EC_EDWARDS` public-key
`CKA_EC_POINT` is described as RFC 8032 public-key bytes, not as a DER OCTET
STRING. The DER OCTET STRING form is the behavior SoftHSM2 currently appears to
require for verification.

## Likely implementation cause

SoftHSM2 appears to store the EdDSA public-key component internally as a DER
OCTET STRING:

- `src/lib/crypto/OSSLEDPublicKey.cpp`
  - `setFromOSSL()` extracts raw Ed25519/Ed448 public-key bytes, then stores
    them with `DERUTIL::raw2Octet(raw)`.
  - `createOSSLKey()` later reads the stored value with `DERUTIL::octet2Raw(a)`.
- `src/lib/crypto/BotanEDPublicKey.cpp` follows the same storage pattern.
- `src/lib/SoftHSM.cpp`
  - generated EdDSA public keys expose `pub->getA()` as `CKA_EC_POINT`; because
    that value is already DER-wrapped internally, generated keys expose the
    wrapper.
  - imported EdDSA public keys pass user-supplied `CKA_EC_POINT` directly to
    `publicKey->setA(value)`.

This matches the runtime behavior: `04 20 <public-key>` fits the internal
representation and verifies; raw `<public-key>` does not.

Source links for the tested 2.7.0 tag:

- <https://github.com/softhsm/SoftHSMv2/blob/13e6e86b83748fef74046dbf0c91f664b7acc1c3/src/lib/crypto/OSSLEDPublicKey.cpp#L160-L207>
- <https://github.com/softhsm/SoftHSMv2/blob/13e6e86b83748fef74046dbf0c91f664b7acc1c3/src/lib/crypto/BotanEDPublicKey.cpp#L106-L163>
- <https://github.com/softhsm/SoftHSMv2/blob/13e6e86b83748fef74046dbf0c91f664b7acc1c3/src/lib/SoftHSM.cpp#L9802-L9808>
- <https://github.com/softhsm/SoftHSMv2/blob/13e6e86b83748fef74046dbf0c91f664b7acc1c3/src/lib/SoftHSM.cpp#L12626-L12653>

A likely compatibility-friendly fix would be to normalize at the PKCS#11
boundary:

- accept raw 32-byte Ed25519 and raw 57-byte Ed448 `CKA_EC_POINT` values for
  `CKK_EC_EDWARDS`
- optionally continue accepting DER OCTET STRING-wrapped values for existing
  users
- return the PKCS#11-specified raw form from `C_GetAttributeValue` for
  generated/imported `CKK_EC_EDWARDS` public keys, or at least document any
  compatibility transition if existing behavior is kept temporarily

## Copyable upstream issue body

SoftHSM2 2.7.0 appears to require a DER OCTET STRING wrapper for
`CKA_EC_POINT` when creating/importing `CKK_EC_EDWARDS` Ed25519 public keys.
PKCS#11 Edwards public-key objects specify `CKA_EC_POINT` as the raw RFC 8032
public-key bytes.

With RFC 8032 Ed25519 test vector 1, verification succeeds only when the public
key is supplied as:

```text
0420d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
```

The raw PKCS#11 Edwards value does not produce a working verification profile:

```text
d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
```

More specifically, SoftHSM2 accepts the raw public-key object and accepts
`C_VerifyInit`, but `C_Verify` returns `CKR_SIGNATURE_INVALID` for the
known-good signature. With the DER OCTET STRING-wrapped public key, `C_Verify`
returns `CKR_OK`.

Expected result: raw RFC 8032 public-key bytes should be accepted for
`CKK_EC_EDWARDS` `CKA_EC_POINT`. Accepting the DER-wrapped form as
compatibility behavior is fine, but it should not be required.

## Separate finding, not this issue

The broader focused EdDSA run also found four ACVP EdDSA KeyVer cases where
SoftHSM2 accepted invalid Ed25519/Ed448 public keys as usable:

- `EDDSA-KeyVer-ED-25519-tc1`
- `EDDSA-KeyVer-ED-25519-tc4`
- `EDDSA-KeyVer-ED-448-tc6`
- `EDDSA-KeyVer-ED-448-tc8`

Those are probably reportable too, but they should be reviewed separately
because ACVP KeyVer semantics and PKCS#11 object creation semantics do not map
as directly as the `CKA_EC_POINT` encoding issue.

Related local notes:

- `docs/softhsm2-eddsa-public-key-encoding.md`
- `docs/softhsm2-eddsa-upstream-issue.md`
- `docs/softhsm2-eddsa-upstream-report.md`
