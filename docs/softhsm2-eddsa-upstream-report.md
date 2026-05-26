# SoftHSM2 EdDSA public-key encoding report draft

Date: 2026-05-26

Status: report draft for SoftHSM2 upstream. This file is meant to be reviewed
before filing; it deliberately separates the public-key encoding issue from
broader ACVP EdDSA invalid-key findings.

## Suggested title

SoftHSM2 accepts Ed25519 verification only with DER-wrapped `CKA_EC_POINT`,
while PKCS#11 Edwards keys use raw RFC 8032 public-key bytes

## Short summary

`pkcs11-check` found that SoftHSM2 2.7.0 can verify the RFC 8032 Ed25519 test
vector only when the `CKK_EC_EDWARDS` public key's `CKA_EC_POINT` attribute is
wrapped as a DER OCTET STRING.

The PKCS#11 Edwards-key text checked locally says that `CKK_EC_EDWARDS`
`CKA_EC_POINT` is the raw RFC 8032 public-key bytes in little-endian order. That
is different from classic Weierstrass `CKK_EC`, where `CKA_EC_POINT` is a
DER-encoded ANSI X9.62 point.

## Environment used by pkcs11-check

- Docker target: `test-softhsm2`
- Provider: SoftHSM2 2.7.0
- Docker build config: `docker/docker-compose.test.yml`
- OpenSSL build argument in this target: `OPENSSL_VERSION=3.6.2`
- Focused artifact:
  `artifacts/_focused/softhsm2-eddsa-encoding-current-20260526/`

This note does not yet claim that SoftHSM2 `main` has the same behavior. A
separate `test-softhsm2-main` focused rerun should be used if the upstream issue
needs current-branch confirmation.

Focused local reproduction:

```bash
bash docker/test.sh softhsm2 -- src/pkcs11_check/testcases/test_eddsa_public_key_encoding.py
```

## Expected behavior

For an Edwards public key object:

- `CKA_CLASS = CKO_PUBLIC_KEY`
- `CKA_KEY_TYPE = CKK_EC_EDWARDS`
- `CKA_EC_PARAMS = 06032b6570` for Ed25519 by OID
- `CKA_EC_POINT` should contain the raw 32-byte RFC 8032 Ed25519 public key

Local spec source checked:

- local OASIS PKCS#11 spec checkout:
  `../other/pkcs11/working/doc/spec/elliptic_curves.md`
- Edwards public-key object table: lines 345-356
- Edwards curve parameter forms and RFC 8032/RFC 8410 note: lines 360-377
- EdDSA mechanism table: lines 758-789

## Observed behavior

The focused pkcs11-check probe tries both provider profiles:

1. raw `CKA_EC_POINT`
2. DER OCTET STRING-wrapped `CKA_EC_POINT`

On SoftHSM2 2.7.0, the raw profile does not produce a working verification
path, while the DER-wrapped profile does. The focused test result is therefore
an expected failure in pkcs11-check:

```text
EdDSA verifies only with DER-wrapped CKA_EC_POINT; PKCS#11 requires raw RFC 8032 public-key bytes for CKK_EC_EDWARDS
```

Focused result summary:

```text
src/pkcs11_check/testcases/test_eddsa_public_key_encoding.py x [100%]
1 xfailed in 0.18s
```

The probe called `C_CreateObject`, `C_VerifyInit`, `C_Verify`, and
`C_DestroyObject` for the tested profiles.

Artifact details:

- result file:
  `artifacts/_focused/softhsm2-eddsa-encoding-current-20260526/results.json`
- node id:
  `src/pkcs11_check/testcases/test_eddsa_public_key_encoding.py::test_eddsa_public_key_encoding_support`
- result: `xfailed`
- xfail reason:
  `EdDSA verifies only with DER-wrapped CKA_EC_POINT; PKCS#11 requires raw RFC 8032 public-key bytes for CKK_EC_EDWARDS`

## Source-side notes

I also checked the SoftHSM2 source for the tested release tag and current
branch:

- release tag `2.7.0`: commit `13e6e86b83748fef74046dbf0c91f664b7acc1c3`
- current branch checked during this note: commit
  `679f33d1b325cca8f5eb1a8febcc7630654a34de`

The relevant EdDSA public-key path appears unchanged between those two source
snapshots.

Likely implementation cause:

- `src/lib/crypto/OSSLEDPublicKey.cpp`
  - `setFromOSSL()` extracts the raw Ed25519/Ed448 public key from a Subject
    Public Key Info structure, then stores it with `DERUTIL::raw2Octet(raw)`.
  - `createOSSLKey()` later reads the stored public-key field with
    `DERUTIL::octet2Raw(a)` before building an OpenSSL `EVP_PKEY`.
- `src/lib/crypto/BotanEDPublicKey.cpp` has the same pattern for the Botan
  backend: generated/imported Botan public-key bytes are stored via
  `DERUTIL::raw2Octet(inA)`, and later decoded with `DERUTIL::octet2Raw(a)`.
- `src/lib/SoftHSM.cpp`
  - generated EdDSA public keys store `pub->getA()` into `CKA_EC_POINT`;
    because `getA()` already contains the DER OCTET STRING wrapper, generated
    SoftHSM2 public keys expose the wrapped form.
  - imported EdDSA public keys are loaded by `getEDPublicKey()`, which reads
    `CKA_EC_POINT` and passes it directly to `publicKey->setA(value)`.

That combination means the internal EdDSA public-key field is treated as
DER-wrapped OCTET STRING data. If an application supplies the PKCS#11 Edwards
form, i.e. raw RFC 8032 public-key bytes, the later OpenSSL/Botan conversion
tries to unwrap it as DER and does not build the expected provider key. If the
application supplies `04 20 <32-byte Ed25519 public key>`, it matches the
current internal representation and verification succeeds.

This source reading is consistent with the pkcs11-check focused result, but the
upstream report should still present the runtime result as the primary
reproducer.

## Minimal test vector

The focused test uses RFC 8032 Section 7.1, Ed25519 test 1:

```text
CKA_EC_PARAMS:
06032b6570

raw Ed25519 public key:
d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a

message:
<empty>

signature:
e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
```

The DER-wrapped form that works in the focused SoftHSM2 run is:

```text
0420d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
```

That value is a DER OCTET STRING wrapper (`04 20`) around the same 32 public-key
bytes.

## pkcs11-check source locations

- Focused behavior test:
  `src/pkcs11_check/testcases/test_eddsa_public_key_encoding.py`
- Adaptive EdDSA public-key helper:
  `src/pkcs11_check/testcases/_eddsa_public_key.py`
- Longer internal evidence note:
  `docs/softhsm2-eddsa-public-key-encoding.md`

Current pkcs11-check behavior is intentionally split:

- the focused encoding test keeps the SoftHSM2 spec-facing issue visible as
  `xfail`
- ACVP and Wycheproof EdDSA vector tests probe the working provider profile so
  cryptographic vector coverage can still run

## Suggested upstream issue wording

SoftHSM2 2.7.0 appears to require a DER OCTET STRING wrapper for
`CKA_EC_POINT` when creating/importing `CKK_EC_EDWARDS` Ed25519 public keys.
PKCS#11 Edwards public-key objects specify `CKA_EC_POINT` as the raw RFC 8032
public-key bytes, not a DER OCTET STRING wrapper.

A minimal reproduction is the RFC 8032 Ed25519 test vector 1 above. With
`CKA_EC_PARAMS = 06032b6570`, verification succeeds only if the public key is
provided as `04 20 <32-byte-public-key>`. The raw 32-byte public key does not
produce a working verification profile.

Compatibility suggestion: SoftHSM2 could continue accepting the DER-wrapped
form for existing users, but it should also accept the raw PKCS#11 Edwards form.

## Suggested issue body

`pkcs11-check` found that SoftHSM2 2.7.0 verifies an RFC 8032 Ed25519 test
vector only when the `CKK_EC_EDWARDS` public key object uses a DER OCTET STRING
wrapper in `CKA_EC_POINT`.

The PKCS#11 Edwards public-key object table says that `CKA_EC_POINT` is the
public-key bytes in little-endian order as defined in RFC 8032. This differs
from classic Weierstrass `CKK_EC` keys, where `CKA_EC_POINT` is an encoded
ANSI X9.62 point.

Minimal vector:

```text
CKA_EC_PARAMS = 06032b6570
raw CKA_EC_POINT = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
DER-wrapped CKA_EC_POINT = 0420d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
message = empty
signature =
  e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
  5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
```

Observed result:

- raw `CKA_EC_POINT`: does not produce a working verification profile
- DER OCTET STRING-wrapped `CKA_EC_POINT`: verification succeeds

Likely source-side reason: SoftHSM2's EdDSA public-key implementation stores
the public-key component internally as a DER OCTET STRING and `C_CreateObject`
imports `CKA_EC_POINT` directly into that field.

Expected result:

- raw RFC 8032 public-key bytes should be accepted for `CKK_EC_EDWARDS`
  `CKA_EC_POINT`
- accepting the DER-wrapped form as compatibility behavior is fine, but it
  should not be the only working form

## Separate EdDSA finding, not part of this report

The broader focused EdDSA run also found four ACVP KeyVer cases where SoftHSM2
accepted invalid Ed25519/Ed448 public keys as usable:

- `EDDSA-KeyVer-ED-25519-tc1`
- `EDDSA-KeyVer-ED-25519-tc4`
- `EDDSA-KeyVer-ED-448-tc6`
- `EDDSA-KeyVer-ED-448-tc8`

Those are not the same issue as the `CKA_EC_POINT` encoding behavior. They
should be reviewed and reported separately, because ACVP KeyVer semantics and
PKCS#11 object creation semantics do not map as directly as the encoding issue.
