# SoftHSM2 Ed25519 `CKA_EC_POINT` encoding

Date: 2026-05-27 · Provider: SoftHSM2 2.7.0 and `main` (5a3466f / 679f33d), OpenSSL backend

## Summary

SoftHSM2 verifies an RFC 8032 Ed25519 signature only when the `CKK_EC_EDWARDS`
public key's `CKA_EC_POINT` is a **DER `OCTET STRING`** (`04 20 <32 bytes>`, 34 B).
Supplied as the **raw** 32-byte RFC 8032 public key, `C_CreateObject` and
`C_VerifyInit` still return `CKR_OK`, but `C_Verify` returns
`CKR_SIGNATURE_INVALID` — i.e. the wrong key material is accepted silently and
only fails later at verify time.

```
profile=raw  (32 B)            C_CreateObject OK  C_VerifyInit OK  C_Verify CKR_SIGNATURE_INVALID (0xC0/192)
profile=der  (04 20 .., 34 B)  C_CreateObject OK  C_VerifyInit OK  C_Verify CKR_OK
```

## Already reported upstream — open and contested

This is **not new**; it is filed and unresolved:

- **softhsm/SoftHSMv2#824 — "Wrong encoding of CKA_EC_POINT for Edwards curve
  keys using OpenSSL"** (open, 2026-04-23). The proper issue. Its body matches
  this finding exactly, including the key symptom: *"softhsm does not validate
  the attribute when creating a public key with `C_CreateObject`. Only when using
  the key to verify a signature, the verification fails."* The thread is
  **contested**: the report argues raw (32 B) is correct; a comment argues the
  DER `OCTET STRING` (34 B) is correct. No maintainer resolution.
- **softhsm/SoftHSMv2#634 — "Ed25519 public key representation"** (open since
  2021). Same raw-vs-wrapped mismatch (SoftHSM2 vs OpenSC), "doesn't match the
  current PKCS#11 specification" — open ~5 years.

**Action: do not open a new issue — add evidence to #824** (reproducer, CppUnit
test, and the errata citation below).

## Why it is unresolved — the spec wording is genuinely ambiguous

The encoding differs by PKCS#11 revision, which is the root of the dispute:

| Source | `CKK_EC_EDWARDS` `CKA_EC_POINT` text | Reading |
|---|---|---|
| v3.0/v3.1 base (quoted in #824) | "**DER-encoding** of the b-bit public key value in little endian order as defined in RFC 8032" | ambiguous → some read a DER `OCTET STRING` (34 B) |
| **v3.0 Current Mechanisms, Errata 01, §2.1** | "**Public key bytes** in little endian order as defined in RFC 8032" | raw (32 B), no DER wrapper |
| Weierstrass `CKK_EC` (for contrast) | "DER-encoding of ANSI X9.62 ECPoint value" | DER `OCTET STRING` |

The Errata 01 wording (raw) is the clarifying reading, and it differs from the
classic Weierstrass form — but because the older/base wording says
"DER-encoding of … public key value", interoperable implementations diverged
(NSS/OpenSC/libp11/pkcs11-provider largely expect the wrapper). So the
strongest, **non-contested** point for #824 is the silent acceptance:
`C_CreateObject` performs no validation and the failure surfaces only at
`C_Verify`.

## Reproduction

### Standalone (no build, any installed module)
`docs/softhsm2-eddsa-ecpoint-repro.py` — sets up a throwaway token, imports the
key both ways, verifies the vector. Confirmed on `/usr/lib/softhsm/libsofthsm2.so`
and a local `main` build:
```
python3 docs/softhsm2-eddsa-ecpoint-repro.py [/path/to/libsofthsm2.so]
#   raw  CKA_EC_POINT (32B)            -> C_Verify = CKR_SIGNATURE_INVALID
#   DER  CKA_EC_POINT (04 20 ..., 34B) -> C_Verify = CKR_OK
```

### SoftHSM2 CppUnit test (drop-in for `SignVerifyTests`)
`docs/softhsm2-eddsa-ecpoint-test.cpp` — adds `testEdImportPublicKeyVerify` (+ an
`importEdPublicKeyAndVerify` helper) with the three `SignVerifyTests.h`
registration lines in its header comment. Built and run against `main` (5a3466f):
```
SignVerifyTests::testEdImportPublicKeyVerify (F) line: 934 SignVerifyTests.cpp
equality assertion failed
- Expected: 0      (CKR_OK)
- Actual  : 192    (CKR_SIGNATURE_INVALID)
```
(The DER sanity assert passes first, so the vector/signature are confirmed
correct; only the raw form fails.)

### Minimal vector — RFC 8032 §7.1, Ed25519 test 1 (empty message)
```
CKA_EC_PARAMS      : 06032b6570                          (OID id-Ed25519, 1.3.101.112)
raw CKA_EC_POINT   : d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
DER CKA_EC_POINT   : 0420 d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
message            : <empty>
signature          : e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
```

## Likely implementation cause

The EdDSA public-key path stores/expects a DER `OCTET STRING` internally:
- `src/lib/crypto/OSSLEDPublicKey.cpp` — `setFromOSSL()` stores the raw key via
  `DERUTIL::raw2Octet(raw)`; `createOSSLKey()` reads it back via
  `DERUTIL::octet2Raw(a)`. `BotanEDPublicKey.cpp` mirrors this.
- `src/lib/SoftHSM.cpp` — generated keys expose `pub->getA()` (already wrapped) as
  `CKA_EC_POINT`; imported keys pass user `CKA_EC_POINT` straight to
  `publicKey->setA(value)` with **no validation**, so a raw value is accepted at
  `C_CreateObject` and only misbehaves at `C_Verify`.

A compatibility-friendly fix: accept **both** raw (32 B Ed25519 / 57 B Ed448) and
DER `OCTET STRING` on import, and validate at `C_CreateObject` rather than failing
silently later.

## Separate finding — ACVP EdDSA KeyVer accepts invalid keys

Not the same issue; review/report separately. The focused EdDSA run also found
SoftHSM2 accepting invalid Ed25519/Ed448 public keys as usable:
`EDDSA-KeyVer-ED-25519-tc1`, `-tc4`, `ED-448-tc6`, `-tc8`. ACVP KeyVer semantics
and PKCS#11 `C_CreateObject` semantics do not map directly, so keep this distinct
from the `CKA_EC_POINT` encoding above.

## pkcs11-check references
- Behavior test: `src/pkcs11_check/testcases/test_eddsa_public_key_encoding.py`
- Adaptive profile helper: `src/pkcs11_check/testcases/_eddsa_public_key.py`
- Standalone repro: `docs/softhsm2-eddsa-ecpoint-repro.py`
- SoftHSM2 CppUnit test: `docs/softhsm2-eddsa-ecpoint-test.cpp`
- Upstream: softhsm/SoftHSMv2#824 (primary), #634 (related)
