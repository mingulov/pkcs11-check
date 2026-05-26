# SoftHSM2 EdDSA public-key encoding notes

Date: 2026-05-26

## Short conclusion

`pkcs11-check` currently has a focused EdDSA public-key encoding test that
shows SoftHSM2 verifies the RFC 8032 Ed25519 test vector only when the
`CKK_EC_EDWARDS` `CKA_EC_POINT` value is DER-wrapped as an OCTET STRING. The
local OASIS PKCS#11 spec text says the Edwards `CKA_EC_POINT` value is the raw
RFC 8032 public-key bytes in little-endian order.

This looks reportable as a SoftHSM2 compatibility/spec issue:

- expected by PKCS#11 text: raw Ed25519 public key bytes in `CKA_EC_POINT`
- observed with SoftHSM2 focused test: raw does not produce a working verify
  profile; DER-wrapped point does
- current `pkcs11-check` behavior: keep a standalone xfail for the spec-facing
  result, but adapt ACVP/Wycheproof vector tests to whichever profile actually
  works so the cryptographic vectors still run

## Spec basis checked locally

Source checked during the audit:
`../other/pkcs11/working/doc/spec/elliptic_curves.md`

Relevant text:

- Edwards public keys are `CKO_PUBLIC_KEY` objects with key type
  `CKK_EC_EDWARDS`.
- For Edwards public keys, `CKA_EC_PARAMS` is DER-encoded parameters.
- For Edwards public keys, `CKA_EC_POINT` is public key bytes in little-endian
  order as defined in RFC 8032.
- `CKM_EDDSA` operates with `CKK_EC_EDWARDS` public/private keys.

Exact local lines checked:

- public-key object table: `elliptic_curves.md:345-356`
- allowed curve parameter forms and RFC 8032/RFC 8410 note:
  `elliptic_curves.md:360-377`
- EdDSA mechanism and key type table: `elliptic_curves.md:758-789`

## pkcs11-check implementation

The current helper deliberately probes both encodings:

- raw `CKA_EC_POINT`: the public key bytes directly
- DER-wrapped `CKA_EC_POINT`: ASN.1 OCTET STRING wrapper around the same bytes

Code:

- `src/pkcs11_check/testcases/_eddsa_public_key.py`
  - `_PREFERRED_PROFILES` tries raw/null, raw/explicit, DER/null, DER/explicit
  - `der_wrap_eddsa_public_key()` creates the OCTET STRING wrapper
  - `probe_eddsa_public_key_encodings()` returns which encoding verifies a
    known-good signature
  - `select_eddsa_public_key_profile()` caches the working profile per
    module/curve

The standalone result test is:

- `src/pkcs11_check/testcases/test_eddsa_public_key_encoding.py`

It uses RFC 8032 Section 7.1 Ed25519 test 1:

- `CKA_EC_PARAMS`: `06 03 2b 65 70` (`id-Ed25519`)
- raw public key:
  `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`
- message: empty string
- signature:
  `e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155`
  `5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b`

If raw works, the test passes. If only DER works, the test xfails with:

```text
EdDSA verifies only with DER-wrapped CKA_EC_POINT; PKCS#11 requires raw RFC 8032 public-key bytes for CKK_EC_EDWARDS
```

## SoftHSM2 focused evidence

Focused artifact:

- `artifacts/_focused/softhsm2-eddsa-encoding-current-20260526/`

Result:

- `src/pkcs11_check/testcases/test_eddsa_public_key_encoding.py::test_eddsa_public_key_encoding_support`
- outcome: `xfailed`
- reason:
  `EdDSA verifies only with DER-wrapped CKA_EC_POINT; PKCS#11 requires raw RFC 8032 public-key bytes for CKK_EC_EDWARDS`

The same xfail is also present in the broader focused EdDSA run:

- `artifacts/_focused/softhsm2-eddsa-adaptive-profile-v3/`
- summary: 21 passed, 4 failed, 4 skipped, 1 xfailed, total 30
- the one xfail is the public-key encoding support test above

## Separate SoftHSM2 ACVP KeyVer findings

The broader focused run also has four ACVP EdDSA KeyVer failures. These are
not the same as the public-key encoding issue; they are current `pkcs11-check`
findings about invalid public keys being accepted as usable:

- `EDDSA-KeyVer-ED-25519-tc1`
  - `q = 5bc0d8831f8d7fb200e32daf36c54bf2808e69d40bd48bd915df585b2696c166`
- `EDDSA-KeyVer-ED-25519-tc4`
  - `q = fbb4f7945f521a5cb169883477e9dfafa14767fd4d973d8fd3667c46253f5943`
- `EDDSA-KeyVer-ED-448-tc6`
  - `q = 8de82d8611d23882cefc1c3bd13c1e5e3bac0d1aae908fff0b0a5431b90bef715f1160073c919b886bbdaf156fa051ca37022e8118b260ff00`
- `EDDSA-KeyVer-ED-448-tc8`
  - `q = 480b6575633fefaf3635efa2294f2cbf1e8d49f6bc0cd8b8f5a91a0a59922be33cdd837a3accaa419970cbe4a21a062cf37f839931cf17ee80`

Current failure message:

```text
Module ACCEPTED an INVALID EdDSA key
```

This should be reviewed separately before reporting upstream, because
PKCS#11 object creation and ACVP KeyVer semantics do not map as directly as the
`CKA_EC_POINT` encoding issue. The current test considers the key usable when
the imported public key can reach the verification path and reject a dummy
signature as a signature failure rather than as an unusable-key failure.

## Suggested upstream wording

SoftHSM2 appears to require a DER OCTET STRING wrapper for `CKA_EC_POINT` when
creating/importing `CKK_EC_EDWARDS` Ed25519 public keys. PKCS#11 v3 Edwards
public-key objects specify `CKA_EC_POINT` as the raw RFC 8032 public-key bytes,
not a DER OCTET STRING wrapper. A minimal reproduction is the RFC 8032 Ed25519
test vector 1 with `CKA_EC_PARAMS = 06032b6570` and the raw public key shown
above: verification succeeds only after wrapping the same 32 bytes as
`04 20 <public-key-bytes>`.

Optional compatibility improvement: SoftHSM2 could continue accepting the
DER-wrapped form for existing users, but it should also accept the raw
PKCS#11 Edwards form.
