# DER handling policy

DER appears in two opposite directions in this framework, and each direction
has its own rules. Mixing them up is a bug: the strict output validator must
never gate intentionally malformed test inputs, and the tolerant input
builder must never judge provider output.

## Direction 1: validating provider output for oracles

When the framework reads DER-encoded material back from the token (for
example `CKA_PUBLIC_KEY_INFO`, which PKCS#11 defines as DER-encoded
SubjectPublicKeyInfo) and feeds it to an oracle, the bytes must be exactly
what the oracle assumes. A `CKR_OK` read that delivers malformed bytes is
provider-malformed metadata, and the row fails (`wrong_result`, kind
`metadata`, operation `C_GetAttributeValue`, mechanism-free) instead of
limping on with unknown bytes.

What the SLH-DSA recovery parser guarantees today:

- Minimal definite lengths everywhere; the outer length matches the input
  exactly (no truncation, no trailing bytes).
- An AlgorithmIdentifier carrying a well-formed OBJECT IDENTIFIER plus at
  most one well-formed parameters element; universal tags obey their DER
  encoding rules (constructed-bit direction, no EOC, canonical
  BOOLEAN/INTEGER/ENUMERATED/BIT STRING shapes, strict UTF-8/16/32 and
  restricted string alphabets, BMP repertoire).
- The BIT STRING ends at the outer end with a nonempty payload, and the
  recovered key length matches the parameter set before anything is
  re-imported (a short key must fail here, never decay into a
  not-operational import xfail).

Deliberately unchecked value semantics: OID arc values, REAL encodings,
time formats, and exotic character-string contents. Shapes the walker
cannot represent (multi-byte tags, nesting past the depth cap) read as
malformed on purpose -- fail loud, never pass silent. Widen either side
only with a valid-encoding regression pin proving no over-strictness
(the constructed-CHARACTER-STRING lesson: strictness once rejected valid
DER, and a pinned valid vector now guards it).

Missing, refused, or empty readback is *unavailability*, not malformation:
those rows xfail oracle-unavailable so a token that simply does not serve
the attribute is never reported as defective.

The shared `raw/der.py` module follows the same split: strict decoding is
opt-in per call site (`decode_ec_point`), while signature parsing stays
lenient, because each direction answers a different question.

## Direction 2: crafting inputs toward providers

Negative tests must be able to send malformed DER *to* the token -- bad
OIDs, broken lengths, truncated children -- and then judge the provider by
its effect (reject cleanly, and the row passes; accept, and the row fails).
The Wycheproof key fallback (`_key_decoders._extract_spki_bitstring_raw`)
exists for exactly this: it extracts bytes tolerantly so the test can probe
provider input validation. That tolerance is intentional and must survive
any future consolidation of DER helpers.

Rules for crafted inputs:

- Build mutations from valid seeds (hand-rolled builders or asn1crypto)
  with explicit names stating the defect.
- Preserve exact bytes end to end: no encoder may silently repair a
  deliberately inconsistent length or re-encode the defect away. Assert
  the intended bytes reach the PKCS#11 call.
- Never route a crafted input through a strict output parser on its way
  to the provider.
- Classify by expected code *and* observed effect, following the
  EC-import probe (`security/test_curve_oid_confusion.py`): rejection
  with an expected code passes, any other rejection xfails; acceptance
  fails only when the token silently rebinds the malformed input to
  something else (`self_contradiction`), and xfails `honest_deviation`
  when the token stores it faithfully. A binary reject-pass/accept-fail
  rule would erase recorded deviations and invent false failures.

## Libraries

- **asn1crypto**: byte construction, schema decoding, and independent test
  controls. Its strict mode only covers trailing data -- it is not a DER
  canonicality validator and must not be used as one.
- **cryptography**: key serialization and cryptographic verification. Its
  key loader can reject an unsupported algorithm regardless of encoding
  validity, so it answers "can we use this key", never "is this DER
  conformant".

## Pointers

- `src/pkcs11_check/raw/der.py` -- shared strict/lenient DER primitives.
- `src/pkcs11_check/testcases/acvp/test_acvp_slhdsa.py` -- SPKI recovery
  contract (`_spki_public_key_bytes`, `_recover_slhdsa_public_key`).
- `src/pkcs11_check/testcases/wycheproof/_key_decoders.py` -- tolerant
  extraction for negative testing toward providers.
- `docs/classification-model-design.md` (metadata kind) -- how each
  DER outcome is classified.
