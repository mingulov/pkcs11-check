# Vector Dataset Coverage Audit - 2026-05-26

This is a working audit for the pkcs11-check report/article effort, not an
official release-statistics update. It records which optional vector datasets
are currently useful, which parts are intentionally not mapped to PKCS#11, and
which gaps are worth adding later.

Local dataset inventory in this checkout:

| Dataset | Local inventory | Current use |
| --- | ---: | --- |
| NIST ACVP | 169 algorithm directories | AES selected modes, SHA2/SHA3/SHAKE, HMAC, RSA, ECDSA, EdDSA, ML-DSA, ML-KEM, SLH-DSA |
| Wycheproof | 340 JSON files | RSA, ECDSA, DSA, ECDH/XDH, EdDSA, AES, HMAC, HKDF/PBKDF/PBES2, ChaCha20-Poly1305, ML-KEM/ML-DSA, aggregate legacy coverage |
| CCTV | 53 files | Ed25519 edge cases, ML-DSA benchmark messages, RFC6979 reference check |
| x509-limbo | 132 files | certificate import, attribute/search checks, capped stress import |

## ACVP

High-value gaps to consider:

- `ACVP-AES-CBC-1.0`, `ACVP-AES-CTR-1.0`, and `ACVP-AES-ECB-1.0`: pkcs11-check
  already has non-ACVP AES coverage for these mechanisms, but ACVP would add a
  larger official KAT surface.
- `CMAC-AES-1.0` and `CMAC-TDES-1.0`: useful because PKCS#11 has AES/TDES MAC
  mechanisms and the suite already exercises mechanism-driven MAC behavior.
- `ACVP-TDES-*`: useful legacy coverage for providers that still advertise DES
  and TDES, especially to distinguish "mechanism advertised but OpenSSL legacy
  provider unavailable" from clean absence.
- KDF/KDA/TLS/PBKDF families: potentially useful, but format mapping is more
  involved than ordinary KATs because PKCS#11 mechanisms often encode
  derivation parameters and output-key templates differently from ACVP.
- `XECDH-*`: useful follow-up for X25519/X448 keygen/keyver/SSC coverage after
  the current Wycheproof XDH duplicate normalization is settled.
- KMAC/cSHAKE/TupleHash/ParallelHash: useful only after confirming the raw
  binding and mechanism-parameter support is complete enough.
- ACVP DSA: lower priority because Wycheproof DSA is already mapped and DSA is
  legacy, but it can be used for a standards-comparison row later.

ACVP KeyGen caveat:

ACVP internal-projection KeyGen files include deterministic seeds and expected
key material. Current PKCS#11 key-generation APIs cannot consume those seeds,
so exact ACVP KeyGen validation is not portable. pkcs11-check now keeps those
vectors collected but skips repeated provider-visible inputs after the first
representative. The current duplicate-to-skip counts are RSA 27, ECDSA 17,
EdDSA 4, ML-DSA 72, and ML-KEM 72. A future PKCS#11 revision could close this
standards gap by adding deterministic validation inputs for key generation, but
there is no portable API for it today. The current
[OASIS PKCS 11 TC page](https://www.oasis-open.org/committees/pkcs11/) lists
published PKCS#11 3.1 standards, and OASIS also publishes
[PKCS#11 Specification Version 3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)
material; this audit does not assume any future availability date.

## Wycheproof

The current normalization work found three important classes:

- ECDH/XDH container variants: many ASN/PEM/ECPOINT/JWK/WebCrypto cases collapse
  to identical PKCS#11-visible curve, public point, private scalar, shared
  secret, and expected result. Those duplicates are now counted as skips.
- ECDSA/DSA signature encodings: DER and P1363 vectors can collapse to the same
  raw `r || s` value consumed by PKCS#11. Exact duplicates are now counted as
  skips.
- RSA-PSS/RSA PKCS#1 signatures: smaller exact-duplicate groups exist after
  mechanism, parameters, public key, message, and signature are normalized.

Likely low-value or non-standard files include ARIA, Camellia, SEED, SM4,
Ascon, AEGIS, MORUS, VMAC, SipHash, BLS, JWS/JWE/JWK/WebCrypto protocol files,
FF1/FF3, and primality tests. They should not be added just to increase counts.
They become useful only if pkcs11-check gains matching standard PKCS#11
mechanism support or a clearly documented non-standard extension target.

Potentially useful follow-ups:

- Re-check HMAC-SM3 and SHA-512/224 or SHA-512/256 RSA files against current raw
  mechanism support before adding them.
- Split or retire remaining aggregate Wycheproof coverage once equivalent
  mechanism-specific files exist, because aggregate failures are harder to
  explain in provider reports.

## CCTV

Current useful coverage:

- `ed25519/ed25519vectors.json` is mapped as Ed25519 edge-case verification
  coverage.
- `ML-DSA/benchmark/*.json` is mapped as sign/verify round-trip message
  coverage.
- `RFC6979/README.md` provides the reference vector used for the deterministic
  nonce sanity check.

Potentially useful follow-ups:

- `ML-DSA/benchmark/*.alt.json` may be useful if its format adds distinct
  messages or edge cases beyond the existing benchmark files.
- `ML-KEM/intermediate`, `modulus`, `strcmp`, and `unluckysample` look useful
  for KEM edge-case behavior, but they need a careful PKCS#11 mapping. Some
  files are text/gzip generator outputs rather than direct provider inputs.

Lower priority:

- `jq255/*` is not a standard PKCS#11 mechanism family.
- `keygen/rsa.bench.*.txt` contains deterministic benchmark material, but
  standard PKCS#11 RSA key generation cannot consume the seeds.

## X.509 Limbo

Current use:

- Import tests cover all offline non-bettertls cases plus sampled bettertls
  success/failure cases.
- Stress import uses a capped set of unique certificates plus the CRLs to find
  object-handling failures without making the default run unbounded.
- Attribute and search tests sample limbo-derived certificates for object
  metadata behavior.

Potential useful gap:

- A deliberate full-stress mode over the complete unique certificate set would
  be useful for provider hardening, but it should be opt-in and documented as a
  stress workload. The current capped default is a pragmatic crash/probing
  surface, not an exhaustive x509-limbo import claim.
