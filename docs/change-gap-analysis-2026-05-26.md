# Provider-Neutral Change Gap Analysis (2026-05-26)

This note records the review criteria for the current provider-matrix cleanup.
The goal is to keep pkcs11-check useful as a common test suite for arbitrary
PKCS#11 modules, not only for the software providers used in the Docker matrix.

## Decision Rules

- Spec checks should prefer a local OASIS TC checkout when available. In the
  current audit workspace, the neighboring checkout is `../other/pkcs11/`; use
  `published/3-02/` for released v3.2 headers and `working/doc/spec/` for
  searchable prose. The checkout's origin is
  `https://github.com/oasis-tcs/pkcs11.git`; the local HEAD observed during
  this audit was `48fa092`.
- Crashes, subprocess signal exits, hangs, accepted invalid cryptography, and
  failed valid cryptography remain findings. They must not be skipped or hidden.
- Missing advertised capability is a skip only when the mechanism or interface
  is absent. If a mechanism is advertised but fails at runtime, the result stays
  visible as a failure or xfail depending on whether the operation reached a
  meaningful provider outcome.
- Invalid-signature vectors have three outcomes:
  - clean PKCS#11 signature rejection (`CKR_SIGNATURE_INVALID` or
    `CKR_SIGNATURE_LEN_RANGE`) is a vector pass;
  - accepted invalid signature is a hard failure;
  - non-clean rejects such as `CKR_DATA_INVALID`, `CKR_DEVICE_ERROR`, or
    `CKR_FUNCTION_FAILED` are xfail evidence, not a clean pass.
- Duplicate vector skips are allowed only for exact PKCS#11-visible duplicates:
  if pkcs11-check has normalized away ASN.1, PEM, DER, P1363, JWK, WebCrypto, or
  ACVP seed metadata before calling the module, repeated identical module inputs
  should be counted as skipped duplicates rather than as repeated provider
  failures.
- Attribute-template quirks must not replace security tests. A mechanism
  roundtrip may retry a documented unwrap-template restriction only when the
  retried object is immediately used to prove the cryptographic roundtrip.
  Attribute enforcement and tamper/integrity tests stay strict.

## Current Change Review

| Area | Review result | Remaining risk |
| --- | --- | --- |
| Raw CKR subprocess reporting | Valid. It separates signal crashes from ordinary child-process assertion exits. It does not suppress crashes. | None beyond normal subprocess coverage. |
| Invalid-signature policy | Valid. It distinguishes cryptographic rejection from clean conformance. `CKR_DEVICE_ERROR` from Kryoptic-like behavior becomes xfail, not pass. | Reports and article text must not describe these rows as fully compliant. |
| EdDSA public-key encoding and runtime classification | Public-key imports now use raw RFC 8032 bytes for `CKK_EC_EDWARDS` `CKA_EC_POINT`, matching the local OASIS spec tree. Runtime rejects including `CKR_FUNCTION_NOT_SUPPORTED` become xfail evidence for advertised-but-not-operational paths; unsupported curves remain skips. | Valid-vector rejects are still provider findings, so article wording should separate "unsupported", "advertised but failing", and "DER-wrapped compatibility only." |
| EdDSA mechanism parameters | Needs separate review. The local PKCS#11 text distinguishes parameterless pure Ed25519 / RFC 8410 OID curves from explicit `CK_EDDSA_PARAMS` variants. | Current generic helpers still default `CKM_EDDSA` to explicit parameters. Before final article wording, rerun a focused parameter-mode check so NSS-like results are not mislabeled. |
| Wycheproof ECDH/XDH deduplication | Valid. Fingerprints include curve/OID, decoded public input, decoded private input, shared secret, and expected result. Exact duplicates are skipped after capability checks. | Earlier Docker artifacts must be rerun before article statistics use the reduced buckets. |
| Wycheproof ECDSA/DSA deduplication and digest normalization | Valid. PKCS#11 receives raw `r || s`, so DER/P1363 rows that normalize to the same public key, digest/message, signature, mechanism, and result are duplicate provider inputs. ECDSA fixed-width P1363 `SignatureSize` negatives are also not provider-neutral when the raw signature is a shorter even-length `r || s` form allowed by the current PKCS#11 spec. DSA public-key imports now also strip Wycheproof's ASN.1-style sign padding from `Big integer` attributes before calling `C_CreateObject`. ECDSA P-521/SHAKE256 now uses the Wycheproof-compatible 64-byte SHAKE256 output before raw `CKM_ECDSA` verification, rather than the 66-byte coordinate width. | Invalid vectors whose only invalidity was DER container metadata, Bitcoin low-S policy, fixed-width P1363 size policy, third-party integer container padding, or wrong harness XOF length must be described as loader-normalized or version-sensitive skips/fixes, not provider passes. |
| Wycheproof RSA/RSA-PSS deduplication and integer normalization | Valid. Fingerprints include mechanism, mechanism parameters where applicable, public key, message, and signature. RSA public/private key imports now strip third-party ASN.1-style sign padding from PKCS#11 `Big integer` attributes, matching the same rule used for DSA. | Need refreshed Docker rows because this patch landed after several targets had already started. RSA PKCS#1 decrypt rows where invalid ciphertext is accepted remain provider/security findings, not loader-padding artifacts. |
| ACVP KeyGen deduplication | Valid with a standards caveat. Current PKCS#11 key-generation APIs do not accept ACVP internal-projection seeds, so only the provider-visible parameter set can be tested. | Documentation must continue saying this is not an exact ACVP KeyGen reproduction. |
| OpenCryptoki unwrap-template fallback | Conditionally valid. The OASIS PKCS#11 specification `C_UnwrapKey` section allows `CKA_CLASS` and `CKA_KEY_TYPE` in unwrap examples, and says unsupported precise templates fail (<https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html>). For mechanism-level roundtrips, retrying without these identifiers is useful only if the unwrapped key is then verified cryptographically and a compliance note is emitted. | Pass counts alone can overstate compliance. Results should include compliance notes or a separate "template quirk retried" note for OpenCryptoki. |
| AES-KWP error-path crash harness | Valid and necessary. The previous subprocess helper accepted positive child exits, and the generated KWP child script had a syntax-path false positive. The decrypt probe also used an oversized output buffer, which hid the OpenSSL `CRYPTO_128_unwrap_pad()` overwrite that only appears with a minimal output buffer. | Provider artifacts generated before this fix must not be used for AES-KWP crash-survival claims. Rebuild/rerun OpenCryptoki rows before final article numbers. |
| RSA error-path crash harness | Valid and necessary. The RSA malformed-ciphertext child scripts had the same generated `try/finally` indentation issue. Current source builds these scripts through a single helper and compiles representative PKCS#1/OAEP variants in meta-tests. | Provider artifacts generated before this fix should not be used for RSA error-path no-crash claims without a focused rerun. |
| Subprocess result policy | Valid and should become the default for crash-survival probes. A negative return code is a crash finding, a positive return code is a child-script failure, and only return code 0 means the probe completed. Security helpers, mutex callback probes, and the OpenSSL interop wrapper now use this rule. | Remaining bespoke subprocess tests should keep being audited when touched. They are acceptable only if they require `rc == 0`, parse required stdout, or deliberately classify positive exits with explicit xfail/skip wording. |
| CKR operation-state subprocess probes | Valid after correction. `test_encrypt_without_init` now calls raw `C_Encrypt` without `C_EncryptInit`, and the double-digest probe now calls `C_DigestInit` twice instead of using wrapper helpers that reset state. Positive child exits use the shared subprocess-result policy instead of being labelled as crashes. | Existing provider artifacts that mention `test_ckr_dual.py` subprocess crashes are pre-fix evidence and need a focused rerun before public crash wording uses them. Other bespoke CKR subprocess files still deserve gradual conversion to the shared classifier. |
| CKR raw/fault subprocess setup classification | Valid. The retained artifacts showed setup assertions in `test_ckr_raw_attrs.py`, `test_ckr_raw_buffer.py`, `test_ckr_raw_state.py`, and `test_ckr_fault_inject.py` reported through `Crash:` wording. These paths now use the shared CKR subprocess classifier: signal exits remain crash findings, positive child exits are child failures, and explicit setup precondition rejects become visible xfail evidence. The same classifier now covers `test_ckr_general.py`, `test_ckr_universal.py`, and `test_ckr_raw_multipart.py`, which had the same return-code classification shape. | Old artifact rows from those files should not be described as confirmed provider crashes without a rerun. The tests still fail actual wrong CKRs, missing injected errors, wrong outputs, and signal exits. |
| Security crash-probe setup preflight | Valid and needed. API-boundary, arithmetic-overflow, FFI length-boundary, RSA error-path, and NULL-pointer probes now preflight setup key generation in the parent before entering the crash-isolated child. This keeps setup capability rejects out of crash-probe failure buckets without skipping the actual malformed API call when setup succeeds. | HMAC/import-based child setup paths still deserve a later audit; they were not the dominant current artifact failures. |
| NULL-pointer PIN/token scripts | Valid. `C_SetPIN` and `C_InitToken` child probes now pass valid PIN/label buffers as `CK_UTF8CHAR_PTR`, matching the raw binding signature. The old positive subprocess exits were Python `ctypes` type errors, not provider findings. | A focused provider rerun is needed before old `test_ffi_null_pointer.py` artifact failures are removed from public result wording. |
| Zero-length AES-CBC generated child script | Valid. The AES-CBC zero-length API-boundary child script now compiles in meta-tests and preflights AES setup before spawning. | Older target artifacts that failed this row should be treated as pre-fix harness noise. |
| Dataset coverage audit | Valid as an analysis artifact. It inventories local ACVP, Wycheproof, CCTV, and x509-limbo data and lists useful gaps without enabling unreviewed tests. | Follow-up tests should be added only when PKCS#11 can actually express the vector input. |
| X.509 limbo stress import boundary | Valid after tightening. A provider may reject malformed Limbo material during `C_CreateObject`, but arbitrary Python exceptions in the harness should not be swallowed as acceptable rejects. The stress tests now only treat `AssertionError` from raw CKR helpers as import rejection. | Other older X.509/object tests still contain broader compatibility catches and should be narrowed only with focused evidence and regression coverage. |

## Provider-Result Interpretation

The result table for the article should avoid a single "best provider" ranking.
A better interpretation is:

- "passed" means the provider produced the expected behavior for the tested
  PKCS#11-visible operation;
- "xfailed" means the suite saw a known or classified non-clean provider result,
  not a pass;
- "skipped" mixes missing mechanisms, unsupported interface versions, and exact
  duplicate vector encodings, so it needs a short explanation in any public
  table;
- "crashed" and "timeout" are first-class findings, even if the rest of a
  provider has good mechanism coverage.

## Required Before Commit

- Finish the current provider rerun or stop it with an explicit partial-results
  note.
- Compare every completed target with the baseline snapshot and update the
  rerun note.
- Run focused regression tests, `ruff`, full meta-tests, `mypy`, and
  `git diff --check` after the final edit.
- Commit only source/docs/tests/artifacts intentionally changed for this work;
  leave unrelated `.claude/` untracked.
