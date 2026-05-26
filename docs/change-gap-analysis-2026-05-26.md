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
| EdDSA public-key encoding and runtime classification | Valid after focused rerun. The local OASIS spec tree requires raw RFC 8032 bytes for `CKK_EC_EDWARDS` `CKA_EC_POINT`, but current providers differ in practice. Vector tests now probe the provider profile with a known-good signature before running ACVP/Wycheproof rows, trying raw and DER-wrapped public points plus NULL and explicit `CKM_EDDSA` parameter modes. A dedicated `test_eddsa_public_key_encoding_support` row keeps the spec-facing result visible: raw support is clean, DER-only support is xfail evidence, and neither profile working is xfail evidence. Runtime rejects from unsupported curves remain skips. | Article wording must separate the standalone spec-facing encoding result from vector crypto coverage. The adaptive profile lets valid vectors run on DER-only or explicit-param providers, but the dedicated encoding test is the row that says whether the provider follows the raw `CKA_EC_POINT` convention. |
| EdDSA mechanism parameters | Valid after focused rerun. The helper no longer assumes a single provider interpretation of pure EdDSA: it probes NULL `CKM_EDDSA` and the raw helper's explicit `CK_EDDSA_PARAMS` form. NSS returned `CKR_FUNCTION_NOT_SUPPORTED` for the NULL profile and then worked with explicit params; Kryoptic worked with NULL params; SoftHSM2's focused result was dominated by point encoding rather than parameter mode. Only specific profile-reject CKRs are swallowed during probing. | Full matrix statistics still need a clean rerun, but the focused SoftHSM2/Kryoptic/NSS evidence is enough to avoid mislabeled EdDSA parameter-mode failures in the current article draft. |
| ACVP ML-KEM key generation runtime rejects | Valid after focused NSS-family rerun. `CKR_PARAMETER_SET_NOT_SUPPORTED` during ML-KEM-512 public-key import remains a capability skip, but `CKR_HOST_MEMORY` during advertised ML-KEM key generation is now xfail evidence rather than a hard harness failure. Focused current-source `nss`, `nss-main`, and `nss-pqc` runs all report 72 passed, 107 skipped, 1 xfailed, and 0 hard failures for `test_acvp_mlkem.py`. | The xfail is still a provider finding, not a clean pass. Full matrix statistics need a rerun before article tables use the reduced hard-failure count. |
| Wycheproof ECDH/XDH deduplication | Valid. Fingerprints include curve/OID, decoded public input, decoded private input, shared secret, and expected result. Exact duplicates are skipped after capability checks. | Earlier Docker artifacts must be rerun before article statistics use the reduced buckets. |
| Wycheproof ECDSA/DSA deduplication and digest normalization | Valid. PKCS#11 receives raw `r || s`, so DER/P1363 rows that normalize to the same public key, digest/message, signature, mechanism, and result are duplicate provider inputs. ECDSA fixed-width P1363 `SignatureSize` negatives are also not provider-neutral when the raw signature is a shorter even-length `r || s` form allowed by the current PKCS#11 spec. DSA public-key imports now also strip Wycheproof's ASN.1-style sign padding from `Big integer` attributes before calling `C_CreateObject`. ECDSA P-521/SHAKE256 now uses the Wycheproof-compatible 64-byte SHAKE256 output before raw `CKM_ECDSA` verification, rather than the 66-byte coordinate width. Focused SoftHSM2 and NSS stable ECDSA reruns on current source now show 0 hard failures for the ECDSA file; three representative old OpenCryptoki P-521/SHAKE256 failures also pass on current source. | Invalid vectors whose only invalidity was DER container metadata, Bitcoin low-S policy, fixed-width P1363 size policy, third-party integer container padding, or wrong harness XOF length must be described as loader-normalized or version-sensitive skips/fixes, not provider passes. Earlier matrix rows that still show ECDSA hard failures from the P-521/SHAKE256 family need a refreshed full run before use in article tables. |
| Wycheproof RSA/RSA-PSS deduplication and integer normalization | Valid. Fingerprints include mechanism, mechanism parameters where applicable, public key, message, and signature. RSA public/private key imports now strip third-party ASN.1-style sign padding from PKCS#11 `Big integer` attributes, matching the same rule used for DSA. | Need refreshed Docker rows because this patch landed after several targets had already started. RSA PKCS#1 decrypt rows where invalid ciphertext is accepted remain provider/security findings, not loader-padding artifacts. |
| Wycheproof RSA PKCS#1 decrypt runtime classification | Valid after focused pkcs11-mock rerun. Current source keeps accepted invalid ciphertext as a hard failure, but treats valid-vector `C_Decrypt` runtime CKRs from an advertised `CKM_RSA_PKCS` path as visible xfail evidence. The pkcs11-mock focused run moved its old RSA decrypt hard bucket to 77 passed, 124 xfailed, and 0 failed after adding `CKR_KEY_TYPE_INCONSISTENT` to that valid-vector runtime-reject set. | This does not make RSA PKCS#1 decrypt compliance clean. Article wording should call these rows advertised-but-not-operational evidence, and should keep provider/security wording for targets that return plaintext for invalid ciphertext. |
| Kryoptic RSA signature buckets | Valid after focused rerun. Current-source focused runs of Wycheproof RSA-PSS and RSA PKCS#1 signature vectors now have 0 hard failures for Kryoptic. The remaining large counts are duplicate skips and xfails where Kryoptic rejects invalid or acceptable signatures with `CKR_DEVICE_ERROR`; that is non-clean provider evidence, not a pkcs11-check vector-loader failure. | Article tables must not use the old Kryoptic RSA-PSS/RSA hard-failure buckets without a refreshed matrix. The xfail counts should be described as non-clean invalid-signature rejection, not clean pass. |
| ACVP KeyGen deduplication | Valid with a standards caveat. Current PKCS#11 key-generation APIs do not accept ACVP internal-projection seeds, so only the provider-visible parameter set can be tested. | Documentation must continue saying this is not an exact ACVP KeyGen reproduction. |
| OpenCryptoki ACVP AES-XTS | Valid provider finding after focused rerun. The local OASIS spec tree defines `CKM_AES_XTS` with a 16-byte data-unit sequence number parameter, same-length output, and `CKK_AES_XTS` double-length keys. Current pkcs11-check sends ACVP `tweakValue` as that 16-byte parameter. A current-source OpenCryptoki focused rerun still produced ciphertext/plaintext mismatches after `CKR_OK` and xfails for advertised-but-rejected XTS rows. | This remains a provider behavior or provider/vector-interpretation issue, not an obvious normalization bug. Deeper follow-up could compare OpenCryptoki's internal XTS tweak handling against NIST SP800-38E/IEEE 1619, but pkcs11-check should keep the ACVP exact-output rows strict. |
| OpenCryptoki generic Wycheproof AES-CBC-PAD | Valid provider/security finding after focused rerun. The generic Wycheproof AES-CBC-PAD test sends `CKM_AES_CBC_PAD` decrypt inputs directly from `aes_cbc_pkcs5_test.json`; current OpenCryptoki still returns plaintext instead of rejecting 144 invalid padding vectors across all three AES key sizes. | Keep this as accepted-invalid-input evidence. It is not similar to the ECDSA/ECDH normalization fixes because no container metadata is stripped before the provider sees the ciphertext and IV. |
| OpenCryptoki unwrap-template fallback | Conditionally valid. The OASIS PKCS#11 specification `C_UnwrapKey` section allows `CKA_CLASS` and `CKA_KEY_TYPE` in unwrap examples, and says unsupported precise templates fail (<https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html>). For mechanism-level roundtrips, retrying without these identifiers is useful only if the unwrapped key is then verified cryptographically and a compliance note is emitted. | Pass counts alone can overstate compliance. Results should include compliance notes or a separate "template quirk retried" note for OpenCryptoki. |
| NSS X448 and HKDF lifecycle classification | Valid after focused rerun. `CKR_DOMAIN_PARAMS_INVALID` on the X448 keygen row is a missing-curve capability skip, not a mechanism-level failure, because NSS still supports X25519. HKDF lifecycle now classifies `CKM_HKDF_KEY_GEN` setup rejects such as `CKR_MECHANISM_INVALID` as advertised-but-not-operational xfail evidence. A current-source NSS focused run of ECDH extended, HKDF extended/basic/lifecycle, Wycheproof X25519/X448, and Wycheproof HKDF has 0 failed and 0 crashed. | This is not a clean HKDF implementation result: the HKDF lifecycle row is still xfail evidence. Article wording should distinguish skipped X448 curve support from HKDF advertised-runtime rejects. |
| Basic HKDF derive catch boundary | Valid after regression. `test_hkdf_derive_basic` now only converts PKCS#11 `AssertionError`/CKR paths into xfail evidence. Python-side bugs whose messages happen to contain a CKR name propagate as real failures instead of becoming provider xfails. | Other older KDF/object tests still contain broad compatibility catches and should be narrowed only with focused evidence and regression coverage. |
| TPM2 interop/crossverify operation rejects | Valid after focused rerun. Current-source `test_interop.py`, `test_crossverify.py`, and `test_crossverify_extended.py` on TPM2 report 23 passed, 4 skipped, 14 xfailed, 0 failed, and 0 crashed. AES/HMAC operations that reach an advertised mechanism and return `CKR_GENERAL_ERROR` are now visible advertised-but-not-operational xfail evidence. | This is not a clean interop result. Exact ciphertext, plaintext, digest, MAC, or signature mismatches after `CKR_OK` remain hard failures. |
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
