# Provider Rerun Notes - 2026-05-26

These notes preserve the deliberate provider rerun requested for the
pkcs11-check report/article work. The run used source commit `e03900a`; the
adaptive crash-reporting fix was merged after the batch completed, so the
artifacts below still reflect the pre-fix runner behavior.

Artifacts:

- Baseline snapshot:
  `artifacts/_baseline-before-provider-rerun-e03900a-20260525T201849Z`
- Comparison output:
  `artifacts/_provider-rerun-e03900a-20260525T201849Z/comparisons`
- Per-provider results:
  `artifacts/<target>/results.json` and `artifacts/<target>/report.jsonl`

Excluded targets: `bouncyhsm` because it is too slow for this iteration, and
`qryptotoken` because it no longer provides useful mechanism coverage.

## Current Dev Rerun Completed

This rerun was requested after commit `918a0bd` with targets:

`softhsm2 softhsm2-generated-iv softhsm2-main kryoptic kryoptic-main
kryoptic-fips nss nss-pqc nss-main opencryptoki opencryptoki-master tpm2
pkcs11-mock`

Baseline snapshot:
`artifacts/_baseline-before-provider-rerun-918a0bd-20260526T025257Z`.

Change-gap review:
[`change-gap-analysis-2026-05-26.md`](change-gap-analysis-2026-05-26.md).

Important caveat: the first completed targets were started before the local
signature-classification and raw subprocess-reporting patches in this working
tree. Stable `kryoptic` was rerun after those patches. The Wycheproof ECDH/XDH
duplicate-skip patch landed while the NSS family was running: `nss` does not
include it, while `nss-pqc` and later targets do.

The Docker command completed with provider failures, not an infrastructure
failure. The final batch passed only `tpm2` and `pkcs11-mock` as Docker targets;
the other targets completed with ordinary pkcs11-check failed tests. Because
source fixes landed during the long run, this section is a traceable engineering
snapshot, not release statistics.

Completed summary:

| Target | Passed | Failed | Skipped | Xfailed | Total | Main delta vs baseline |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `softhsm2` | 59,499 | 1,138 | 16,521 | 4,993 | 82,151 | RSA-PSS invalid-vector rejects moved from fail to xfail: failed -91, xfailed +91. |
| `softhsm2-generated-iv` | 59,501 | 1,138 | 16,519 | 4,993 | 82,151 | RSA-PSS failed -91/xfailed +91; ECDSA timing variance produced one new security failure. |
| `softhsm2-main` | 60,931 | 1,155 | 15,781 | 5,063 | 82,930 | RSA-PSS failed -91/xfailed +91; ML-DSA setup rejects moved skipped -19/xfailed +19; one new padding-oracle result; total +1 from threading. |
| `kryoptic` | 65,881 | 2,174 | 33,265 | 7,337 | 108,657 | Rerun with current patches: EdDSA runtime rejects failed -7/xfailed +7; wrong-signature rejects failed -2/xfailed +2; ML-DSA skipped -6/xfailed +6. |
| `kryoptic-main` | 65,895 | 2,165 | 33,264 | 7,333 | 108,657 | EdDSA runtime rejects failed -7/xfailed +7; wrong-signature rejects in `test_sign.py` failed -2/xfailed +2; ML-DSA skipped -6/xfailed +6; one new padding-oracle result. |
| `kryoptic-fips` | 52,187 | 1,867 | 33,067 | 5,447 | 92,580 | Clean-policy rerun preserved 12 crashes; EdDSA/RSA wrong-signature/ML-DSA setup rejects moved into xfail; failures -67, xfailed +74. |
| `nss` | 49,012 | 787 | 42,774 | 442 | 93,018 | DSA valid-runtime rejects failed -126/xfailed +126; ML-DSA skipped -19/xfailed +19; `test_sign.py` failed -3/xfailed +3; crashes unchanged at 3. |
| `nss-pqc` | 40,511 | 749 | 50,684 | 374 | 92,322 | Includes ECDH/XDH duplicate skip: ECDH passed -5,511/skipped +5,511; XDH passed -1,555/skipped +1,555; DSA failed -126/xfailed +126; crashes unchanged at 4. |
| `nss-main` | 40,510 | 750 | 50,684 | 374 | 92,322 | Same ECDH/XDH duplicate-skip shape as `nss-pqc`; DSA failed -126/xfailed +126; `test_mech_sign.py` failed -3/xfailed +3; crashes unchanged at 4. |
| `opencryptoki` | 63,905 | 918 | 30,904 | 1,675 | 97,402 | Includes ECDH/XDH and ECDSA duplicate skips: ECDH passed -7,023/skipped +7,023; XDH passed -3,087/skipped +3,087; ECDSA passed -5,145/failed -235/skipped +5,476/xfailed -96; RSA-PSS failed -91/xfailed +91. |
| `opencryptoki-master` | 62,890 | 908 | 32,111 | 1,493 | 97,402 | Later target picked up ECDH/XDH, ECDSA/DSA, RSA/RSA-PSS, and ACVP KeyGen duplicate normalization: ECDH skipped +7,023; XDH skipped +3,087; ECDSA failed -235/skipped +5,476; RSA-PSS failed -91/skipped +913. |
| `tpm2` | 8,306 | 422 | 68,568 | 4,108 | 81,404 | Later target includes most vector duplicate/projection skips: failures -330, skips +1,435. Remaining top buckets include RSA-PSS 82, ACVP RSA 27, and security crash-probe/provider-behavior files. |
| `pkcs11-mock` | 1,326 | 2,431 | 28,666 | 214 | 32,637 | Synthetic harness-stress target: failures -249, skipped +66, xfailed +194 after ACVP RSA, keygen projection, attribute/export, and capability-guard classification. |

Completed high-signal observations:

- SoftHSM2 variants remain dominated by valid DSA/ECDSA signature rejections,
  invalid RSA PKCS#1 decrypt acceptance, arithmetic-overflow subprocess
  crashes, EdDSA/ML-DSA vector failures, wrong CKRs on wrap/OAEP paths, and
  security checks such as Tookan sensitive unwrap and padding-oracle behavior.
- `softhsm2-generated-iv` avoids the GCM null-IV crash path that plain SoftHSM2
  still exposes, but otherwise has the same dominant result shape.
- Kryoptic-main keeps the important provider findings visible: RSA-PSS,
  Ed25519, RSA PKCS#1 decrypt, ML-DSA, FFI length-boundary crashes/timeouts,
  Rust capacity panics, NULL-pointer crashes, generated IV/nonce writeback
  gaps, AES-CBC-ENCRYPT-DATA IV-insensitivity, Tookan sensitive unwrap, and
  trusted-attribute escalation.
- The current pkcs11-check fixes do not hide crashes. They only improve
  classification for non-clean invalid-signature rejects and wording for child
  subprocess assertion exits versus actual signal crashes.
- Wycheproof ECDH/XDH container variants need special handling. Some vectors
  are distinct after decoding, for example `ecdh_secp256k1_test.json:tc70` and
  `ecdh_secp256k1_webcrypto_test.json:tc70` have different public points and
  shared secrets. Many ASN/PEM/ECPOINT/JWK/WebCrypto vectors collapse to the
  same PKCS#11-visible inputs because the module receives only curve params,
  the raw public point, and the private scalar. Current source now counts exact
  decoded-operation duplicates as skips before provider calls: 7,023 of 13,128
  ECDH vectors and 3,087 of 4,176 XDH vectors are duplicate encodings. The
  `nss-pqc` and later Docker artifacts include this patch; earlier artifacts
  still include the old duplication until those targets are rerun.
- Wycheproof ECDSA/DSA DER-vs-P1363 signature variants have the same issue.
  PKCS#11 receives raw `r || s`, so a DER vector and a P1363 vector that
  normalize to the same public key, message/digest, signature, and mechanism
  are not independent provider tests. Current source now skips 6,707 of 28,915
  ECDSA vectors and 442 of 1,956 DSA vectors as exact PKCS#11-input
  duplicates. This also prevents DER-only or Bitcoin low-S policy metadata from
  being reported as a provider failure after pkcs11-check has normalized the
  signature to raw ECDSA/DSA form. A later source review also found
  fixed-width P1363 `SignatureSize` negative vectors where the raw ECDSA
  signature is a shorter even-length `r || s` value that current PKCS#11
  verification permits; those are now treated as version-sensitive skips. The
  same review found that Wycheproof DSA public-key integers can carry leading
  sign-padding bytes; current source strips that padding before PKCS#11 import.
  A focused SoftHSM2 DSA rerun moved from 296 valid-signature failures to 0
  failures, with 613 passed and 1,343 skipped out of 1,956 collected vectors.
  A later focused SoftHSM2 ECDSA rerun found that P-521/SHAKE256 valid vectors
  need SHAKE256(64), not the 66-byte P-521 coordinate width, before raw
  `CKM_ECDSA`; current source no longer shows that valid-vector rejection
  pattern. A focused NSS stable ECDSA rerun on current source likewise removed
  the old NSS-family ECDSA hard-failure bucket: 6,832 passed and 22,083 skipped
  out of 28,915 collected vectors, with 0 failed. The skips were mostly exact
  PKCS#11-visible duplicates, unsupported curves, and version-sensitive
  short-P1363 signature-size rows. Evidence directory:
  `artifacts/_focused/nss-ecdsa-current-after-shake`.
  These patches landed while the current batch was running or after it
  completed, so a later full rerun is needed before Docker statistics reflect
  them.
- Wycheproof RSA signature vectors also contain exact PKCS#11-input
  duplicates, though at a smaller scale: current source skips 913 of 2,502
  RSA-PSS vectors and 75 of 5,313 RSA PKCS#1 signature vectors when the
  mechanism, parameters, public key, message, and signature are identical.
  A later source review found the same third-party integer-padding issue as DSA:
  Wycheproof RSA public/private key fields can carry ASN.1-style leading `00`
  sign bytes, while PKCS#11 RSA attributes are unsigned `Big integer` values.
  Current source strips that padding before RSA key import and duplicate
  grouping. A focused SoftHSM2 RSA rerun no longer showed RSA-PSS, RSA
  signature verification, or RSA-OAEP failures from the padded imports; RSA
  PKCS#1 decrypt still showed accepted-invalid-ciphertext failures, which
  remain provider/security findings. These changes landed after the current
  Docker batch had already started, so the affected artifacts still need a
  refresh before the table reflects them.
  A later focused Kryoptic rerun on current source also removed the old hard
  RSA signature buckets: RSA-PSS produced 1,146 passed, 913 duplicate skips,
  and 443 xfailed invalid-vector rejects, with 0 failed; RSA PKCS#1 signature
  verification produced 252 passed, 75 skipped, and 4,986 xfailed invalid or
  acceptable-vector rejects, with 0 failed. Those xfails are mostly Kryoptic
  returning `CKR_DEVICE_ERROR` for invalid signature verification, so they are
  non-clean provider evidence rather than clean passes. Evidence directories:
  `artifacts/_focused/kryoptic-rsapss-current` and
  `artifacts/_focused/kryoptic-rsa-signature-current`.
  A focused current-source rerun of the older generic Wycheproof file for
  Kryoptic now also completes with 1,555 passed, 398 xfailed, and 0 failed, so
  the small old generic RSA-signature failure bucket is stale pre-fix evidence.
  Evidence directory:
  `artifacts/_focused/kryoptic-generic-wycheproof-current-20260526`.
- ACVP KeyGen internal-projection vectors contain seeds and expected keys that
  current PKCS#11 key-generation APIs cannot consume. The suite now keeps those
  vectors collected but skips duplicate provider-visible inputs after the first
  representative: RSA 27/30, ECDSA 17/20, EdDSA 4/6, ML-DSA 72/75, and ML-KEM
  72/75 duplicate-to-skip. Future PKCS#11 revisions could standardize
  deterministic validation inputs for exact ACVP KeyGen checks, but there is no
  portable API for that today.
- Focused EdDSA public-key encoding checks after the batch found provider
  profile differences that should not be collapsed into generic vector
  failures. PKCS#11 `CKK_EC_EDWARDS` uses raw RFC 8032 `CKA_EC_POINT`, but
  SoftHSM2 verified the RFC 8032 Ed25519 vector only with a DER-wrapped point
  and is now reported by the standalone encoding test as xfail. Kryoptic passed
  the standalone encoding test with a raw point and NULL `CKM_EDDSA` params.
  NSS passed with a raw point after falling back from NULL params
  (`CKR_FUNCTION_NOT_SUPPORTED`) to explicit EdDSA params; Ed448
  `CKR_DOMAIN_PARAMS_INVALID` is now treated as unsupported-curve skip during
  the probe. With adaptive ACVP EdDSA probing, the remaining focused failures
  are invalid-key acceptance findings: four for SoftHSM2, four for Kryoptic,
  and two Ed25519 cases for NSS. Evidence directories:
  `artifacts/_focused/softhsm2-eddsa-adaptive-profile-v3`,
  `artifacts/_focused/kryoptic-eddsa-adaptive-profile-v3`, and
  `artifacts/_focused/nss-eddsa-adaptive-profile-v3`.
- `kryoptic-fips` was rerun after clearing stale adaptive per-test isolation
  policy. The clean run still discovered the AES-CCM and Wycheproof AES crash
  culprits and preserved the same 12-crash count instead of hiding them.
- NSS-family crashes remain real provider findings. In the Fedora package run,
  `test_mech_flags.py` isolated `libsoftokn3.so` segfaults in MAC-general
  `C_SignInit` probes, hit the per-file crash limit, and then skipped the rest
  of that file as designed.
- Focused current-source NSS-family ML-KEM reruns moved the old ML-KEM-512
  `CKR_HOST_MEMORY` key-generation bucket into visible xfail evidence. The
  `nss`, `nss-main`, and `nss-pqc` focused runs for `test_acvp_mlkem.py` each
  ended with 72 passed, 107 skipped, 1 xfailed, and 0 hard failures. Evidence
  directories:
  `artifacts/_focused/nss-mlkem-current-after-host-memory-20260526`,
  `artifacts/_focused/nss-main-mlkem-current-after-host-memory-20260526`, and
  `artifacts/_focused/nss-pqc-mlkem-current-after-host-memory-20260526`.
- OpenCryptoki stayed crash-free in this rerun. After ECDH/XDH/ECDSA duplicate
  normalization, its largest failed buckets in the batch artifact were ACVP
  AES-XTS 382, Wycheproof ECDSA 234, generic Wycheproof 144, RSA PKCS#1 decrypt
  59, and Wycheproof AES 27. Later current-source checks split those buckets:
  three representative old P-521/SHAKE256 ECDSA failures now pass after the
  SHAKE256(64) loader fix, so the ECDSA bucket must be treated as pre-fix
  harness evidence until a full ECDSA refresh completes. The generic
  Wycheproof bucket still reproduces on current source as 144 AES-CBC-PAD
  invalid-padding acceptances across 128-, 192-, and 256-bit AES keys. Evidence
  directories: `artifacts/_focused/opencryptoki-ecdsa-shake-representatives-20260526`
  and `artifacts/_focused/opencryptoki-generic-wycheproof-current-20260526`.
- A focused current-source OpenCryptoki AES-XTS rerun confirmed the old XTS
  bucket is still live: 218 passed, 382 failed with ciphertext/plaintext
  mismatches after `CKR_OK`, and 600 xfailed with
  `CKR_MECHANISM_PARAM_INVALID` after `CKM_AES_XTS` was advertised. The local
  OASIS spec tree defines `CKM_AES_XTS` with a 16-byte data-unit sequence
  number parameter and same-length output for inputs of at least one block; the
  pkcs11-check test sends the ACVP `tweakValue` as that 16-byte parameter and
  compares exact ACVP ciphertext/plaintext. This remains provider behavior or
  provider/vector-interpretation evidence, not an obvious pkcs11-check loader
  issue. Evidence directory:
  `artifacts/_focused/opencryptoki-xts-current`.
- The current OpenCryptoki artifacts also predate the AES-KWP error-path
  harness fix. A current Docker rerun of `security/test_error_path_kwp.py` and
  `security/test_error_path_rsa.py` against OpenCryptoki master + OpenSSL 4.0.0
  produced 42 passes and 8 KWP decrypt guard-overwrite failures in
  `artifacts/_focused/opencryptoki-master-error-path-current-20260527/`. The
  RSA error-path rows passed after the generated-script fix. Do not use the
  older KWP 42/42 pass result as evidence that the OpenSSL-side KWP issue is
  fixed.
- The `opencryptoki-master` artifact picked up later vector deduplication than
  `opencryptoki`, including RSA/RSA-PSS and ACVP KeyGen projection skips. It
  still predates the corrected KWP/RSA subprocess harness, because the security
  files ran before that local fix landed.
- `tpm2` improved mostly from vector duplicate/projection skips and runtime
  classification, but the remaining findings are mixed. Real provider findings
  include RSA-PSS valid/invalid semantic failures, `C_Digest` length-boundary
  SIGSEGV evidence, `fork_after_initialize` timeout, threaded-random TPM2-TSS
  errors, and non-modifiable X.509 certificate labels being mutable. Some
  security crash-probe failures in the artifact were harness setup noise from
  child-side AES/RSA/EC key generation; current source now preflights those
  setup operations before entering the crash child.
- `pkcs11-mock` remains useful for shaking out harness assumptions rather than
  for provider-compliance wording. Its large X.509, RSA-OAEP, object, multipart,
  and digest buckets mostly reflect synthetic placeholder behavior, small
  advertised mechanism surface, and session/object constraints. The latest
  NULL-pointer subprocess preflight fix also postdates this artifact, so do not
  use its old `security/test_ffi_null_pointer.py` failures as crash evidence.
- A final current-source rerun is still needed before article numbers are
  official. The useful article material from this pass is the shape of findings
  and the test-suite hardening work, not exact percentages.

## Summary Table

| Target | Passed | Failed | Skipped | Xfailed | Crashed | Timeout | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `softhsm2` | 59,499 | 1,229 | 16,521 | 4,902 | 0 | 0 | 82,151 |
| `softhsm2-generated-iv` | 59,502 | 1,228 | 16,519 | 4,902 | 0 | 0 | 82,151 |
| `softhsm2-main` | 60,931 | 1,245 | 15,800 | 4,953 | 0 | 0 | 82,929 |
| `kryoptic` | 65,881 | 2,183 | 33,271 | 7,322 | 0 | 0 | 108,657 |
| `kryoptic-main` | 65,896 | 2,173 | 33,270 | 7,318 | 0 | 0 | 108,657 |
| `kryoptic-fips` | 52,188 | 1,934 | 33,073 | 5,373 | 12 | 0 | 92,580 |
| `nss` | 49,019 | 916 | 42,786 | 294 | 3 | 0 | 93,018 |
| `nss-pqc` | 47,583 | 879 | 43,611 | 245 | 4 | 0 | 92,322 |
| `nss-main` | 47,584 | 878 | 43,611 | 245 | 4 | 0 | 92,322 |
| `opencryptoki` | 79,160 | 1,244 | 15,318 | 1,680 | 0 | 0 | 97,402 |
| `opencryptoki-master` | 79,160 | 1,244 | 15,318 | 1,680 | 0 | 0 | 97,402 |
| `tpm2` | 9,319 | 752 | 67,133 | 4,200 | 0 | 0 | 81,404 |
| `pkcs11-mock` | 1,337 | 2,680 | 28,600 | 20 | 0 | 0 | 32,637 |

## High-Signal Findings

- SoftHSM2 results are dominated by Wycheproof DSA/ECDSA, RSA-PSS, and RSA
  decrypt findings. `softhsm2-main` adds a visible ML-DSA surface. The main
  run also exposed a threaded keygen/destroy crash pattern that the pre-fix
  adaptive runner could hide if the isolated culprit passed later.
- Kryoptic has broad coverage and many real FFI/API-boundary findings,
  including NULL-pointer crashes, length-boundary crashes, extreme-size panics,
  RSA-PSS/Ed25519/ML-DSA failures, and policy issues around sensitive/trusted
  attributes. The FIPS build additionally has runner-level crashes in AES-CCM,
  AES mechanism paths, and KDF paths.
- NSS package/tagged/main variants show similar shapes: ECDSA/DSA/RSA-decrypt
  failures, AES-KWP mismatches, ML-KEM keygen failures, CTS advertisement that
  is not operational, and crashes in MAC flag probes. Tagged/main builds also
  crash on an HMAC-with-RSA-key negative probe.
- OpenCryptoki and OpenCryptoki master were identical in this batch. Largest
  buckets are ECDSA, AES-XTS, AES-CBC-PKCS5 invalid padding, RSA-PSS non-clean
  rejects, and RSA PKCS#1 decrypt behavior. No runner-level crashes were
  recorded. The VerifySignature multipart failure is on the actual
  `C_VerifySignatureUpdate` path, not setup signing.
- TPM2 has the most setup/capability noise. Many tests reach advertised
  mechanisms but fail because AES keygen returns `CKR_FUNCTION_NOT_SUPPORTED`,
  imported secret-key operations require attributes such as
  `CKA_ALLOWED_MECHANISMS`, and generated RSA/EC attributes can be malformed or
  provider-specific. Subprocess crash probes for raw invalid calls still remain
  visible as test failures, even though the final runner summary has
  `crashed=0`.
- `pkcs11-mock` is useful as a harness-stress target, not as a production
  compliance signal. It advertises a small and synthetic surface, returns many
  placeholder values, and exposes places where pkcs11-check should produce
  clearer xfail/failure wording instead of raw Python arithmetic or encoding
  errors.

## Post-Run Fix Decisions

- Adaptive crash findings must stay visible even when the suspected isolated
  test later passes. The runner fix from `fix/adaptive-crash-report` was merged
  after this batch and verified with focused regression tests.
- Negative signature verification has three categories:
  clean reject (`CKR_SIGNATURE_INVALID` / `CKR_SIGNATURE_LEN_RANGE`), non-clean
  reject (`xfail` evidence), and accepted invalid signature (hard failure).
  The non-clean reject set now includes explicit runtime CKRs observed in this
  batch, including `CKR_ARGUMENTS_BAD`, `CKR_MECHANISM_INVALID`,
  `CKR_MECHANISM_PARAM_INVALID`, `CKR_KEY_TYPE_INCONSISTENT`, and
  `CKR_FUNCTION_NOT_SUPPORTED`.
- EdDSA vector loaders now start from the raw RFC 8032 public-key bytes
  required for `CKK_EC_EDWARDS` `CKA_EC_POINT`, then probe raw versus
  DER-wrapped point import and the two observed `CKM_EDDSA` parameter modes
  with a known-good signature. The local PKCS#11 spec tree says Edwards
  public-key objects store the public key bytes directly; DER OCTET STRING
  wrapping applies to classic `CKK_EC` ANSI X9.62 points, not Edwards keys.
  The dedicated `test_eddsa_public_key_encoding_support` row remains the
  spec-facing result: raw support passes cleanly, DER-only support is visible
  xfail evidence, and the vector rows use the working profile so they still
  measure signature behavior where possible.
- Padding-oracle structured RSA tests now treat malformed generated RSA public
  modulus/exponent attributes as an xfail setup finding instead of crashing with
  Python `ValueError`.
- ACVP ECDH generated-key probes now treat malformed `CKA_EC_POINT` readback as
  xfail evidence instead of a raw DER decoding exception.
- Continued raw-error triage found the same malformed-attribute pattern in
  pkcs11-mock: CK_ULONG and CK_BBOOL attributes can be returned as empty byte
  strings. Attribute-default, mechanism-attribute, and key-generation-mechanism
  tests now report those as xfail setup/readback findings instead of raw Python
  conversion/assertion failures.
- RSA cross-verification and interop tests now validate exported RSA attributes
  before constructing `cryptography` keys. Missing private-key components and
  malformed public modulus/exponent values are xfail export findings, covering
  the TPM2 `CKA_PRIVATE_EXPONENT` gap and pkcs11-mock `n must be >= 3` cases.
- Raw operation-state subprocess tests now distinguish setup failure from crash:
  if the subprocess cannot generate the AES setup key, the test xfails with the
  setup CKR; non-zero subprocess exit and signals still fail as crash evidence.
- Dual-function and same-session operation-state raw subprocess tests now
  preflight required AES/SHA mechanisms in the parent. A focused pkcs11-mock
  rerun in `artifacts/_focused/pkcs11-mock-dual-operation-r2-20260527/`
  reports 3 passed, 5 skipped, and 0 failed for those two files, replacing old
  hard setup rows from missing AES/SHA support.
- Legacy access/session tests now share the same setup boundary as the newer
  access-level files. A focused pkcs11-mock rerun in
  `artifacts/_focused/pkcs11-mock-access-r2-20260527/` reports 1 passed,
  7 skipped, and 0 failed; the skips are one missing `AES_KEY_GEN` precondition
  and six `CKR_SESSION_COUNT` extra-session limits.
- API-security tests now use explicit setup classification instead of treating
  setup rejection as a security result. A focused pkcs11-mock rerun in
  `artifacts/_focused/pkcs11-mock-api-security-r2-20260527/` reports
  11 skipped and 1 failed; the remaining failed row is readable
  `CKA_PRIVATE_EXPONENT` after RSA setup succeeds.
- Data-object tests now skip extra-session capacity limits for token-object
  persistence while keeping storage/readback/search checks strict. A focused
  pkcs11-mock rerun in
  `artifacts/_focused/pkcs11-mock-data-objects-r2-20260527/` reports
  3 passed, 1 skipped, and 9 failed; the failed rows are CKO_DATA storage and
  search behavior, not setup failures.
- Property-fuzz tests now preflight required mechanisms before Hypothesis
  operation loops. A focused pkcs11-mock rerun in
  `artifacts/_focused/pkcs11-mock-fuzz-r2-20260527/` reports 11 skipped and
  0 failed, replacing old hard falsifying examples caused by absent AES-ECB,
  SHA-2, RSA-SHA256, HMAC, and ECDSA mechanisms.
- Remaining-gap and subprocess-safety focused TPM2 evidence:
  `artifacts/_focused/tpm2-remaining-sign-safety-r2-20260527/`. Current source
  reports 6 passed, 23 skipped, 8 xfailed, and 1 failed across
  `test_remaining_gaps.py`, `test_sign_recover.py`, and
  `test_subprocess_safety.py`. The former hard template/legacy/sign-recover
  setup rows are now setup xfails or compliance notes; the remaining hard row
  is the fork-after-initialize timeout. The fork test now parses explicit child
  status, so a non-zero child exit or child signal is a hard result even if the
  parent process exits normally. Focused pkcs11-mock evidence:
  `artifacts/_focused/pkcs11-mock-fork-safety-current-20260527/`.

## Remaining Raw-Looking Buckets

- Kryoptic `test_generate_key_oom_value_len` timeouts remain real provider
  hangs in the FFI length-boundary probe, not a pkcs11-check classification gap.
- Message-crypto generated IV/nonce assertions remain provider behavior: the
  provider completed the operation but did not write the generated IV/nonce back
  through the PKCS#11 message API parameter.
- AES-KWP ciphertext mismatches, buffer-size writeback mismatches, CTS detection
  failures, and padding-oracle/security findings are semantic provider results,
  not raw harness exceptions.
- Broad catch-all exception handling still exists in older test files. This pass
  tightened the x509-limbo stress import boundary because it was tied to a large
  current mock bucket; the remaining catches are a separate cleanup track and
  should be narrowed only with focused evidence and regression coverage.

## Focused Post-Fix Reruns

These are targeted reruns used to validate classification fixes. They are not
official full-matrix release statistics.

- `pkcs11-mock` focused artifacts:
  `artifacts/_focused/pkcs11-mock-post-38c12f8-r4`. The same 9-file focus list
  moved from 37 failures in `r3` to 7 failures in `r4`. Attribute enforcement,
  mechanism attribute readback, raw operation-state setup, and interop all moved
  out of raw failure buckets.
- `pkcs11-mock` mechanism probing showed the mock advertises only 9 mechanisms.
  The interop and crossverify files were missing guards for absent mechanisms
  such as `AES_ECB`, `SHA256_RSA_PKCS`, `SHA256`, HMAC, and ECDSA. After adding
  those guards, `test_interop.py` moved from 13 failures to 13 skips plus 2
  xfails. `test_crossverify.py` moved from 18 failures to one remaining failure:
  advertised `CKM_SHA_1` returns a digest mismatch. Remaining mock failures are
  therefore provider/mock behavior: SHA-1 digest mismatch, advertised AES-CBC
  returning `CKR_KEY_TYPE_INCONSISTENT`, and RSA-OAEP semantic failures.
- `pkcs11-mock` standalone KAT focused artifact:
  `artifacts/_focused/pkcs11-mock-kat-r2-20260527/`. The focused `test_kat.py`
  run moved from 10 failed / 10 skipped / 1 xfailed to 2 failed / 18 skipped /
  1 xfailed. pkcs11-mock does not advertise `CKM_AES_ECB`, so the old AES-ECB
  KAT `CKR_MECHANISM_INVALID` rows were missing-capability guard noise. The two
  remaining hard rows are SHA-1 digest mismatches after `CKR_OK`, which remain
  strict wrong-output findings.
- `pkcs11-mock` legacy multipart smoke focused artifact:
  `artifacts/_focused/pkcs11-mock-multipart-r2-20260527/`. The focused
  `test_multipart.py` run moved from 9 failed to 9 skipped. The old rows were
  missing SHA-2/AES/RSA-SHA256 capability guards in the legacy smoke file, not
  provider cryptographic-output failures.
- `pkcs11-mock` key-size focused artifact:
  `artifacts/_focused/pkcs11-mock-key-sizes-r2-20260527/`. The focused
  `test_key_sizes.py` run moved from 9 failed / 6 skipped to 6 failed /
  9 skipped. RSA/SHA-256 sign rows now skip when `SHA256_RSA_PKCS` is absent.
  The remaining hard rows are AES value readback placeholders and empty RSA
  public modulus readback after setup succeeds.
- `pkcs11-mock` metamorphic focused artifact:
  `artifacts/_focused/pkcs11-mock-metamorphic-signature-current-r2-20260527/`.
  The focused `test_metamorphic.py` run moved from 6 failed / 9 skipped to
  15 skipped. Missing RSA/SHA mechanisms now skip before setup, and the RSA
  wrong-data row no longer catches its own failure assertion; accepting a
  tampered signature remains a hard failure when setup succeeds.
- `pkcs11-mock` resource/stress focused artifact:
  `artifacts/_focused/pkcs11-mock-resource-stress-r2-20260527/`. The focused
  `test_resource.py` and `test_stress.py` run moved from 1 passed / 16 failed
  to 16 skipped / 1 failed. Missing AES/SHA/RSA mechanisms and exact
  `CKR_SESSION_COUNT` extra-session capacity are now setup skips. The remaining
  hard row is `test_rapid_random_1000`, where the mock returns the same
  32-byte value on every random-generation call.
- `pkcs11-mock` handle-reuse focused artifact:
  `artifacts/_focused/pkcs11-mock-handle-reuse-r2-20260527/`. The focused
  `security/test_handle_reuse.py` run moved from 1 passed / 5 failed /
  1 skipped to 7 skipped. The file also no longer swallows Python exceptions or
  accepts arbitrary non-OK CKRs for destroyed-handle operations; when setup
  succeeds, only explicit handle-related CKRs count as the expected result.
- `pkcs11-mock` sign/key-management focused artifact:
  `artifacts/_focused/pkcs11-mock-sign-keymgmt-r2-20260527/`. The focused
  `test_sign.py` and `test_keymgmt.py` run moved from 2 passed / 14 failed /
  12 skipped to 2 passed / 4 failed / 22 skipped. The remaining hard rows are
  key-management readback findings: imported AES `CKA_KEY_TYPE` is empty,
  exported AES key material is the mock placeholder `Hello world!`, and the RSA
  public modulus reads back empty.
- `pkcs11-mock` RNG focused artifact:
  `artifacts/_focused/pkcs11-mock-rng-current-20260527/`. The focused
  `test_rng.py` run reports 4 passed and 5 failed. This is not setup noise:
  `C_GenerateRandom` succeeds, but every byte is `0x01`, causing duplicate,
  bit-frequency, byte-distribution, entropy, and runs-test failures.
- `pkcs11-mock` Double Ratchet focused artifact:
  `artifacts/_focused/pkcs11-mock-double-ratchet-current-20260527/`. Current
  source no longer uses a classic EC/P-256 fallback for X2RATCHET setup; it
  requires Montgomery setup and tries X25519 then X448. The mock target has no
  advertised X2RATCHET coverage, so this artifact is capability-skip evidence,
  not provider Double Ratchet behavior evidence.
- `pkcs11-mock` Wycheproof XDH focused artifact:
  `artifacts/_focused/pkcs11-mock-xdh-decode-current-20260527/`. Current source
  narrows X25519/X448 decoder exception handling so local decoder bugs propagate
  instead of becoming valid-vector skips or invalid-vector passes. The mock
  target does not advertise `ECDH1_DERIVE`, so the focused run reports 4,176
  skipped and 0 failed as capability-skip evidence.
- `pkcs11-mock` Wycheproof ECDH focused artifact:
  `artifacts/_focused/pkcs11-mock-ecdh-decode-current-20260527/`. Current source
  narrows ECDH curve-mapping and decoder exception handling so local bugs
  propagate instead of becoming provider capability skips. The mock target does
  not advertise `ECDH1_DERIVE`, so the focused run reports 13,128 skipped and
  0 failed as capability-skip evidence.
- `pkcs11-mock` SO PIN focused artifact:
  `artifacts/_focused/pkcs11-mock-so-pin-current-20260527/`. Current source no
  longer turns arbitrary `C_SetPIN` setup exceptions into skips; exact token
  policy/permission CKRs still skip and generic runtime rejects are visible
  xfail evidence. The normal Docker run is destructive-gated, so this artifact
  confirms gating rather than mock PIN-change behavior.
- `pkcs11-mock` access-level C_InitPIN focused artifact:
  `artifacts/_focused/pkcs11-mock-access-levels-init-pin-current-20260527/`.
  Current source validates the SO-login result before `C_InitPIN` and no longer
  turns arbitrary setup exceptions or generic CKRs into unsupported skips. The
  focused run reports 27 skipped and 0 failed; this is destructive/capability
  gating evidence, not mock PIN-initialization behavior evidence.
- `pkcs11-mock` object-size focused artifact:
  `artifacts/_focused/pkcs11-mock-object-size-current-20260527/`. Current
  source no longer treats arbitrary `C_GetObjectSize` exceptions or generic
  CKRs as unsupported size reporting. The focused run reports 2 skipped and
  1 failed; the hard row is a wrong-result finding where both 100-byte and
  10KB data objects report size 256.
- `pkcs11-mock` RSA PKCS#1 decrypt current-source artifact:
  `artifacts/_focused/pkcs11-mock-rsa-decrypt-runtime-classification-current-20260526`.
  The focused `test_wycheproof_rsa_decrypt.py` run now has 77 passed, 124
  xfailed, and 0 failed. The former hard failures were valid-vector
  `CKR_KEY_TYPE_INCONSISTENT` runtime rejects from an advertised
  `CKM_RSA_PKCS` decrypt path, so they are visible xfail evidence rather than
  raw harness failures. Accepted invalid ciphertext would still be a hard
  failure in this test.
- `tpm2` focused artifacts:
  `artifacts/_focused/tpm2-post-38c12f8-r3`. The same 5-file focus list moved
  from 13 failures / 17 xfails in `r1` to 12 failures / 18 xfails in `r3`.
  The raw `CKA_ALLOWED_MECHANISMS` setup complaint disappeared after imported
  AES/HMAC secret keys started carrying the operation mechanism in
  `CKA_ALLOWED_MECHANISMS`.
- `nss` X448/HKDF focused artifact:
  `artifacts/_focused/nss-x448-hkdf-current-v2-20260526`. Current source now
  reports the focused X448/HKDF set with 909 passed, 3,646 skipped, 8 xfailed,
  0 failed, and 0 crashed. X448 `CKR_DOMAIN_PARAMS_INVALID` is treated as an
  unsupported-curve skip, while HKDF lifecycle `CKM_HKDF_KEY_GEN`
  `CKR_MECHANISM_INVALID` is visible advertised-but-not-operational xfail
  evidence. Wycheproof X25519/X448 and HKDF vector rows already passed or
  skipped cleanly in this focused run.
- `tpm2` interop/crossverify current-source artifact:
  `artifacts/_focused/tpm2-interop-crossverify-current-20260526`. Current
  source reports `test_interop.py`, `test_crossverify.py`, and
  `test_crossverify_extended.py` with 23 passed, 4 skipped, 14 xfailed, 0
  failed, and 0 crashed. AES/HMAC operations that reach the TPM operation and
  return `CKR_GENERAL_ERROR` with TPM2-TSS errors such as
  `Esys_EncryptDecrypt2` / `Esys_HMAC` handle value out of range are visible
  provider behavior findings, not missing-template setup failures. Exact wrong
  ciphertext, plaintext, digest, MAC, or signature outputs remain hard failures.
  RSA-4096 crossverify remains xfail setup evidence because the provider rejects
  that key size with `CKR_ATTRIBUTE_VALUE_INVALID`.
- `softhsm2` focused DSA artifacts:
  `artifacts/_focused/softhsm2-dsa-current-after-bigint`. The same
  `test_wycheproof_dsa.py` focus moved from 296 valid-signature failures to 0
  failures after stripping third-party DSA `Big integer` sign padding before
  PKCS#11 import. Current focused result: 613 passed, 1,343 skipped, 1,956
  total.
- `softhsm2` focused ECDSA artifacts:
  `artifacts/_focused/softhsm2-ecdsa-current-after-shake`. Current source
  removes the P-521/SHAKE256 valid-vector rejection pattern by using
  SHAKE256(64) before raw `CKM_ECDSA`. Exact interim counts stay in the
  artifact JSON rather than this working note.
- `softhsm2` focused RSA artifacts:
  `artifacts/_focused/softhsm2-rsa-current-after-bigint`. Current-source
  normalized-RSA run removed the padded-import failures from RSA-PSS, RSA
  signature verification, and RSA-OAEP. The remaining RSA PKCS#1 decrypt
  failures are accepted-invalid-ciphertext findings, not sign-padding import
  artifacts. Exact interim counts stay in the artifact JSON rather than this
  working note.

## Follow-Up Queue

- Re-run the affected files on TPM2/OpenCryptoki/NSS after the post-run fixes
  to confirm the largest raw harness failures move into clear xfail/failure
  categories without hiding real crashes.
- Separate TPM2 provider limitations from pkcs11-check setup assumptions:
  AES keygen vs import, `CKA_ALLOWED_MECHANISMS`, token/session object
  templates, and EC/RSA attribute readback need source-level review.
- Keep BouncyHSM out of the default article table unless a separate long run is
  needed. It is useful as an example of an obscure software provider with slow
  and uneven behavior, but not central to the announcement.
