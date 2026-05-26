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
  `CKR_MECHANISM_PARAM_INVALID`, and `CKR_KEY_TYPE_INCONSISTENT`.
- Padding-oracle structured RSA tests now treat malformed generated RSA public
  modulus/exponent attributes as an xfail setup finding instead of crashing with
  Python `ValueError`.
- ACVP ECDH generated-key probes now treat malformed `CKA_EC_POINT` readback as
  xfail evidence instead of a raw DER decoding exception.

## Follow-Up Queue

- Re-run the affected files on TPM2/OpenCryptoki/NSS after the post-run fixes
  to confirm the largest raw harness failures move into clear xfail/failure
  categories without hiding real crashes.
- Separate TPM2 provider limitations from pkcs11-check setup assumptions:
  AES keygen vs import, `CKA_ALLOWED_MECHANISMS`, token/session object
  templates, and EC/RSA attribute readback need source-level review.
- Re-check NSS X448 and HKDF lifecycle failures; they look like advertised but
  non-operational paths and may need tighter xfail classification.
- Keep BouncyHSM out of the default article table unless a separate long run is
  needed. It is useful as an example of an obscure software provider with slow
  and uneven behavior, but not central to the announcement.
