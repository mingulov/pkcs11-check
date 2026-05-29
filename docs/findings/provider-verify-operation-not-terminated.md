# Finding: `C_Verify` does not terminate the operation on a rejected signature

**Severity:** High (causes `CKR_OPERATION_ACTIVE` on the next operation of the
same session; breaks any client that reuses a session for multiple verifies).

**Affected providers (observed):**

| Provider | Version | Interface |
|---|---|---|
| kryoptic | v1.5.0 | 3.2 |
| tpm2-pkcs11 | (image `docker-test-tpm2`) | — |

**Not affected (control):** SoftHSM2 2.7.0 (v2.40) terminates correctly.

---

## Summary

When `C_Verify` rejects a signature — returning `CKR_SIGNATURE_INVALID` or
`CKR_SIGNATURE_LEN_RANGE` — the affected providers leave the **verification
operation active** on the session. The next `C_VerifyInit` (or any other
`C_*Init` of the same class) then returns **`CKR_OPERATION_ACTIVE`**.

This violates the PKCS#11 specification. From *Functions for verifying
signatures and MACs*, `C_Verify`:

> "The verification operation MUST have been initialized with **C_VerifyInit**.
> A call to **C_Verify** always terminates the active verification operation."
>
> "A successful call to **C_Verify** should return either the value **CKR_OK**
> … or **CKR_SIGNATURE_INVALID** …. If the signature can be seen to be invalid
> purely on the basis of its length, then **CKR_SIGNATURE_LEN_RANGE** should be
> returned. **In any of these cases, the active verification operation is
> terminated.**"

So `CKR_SIGNATURE_INVALID` and `CKR_SIGNATURE_LEN_RANGE` are *explicitly*
enumerated as terminal outcomes — the operation must be terminated.

## Scope

The defect is systemic across every verify mechanism, not RSA-specific. In a
full pkcs11-check run the resulting `CKR_OPERATION_ACTIVE` cascade appeared in
(kryoptic): `test_wycheproof_rsa` (RSA PKCS#1), `test_wycheproof_ecdsa`
(ECDSA), `test_wycheproof_rsa_pss` (RSA-PSS), `test_wycheproof_hmac` (HMAC),
`test_wycheproof_mldsa` (ML-DSA), `test_wycheproof_ed25519` (Ed25519),
`test_acvp_slhdsa` (SLH-DSA), `test_acvp_eddsa` (EdDSA). tpm2-pkcs11 showed the
same in RSA + RSA-PSS verify.

## Impact

A single rejected verify leaves the session unusable for further operations of
that class until the operation is explicitly cancelled. Any application that
reuses one session across multiple verifications (the common case) sees every
verification after the first rejected one fail with `CKR_OPERATION_ACTIVE`.

## Reproduction

Two self-contained scripts (no test framework) are in
[`repro/`](repro/):

- [`verify_no_terminate.py`](repro/verify_no_terminate.py) — generates a key,
  signs a message, then verifies a **one-byte-short** signature (a length-based
  terminal rejection) and probes whether the operation was terminated. Also
  verifies that `C_SessionCancel` recovers the session.
- [`verify_no_terminate_wycheproof.py`](repro/verify_no_terminate_wycheproof.py)
  — replays the real Wycheproof `rsa_signature_2048_sha224` vectors and reports
  the first one whose rejection leaves the operation active (this is
  `tc242` on kryoptic).

Run inside a provider container:

```
docker compose -f docker/docker-compose.test.yml run --rm \
    test-kryoptic uv run --no-sync python /app/docs/findings/repro/verify_no_terminate.py
```

### kryoptic v1.5.0 output

```
module           : /usr/lib/libkryoptic_pkcs11.so
interface version: 3.2
  control  C_Verify(valid)                 -> CKR_OK
  control  C_VerifyInit after valid verify -> CKR_OK
  probe    C_Verify(invalid)               -> CKR_SIGNATURE_LEN_RANGE
  probe    C_VerifyInit after invalid      -> CKR_OPERATION_ACTIVE   <-- spec violation
  recover  C_SessionCancel(CKF_VERIFY)     -> CKR_OK
  recover  C_VerifyInit after cancel       -> CKR_OK                 <-- recovery works
BUG REPRODUCED: C_Verify left the verify operation ACTIVE after CKR_SIGNATURE_LEN_RANGE.
```

The control (a *valid* signature → `CKR_OK`) terminates correctly; only the
rejection path leaves the operation dangling.

### SoftHSM2 (control) output

```
  control  C_Verify(valid)                 -> CKR_OK
  control  C_VerifyInit after valid verify -> CKR_OK
  probe    C_Verify(invalid)               -> CKR_SIGNATURE_INVALID
  probe    C_VerifyInit after invalid      -> CKR_OK                 <-- terminated, spec-compliant
PASS: C_Verify terminated the operation on CKR_SIGNATURE_INVALID (spec-compliant).
```

## Recovery

`C_SessionCancel(hSession, CKF_VERIFY)` clears the dangling operation
(returns `CKR_OK`; the subsequent `C_VerifyInit` succeeds). This is the
spec-blessed way to abort an in-progress operation and is a no-op for any
operation class that is not active, so it is safe to issue unconditionally.

## A related, separate quirk (kryoptic)

kryoptic rejects most *invalid* (wrong-hash / bad-padding) RSA signatures with
**`CKR_DEVICE_ERROR`** rather than `CKR_SIGNATURE_INVALID`, and *does* terminate
the operation in that case. Only the wrong-*length* path
(`CKR_SIGNATURE_LEN_RANGE`) leaves the operation active. pkcs11-check records
the `CKR_DEVICE_ERROR` rejections as `xfail` (a noted, non-canonical-but-clean
rejection code), not as failures.

## How pkcs11-check handles this

1. **Surfaced as a finding** — `testcases/test_operation_termination.py` is a
   provider-general conformance test that rejects a signature and asserts the
   verify operation was terminated. It `fail`s (Type-C lifecycle
   self-contradiction) on the affected providers and `pass`es on compliant
   ones. No per-provider configuration.
2. **Cascade neutralized** — the shared module-scoped session
   (`_ModuleSessionHolder` in `fixtures.py`) now cancels any dangling operation
   via `C_SessionCancel` on each per-test handout, so one provider's
   non-termination can no longer corrupt the thousands of unrelated tests that
   share the session. This restores the true (un-inflated) outcomes of those
   tests while keeping the finding itself visible (point 1).
