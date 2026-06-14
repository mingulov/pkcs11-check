# Finding: `C_Verify` does not terminate the operation on a rejected signature

**Severity:** High (causes `CKR_OPERATION_ACTIVE` on the next operation of the
same session; breaks any client that reuses a session for multiple verifies).

**Affected providers (observed):**

| Provider | Interface | Trigger (rejection code that is NOT terminated) | Recovery that works |
|---|---|---|---|
| kryoptic v1.5.0 | 3.2 | wrong-**length** sig → `CKR_SIGNATURE_LEN_RANGE` | `C_SessionCancel` |
| tpm2-pkcs11 | **2.40** | **empty** sig → `CKR_ARGUMENTS_BAD` (terminates fine on `CKR_SIGNATURE_INVALID`) | **only close+reopen** |
| BouncyHSM | 3.2 | **empty** sig → `CKR_ARGUMENTS_BAD` (terminates fine on a wrong-length sig) | `C_SessionCancel` (v3.0) |
| OpenCryptoki | 3.x | **empty** sig → `CKR_ARGUMENTS_BAD`, **multipart `C_VerifyFinal` only** (single-shot `C_Verify` terminates correctly) | `C_SessionCancel` |

(Confirmed by running `test_operation_termination.py` across the stable providers:
kryoptic, tpm2-pkcs11, BouncyHSM, and **OpenCryptoki** FAIL it; softhsm2, NSS, and
NSS-PQC PASS; pkcs11-mock skips. kryoptic is caught by the *too-short* variant;
tpm2, BouncyHSM, and OpenCryptoki only by the *empty* variant — which is why the
test probes several malformations rather than one. **Re-verify 2026-06-10:**
OpenCryptoki was previously listed as PASS — that held for the single-shot
`C_Verify` test, but the multipart `C_VerifyFinal` probe
(`test_c_verify_final_terminates_after_rejected_signature`) leaves the op active
after an empty-sig `CKR_ARGUMENTS_BAD` (fresh: 1 failed / 25 passed), same class
as tpm2/BouncyHSM.)

Both leave the verify operation active after *some* rejection; they differ in
*which* rejection and in what recovery is possible. tpm2-pkcs11 is the harder
case: being v2.40 it has no `C_SessionCancel`, its NULL-mechanism `C_VerifyInit`
cancel idiom returns `CKR_ARGUMENTS_BAD` without cancelling, and
`C_GetOperationState` is unsupported — so the only way to clear the dangling op
is to close and reopen the session.

**Not affected (control):** SoftHSM2 2.7.0 (v2.40) terminates correctly after
every rejection.

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
   provider-general conformance test that rejects a signature (probing several
   malformations: too-short, too-long, empty, all-zero, wrong-value) and asserts
   the verify operation was terminated. It `fail`s (lifecycle
   self-contradiction) on kryoptic and tpm2-pkcs11 and `pass`es on compliant
   modules. No per-provider configuration.
2. **Cascade neutralized** — `recipes._init_or_recover` wraps every single-shot
   `C_*Init`. It fires only on `CKR_OPERATION_ACTIVE` (zero cost on the clean
   path, so no regression for RPC-bound modules) and recovers in tiers:
   `C_SessionCancel` + retry clears it in place on v3.0+ modules (kryoptic);
   if that cannot clear it (tpm2-pkcs11), it asks the shared-session holder
   (`_ModuleSessionHolder`) to close+reopen the session before the next handout.
   This restores the true outcomes of the unrelated tests that share the session
   while keeping the finding itself visible (point 1).

   Effect (single file, `test_wycheproof_rsa.py`): kryoptic 4866 → 0
   `CKR_OPERATION_ACTIVE`; tpm2-pkcs11 2803 → 12 (the residual 12 are the single
   immediate-victim test of each of the ~12 length-malformed trigger vectors,
   detected one test too late to save — a bounded, near-source remnant rather
   than a file-wide cascade).

## Recovery: scope, interface-independence, and limitations

- **Interface-independent (behaviour-based, not version-based).** Recovery never
  reads the negotiated interface version; it tries `C_SessionCancel` and reacts
  to what happens. Absent function (v2.40, or a v3.x NULL/unloaded pointer) →
  `AttributeError` → reopen path. Present-but-failing (`CKR_FUNCTION_NOT_SUPPORTED`,
  `CKR_OPERATION_CANCEL_FAILED`, or a call that raises) → swallowed; the **retry**
  `C_*Init` decides. The cancel's return value is never trusted — the *effect* is
  verified by the retry, so a missing, broken, or lying `C_SessionCancel` all
  converge on the safe outcome (reopen).
- **All crypto-operation init entry points are wrapped**: single-shot
  encrypt/decrypt/sign/verify/digest, the multipart `*Init`, and
  sign-recover/verify-recover. Any of them can be the victim of a stale op left
  by a prior test, so any of them can trigger recovery.
- **Findings are not masked.** Recovery fires only on `CKR_OPERATION_ACTIVE`
  (never on the clean path). The tests that deliberately assert
  `CKR_OPERATION_ACTIVE` (op-race, dual-function, the raw CKR suites) use raw
  `C_*Init` and check the return code themselves — they do not route through the
  recovering recipes, so they are unaffected. The genuine non-termination finding
  is surfaced by `test_operation_termination.py` using raw calls.
- **Known limitations.** (1) `C_FindObjectsInit` is not wrapped — object-search is
  a separate operation class not addressable by `C_SessionCancel`'s mechanism
  flags; a dangling find op (none observed) would be bounded by the per-test
  session reopen / per-file subprocess teardown rather than recovered in place.
  (2) The conformance test probes *verify* termination (RSA + ECDSA); a
  hypothetical success-path non-termination on another operation class probed
  *through a recipe* could be recovered (masked) — extend the conformance test
  if such a provider appears.
