# Provider Failure Gap Analysis - 2026-06-02

Scope: pooled artifacts under `artifacts/_base/*-pooled/`, current worktree
source, and a local OASIS PKCS#11 specification checkout.
This is an investigation document only. Fixes are intentionally deferred except
for source changes already present in the current worktree.

## Source and spec anchors

- `artifacts/_base/*-pooled/results.json` was used for file-level unit status.
- `artifacts/_base/*-pooled/report.jsonl` was used for per-test failed/xfail
  records and RV traces.
- Local OASIS spec:
  - `working/doc/spec/session_mgmt_functions.md`: `C_OpenSession` may return
    `CKR_SESSION_COUNT` when the token has too many sessions already open.
  - `working/doc/spec/function_return_values.md`: `CKR_SESSION_COUNT` can only
    be returned by `C_OpenSession`.
  - `working/doc/spec/encryption_functions.md`: `C_EncryptFinal` termination is
    meaningful after an initialized active encryption operation reaches final.
    `CKR_OPERATION_NOT_INITIALIZED` means there was no active operation of the
    appropriate type.

## Executive conclusion

It is not correct to say that nothing suspicious remains.

Current source is better than the `_base` artifacts: the known pkcs11-mock
`CKR_SESSION_COUNT` rows and the `test_operation_termination.py`
`CKR_OPERATION_NOT_INITIALIZED` rows are stale with respect to the current
worktree. They should move to setup skips or advertised-but-not-operational
xfails after a provider rerun.

However, sessions are not proven globally stable yet:

- There are real provider lifecycle failures where operations remain active
  after a completed/rejected operation. These are not harness noise.
- There are hard invalid-session/token-state rows in pkcs11-mock and TPM2 CKR
  tests.
- There are xfailed token/login state rows where the intended negative path is
  blocked by already-logged-in token state.
- Several older session/PIN/token-object files still open extra sessions
  directly rather than through the newer exact `CKR_SESSION_COUNT` setup wrapper.
  `_base` did not show hard `CKR_SESSION_COUNT` rows there, but the source is not
  uniformly guarded.

## Session stability review

Current source has three useful stability layers:

- `p11_raw_session` is function-scoped and closes/logs out in fixture teardown.
- `p11_module_session` uses a module-scoped holder that health-checks
  `C_GetSessionInfo`, detects dropped login state, and reopens when needed.
- Current subprocess-related diffs add atexit cleanup paths for raw subprocess
  scripts and CKR child scripts, closing sessions and finalizing on normal exit.

Remaining session gaps to address in the next fix batch:

1. Add or reuse a common extra-session helper instead of repeating local wrappers.
2. Audit older direct extra-session call sites that do not currently classify
   exact `CKR_SESSION_COUNT`:
   - `src/pkcs11_check/testcases/test_pin.py`
   - `src/pkcs11_check/testcases/test_so_pin.py`
   - `src/pkcs11_check/testcases/test_token_objects.py`
   - `src/pkcs11_check/testcases/test_session_edge_cases.py`
   - `src/pkcs11_check/testcases/test_v30_session.py`
   - `src/pkcs11_check/testcases/test_access_control.py`
   - selected direct opens in `src/pkcs11_check/testcases/test_mech_state.py`
3. Rerun providers after the current source changes before claiming the stale
   artifact rows are gone.

## State/lifecycle buckets

### Stale with current source, rerun required

- pkcs11-mock: 10 hard `CKR_SESSION_COUNT` rows:
  - `ckr/test_ckr_session.py`
  - `test_ro_session.py`
  - `test_session_info.py`
- Kryoptic variants: 1 hard `CKR_OPERATION_NOT_INITIALIZED` row each in
  `test_operation_termination.py::test_c_encrypt_terminates_after_multipart[AES_CTS]`.
- NSS variants: 14-17 hard `CKR_OPERATION_NOT_INITIALIZED` rows each in
  `test_operation_termination.py::test_c_encrypt_terminates_after_multipart[...]`.

These are source-classification gaps already addressed in the current worktree,
but `_base` is stale until rerun.

### Real lifecycle/state failures

`CKR_OPERATION_ACTIVE` remains a real finding. It means the provider left an
operation active after the test reached a result path that should have terminated
the operation.

Observed hard rows:

| Provider | Count | Representative tests |
|---|---:|---|
| bouncyhsm | 4 | verify reject, ECDSA verify reject, verify-final reject, digest termination |
| kryoptic-fips | 3 | verify reject, ECDSA verify reject, verify-final reject |
| kryoptic-main | 3 | verify reject, ECDSA verify reject, verify-final reject |
| kryoptic | 3 | verify reject, ECDSA verify reject, verify-final reject |
| NSS variants | 1 each | `test_mech_multipart.py::...DES3_CBC` |
| opencryptoki-master | 1 | verify-final reject |
| opencryptoki | 1 | verify-final reject |
| pkcs11-mock | 2 | SHA-1 digest length and digest termination |
| tpm2 | 23 | operation-termination rows plus Wycheproof RSA invalid-signature rows |

### Suspicious invalid session/token state

Hard failed rows:

- pkcs11-mock:
  - `ckr/test_ckr_keygen.py::TestGenerateKeyErrors::test_template_inconsistent`
  - `ckr/test_ckr_keygen.py::TestGenerateKeyPairErrors::test_attribute_type_invalid`
  - `ckr/test_ckr_sign.py::TestSignInitErrors::test_key_handle_invalid`
  - `ckr/test_ckr_verify.py::TestVerifyInitErrors::test_key_handle_invalid`
- tpm2:
  - `ckr/test_ckr_keygen.py::TestGenerateKeyErrors::test_bad_key_size_zero`
  - `ckr/test_ckr_keygen.py::TestGenerateKeyErrors::test_bad_key_size_non_standard`
  - `ckr/test_ckr_keygen.py::TestGenerateKeyErrors::test_template_inconsistent`
  - `ckr/test_ckr_keygen.py::TestGenerateKeyPairErrors::test_attribute_type_invalid`

These mention `CKR_SESSION_HANDLE_INVALID`, `CKR_TOKEN_NOT_PRESENT`, or
`CKR_DEVICE_REMOVED` in failed negative/setup paths. They need per-test review in
the next fix pass to decide whether the test setup is damaged or the provider is
returning nonsensical state.

### Xfailed login/session state evidence

These are visible and not hidden, but they still show state preconditions that
block the intended check:

- Wrong-PIN path blocked by `CKR_USER_ALREADY_LOGGED_IN` in Kryoptic variants,
  SoftHSM2 variants, and TPM2.
- NSS stale closed-session behavior is xfailed where `C_GenerateRandom` on a
  stale session returns `CKR_OK` rather than a closed/invalid-session CKR.
- Several `C_LoginUser` v3 rows are xfailed as unsupported/deviation paths.

## Provider-by-provider hard-failure summary

Counts below are failed test call records in `report.jsonl`, not official release
statistics. They are for triage only.

| Provider | Hard failed records | Crashed units | Main hard-failure buckets |
|---|---:|---:|---|
| bouncyhsm | 8144 | 0 | ACVP AES-CCM return-code/runtime/assertion failures dominate; 4 real operation-active lifecycle failures |
| kryoptic-fips | 130 | 5 | invalid inputs accepted, runtime/setup CKRs, 3 operation-active rows, 1 stale operation-termination row |
| kryoptic-main | 164 | 0 | RSA decrypt/AES invalid inputs accepted, security-policy rows, 3 operation-active rows, 1 stale operation-termination row |
| kryoptic | 173 | 0 | same as kryoptic-main plus extra assertion/output rows, 3 operation-active rows, 1 stale operation-termination row |
| nss-main | 162 | 2 | invalid RSA decrypt inputs accepted, KWP/error-path failures, 16 stale operation-termination rows, 1 operation-active row |
| nss-main-slot0 | 180 | 1 | same NSS pattern, 17 stale operation-termination rows, buffer/output rows in slot0 |
| nss | 181 | 1 | same NSS pattern, 14 stale operation-termination rows, extra PQC/MLDSA rows |
| nss-pqc | 162 | 2 | same NSS pattern, 16 stale operation-termination rows |
| nss-pqc-slot0 | 177 | 1 | same NSS pattern, 17 stale operation-termination rows, slot0 buffer/output rows |
| nss-slot0 | 196 | 1 | same NSS pattern, 15 stale operation-termination rows, slot0 buffer/output rows |
| opencryptoki-master | 357 | 0 | invalid EdDSA inputs accepted, KCV/readback failures, RSA/AES wrap CKRs, 1 operation-active row |
| opencryptoki | 357 | 0 | same as opencryptoki-master |
| pkcs11-mock | 114 | 0 | synthetic readback/RNG/signature findings, 10 stale session-count rows, 4 suspicious invalid-session/token rows |
| softhsm2-generated-iv | 134 | 0 | invalid EdDSA key/vector rows, security policy, ECDSA-with-RSA negative row |
| softhsm2-main | 135 | 0 | invalid EdDSA key/vector rows, arithmetic-overflow/security rows |
| softhsm2 | 136 | 0 | invalid EdDSA key/vector rows, security policy, ECDSA-with-RSA negative row |
| tpm2 | 186 | 0 | valid RSA signatures rejected, runtime/setup CKRs, 23 operation-active rows, 4 suspicious invalid-session/token rows |

Unit-level crashes/timeouts/errors from `results.json`:

- `kryoptic-fips`: crashed units in ACVP AES-CCM, mechanism derive/encrypt,
  misc KDF, and Wycheproof AES.
- `nss-main`: crashed units in mechanism flags and mechanism negative tests.
- `nss-main-slot0`, `nss`, `nss-pqc-slot0`, `nss-slot0`: crashed unit in
  mechanism flags.
- `nss-pqc`: crashed units in mechanism flags and mechanism negative tests.

## High-priority finding groups for the next fix/review pass

1. Stale source-classification buckets: rerun after current source changes and
   confirm pkcs11-mock `CKR_SESSION_COUNT` and operation-termination
   `CKR_OPERATION_NOT_INITIALIZED` rows disappear or move to skip/xfail.
2. Operation-active lifecycle failures: keep as hard provider findings unless a
   row is proven to be precondition/setup damage.
3. Invalid session/token state rows in pkcs11-mock and TPM2 CKR keygen/sign/verify
   tests: inspect setup order and RV trace before deciding provider vs harness.
4. Older direct extra-session call sites: standardize on one helper that handles
   exact `CKR_SESSION_COUNT` as setup capacity where the test needs an additional
   session before reaching its assertion.
5. Provider-specific high-volume real failures:
   - BouncyHSM AES-CCM and ACVP return-code/runtime buckets.
   - NSS RSA-decrypt invalid-vector acceptance and KWP/error-path rows.
   - OpenCryptoki EdDSA invalid-key acceptance and KCV/readback rows.
   - SoftHSM2 EdDSA invalid-key acceptance and security-policy rows.
   - TPM2 valid RSA signature rejection and operation-active rows.
   - pkcs11-mock synthetic behavior: placeholder readbacks, deterministic/random
     quality rows, and tampered signature acceptance.

## Current answer to "are sessions stable?"

No, not as a proven global claim.

The current worktree has better cleanup and classification, and the known
pkcs11-mock session-count artifact rows are stale. But the codebase still has
older direct extra-session call sites, visible xfailed login-state preconditions,
and hard invalid-session/token-state rows. The correct release statement after
this pass is:

> Session handling is improved and several stale session-capacity failures should
> clear on rerun, but the suite still has session/state gaps requiring a focused
> follow-up before claiming no suspicious session behavior remains.

