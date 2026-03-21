# PKCS#11 OASIS Spec Compliance — Gap Analysis

**Date:** 2026-03-21
**Source:** OASIS PKCS#11 spec (`/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/`, 95 files)
**Current suite snapshot:** `194` product test files, `74,866` collected tests

Verification commands used for this audit:
- `find src/pkcs11_check/testcases -name 'test_*.py' | wc -l`
- `uv run pytest src/pkcs11_check/testcases --co -q`
- `uv run pytest tests -q`
- targeted `rg` sweeps for roadmap mechanisms, functions, and attributes

---

## Executive Summary

The 2026-03-20 gap analysis is no longer accurate. Phases A-H were implemented substantially, and
the suite now far exceeds the old size baseline. The remaining work is not "grow the suite"; it is
"finish the missing OASIS corners, fix stale accounting, and keep the docs honest."

| Area | Current status | Main remaining gaps |
|------|----------------|---------------------|
| Mechanisms | Broad expansion across Phases C-G | `ML_DSA_EXTERNAL_MU*`, `KMAC`, standalone SHAKE, `PKCS12_PBE_EXPORT` / `IMPORT`, `RSA_PKCS_NULL`, some Tier 1 stragglers |
| API functions | Strong coverage with new dedicated files | `C_WaitForSlotEvent` success path, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate`, message finalizers, async lifecycle, legacy parallel functions |
| Object types / attributes | Substantial progress | Template constraint attrs, explicit `CKO_OTP_KEY` object coverage, final 12/12 object confirmation |
| Session semantics | Strong dedicated coverage landed | Final completeness accounting and cross-checking against Phase H acceptance criteria |
| Reporting / docs | Partially implemented | `compliance_report.py` keyword mapping is stale; several status docs still lag the repo |

---

## Phase Status

| Phase | Status | Audit summary |
|------|--------|---------------|
| A | Partial | `test_operation_state.py`, `test_sign_recover.py`, `test_v30_session.py`, and `test_dual_function.py` landed, but Phase A acceptance is still blocked by missing success-path coverage for `C_WaitForSlotEvent`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate`, message finalizers, and async lifecycle |
| B | Partial | Major object and attribute-enforcement files landed, including `test_attribute_enforcement.py`, but template-constraint attrs and explicit `CKO_OTP_KEY` object coverage remain open |
| C | Mostly complete | All major planned files exist; the remaining work is narrower mechanism-level cleanup rather than whole families |
| D | Partial | `test_hash_ml_dsa.py`, `test_hash_slh_dsa.py`, and `test_stateful_sigs.py` exist, but `ML_DSA_EXTERNAL_MU*`, `KMAC`, and standalone SHAKE are still missing, and the generic `CKM_HASH_*` cases are still skipped due to missing binding support |
| E | Mostly complete | DES, Camellia, ARIA, SEED, Blowfish, Twofish, and GOST files are present and broad |
| F | Mostly complete | TLS, SSL3, WTLS, IKE, CMS, and PBE coverage landed, but `CKM_PKCS12_PBE_EXPORT` / `CKM_PKCS12_PBE_IMPORT` are still missing |
| G | Partial | OTP, X3DH, ratchet, Salsa20, misc KDF, and BLAKE2 files landed, but `CKM_RSA_PKCS_NULL` is still open and the ratchet naming needs consistent accounting |
| H | Partial | `test_session_state_machine.py`, `test_object_visibility.py`, `test_ro_session_restrictions.py`, and `test_access_levels.py` exist, but compliance-report accounting is stale and the final per-function / per-section completeness pass is not done |

---

## Current Gaps By Domain

### 1. API Function Coverage

Clearly implemented since the previous analysis:
- `C_GetOperationState` / `C_SetOperationState`
- `C_SignRecoverInit` / `C_SignRecover`
- `C_VerifyRecoverInit` / `C_VerifyRecover`
- `C_LoginUser`
- `C_SessionCancel`
- `C_DigestEncryptUpdate`
- `C_DecryptDigestUpdate`

Still missing or only partially covered:
- `C_WaitForSlotEvent` has CKR/error coverage, but not a primary functional success-path test.
- `C_SignEncryptUpdate` appears in CKR/spec accounting, but not in a dedicated functional test file.
- `C_DecryptVerifyUpdate` appears in CKR/spec accounting, but not in a dedicated functional test file.
- `C_MessageEncryptFinal`, `C_MessageDecryptFinal`, `C_MessageSignFinal`, and `C_MessageVerifyFinal` do not have clear happy-path test coverage.
- `C_AsyncComplete` / `C_AsyncJoin` are not covered by dedicated functional tests.
- `C_GetFunctionStatus` / `C_CancelFunction` remain legacy gaps.

Practical conclusion:
- Phase A is no longer an untouched gap.
- Phase A is also not done.

### 2. Mechanism Coverage

Large families added since the previous analysis:
- AES mode expansion
- AES encryption-based KDF
- RSA extended mechanisms
- DSA and ECDSA/ECDH expansion
- X9.42 DH
- SP800-108 KDF
- HKDF extension
- HASH_ML_DSA / HASH_SLH_DSA variants
- HSS / XMSS / XMSSMT
- DES, Camellia, ARIA, SEED, Blowfish, Twofish, GOST
- TLS 1.2, SSL3, WTLS, IKE, CMS, PBE
- OTP, X3DH, ratchet, Salsa20, misc KDF, BLAKE2

Remaining concrete gaps found during this audit (now covered with availability tests in `test_remaining_gaps.py` — all skip cleanly on modules without support):
- `CKM_ML_DSA_EXTERNAL_MU` — availability test added
- `CKM_ML_DSA_EXTERNAL_MU_GEN` — availability test added
- `CKM_KMAC_128` / `CKM_KMAC_256` — availability test added
- standalone SHAKE XOF — availability test added
- `CKM_PKCS12_PBE_EXPORT` / `CKM_PKCS12_PBE_IMPORT` — availability test added
- `CKM_RSA_PKCS_NULL` — availability test added

Named Tier 1 stragglers that still appear absent:
- `CKM_AES_CMAC_GENERAL`
- `CKM_DSA_PROBABILISTIC_PARAMETER_GEN`
- `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS`

Ratchet naming note:
- The current code uses `CKM_X2RATCHET_*` / `CKK_X2RATCHET`.
- Earlier planning text used `CKM_DOUBLE_RATCHET_*`.
- Future accounting must use one naming scheme consistently.

### 3. Object Types and Attribute Enforcement

Clearly improved since the previous analysis:
- `CKA_COPYABLE`
- `CKA_DESTROYABLE`
- `CKA_KEY_GEN_MECHANISM`
- `CKA_CHECK_VALUE`
- `CKA_ALLOWED_MECHANISMS`
- `CKA_WRAP_WITH_TRUSTED`
- `CKA_ALWAYS_AUTHENTICATE`
- `CKA_START_DATE` / `CKA_END_DATE`

Still open or not clearly demonstrated:
- explicit `CKO_OTP_KEY` object attribute coverage (OTP mechanisms tested in `test_otp.py`)

Closed since last audit:
- `CKA_WRAP_TEMPLATE` — tested in `test_remaining_gaps.py`
- `CKA_UNWRAP_TEMPLATE` — tested in `test_remaining_gaps.py`
- `CKA_DERIVE_TEMPLATE` — tested in `test_remaining_gaps.py`

Practical conclusion:
- Phase B has real progress and should no longer be described as "6 object types completely untested."
- Phase B acceptance criteria are still not met as written.

### 4. Session Semantics and Compliance Hardening

Clearly implemented since the previous analysis:
- session object vs token object visibility
- private object visibility rules
- RO session restrictions
- login / logout / SO state transitions
- concurrent session behavior in dedicated session-semantics files

Still open:
- `src/pkcs11_check/compliance_report.py` uses stale keyword mappings for several functions
- final per-function completeness accounting is not trustworthy yet
- the "all 802 CKR entries either tested or documented as untestable" acceptance text still needs a final audit pass, even though CKR coverage is strong

---

## Repo-Health Findings

`uv run pytest tests -q` during this audit initially failed with one marker-registration error:
- product tests used custom markers `encrypt` and `sign` that were not registered
- the meta-test also treated pytest built-ins `usefixtures` and `xfail` as custom markers

This audit updated:
- `src/pkcs11_check/markers.py` to register `encrypt` and `sign`
- `tests/test_markers.py` to treat `usefixtures` and `xfail` as built-ins

Further repo-health notes:
- `docs/status.md` and `docs/module-matrix.md` still predate the current suite size and need a separate refresh
- `docs/test-coverage.md` also had a stale `test_acvp_mldsa.py` reference and was corrected during this audit

---

## Recommended Next Pass

1. Finish the real Phase D gaps: `ML_DSA_EXTERNAL_MU*`, `KMAC`, standalone SHAKE.
2. Close the remaining Phase A function gaps: `C_WaitForSlotEvent`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate`, message finalizers, async lifecycle, legacy parallel functions.
3. Close the remaining explicit Phase B/F/G deltas: template-constraint attrs, `CKO_OTP_KEY`, `PKCS12_PBE_EXPORT` / `IMPORT`, `RSA_PKCS_NULL`.
4. Refresh `compliance_report.py` so machine-readable coverage claims match the actual dedicated files.
5. Refresh the remaining stale status docs after the next verification pass.

---

## Verification Snapshot

Results observed during this audit:
- `194` product test files
- `74,866` collected product tests
- `uv run pytest tests -q`: passed after the marker-fix patch
- `uv run ruff check src tests`: could not run in this environment because `ruff` is not installed
- `uv run mypy src`: could not run in this environment because `mypy` is not installed

This document supersedes the previous March 20 gap estimates.
