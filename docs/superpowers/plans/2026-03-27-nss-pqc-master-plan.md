# NSS-PQC Test Investigation & Fix Master Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Systematically investigate and fix all 415 failed, 598 xfailed, and key skipped tests in the NSS-PQC (NSS 3.121.0) artifact run. Fix test bugs in pkcs11-check, document genuine NSS module issues, and improve spec compliance verification against the OASIS PKCS#11 v3.2 specification.

**Architecture:** Each task targets a specific failure category from the NSS-PQC artifacts. Tasks are grouped into 8 phases, progressing from infrastructure through security findings to PQC-specific issues. Each task produces either code fixes (test bugs) or documentation (module issues), never silent suppression. All CKR return code validations are checked against the OASIS spec at `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/`.

**Tech Stack:** Python 3.11+, pytest, pkcs11_check.raw (pure ctypes), NSS 3.121.0 (Docker: `test-nss-pqc`), OASIS PKCS#11 v3.2 spec

**Artifacts under analysis:** `/home/user/src/m/pkcs11-check/artifacts/nss-pqc/` (35,292 passed / 415 failed / 31,947 skipped / 598 xfailed)

**Cross-reference:** NSS 3.120.1 (`artifacts/nss/`: 618 failed) and NSS main (`artifacts/nss-main/`: 552 failed) — NSS-PQC is the best-performing variant with 203 fewer failures than base NSS.

**Existing documentation:** `docs/module-issues.md` (NSS 3.120.1 section), `docs/cve-regression.md` (6 NSS CVEs tracked)

---

## Phase 0: Infrastructure & Baseline

### Task 0.1: Fresh NSS-PQC Docker Run with Coverage

**Goal:** Establish a current baseline with the new mechanism coverage tracking.

**Files:**
- Run: `bash docker/test.sh nss-pqc`
- Output: `artifacts/nss-pqc/` (results.json, report.jsonl, coverage.json, state.json)

- [ ] **Step 1:** Run full NSS-PQC test suite via Docker
```bash
bash docker/test.sh nss-pqc
```

- [ ] **Step 2:** Verify coverage.json was produced
```bash
cat artifacts/nss-pqc/coverage.json | python3 -c "
import json, sys
d = json.load(sys.stdin)
mc = d['mechanism_coverage']
fc = d['function_coverage']
print(f'Functions: {fc[\"called\"]}/{fc[\"available\"]} called')
print(f'Mechanisms: {mc[\"invoked\"]}/{mc[\"available\"]} invoked')
print(f'Stacked detail entries: {len(mc.get(\"invoked_detail\", []))}')
"
```

- [ ] **Step 3:** Extract and save the summary for comparison
```bash
python3 -c "
import json
d = json.load(open('artifacts/nss-pqc/results.json'))
print(json.dumps(d['summary'], indent=2))
"
```

- [ ] **Step 4:** Commit baseline artifacts reference
```bash
git add -A && git commit -m 'chore: fresh NSS-PQC baseline with coverage tracking'
```

### Task 0.2: Create NSS-PQC Section in module-issues.md

**Goal:** Create a dedicated NSS-PQC (3.121.0) documentation section separate from existing NSS 3.120.1 section.

**Files:**
- Modify: `docs/module-issues.md`

- [ ] **Step 1:** Read current NSS section in module-issues.md
```bash
grep -n "NSS" docs/module-issues.md | head -20
```

- [ ] **Step 2:** Add a new `## NSS-PQC (3.121.0)` section after the existing NSS section with:
  - Version: NSS 3.121.0, interface v3.0
  - Docker target: `test-nss-pqc`
  - Baseline counts from Task 0.1
  - Placeholder subsections: Known Quirks, Security Findings, PQC Issues, Spec Deviations

- [ ] **Step 3:** Commit
```bash
git add docs/module-issues.md && git commit -m 'docs: add NSS-PQC 3.121.0 section to module-issues'
```

---

## Phase 1: Read-Only Token & Session Model (29 failures)

### Task 1.1: Investigate Token Write-Protected Failures

**Goal:** Determine if `CKR_TOKEN_WRITE_PROTECTED` failures are test bugs or expected NSS behavior.

**Files:**
- Read: `src/pkcs11_check/testcases/test_object_visibility.py`
- Read: `src/pkcs11_check/testcases/test_ro_session_restrictions.py`
- Read: `src/pkcs11_check/testcases/test_concurrent_sessions.py`
- Read: `src/pkcs11_check/testcases/test_access_control.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/object_mgmt_functions.md`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/session_mgmt_functions.md`

- [ ] **Step 1:** List all 29 failing test nodeids from artifacts
```bash
python3 -c "
import json
d = json.load(open('artifacts/nss-pqc/results.json'))
for u in d['units']:
    for t in u.get('tests', []):
        if t.get('outcome') in ('failed',) and 'WRITE_PROTECTED' in t.get('message', ''):
            print(t['nodeid'])
" | sort
```

- [ ] **Step 2:** For each test, determine: does the test create token objects (`CKA_TOKEN=True`) or session objects? Read each test file.

- [ ] **Step 3:** Read OASIS spec `object_mgmt_functions.md` — check what `CKR_TOKEN_WRITE_PROTECTED` means and when it's valid.

- [ ] **Step 4:** Categorize each failure:
  - **Test bug:** Test creates token objects when session objects would suffice → fix test
  - **Expected:** NSS crypto-services slot is read-only by design → skip with clear reason
  - **Spec deviation:** NSS returns wrong CKR code → document in module-issues.md

- [ ] **Step 5:** Fix test bugs (use `CKA_TOKEN=False` where appropriate)

- [ ] **Step 6:** For tests that genuinely need token objects, add mechanism check:
```python
if not rs.has_mechanism("..."):
    pytest.skip("NSS crypto-services slot is read-only")
```
Wait — this is a token property, not a mechanism. Check `CK_TOKEN_INFO.flags` for `CKF_WRITE_PROTECTED` instead.

- [ ] **Step 7:** Document findings in `docs/module-issues.md` NSS-PQC section

- [ ] **Step 8:** Run `bash docker/test.sh nss-pqc -- src/pkcs11_check/testcases/test_object_visibility.py` to verify fixes

- [ ] **Step 9:** Commit
```bash
git commit -m 'fix: handle NSS read-only token in object visibility/session tests'
```

### Task 1.2: Fix test_ro_session_restrictions.py Template Errors

**Goal:** Fix the 1 test that gets `CKR_TEMPLATE_INCOMPLETE` instead of expected RO session error.

**Files:**
- Modify: `src/pkcs11_check/testcases/test_ro_session_restrictions.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/creating_objects.md`

- [ ] **Step 1:** Read the failing test and identify which attributes are missing from the template

- [ ] **Step 2:** Read OASIS spec `creating_objects.md` — check required attributes for the object type being created

- [ ] **Step 3:** Fix the template to include all required attributes so the test actually reaches the RO-session check

- [ ] **Step 4:** Verify with Docker run

- [ ] **Step 5:** Commit

---

## Phase 2: Missing v3.0 Attributes (16 failures)

### Task 2.1: Investigate CKA_COPYABLE / CKA_DESTROYABLE Missing

**Goal:** Determine if NSS-PQC supports these v3.0 attributes or if tests need guards.

**Files:**
- Read: `src/pkcs11_check/testcases/test_attribute_defaults.py`
- Read: `src/pkcs11_check/testcases/test_attribute_enforcement.py`
- Read: `src/pkcs11_check/testcases/test_access_control.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/common_attributes.md`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/key_objects.md`

- [ ] **Step 1:** Read OASIS spec for CKA_COPYABLE, CKA_DESTROYABLE, CKA_KEY_GEN_MECHANISM, CKA_ALWAYS_AUTHENTICATE — determine which PKCS#11 version introduced each

- [ ] **Step 2:** Check NSS-PQC interface version from artifacts (v3.0) — which attributes MUST be supported?

- [ ] **Step 3:** For each `KeyError: CKA_COPYABLE` etc., determine:
  - Is the attribute spec-required for the interface version? → Module bug, document
  - Is the attribute optional? → Test should guard with try/except or attribute probe

- [ ] **Step 4:** Fix tests that assume v3.0 attributes without checking:
```python
# Pattern: probe attribute availability before asserting
try:
    val = rs.raw.get_attribute(obj, CKA_COPYABLE)
except Exception:
    pytest.skip("CKA_COPYABLE not supported by module")
```

- [ ] **Step 5:** Document missing attributes in NSS-PQC module-issues section

- [ ] **Step 6:** Verify with Docker

- [ ] **Step 7:** Commit

### Task 2.2: Fix CKA_LOCAL / CKA_PRIVATE / CKA_EXTRACTABLE Default Tests

**Goal:** Fix 5 tests where CKA_LOCAL/CKA_PRIVATE return False when spec requires True.

**Files:**
- Modify: `src/pkcs11_check/testcases/test_attribute_defaults.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/key_objects.md`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/private_key_objects.md`

- [ ] **Step 1:** Read the failing tests and the OASIS spec for each attribute's default value

- [ ] **Step 2:** Determine for each:
  - CKA_LOCAL should be True for generated keys (spec says so) → NSS bug, document
  - CKA_PRIVATE should default to True for private keys → NSS bug, document
  - CKA_EXTRACTABLE should default to False for private keys → NSS bug, document

- [ ] **Step 3:** These are genuine module spec deviations. Document each in module-issues.md. Tests should FAIL (they are correct).

- [ ] **Step 4:** Commit documentation update

---

## Phase 3: CKR Error Code Compliance (15 failures)

### Task 3.1: Investigate NULL Mechanism CKR Returns

**Goal:** Determine correct CKR for NULL mechanism pointer per OASIS spec.

**Files:**
- Read: `src/pkcs11_check/testcases/ckr/test_ckr_raw_args_bad.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/function_return_values.md`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/encryption_functions.md`

- [ ] **Step 1:** Read 5 failing NULL mechanism tests — they expect `CKR_ARGUMENTS_BAD`, NSS returns `CKR_MECHANISM_INVALID` (0x70) or `CKR_MECHANISM_PARAM_INVALID` (0x71)

- [ ] **Step 2:** Read OASIS spec `function_return_values.md` section on error priority — is `CKR_MECHANISM_INVALID` acceptable for a NULL mechanism pointer?

- [ ] **Step 3:** Read the CKR tables for C_EncryptInit, C_SignInit, etc. in the relevant function spec files

- [ ] **Step 4:** Determine:
  - If spec says `CKR_ARGUMENTS_BAD` is the only correct response for NULL → NSS bug, document, test is correct
  - If spec allows `CKR_MECHANISM_INVALID` as an alternative → update test's acceptable CKR set

- [ ] **Step 5:** Apply fix or document

- [ ] **Step 6:** Commit

### Task 3.2: Fix CKR_KEY_FUNCTION_NOT_PERMITTED Tests

**Goal:** Handle NSS returning `CKR_KEY_TYPE_INCONSISTENT` instead of `CKR_KEY_FUNCTION_NOT_PERMITTED`.

**Files:**
- Read: `src/pkcs11_check/testcases/ckr/test_ckr_raw_attrs.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/function_return_values.md`

- [ ] **Step 1:** Read the 2 failing tests and the OASIS spec CKR priority rules

- [ ] **Step 2:** Check: does the spec say `CKR_KEY_FUNCTION_NOT_PERMITTED` MUST be returned, or is `CKR_KEY_TYPE_INCONSISTENT` also valid for this situation?

- [ ] **Step 3:** The spec section "More on relative priorities of Cryptoki errors" defines the ordering. Check if key-type check happens before key-function-permission check.

- [ ] **Step 4:** If test is overly strict → widen acceptable CKR set. If NSS is wrong → document.

- [ ] **Step 5:** Commit

### Task 3.3: Fix Remaining CKR Mismatches (8 tests)

**Goal:** Investigate and fix/document the remaining 8 CKR error code mismatches across 7 files.

**Files:**
- Read: `src/pkcs11_check/testcases/ckr/test_ckr_codes.py` (2 failures)
- Read: `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py` (1)
- Read: `src/pkcs11_check/testcases/ckr/test_ckr_object.py` (1)
- Read: `src/pkcs11_check/testcases/ckr/test_ckr_session.py` (1)
- Read: `src/pkcs11_check/testcases/ckr/test_ckr_spec_compliance.py` (1)
- Read: `src/pkcs11_check/testcases/ckr/test_ckr_universal.py` (1)
- Read: `src/pkcs11_check/testcases/ckr/test_ckr_wrap.py` (1)
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/function_return_values.md`

For each failure:

- [ ] **Step 1:** Read the test and the expected vs actual CKR

- [ ] **Step 2:** Read the OASIS spec CKR table for the specific function

- [ ] **Step 3:** Categorize:
  - `CKR_OK` when error expected (e.g., sensitive value readable, already-logged-in accepted) → **Security finding**, document prominently
  - Different CKR code but still indicating failure → check spec priority rules
  - Test bug (wrong expectation) → fix test

- [ ] **Step 4:** Special attention to security-relevant ones:
  - `CKR_ATTRIBUTE_SENSITIVE` expected, got `CKR_OK` → NSS returns sensitive values (SECURITY)
  - `CKR_BUFFER_TOO_SMALL` expected, got `CKR_OK` → NSS overwrites buffer (SECURITY)
  - Wrapping non-extractable key succeeded → SECURITY

- [ ] **Step 5:** Apply fixes and document each finding

- [ ] **Step 6:** Commit

---

## Phase 4: Security Findings (6 failures)

### Task 4.1: Investigate Sensitive Key Material Leakage

**Goal:** Verify and document NSS allowing read of CKA_VALUE on sensitive keys.

**Files:**
- Read: `src/pkcs11_check/testcases/test_sensitivity.py`
- Read: `src/pkcs11_check/testcases/test_api_security.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/key_objects.md`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/common_attributes.md`

- [ ] **Step 1:** Read both test files and understand what they test

- [ ] **Step 2:** Read OASIS spec on CKA_SENSITIVE behavior — when must `CKR_ATTRIBUTE_SENSITIVE` be returned?

- [ ] **Step 3:** Verify the tests are correct per spec. If CKA_SENSITIVE=True and CKA_EXTRACTABLE=False, reading CKA_VALUE MUST fail.

- [ ] **Step 4:** These are genuine security findings in NSS. Tests should FAIL. Document in module-issues.md under "Security Findings" subsection with severity assessment.

- [ ] **Step 5:** Cross-check against `artifacts/nss/` — is this the same in NSS 3.120.1? (Yes per cross-reference data — it's a long-standing NSS issue)

- [ ] **Step 6:** Commit documentation

### Task 4.2: Investigate Wrap-Decrypt Oracle and Copy Escalation

**Goal:** Verify and document the remaining 4 security findings.

**Files:**
- Read: `src/pkcs11_check/testcases/test_api_security.py` (wrap-decrypt oracle, copy escalation)
- Read: `src/pkcs11_check/testcases/test_padding_oracle.py` (OAEP timing)
- Read: `src/pkcs11_check/testcases/test_tookan.py` (Tookan extractable escalation)
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/key_objects.md`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/rsa.md` (OAEP error codes)

- [ ] **Step 1:** Read each test, understand what security property it checks

- [ ] **Step 2:** For wrap-decrypt oracle: verify per spec that a key SHOULD NOT have both CKA_WRAP and CKA_DECRYPT simultaneously

- [ ] **Step 3:** For copy escalation: verify per spec that CKA_EXTRACTABLE cannot be changed from False to True via C_CopyObject

- [ ] **Step 4:** For OAEP timing: read RSA OAEP spec section — does it mandate uniform error codes?

- [ ] **Step 5:** For Tookan: this is a well-known vulnerability class. Check if NSS applies the recommended countermeasures.

- [ ] **Step 6:** Document all 4 as security findings with severity levels. Tests are correct — they SHOULD fail.

- [ ] **Step 7:** Commit

---

## Phase 5: EdDSA & Signature Issues (7+296 failures)

### Task 5.1: Fix EdDSA CKR_MECHANISM_PARAM_INVALID

**Goal:** Fix 7 EdDSA test failures where NSS-PQC rejects the mechanism parameters.

**Files:**
- Read: `src/pkcs11_check/testcases/test_eddsa.py`
- Read: `src/pkcs11_check/raw/pack_mechanisms.py` (`mech_eddsa` function)
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/elliptic_curves.md` (EdDSA section)

- [ ] **Step 1:** Read the 7 failing tests — which Ed25519/Ed448 operations fail?

- [ ] **Step 2:** Read OASIS spec EdDSA section — what does `CK_EDDSA_PARAMS` require?

- [ ] **Step 3:** Check `docs/module-issues.md` — NSS previously returned `CKR_ARGUMENTS_BAD` for EdDSA, fixed by using explicit `CK_EDDSA_PARAMS`. Does NSS-PQC (3.121.0) need a different parameter structure?

- [ ] **Step 4:** Possible causes:
  - NSS-PQC requires `phFlag=0` explicitly (pure EdDSA mode)
  - NSS-PQC doesn't accept CK_EDDSA_PARAMS at all (wants NULL params like v2.40 style)
  - Context data handling differs

- [ ] **Step 5:** Test different parameter configurations via subprocess script

- [ ] **Step 6:** Fix test or document NSS-PQC EdDSA parameter requirements

- [ ] **Step 7:** Commit

### Task 5.2: Investigate Wycheproof DSA Rejections (296 failures)

**Goal:** Determine root cause of NSS rejecting all valid Wycheproof DSA signatures.

**Files:**
- Read: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_dsa.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/dsa.md`

- [ ] **Step 1:** Read the test — how are DSA keys imported and signatures verified?

- [ ] **Step 2:** Check which 4 DSA parameter sets fail:
  - `dsa_2048_256_sha256_test.json` (82)
  - `dsa_3072_256_sha256_test.json` (82)
  - `dsa_2048_224_sha256_test.json` (80)
  - `dsa_2048_224_sha224_test.json` (52)

- [ ] **Step 3:** This is a known NSS issue (same 296 in all 3 NSS variants). Determine:
  - Is NSS over-strict on DSA parameter validation?
  - Does NSS require specific key encoding that differs from Wycheproof format?
  - Is the Wycheproof import format correct for PKCS#11?

- [ ] **Step 4:** Read OASIS spec DSA section for key import attribute requirements

- [ ] **Step 5:** Try importing a single DSA key manually via subprocess to get the exact error

- [ ] **Step 6:** Document root cause in module-issues.md. If it's a key import format issue in the test → fix. If NSS rejects valid signatures → document as module bug.

- [ ] **Step 7:** Commit

---

## Phase 6: PQC-Specific Issues (ML-KEM, 11+1 failures)

### Task 6.1: Fix ML-KEM Buffer Too Small Errors (9 failures)

**Goal:** Fix ML-KEM encapsulate/decapsulate `CKR_BUFFER_TOO_SMALL` errors.

**Files:**
- Read: `src/pkcs11_check/testcases/test_kem.py`
- Read: `src/pkcs11_check/raw/api.py` (C_EncapsulateKey, C_DecapsulateKey signatures)
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/ml-kem.md`

- [ ] **Step 1:** Read the 9 failing ML-KEM tests — which parameter sets? (ML-KEM-768, ML-KEM-1024?)

- [ ] **Step 2:** Read OASIS ML-KEM spec — what are the correct ciphertext and shared-secret sizes?
  - ML-KEM-512: ct=768, ss=32
  - ML-KEM-768: ct=1088, ss=32
  - ML-KEM-1024: ct=1568, ss=32

- [ ] **Step 3:** Check test buffer allocation — is it using the correct sizes?

- [ ] **Step 4:** Check if tests use two-pass (query size first, then allocate) or pre-allocated buffers

- [ ] **Step 5:** If test allocates wrong buffer size → fix test. If NSS returns wrong required size → document as module bug.

- [ ] **Step 6:** Verify fix with Docker

- [ ] **Step 7:** Commit

### Task 6.2: Fix ML-KEM Template and Error Code Issues (2+1 failures)

**Goal:** Fix remaining ML-KEM failures: template errors and CKR mismatches.

**Files:**
- Read: `src/pkcs11_check/testcases/test_kem.py`
- Read: `src/pkcs11_check/testcases/ckr/test_ckr_kem.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/ml-kem.md`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/key_management_functions.md`

- [ ] **Step 1:** Read the `CKR_TEMPLATE_INCOMPLETE` failure — which attributes are missing from the derive template?

- [ ] **Step 2:** Read ML-KEM spec for required template attributes in C_EncapsulateKey and C_DecapsulateKey

- [ ] **Step 3:** Read the CKR_KEM test — NSS returns `CKR_KEY_HANDLE_INVALID` instead of `CKR_KEY_TYPE_INCONSISTENT` when using RSA key for KEM. Check spec CKR table for C_EncapsulateKey.

- [ ] **Step 4:** Fix tests where our template is incomplete; document NSS CKR deviations

- [ ] **Step 5:** Commit

### Task 6.3: Investigate Wycheproof ML-KEM Decapsulation Failure

**Goal:** Fix the 1 Wycheproof ML-KEM-512 decapsulation failure.

**Files:**
- Read: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mlkem.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/ml-kem.md`

- [ ] **Step 1:** Read the failing test — `mlkem_512_semi_expanded_decaps_test.json:tc1-valid`

- [ ] **Step 2:** Check if "semi_expanded" format is something NSS doesn't support (NSS may only support standard format)

- [ ] **Step 3:** If test uses unsupported key format → add mechanism/capability check. If NSS should support it → document.

- [ ] **Step 4:** Commit

---

## Phase 7: AES/AEAD Buffer Issues (18+2 failures)

### Task 7.1: Fix AES-GCM Buffer Too Small (4+1 failures)

**Goal:** Fix AES-GCM tests returning `CKR_BUFFER_TOO_SMALL`.

**Files:**
- Read: `src/pkcs11_check/testcases/test_aead.py`
- Read: `src/pkcs11_check/testcases/test_interop.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/additional_aes_mechanisms.md`

- [ ] **Step 1:** Read failing tests — how is the output buffer sized for GCM?

- [ ] **Step 2:** Read OASIS spec GCM section — does output include the tag? What's the correct buffer size: `len(plaintext) + tag_bits/8`?

- [ ] **Step 3:** Check if tests account for the GCM authentication tag in buffer sizing

- [ ] **Step 4:** Fix buffer allocation if test is wrong; document if NSS requires non-standard sizes

- [ ] **Step 5:** Commit

### Task 7.2: Fix AES Key Wrap KWP Failures (2 failures)

**Goal:** Fix AES-KEY-WRAP-KWP extended mechanism failures.

**Files:**
- Read: `src/pkcs11_check/testcases/test_extended_mechanisms.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/aes_key_wrap.md`

- [ ] **Step 1:** Read failing tests — what mechanism params are used?

- [ ] **Step 2:** Read OASIS spec for AES-KEY-WRAP-KWP — parameter requirements

- [ ] **Step 3:** Fix or document

- [ ] **Step 4:** Commit

### Task 7.3: Fix AES-XCBC-MAC Verify Failure (2 failures)

**Goal:** Investigate NSS returning `CKR_KEY_TYPE_INCONSISTENT` on AES-XCBC-MAC verify.

**Files:**
- Read: `src/pkcs11_check/testcases/test_aes_modes.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/aes.md`

- [ ] **Step 1:** Read the test — sign works but verify fails. Is the key the same object?

- [ ] **Step 2:** Read OASIS spec — does AES-XCBC-MAC support C_Verify or only C_Sign?

- [ ] **Step 3:** If spec says verify is valid for XCBC-MAC → document NSS bug. If verify is not in the mechanism-function table → fix test to not attempt verify.

- [ ] **Step 4:** Commit

---

## Phase 8: Miscellaneous Module Failures (25 failures)

### Task 8.1: Fix Key Flag and Data Object Tests (4 failures)

**Goal:** Fix CKA_LOCAL, CKA_NEVER_EXTRACTABLE flag tests and data object creation.

**Files:**
- Read: `src/pkcs11_check/testcases/test_key_flags.py`
- Read: `src/pkcs11_check/testcases/test_data_objects.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/key_objects.md`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/data_objects.md`

- [ ] **Step 1:** Read each test and the spec for the relevant attributes

- [ ] **Step 2:** CKA_LOCAL not set on generated keys — spec says it MUST be set. NSS bug, document.

- [ ] **Step 3:** Data object creation fails — check required attributes per spec

- [ ] **Step 4:** Commit

### Task 8.2: Fix Session and Operation State Tests (3 failures)

**Goal:** Investigate session state machine and operation state issues.

**Files:**
- Read: `src/pkcs11_check/testcases/test_session_state_machine.py`
- Read: `src/pkcs11_check/testcases/test_operation_state.py`
- Read: `src/pkcs11_check/testcases/test_v30_session.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/session_mgmt_functions.md`

- [ ] **Step 1:** C_CloseSession returning CKR_OK on already-closed session — read spec for expected behavior

- [ ] **Step 2:** C_GetOperationState returning CKR_STATE_UNSAVEABLE — is this valid for the operation type?

- [ ] **Step 3:** C_LoginUser returning CKR_OPERATION_NOT_INITIALIZED — read spec for C_LoginUser requirements

- [ ] **Step 4:** Fix tests or document NSS deviations

- [ ] **Step 5:** Commit

### Task 8.3: Fix Sign/Verify and Access Control Edge Cases (8 failures)

**Goal:** Fix remaining signature, access control, and RNG failures.

**Files:**
- Read: `src/pkcs11_check/testcases/test_sign_recover.py` (2)
- Read: `src/pkcs11_check/testcases/test_verify_signature.py` (1)
- Read: `src/pkcs11_check/testcases/test_access_control.py` (1 — copy non-copyable)
- Read: `src/pkcs11_check/testcases/test_access_levels.py` (1 — trusted wrap)
- Read: `src/pkcs11_check/testcases/test_large_objects.py` (1 — 100KB random)
- Read: `src/pkcs11_check/testcases/test_protocol_edge_cases.py` (1 — large random)
- Read: `src/pkcs11_check/testcases/test_rsa_key_wrapping.py` (1 — non-extractable wrap)

For each:

- [ ] **Step 1:** Read the test and identify the failure

- [ ] **Step 2:** Read the relevant OASIS spec section

- [ ] **Step 3:** Categorize: test bug → fix. Module deviation → document. Security finding → document prominently.

- [ ] **Step 4:** The verify-with-wrong-key returning CKR_OK and non-extractable-key wrap succeeding are potential SECURITY findings — handle with care.

- [ ] **Step 5:** The 100KB C_GenerateRandom CKR_ARGUMENTS_BAD may be a valid NSS limit — check spec.

- [ ] **Step 6:** Fix and document all

- [ ] **Step 7:** Commit

### Task 8.4: Fix PBE and Token Flag Issues (2 failures)

**Goal:** Fix PBE key type mismatch and token flag test.

**Files:**
- Read: `src/pkcs11_check/testcases/test_pbe.py`
- Read: `src/pkcs11_check/testcases/test_token_flags.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/password-based_encryption.md`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/slot_and_token_mgmt_functions.md`

- [ ] **Step 1:** PBE-SHA1 key type mismatch — which key type does NSS produce vs what test expects?

- [ ] **Step 2:** CKF_USER_PIN_INITIALIZED not set — this is expected for NSS crypto-services slot (no PIN). Check if test should skip when no PIN.

- [ ] **Step 3:** Fix or document

- [ ] **Step 4:** Commit

---

## Phase 9: Xfail Investigation & Triage (598 xfails)

### Task 9.1: Verify Wycheproof ChaCha20-Poly1305 Xfails (256)

**Goal:** Confirm these are expected NSS limitations, not test issues.

**Files:**
- Read: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_chacha.py`

- [ ] **Step 1:** Check if NSS-PQC advertises CKM_CHACHA20_POLY1305 mechanism

- [ ] **Step 2:** If advertised but not functional → module bug, document. If not advertised but tests run anyway → check why they're not skipping.

- [ ] **Step 3:** Document status

- [ ] **Step 4:** Commit

### Task 9.2: Verify HKDF Xfails (232)

**Goal:** Confirm HKDF parameter issues are NSS limitations.

**Files:**
- Read: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_hkdf.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/hkdf_mechanisms.md`

- [ ] **Step 1:** Check which HKDF mechanism(s) fail — CKM_HKDF_DERIVE or CKM_HKDF_DATA?

- [ ] **Step 2:** Read OASIS HKDF spec for parameter requirements

- [ ] **Step 3:** Is it a parameter format issue (test bug) or NSS limitation?

- [ ] **Step 4:** If test bug → fix and un-xfail. If NSS limitation → document.

- [ ] **Step 5:** Commit

### Task 9.3: Verify AES-KWP Xfails (77)

**Goal:** Check if AES-KWP output size mismatches are test bugs.

**Files:**
- Read: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/aes_key_wrap.md`

- [ ] **Step 1:** 55 are "output size mismatch", 22 are "wrap failed". Read test logic.

- [ ] **Step 2:** Read OASIS AES-KEY-WRAP-KWP spec — what's the correct output size formula?

- [ ] **Step 3:** If test has wrong expected size → fix and un-xfail. If NSS produces wrong size → document.

- [ ] **Step 4:** Commit

### Task 9.4: Investigate IKE / SP800-108 / Remaining Xfails (33)

**Goal:** Triage remaining xfails: IKE (16), SP800-108 (7), HKDF_DATA (3), and scattered (7).

**Files:**
- Read: `src/pkcs11_check/testcases/test_ike.py`
- Read: `src/pkcs11_check/testcases/test_sp800_108_kdf.py`
- Read: `src/pkcs11_check/testcases/test_hkdf_extended.py`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/ike_mechanisms.md`
- Spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/sp800-108_key_derivation.md`

- [ ] **Step 1:** IKE mechanisms all return CKR_MECHANISM_PARAM_INVALID — check if our parameter packing matches the OASIS IKE spec

- [ ] **Step 2:** SP800-108 Feedback/Double Pipeline — check parameter packing against spec

- [ ] **Step 3:** HKDF_DATA derive CKR_TEMPLATE_INCONSISTENT — check derive template attributes

- [ ] **Step 4:** For each: fix if test bug, document if NSS limitation

- [ ] **Step 5:** Commit

---

## Phase 10: Skip Analysis & Coverage Gaps

### Task 10.1: Analyze EC Curve Skip Patterns (~24,700 skips)

**Goal:** Document which EC curves NSS-PQC supports and verify skips are correct.

**Files:**
- Read: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py`
- Read: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py`

- [ ] **Step 1:** Extract the exact skip reasons and group by curve

- [ ] **Step 2:** Verify: NSS supports P-256, P-384, P-521 but NOT secp256k1, brainpool, secp224r1, secp192r1, secp160x, Montgomery (X25519/X448). Confirm this matches the skip pattern.

- [ ] **Step 3:** Check if Ed25519/Ed448 skips (236) are due to import format or mechanism. NSS does support EdDSA — maybe the Wycheproof key import format needs fixing.

- [ ] **Step 4:** Document NSS-PQC curve support in module-issues.md

- [ ] **Step 5:** Commit

### Task 10.2: Analyze Mechanism Skip Patterns (~2,500 skips)

**Goal:** Document which mechanisms NSS-PQC does NOT support.

- [ ] **Step 1:** Extract unique skip reasons matching "not supported" from the state.json

- [ ] **Step 2:** Group by mechanism family: SHA-3, AES variants, ML-DSA, SLH-DSA, ChaCha20, GMAC, XTS, etc.

- [ ] **Step 3:** Cross-reference with coverage.json mechanism list

- [ ] **Step 4:** Document in module-issues.md and update mechanism-audit.md with NSS-PQC section

- [ ] **Step 5:** Commit

### Task 10.3: Create NSS-PQC Mechanism Audit

**Goal:** Create an NSS-PQC mechanism audit (like the existing Kryoptic one).

**Files:**
- Create: section in `docs/mechanism-audit.md` for NSS-PQC
- Read: `artifacts/nss-pqc/coverage.json`

- [ ] **Step 1:** From coverage.json, extract available mechanisms, invoked mechanisms, not-invoked mechanisms

- [ ] **Step 2:** For each not-invoked mechanism, determine if it's because:
  - No test exists for it → gap to fill
  - Test exists but was skipped → check skip reason
  - Test exists but uses different mechanism name → mapping issue

- [ ] **Step 3:** Write the audit section with tables

- [ ] **Step 4:** Commit

---

## Phase 11: Documentation & Matrix Update

### Task 11.1: Update Module Matrix

**Goal:** Add post-fix NSS-PQC results to the module matrix.

**Files:**
- Modify: `docs/module-matrix.md`

- [ ] **Step 1:** Run fresh Docker test after all fixes
```bash
bash docker/test.sh nss-pqc
```

- [ ] **Step 2:** Extract final counts

- [ ] **Step 3:** Update the module-matrix.md table with NSS-PQC 3.121.0 results

- [ ] **Step 4:** Commit

### Task 11.2: Final module-issues.md Review

**Goal:** Ensure all findings are documented with spec references.

**Files:**
- Modify: `docs/module-issues.md`

- [ ] **Step 1:** Review the NSS-PQC section — every documented issue should reference the OASIS spec section

- [ ] **Step 2:** Add severity levels: Critical (security), Major (spec violation), Minor (non-standard but harmless), Info (implementation choice)

- [ ] **Step 3:** Cross-reference with CVE list — any findings that match known CVEs?

- [ ] **Step 4:** Commit

### Task 11.3: Update docs/status.md and docs/test-coverage.md

**Goal:** Reflect NSS-PQC testing status in project docs.

- [ ] **Step 1:** Update status.md with NSS-PQC section

- [ ] **Step 2:** Update test-coverage.md with NSS-PQC numbers

- [ ] **Step 3:** Commit

---

## Gap Analysis

### What This Plan Covers
- All 415 failed tests investigated and categorized
- All 598 xfailed tests verified or fixed
- Key skip patterns analyzed
- Mechanism coverage audit created
- Module-issues documentation comprehensive
- OASIS spec cross-referenced for every CKR/attribute claim

### What This Plan Does NOT Cover
1. **Writing new tests for untested NSS mechanisms** — covered by the mechanism audit (Task 10.3) which identifies gaps, but writing the actual tests is a separate plan
2. **NSS 3.120.1 / NSS-main fixes** — this plan focuses on NSS-PQC; findings may apply to other variants but aren't validated against them
3. **Upstream NSS bug reports** — documenting findings in module-issues.md is in scope; filing Mozilla Bugzilla reports is out of scope
4. **ASAN/fuzzing runs** — CVE-2019-11729/11745 and CVE-2024-6602 require ASAN builds, which is a separate infrastructure task
5. **ML-DSA / SLH-DSA testing** — NSS-PQC doesn't support these yet (all skipped); when NSS adds support, a new plan will be needed
6. **CI integration** — adding NSS-PQC to automated CI is a separate infrastructure task

### Risk Assessment
- **Low risk:** Phases 0-2 (infrastructure, documentation, attribute tests)
- **Medium risk:** Phases 3-4 (CKR compliance may require nuanced spec interpretation)
- **Medium risk:** Phases 5-8 (fixing tests may reveal additional issues)
- **Low risk:** Phases 9-11 (triage and documentation)

### Estimated Effort
- Phase 0: 1-2 hours (baseline)
- Phase 1: 2-4 hours (29 tests, mostly token write-protected)
- Phase 2: 2-3 hours (16 tests, attribute investigation)
- Phase 3: 4-6 hours (15 tests, deep spec reading required)
- Phase 4: 2-3 hours (6 tests, security documentation)
- Phase 5: 4-8 hours (303 tests, EdDSA + DSA investigation)
- Phase 6: 4-6 hours (12 tests, PQC spec compliance)
- Phase 7: 3-4 hours (20 tests, buffer sizing)
- Phase 8: 4-6 hours (25 tests, diverse)
- Phase 9: 6-8 hours (598 xfails, deep triage)
- Phase 10: 4-6 hours (coverage analysis)
- Phase 11: 2-3 hours (documentation)
- **Total: ~40-60 hours across 30 tasks**
