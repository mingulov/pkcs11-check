# Timeout Recovery & Artifact Failure Fixes

**Date:** 2026-04-07
**Status:** Approved
**Scope:** Two-part design — (1) fix adaptive isolation timeout behavior, (2) fix pkcs11-check failures found in artifact analysis

---

## Part 1: Timeout Recovery — Progressive Retry with Deselect

### Problem

When a test file times out at file granularity in `--isolation auto` mode, the current code
(`file_runner.py` lines 2112-2169):

1. Parses partial JSONL and saves records to state — good
2. Calls `_promote_crashing_unit()` to add file to policy — wrong for timeouts
3. Calls `_escalate_current_file()` which discovers ALL nodeids and inserts them as per-test units
4. Does NOT exclude already-passed tests from the escalated list

**Result:** A file with 28,668 tests that timed out at 87% completion gets escalated to 28,668
individual subprocess runs (~2.3s each = ~18 hours), even though ~24,000 tests already passed.

### Solution: Progressive Retry with Deselect

Reuse the existing iterative-deselect pattern (used for crash recovery, lines 2259-2384) but
adapted for timeout recovery.

#### Flow

```
File times out at file granularity in mixed mode:
  1. TimeoutExpired → parse partial JSONL (already done at lines 2114-2120)
  2. _identify_crash_culprit() → get (culprit, completed_nodeids)
  3. If culprit exists:
     - Run culprit individually with per-test timeout
     - If passes/fails normally → module is fine, it was just slow
     - If times out/crashes → record it, add to deselect set
  4. Deselect completed + culprit from the file
  5. Retry the SAME FILE in per-file mode with new timeout scaled to remaining tests
  6. If retry times out → repeat from step 1 (progressive shrinking)
  7. Safety cap: after 3 consecutive file-level timeouts on same file, fall back to
     escalation of REMAINING untested nodeids only (not all)
  8. Do NOT promote to policy on timeout (only on crash) — timeout is not a module bug
```

#### Timeout Calculation Change

**Current** (`_unit_timeout_seconds`, line 1635):
```python
def _unit_timeout_seconds(test_timeout: int, granularity: IsolationGranularity) -> int:
    if granularity == "test":
        return max(test_timeout + 60, 120)
    return max(test_timeout * 30, 900)  # Fixed 3600s for default 120s timeout
```

**Proposed** — add `num_tests` parameter:
```python
def _unit_timeout_seconds(
    test_timeout: int,
    granularity: IsolationGranularity,
    num_tests: int = 0,
) -> int:
    if granularity == "test":
        return max(test_timeout + 60, 120)
    if num_tests > 0:
        # 5s per test + 60s startup, floor 300s, cap 14400s (4h)
        return min(max(num_tests * 5 + 60, 300), 14400)
    return max(test_timeout * 30, 900)  # fallback when count unknown
```

The `num_tests` count comes from:
- Initial run: `discover_pytest_units()` with `granularity="test"` to count nodeids
- Retry runs: `num_tests = total_nodeids - len(deselect_set)`

For the wycheproof ECDSA case (28,668 tests): `min(143,400, 14400)` = 14,400s (4h).
After timeout with ~24,000 passed, retry with ~4,668 remaining: still capped at 14,400s = ample.

#### Test Count Discovery

To compute `num_tests` for the timeout formula, we need the test count for each file-level unit.
Two options:

**Option A (lazy):** Count from JSONL after first run. For initial run, use fallback formula.
On retry, `num_tests` = number of nodeids seen in JSONL (`len(completed) + (1 if culprit else 0)`)
gives the total test count for the file. Remaining tests = total - `len(deselect_set)`.

**Option B (upfront):** Pre-discover test counts for all file units via `--collect-only`.
Adds startup cost but gives accurate timeouts from the start.

**Choice: Option A** — simpler, no extra subprocess per file. The first run uses the
existing fallback formula (`max(test_timeout * 30, 900)`). Retries use accurate counts
derived from JSONL parsing.

#### Changes to `_promote_crashing_unit()`

Do NOT call `_promote_crashing_unit()` for timeout status. Timeouts are not module bugs —
they're just slow files. The policy file should only track crash-promoted files.

**Current** (line 2129): Called unconditionally for both timeout and crash.
**Proposed:** Only call for crash status, not timeout.

#### Safety Cap

After 3 consecutive file-level timeout retries on the same file within the same retry loop
(i.e., 3 iterations of the progressive-retry without the file completing):
- Fall back to escalation of REMAINING untested nodeids only
- The `_escalate_current_file()` function needs a `exclude_nodeids` parameter
  to filter out already-completed tests

#### Files Modified

- `src/pkcs11_check/core/file_runner.py`:
  - `_unit_timeout_seconds()` — add `num_tests` parameter
  - Timeout handler block (lines 2112-2196) — replace escalation with progressive retry loop
  - `_escalate_current_file()` — add `exclude_nodeids` parameter
  - `_promote_crashing_unit()` — skip for timeout status (or move call out of timeout path)

---

## Part 2: Artifact Failure Fixes

### Analysis Summary

Artifacts analyzed from 5 providers: kryoptic-main, nss-main, opencryptoki-master,
softhsm2-main, tpm2. Total: ~106K tests per provider.

| Provider | Passed | Failed | Errors | Skipped | Crashed |
|----------|--------|--------|--------|---------|---------|
| kryoptic | 64,215 | 1,525 | 0 | 40,802 | 0 |
| nss | 47,351 | 1,082 | 0 | 57,907 | 1 |
| opencryptoki | 73,946 | 2,157 | 0 | 30,322 | 6 |
| softhsm2 | 59,547 | 1,397 | 0 | 44,923 | 0 |
| tpm2 | 3,032 | 3,503 | 59,112 | 39,851 | 0 |

### Category 1: Confirmed Framework Bug (fix immediately)

**AES-XTS test TypeError** — `src/pkcs11_check/testcases/acvp/aes/test_xts.py`
- 1,200 failures on OpenCryptoki (only provider supporting XTS)
- Missing `lambda x: bytes.fromhex(x)` for "tweak" field in vector loading (~lines 40, 46)
- Other providers skip XTS, masking the bug
- **Fix:** Add proper lambda converter for tweak field

### Category 2: Cross-Provider Failures — Investigate Each

These files fail on 3-4 providers. The agent found they have DIFFERENT error codes per
provider (e.g., `test_acvp_ecdh.py` returns CKR_DEVICE_ERROR on kryoptic,
CKR_TEMPLATE_INCONSISTENT on NSS, CKR_FUNCTION_FAILED on opencryptoki,
CKR_GENERAL_ERROR on softhsm2). This suggests the tests are correct and each module
has its own bug. But each needs verification.

**Investigation protocol per file:**
1. Read test code — are parameters valid per PKCS#11 spec?
2. Read error messages from report.jsonl for 2+ providers
3. Classify: test bug (fix) / correct finding (leave) / too strict (soften carefully)

| File | Failures (4 providers) | Hypothesis |
|------|----------------------|------------|
| `acvp/test_acvp_ecdh.py` | 100+100+100+100 | Likely correct — different CKR per module |
| `test_mech_sign.py` | 66+39+6+0 | Investigate kryoptic/NSS counts |
| `test_mech_multipart.py` | 7+31+9+10 | Investigate NSS count |
| `test_mech_attribute.py` | 4+47+4+0 | Investigate NSS count (47) |
| `test_mech_keygen.py` | 3+34+2+0 | Investigate NSS count (34) |
| `acvp/test_acvp_eddsa.py` | 13+15+4+4 | EdDSA implementation variance |
| `wycheproof/test_wycheproof_aes.py` | 123+77+107+0 | AES mode params |
| `test_mech_encrypt.py` | 3+3+3+6 | Quick check — small counts |
| `test_mech_wrap.py` | 2+5+4+2 | Quick check |
| `security/test_arithmetic_overflow.py` | 4+0+3+8 | Security — should stay strict |
| `wycheproof/test_wycheproof.py` | 3+0+3+9 | Quick check |
| `test_mech_derive.py` | 1+1+0+2 | Quick check |
| `test_mech_lifecycle.py` | 1+1+0+1 | Quick check |
| `test_interop_openssl.py` | 0+1+1+1 | Quick check |

### Category 3: Module-Specific — Investigate Suspect Cases Only

Only investigate where there's reason to suspect a test parameter bug:

| File | Provider(s) | Failures | Why investigate |
|------|-------------|----------|----------------|
| `wycheproof/test_wycheproof_rsa_pss.py` | ock+softhsm2 | 435+435 | Same count on 2 providers — PSS param encoding? |
| `wycheproof/test_wycheproof_rsa_oaep.py` | softhsm2 | 668 | Large count — OAEP params valid? |
| `acvp/aes/test_cts.py` | kryoptic+nss | 405+399 | CTS variant detection logic |

**Leave as findings (do not fix — these ARE the test suite's purpose):**
- Kryoptic ECDSA (467F) — CKR_DEVICE_ERROR
- Kryoptic ML-DSA (249F) — PQC incomplete
- NSS DSA (296F) — CKR_ARGUMENTS_BAD
- OpenCryptoki x509 (233F) — CKR_USER_NOT_LOGGED_IN
- SoftHSM2 ECDH (32F) — derivation bug
- TPM2 (62K errors) — DA lockout, expected for hardware HSM

### Category 4: xfails Audit

268 xfails across providers. Key target:
- `acvp/test_acvp_ecdsa.py` — 30 xfails on ALL 4 main providers
- Each xfail must have evidence and spec reference per project philosophy
- Quick audit: read the xfail markers, verify reasoning

### Execution Model

**Part 1 (timeout fix):**
- Single Opus agent modifying `file_runner.py`
- Requires careful understanding of the iterative-deselect pattern
- Tests: meta-tests in `tests/test_isolation.py`

**Part 2 investigations (Category 2 — 14 files):**
- Parallel Sonnet agents, one per file or small group
- Read-only analysis: read test code + report.jsonl errors
- Output: classification per file (fix / leave / soften)
- Can run 4-5 agents in parallel

**Part 2 fixes (based on investigation results):**
- Confirmed framework bugs: Sonnet agents for simple fixes (XTS lambda)
- Complex fixes (if any found): Opus agent
- Each fix verified against the specific provider that exposed it

**Part 2 xfails audit:**
- Single Sonnet agent to audit the 30 cross-provider xfails
