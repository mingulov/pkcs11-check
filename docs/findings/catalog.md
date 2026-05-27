# Findings Catalog (2026-05-27 artifact set, excl. bouncyhsm)

Detailed root cause + classification for each failure/crash class. Classification:
**PROVIDER** (real module defect) · **PKCS11-CHECK** (our test/harness bug) ·
**KNOWN** (already in `docs/module-issues.md`) · **EXPECTED** (correct behavior).
Status per finding: `confirmed` or `NEEDS-CONFIRM` (verify in fix phase, possibly
via Docker rerun into a new artifact folder).

Counts are failures in this artifact set (per `failure-inventory.json`).

---

## A. PKCS11-CHECK bugs (fix in our code)

### PC-1 — GCM NULL-AAD probe: test script ctypes error  ·  confirmed
- **Count/scope:** 10 (every in-scope provider, 1 each).
- **Class:** `test_gcm_null_aad_pointer_nonzero_length :: GCM NULL AAD pointer with nonzero ulAADLen: subprocess failed with exit code 1`.
- **Evidence:** subprocess stderr is a **Python traceback**, not a module crash:
  `File "<string>", line 40 ... params.pIv = (cty...`. `exit code 1`.
- **Root cause:** `src/pkcs11_check/testcases/security/test_parameter_validation.py:266`
  `params.pIv = (ctypes.c_ubyte * 12)(*range(12))` — assigning a ctypes array to the
  `CK_AES_GCM_PARAMS.pIv` pointer field raises in the generated subprocess script, so the
  probe dies during setup and **never reaches `C_EncryptInit`**.
- **The probe itself is INTENDED and valid** (NULL `pAAD` + nonzero `ulAADLen` is a real
  robustness scenario; a robust module must return `CKR_ARGUMENTS_BAD`, a buggy one may
  deref NULL and crash). The harness bug only *blocks* it on all providers; it is **not**
  evidence the providers are fine.
- **Classification:** PKCS11-CHECK (setup bug) — but **fixing it must SURFACE, not hide,
  real behavior.** Fix = build `pIv` via `ctypes.cast(...)` like the other GCM tests, then
  **re-run the affected Docker targets (new artifact folder)** and record whatever the now-live
  probe finds: a crash = PROVIDER finding (`fail`), a clean reject = pass, accepting
  NULL+nonzero-len = PROVIDER finding. **Add a dedicated regression test** (mock-`raw`
  meta-test in `tests/`) that asserts the probe constructs `CK_AES_GCM_PARAMS` correctly and
  that a NULL-deref/crash is reported — so this can never silently regress to a setup no-op.
- **RESOLVED 2026-05-27 (FP-1):** fixed the `pIv` assignment (`ctypes.cast(_iv_buf, c_void_p)`,
  IV buffer kept alive); param snippet extracted to a module constant; regression test
  `tests/test_parameter_validation_gcm_probe.py` (verified RED with the old line:
  `TypeError: ... c_ubyte_Array_12 instead of c_void_p`, GREEN after fix). **The now-live probe
  UNMASKED a real PROVIDER crash**: stock SoftHSM2 2.7.0 **SIGSEGV (signal 11)** on
  `C_EncryptInit(AES_GCM, pAAD=NULL, ulAADLen=16)` — documented in `module-issues.md`
  (GCM null-AAD finding). Full cross-provider rerun pending. Lesson confirmed: the harness
  bug was hiding a genuine finding.

### PC-2 — ML-DSA sigVer rejects VALID signatures across 3 unrelated providers  ·  NEEDS-CONFIRM
- **Count/scope:** 36 — softhsm2-main 9, nss 9, opencryptoki 9, opencryptoki-master 9.
- **Class:** `TestMlDsaSigVer::test_acvp_mldsa_sigver :: ML-DSA-sigVer-...-tcN: module rejected a VALID ML-DSA signature`.
- **Reasoning:** the *same* ACVP vectors rejected by three independent implementations is a
  signal of a pkcs11-check encoding/context bug (e.g. ML-DSA context byte, mu/pure mode, or
  message encoding) rather than three coincident provider defects. Kryoptic is absent here
  (it returns DEVICE_ERROR on ML-DSA sign — see PV-7), so the picture is muddied.
- **Classification:** likely PKCS11-CHECK (ML-DSA sigVer vector handling). Confirm by
  decoding one rejected vector and checking the signature/context encoding the harness sends.

### PC-3 — tpm2 RSA-PSS with MD5/SHA-1 hash: missing capability guard  ·  NEEDS-CONFIRM
- **Scope:** tpm2 (`test_rsa_pss_md5_hash` etc.; part of the 43 "valid rejected").
- **Evidence:** `Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK`.
- **Reasoning:** TPM legitimately refuses MD5 (and often SHA-1) PSS. The test asserts CKR_OK,
  so a correct provider rejection is scored as a failure. Should be a capability skip.
- **Classification:** likely PKCS11-CHECK (guard MD5/SHA-1 PSS by mechanism/hash support).
  Confirm against the tpm2 mechanism list. (The "invalid accepted = 39" tpm2 rows are the
  opposite direction and may be a real PROVIDER finding — see PV-8.)

### PC-4 — WRONG_CKR expectation mismatches (assorted)  ·  NEEDS-CONFIRM
Small classes where the module returns a *plausibly correct* CKR the test didn't list:
- `TestROWrapUnwrapRestrictions::test_unwrap_to_token_object_in_ro_fails` → `CKR_TEMPLATE_INCOMPLETE` (softhsm2, opencryptoki). RO-session rejection via a different-but-valid CKR.
- `TestWrapIntegrity::test_aes_key_wrap_bit_flip_detected` → `CKR_GENERAL_ERROR` (softhsm2).
- `TestRSAOAEPWrapLifecycle::test_rsa_oaep_wrap_aes_roundtrip` → `CKR_ARGUMENTS_BAD` (softhsm2).
- `TestEcPointValidation::test_ecdh_invalid_point` → `CKR_ATTRIBUTE_VALUE_INVALID` (tpm2) — looks like a *correct* rejection scored as wrong.
- **Classification:** mostly PKCS11-CHECK (widen accepted-CKR sets) — confirm each is genuinely
  a valid rejection, not a real wrong-code provider bug. Per project rule, only widen to
  SPECIFIC additional CKRs.

### PC-5 — KWP bit-flip unwrap: setup wrap failure unguarded  ·  confirmed
- **Count/scope:** 15 — nss, nss-main, nss-pqc (5 each).
- **Class:** `TestBitFlipUnwrap::test_bit_flip_unwrap :: ... subprocess failed with exit code 1`.
- **Evidence:** Python traceback in **setup**: `wrapped_blob = wrap_key_recipe(raw, sh, wrap_key, target_key, CKM_AES_KEY_WRAP_KWP)` → `recipes.py:1031 _two_call_output`. The KWP *wrap* step (test setup) raises and is not classified.
- **Classification:** PKCS11-CHECK (guard/xfail the KWP-wrap setup reject like other capability setups). **Must not hide a real defect:** capture the actual CKR from the failing KWP *wrap* — if NSS genuinely cannot KWP-wrap, that is a PROVIDER capability gap to record (skip/xfail with the real `rv`), not silently pass. The *unwrap* bit-flip integrity check (the test's real purpose) must still run wherever wrap succeeds. Add a regression test pinning the setup-reject classification.
- **RESOLVED 2026-05-27 (FP-2):** added importable `child_setup_reject_known()` in
  `security/conftest.py` (emits `SETUP_XFAIL` marker → parent `pytest.xfail` for a known
  reject; returns False to **re-raise** unknown errors/crashes so they still surface). The KWP
  subprocess script now scopes the wrap in an inner `try` and classifies the reject against a
  **specific** CKR set. Regression test `tests/test_error_path_kwp_setup_classification.py`
  (RED → GREEN). softhsm2 (KWP-capable) still runs the real unwrap-integrity check (5 passed).
  NSS's actual reject `rv` (truncated in the baseline artifact) is confirmed in the FP-8 rerun;
  if it falls outside the set, the test surfaces it rather than hiding it.

### PC-6 — tpm2 negative-path CKR expectations too narrow  ·  NEEDS-CONFIRM
- **Scope:** tpm2, many count-1 classes: `C_GenerateKey(invalid_*)` → `CKR_FUNCTION_NOT_SUPPORTED`
  not in acceptable set; `test_mechanism_invalid` "Should have rejected AES_ECB as signing
  mechanism"; `test_stale_session_handles` got `CKR_FUNCTION_NOT_SUPPORTED`; several
  session-object-lifecycle `assert False`.
- **Classification:** mixed PKCS11-CHECK (widen accepted-CKR sets to include
  `CKR_FUNCTION_NOT_SUPPORTED` for tpm2's limited surface) vs genuine tpm2 capability gaps.
  Confirm against tpm2 mechanism/function support; only widen to specific CKRs.

---

## B. PROVIDER findings

### PV-1 — RSA PKCS#1 v1.5 decrypt: lenient/invalid-padding acceptance  ·  confirmed (biggest)
- **Count/scope:** 546 — kryoptic/kryoptic-main 62, nss/nss-main/nss-pqc 62, softhsm2/softhsm2-main 59, opencryptoki/opencryptoki-master 59. **tpm2 rejects (not in list).**
- **Class:** `test_rsa_pkcs1_decrypt :: RSA PKCS#1 decrypt VEC accepted invalid ciphertext`.
- **Root cause:** Wycheproof `rsa_pkcs1_*` "invalid" vectors (flags `InvalidPkcs1Padding`,
  `InvalidCiphertextFormat`, CVE-2020-14967 leading-zero ciphertext, CVE-2021-3580 over-long).
  e.g. tc9 "padding string is all 0" — should be rejected; modules return plaintext via
  `C_Decrypt(CKM_RSA_PKCS)`. Lenient PKCS#1 v1.5 unpadding (Bleichenbacher/malleability class).
- **Classification:** PROVIDER, widespread. Correctly a hard fail per the classification model
  (accept-invalid-crypto = crypto break). **Caveat to note in report:** raw `CKM_RSA_PKCS`
  leniency is industry-common; real-world risk is at the protocol layer. tpm2 is the outlier
  that rejects. Check whether `docs/module-issues.md` already covers it; add if not.

### PV-2 — opencryptoki AES-CBC-PKCS5: invalid vectors decrypt successfully  ·  confirmed
- **Count/scope:** 288 — opencryptoki 144, opencryptoki-master 144.
- **Class:** `TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5 :: Invalid AES-CBC vector tcN decrypted successfully`.
- **Root cause:** OpenCryptoki accepts invalid CBC-PKCS#5/PKCS#7 padding (padding-oracle class)
  — returns plaintext where strict unpadding should reject.
- **Classification:** PROVIDER (opencryptoki-specific; other providers not in list).

### PV-3 — EdDSA KeyVer: modules ACCEPT invalid EdDSA keys  ·  confirmed
- **Count/scope:** 34 — softhsm2/softhsm2-main/kryoptic/kryoptic-main/kryoptic-fips/opencryptoki(+master) 4 each, nss(+variants) 2 each. tc1 + tc4.
- **Class:** `TestEdDsaKeyVer::test_eddsa_keyver :: Module ACCEPTED an INVALID EdDSA key`.
- **Root cause:** ACVP EdDSA KeyVer negative vectors (malformed/invalid public keys) are
  accepted on import/verify; modules do not validate the Edwards point.
- **Classification:** PROVIDER, widespread.

### PV-7 — kryoptic ML-DSA sign + AES-CTS return CKR_DEVICE_ERROR  ·  confirmed (KNOWN)
- **Scope:** kryoptic, kryoptic-main, kryoptic-fips. `test_mldsa_sign` (18), `TestAESCTS::test_aes_cts_roundtrip`/`_different_keys` (3+3).
- **Root cause:** kryoptic returns `CKR_DEVICE_ERROR` for ML-DSA sign and AES-CTS round-trip
  (advertised mechanism not operational / broken). Cross-ref `module-issues.md` ML-DSA context.
- **Classification:** PROVIDER; likely KNOWN (ML-DSA context failure documented).

### PV-8 — tpm2 RSA-PSS: invalid signatures accepted  ·  NEEDS-CONFIRM
- **Scope:** tpm2, 39 "Invalid RSA-PSS sig accepted by module" (+43 "valid rejected", overlaps PC-3).
- **Classification:** mixed — the "invalid accepted" direction is a possible PROVIDER finding;
  the "valid rejected" direction is likely the PC-3 capability-guard test bug. Separate them
  in the fix phase.

### PV-9 — ML-DSA sign: invalid vectors accepted  ·  NEEDS-CONFIRM
- **Scope:** 32 — nss 14, softhsm2-main/kryoptic*/opencryptoki* 3 each.
- **Classification:** likely PROVIDER (don't reject malformed ML-DSA sign inputs), but confirm
  against the PC-2 ML-DSA encoding question first.

---

## C. Crashes (all PROVIDER; cross-referenced to module-issues.md)

File-level crashes (`results.json status=crashed`) + test-level "module crashed with signal".

### CR-1 — kryoptic-fips FIPS build aborts (SIGABRT, rc=6)  ·  confirmed; KNOWN class
- **Files:** acvp/aes/test_ccm.py, test_mech_derive.py, test_mech_encrypt.py, test_misc_kdf.py, wycheproof/test_wycheproof_aes.py.
- **Evidence:** `test_acvp_aes_ccm_encrypt[AES-enc-tc2051/2052]` → `Fatal Python error: Aborted`,
  backtrace ends in libc `abort()`. Adaptive isolation pinned the culprit vectors.
- **Root cause:** kryoptic FIPS/PQC build (custom OpenSSL branch) calls `abort()` on
  non-approved/edge AES + KDF operations instead of returning a CKR. Matches documented
  `module-issues.md` "FIPS mode ... aborts instead of [rejecting]" (≈L1285).
- **Classification:** PROVIDER, KNOWN class; add the concrete AES-CCM encrypt trigger.

### CR-2 — NSS softoken SIGSEGV on NULL params + extreme lengths  ·  confirmed; partly KNOWN
- **Files:** test_mech_flags.py (nss, nss-main, nss-pqc), test_mech_negative.py (nss-main, nss-pqc).
- **Evidence (signal 11):** `C_GetInfo(NULL)`, `C_GetSlotList(NULL)`, `C_DigestInit(NULL mech)`,
  `C_CreateObject(template=NULL)`, `C_FindObjectsInit(template=NULL)`, `C_GenerateKey(template=NULL)`,
  `C_EncryptInit(AES_GCM, pIv=NULL)`, `C_Sign/Verify/SignUpdate/VerifyUpdate/SeedRandom/GenerateRandom/SetOperationState(data=NULL)`,
  `C_Sign(HMAC, ulDataLen=isize::MAX)`.
- **Root cause:** NSS softoken (software token) does not validate NULL pointers / absurd
  lengths and segfaults instead of returning `CKR_ARGUMENTS_BAD`.
- **Classification:** PROVIDER; `C_DigestInit(NULL)` already in module-issues.md (≈L821).
  Consolidate the full NSS NULL-parameter cluster as one finding.

### CR-3 — Cross-provider isize::MAX `ulDataLen` crash/abort  ·  confirmed; KNOWN
- **Scope:** `C_Sign(HMAC)`/`C_Digest(SHA256)` with `ulDataLen` = `0x7fff…`/`0x8000…`.
  Signal-11 on kryoptic*, nss*, opencryptoki*, tpm2; SoftHSM2 exits 5 (documented separately).
- **Classification:** PROVIDER, KNOWN (module-issues.md isize::MAX rows ≈L1116, L1398).

### CR-4 — `C_FindObjectsInit(template_count)` integer-overflow crash  ·  confirmed; KNOWN
- **Scope:** kryoptic*, opencryptoki* (signal crash). module-issues.md ≈L34.
- **Classification:** PROVIDER, KNOWN.

### CR-5 — KWP bit-flip / GCM NULL-IV aborts (ABORT_exit class)  ·  NEEDS-CONFIRM
- **Scope:** `TestBitFlipUnwrap::test_bit_flip_unwrap` KWP (nss*, 15), GCM null-IV (KNOWN, ≈L51).
- **Note:** distinguish genuine provider aborts from any PC-1-style test-script issues; the KWP
  bit-flip rows report `subprocess failed with exit code N` — verify whether N<0 (provider) or a
  Python error (pkcs11-check) like PC-1.

---

## D. EXPECTED / non-defects

### EX-1 — pkcs11-mock CKA_VALUE round-trip mismatch  ·  confirmed
- **Count/scope:** ~559 + 30 — pkcs11-mock only (`test_exhaustive_cert_import_no_crash`,
  `test_import_limbo_failure_cert_raw`). e.g. "stored 12B vs original 454B".
- **Root cause:** pkcs11-mock is a mock that does not faithfully store object values; cert
  round-trip is meaningless against it.
- **Classification:** EXPECTED (mock artifact). Option for fix phase: skip cert round-trip /
  large-value tests on the mock provider (capability/identity guard), not a bug.

---

### EX-2 — pkcs11-mock: full functional/security suite is meaningless on a mock  ·  confirmed
- **Count/scope:** ~1,353 (pkcs11-mock dominates its own failures). Round-trip/KAT/RNG/attribute
  tests all "fail" because the mock returns canned values ("Hello world!"), non-random RNG,
  fixed labels, and does not really store objects. Examples across ~150 count-1 classes:
  `assert b'Hello world!' == ...`, `RNG produced duplicate values`, `Shannon entropy too low`,
  `cryptoki version ... below baseline`, KCV/KAT/cert/CRL round-trip mismatches.
- **Classification:** EXPECTED (mock identity). Fix-phase option: gate the functional/security/
  KAT suites off pkcs11-mock (run only smoke/diagnostic), or label it non-conformance-bearing.
  A handful of *negative* mock rows (e.g. "Should have rejected ...") are also mock no-ops.

---

## E. Long-tail PROVIDER security/behavior findings (classes ≤9)

These are genuine, smaller-count PROVIDER findings (security-marked or behavioral). All
`confirmed` as real unless noted. Counts approximate; see `failure-inventory.json`.

- **PV-10 attribute-enforcement / Tookan (softhsm2, kryoptic, opencryptoki, nss):**
  unwrapped key can unset `CKA_SENSITIVE` / preserves `CKA_EXTRACTABLE=False` wrongly;
  user can set `CKA_TRUSTED`; `CKA_COPYABLE=False` copied; `CKA_DESTROYABLE=False` destroyed;
  `C_WrapKey` on `CKA_EXTRACTABLE=False` returns CKR_OK; AES-as-DES3 key-type confusion on unwrap;
  `CKA_PRIVATE_EXPONENT`/sensitive material readable. → PROVIDER access-control findings.
- **PV-11 padding/error-uniformity oracles:** AES-CBC-PAD padding oracle (Vaudenay) distinct
  outcomes (softhsm2-main, kryoptic*, opencryptoki*); RSA-OAEP non-uniform error codes
  (nss*, opencryptoki*). → PROVIDER (oracle), aligns with PV-1/PV-2.
- **PV-12 v3.0 message API IV/nonce writeback (kryoptic*, nss):** `C_EncryptMessage` does not
  write the generated GCM IV / CCM nonce back to `pIv`. → PROVIDER.
- **PV-13 AES-CTR / KCV / buffer-state (opencryptoki*):** `ulCounterBits`=0/129 accepted (spec
  requires reject); wrong/missing KCV length; `C_SignFinal`/`C_VerifySignatureUpdate` buffer-retry
  state issues. → PROVIDER.
- **PV-14 output-buffer pulSize after CKR_BUFFER_TOO_SMALL (kryoptic*, nss, opencryptoki*):**
  required size not reported correctly / state not preserved across retry. → PROVIDER (or strict;
  confirm against spec wording for each call).
- **PV-15 misc provider correctness:** softhsm2 `C_SignInit(CKM_ECDSA, RSA_priv)` returns CKR_OK
  (should reject); kryoptic `ExtractKeyFromKey` offset wrong bytes; kryoptic AES-CBC derive same-IV;
  kryoptic `C_SessionCancel` during digest crashes (signal — see crashes). → PROVIDER.

## F. NEEDS-CONFIRM (flaky / environment / timeout)

- **CR-6 timeouts:** `TestAllocationGuard::test_generate_key_oom_value_len` (kryoptic*),
  `TestForkSafety`/`test_finalize_not_initialized` (tpm2/nss) → `subprocess.TimeoutExpired`.
  Could be PROVIDER hang (OOM keygen) or too-short test timeout (PKCS11-CHECK). Confirm via
  focused Docker rerun into a new artifact folder.
- **Timing tests:** `TestECDSATimingBasic::test_ecdsa_timing_variance` (nss, opencryptoki-master)
  — CV-based timing-leak heuristic; environment-sensitive, likely flaky → PKCS11-CHECK
  (make non-gating / informational) unless reproducible.

## Gap analysis 2026-05-27 (harness-masking pattern, using FP-1/FP-2 evidence)

Scanned all ABORT_exit failures for a **Python traceback** in the child stderr (= harness
bug masking real behavior, the PC-1/PC-5 signature). 9 classes; conclusions:
- `test_corrupted_unwrap` (48, nss) + `test_bit_flip_unwrap` (15, nss): share `_KEYGEN_AND_WRAP`
  → **already fixed by FP-2** (wrap-setup now classified).
- `test_gcm_null_aad_pointer_nonzero_length` (10): **fixed by FP-1**.
- `test_corrupted_unwrap` (16, opencryptoki): the `raise AssertionError("C_Decrypt wrote past
  the minimal output buffer …")` site — a **real PROVIDER finding** (heap overflow, matches
  OpenCryptoki PR #932), surfaced (messily) as exit-1. Visible, not hidden; improve reporting later.
- NULL-pointer hard-asserts (`test_encapsulate/decapsulate_null_pointers` kryoptic;
  `TestArgsBadNullPointers::test_*_null_mechanism` tpm2; ~5): `assert rv == CKR_ARGUMENTS_BAD`
  masks the actual rv when the module returns a different *non-crash* code → these are the
  plan's **N2 "binary assert lacking the xfail tier"** sites; fixed systematically via
  `classify_negative_rv` in the N2 phase.
- pkcs11-mock `test_double_digest_init_via_subprocess` (1): EXPECTED mock.

Net: FP-1/FP-2 covered the high-volume masking; the rest are real findings (already visible)
or N2-phase classification work. No new standalone harness-bug class found.

## Long-tail category totals (classes ≤3 occurrences)
OTHER 673 (dominated by pkcs11-mock EXPECTED), WRONG_CKR 221 (mostly PKCS11-CHECK CKR-widening /
tpm2 capability), CRASH_signal 40 (PROVIDER), ABORT_exit 31 (mix incl. PC-1/PC-5 test bugs),
ACCEPT_INVALID 1.

## Outstanding (to finish this phase)
- Confirm: PC-2 (ML-DSA sigVer encoding), PC-3/PV-8 (tpm2 RSA-PSS split), PC-4/PC-6 (CKR widenings), CR-6 (timeouts).
- Cross-check each PROVIDER finding against `docs/module-issues.md`; mark KNOWN vs NEW.
- Write per-provider summary docs (task #4) keyed to these finding IDs.
- Then (separate phase): batch fixes (PC-* in our code; widen CKR sets; gate pkcs11-mock) +
  Docker reruns into NEW artifact folders to re-measure.
