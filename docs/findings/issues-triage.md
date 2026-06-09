# Living issue triage — pool fail / xfail / crash analysis

**Purpose:** Standing, periodically-refreshed triage of every `fail` / `xfail` / `crash` across the
docker provider pool. Each issue is classified by the project's one rule
([classification-model-design.md](../classification-model-design.md)):

- **harness-bug** — pkcs11-check's own fault (mis-classification, missing negotiation/gating, provoked
  UB). **Fixable in pkcs11-check.** Marked 🔧. Fixes go through a separate, user-approved pass and must
  not hide findings (real provider behavior stays visible; a fix that changes a verdict gets a
  dedicated regression test — see [[feedback_harness_fix_regression_test]]).
- **provider-deviation** — the module did the right thing imperfectly (clean non-spec CKR, advertised
  but not operational). Already `xfail`ed by the model = **working as intended**, document only. Marked 📋.
- **crash** — segfault / SIGBUS / hang. The finding itself. Marked 💥. (But: a crash provoked by the
  *harness* feeding undefined-behavior input is a harness-bug, not a module finding — see C-cluster.)

> **ANALYSIS ONLY.** This file records and classifies. No test/source changes are made while building it.

---

## Run log

| Pass | Date | Pool run | Shards done | Notes |
|---|---|---|---|---|
| 1 | 2026-06-09 | `--all --concurrency 4` (PID 1250142, **still running**) | 20 / 24 | kryoptic + tpm2 + (pkcs11-mock report pending) still executing. wolfpkcs11/corepkcs11 shards not yet reached. |

**Method:** parse each completed shard's `artifacts/<shard>/results.json` (`tool=pkcs11-check`, structured
per-test outcomes), merge shards by provider, group failed/error tests by `(outcome, file, normalised
longrepr)` to collapse per-vector explosions. Aggregator: `/tmp/triage_agg.py` (throwaway).

---

## Per-provider summary (pass 1, 20 shards)

| provider | total | passed | **failed** | xfailed | crashed | skipped | baseline failed (2026-05-27) |
|---|---|---|---|---|---|---|---|
| bouncyhsm | 108,635 | 55,388 | **8,197** | 8,604 | 7 | 36,439 | 7,692 |
| softhsm2 | 82,467 | 44,792 | **171** | 5,021 | 0 | 32,483 | 85 |
| kryoptic | — | — | — | — | — | — | 115 (pending this run) |
| nss | 93,493 | 38,137 | **234** | 1,805 | 6 | 53,311 | 151 |
| nss-pqc | 92,650 | 36,661 | **209** | 1,724 | 7 | 54,049 | 119 |
| nss-slot0 | 2,391 | 1,440 | **61** | 191 | 6 | 693 | — (slot0 subset) |
| nss-pqc-slot0 | 2,442 | 1,470 | **61** | 194 | 7 | 710 | — (slot0 subset) |
| opencryptoki | 97,875 | 63,175 | **360** | 1,218 | 0 | 33,122 | 270 |
| opencryptoki-master | 97,875 | 63,175 | **360** | 1,218 | 0 | 33,122 | 271 |
| pkcs11-mock | 32,944 | 736 | **290** | 70 | 0 | 31,848 | 1,353 |
| tpm2 | — | — | — | — | — | — | 213 (pending this run) |

Note: totals shifted vs. baseline (suite grew, e.g. opencryptoki 97,356 → 97,875), so a raw failed-count
delta is **not** by itself a regression — the *signature* is what matters below.

---

## 🔧 HARNESS-BUG CANDIDATES (for the approved fix pass)

### H1 — De-identification coverage gap: raw-unwrap wrap tests miss the negotiation relaxation  ·  ✅ FIXED (commit 1941ac77)

> **Resolved 2026-06-09** on `fix/triage-harness-improvements`. Scope was wider than the top-18 list
> showed: **12 sites / 6 files** (added `test_extended_mechanisms` AES-KWP ×2, `test_keymgmt` ×1,
> `test_metamorphic` ×1). All routed through `unwrap_key_for_mechanism_roundtrip`. **Landmine avoided:**
> `test_cve_regression.py::test_unwrapped_key_preserves_extractable` also uses a raw policy-attr unwrap
> but its *premise* is that CKA_EXTRACTABLE survives — a blanket reroute would have silently broken it;
> it (plus `test_tookan` negative + `test_ro_session_restrictions`) is allowlisted in the new guard
> `tests/test_wrap_roundtrip_uses_negotiation.py`. **Verified (docker):** opencryptoki 12 prev-failing
> tests now pass; softhsm2 unchanged. Gates: mypy 359 clean, ruff clean, 1902 meta-tests pass.

- **Providers:** opencryptoki, opencryptoki-master
- **Tests / effect:**
  - `test_rsa_key_wrapping.py::TestRSAPKCSWrap::test_wrap_unwrap_aes128` — `CkrAssertionError: CKR_ATTRIBUTE_READ_ONLY; expected CKR_OK` ×4
  - `test_rsa_extended.py::TestRSAAESKeyWrap::test_wrap_unwrap_aes128` — `CKR_ATTRIBUTE_READ_ONLY` ×2
  - `test_key_lifecycle.py::TestAESKeyWrapLifecycle::test_aes_wrap_unwrap_roundtrip` — `CKR_ATTRIBUTE_READ_ONLY` ×2
  - (long tail of related 1–2× wrap/unwrap signatures inside opencryptoki's 1,509 distinct sigs)
- **Evidence:** these three files are **RAW-UNWRAP** — they do *not* call `negotiate_request` /
  `unwrap_key_for_mechanism_roundtrip` (grep-confirmed). The behavioral-adaptation refactor
  ([[project_behavioral_module_adaptation]]) applied the policy-attr relaxation (drop
  `CKA_EXTRACTABLE`/`CKA_SENSITIVE` on a template-shape reject) only to `test_authenticated_wrap`,
  `test_aes_modes`, `test_mech_wrap`, `test_aead_wrap_outputs`, `security/test_tookan`,
  `wycheproof/test_wycheproof_aes`. opencryptoki rejects unwrap templates carrying policy attrs with
  `CKR_ATTRIBUTE_READ_ONLY` (documented in [module-issues.md](../module-issues.md)). opencryptoki
  failed 270 → 360.
- **Spec:** PKCS#11 v3.x §5.18.4 (C_UnwrapKey); opencryptoki policy-attr behavior.
- **Proposed direction (fix pass):** route these unwrap valid-legs through
  `unwrap_key_for_mechanism_roundtrip` / `negotiate_request` so the policy-attr drop is negotiated; keep
  the wrap/unwrap correctness assertion intact. Add a regression test. **Do not** simply widen the
  accepted-CKR set (that would hide a real READ_ONLY).
- **Why it matters:** this is the clearest "pkcs11-check's own fault" item — a known gap left by the
  refactor I shipped, provider-general, directly verifiable.

### H2 — ACVP / Wycheproof positive-op KATs hard-fail on a *clean* error (model says xfail)  ·  HIGH (large)

- **Providers:** bouncyhsm (dominant), some on opencryptoki.
- **Tests / effect (positive op, valid vector, clean non-OK CK_RV → hard `fail`):**
  - `test_ccm.py::test_acvp_aes_ccm_encrypt` — `CKR_GENERAL_ERROR; expected CKR_OK` ×2,518
  - `test_ccm.py::test_acvp_aes_ccm_decrypt` — `CKR_ENCRYPTED_DATA_INVALID; expected CKR_OK` ×3,161
  - `test_wycheproof_aes.py::test_aes_ccm[*-valid]` — `CKR_ENCRYPTED_DATA_INVALID` ×357
  - `test_wycheproof_hmac.py::test_hmac_wycheproof[...sha1...valid]` — `CKR_ARGUMENTS_BAD` ×48
  - `test_sha3.py::TestSHA3Digest::test_sha3_empty` — `CKR_ARGUMENTS_BAD` ×4
  - `test_wycheproof_rsa_siggen.py::test_rsa_pkcs1_siggen` — `CKR_GENERAL_ERROR` ×10
- **Why candidate:** per the classification table, a *clean error* on a **positive op for an advertised
  mechanism** = "advertised but not operational" = **xfail**, not fail. These KAT runners hard-fail it.
  This looks like a coverage gap in the classification rework ([[project_classification_rework]]) — the
  ACVP-AES / wycheproof-KAT positive-op paths never got the advertised-but-not-operational downgrade
  that other suites did.
- **MUST VERIFY before fixing (two forks, both harness-bugs but different fix):**
  1. Is the mechanism **advertised**? softhsm2/kryoptic pass these CCM/HMAC vectors (not in their
     failure lists) → the harness param-encoding is correct and the failures are bouncyhsm-specific. If
     bouncyhsm *advertises* CKM_AES_CCM but errors → xfail downgrade is right. If it does **not**
     advertise it, the test failed to gate on `has_mechanism()` → that's the bug instead.
  2. Confirm these are **error returns**, not `CKR_OK`+wrong-output. The signatures are all CK_RV
     errors (GENERAL_ERROR / ENCRYPTED_DATA_INVALID / ARGUMENTS_BAD), so xfail is indicated — but the
     fix must **preserve `CKR_OK`+wrong-output as `fail` (Type A)**.
- **Spec:** [classification-model-design.md](../classification-model-design.md) positive-op row; CLAUDE.md
  "right thing done imperfectly = xfail."
- **Proposed direction:** a shared KAT helper that downgrades a clean non-OK CK_RV on an advertised
  mechanism to xfail ("advertised but not operational"), reserving `fail` for wrong-output and
  crash/hang. Large surface — one helper, not per-test edits. **This is ~⅔ of bouncyhsm's failures**, so
  resolving it would mostly explain the 8,197 count.

### H3 — opencryptoki RSA-OAEP SHA-512/224 | SHA-512/256 hard-fail (newly-added vectors)  ·  MEDIUM

- **Provider:** opencryptoki, opencryptoki-master
- **Test / effect:** `test_wycheproof_rsa_oaep.py::test_rsa_oaep[rsa_oaep_2048_sha512_224|256_mgf1*]` —
  `CKR_ENCRYPTED_DATA_INVALID; expected CKR_OK` ×26
- **Why candidate:** these OAEP SHA-512/224|256 vectors were added recently
  ([[project_testdata_coverage_gaps]]). opencryptoki evidently doesn't implement those OAEP hash params
  → clean error on a positive op → xfail material ("hash variant not operational"). The KAT hard-fails.
- **Same fork as H2** (advertised/operational vs wrong-output — here it's an error return → xfail).
- **Proposed direction:** same shared KAT downgrade as H2 (per-hash OAEP not operational → xfail).

### H4 — bouncyhsm: legal session object in RO session rejected, hard-fails  ·  MEDIUM

- **Provider:** bouncyhsm
- **Test / effect:** `test_ro_session_restrictions.py::TestROSessionObjectsAllowed::test_create_session_object_in_ro_succeeds`
  — `CKR_SESSION_READ_ONLY; expected CKR_OK` ×5
- **Why candidate:** creating a **session** (non-token) object in an RO session is spec-**legal**
  (`CKR_SESSION_READ_ONLY` is only for *token* objects). bouncyhsm rejects it — a clean deviation on a
  positive op → xfail per model; the test asserts `CKR_OK` and hard-fails.
- **Spec:** PKCS#11 §5.4 / object creation in RO sessions.
- **Proposed direction:** downgrade a clean `CKR_SESSION_READ_ONLY` on a *session-object* create to
  xfail (records the bouncyhsm deviation without calling it a hard fail). Low count.

### H5 — opencryptoki AES-CTR / AES-CTS operational errors hard-fail  ·  LOW

- **Provider:** opencryptoki. `test_aes_modes.py` — `TestAESCTR::test_aes_ctr_different_keys`
  `CKR_DATA_LEN_RANGE` ×2; `TestAESCTS::test_aes_cts_roundtrip` `CKR_MECHANISM_INVALID` ×2.
- CTS `MECHANISM_INVALID` = not supported → should be a `has_mechanism` **skip** (or xfail). CTR
  `DATA_LEN_RANGE` = clean operational error → xfail. `test_aes_modes` already uses the helper, so this
  is a *different* gap (capability gating / clean-error on the non-unwrap path), not H1. Verify gating.

---

## 💥 CRASHES (report) — **pending UB-vs-module determination**

> Precedent: [[project_threading_ub_finding]] — a "crash" the *harness* provokes by feeding
> undefined-behavior input (e.g. declaring `ulDataLen = ULONG_MAX` while `pData` points at a small
> buffer → the module reads out of bounds) is a **harness-bug**, not a module finding. Each cluster
> below must be checked: does the test pass an honestly-sized buffer, or lie about the length? That
> determines crash-report vs 🔧.

### C1 — bouncyhsm: AES encrypt/decrypt length-overflow segfault
- `test_arithmetic_overflow.py::TestDataLengthOverflow::test_data_length_overflow[encrypt|decrypt-ulong_max]`
  — `C_Encrypt/C_Decrypt(ulDataLen=ULONG_MAX): module crashed with signal 11` ×4 each.

### C2 — NSS (all variants): FFI isize_max segfault
- `test_ffi_length_boundary.py` — `C_Sign / C_Verify / C_Digest / C_SignUpdate / C_VerifyUpdate /
  C_DigestUpdate(... isize_max): module crashed with signal 11` ×2 each, plus `C_SeedRandom(isize_max):
  subprocess exit 1`. Present identically on nss, nss-pqc, nss-slot0, nss-pqc-slot0 (= the 6–7 "crashed"
  per nss variant).

### C3 — opencryptoki: template-count overflow crash
- `test_arithmetic_overflow.py::TestTemplateCountOverflow::...[find_objects_init-ulong_max]` —
  `C_FindObjectsInit(template_count=ULONG_MAX): signal 7` (SIGBUS) ×3
- `...TestTemplateCountOverflowValidHandles...` — `C_GetAttributeValue(valid object,
  template_count=ULONG_MAX): signal 11` ×3

**Determination needed (next pass):** read `test_arithmetic_overflow.py` / `test_ffi_length_boundary.py`
buffer construction. If they allocate a real buffer and only *declare* an oversized length → these are
harness-provoked OOB UB (→ 🔧, document misuse per the threading precedent, don't fail-test). If the
request is honest → real module length-validation crash (→ keep as 💥 finding). The `*_rejects_cleanly`
sibling variants already xfail (clean reject), so the test family *expects* clean rejection — the crash
cases are the ones to adjudicate.

---

## 📋 PROVIDER DEVIATIONS — already `xfail`ed correctly (working as intended, document only)

These are the model doing its job (de-identification routing clean deviations to xfail). **No action.**
Representative clusters:

- **bouncyhsm** `test_acvp_ecdh.py` — "Curve P-* advertised but ECDH derive not operational:
  CKR_MECHANISM_PARAM_INVALID" ×1,736 (xfail). `test_cctv_ed25519.py` low-order-point vectors rejected
  with GENERAL_ERROR ×464 (xfail). `test_gcm.py` GMAC not supported ×30 (xfail).
- **nss / nss-pqc** `test_cctv_ed25519.py` Ed25519 verify → `CKR_FUNCTION_NOT_SUPPORTED` ×814 (xfail);
  `test_eddsa`, `test_ike`, `test_ssl3`, `test_sp800_108_kdf`, `test_mech_attribute` clean
  not-operational deviations (xfail). softhsm2 5,021 xfail — the model's main bucket.
- **opencryptoki** `test_v30_session` C_LoginUser FUNCTION_NOT_SUPPORTED, `test_message_crypto`,
  `test_ssl3`, `test_hash_ml_dsa`, `test_authenticated_wrap` GCM-wrap FUNCTION_NOT_SUPPORTED — all xfail.

The large `xfailed` totals (softhsm2 5,021; bouncyhsm 8,604) confirm the classification rework +
de-identification are routing clean deviations correctly; no provider-identity leakage observed.

---

## Pending for next pass

1. kryoptic + tpm2 shards (still running) — add to summary, watch for de-identification regressions
   (kryoptic DEVICE_ERROR catch-all must stay code-irrelevant per [[reference_kryoptic_default_ckrv]]).
2. wolfpkcs11 / corepkcs11 — not yet reached this run (no prior baseline either).
3. Adjudicate the C1–C3 crash clusters (UB vs module) by reading the two overflow test files.
4. Confirm H2/H3 fork (advertised? error-vs-wrong-output) before any fix.
