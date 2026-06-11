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

> ⚠️ **POOL-STALENESS WARNING (proven 2026-06-09).** The pool ran `--all --no-build`, so each
> provider used a **pre-built image** that may predate fixes already on `dev`. Confirmed concrete:
> the pool reported kryoptic AES-CCM as **0 pass / 3,420 xfail**, but a **fresh rebuild**
> (`docker/test.sh kryoptic -- test_ccm.py`) gives **4,890 pass / 3,508 xfail** — kryoptic CCM works
> fine. **Pool numbers can grossly overstate issues. Every candidate MUST be re-confirmed with a fresh
> targeted rebuild before any fix.** (Reinforces the earlier full-results-audit staleness gotcha.)

---

## Run log

| Pass | Date | Pool run | Shards done | Notes |
|---|---|---|---|---|
| 1 | 2026-06-09 | `--all --concurrency 4` (PID 1250142, **still running**) | 20 / 24 | kryoptic + tpm2 + (pkcs11-mock report pending) still executing. wolfpkcs11/corepkcs11 shards not yet reached. **Pool used `--no-build` → some provider images stale (see warning above).** |
| 2 | 2026-06-09 | same run (still running) | 33 shards | New providers landed: kryoptic/-main/-fips, tpm2, softhsm2-main/-generated-iv, corepkcs11, nss-main. wolfpkcs11/-master still running. **Staleness re-confirmed:** completed kryoptic shard shows CCM 3,420 xfail / 0 pass, but fresh rebuild = 4,890 pass → the pool kryoptic image is genuinely stale for CCM. New signal: **corepkcs11 22,756 failed** (21,906 = `ARGUMENTS_BAD` in `test_wycheproof_ecdsa.py`) — see H6. |
| 3 | 2026-06-09 | same run | +corepkcs11-main | corepkcs11-main byte-identical to corepkcs11 (H6 stable trait). |
| 4 | 2026-06-09 | same run | +wolfpkcs11 | wolfpkcs11 stable: 3,071 fail / 18 crash — H7 (digest malformed CK_RV) + C4 (crashes). |
| 5 | 2026-06-09 | **POOL COMPLETE** — 191m45s, 21 providers / 32 items / K=4 | 21 / 21 | wolfpkcs11-master landed: **2,673 fail / 4 crash** (vs stable 3,071 / 18) — master fixed most crashes → strongly reinforces the fresh-verify rule. **Analysis loop done; next phase = fresh-rebuild verification + user-approved fixes.** |

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

### H2 — KAT clean-error classification  ·  RE-SCOPED after deep investigation (2026-06-09)

**The original "broaden the xfail set" framing was wrong** — a deep, fresh-rebuild investigation
(probing kryoptic + bouncyhsm directly) disproved the "⅔ of bouncyhsm is a clean-error misclassification"
hypothesis and split it into three very different things:

**(a) CCM mass-failure was mostly STALE POOL DATA.** Pool showed kryoptic CCM 0 pass / 3,420 xfail and
bouncyhsm 7,282 fail, suggesting "CCM broken everywhere." Fresh evidence:
- `docker/test.sh kryoptic -- test_ccm.py` → **4,890 pass / 3,508 xfail**. kryoptic CCM **works**; the
  pool ran a stale `--no-build` image. The 3,508 xfails are real param rejections (e.g. kryoptic rejects
  7-byte CCM nonce → `MECHANISM_PARAM_INVALID`, correctly xfailed by the existing narrow guard).
- Direct probe (canonical n13/tag16 vector, fresh build): kryoptic CCM single-shot → **CKR_OK + ct**;
  bouncyhsm CCM single-shot → **CKR_GENERAL_ERROR on every variant**, while bouncyhsm **GCM works**.
  Both advertise CCM with `CKF_ENCRYPT` (kryoptic 0x60326, bouncyhsm 0x60301).
- **Conclusion:** kryoptic CCM = healthy (no action). bouncyhsm CCM single-shot = **genuinely
  non-operational** (advertised but `GENERAL_ERROR`) → the model says **xfail**, currently `fail`
  because `GENERAL_ERROR` isn't in the runner's narrow `{MECHANISM_INVALID, MECHANISM_PARAM_INVALID}`
  xfail set. This is the *only* real CCM issue, and it is **bouncyhsm-specific and modest**, not 5,700.

**(b) HMAC-wycheproof zero-pass is mostly a known deviation, not a bug.** Every provider shows pass=0;
the xfail reason is "module did not verify a valid HMAC tag" on high-index `hmac_sha1` vectors =
wycheproof **truncated-tag** valid vectors, a legitimate provider-dependent deviation already xfailed by
`_xfail_if_hmac_runtime_reject`. The only outliers are **bouncyhsm's 48 `CKR_ARGUMENTS_BAD`** (bouncyhsm
rejects some HMAC inputs differently) — bouncyhsm-specific, small.

**(c) Genuine small bouncyhsm-specific tail:** `test_sha3_empty` `ARGUMENTS_BAD` ×4, `rsa_pkcs1_siggen`
`GENERAL_ERROR` ×10 — advertised mechanism, clean error on a valid vector → xfail per model. (bouncyhsm
images in the pool are fresh — built 16:42 this run — so these are reliable; CCM proven via fresh probe.)

**Better fix than a wider CKR allowlist (the "how to do it better"): an effect-based operability probe.**
Instead of enumerating "which error codes count as not-operational" (brittle; and a too-wide list could
mask a real break), the runner should probe the mechanism **once** with a canonical known-answer vector:
- canonical → **CKR_OK + correct output** ⇒ mechanism is **operational** ⇒ every real vector failure
  stays a genuine `fail` (this is what catches a true crypto break — e.g. it would NOT have masked a
  kryoptic CCM bug, because kryoptic's canonical passes).
- canonical → **clean error (any CK_RV)** ⇒ mechanism **advertised but not operational** ⇒ xfail the
  suite, **independent of which CKR** (handles bouncyhsm's `GENERAL_ERROR` and kryoptic's
  `PARAM_INVALID` identically — no per-provider, no CKR allowlist).
- canonical → **CKR_OK + wrong output** ⇒ **crypto break** ⇒ `fail` (never xfailed).
- non-CKR exception ⇒ re-raise (a harness/ctypes bug must never be read as "not operational").

This is the same effect-over-return-code principle as the discrimination model
([[project_behavioral_module_adaptation]]), extended to KAT suites. It removes the narrow
`{MECHANISM_INVALID, MECHANISM_PARAM_INVALID}` allowlist (the actual root flaw) and is provider-general.

- **Status:** ✅ **IMPLEMENTED + fresh-verified for the AEAD runners (pass 7, 2026-06-09).**
  `testcases/_operability.py`: per-(mechanism, direction) canonical known-answer probe with
  OPERATIONAL / NOT_OPERATIONAL / WRONG_OUTPUT / INCONCLUSIVE verdicts (INCONCLUSIVE = staging/
  import failed — the H6 lesson: setup failure is not mechanism evidence) and
  `classify_kat_clean_error` (xfail on NOT_OPERATIONAL regardless of CKR; param-shape rejects
  {MECHANISM_INVALID, MECHANISM_PARAM_INVALID, ARGUMENTS_BAD} xfail on an operational mech; all
  else re-raises; non-CKR AssertionErrors always re-raise). Canonical truth is computed with
  `cryptography`, so it is spec-derived, not provider-derived. Wired into
  `base_runner_aead.py` (GCM/CCM, all four directions); meta-tests
  `tests/test_operability_probe.py` + `tests/test_aead_operability_classification.py`.
  **Fresh verification:**
  - **bouncyhsm CCM: 7,370 failed → 1,691 failed / 5,679 xfailed / 1,028 passed (passes
    unchanged)** — and the surviving failures are a REAL Type-A finding: 423× invalid-tag
    CCM ciphertext ACCEPTED + ~1,268× plaintext returned with unstripped tag bytes ⇒
    BouncyHSM CCM decrypt does not authenticate (documented in module-issues.md).
  - kryoptic CCM: 4,890 passed / 3,508 xfailed — **byte-identical to baseline** (param-shape
    xfails preserved; canonical works so nothing else got masked).
  - softhsm2: GCM 80 passed, CCM skipped (no mechanism) — unchanged; bouncyhsm GCM 80/120/30
    unchanged.
  - **Wave 2 (same pass): `test_wrap.py` (KW/KWP ×4 sites), `base_cts.py`, `test_xts.py`**
    routed through the same probe (KW/KWP canonical via `cryptography.keywrap`, XTS via
    AES-128-XTS `cryptography` cipher, CTS via the existing variant-detection effect probe).
    **Classifier corrected to match the model's positive-op row** during wolfpkcs11
    verification: with an OPERATIONAL canonical, ANY clean CKR on a positive op is the
    honest-deviation xfail (only wrong output / crash / self-contradiction fail; decrypt
    false-rejects of valid data are verdict errors handled in the runners). The
    param-shape-only narrowing now applies only to INCONCLUSIVE probes (no effect
    evidence — blanket-xfail there would have hidden H6). wolfpkcs11 `test_cts.py`
    2,079 hard-fails (unaligned-input `ENCRYPTED_DATA_INVALID`/`FUNCTION_FAILED` while
    aligned CTS works) reclassify to deviation xfails; softhsm2 `test_wrap.py`
    3,600 xfail / 3,600 skip byte-identical to pool. Fresh numbers in run log.
  - Remaining H2 surface (HMAC/SHA3/RSA KAT paths, H3 per-hash OAEP) is the sweep's next
    step using the same probe module.
- **Spec:** [classification-model-design.md](../classification-model-design.md) positive-op row.

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

### H6 — corepkcs11: ~22k `ARGUMENTS_BAD` on wycheproof ECDSA KAT  ·  🔧 ROOT-CAUSED + FIXED (pass 7, 2026-06-09)

> **Verdict overturned by deep root-cause (user prompt: "perhaps a bad wrapper?").** The earlier
> "real provider deviation, fold into H2 probe" classification was WRONG. corePKCS11's ECDSA verify
> **works** (probed in-container: valid sig → CKR_OK/True, corrupted sig → clean False). The 21,906
> hard-fails were a three-layer **call-shape/deployment mismatch**, none of them a crypto failure:
>
> 1. **Harness 🔧:** `import_ec_public_key` sends no `CKA_LABEL`; corePKCS11 (`prvCreateECKey`,
>    v3.6.4 `core_pkcs11_mbedtls.c`) requires one and returns `CKR_ARGUMENTS_BAD` — which is not in
>    the test's import-skip tuples → every vector hard-failed **at C_CreateObject**, before any
>    verify. (Verify-path ARGUMENTS_BAD was already xfail-classified; the import path wasn't.)
> 2. **Provider trait 📋:** corePKCS11 supports only **token objects** (`CKA_TOKEN=False` →
>    `CKR_ATTRIBUTE_VALUE_INVALID`) and only **P-256 + 32-byte digests** for CKM_ECDSA
>    (`CKR_DATA_LEN_RANGE` otherwise — a §2.3.1 deviation: spec requires truncating long hashes).
> 3. **Our docker target 🔧:** the stock posix demo PAL stores only the 8 fixed configured labels;
>    any other label → save fails → `CKR_DEVICE_MEMORY`. The PAL is corePKCS11's designated porting
>    point — the target, not the provider, made arbitrary-label storage impossible.
>
> **Fixes shipped (branch `fix/triage-harness-improvements`):**
> - `create_object_negotiated` / `import_ec_public_key_negotiated` (testcases/conftest.py):
>   provider-general storage-shape negotiation — canonical minimal template first, then
>   `+CKA_LABEL` (unique), then `+CKA_TOKEN=TRUE`, retrying only on clean storage-shape rejects
>   (`IMPORT_STORAGE_SHAPE_REJECTS`); crypto attrs never change, no provider identity.
>   `negotiate_request` gained a per-site `shape_rejects` param (default unchanged — guarded by
>   meta-test). Wired into `test_wycheproof_ecdsa.py` (wiring guarded by meta-test).
> - `CKR_DATA_LEN_RANGE` added to `_ECDSA_RUNTIME_REJECT_CKRS` (valid-vector xfail) and
>   `NON_CLEAN_SIGNATURE_REJECT_RVS` (invalid-vector xfail evidence) with §2.3.1 rationale.
> - Generic in-memory PAL (`docker/corepkcs11/corepkcs11_pal_generic.c`): any label, honest
>   `isPrivate` (DER-shape), real `PKCS11_PAL_DestroyObject` (store slots are reclaimed).
> - Meta-tests: `tests/test_import_template_negotiation.py` (8 tests) + classification guards.
>
> **Post-fix probe (rebuilt image):** arbitrary-label import OK → verify valid True / corrupted
> False / 64B digest `DATA_LEN_RANGE` (now xfail).
>
> **Two follow-on defects found and fixed during fresh verification:**
> - **Harness object leak (all providers):** `test_ecdsa_wycheproof` decoded the DER signature
>   *after* importing the key but *outside* the destroying try/finally — every invalid-DER vector
>   leaked one object. Fatal on a bounded store (corePKCS11's 128-slot list filled →
>   6,551 `CKR_DEVICE_MEMORY`/`HOST_MEMORY` failures). Fixed: decode before import.
> - **corePKCS11 silent curve rebind (REAL provider bug, Type-C):** C_CreateObject returns
>   `CKR_OK` for foreign-curve EC keys whose coordinate size matches P-256 (secp256k1,
>   brainpoolP256r1 — the OID length check is bypassed and `mbedtls_ecp_point_read_binary` does
>   no curve-membership check); the object is then **unusable** (readback →
>   `CKR_OBJECT_HANDLE_INVALID`, verify → `CKR_KEY_HANDLE_INVALID`). Handled effect-based:
>   `ec_public_key_binding_defect` (conftest) readback-checks each curve once per process — KAT
>   vectors of an unhonored curve **skip** (capability absent), and the contradiction itself is a
>   dedicated conformance test `test_ec_import_coherence.py` that **fails** (Type-C), once per
>   curve instead of 22k noise-fails.
>
> **Fresh verified result (corepkcs11, rebuilt image + fixed harness):**
> `test_wycheproof_ecdsa.py`: **21,906 failed / 0 passed → 0 failed / 8,662 passed /
> 19,621 skipped / 632 xfailed** (327s → 59s). `test_ec_import_coherence.py`: 1 passed
> (P-256 honored), 1 skipped (secp224r1 cleanly rejected), **2 failed = the real corePKCS11
> finding** (secp256k1/brainpoolP256r1 silent-rebind self-contradiction).
>
> **Cross-provider regression verification (user-requested, fresh runs, same files):**
> - softhsm2: **byte-identical** (21,906 passed / 7,009 skipped, 0 failed; coherence 4/4).
> - opencryptoki: 0 failed, xfail identical to pool (186); coherence 4/4.
> - kryoptic: 0 failed, xfail identical to pool (1,012); coherence 1 passed / 3 skipped
>   (cleanly rejects unsupported curves — correct).
> - kryoptic/opencryptoki show MORE passes than the pool (+7,202 / +1,149) with equally
>   fewer skips. Attributed exactly (old-harness-vs-new on the same fresh image,
>   brainpoolP224r1 slice: 1,153 skipped → 468 passed + 685 skipped; host recount of
>   undecodable-invalid vectors = 468): the **leak-fix reorder** moved DER decoding before
>   key import, so wycheproof vectors that are invalid at the encoding level (sig
>   undecodable → vacuous pass, module never involved — the pre-existing semantic wherever
>   import succeeded) no longer hide behind the unsupported-curve import skip. Outcomes are
>   now uniform across providers for those vectors; no module behavior changed, no findings
>   hidden. Probe confirmed kryoptic rejects brainpool imports with
>   `CKR_ATTRIBUTE_VALUE_INVALID` for ALL template variants — negotiation does not engage
>   usefully there and the result is the same skip as before.

- **Provider:** corepkcs11 (FreeRTOS corePKCS11, mbedTLS-backed minimal impl). 22,756 failed total;
  **21,906** were `CKR_ARGUMENTS_BAD; expected CKR_OK` in `test_wycheproof_ecdsa.py`; the rest small
  (`test_limbo_import` DATA_LEN_RANGE ×493, `test_acvp_hmac` ×148 — same storage-shape class, to be
  migrated to the negotiated import in the sweep). **corepkcs11-main is byte-identical** (same
  22,756 / 21,906) → stable corePKCS11 trait, not version-specific.
- **Lesson recorded:** a uniform clean error across an entire KAT suite at the *same call site* is a
  **pre-crypto setup failure**, not an operability statement about the mechanism — check the first
  raw call (here C_CreateObject) before classifying. This also re-scopes what the H2 probe must
  cover: the probe must distinguish "import path broken" from "mechanism not operational".

### H7 — wolfpkcs11: digest ops return a malformed CK_RV (raw wolfSSL error leak)  ·  ✅ FRESH-VERIFIED REAL (pass 6)

> **2026-06-09 fresh rebuild** (`docker/test.sh wolfpkcs11 -- acvp/test_acvp_hash.py`) = **160 failed**,
> all `Unexpected CK_RV 0xffffffffffffff7c` (e.g. SHA3-512 tc117/tc118). **Not stale** — wolfpkcs11
> genuinely leaks a raw negative wolfSSL error (-132) as the `CK_RV` on digest. Real provider bug
> (returning a non-`CKR_*` value violates the spec). Document; the suite surfaces it as a clean return.

- **Provider:** wolfpkcs11 (wolfSSL in-process C lib). 3,071 failed, **18 crashed**, 38,882 passed.
- **Signature:** `Unexpected CK_RV 0xffffffffffffff7c` ×103+ — `0x…ff7c` = **-132 sign-extended**, i.e. a raw
  negative wolfSSL internal error code leaking out as the `CK_RV` instead of a defined `CKR_*`. Sites:
  `test_acvp_hash` ×158, `test_acvp_sha3` ×79, `test_mech_digest`, `test_mech_multipart` — i.e. the
  **digest path wholesale**.
- **Class:** if real, this is a genuine **provider deviation/bug** (returning a non-CKR value violates the
  spec — `CK_RV` must be a defined code) — document, and it's a clean *return* (not a crash) so the suite
  surfaces it correctly. **BUT digest is the most basic op; wholesale digest failure smells like a STALE
  `--no-build` image.** ⚠️ **Re-confirm with `docker/test.sh wolfpkcs11 -- test_acvp_hash.py` (fresh
  rebuild) before classifying.** wolfpkcs11 stable lacks PQC. **wolfpkcs11-master: 2,673 fail / 4 crash
  (vs stable 3,071 / 18)** — master fixed most crashes, so stable's pool image is very likely behind;
  fresh-verify is essential before reporting any wolfpkcs11 finding.
- **Also on wolfpkcs11 (fold into existing buckets):** `test_cts.py` ×2,079 (CTS
  `ENCRYPTED_DATA_INVALID`/`FUNCTION_FAILED` → H2 operability-probe class); `test_wycheproof_rsa_oaep`
  ×209. All need the same fresh-rebuild re-confirmation.

---

## 💥 CRASHES — **DETERMINED 2026-06-09 (code-read + fresh repro)**

> **✅ DENIS DECISION (2026-06-10): KEEP the C1–C3 UB probes as-is — "crashes are findings."**
> The lying-buffer / NULL-deref probes stay; their crashes are reported as module findings, not
> removed/neutered. This closes the C1–C3 flag. (The analysis below stands as the rationale for why
> they are *harness-provoked UB*, but the call is to retain them as robustness probes.)
>
> Precedent: [[project_threading_ub_finding]] — a "crash" the *harness* provokes by feeding
> undefined-behavior input (e.g. declaring `ulDataLen = ULONG_MAX` while `pData` points at a small
> buffer → the module reads out of bounds) is a **harness-bug**, not a module finding.
>
> **VERDICT: C1, C2, C3 (+ the C4 UB-fork) are HARNESS-PROVOKED UB. C4 HKDF/keygen is a GENUINE
> module crash.** The overflow-suite source was read line-by-line and the crashes fresh-reproduced:
> - `test_arithmetic_overflow.py:149` — `# Small real buffer, but claim huge length`:
>   `buf = (c_ubyte*16)(...)` then `C_Encrypt(sh, buf, ULONG_MAX, ...)`. The module is told the input
>   is 2⁶⁴−1 bytes when 16 exist → it reads OOB → SIGSEGV. Fresh bouncyhsm: **24 crashed** (incl.
>   `ulDataLen=0x80000000`, `C_EncryptInit ulParameterLen=0xffff...ff` with a 16B param, and
>   `C_CreateObject template_count=0xaaa...`). Every signature is a *declared length/count that exceeds
>   the real buffer/array*.
> - `test_ffi_length_boundary.py:253` — same shape, targeting a Rust binding's `check_slice_len` panic
>   (`buf = (c_ubyte*16)`, then `C_Sign(sh, buf, isize_max, ...)`). For a C module (NSS) this is plain
>   OOB-read UB.
> - PKCS#11 §5: the caller guarantees `pData`/`pTemplate` point to `ulDataLen`/`ulCount` elements.
>   Passing a length that exceeds the buffer is **caller UB**; a module that trusts it (as the spec
>   permits — softhsm2 happens to sanity-check and so does *not* crash) is not violating the spec.
>   This is the exact pattern Denis already adjudicated as harness-UB in the threading finding.
>
> **The near-SIZE_MAX overflow class is fundamentally un-blackbox-testable through the C API**: to
> trigger an integer-overflow in `padded_len = bs*(len/bs+1)` you must pass a near-2⁶⁴ length, which is
> unallocatable as a real buffer — so the only way to reach it is to lie about the buffer, i.e. provoke
> UB. There is no honest version of these specific probes.
>
> **⚠️ ACTION NEEDS DENIS'S NOD (outward-facing, touches the "a segfault IS the finding" core):** the
> precedent resolution is *don't provoke UB in a test* (remove the lying-buffer probes / stop asserting
> `crash = module finding` for them). That removes/neuters a large, deliberately-written security suite
> (`TestDataLengthOverflow`, `TestMechanismParamLengthOverflow`, `TestTemplateCountOverflow*`,
> `TestAttributeValueLenOverflow`, the `test_ffi_length_boundary` isize probes, C4's UB-fork). Because
> that is hard to reverse and changes what the tool reports, it is **flagged here for approval** rather
> than auto-applied in the fix loop. Nuance to preserve when actioned: `CKA_VALUE_LEN=ULONG_MAX` in a
> *keygen* template is a key-*size request* (not a buffer read) — the module must validate it
> (`CKR_KEY_SIZE_RANGE`/`CKR_HOST_MEMORY`); an unchecked `malloc(ULONG_MAX)` crash there is arguably a
> *real* robustness finding and should be kept. Each overflow case must be sorted buffer-read-UB
> (remove) vs value-request (keep) — not a blanket delete.

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

### C4 — wolfpkcs11: GENUINE module crashes (real findings) + a UB-fork  ·  ✅ FRESH-VERIFIED REAL (2026-06-09)
- **GENUINE (keep as 💥 findings):** fresh rebuild `docker/test.sh wolfpkcs11 -- test_wycheproof_hkdf.py`
  → `test_hkdf` runs **10 normal Wycheproof vectors green, then SIGABRT** (`Fatal Python error: Aborted`)
  on the 11th. The input is an ordinary HKDF salt/info vector, no lying length → **real wolfpkcs11 crash
  on valid input.** `test_ckr_keygen.py` signal 11 + Aborted ×2 likewise crash on normal keygen. These
  are legitimate module bugs to report; **no harness change.** wolfpkcs11-master fixed most crashes
  (4 vs stable's 18) so report against current master.
- **UB-fork (same verdict as C1–C3, harness-provoked UB):** `test_arithmetic_overflow`
  C_GenerateKeyPair(count=ULONG_MAX); `test_ffi_length_boundary` Sign/Verify/Digest/*Update at
  `ulDataLen=0x7fffffffffffffff` ×6 — lying length/count. `test_secret_key_value_len`
  C_CreateObject(CKA_VALUE_LEN=huge) is the *value-request* nuance above (keep, it's a real
  length-validation test, not a buffer read).

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

## Fix-pass progress (2026-06-09, branch fix/triage-harness-improvements)

| Item | Provider file | Before (pool) | After (fresh) | Class |
|---|---|---|---|---|
| H6 | corepkcs11 wycheproof_ecdsa | 21,906 F / 0 P | **0 F / 8,662 P** / 632 xf | harness+target 🔧 + Type-C finding (coherence test ×2 F) |
| H2 | bouncyhsm test_ccm | 7,370 F | **1,691 F (real: no-auth CCM decrypt)** / 5,679 xf, passes = | probe 🔧 + Type-A finding 📋 |
| H2w2 | wolfpkcs11 test_cts | 2,079 F | **0 F** / 2,079 xf, 399 P = | probe 🔧 |
| sweep | corepkcs11 acvp_hmac | 148 F | **0 F** / 148 xf | negotiation 🔧 |
| sweep | corepkcs11 limbo_import | 493 F / 156 P | **0 F / 589 P** / 74 xf | portable label 🔧 |
| sweep | corepkcs11 wycheproof_aes | 63 F / 248 P | **0 F / 269 P** / 42 xf | negotiation + KEY_HANDLE_INVALID reclass 🔧 |

| H3 | opencryptoki rsa_oaep | 26 F | **0 F** / 26 xf (RFC8017 combo probe) | probe 🔧 |
| H4 | bouncyhsm ro_session | 5 F | **0 F** / 5 xf | deviation 📋 |
| H5 | opencryptoki aes_modes | 6 F | **2 F (real ulCounterBits accept)** / 4 xf | classify 🔧 + Type-A finding |
| H8 | **NSS/softhsm2/kryoptic RSA PKCS#1 v1.5 decrypt** | 62/59/62 F | **0 F** (201P each) | 🔧 security test was BACKWARDS |
| — | bouncyhsm wycheproof CCM | 420 F | **63 F (real no-auth)** / 366 xf | H2 probe routing 🔧 |

### H8 — RSA PKCS#1 v1.5 decrypt test penalized the anti-Bleichenbacher mitigation ·  🔧 FIXED (high value)

`test_wycheproof_rsa_decrypt` hard-failed **any** non-rejection of an invalid-padding PKCS#1 v1.5
ciphertext. That is **backwards**: the recommended Bleichenbacher mitigation (RFC 8017 §7.2.2;
"Marvin" 2023) is to NOT reveal padding validity — return a synthetic plaintext (or constant-time
reject). The test therefore **failed every correct provider and would have passed a naive
oracle-prone one** — the single clearest "the test is wrong, not the module" finding of the sweep.

- Evidence: softhsm2 59F / kryoptic 62F / NSS 62F (every real provider). In-container probe of NSS
  over all 25 invalid vectors: **0 returned the target message (zero breaks)**, 20 synthetic, 5
  rejected — all secure.
- Fix: flag a finding only when the returned plaintext **equals the target message** (each invalid
  Wycheproof vector carries it) = the actual padding-check bypass. Synthetic plaintext or clean
  reject = secure → pass. The real break is still caught.
- Verified: nss/softhsm2/kryoptic **201/201 passed** (≈183 cross-provider false failures gone).
  OAEP (Manger = constant-time reject, no synthetic) left as-is — no live false-positive.

Controls byte-identical on every step: softhsm2 (ecdsa 21,906P, wrap 3,600xf, hmac 470P,
aes 476P, limbo 663P, oaep 439P/646xf, aes_modes 5P, ro_session 16P/2xf), kryoptic
(ccm 4,890P/3,508xf ×2, ecdsa 0F), opencryptoki (0F where unchanged).

**Quality-loop regression gate (2026-06-09, full `docker/test.sh corepkcs11`):** every fixed
bucket 0 failed; the remaining **206 failures are corepkcs11's untouched minimal-impl long-tail**
(`test_data_objects` 12, `x509/test_core_ops` 9, `test_buffers` 7, `test_sign` 6,
`test_rsa_key_import` 5, `test_aead` 5, `ckr/test_ckr_object` 5, `test_kdf`/`test_profiles` 4 …)
— **byte-identical to the pool baseline, zero regressions** from the KAT-suite changes. The 6
`crashed with signal` are the documented C-cluster harness-UB. Provider-generality re-audited:
no provider-identity branch in any changed logic path (only in explanatory comments).

Net: ~22,610 corepkcs11 KAT hard-failures eliminated (ECDSA 21,906 + HMAC 148 + limbo 493 +
AES 63) by harness fixes, plus bouncyhsm CCM no-auth + opencryptoki ulCounterBits surfaced as
REAL findings, with controls unchanged.

### corepkcs11 long-tail triage conclusion (2026-06-09)

The remaining ~200 corepkcs11 failures were categorized by direct probe + v3.6.4 source read.
**They split into a small harness-fixable subset (DONE) and a genuine-findings majority (KEEP).**

- **Harness-fixable storage-shape subset — FIXED:** general (non-KAT) conformance tests that used
  the raw import recipes and so hit corePKCS11's label/token requirement
  (`test_rsa_key_import` 5F → 1P/2skip/2xf; the KAT suites earlier). Same negotiation pattern.
- **Genuine minimal-impl limitations — KEEP AS FINDINGS (do NOT suppress):**
  - `test_data_objects` (12): corePKCS11 `C_CreateObject` has no `CKO_DATA` case
    (`default: CKR_ATTRIBUTE_VALUE_INVALID`, source-confirmed) — it genuinely cannot create data
    objects. Correct finding.
  - `test_sign` / `test_buffers` (13): unadvertised mechanisms + two-call buffer-size protocol
    quirks (e.g. `pulSize` reports 8 where 32 is required). Real corePKCS11 behaviors.
  - `x509/test_core_ops`, `ckr/*`, `test_aead`, `test_kdf`, … : minimal-impl operation gaps.
  - corePKCS11 secret-key import (CMAC/HMAC) advertised-but-not-operational (sign →
    `KEY_TYPE_INCONSISTENT`, readback → `OBJECT_HANDLE_INVALID`) — documented in module-issues.md.

  **These are the conformance suite working as intended** — corePKCS11 is a minimal embedded
  impl and the suite correctly reports the features it lacks. Per "failures ARE findings,"
  converting them to xfail/skip would HIDE findings; they stay as failures. The classification
  model's xfail bucket ("advertised but not operational") applies to *mechanisms*, not to a
  minimal impl missing a core object class — that's a genuine non-conformance, reported as such.

**Harness-fix scope is therefore COMPLETE for the discovered bug classes.** What remains is not
harness work: (a) C1-C3 UB-probe removal — flagged for Denis's nod (outward-facing); (b) secret-key
coherence stock-PAL root-cause; (c) merge to dev (user milestone decision — CLAUDE.md: never auto-merge).

---

## Cross-provider signature analysis (2026-06-09) — the highest-leverage view

Aggregating `(file, normalized-reason)` across ALL providers' pool baselines surfaces signatures that
appear on MANY providers at once — those are almost always harness mis-expectations, not real
single-provider findings. Ranked by provider-count:

| #prov | file | signature | verdict |
|---|---|---|---|
| 11 | wycheproof_rsa_decrypt | "invalid accepted" (×608) | 🔧 **FIXED (H8)** — anti-Bleichenbacher penalized |
| 14 | ffi_length_boundary | C_Sign/Verify/Digest/*Update(huge len) crash | 💥→🔧 **C2 UB** (lying length, flagged for nod) |
| 16 | ckr_raw_buffer | "C_Digest returns CKR_OK with 1-byte buffer" | 🔧 **FIXED** — gated on overflow evidence: CKR_OK + 0-overwrite = benign §5.10.2 deviation (xfail); >0-overwrite = real OOB write (fail). Surfaced a REAL NSS finding (see below) |
| 14 | parameter_validation | AES-GCM short IV "accepted" | ⚖️ over-strict vs model (spec-legal; NIST advisory) — **flag for Denis** |
| 14 | parameter_validation | AES-GCM IV reuse "accepted" | ⚖️ module can't track IV history → unreasonable to require; **flag** |
| 14 | parameter_validation | RSA-PSS sLen=0 "accepted" | ⚖️ **sLen=0 is VALID deterministic PSS (RFC 8017)**, not a Type-A break — strongest reclassify candidate; **flag** |
| 12 | parameter_validation | AES-GCM short tag "accepted" | ⚖️ spec-legal (NIST advisory); **flag** |
| 13 | wycheproof_ecdh | "derived a secret for invalid vector" (×92) | 🔧 **FIXED** — off-base-curve gate; softhsm2 42F→0F (all on-curve encoding-invalid), real off-curve finding preserved |
| 11 | acvp_eddsa | "ACCEPTED an INVALID EdDSA key" | ⚠️ same determination as ECDH (next) |

### The two categories among the not-yet-fixed cross-cutting signatures

**(A) Parameter-validation over-strictness (⚖️, flag for Denis — philosophy call, NOT auto-fixed).**
`test_parameter_validation` hard-`fail`s (`reject_or_classify(None,…)`) when a module *accepts* a
weak-but-**spec-legal** parameter: GCM IV < 12 B, GCM tag < 96 bit, GCM IV reuse, **RSA-PSS sLen=0**.
Per the project's own classification model a negative-op acceptance `fail`s only when it is a
*crypto-correctness break* — and none of these are: a 32-bit GCM tag is a correct (weaker) tag, a
short IV is correct GCM, IV-reuse prevention is the *caller's* duty (the module has no IV history),
and **sLen=0 PSS is a standardized deterministic variant (RFC 8017 §9.1), not a forgeable break.**
These are deliberate hardening checks (documented NIST citations) that conflict with the model and
fail 12-14 providers each. Reclassifying fail→note/xfail is defensible and model-aligned but changes
a whole security-test category across all providers (outward-facing) — **Denis's call**, like C1-C3.

### Second cross-provider sweep (resolved-files excluded) — more candidates

| #prov | file | signature | verdict |
|---|---|---|---|
| 10 | wycheproof_x25519 | "derived a secret for invalid vector" (×93) | ⚖️ **strong over-strict** — X25519/X448 (RFC 7748 §6.1) is safe-by-design with NO invalid-curve attack and is a TOTAL function; deriving on a malformed/special point is not a crypto break (the 72 invalid vectors are `InvalidPublic`/`PublicKeyTooLong` encoding cases, not low-order). Rejecting malformed keys is optional robustness. But a prior author deliberately set "any derive on invalid → fail" (Phase-2 V1) → **flag, don't unilaterally overturn**. Model-aligned fix = `fail` only on a WRONG output (shared != expected). |
| 10 | test_padding_oracle | "AES-CBC-PAD padding oracle (Vaudenay)" | ⚠️ **investigated — criterion questionable, needs crypto review.** `test_cbc_pad_error_uniformity` flags when corrupting the last byte vs a middle byte yields *different* error codes. But for a 16-byte plaintext (2-block CBC-PAD) both corruptions hit the padding block, and two distinct *failure* codes (e.g. ENCRYPTED_DATA_INVALID vs DATA_LEN_RANGE) is not a Vaudenay oracle unless one specifically signals *valid* padding — which this comparison (bad-vs-bad, never bad-vs-valid) does not establish. The RSA oracle tests in the same file ARE sound (error-uniformity across padding *categories*). Likely over-strict, but confirming requires careful Vaudenay analysis — do NOT reclassify blind. |
| 10 | test_cve_regression | "Tookan unwrap CKA_SENSITIVE" | ⚠️ Tookan attribute-attack regression — likely real intent; verify not over-strict. |
| 9 | ffi_null_pointer | C_GenerateRandom/SeedRandom/SetOperationState(NULL) crash | 🔧→💥 **DETERMINED = C1-C3 harness-UB class** (consolidate the decision). The test passes `NULL` with **nonzero length** to ops that have NO NULL length-query mode (`C_GenerateRandom(sh, None, 32)` etc.) and the file itself calls this *"always a crash vector"* — i.e. it provokes a guaranteed NULL-deref by violating the PKCS#11 buffer contract (the pointer must address `ulLen` bytes), then reports the crash. Same as C1-C3: harness-provoked UB, not a module finding. **Precise scope:** ONLY the NULL-with-nonzero-length cases for no-query ops; the *other* tests in the file (NULL **output** buffer for the standard length-query path, lines ~265-309) are FAIR and a crash there IS a real finding. Caveat for the user's call: defensive NULL-checks on pointer args are more common than ULONG_MAX length-sanity-checks, so this subset is a slightly stronger "keep as a robustness probe" candidate than the lying-length C1-C3 cases — but mechanically it's the same contract-violating UB. |
| 9 | wycheproof_mldsa_sign | "Invalid ML-DSA sign vector" (×50) | ⚠️ ML-DSA deterministic-sign with invalid input — determine. |
| 7 | ckr_keygen | "C_GenerateKeyPair with CK_ULONG-sized CKA_…" | 💥→🔧 the ULONG-overflow UB class (C-cluster, flagged). |
| 9 | test_set_attribute | "C_SetAttributeValue partially applied CKA_LABEL" | ⚖️ **DETERMINED = deliberate stricter-than-spec hardening (policy, flag).** `TestSetAttributeAtomicity` requires C_SetAttributeValue to be atomic (a mixed `{CKA_LABEL, read-only CKA_CLASS}` template must roll back CKA_LABEL when the CKA_CLASS row is rejected). PKCS#11 §5.7 does NOT guarantee atomicity — processing rows in order and leaving earlier ones applied is spec-permitted; applying a benign CKA_LABEL (not a security attr like CKA_SENSITIVE) while rejecting a structural read-only row is neither a crypto break nor a Type-C self-contradiction. 9 providers exhibit the natural non-atomic behavior. Same class as parameter-validation: an intentional hardening check that conflicts with the model's "fail only on crypto break / self-contradiction". Reclassify fail→note/xfail is defensible (and the security-relevant variant — partial-apply of CKA_SENSITIVE/EXTRACTABLE — would still be a real finding worth a separate targeted test); flag for decision. |

### Determinations summary (every cross-cutting item is now categorized)

After two cross-provider sweeps + per-item investigation, the not-yet-actioned signatures resolve to exactly three buckets — **no un-investigated clear harness bug remains**:

1. **⚖️ Deliberate stricter-than-spec hardening checks (policy call — flag, don't auto-change):**
   RSA-PSS sLen=0*, AES-GCM short IV / short tag / IV-reuse, X25519/X448 invalid-vector, EdDSA
   keyver, C_SetAttributeValue atomicity, (CBC-PAD oracle = ambiguous, leans here). All conflict
   with the model ("fail only on crypto break / self-contradiction") but were chosen deliberately.
   *Footnote: **PSS sLen=0 is the one I judge a genuine harness BUG, not a defensible policy** —
   deterministic PSS (sLen=0) is RFC 8017 §9.1 / FIPS 186-5 standard and produces correct,
   verifiable, non-forgeable signatures, so the "Type-A crypto break" label is factually wrong
   (unlike a 32-bit GCM tag, which is genuinely weaker). Recommend fixing this one.
2. **💥→🔧 Harness-provoked UB (the C1-C3 decision):** the lying-buffer overflow probes
   (`test_arithmetic_overflow`, `test_ffi_length_boundary` near-SIZE_MAX) AND the NULL-pointer
   crashes (`test_ffi_null_pointer` NULL+nonzero-len, no-query ops). One decision; per-case sort
   (CKA_VALUE_LEN-as-keygen-size and NULL-output length-query tests stay; buffer-read UB goes).
3. **✅ Genuine findings — KEEP failing (already correct):** bouncyhsm CCM no-auth, opencryptoki
   ulCounterBits accept, corePKCS11 EC silent-rebind + secret-key non-operability, NSS
   output-buffer overruns, wolfpkcs11 HKDF crash, corePKCS11 minimal-impl long-tail.

**(B) ECDH / EdDSA invalid-vector acceptance (⚠️ SECURITY — determine, do not assume).**
`test_wycheproof_ecdh` `fail`s when a module derives a secret for an "invalid" vector (×92 / 13 prov).
The intent is RIGHT (deriving on an off-curve point IS the invalid-curve attack). But softhsm2 — a
careful impl — rejects MOST invalid vectors and derives for only ~42, flagged
`InvalidPublic/UnnamedCurve/WrongOrder/ModifiedPrime/WrongCurve`. Key PKCS#11 insight: ECDH1_DERIVE
gets only the **raw peer-point bytes + the base key's curve** — the X.509 curve-encoding invalidity
(`UnnamedCurve`/`ModifiedPrime`/`ModifiedGroup`) is at a layer PKCS#11 never sees. So the finding is
real **only when the peer point is off the BASE curve** (genuine invalid-curve attack); if the point
is on the base curve the module derived correctly and the flag is harness over-reach. **The fix is a
per-vector on-curve check** (`cryptography.from_encoded_point(base_curve, point)`): on-curve → not a
finding; off-curve → keep the `fail` (real invalid-curve weakness). This is H8-shaped and safe in the
dangerous direction (from_encoded_point never accepts an off-curve point, so a real finding is never
hidden) — but whether softhsm2/NSS genuinely derive on **off-base-curve** points (a serious, real
finding to KEEP) vs only on-curve ones (harness over-flag) must be **determined per vector before
acting**. Not auto-fixed this pass: getting invalid-curve classification wrong either hides a real
vuln or cries wolf. EdDSA-keyver (×11 prov) needs the same valid-vs-genuinely-invalid determination — **but it is
murkier and likely over-strict**: `test_eddsa_keyver` fails when a module imports+uses an "invalid"
ACVP EdDSA public key, yet RFC 8032 does NOT require a verifier to reject non-canonical or
small-order EdDSA public keys (verification is defined to work regardless). ACVP KeyVer tests an
*optional* key-validation capability, not a PKCS#11 requirement. The vectors carry no reason field
(8 vectors / 4 invalid), so an Edwards-point analysis (off-curve vs non-canonical/small-order) is
needed: off-curve acceptance is arguably questionable, but canonical/small-order acceptance is
RFC-permitted and should not hard-`fail`. Treat with the parameter-validation philosophy items
(⚖️, flag) pending that analysis — do NOT blindly reclassify.

### ✅ ECDH RESOLVED (off-base-curve gate) — the determination came out clean

The ECDH ⚠️ item above is now FIXED and the security question answered: gating the
"derived-on-invalid" finding on `_point_on_base_curve` (cryptography.from_encoded_point) reduced
softhsm2 ECDH **42 F → 0 F** and NSS to 0 F — **every** failing vector was an on-curve point flagged
invalid only at the X.509-encoding layer the raw PKCS#11 ECDH path never sees. softhsm2/NSS both
correctly REJECT genuine off-curve points (those were already in the reject→pass path), so neither
has an invalid-curve weakness. The real-finding path is preserved: a provider that DID derive on an
off-base-curve point still `fail`s (verified via tc332 `InvalidCurveAttack`, off-curve, still fails).
This is the model for the EdDSA item: implement a *safe* gate (never masks an off-curve/real case),
let the fresh run reveal whether any residual failures are genuine.

## Post-merge regression gate — softhsm2 full suite on dev (2026-06-10)

Full `docker/test.sh softhsm2` on dev after merging the complete fix-pass:
**171 (pool baseline) → 68 failed** / 44,898 passed / 5,022 xfailed / **0 crashed / 0 error**.

- **Every fixed file is now 0 failed** (no regression): `test_wycheproof_rsa_decrypt` 59→0 (H8),
  `test_wycheproof_ecdh` 42→0 (off-curve gate), `test_ckr_raw_buffer` 1→0 (C_Digest), PSS −1.
  The 103-failure reduction is fully accounted for by these fixes.
- **Zero cross-test regressions**: all 68 remaining failures were present in the pool baseline,
  and none is in a file the fix-pass touched.
- The 68 remaining are EXACTLY the flagged-for-decision items: UB probes
  (`test_ffi_length_boundary` 22 + `test_arithmetic_overflow` 18 + `test_ckr_keygen` 5 = 45) +
  policy hardening checks (`test_parameter_validation` GCM weak-params 9, `test_acvp_eddsa` 4,
  `test_cve_regression`/`test_tookan` Tookan 2+1, `test_set_attribute` atomicity 1,
  `test_padding_oracle` 1, `test_mech_negative` 1, `test_ckr_wrong_key_type_hardening` 2).
  **Update (2026-06-10):** the `test_ckr_wrong_key_type_hardening` 2 are now **xfailed**, not failed,
  after the wrong-key-type continuation fix (lenient-init + safe-op-rejection → xfail; produced
  output/crash → fail) — so the post-fix softhsm2 failed count is **66**, of which `test_mech_negative` 1
  + the analogous `test_ckr_sign/verify::*InitErrors` are the first-line init-only strictness still
  flagged for the same fail-vs-xfail decision (the continuation probe is now the authoritative verifier).

Confirms the merged fix-pass is correct, complete for clear bugs, and regression-free; what remains
on softhsm2 is precisely the documented policy/UB decisions awaiting the user.

## Post-merge regression gate #2 — wolfpkcs11 full suite on dev (2026-06-10)

Pool baseline 3,067. Cleared by the fix-pass: `test_cts` 2,079→0 (H2 operability → xfail),
`test_wycheproof_rsa` 21→0, `test_wycheproof_aes`/`_ecdh`/`_rsa_decrypt` 0. Zero regressions (no
fixed file fails). **CORRECTION (2026-06-10 re-verify):** two files this section previously listed
as `→0` were NOT cleared — fresh targeted runs on dev show `test_wycheproof_rsa_oaep` **209 failed**
(stable) / 210 (master) and `test_wycheproof.py::TestAESCBCPKCS5Wycheproof` **144 failed**. Both are
genuine wolfpkcs11 deviations (OAEP empty-message ~125 + 3-prime RSA 54 + near-max ~15, operational
combo → fail per H3 design; AES-CBC-PAD accepts non-PKCS#5 BadPadding, shared with opencryptoki —
softhsm2/kryoptic reject). The H3 OAEP probe only clears *combo-dead* OAEP (opencryptoki's 26), never
these. So the earlier `400 failed` total was understated by ~353 (it wrongly excluded OAEP+CBC-PAD);
per project policy no precise total is re-asserted here. The genuine + flagged buckets that ARE
correctly counted: digest H7 malformed-CK_RV ~309, CCM tag-auth bypass + non-operability 45,
output-buffer size-protocol violations 6 (wrong required count / OOB write / garbage length —
module-issues.md), GCM 9, flagged UB probes (`test_ffi_length_boundary` 21 + `test_secret_key_value_len`
8), **plus OAEP 209 + AES-CBC-PAD 144 (above)**. Determination note: the buffer-guard failures were
verified REAL (LEN values prove wrong-size-query / OOB / garbage), NOT the benign CKR_OK+0-overwrite
deviation the C_Digest guard now xfails — so no harness change.

## Determination — nss `test_mldsa_verify` 8 F = GENUINE Type-A (over-long-encoding acceptance) (2026-06-11)

**Verdict: GENUINE FINDING (Type-A crypto-correctness), not a harness bug. No code change.**
Documented in [module-issues.md](../module-issues.md) under NSS.

**Trigger.** SESSION-RESTORE queue flagged the nss "Invalid ML-DSA sig … accepted by module" 8 F
as a *potential* forgery-acceptance Type-A. Determined, not assumed.

**Source of the 8 F.** Fresh pool `artifacts/nss-pooled/report.jsonl` (base NSS variant, 2026-06-11).
Note the pool split: the base `nss-pooled` module **advertises and operates** `CKM_ML_DSA`, so it
RUNS `test_mldsa_verify` (607 passed / 8 failed / 15 skipped); `nss-pqc-pooled` reports
`has_mechanism("ML_DSA") == False` and **collection-skips the whole file** (1 skip) — which is why
the 8 F live only in `nss-pooled`, not in the "pqc" variant.

**The 8 vectors (all `result: invalid`, wycheproof v1 schema → no "acceptable" three-state):**

| File | tcId | flags | comment | over-long by |
|---|---|---|---|---|
| mldsa_44_verify | tc7 | IncorrectSignatureLength | long signature | sig 2421 vs 2420 |
| mldsa_44_verify | tc65 | IncorrectPublicKeyLength | long public key | pk 1313 vs 1312 |
| mldsa_44_verify | tc144 | IncorrectSignatureLength | sig + one trailing zero byte | sig 2421 vs 2420 |
| mldsa_65_verify | tc7 | IncorrectSignatureLength | long signature | sig 3310 vs 3309 |
| mldsa_65_verify | tc70 | IncorrectPublicKeyLength | long public key | pk 1953 vs 1952 |
| mldsa_65_verify | tc157 | IncorrectSignatureLength | sig + one trailing zero byte | sig 3310 vs 3309 |
| mldsa_87_verify | tc7 | IncorrectSignatureLength | long signature | sig 4628 vs 4627 |
| mldsa_87_verify | tc170 | IncorrectSignatureLength | sig + one trailing zero byte | sig 4628 vs 4627 |

Two sub-classes, **both genuine Type-A**:
- **6× IncorrectSignatureLength** — signature is exactly +1 byte over the FIPS-204 fixed length.
  NSS `C_Verify` returns `CKR_OK` (`verify_single` → `True`) on the over-long signature → test
  fails at line 161 ("accepted by module").
- **2× IncorrectPublicKeyLength** — the *public key* is +1 byte over the fixed length. NSS
  **accepts the malformed key at import** (`import_pqc_public_key` does NOT raise; the
  `_MLDSA_INVALID_PUBLIC_KEY_FLAGS` correctly-rejected path at lines 142-145 is never taken) **and
  then verifies as valid**. Confirmed by traceback: the failure is at line 161, downstream of a
  successful import.

**Why Type-A, not harness / not "acceptable":**
1. **FIPS-204 mandates fixed-length encoding.** Canonical sizes (computed from the same vector
   files' `result:valid` rows; match FIPS-204 Table 2 exactly): pk = 1312/1952/2592, sig =
   2420/3309/4627 for ML-DSA-44/65/87. ML-DSA.Verify (FIPS-204 Alg. 3) decodes the signature via
   `sigDecode` / the key via `pkDecode`, which operate **only** on byte strings of the fixed length;
   any other length is malformed and MUST be rejected. Accepting an over-long encoding and returning
   "valid" is a **non-malleability break**: an attacker appends a trailing byte and the signature
   still validates (signature/key malleability → forgeable variant of an existing signature).
2. **Wycheproof semantics confirm "must reject".** Both flags carry `bugType: BASIC` (file `notes`),
   not `LEGACY`/`KNOWN_BUG`; `result: invalid`. v1 schema is two-state (valid/invalid) — there is no
   "acceptable" variant the test is mis-hard-failing.
3. **Harness presents the input faithfully — no mis-encoding.** `test_wycheproof_mldsa.py`
   `sig = bytes.fromhex(vec["sig"])` / `pk_bytes = bytes.fromhex(pk_hex)` are passed verbatim;
   `verify_single` calls `C_Verify(..., sig_buf, len(signature))` with the full 2421/3310/4628 bytes.
   No truncation, no re-encode. NSS itself returns `CKR_OK` → NSS is what accepts it.
4. **NSS is otherwise correct.** Same module rejects **380/388** invalid vectors and accepts
   **227/227** valid ones — only these 8 fixed-length-malformation cases slip through. So this is a
   specific malformation-tolerance gap (NSS ignores trailing bytes past the fixed length), not a
   blanket "verify always true" bug.

**Baseline cross-check (regression vs pre-existing).** The **identical 8 vectors** fail in
`artifacts2/nss-pooled`, `artifacts2/nss-shard-0`, `artifacts3/nss-pooled`, `artifacts3/nss-shard-0`
and the fresh `artifacts/nss-pooled` — stable, deterministic, **pre-existing**. NOT introduced by
this session's ML-DSA fixes (`f08369da` ctx-skip + malformed-key xfail): those reduced nss-pooled's
total F from 234 (artifacts2) → 130 (fresh) by clearing OTHER files, and correctly left these 8
standing (they are a real module behavior the fixes did not — and should not — mask).

**Action.** Documented under NSS in module-issues.md (Type-A, vector ids + flags + the 380/8 split).
**No harness change** — the test classifies correctly per the model (positive: n/a; negative:
`CKR_OK` on a must-reject malformed input + crypto-correctness break = Type-A `fail`). Reportable
upstream to NSS (softoken ML-DSA verify / pubkey import should enforce FIPS-204 fixed lengths).

**Confidence: HIGH.** Evidence is direct (module returns `CKR_OK`; canonical sizes derived from the
vectors themselves match FIPS-204; flags are `BASIC`/`invalid`; faithful harness path; reproduced
identically across three independent pool snapshots; NSS otherwise rejects 380/388 invalids). The one
residual not directly observed here is upstream root-cause line in NSS softoken (no NSS 3.120.1 source
to hand; system NSS is 3.98 and does not advertise ML-DSA, so a local re-exec could not reproduce the
exact build) — that is a *report-detail* gap, not a determination gap.

## softhsm2 long-tail triage 2026-06-11

**Scope.** Full triage of **every** `outcome:failed` (`when:call`) record in the fresh VALIDATED
pool `artifacts/softhsm2-pooled/report.jsonl`. softhsm2 is the suite's correctness baseline
("must stay byte-identical"), so each hard fail is high-signal. **Total: 65 failed call records,
across 11 files** (matches the post-merge regression gate above and the pool-comparison `171→65`).

**Method.** Aggregated by `(file, normalized message)`; cross-checked each bucket against the
softhsm2 section of [module-issues.md](../module-issues.md), the determinations above, and the
[pool-2026-06-10-comparison.md](pool-2026-06-10-comparison.md) validation. Cross-provider outcome
pulled from every `<provider>-pooled/report.jsonl` in the fresh pool for the one genuine new finding.

### Bucket table (file → count → determination)

| Count | File | Class | Determination |
|---|---|---|---|
| 22 | `security/test_ffi_length_boundary.py` | 💥→🔧 | **KNOWN** — C2/C-cluster harness-provoked UB (lying buffer length / isize_max + huge-len subprocess exits). Denis 2026-06-10: KEEP as-is ("a segfault IS the finding"). Documented module-issues.md §SoftHSM2. |
| 18 | `security/test_arithmetic_overflow.py` | 💥→🔧 | **KNOWN** — C-cluster template/keypair/derive count-overflow SIGSEGV (`ulCount=ULONG_MAX`). HIGH module crash finding, documented module-issues.md §SoftHSM2 ("HIGH — SIGSEGV on integer-overflow template_count"); also the lying-buffer UB class flagged for decision. KEEP as-is. |
| 9 | `security/test_parameter_validation.py` | ⚖️ + 💥 | **KNOWN, MIXED.** 8 = deliberate stricter-than-spec GCM hardening (0/8/32/64-bit tag, empty/1-/4-byte IV, IV-reuse) — ⚖️ flagged-for-Denis policy (spec-legal weak params), left as-is. 1 = `TestGcmAadNullWithLength` GCM **NULL-AAD-pointer-with-nonzero-length SIGSEGV** = GENUINE softhsm2 crash, documented module-issues.md §SoftHSM2. |
| 5 | `ckr/test_ckr_keygen.py` | 🔧→📋 | **KNOWN** — `CKA_TOKEN` scalar-length validation gap (BBOOL given `sizeof(CK_ULONG)`) accepted on AES/RSA/EC keygen+keypair. Documented module-issues.md §SoftHSM2 ("CKA_TOKEN scalar-length validation missing"). The ULONG-overlong-length probes are the C-cluster value-shape class; documented module finding, not reclassified. |
| 4 | `acvp/test_acvp_eddsa.py` | ⚖️ | **KNOWN (flagged-for-decision)** — `TestEdDsaKeyVer` invalid-EdDSA-key acceptance (ED-25519 tc1/tc4, ED-448 tc6/tc8). The triage above (§"two categories", EdDSA-keyver paragraph) flagged this ⚖️: RFC 8032 does NOT require a verifier to reject non-canonical/small-order pubkeys, so it leans over-strict but needs an Edwards-point (off-curve vs small-order) analysis before any reclassify. Stays `fail`, not blindly changed. NOT yet in module-issues.md §SoftHSM2 (sigver is; keyver is not) — **doc gap, recorded here.** |
| 2 | `security/test_cve_regression.py` | 📋 + ⚠️**NEW** | **SPLIT.** `TestTookanUnwrapAttrs::test_unwrapped_key_cannot_unset_sensitive` = KNOWN Tookan §3.3 sensitive-key-boundary finding (documented module-issues.md §SoftHSM2 main). `TestInvalidECCurve::test_import_ec_key_with_bad_oid` = **GENUINE NEW softhsm2 Type-A finding** — see determination below. |
| 1 | `security/test_tookan.py` | 📋 | **KNOWN** — `TestKeyTypeConfusionOnUnwrap::test_unwrap_aes_as_des3_rejected` (unwrap AES-KW blob as CKK_DES3). Documented module-issues.md §SoftHSM2 main. |
| 1 | `ckr/test_ckr_sign.py` | ⚖️ | **KNOWN** — `TestSignInitErrors::test_key_type_inconsistent` (lenient `C_SignInit(CKM_ECDSA, RSA key)`). First-line init-only strictness, flagged-for-decision (continuation probe is authoritative; the op is safe). Documented module-issues.md §SoftHSM2 ("Lenient wrong-key-type at C_SignInit/C_VerifyInit … but SAFE at the operation"). |
| 1 | `ckr/test_ckr_verify.py` | ⚖️ | **KNOWN** — `TestVerifyInitErrors::test_key_type_inconsistent`, same class as above. Documented. |
| 1 | `test_mech_negative.py` | ⚖️ | **KNOWN** — `TestWrongKeyType::test_ecdsa_with_rsa_key_rejected`, same lenient-init first-line class. Documented. |
| 1 | `test_set_attribute.py` | ⚖️ | **KNOWN** — `TestSetAttributeAtomicity` partial CKA_LABEL apply before rejecting read-only CKA_CLASS. Determined above (§"second cross-provider sweep") = deliberate stricter-than-spec atomicity hardening; PKCS#11 §5.7 does not mandate atomicity; flagged-for-decision, stays `fail`. |

**Known vs new roll-up:** 64 of 65 are KNOWN — each is either (a) a documented genuine softhsm2
crash/validation finding (kept failing per "a segfault IS the finding"), or (b) a ⚖️
flagged-for-decision stricter-than-spec hardening / first-line-init policy item that Denis left
as-is. **1 is NEW and un-triaged:** the bad-OID EC public-key import acceptance.

### NEW — `TestInvalidECCurve::test_import_ec_key_with_bad_oid` = GENUINE softhsm2 Type-A finding

**Verdict: GENUINE FINDING (Type-A crypto-correctness), not harness over-strictness. No code change —
the test classifies correctly; documented in module-issues.md §SoftHSM2.**

- **What.** `test_cve_regression.py::TestInvalidECCurve::test_import_ec_key_with_bad_oid`
  (CVE-2021-3798 pattern) does `C_CreateObject` of a `CKO_PUBLIC_KEY`/`CKK_EC` with
  `CKA_EC_PARAMS = 06 05 DE AD BE EF 00` (a syntactically-valid DER OID for a **nonexistent**
  curve) and a bogus uncompressed point `04 || 01*64`. **softhsm2 returns `CKR_OK`** (rv-trace:
  `C_CreateObject → CKR_OK`, `C_DestroyObject → CKR_OK`). Identical on `softhsm2` (2.7.0) and
  `softhsm2-main`.
- **Why it's the wrong thing (Type-A).** Importing an EC public key whose curve OID resolves to no
  known curve must be rejected (`CKR_CURVE_NOT_SUPPORTED` / `CKR_DOMAIN_PARAMS_INVALID` /
  `CKR_ATTRIBUTE_VALUE_INVALID` / `CKR_TEMPLATE_INCONSISTENT`). Accepting a public key with no valid
  domain parameters is a crypto-correctness break (an unverifiable/garbage key object enters the
  store as if usable). The classifier `reject_or_classify(None, …)` correctly `fail`s on acceptance.
- **Test is sound, not over-strict.** `_INVALID_EC_CURVE_REJECT_RVS` is a 4-code reject set; ANY
  clean reject → pass/xfail. Only outright acceptance fails. The harness presents the OID verbatim
  (no mis-encoding). This is the same negative-op classification model used project-wide.
- **Cross-provider check (fresh pool, definitive — this is softhsm2-specific):**
  kryoptic / kryoptic-main / kryoptic-fips / nss / nss-main / opencryptoki / opencryptoki-master /
  bouncyhsm / tpm2 all **PASS** (reject with an expected code). wolfpkcs11 / wolfpkcs11-master /
  corepkcs11 **xfail** (reject with a non-spec clean code — `CKR_FUNCTION_FAILED` / `CKR_ARGUMENTS_BAD`).
  **Only softhsm2 (both variants) ACCEPTS** → softhsm2-specific validation gap, high-confidence genuine.
- **Action.** Documented under module-issues.md §SoftHSM2 (Type-A, EC domain-param validation gap).
  No harness change — keeping it failing is correct ("failures ARE findings"). Reportable upstream
  (SoftHSM2 should reject EC public-key import with an unknown `CKA_EC_PARAMS` OID).
- **Confidence: HIGH.** Direct rv-trace evidence (CKR_OK accept), reproduced on both softhsm2
  variants, and a clean cross-provider split (every other careful provider rejects). Not previously
  in module-issues.md §SoftHSM2 (the section documents EdDSA EC_POINT and SigVer issues, not this
  bad-OID import path) → genuinely new this triage.

### Probabilistic-noise note (not in the softhsm2 fail set, recorded for completeness)

`security/test_padding_oracle.py` and `security/test_arithmetic_overflow.py` randomized
oracle/overflow flips that the pool-comparison R3 lists for *other* providers (and which the
post-merge gate mentioned for softhsm2-generated-iv) are the documented cross-run nondeterminism
([[reference_oracle_tests_probabilistic]]); in **this** fresh `softhsm2-pooled` snapshot they did
not land in the fail set. Verify-don't-alarm; **no action.**

**No code change this triage** — 64/65 were already documented/flagged; the 1 new is a genuine
softhsm2 finding that stays `fail` and is added to module-issues.md (documentation only). No HARNESS
bug was proven on softhsm2 in this pass.

## kryoptic long-tail triage 2026-06-11

**Scope.** Full triage of **every** `outcome:failed` (`when:call`) record in the fresh VALIDATED
pool `artifacts/kryoptic-pooled/report.jsonl`. kryoptic (v1.5.0) is the suite's **other** mature
CONTROL module alongside softhsm2 ("must stay byte-identical"), so each hard fail is high-signal.
**Total: 137 failed call records, across 24 files** (matches the bucket counts in the triage brief).

**Method.** Aggregated by `(file, normalized message)`; cross-checked each bucket against the
kryoptic section of [module-issues.md](../module-issues.md), the determinations above, and the
pool-comparison validation. For the three un-triaged NEW buckets every failing vector was decoded
from the Wycheproof JSON and cross-checked across **all** `<provider>-pooled/report.jsonl` snapshots
(rv-trace inspected for the actual `CK_RV` on the call that determined the verdict).

### Bucket table (file → count → determination)

| Count | File | Class | Determination |
|---|---|---|---|
| 30 | `security/test_ffi_length_boundary.py` | 💥 | **KNOWN** — C-cluster harness-provoked UB (lying-buffer / isize_max SIGSEGV/SIGABRT). Denis 2026-06-10: KEEP ("a segfault IS the finding"). Documented module-issues.md §Kryoptic FFI/arithmetic findings. |
| 27 | `wycheproof/test_wycheproof_aes.py` | 📋 ⚠️**NEW** | **GENUINE kryoptic Type-A finding** — `C_UnwrapKey(CKM_AES_KEY_WRAP)` accepts an **empty / non-multiple-of-8 wrapped blob** (`ct_len=0`) and returns `CKR_OK`, creating a key. RFC 3394 requires ≥2 semiblocks; an empty blob is malformed. **kryoptic-only** (all 3 variants); softhsm2/nss/opencryptoki/wolfpkcs11 all reject (pass). Stays `fail`. See determination below. |
| 12 | `security/test_arithmetic_overflow.py` | 💥 | **KNOWN** — C-cluster `ulCount=ULONG_MAX` template/find-objects count-overflow SIGABRT (`thread panicked`, `memory allocation of 274 GiB`). KEEP. Documented module-issues.md §Kryoptic. |
| 12 | `wycheproof/test_wycheproof_x25519.py` | 🔧 ⚠️**NEW→FIXED** | **HARNESS over-strictness, FIXED (effect-gated, provider-general).** All 12 are JWK `InvalidPublic` vectors (wrong `crv`/`kty`) whose `x` decodes to canonical length; per RFC 7748 §5 every such raw point is valid. Resolves the flagged SESSION-RESTORE decision. See determination below. |
| 11 | `test_operation_termination.py` | 📋 | **KNOWN** — `C_Verify`/`C_VerifyFinal` non-termination after a rejected short signature (next `C_VerifyInit` → `CKR_OPERATION_ACTIVE`). Documented root cause ([[project_operation_active_cascade]], provider-verify-operation-not-terminated.md). |
| 6 | `test_parameter_validation.py` | ⚖️ | **KNOWN (flagged-for-decision)** — `TestGcmTagSize` accepts 8/32/64-bit GCM tags (below NIST 96-bit minimum). Same stricter-than-spec GCM hardening class flagged ⚖️ on softhsm2; spec-legal weak params, left as-is. |
| 6 | `wycheproof/test_wycheproof_mldsa_sign.py` | 🔧 ⚠️**NEW→FIXED** | **HARNESS over-strictness, FIXED.** kryoptic correctly **rejects** the `InvalidPrivateKey` (out-of-range s1/s2) vectors at `C_CreateObject` — right direction — but with `CKR_DEVICE_ERROR`, a clean code outside the narrow 3-code import-reject set. Per the model that is pass/xfail, not fail. Different class from the nss ML-DSA finding (that was over-length *acceptance*). See determination below. |
| 4 | `acvp/test_acvp_eddsa.py` | ⚖️ | **KNOWN (flagged-for-decision)** — `TestEdDsaKeyVer` accepts invalid Ed25519/Ed448 keys (tc1/tc4/tc6/tc8). Same ⚖️ Edwards-point analysis pending as on softhsm2; RFC 8032 does not require verifiers to reject non-canonical/small-order pubkeys. Documented module-issues.md §Kryoptic (EdDSA SigVer is; keyver class flagged here, consistent with the softhsm2 doc-gap note). |
| 4 | `test_ckr_raw_buffer.py` | 💥/📋 | **KNOWN** — undersized output-buffer guard subprocess failures (`C_GetMechanismList`/`C_GetInterfaceList`/`C_Decrypt` AES-CBC-PAD). Same two-call-convention probe class documented for nss (module-issues.md §NSS); applies to kryoptic too. |
| 3 | `security/test_ffi_null_pointer.py` | 💥 | **KNOWN** — NULL-pointer SIGSEGV (`C_GenerateRandom`/`C_SetOperationState`/`C_SignInit` NULL param). C-cluster, KEEP. The `C_SetPIN` NULL-new-PIN PIN-corruption is separately documented (module-issues.md §Kryoptic, `@destructive`). |
| 3 | `test_secret_key_value_len.py` | 💥 | **KNOWN** — `CKA_VALUE_LEN=0xffff…` overflow on `C_GenerateKey`/`C_CopyObject`/`C_SetAttributeValue` SIGABRT. C-cluster value-shape, KEEP. |
| 3 | `test_set_attribute.py` | ⚖️ | **KNOWN (flagged-for-decision)** — `TestSetAttributeAtomicity`/`TestSetAttributeNegative` read-back after partial write of read-only `CKA_CLASS`/`CKA_KEY_TYPE`. Same stricter-than-spec atomicity hardening flagged ⚖️ on softhsm2; PKCS#11 §5.7 does not mandate atomicity. |
| 2 | `test_ckr_object.py` | 📋 | **KNOWN** — `CKA_ALLOWED_MECHANISMS` NULL-pointer-nonzero-length accepted (documented module-issues.md §Kryoptic NEW 2026-06-08); `TestSetAttributeErrors` `CKR_GENERAL_ERROR` on read-only class set (same hardening class). |
| 2 | `test_access_levels.py` | 📋 | **KNOWN** — USER-session `CKA_TRUSTED=True` grant + public-session `CKA_PRIVATE=True` create. Same security-boundary class documented for kryoptic (module-issues.md §Kryoptic 1595+ CKA_TRUSTED finding). |
| 2 | `test_mech_message.py` | 📋 | **KNOWN** — `C_EncryptMessage` AES-GCM/CCM generated-IV not written back to `pIv`/nonce. Same generated-IV message-API class as softhsm2-generated-iv. |
| 2 | `test_misc_kdf.py` / `test_aes_kdf.py` | 📋 | **KNOWN** — `TestExtractKeyFromKey` / `CKM_AES_CBC_ENCRYPT_DATA` derived-bytes mismatch (kryoptic KDF byte-ordering / extract-from-key offset quirk). Module-specific derive output; recorded. |
| 1 each | `test_ckr_decrypt`, `test_ckr_wrap`, `test_api_boundary`, `test_cve_regression`, `test_kem`, `test_buffers` | 📋/💥 | **KNOWN** — RSA wrong-length ciphertext accepted; generic-secret accepted for AES wrap (documented module-issues.md §Kryoptic 1645+); `CKA_VALUE_LEN=0xffff…` AES keygen SIGABRT (C-cluster); Tookan §3.3 sensitive-unwrap boundary; ML-KEM `CKA_VALUE` injection accepted; `C_SignFinal` buffer-too-small `pulSize` deviation. Each is a documented kryoptic finding or C-cluster crash. |
| 1 | `security/test_padding_oracle.py` | 📋 noise | **KNOWN** — probabilistic AES-CBC-PAD Vaudenay oracle (1/320 `CKR_OK_DIFFERENT` this snapshot). Documented cross-run nondeterminism ([[reference_oracle_tests_probabilistic]]); verify-don't-alarm. |

**Known vs new roll-up:** 135 of 137 are KNOWN — documented kryoptic crash/validation findings (kept
failing) or ⚖️ flagged stricter-than-spec hardening Denis left as-is. **3 buckets were un-triaged
NEW; 2 are HARNESS over-strictness now FIXED, 1 is a genuine kryoptic Type-A finding kept `fail`.**

### NEW #1 — `test_wycheproof_aes::test_aes_key_wrap` (27F) = GENUINE kryoptic Type-A finding

**Verdict: GENUINE FINDING (Type-A crypto-correctness). No code change — the test classifies
correctly; documented in module-issues.md §Kryoptic.**

- **What.** All 27 are AES-KW **unwrap** of `WrongDataSize` / `InvalidWrappingSize` vectors
  (tc14–22, 56–64, 111–119 across AES-128/192/256). Wycheproof gives a plaintext `msg` whose length
  is **not a multiple of 8** (1–20 bytes) and therefore an **empty `ct`** (no valid wrapped blob can
  exist). The test calls `C_UnwrapKey(CKM_AES_KEY_WRAP, wrapped=b"")`. rv-trace:
  `C_CreateObject→CKR_OK`, **`C_UnwrapKey→CKR_OK`**, `C_DestroyObject→CKR_OK` — kryoptic accepts the
  empty blob and creates a key object.
- **Why it's the wrong thing (Type-A).** RFC 3394 AES-KW requires the wrapped data to be a multiple
  of 64 bits with a minimum of two 64-bit semiblocks (16 bytes). An empty (and any
  non-multiple-of-8) ciphertext is malformed and MUST be rejected
  (`CKR_WRAPPED_KEY_LEN_RANGE`/`CKR_DATA_LEN_RANGE`). Unwrapping it into a key is a
  crypto-correctness break (a garbage/zero key object enters the store as if it were a recovered
  key). The negative-op classifier `fail`s on this acceptance — correct.
- **Test is sound.** The adaptive unwrap passes `value_len=None` for invalid vectors precisely so a
  forged/malformed blob is never coerced through a restated length; the module's own
  rejection is what's checked, and kryoptic doesn't reject.
- **Cross-provider (fresh pool, definitive — kryoptic-specific):** on these exact 27 vector ids,
  **kryoptic / kryoptic-main / kryoptic-fips all return `CKR_OK` (fail)**; softhsm2 (both),
  nss (all 3), opencryptoki (both), wolfpkcs11 (both) all **reject (pass)**; bouncyhsm/tpm2/corepkcs11
  do not advertise `AES_KEY_WRAP` (skip). Clean split → kryoptic-specific input-validation gap.
- **Confidence: HIGH.** Direct rv-trace `CKR_OK` on an empty blob, reproduced on all three kryoptic
  variants, every other careful provider rejects. Reportable upstream.

### NEW #2 — `test_wycheproof_x25519::test_xdh` (12F) = HARNESS over-strictness — FIXED (resolves the X25519 flag)

**Verdict: HARNESS over-strictness. FIXED effect-gated + provider-general. The flagged
SESSION-RESTORE "X25519 invalid-vector over-strictness" decision is RESOLVED = resolved-harness-fix.**

- **What the 12 vectors assert.** x25519_jwk tc519/522/524/525/526/527/529 + x448_jwk
  tc516/517/518/519/521, all `result:invalid`, flag **`InvalidPublic`** ("private and public key do
  not use the same underlying group"). Their invalidity is purely in the **JWK wrapper**: a wrong
  `crv` (`P-256`, `secp256k1`) with both x AND y, or a malformed/missing `kty`. The harness decoder
  `decode_xdh_public_bytes(..., "jwk")` extracts **only the raw `x` field** and discards
  `kty`/`crv`/`y`, so the module receives a **canonical-length raw coordinate** (32/56 B).
- **Why deriving is correct (RFC 7748 §5).** On Montgomery curves every 32-byte (X25519) / 56-byte
  (X448) string is a valid public key — the X25519/X448 functions clamp the scalar and are defined
  for **all** inputs (and for twist points, §5/§7: implementations are recommended to accept
  non-canonical keys). There is **no invalid-curve / invalid-point attack class** to detect once the
  JWK wrapper is stripped. So the module deriving a secret is the right thing; the test failing it is
  the harness treating a JWK-encoding-layer property as a crypto invalidity.
- **The discriminator (why only these 12).** The passing/skipped JWK-invalid vectors are exactly the
  ones whose `x` decodes to a **wrong length** (P-384→48 B, P-521→66 B) or is **missing** — those a
  careful module rejects at import (pass) and remain testable. Only the **canonical-length**
  container-mismatch subset is untestable.
- **Direct analog already in the suite.** ECDH (`test_wycheproof_ecdh`) drops `InvalidAsn`/`InvalidPem`
  at load (`_UNTESTABLE_FLAGS`) for the same reason — PKCS#11 takes pre-extracted points, not
  containers — and reduces parameter-level WrongCurve vectors via `ecdh_cofactor1_shared_x`. The
  asn/pem XDH `InvalidPublic` vectors already self-correct (cryptography's `.public_bytes(Raw)` or the
  SPKI fallback yields a wrong-length/full point → import-reject → pass), so **only the jwk path**
  needed the fix.
- **Cross-provider (provider-general, no kryoptic identity).** Every provider that advertises XDH
  fails a subset of exactly these 12 with **no extras**: kryoptic/opencryptoki/bouncyhsm = all 12,
  nss = the 7 X25519 (nss doesn't advertise X448). softhsm2/tpm2/wolfpkcs11 skip XDH entirely. No
  provider had a real invalid-point break here.
- **Fix.** `test_wycheproof_x25519._xdh_jwk_invalidity_not_representable` + a load-time drop: a jwk
  `InvalidPublic` vector whose decoded `x` is the canonical curve length is excluded from
  parametrization (like `InvalidAsn`/`InvalidPem`). **Effect-gated:** wrong-length / missing-`x`
  invalid vectors stay testable, and a *raw/asn/pem* vector whose canonical-length point a provider
  derives from is untouched — a genuine raw-point break still fails. TDD:
  `tests/test_wycheproof_kryoptic_classification.py` (drop + retain + valid-unaffected) and the
  reconciled `tests/test_wycheproof_xdh_guards.py::test_invalid_xdh_correct_length_success_is_reported`
  (its prior exemplar tc519 was a misdiagnosed "low-order point"; rewritten to a synthetic
  raw-encoding invalid vector so the runtime fail-on-derive guard still fires).
- **Confidence: HIGH.** Decoded every failing vector's JWK `x`/`crv`/`kty`, confirmed the
  canonical-length / wrong-length split exactly predicts fail vs pass, RFC 7748 §5 is dispositive,
  and the fix is the established ECDH untestable-flag pattern.

### NEW #3 — `test_wycheproof_mldsa_sign::test_mldsa_sign` (6F) = HARNESS over-strictness — FIXED

**Verdict: HARNESS over-strictness. FIXED provider-general. Different class from the nss ML-DSA
finding (b251ad1b) — that was over-length *acceptance* (Type-A); this is *rejection* with a non-spec
clean code.**

- **What.** mldsa_44 tc52/53, mldsa_65 tc56/57, mldsa_87 tc47/48 — all `result:invalid`, flag
  **`InvalidPrivateKey`** ("private key with s1/s2 vector out of range"). rv-trace:
  **`C_CreateObject→CKR_DEVICE_ERROR`** — kryoptic **rejects** the malformed private key at import
  (the right direction for a negative vector), but with `CKR_DEVICE_ERROR` (its crypto-layer
  decode-failure fallback, [[reference_kryoptic_default_ckrv]]), which is outside the test's narrow
  3-code reject set `{TEMPLATE_INCOMPLETE, TEMPLATE_INCONSISTENT, ATTRIBUTE_VALUE_INVALID}` → the old
  code `raise`d → fail.
- **Why it's over-strict.** Per the classification model, a negative op rejected with **some other
  clean code** is `pass`/`xfail`, never `fail`. A `CkrAssertionError` always carries a clean module
  `CK_RV` (a crash surfaces as `returncode<0` at the runner, not here), so the import-reject of an
  `InvalidPrivateKey`-flagged vector is honest behavior regardless of which clean code is used.
- **Not the nss class.** nss b251ad1b *accepts* over-length ML-DSA signatures/keys (Type-A, wrong
  thing → fail, kept). Here kryoptic *rejects* malformed key material → correct direction. Opposite
  sign.
- **Cross-provider.** softhsm2-main/opencryptoki **pass**; bouncyhsm/nss/wolfpkcs11 *accept* the
  malformed key at import then reach the sign branch (which xfails them as lenient key validation —
  the existing `_MLDSA_INVALID_PRIVATE_KEY_FLAGS` path). kryoptic is the only one rejecting at import,
  and it does so cleanly. Both directions are honest; the harness was failing only the clean-reject
  direction.
- **Fix.** `test_wycheproof_mldsa_sign` now treats a clean `CkrAssertionError` import-reject of an
  `InvalidPrivateKey`/`IncorrectPrivateKeyLength` invalid vector as a pass (rejecting malformed key
  material is the correct outcome), narrowing the `except` to `CkrAssertionError` so non-CKR Python
  bugs still propagate. TDD: `tests/test_wycheproof_kryoptic_classification.py` (clean import-reject
  for `DEVICE_ERROR`/`FUNCTION_FAILED`/`GENERAL_ERROR` is not-fail; a valid-vector import reject still
  propagates as a real signal).
- **Confidence: HIGH.** rv-trace pinpoints `C_CreateObject→CKR_DEVICE_ERROR`, the model is explicit
  that a clean non-spec reject of a negative vector is not a fail, and the fix preserves the lenient
  *acceptance* path (still xfailed) and valid-vector signal.

### Code + docs this triage

- `fix(tests)` x25519 jwk `InvalidPublic` canonical-length drop + mldsa_sign clean import-reject —
  provider-general, effect-gated, with TDD (`tests/test_wycheproof_kryoptic_classification.py`,
  reconciled `tests/test_wycheproof_xdh_guards.py`). Full gates green; meta-suite 0-fail/0-xfail.
- module-issues.md §Kryoptic: NEW Type-A AES-KW empty-blob acceptance entry (genuine, stays `fail`).
- No fix for the 27 AES-KW fails — keeping them failing is correct ("failures ARE findings").

## nss long-tail triage 2026-06-11

**Scope.** Full triage of **every** `outcome:failed` (`when:call`) record in the fresh VALIDATED
pool `artifacts/nss-pooled/report.jsonl`. nss (Network Security Services softoken 3.120.1, v3.0)
is a software-only PKCS#11 token, so the suite's hardware-token threat model flags many
attribute-protection deviations that are upstream-known properties of the softoken design (the
module-issues.md §NSS "Security Findings" preamble at line 408 records this). **Total: 130 failed
call records, across 34 files** (matches the bucket counts in the triage brief).

**Method.** Aggregated by `(file, normalized message)`; cross-checked **every** bucket against
**all** `<provider>-pooled/report.jsonl` snapshots in the fresh pool (per-nodeid outcome decoded so
the cross-provider split is on identical test ids), and against the §NSS / §NSS-PQC / §NSS-main
sections of [module-issues.md](../module-issues.md). The ChaCha20-Poly1305 KAT vector was decoded
and recomputed independently against the RFC 8439 / OpenSSL reference to decide vector-vs-module
fault. **Note (post-triage correction):** the `test_mech_encrypt` ChaCha bucket was subsequently
proven to be a **harness bug**, not an NSS bug — see the HARNESS BUG determination below and the
retraction in module-issues.md §NSS.

### Bucket table (file → count → determination)

| Count | File | Class | Determination |
|---|---|---|---|
| 32 | `security/test_ffi_length_boundary.py` | 💥 | **KNOWN** — C-cluster harness-provoked UB (lying-buffer length / isize_max huge-len). Denis 2026-06-10: KEEP ("a segfault IS the finding"). Documented module-issues.md §NSS. |
| 15 | `ckr/test_ckr_keygen.py` | 📋 ⚠️**NEW** | **GENUINE nss attribute-length-validation gap** — `C_GenerateKey`/`C_GenerateKeyPair` accept malformed-length scalar attributes (`CKA_TOKEN` BBOOL given 8 bytes; `CKA_VALUE_LEN`/`CKA_PARAMETER_SET` CK_ULONG given 1 or 9 bytes) and return `CKR_OK`. Same class as the softhsm2 `CKA_TOKEN` gap but **broader** (nss also misses `CKA_VALUE_LEN`/ML-DSA+ML-KEM `CKA_PARAMETER_SET`). kryoptic/opencryptoki/wolfpkcs11 **reject** all; softhsm2 rejects 2 of the 7 non-PQC. Stays `fail`. See determination below. |
| 8 | `ckr/test_ckr_object.py` | 📋 ⚠️**NEW** | **GENUINE nss findings (same family).** 6 = the scalar-length gap on `C_CreateObject`/`C_CopyObject` (`CKA_TOKEN`/`CKA_CLASS`/`CKA_KEY_TYPE` malformed length) — here softhsm2 + wolfpkcs11 **both reject**, nss accepts → nss-specific. 1 = `CKA_ALLOWED_MECHANISMS` NULL-ptr-nonzero-length accepted (shared w/ kryoptic, documented). 1 = `test_allowed_mechanisms_empty_null_pointer_enforced` **Type-B**: nss accepts an empty allow-list, reads it back empty, then still encrypts (self-contradiction; shared w/ opencryptoki). See determination below. |
| 8 | `wycheproof/test_wycheproof_mldsa.py` | 📋 | **KNOWN, ALREADY-ACCOUNTED** — the documented genuine nss ML-DSA verify Type-A finding (b251ad1b, module-issues.md §NSS): tc7/tc65/tc70/tc144/tc157/tc170 over-length signature + over-length public-key acceptance (FIPS-204 fixed-length / non-malleability break). Confirmed = that class. No action; stays `fail`. |
| 7 | `security/test_ffi_null_pointer.py` | 💥 | **KNOWN** — C-cluster NULL-data/NULL-buffer SIGSEGV (`C_Sign`/`C_Verify`/`C_*Update`/`C_GenerateRandom`/`C_SeedRandom`/`C_SetOperationState` with NULL ptr + nonzero len). Denis-KEEP UB class. Recorded with the genuine NULL-deref crashes below (nss segfaults where careful modules return `CKR_ARGUMENTS_BAD`). |
| 7 | `wycheproof/test_wycheproof_x25519.py` | 🔧 ⚠️**KNOWN→FIXED-AFTER** | **HARNESS over-strictness, FIXED this session (9908f272).** All 7 are x25519_jwk `InvalidPublic` tc519/522/524/525/526/527/529 — JWK-wrapper-only invalidity whose `x` decodes to canonical length (the kryoptic-triage NEW #2 determination). The provider-general load-time drop drops them next run; this pre-fix pool still shows 7F. Confirmed = that class. No further action. |
| 6 | `ckr/test_ckr_raw_buffer.py` | 💥/📋 | **KNOWN** — output-buffer overrun: nss ignores the caller-declared `*pulCount`/`*pulBufLen` and writes the full result past the boundary (guard-byte probe). Documented module-issues.md §NSS ("Output-buffer overrun" 2026-06-09). Buffer-guard class shared w/ kryoptic. |
| 6 | `security/test_parameter_validation.py` | 💥 + ⚖️ | **KNOWN, MIXED.** 1 = `TestGcmAadNullWithLength` GCM **NULL-AAD-pointer-with-nonzero-length SIGSEGV** = GENUINE nss crash (kryoptic/opencryptoki survive; only nss + softhsm2 crash). 5 = GCM weak-IV (1/4-byte) / weak-tag (32/64-bit) / IV-reuse stricter-than-spec hardening — ⚖️ flagged-for-decision (spec-legal weak params), same class flagged on softhsm2/kryoptic, left as-is. |
| 4 | `security/test_api_boundary.py` | 💥 ⚠️**NEW(distinguishing)** | **GENUINE nss NULL-deref crash finding** (recorded; KEEP). `C_DigestInit(NULL mech)`, `C_CreateObject`/`C_FindObjectsInit`/`C_GenerateKey(template=NULL, count=5)` → **signal 11**. softhsm2/kryoptic/opencryptoki all **survive and return `CKR_ARGUMENTS_BAD`** on these exact calls → nss-specific NULL-deref, not generic harness UB. "A segfault IS the finding." See determination below. |
| 3 | `test_access_levels.py` | 📋 | **KNOWN** — `CKA_TRUSTED` USER-grant, `CKA_WRAP_WITH_TRUSTED` downgrade + untrusted-wrap. Type-B attribute-non-enforcement of the softoken security-design family (module-issues.md §NSS Security Findings; `CKA_WRAP_WITH_TRUSTED not enforced` HIGH row + umbrella note). |
| 3 | `test_kem.py` | 📋 ⚠️**NEW(partly)** | 2 = ML-KEM `CKA_ENCAPSULATE`/`CKA_DECAPSULATE=False` permission flag **not enforced** (Type-B): nss reads the flag back False then still encaps/decaps. **nss-only** (kryoptic/opencryptoki/bouncyhsm/wolfpkcs11 all enforce). Documented module-issues.md §NSS "ML-KEM permission flags not enforced" HIGH row. 1 = `CKA_VALUE` injected into the decaps template accepted (value-shape class, shared w/ kryoptic/bouncyhsm/wolfpkcs11). All stay `fail`. |
| 2 | `acvp/test_acvp_eddsa.py` | ⚖️ | **KNOWN (flagged-for-decision)** — `TestEdDsaKeyVer` accepts invalid Ed25519 keys (tc1/tc4). Same ⚖️ Edwards-point analysis pending as on softhsm2/kryoptic; RFC 8032 does not require verifiers to reject non-canonical/small-order pubkeys. |
| 2 | `ckr/test_ckr_null_params.py` | 💥 ⚠️**NEW(distinguishing)** | **GENUINE nss NULL-deref crash** — `C_GetInfo(NULL)`, `C_GetSlotList(pulCount=NULL)` → signal 11. softhsm2/kryoptic survive (return cleanly). Same nss-specific NULL-deref family as `test_api_boundary`. KEEP. |
| 2 | `ckr/test_ckr_raw_args_bad.py` | 💥 ⚠️**NEW(distinguishing)** | **GENUINE nss NULL-deref crash** — `C_DigestInit(NULL mech)`, `C_GenerateKey(NULL mech)` → signal 11. softhsm2/kryoptic survive. Same family. KEEP. |
| 2 | `ckr/test_ckr_wrap.py` | 📋 | **KNOWN** — `CKA_TOKEN` overlong-length on `C_UnwrapKey` (scalar-length family); `test_key_not_extractable` = `C_WrapKey` on `CKA_EXTRACTABLE=False` key (Type-B, softoken attribute-non-enforcement family, documented HIGH row). |
| 2 | `security/test_api_security.py` | 📋 | **KNOWN** — `C_CopyObject` `CKA_EXTRACTABLE False→True` laundering + wrap-decrypt oracle key extraction. Type-B Tookan/laundering family, documented module-issues.md §NSS CRITICAL rows. |
| 2 | `security/test_padding_oracle.py` | 📋 noise | **KNOWN** — probabilistic AES-CBC-PAD Vaudenay (`CKR_OK_DIFFERENT`=1) + RSA-OAEP Manger non-uniform error codes. Documented cross-run nondeterminism ([[reference_oracle_tests_probabilistic]]); verify-don't-alarm. |
| 2 | `security/test_recover_length_boundary.py` | 💥/📋 | **KNOWN** — `C_SignRecover` isize_max+1 accepted + `C_VerifyRecover` one-byte-output guard subprocess fail. C-cluster value-shape / buffer-guard, KEEP. |
| 2 | `test_remaining_gaps.py` | 📋 | **KNOWN** — `CKA_UNWRAP_TEMPLATE`/`CKA_WRAP_TEMPLATE` created-object/target-attribute enforcement (Type-B). softoken attribute-non-enforcement family (umbrella note). |
| 1 | `test_mech_encrypt.py` | 🔧 ⚠️**RETRACTED→HARNESS BUG FIXED** | **HARNESS BUG, not an NSS finding.** `build_params_from_vector` had no `chacha20_poly1305` branch and fell through to `build_test_params`, generating a fresh random nonce instead of the vector's `iv_hex`. Encrypting under a random nonce then comparing against a fixed-nonce KAT vector is unpassable by any correct module. Fixed: `chacha20_poly1305` branch added to `build_params_from_vector`; regression test `tests/test_chacha_kat_params.py`. NSS is NOT at fault. See full determination below. |
| 1 | `test_mech_wrap.py` | 📋 ⚠️**NEW** | **GENUINE nss `CKM_RSA_X_509` unwrap finding (Type-A roundtrip break).** nss derives the unwrapped AES key from the **leading** bytes of the raw RSA block; `CKM_RSA_X_509` right-justifies the key (trailing bytes). The harness `_raw_rsa_unwrap_hint` confirms `unwrapped == leading ≠ trailing`. wrap→unwrap on the same module recovers a different key. Stays `fail`. See determination below. |
| 1 | `acvp/aes/test_cts_detect.py` | 📋 | **KNOWN** — nss advertises `CKM_AES_CTS` but errors on CTS encrypt probes (CTS non-functional). Advertised-but-not-operational; recorded module-issues.md §NSS (mechanism fuzz). |
| 1 | `ckr/test_ckr_general.py` | 📋 ⚠️**NEW(minor)** | nss accepts `C_Finalize` after `C_Finalize` (`finalize_accepted`) where spec wants `CKR_CRYPTOKI_NOT_INITIALIZED`; softhsm2/kryoptic/opencryptoki reject. Lifecycle deviation (nss + wolfpkcs11). Stays `fail`; minor, recorded here. |
| 1 | `security/test_arithmetic_overflow.py` | 💥 | **KNOWN** — `C_FindObjectsInit(template_count=ULONG_MAX)` SIGSEGV. C-cluster count-overflow (kryoptic also crashes). KEEP. |
| 1 | `security/test_cve_regression.py` | 📋 | **KNOWN** — Tookan §3.3 unwrap-with-`CKA_SENSITIVE=False` produces a non-sensitive copy of a SENSITIVE=True key. softoken sensitive-boundary family. |
| 1 | `security/test_tookan.py` | 📋 | **KNOWN** — `C_CopyObject` escalates `CKA_EXTRACTABLE False→True`. Type-B laundering family (documented CRITICAL row). |
| 1 | `test_access_control.py` | 📋 | **KNOWN** — `CKA_COPYABLE=False` key copied. Documented module-issues.md §NSS ("CKA_COPYABLE not enforced"). |
| 1 | `test_attribute_enforcement.py` | 📋 | **KNOWN** — `C_DestroyObject` on `CKA_DESTROYABLE=False`. Documented ("CKA_DESTROYABLE not enforced"). |
| 1 | `test_buffers.py` | 📋 | **KNOWN** — `C_SignFinal` returns `pulSize=0` after `CKR_BUFFER_TOO_SMALL` (two-call-convention deviation; shared w/ kryoptic/opencryptoki/wolfpkcs11). Buffer-guard class. |
| 1 | `test_mech_derive.py` | 📋 | **KNOWN** — HKDF base-key gen → `CKR_MECHANISM_INVALID`; nss HKDF non-operational. Documented module-issues.md §NSS (Group 2, HKDF limitation). |
| 1 | `test_mech_message.py` | 📋 | **KNOWN** — `C_EncryptMessage` AES-GCM generated IV not written back to `pIv`. Same generated-IV message-API class as kryoptic/softhsm2-generated-iv. |
| 1 | `test_operation_termination.py` | 📋 | **KNOWN** — `C_EncryptUpdate(NULL input)` returns `CKR_ARGUMENTS_BAD` but leaves the encrypt op active (next init → `CKR_OPERATION_ACTIVE`). Same operation-non-termination class as kryoptic ([[project_operation_active_cascade]]). |
| 1 | `test_rsa_key_wrapping.py` | 📋 | **KNOWN** — `C_WrapKey` on `CKA_EXTRACTABLE=False` (Type-B, documented HIGH "Non-extractable key is wrappable"). |
| 1 | `test_set_attribute.py` | ⚖️ | **KNOWN (flagged-for-decision)** — `TestSetAttributeAtomicity` partial `CKA_LABEL` apply before rejecting read-only `CKA_CLASS`. Stricter-than-spec atomicity hardening flagged ⚖️ on softhsm2/kryoptic; PKCS#11 §5.7 does not mandate atomicity. |

**Known vs new roll-up.** Of 130: the great majority are **KNOWN** — documented genuine nss
findings (Type-A ML-DSA over-length, output-buffer overrun, HKDF non-operational, generated-IV,
operation-non-termination, the softoken attribute-non-enforcement security family) kept `fail`, the
two ⚖️ flagged stricter-than-spec hardening items, C-cluster crashes (KEEP), the probabilistic-noise
pair, and the two already-accounted buckets (ML-DSA 8 confirmed, X25519 7 known-fixed-after). The
**NEW** material this pass, all GENUINE nss (no harness bug), stays `fail` and is added to
module-issues.md §NSS: (1) the attribute-length-validation gap (keygen 15 + object 6 = scalar-length
family), (2) the empty-`CKA_ALLOWED_MECHANISMS` Type-B + ML-KEM permission-flag Type-Bs (the latter
already had a HIGH row — confirmed), (3) the **nss-specific NULL-deref crash family** (api_boundary 4
+ ckr_null_params 2 + ckr_raw_args_bad 2 + GCM-NULL-AAD 1 = 9 SIGSEGVs where every other careful
module returns `CKR_ARGUMENTS_BAD`), (4) the ChaCha20-Poly1305 KAT mismatch (Type-A; param-layout
root-cause deferred), (5) the `CKM_RSA_X_509` leading-vs-trailing unwrap break (Type-A), and (6) the
minor `C_Finalize`-after-`C_Finalize` lifecycle acceptance.

### NEW — attribute-length-validation gap (`test_ckr_keygen` 15 + `test_ckr_object` 6) = GENUINE nss finding

**Verdict: GENUINE FINDING (input-validation gap). No code change — the test classifies correctly;
documented module-issues.md §NSS.**

- **What.** Probes inject a syntactically-valid template attribute with a **wrong declared
  `ulValueLen`** (a valid non-NULL pointer — *not* a lying buffer): a `CKA_TOKEN` `CK_BBOOL` given
  `sizeof(CK_ULONG)`=8 bytes (`make_bool_attr_overlong`), or a `CKA_VALUE_LEN` / `CKA_CLASS` /
  `CKA_KEY_TYPE` / ML-DSA+ML-KEM `CKA_PARAMETER_SET` `CK_ULONG` given 1 byte (underlong) or 9 bytes
  (overlong) (`make_ulong_attr_with_length`). On `C_GenerateKey`, `C_GenerateKeyPair`,
  `C_CreateObject`, `C_CopyObject`, **nss returns `CKR_OK`** and creates the object (rv-trace /
  message: "accepted invalid (CKR_OK) -- must reject").
- **Why it's the wrong thing.** PKCS#11 fixes each attribute's value length by type
  (`CK_BBOOL`=1 byte, `CK_ULONG`=`sizeof(CK_ULONG)`); a value whose length does not match is
  malformed and must be rejected (`CKR_ATTRIBUTE_VALUE_INVALID` / `CKR_TEMPLATE_INCONSISTENT`). The
  `classify_negative_rv(rv, TEMPLATE_ERRORS, …)` helper `fail`s **only on outright `CKR_OK`
  acceptance** — any clean reject (spec code → pass, other clean code → xfail) is honest. nss accepts.
- **Test is sound, not over-strict, not UB.** The pointer handed to nss is valid and points at real
  storage; only the declared length is wrong (this is the documented value-shape probe, *not* the
  C-cluster lying-buffer UB). The module reads a real buffer and simply fails to length-check it.
- **Cross-provider (fresh pool, definitive):** on the 7 non-PQC scalar nodeids,
  **kryoptic (×3) / opencryptoki (×2) / wolfpkcs11 (×2) PASS** (reject); softhsm2 rejects 2 of 7 (its
  documented narrower `CKA_TOKEN` gap). On the 8 ML-DSA/ML-KEM `CKA_PARAMETER_SET` nodeids,
  **kryoptic (×3) / opencryptoki (×2) PASS**. On the 6 object-creation nodeids,
  **softhsm2 (×3) + wolfpkcs11 (×2) PASS** (so nss is uniquely permissive on `C_CreateObject`).
  **nss (all advertised variants) accepts every one.** Clean split → nss-specific length-validation gap.
- **Confidence: HIGH.** Direct `CKR_OK`-accept messages, well-formed value-shape probes, and a clean
  cross-provider split (every other careful provider rejects at least the subset it advertises).

### NEW — `test_ckr_object::test_allowed_mechanisms_empty_null_pointer_enforced` (1) + `test_kem` permission flags (2) = GENUINE nss Type-B

**Verdict: GENUINE Type-B self-contradiction. No code change — `classify_policy_enforcement` only
`fail`s when both claimed AND violated; documented module-issues.md §NSS.**

- **What.** (a) nss accepts an **empty** `CKA_ALLOWED_MECHANISMS` array (NULL_PTR, len 0) at
  `C_CreateObject`, reads it back as `[]` (`claimed=True`), then **still** `C_EncryptInit`/`C_Encrypt`
  succeeds with `CKM_AES_ECB` (`violated=True`). (b) ML-KEM key created `CKA_ENCAPSULATE=False` /
  `CKA_DECAPSULATE=False` reads the flag back False, then `C_EncapsulateKey`/`C_DecapsulateKey`
  succeeds.
- **Why it's the wrong thing (Type-B).** The module *claimed* a protection (the attribute it reports
  back) then *violated* it (performed the operation the attribute forbids) — a self-contradiction
  that `fail`s by the model, not a single honest deviation.
- **Cross-provider.** The empty-allow-list one: nss + opencryptoki fail; softhsm2/kryoptic/wolfpkcs11
  enforce (pass). The ML-KEM permission flags: **nss-only** — kryoptic/opencryptoki/bouncyhsm/
  wolfpkcs11 all enforce (pass). The ML-KEM rows are already a documented HIGH §NSS finding (confirmed
  here); the empty-allow-list one is added.
- **Confidence: HIGH.** The `classify_policy_enforcement` claim/effect gate plus the cross-provider
  enforcement split.

### NEW — nss-specific NULL-pointer SIGSEGV family (`test_api_boundary` 4 + `test_ckr_null_params` 2 + `test_ckr_raw_args_bad` 2 + GCM-NULL-AAD 1 = 9) = GENUINE nss crash findings

**Verdict: GENUINE crash findings ("a segfault IS the finding"). No code change — KEEP `fail`;
documented module-issues.md §NSS.**

- **What.** nss softoken **SIGSEGVs (signal 11)** on `C_GetInfo(NULL)`, `C_GetSlotList(pulCount=NULL)`,
  `C_DigestInit`/`C_GenerateKey`/`C_CreateObject`/`C_FindObjectsInit` with a NULL `pMechanism` or NULL
  `pTemplate` (nonzero `count`), and `C_EncryptInit(CKM_AES_GCM)` with a NULL `pAAD` + nonzero
  `ulAADLen`. The subprocess runner records `returncode < 0` and the test correctly `fail`s.
- **Why it's a finding, not generic harness UB.** Per spec these calls must return
  `CKR_ARGUMENTS_BAD`, not dereference NULL. The cross-provider split is decisive:
  **softhsm2 / kryoptic / opencryptoki all survive and return `CKR_ARGUMENTS_BAD`** on the exact same
  NULL-mechanism / NULL-template calls; only nss crashes. (For the GCM NULL-AAD one, softhsm2 also
  crashes — a separately documented softhsm2 finding — but kryoptic/opencryptoki survive, so nss
  crashing is still a real finding.) Because careful modules handle these NULLs gracefully, the nss
  crash is an nss NULL-deref bug, not a harness-provoked-UB exclusion.
- **Relation to the C-cluster.** The brief framed `test_api_boundary`/`ffi_null_pointer` as
  Denis-KEEP harness-provoked UB; that KEEP stance holds (don't suppress), but for **nss specifically**
  these are *distinguishing* genuine NULL-deref crashes (other providers don't crash) and are recorded
  as such. `ffi_null_pointer` (7, NULL *data*-with-nonzero-len) stays in the broad C-cluster KEEP set.
- **Confidence: HIGH.** Direct `returncode<0` signal-11 records + a clean cross-provider survival split.

### RETRACTED — `test_mech_encrypt::test_kat_vector[CHACHA20_POLY1305]` (1) = HARNESS BUG (param-wiring), NOT nss Type-A

**Verdict: HARNESS BUG. The original "GENUINE Type-A" determination was incorrect. Retracted.**

- **Root cause.** `build_params_from_vector` in `mechanism_helpers.py` had no `chacha20_poly1305`
  branch. The function fell through to `build_test_params`, which generates a **fresh random nonce**
  with `aad=None` and ignores the vector's `iv_hex`/`aad_hex` entirely. Encrypting under a random
  nonce and comparing against a fixed-nonce KAT vector is unpassable by any correct module — the
  test was guaranteed to produce a ciphertext mismatch regardless of the module's correctness.
- **Evidence from verification.** Five nss and bouncyhsm pools each produced a *different* "wrong"
  ciphertext (nondeterministic, matching the random-nonce signature). NSS passes 325/325 Wycheproof
  ChaCha vectors through the standard `mech_chacha20_poly1305` packer, proving NSS consumes
  `CK_SALSA20_CHACHA20_POLY1305_PARAMS` correctly. bouncyhsm failing the same vector with a
  *different* wrong ciphertext is also explained by random nonce (each pool draw a new nonce).
- **The "vector independently recomputed" check was sound but insufficient.** The KAT vector IS
  RFC-8439-correct; what the triage did not catch was that the harness was never feeding that
  vector's nonce to the module at all.
- **Fix.** A `chacha20_poly1305` branch was added to `build_params_from_vector` (analogous to the
  `gcm`/`ccm` branches) that reads `iv_hex` as nonce and `aad_hex` as optional AAD. Regression
  test: `tests/test_chacha_kat_params.py` (3 cases: vector nonce wired, no-AAD path, no-iv fallback).
- **nss is not at fault.** This entry is removed from the NSS finding list (module-issues.md §NSS
  retracted the Type-A entry and replaced it with a harness-bug note).
- **Confidence: HIGH (the harness bug is proven and fixed; regression test is GREEN).**

### NEW — `test_mech_wrap::test_wrap_unwrap_aes_key[RSA_X_509]` (1) = GENUINE nss Type-A unwrap break

**Verdict: GENUINE Type-A (wrap→unwrap roundtrip recovers a different key). Stays `fail`. No code
change.**

- **What.** With `CKM_RSA_X_509` (raw RSA, no padding) the decrypted block is a full modulus-width
  block with the key **right-justified** (spec §6.1.12: key bytes taken from the *end* of the
  block, zero-padded on the left). NSS softoken reads `CKA_VALUE` as the **first** `ulValueLen`
  bytes instead (leading bytes). With RSA-2048 and a 16-byte AES key the leading 16 bytes are all
  zeros (the zero-padding), so the unwrapped key is observationally zero-filled. The harness
  `_raw_rsa_unwrap_hint` confirms `unwrapped_value == leading and != trailing`: `2643ad30…` is
  the wrong decryption output (leading-bytes read), and `5aa55aa5…` is the original test plaintext
  (the AES key being wrapped/unwrapped). A wrap→unwrap on the same nss module recovers incorrect
  key material.
- **Why it's the wrong thing (Type-A).** `CKM_RSA_X_509` unwrap must take the key from the
  low-order (trailing) bytes of the raw block; taking the leading bytes yields wrong key material —
  a self-inconsistent roundtrip (a real application would get garbage). opencryptoki passes this id.
- **Confidence: HIGH.** Direct decrypt-mismatch + the leading-vs-trailing diagnostic, and a passing
  cross-provider comparator (opencryptoki).

### Code + docs this triage

- **Post-triage harness fix.** Adversarial verification after this triage session proved the
  `test_mech_encrypt` ChaCha20-Poly1305 bucket was a harness param-wiring bug (see RETRACTED
  section above). The `chacha20_poly1305` branch was added to `build_params_from_vector`;
  regression test `tests/test_chacha_kat_params.py` guards the fix.
- **No other code change.** All other failing tests are sound and provider-general
  (the cross-provider splits are the proof). The two harness over-strictness classes
  that touch nss (X25519 jwk, ML-DSA-sign clean-reject) were already fixed in the kryoptic pass
  (9908f272 / 439fc3a1) and drop next run.
- module-issues.md §NSS: NEW entries — attribute-length-validation gap (keygen + object creation);
  empty-`CKA_ALLOWED_MECHANISMS` Type-B; nss-specific NULL-pointer SIGSEGV family;
  `CKM_RSA_X_509` leading-vs-trailing unwrap break (Type-A); minor `C_Finalize`-after-`C_Finalize`
  acceptance. All stay `fail` ("failures ARE findings"). ChaCha20-Poly1305 entry RETRACTED (harness
  bug, not NSS bug).

## tpm2 long-tail triage 2026-06-11

**Scope.** Full triage of **every** `outcome:failed` (`when:call`) record in the fresh VALIDATED
pool `artifacts/tpm2-pooled/report.jsonl`. tpm2 (tpm2-pkcs11 1.10.0, swtpm-backed daemon) is a
hardware/daemon-backed provider with a deliberately **narrow** surface — 26 mechanisms, and notably
**no operational key/object *creation* surface** for the suite's setup recipes. **Total: 112 failed
call records, across 44 files** (matches the bucket counts in the triage brief; very diffuse).

**Method.** Decoded the structured `longrepr.reprcrash` + first traceback frame of all 112 records
and bucketed by **root cause site** (which setup recipe / op raised), not just by file. Cross-checked
the focus buckets against **all** `<provider>-pooled/report.jsonl` snapshots (per-nodeid outcome
decoded), and against the §tpm2-pkcs11 1.10.0 section of [module-issues.md](../module-issues.md) +
[provider-tpm2.md](provider-tpm2.md). The dominant story was confirmed by the pool's own
**xfail** records: tpm2 already produces 147+88+75+… `XFailed: AES_KEY_GEN advertised but key
generation is not operational` (and the RSA/EC equivalents) — i.e. the provider **advertises**
`CKM_AES_KEY_GEN`/`CKM_RSA_PKCS_KEY_PAIR_GEN`/`CKM_EC_KEY_PAIR_GEN` but `C_GenerateKey*` rejects at
runtime. The 112 hard fails are the **laggard setup sites** that still call the *raw* recipe instead
of the established `_or_xfail` wrapper, plus a tail of genuine findings and the Denis-KEEP C-cluster.

### Root-cause classification (all 112)

| Count | Root cause | Class | Determination |
|---|---|---|---|
| 51 | `gen_aes_key()` setup → `CKR_FUNCTION_NOT_SUPPORTED` | 🔧 **NEW→FIXED** | **HARNESS over-strictness, FIXED (provider-general).** tpm2 advertises `CKM_AES_KEY_GEN` but `C_GenerateKey` is non-operational — the documented PC-6 advertised-but-not-operational condition, **already routed to xfail in ~330 sites** via `gen_aes_key_or_xfail`/`require_operational_aes_keygen`. These 51 call the raw `gen_aes_key()` in setup and so hard-fail. **Cross-provider: every other provider PASSES these nodeids** (softhsm2/kryoptic/nss/opencryptoki/wolfpkcs11/bouncyhsm) — only tpm2 fails, exactly the non-operational-keygen signature. Fixed this pass for the 7 focus-bucket files (see below); rest is the same class. |
| 6 | `gen_rsa_keypair()` setup → `CKR_ATTRIBUTE_VALUE_INVALID` | 🔧/📋 **NEW** | **Same advertised-but-not-operational class (RSA).** tpm2 advertises `CKM_RSA_PKCS_KEY_PAIR_GEN`; the pool already xfails 45+ such sites (`RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational`). The 6 raw `gen_rsa_keypair()` setup sites (`test_encrypt`, `test_mech_sign_recover`, `test_crypto_weakness`) hard-fail. NOTE the surface is *template-conditional*: some templates succeed (e.g. `test_ckr_sign::test_mechanism_invalid` reaches its assertion), so the right wrapper is `gen_rsa_keypair_or_xfail` per-site, not a blanket skip. Documented; same fix recipe as AES, deferred (not in the 7 focus files). |
| 3 | `gen_ec_keypair()` setup → `CKR_ATTRIBUTE_VALUE_INVALID` | 🔧/📋 **NEW** | **Same class (EC).** `test_kdf::TestECDHDerive` ×3 abort at EC keypair setup; pool already xfails 8+ `EC_KEY_PAIR_GEN advertised but keypair generation is not operational`. Same `gen_ec_keypair_or_xfail` recipe; deferred. |
| 2 | HMAC-as-KDF op → `CKR_GENERAL_ERROR` | 📋 **NEW** | `test_kdf::TestKeyDeriveSoftware` ×2: HMAC sign returns `CKR_GENERAL_ERROR` (advertised-but-not-operational HMAC). Same `SHA256_HMAC advertised but … not operational` xfail class already used by `test_generic_secret`. Deferred. |
| 11 | C-cluster SIGSEGV (`ffi_length_boundary`, `arithmetic_overflow`, `api_boundary`, `ckr_raw_args_bad` NULL-mech) | 💥 | **KNOWN** — harness-provoked UB (isize_max huge-len digest/update/random, `template_count=ULONG_MAX`, NULL `pMechanism`). Denis-KEEP ("a segfault IS the finding"). Documented module-issues.md §tpm2 (Raw CKR NULL-mechanism findings). |
| 5 | `test_secret_key_value_len.py` oversized `CKA_VALUE_LEN` | 💥 | **KNOWN, excluded** — the ulong/scalar `CKA_VALUE_LEN=0xffff…` value-shape class (`C_CreateObject`/`C_SetAttributeValue`/`C_DigestKey` store the toxic length). Shared, documented C-cluster value-shape. KEEP. |
| 3 | `test_operation_termination.py` C_Verify/VerifyFinal non-termination | 📋 | **KNOWN, excluded** — documented tpm2 `C_Verify`/`C_VerifyFinal` non-termination after rejected signature (next `C_VerifyInit` → `CKR_OPERATION_ACTIVE`). provider-verify-operation-not-terminated.md / [[project_operation_active_cascade]]. Stays `fail`. |
| 1 | `test_subprocess_safety.py::test_fork_after_initialize` timeout | 📋 | **KNOWN, excluded** — documented tpm2 fork/daemon re-init timeout (module-issues.md §tpm2 "Remaining-gap and subprocess-safety"). Environmental daemon behavior; KEEP. |
| 2 | `ckr_raw_args_bad` `C_GenerateKey/C_WrapKey(NULL mech)` → `CKR_FUNCTION_NOT_SUPPORTED` | 📋 | **KNOWN** — documented module-issues.md §tpm2 ("`C_GenerateKey(NULL)`/`C_WrapKey(NULL)` returns `0x54` not `CKR_ARGUMENTS_BAD`"). Stays `fail`. |
| ~13 | genuine semantic findings (session/object/login/attribute) | 📋 | **KNOWN (documented)** — `test_open_session_is_public` / `test_access::public_session_no_private_keys` / `test_session_state_machine` (private keys visible pre-login); `test_object_visibility` ×2 (session objects survive owning-session close); `test_ro_session::test_verify_in_ro_session`; `test_sensitivity` Type-B; `test_set_attribute::test_cannot_change_modulus` + `test_ckr_object::test_set_readonly_class` (read-only `CKA_MODULUS`/`CKA_CLASS` mutated); `x509/test_lifecycle::test_cert_modifiability`; `ckr_sign`/`ckr_verify::test_mechanism_invalid` (AES_ECB accepted as sign/verify mech); `test_data_objects`/`test_access_control` data-object create rejected. The lifecycle/visibility set is documented module-issues.md §tpm2 "Session and object lifecycle findings". All stay `fail`. |
| 3 | AES-GCM crossverify op → `CKR_GENERAL_ERROR` | 📋 **NEW(minor)** | `test_aead::TestAESGCMCrossVerify` ×3: tpm2 does **not** advertise AES-GCM (the suite already `Skipped: AES_GCM not supported` for the ACVP-GCM path), but these 3 crossverify tests `_import_aes` then GCM-encrypt without a GCM capability gate, so they hard-fail at the op with `CKR_GENERAL_ERROR`. Advertised-vs-operational mismatch on the *op* side; same advertised-but-not-operational family. Deferred (left `fail`; a `skip_unless_mechanism(rs, "AES_GCM")` gate would convert to skip — minor, not in focus fix). |

**Known vs new roll-up.** Of 112: the great majority are the **single dominant class** — the
tpm2 *no-operational-key/object-creation-surface* setup aborts (51 AES + 6 RSA + 3 EC + 2 HMAC = 62)
that the harness should route to xfail (provider-general; it already does for ~330+ sibling sites).
The rest is the Denis-KEEP C-cluster (11 SIGSEGV + 5 value-shape + 2 NULL-mech = 18), the documented
non-termination/fork environmental pair (4), and ~13 genuine documented semantic findings (kept
`fail`) plus 3 GCM-op advertised/operational-mismatch (minor). **No genuine Type-A crypto break was
found** — and, per the nss-ChaCha lesson, I specifically checked the AES "wrong output" candidates:
there are none; every AES bucket is a *setup keygen reject*, not a wrong-ciphertext. The wrong-output
risk simply does not arise here because tpm2 cannot create the setup keys to reach a crypto op.

### NEW — the `gen_aes_key()` setup-abort class (51) = HARNESS over-strictness — FIXED (7 focus files)

**Verdict: HARNESS over-strictness. tpm2 advertises `CKM_AES_KEY_GEN` but `C_GenerateKey` is
non-operational; a *setup* keygen abort for a non-operational advertised mechanism must be `xfail`
(not `fail`), exactly as the established `gen_aes_key_or_xfail`/`require_operational_aes_keygen`
helpers already do in ~330 sites. Fixed for the focus-bucket files this pass.**

- **What.** 51 tests across 22 files call the *raw* `gen_aes_key(rs.raw, rs.sh, …)` in their setup
  (the first line of the test body). On tpm2, `C_GenerateKey(CKM_AES_KEY_GEN)` returns
  `CKR_FUNCTION_NOT_SUPPORTED`, so `gen_aes_key`'s internal `expect_rv(rv, CKR_OK)` raises and the
  whole test hard-fails *before reaching its actual negative-op/contract assertion*.
- **Why it's harness over-strictness, not a tpm2 finding.** The pool **already records** tpm2 as
  `XFailed: AES_KEY_GEN advertised but key generation is not operational` for the ~330 sites that
  route setup through `gen_aes_key_or_xfail`/`require_operational_aes_keygen`. The model's "capability
  genuinely absent / advertised-but-not-operational" rule makes this an `xfail`, not a `fail`. The
  51 laggard sites are simply unmigrated. `CKR_FUNCTION_NOT_SUPPORTED` is already in
  `AES_KEYGEN_RUNTIME_REJECT_RVS`.
- **Provider-general (the proof).** The wrapper only triggers on the specific keygen-reject CKRs;
  on every module whose AES keygen *works* (softhsm2/kryoptic/nss/opencryptoki/wolfpkcs11/bouncyhsm)
  the raw keygen succeeds and the test runs normally — confirmed by the cross-provider matrix
  (the 6 other providers reach each migrated nodeid's post-keygen assertion instead of aborting at
  setup) and by the existing `*_use_operational_aes128*` green meta-tests. No provider identity is
  consulted. **Correction (earlier overstatement):** it is *not* true that all 6 other providers PASS
  every one of these nodeids — 3 nodeid×provider pairs are genuine post-keygen findings that still
  `fail` after migration (wolfpkcs11 `test_double_encrypt_init`, wolfpkcs11 + bouncyhsm
  `test_encrypt_final_no_update`). The wrapper sits at the keygen call only; a real post-keygen
  finding on any provider is unaffected and still hard-fails — which is exactly the desired behavior.
- **Fix (this pass).** Migrated the **7 focus-bucket files** to a module-level `gen_aes_key` wrapper
  (raw imported as `_raw_gen_aes_key`; wrapper catches the setup `AssertionError` and calls
  `xfail_if_known_ckr(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, …)`): `test_concurrent_sessions.py`,
  `ckr/test_ckr_codes.py`, `ckr/test_ckr_object.py`, `ckr/test_ckr_spec_compliance.py`,
  `test_mech_state.py`, `test_ro_session.py`, `test_aead.py`. Each gets a dedicated regression test
  in `tests/test_setup_runtime_capability_guards.py` (the established guard suite; +7 tests, now 122
  passing) that monkeypatches `_raw_gen_aes_key` to raise `CKR_FUNCTION_NOT_SUPPORTED` and asserts
  the setup becomes an `xfail` with the file-specific message.
- **Deferred sites — NOW MIGRATED (follow-up pass).** The remaining setup-keygen laggards have been
  migrated to the **canonical conftest helpers** (no per-file local wrapper — the review flagged the
  7×-duplicated `_raw_gen_aes_key` wrapper; this pass uses `gen_aes_key_or_xfail` /
  `gen_rsa_keypair_or_xfail` / `gen_ec_keypair_or_xfail` / new shared `hmac_sign_or_xfail` directly):
  the remaining AES setup nodeids across `ckr/test_ckr_derive|priority|sign|verify`,
  `test_duplicate_labels`, `test_interface`, `test_large_objects`, `test_session_edge_cases`,
  `test_session_exhaustion`, `test_session_info`, `test_surface_audit`, `test_v30_session`,
  `security/test_parameter_validation|tookan`; the 6 RSA setup sites (`test_encrypt` ×3,
  `test_mech_sign_recover` ×2 via one helper, `security/test_crypto_weakness` ×1); the 3 EC sites
  (`test_kdf::TestECDHDerive` via one helper); and the 2 HMAC sign-op sites
  (`test_kdf::TestKeyDeriveSoftware` ×2, routed through the new shared `hmac_sign_or_xfail`, which
  also replaced the duplicated local `_HMAC_RUNTIME_REJECT_RVS` block in `test_generic_secret`). The
  3 GCM-op nodeids (`test_aead::TestAESGCMCrossVerify` ×3) got their distinct fix — a
  `has_mechanism("AES_GCM")` skip-gate (these had no GCM capability gate while sibling GCM tests do).
  `gen_aes_key_or_xfail` gained an optional `sh=` override for the few setup keys generated in a
  freshly opened session. **Deliberately left `fail` (subject-keygen tests, not setup):**
  `test_surface_audit::test_key_size_range_respected` and `test_generate_key_all_aes_sizes`,
  `test_attribute_fuzz::test_create_key_normal` (baseline "keygen works" assertions whose subject IS
  keygen), and `test_crypto_weakness::test_weak_rsa_key_generation` /
  `test_attribute_fuzz::test_negative_key_length` (key-size probes that already tolerate the reject).
- **Confidence: HIGH.** Direct `CKR_FUNCTION_NOT_SUPPORTED`/`CKR_ATTRIBUTE_VALUE_INVALID`/
  `CKR_GENERAL_ERROR`-at-setup-or-op traceback frames (artifacts/tpm2-pooled), the pool's own xfail
  records for the migrated-sibling sites, and red→green + mutation-checked regression tests in
  `tests/test_setup_runtime_capability_guards.py` (+ direct helper unit tests in
  `tests/test_classification_helpers.py`).

### Code + docs this triage

- **Harness fix (commit pending).** 7 focus-bucket files migrated to the advertised-but-not-
  operational AES-keygen xfail wrapper; +7 regression tests in
  `tests/test_setup_runtime_capability_guards.py`. Full gates green: `ruff check`/`ruff format
  --check` clean on all changed files, `mypy --strict` clean (package scope), `tests/` meta-suite
  **2183 passed, 2 skipped, 0 failed, 0 xfailed**.
- **No false Type-A.** Per the nss-ChaCha lesson, every AES "wrong output" candidate was checked and
  is a *setup keygen reject*, not a wrong-ciphertext — there is no genuine tpm2 crypto break in this
  pool. The genuine findings are all already-documented session/object/login/attribute semantics +
  the Denis-KEEP C-cluster, kept `fail`.
- **No doc churn for stats** (per project policy). module-issues.md §tpm2 already documents the
  advertised-but-not-operational keygen (PC-6), the lifecycle/visibility findings, the NULL-mech
  rejects, and the fork timeout; this triage adds no new finding rows (the 62 setup aborts are a
  harness classification bug, not module bugs).
