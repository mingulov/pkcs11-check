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
