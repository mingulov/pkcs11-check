# Session restore — triage/fix loop (updated 2026-06-11, on `dev`)

This file restores the goal + loop after a context clear / new session. History: branch
`fix/triage-harness-improvements` is MERGED into `dev`; all work now lands on `dev` via small
feature branches or direct doc commits. Auto-memory: `project_issue_triage_loop.md`.

## LOOP STOPPED by Denis 2026-06-11 (cron 45473fc2 deleted). Campaign complete — see below.

**Triage campaign DONE: all 4 control/major providers' long tails fully accounted for.** dev is
clean (suite 2217P/3s/0F/0xf, CI gates green). To resume autonomous work, re-arm via "How to
restore the loop" below. Remaining substantive work = mechanism-registry Phases B–D (a
design-then-implement arc — start with `/brainstorm`, not a raw loop). Highlights this session:
- **Advertised-capability honesty package** (12 plan tasks) + **import-skip audit COMPLETE**
  (A1-A16/A18/A19; A17 evidence-deferred) + **D1-D3 determinations**, all two-stage reviewed.
- **tpm2 advertised-but-not-operational keygen class fully resolved** (75 setup sites → xfail via
  canonical `gen_*_or_xfail` helpers; local-wrapper duplication consolidated; new `hmac_sign_or_xfail`).
- **5 genuine module findings** documented + upstream-reportable: nss ML-DSA non-malleability,
  nss RSA_X_509 wrong-key-recovery, opencryptoki CBC-PAD malformed-ciphertext accept, softhsm2
  bad-OID EC accept, kryoptic empty-AES-KW accept. **X25519 over-strictness flag RESOLVED**
  (RFC 7748, effect-gated). ML-DSA(kryoptic) non-spec-reject → xfail.
- **2 finding-hiding-class harness bugs killed:** test_data_paths WYCHEPROOF_DIR poisoning
  (silently skipped 4 HKDF meta-tests); ChaCha20-Poly1305 dead-KAT (random-nonce, unpassable since
  v0.1.0 — was a FALSE nss accusation, retracted). LESSON: [[feedback_triage_verify_typea]].
- Validated pool comparison FINAL; `artifacts3/` = validated baseline for pkcs11-proxy-ng.
- **NOT pushed:** dev is ahead of origin (~230 commits) / behind 1 — Denis to `git pull --rebase && git push` when ready.

## CURRENT STATE — POOL COMPLETE + VALIDATED, artifacts3 baseline created (2026-06-11)

**The 21-provider full pool is COMPLETE and VALIDATED.** All `artifacts/<provider>-pooled/`
have results; the post-pool procedure (Denis 2026-06-10) is DONE:
- **Comparison FINAL:** `docs/findings/pool-2026-06-10-comparison.md` flipped PARTIAL→FINAL —
  wolfpkcs11 ×2 amended (§4), validation verdict §6. New vs `artifacts2/` baselines.
- **Verdict: VALIDATED.** Nothing broken. Every fail-count change is an intended fail→xfail/pass
  shift (honesty package, vacuous-reject downgrade, ECDH-H9, capability-gating retirement), a
  documented genuine module finding, new-test coverage, or documented probabilistic/scheduling
  noise. **0 newly-failing nodeids** on the controls and both wolf variants. wolfpkcs11 CTS =
  exactly 2,079 fail→xfail (both variants); OAEP 209/210F, AES-CBC-PKCS5 144F(stable), CCM/GCM,
  access-levels SECURITY findings all present and pre-existing. Crash-file wobble = exit-time
  teardown SIGSEGV that lands on whichever file the isolation scheduler finalizes (verdicts all
  captured), not a new crash target.
- **Known R1 does NOT block** (and is already fixed in code at `9b3e52f9`): the 7 false fails
  (NSS HKDF + mock XOR base-keygen plain-assert escaping not-operational xfail) ARE in this pool
  data (images predate the fix) — documented as known-fixed-after, surfaces in the next run.
- **`artifacts3/` CREATED** = `cp -a artifacts artifacts3` (14G, 53 entries, verified match;
  gitignored). **This is the VALIDATED BASELINE for pkcs11-proxy-ng tests.**
- **Metrics refreshed:** `docs/docker-provider-results.md` Matrix Results table updated from this
  validated pool (corepkcs11/-main now included as full rows).

**IMPORT-SKIP AUDIT COMPLETE (2026-06-11).** All of `docs/findings/import-skip-audit.md`
A1–A16, A18, A19 shipped + two-stage reviewed across Batches 1–4 (b38ad9b2 e0340c2d 3c72cc3f
45441f10 72b9b7d8 74d09c18 b25b9bd5 b75dd935) + D1–D3 (6857bebf b56c3f8c 9a040f98). A17 (DSA)
= evidence-backed DEFER (skip hit by ZERO providers; resolution recipe in doc). §5 marks COMPLETE.
- **Two fresh-data DETERMINATIONS (both GENUINE crypto, HIGH confidence, upstream-reportable, docs only):**
  nss `test_mldsa_verify` 8F = ML-DSA non-malleability break (verifies +1-byte-over-length
  sigs/keys; FIPS-204 fixed-length; `b251ad1b`); opencryptoki AES-CBC-PKCS5 144F = malformed-
  ciphertext acceptance (byte-identical to wolfpkcs11-stable; strict providers reject 216P;
  `27e4e6b5`+`7fa1f587`). Both in module-issues.md + issues-triage.md.
- **Finding-hiding bug KILLED (`a47170d0`):** `test_data_paths.py::test_env_var_overrides`
  poisoned `WYCHEPROOF_DIR` process-wide (restore-reload ran with the bogus env still set),
  silently SKIPPING 4 HKDF meta-tests in every full-suite run = hard-pins disabled in CI, masked
  as "6 skipped". Fixed via monkeypatch.context() + module-level vector pre-import. Suite 6s→2s.
- Suite now **2165 passed / 2 skipped / 0 xfailed**, gates green. dev ahead 214 / behind 1 of origin.

**STILL PENDING (next session / next pool):**
- **Mechanism-registry Phases B–D** — the remaining LONGER ARC (see [[project_mechanism_tests_progress]]:
  Phase A 1-4 done, 439 entries; Task 5 + B-D remain). This is a design-then-implement effort —
  warrants its own brainstorm/plan, not autonomous loop squeezing.
- **A17 DSA importer** (low priority; deferred with recipe — no provider hits it).
- **Next-run verification items** (changes merged AFTER the validated pool images — verify in the
  NEXT pool vs `artifacts3/` baseline): R1 fix (`9b3e52f9`), import-skip Batches 1–4 + D1–D3
  reclassifications (kryoptic-fips acvp_rsa ~216 skip→xf; tpm2 ~7k NIST-curve skip→xf;
  EC/Montgomery private-import xfails), FIPS unwrap (`xfail_if_op_not_operational`, kryoptic-fips 3F→0).

## CURRENT STATE — advertised-capability honesty MERGED (2026-06-10, later session)

**Advertised-capability honesty package: plan Tasks 1–9 MERGED to dev (`ec9db778`).**
Spec: `docs/superpowers/specs/2026-06-10-advertised-capability-honesty-design.md`; plan:
`docs/superpowers/plans/2026-06-10-advertised-capability-honesty.md`. Shipped: claim-layer
3-way mapping in all `test_mech_*` suites (OPERATION_NOT_VALIDATED → pass+note; per-suite CKR
allowlists retired), `_capability_claims.py`, `not_operational_reason`/`xfail_vacuous_reject`
helpers, three-state SigVer + PSS probes (staging → INCONCLUSIVE, never downgrades),
vacuous-reject downgrade at 8 probe-gated sites (AEAD GCM/CCM, KW/KWP, wycheproof-CCM,
SigVer, PSS ×2). Meta-suite 2060P/2s, gates green. Every task two-stage reviewed except
Task 9 (gates+self-verified; review pair skipped on user redirect — loop may backfill).
**REMAINING: plan Tasks 10–12** — registry coverage meta-check; CLAUDE.md +
classification-model-design.md amendments (MUST land before release — model/behavior drift);
docker fresh-verify (tpm2 acvp_rsa ~135 P→xf, bouncyhsm test_ccm 1,691 genuine F must remain,
kryoptic-fips test_mech_sign, controls softhsm2/kryoptic/opencryptoki).

## PREVIOUS STATE — session-exit snapshot (2026-06-10, earlier)

**Denis decisions (this session):**
- **C1–C3 UB probes = KEEP** ("crashes are findings"). The flag is CLOSED; do not remove the
  lying-buffer / NULL-deref probes. (Recorded in the CRASHES verdict block in issues-triage.md.)
- **Hardening checks** (GCM weak-params, EdDSA keyver, SetAttribute atomicity, AES-CBC-PAD lax
  padding, wrong-key-type init-only) = **no preference → leave AS-IS** (still `fail`, unchanged).

**Shipped this session (all merged to `dev`):** wrong-key-type continuation→xfail; CI ruff-format
gate; **FIPS "advertised-but-not-operational" class** — ECDSA-prehash SHA-1 + RSA encrypt/interop
(new helper `_signature_policy.xfail_if_op_not_operational`); doc corrections (wolfpkcs11 OAEP/CBC-PAD
over-claim ×2 docs; opencryptoki verify-final). A parallel worker also landed
`advertised-not-operational-gap-analysis.md` + an ML-DSA ctx-skip fix.

**Pending / pick up here:**
1. **`test_rsa_key_wrapping` FIPS** (3F on kryoptic-fips) — failure is on the **unwrap**
   (`unwrap_key_for_mechanism_roundtrip`, private-key C_UnwrapKey = key transport), NOT the public
   wrap. Wrap the 3 unwrap call sites with `xfail_if_op_not_operational`; verify kryoptic-fips→0,
   non-FIPS no-regression.
2. **gap-analysis follow-ups** (`advertised-not-operational-gap-analysis.md`): vacuous negative-op
   reject downgrade on NOT_OPERATIONAL mechanisms; registry-coverage meta-check.
3. Hardening reclassification (open, no decision). main promotion (Denis only).

## How to restore the loop (run on Fable, not Opus)

1. `claude --model claude-fable-5` (do not run `/fast`).
2. Standing goal (paste, or `/goal …`) — CURRENT version (2026-06-10, post-merge):

   > Improve pkcs11-check quality continuously on dev. Context: advertised-capability honesty
   > package is merged (dev ec9db778+; spec: docs/superpowers/specs/2026-06-10-advertised-
   > capability-honesty-design.md). A full pool run (docker/test_pool.py --all, 21 providers,
   > run by Denis) writes fresh artifacts/<provider>-pooled/; artifacts2/ = READ-ONLY pre-fix
   > baselines. Work queue, in order: (1) finish the plan
   > docs/superpowers/plans/2026-06-10-advertised-capability-honesty.md — Task 10 quality
   > review (commit 699cf42c, spec review done), Task 11 model-doc amendments (CLAUDE.md
   > classification table + docs/classification-model-design.md must match shipped behavior),
   > backfill Task 9's review pair (ec9db778); (2) when the pool completes, compare
   > artifacts/<provider>-pooled vs artifacts2/ per provider — expected: tpm2 SigVer ~135 P→xf
   > vacuous; bouncyhsm CCM thousands P→xf with the 1,691 genuine fails INTACT (fewer =
   > downgrade leaked = STOP and investigate); kryoptic-fips test_mech_sign F→xf; wolfpkcs11
   > CTS 2,079xf unchanged; controls softhsm2/kryoptic/opencryptoki ≈ byte-identical
   > (probabilistic oracle tests excepted — verify before alarming). POST-POOL PROCEDURE
   > (Denis 2026-06-10): after the comparison, (a) update internal metrics docs (Docker results
   > table — permitted after a deliberate full validation run), (b) ensure nothing is broken and
   > results are as intended (account for ALL intentional reclassifications: honesty package,
   > vacuous downgrades, import-skip batches, FIPS unwrap), (c) if ALL OK → backup
   > `cp -a artifacts artifacts3` = the validated baseline for pkcs11-proxy-ng tests,
   > (d) if broken → investigate and fix (prefer fixing obvious breakage; intentional
   > reclassifications are expected). Document in docs/findings/ (round counts >1000),
   > update SESSION-RESTORE.md, triage UNEXPECTED shifts as harness bugs;
   > (3) then the queue below: test_rsa_key_wrapping FIPS unwrap, import-skip→xfail audit
   > (32 sites, negotiated-exhausted + advertised only), nss mldsa_verify 8F, opencryptoki
   > AES-CBC-PKCS5 144F, pkcs11-mock canned-CKA_VALUE module-issues entry, mechanism-registry
   > Phases B–D. Rules: provider-general only; never hide findings (fail vs xfail per the
   > classification model); TDD meta-test per harness change; full CI gates before every
   > commit; NEVER launch/kill docker while the pool runs, afterwards targeted docker/test.sh
   > only; commit small coherent units to dev; subagent-driven implementation with two-stage
   > review (sonnet/opus implement, fable review).

3. Re-arm: `/loop 10m check Denis's pool run passively (pgrep -af test_pool.py; count
   artifacts/<provider>-pooled of 21 — never launch/kill docker); work the standing goal queue
   in order (plan task reviews + model-doc amendments → post-pool comparison vs artifacts2/ →
   SESSION-RESTORE queue); provider-general, never hide findings, full CI gates before each
   commit`

## Operating rules (proven)

- **Staleness:** artifacts/ + artifacts2/ pool data predates ALL session fixes; re-confirm every
  candidate fresh: `bash docker/test.sh <provider> -- <full/path/test.py>`. Controls = softhsm2 /
  kryoptic / opencryptoki, must stay byte-identical. artifacts/<provider>/ (plain dirs) = fresh
  targeted-run outputs; artifacts2/ = READ-ONLY backup.
- **Classification:** CKR_OK+correct=pass; clean error=xfail; CKR_OK+wrong output / crash /
  self-contradiction=fail; capability genuinely absent=skip. Provider-general only. Never hide
  findings — xfail is recorded, not hidden.
- **Fix workflow:** TDD RED meta-test → implement → ruff format+check + mypy --strict (full CI
  gate set, see feedback_ci_gates memory) → fresh per-provider verify + control → commit with
  before/after counts.
- **Two parallel sessions may share this tree.** Check `git status`/`git log` before editing;
  commit small coherent units fast; don't touch files another session has dirty.

## DONE this session (2026-06-09/10), all on dev

- **ECDH parameter-level invalidity (H9):** all 42 cross-provider "invalid-point accepted" =
  on-curve points (WrongCurve/UnnamedCurve/ModifiedPrime invalidity strips at decode;
  CK_ECDH1_DERIVE_PARAMS cannot carry curve params). `ecdh_cofactor1_shared_x` (pure math, incl.
  brainpool 224/320) + `_point_on_base_curve` (cryptography, sect*). Reduced to value-checked
  positives; off-curve derive stays FAIL "invalid-curve attack". Fresh-verified:
  softhsm2/opencryptoki 42F→0F, kryoptic 0F. 18 guard meta-tests.
- **RSA-PSS salt-variant acceptance:** reference auto-salt verification discriminates a genuine
  re-salted signature (xfail: salt policy not enforced — tpm2) from accepted garbage (crypto
  fail). tpm2 rsa_pss 46F→0F (passes unchanged 781), softhsm2 control 1183P/0F.
- **CKR_OPERATION_ACTIVE collaterals → xfail** in `_signature_policy` + PSS tuples (root cause
  stays FAIL in test_operation_termination). tpm2 rsa 12F→0F.
- **ACVP SigVer canonical operability probe** (commit 8d36a597): tpm2 rejects 27/27 valid SHA-1
  vectors with imported keys → per-(mech,key-bits) probe → xfail. tpm2 acvp_rsa 27F→0F,
  softhsm2 control 854P/0F.
- **ML-DSA sign (f08369da):** ctx vectors skip (never transmitted in this suite; covered by
  test_wycheproof_mldsa_context); malformed-key import+sign → xfail lenient (per a4ca5891
  precedent); other accepted invalid stays fail. **VERIFIED 2026-06-10: nss mldsa_sign 14F→0F
  (200P / 11xf / 9 skipped).** (Control runs on softhsm2/kryoptic optional — change is
  vector-metadata-gated, no provider branch.)
- **Gap analysis (9a288fac):** docs/findings/advertised-not-operational-gap-analysis.md — NOT
  FIPS-only (6 providers show the pattern); the "separate test" largely exists = test_mech_*
  registry suites (gaps: registry completeness, coverage meta-check); two leak classes violate
  "internal failure must be xfail, never pass": vacuous negative-op passes + 32 import-skip sites.
- **pkcs11-mock limbo 175F determined GENUINE** (mock stores a canned 12-byte CKA_VALUE for every
  cert → lifecycle readback contradiction, correctly FAILs; count grew from pool's 88F because the
  portable-label fix let more imports succeed). Not yet written into module-issues.md.
- Parallel session also landed: FIPS ECDSA-prehash/RSA-encrypt xfails (+ xfail_if_op_not_operational
  helper), wrong-key-type lenient-init xfail (a4ca5891), C_Digest OOB split, X25519/EdDSA sweep
  categorization, ruff-format CI gate fix (28 files), wolfpkcs11 OAEP/CBC-PAD = genuine findings.

## Queue (next iterations)

1. ~~Docker-verify f08369da~~ DONE 2026-06-10: nss 14F→0F (200P/11xf/9s).
2. **Vacuous-reject downgrade** (gap-analysis rec #1; direction endorsed by Denis 2026-06-10):
   where the canonical probe says NOT_OPERATIONAL, negative-op rejections pass→xfail "vacuous
   reject — input never evaluated". Scope: base_runner_aead, acvp/aes/test_wrap, base_cts,
   test_xts, wycheproof_aes, acvp SigVer, PSS combo. Evidence: tpm2 135 vacuous SHA-1 SigVer
   passes; bouncyhsm CCM thousands. Await scope confirmation (decision #5 below) or proceed
   per endorsement.
3. **Coverage meta-check** for advertised-but-unprobed mechanisms (registry blind spots visible).
4. **Import-skip→xfail audit** (32 `pytest.skip("Cannot import …")` sites; only
   negotiated-exhausted + advertised mechanisms qualify).
5. **nss mldsa_verify 8F** (verify-direction invalid acceptance = potential REAL crypto —
   determine, don't assume) + nss/mock malformed-length ulong CKR buckets (⚖️ family).
6. **opencryptoki AES-CBC-PKCS5 144F** — determine (wolfpkcs11's analogous OAEP/CBC-PAD were
   confirmed genuine).
7. **pkcs11-mock section in module-issues.md** (canned-CKA_VALUE lifecycle; evidence above).
8. **Mechanism-registry Phases B–D** (longer arc).
9. **Catalog follow-up:** retain unknown-name manifest entries as `MechEntry(config=None)` so
   the blind-spot check sees them (check `select_for_scenario` tolerance).
10. **acvp PSS three-state probe** (`_PSS_VER` canonical valid vectors exist) so
    `test_rsa_pss_verify` invalid rejects get the vacuous gate (residual from ec9db778;
    the PKCS15 probe does not cover PSS combos and the wycheproof PSS combo probe is
    private — cross-module import forbidden).

## DECISIONS NEEDED FROM DENIS (as of 2026-06-10)

1. **C1–C3 deliberate-UB security tests** (lying buffer/array lengths provoke crashes):
   remove/rework is outward-facing — needs explicit nod.
2. **Parameter-validation hardening family (⚖️):** GCM short-IV / short-tag / IV-reuse and
   RSA-PSS sLen=0 acceptance hard-fail 12–14 providers; all spec-legal. Model says xfail/note;
   they are deliberate hardening checks. (Triage doc argues sLen=0 fail is an outright harness
   bug.) Reclassify or keep?
3. **X25519 invalid-vector over-strictness** (RFC 7748: no invalid-curve attack class) — flagged.
4. **EdDSA keyver over-strict** — pending Edwards-point analysis.
5. **Vacuous-pass downgrade + import-skip→xfail:** direction endorsed in the FIPS message;
   confirm scope — affected providers gain thousands of xfails that were "passes" (honest, but
   big count shift).
6. **Wrong-key-type init-only lenient checks** fail-vs-xfail (flag noted in a4ca5891).
7. **Merge dev → main / release tagging** — milestone call; delete merged branch
   `fix/triage-harness-improvements`?

## Pointers

- Gap analysis: `docs/findings/advertised-not-operational-gap-analysis.md`.
- Triage log: `docs/findings/issues-triage.md` (fix-pass table + sweep categorizations).
- Operability machinery: `testcases/_operability.py`; `_signature_policy.py`
  (OP_NOT_OPERATIONAL_RVS, xfail_if_op_not_operational, OPERATION_ACTIVE in non-clean tuple);
  per-suite probes `_pss_combo_operational`, `_pkcs15_sigver_operational`,
  `ecdh_cofactor1_shared_x` / `_point_on_base_curve`.
- Targeted run: `bash docker/test.sh <provider> -- <full/path>`; fresh outputs land in
  `artifacts/<provider>/` (`report.jsonl` has per-test outcomes — used to prove tpm2 27/27).
- Wycheproof data: `~/.local/share/pkcs11-check/data/wycheproof/testvectors_v1/`.
