# Session restore — triage/fix loop (updated 2026-06-10, on `dev`)

This file restores the goal + loop after a context clear / new session. History: branch
`fix/triage-harness-improvements` is MERGED into `dev`; all work now lands on `dev` via small
feature branches or direct doc commits. Auto-memory: `project_issue_triage_loop.md`.

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
2. Standing goal (paste, or `/goal …`):

   > fully analyze failures (both xfail/fail) in docker test_pool.py (and other runs) results.
   > artifacts/ = fresh, artifacts2/ = backup baselines (docker target re-runs allowed). Analyze
   > all issues in pkcs11-check test cases — misconfiguration, incorrect usage, harness bugs vs
   > real provider findings. Document all findings, fix the real pkcs11-check issues, keep the
   > suite general/provider-valid (no per-provider gating). Do not stop: when ready, code-review /
   > gap-analyze from new angles and fix found issues — continue until quality improves.

3. Re-arm: `/loop 10m analyze issues by artifacts/ and artifacts2/ docker results, investigate,
   if an issue is in pkcs11-check fix/improve, keep provider-general`

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
  re-salted signature (xfail: salt policy not enforced — tpm2) from accepted garbage (Type-A
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
  cert → Type-C readback contradiction, correctly FAILs; count grew from pool's 88F because the
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
5. **nss mldsa_verify 8F** (verify-direction invalid acceptance = potential REAL Type A —
   determine, don't assume) + nss/mock malformed-length ulong CKR buckets (⚖️ family).
6. **opencryptoki AES-CBC-PKCS5 144F** — determine (wolfpkcs11's analogous OAEP/CBC-PAD were
   confirmed genuine).
7. **pkcs11-mock section in module-issues.md** (canned-CKA_VALUE Type-C; evidence above).
8. **Mechanism-registry Phases B–D** (longer arc).

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
