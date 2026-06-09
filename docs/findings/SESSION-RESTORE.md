# Session restore — triage/fix loop (2026-06-09)

This file lets you **restore the goal + loop after clearing context**. Everything below is also
in git history (branch `fix/triage-harness-improvements`), `docs/findings/issues-triage.md`, and
auto-memory `project_issue_triage_loop.md`.

## How to restore the loop (run on Fable, not Opus)

1. Start / resume on Fable: `claude --model claude-fable-5` (the only thing that forces Opus is
   `/fast` — do not run it).
2. Re-set the standing goal (paste as a message):

   > fully analyze failures (both xfail/fail) in docker test_pool.py (and other runs) results.
   > artifacts/ = fresh, artifacts2/ = backup baselines (docker target re-runs allowed). Analyze
   > all issues in pkcs11-check test cases — misconfiguration, incorrect usage, harness bugs vs
   > real provider findings. Document all findings, fix the real pkcs11-check issues, keep the
   > suite general/provider-valid (no per-provider gating). Do not stop: when ready, code-review /
   > gap-analyze from new angles and fix found issues — continue until quality improves.

3. Re-arm the loop:

   ```
   /loop 10m analyze issues by artifacts/ and artifacts2/ docker results, investigate, if an issue is in pkcs11-check fix/improve, keep provider-general
   ```
   (The previous session-only cron `93250212` dies on restart; this recreates it.)

## Operating rules (proven this session)

- **Staleness rule:** the pool ran `--no-build`; every candidate MUST be re-confirmed with a fresh
  `docker/test.sh <provider> -- <path>` before acting. Controls = softhsm2 / kryoptic / opencryptoki
  (must stay byte-identical).
- **Classification model (positive-op row):** CKR_OK+correct = pass; clean error = xfail (honest
  deviation, even if mechanism operational); CKR_OK+wrong-output / crash / self-contradiction
  (accept-invalid, claimed-success-then-violated) = fail; capability genuinely absent = skip.
- **Provider-general only** — no `if module == ...` in logic (comments OK). Re-audited clean.
- **Never hide findings.** A genuine provider limitation that fails IS the finding (e.g. corePKCS11
  has no CKO_DATA support — keep it failing). Only fix HARNESS bugs (false failures).
- **Fix workflow:** TDD (RED meta-test first) → implement → ruff+mypy --strict → fresh per-provider
  verify (fixed provider + a control) → commit with before/after counts.
- **Gotcha:** 2 CLI meta-tests (test_cli preflight, test_state_cmd json) FAIL ONLY in the colored
  remote-control shell; they pass in `env -i HOME=$HOME PATH=$PATH TERM=dumb uv run pytest tests/`.
  Not code. Everything else green (1948 passed).

## What's DONE + verified (branch `fix/triage-harness-improvements`, NOT merged to dev)

~22,610 corepkcs11 KAT false-failures eliminated + cross-provider, all fresh-verified, controls
unchanged. Detail in `docs/findings/issues-triage.md` (fix-pass table + long-tail conclusion) and
`docs/module-issues.md` (corePKCS11 / bouncyhsm / opencryptoki sections).

- **H6** corePKCS11 ECDSA 21,906F→0F: storage-shape negotiation (`create_object_negotiated` +
  `import_{ec_public,secret,rsa_public,rsa_private}_key_negotiated` in conftest; winner cached per
  shape; policy-attr drop), generic in-memory PAL (`docker/corepkcs11/corepkcs11_pal_generic.c`),
  sig-decode-before-import leak fix, `ec_public_key_binding_defect` gate + `test_ec_import_coherence.py`
  (REAL Type-C: secp256k1/brainpoolP256r1 silent curve rebind, 2 fails).
- **H2** `testcases/_operability.py`: canonical KAT probe per (mech,direction), cached;
  `classify_kat_clean_error`. Wired: base_runner_aead (GCM/CCM), test_wrap (KW/KWP), base_cts,
  test_xts, **and wycheproof_aes CCM (in-flight at context-clear — see below)**. Found REAL
  bouncyhsm bug: CCM decrypt accepts invalid tags + returns unstripped tag bytes (no auth).
- **Sweep** KAT/conformance imports → negotiated: acvp_hmac 148F→0F, limbo 493F→0F (_portable_label
  ≤32B), wycheproof_aes 63F→0F, rsa/rsa_pss/wycheproof/acvp_rsa 0F, test_rsa_key_import 5F→1P/2s/2xf
  (+capability gating).
- **H3** opencryptoki OAEP 26F→0F (RFC-8017 hashlib combo probe). **H4** bouncyhsm ro_session 5F→0F.
  **H5** opencryptoki aes_modes 6F→2F REAL (ulCounterBits=0/129 accepted) +4xf.
- **H8 (high value)** RSA PKCS#1 v1.5 decrypt test was BACKWARDS — it penalized the
  anti-Bleichenbacher mitigation (synthetic plaintext) and failed every real provider
  (nss/softhsm2/kryoptic 62/59/62 F). Fixed: flag only when plaintext == target msg (real
  padding bypass). All -> 201/201 P. NSS probe: 0 breaks. Also bouncyhsm wycheproof CCM
  420F->63F via H2 probe routing.
- **C1-C4 determined:** C1/C2/C3 = harness-provoked UB (lying buffer/array lengths) — **flagged for
  YOUR nod** (removing the deliberate overflow security suite is outward-facing). C4 wolfpkcs11
  HKDF/keygen = GENUINE crashes (real findings, kept).

## State at this checkpoint

Branch `fix/triage-harness-improvements`, **26 commits ahead of dev, working tree clean**, full
meta-suite **1950 passed** in clean env (the 2 CLI color-env flakes are gone after the colored shell
note above; re-check with `env -i HOME=$HOME PATH=$PATH TERM=dumb uv run pytest tests/`). The
wycheproof_aes CCM H2 routing and the H8 RSA-decrypt fix are both committed + verified.

## Remaining queue (next angles)

1. **Other-provider triage IN PROGRESS:** NSS rsa_decrypt DONE (H8); pkcs11-mock = mock
   stub-storage (not findings, skip). STILL TODO: NSS remainder (ffi UB=C2, error_path_kwp 21,
   mldsa_sign 14), tpm2, kryoptic-fips, nss-pqc, softhsm2-main, qryptotoken, opencryptoki-master —
   extract from `artifacts2/<prov>-shard-*/results.json` units[].stdout, find harness-bug
   candidates vs genuine findings. (bouncyhsm now ~CCM-only + small tails; corepkcs11 long-tail
   = genuine, done.)
3. **xfail audit:** confirm no xfail added this session is over-broad / hides a real fail.
4. **C1-C3 removal** — needs your decision (outward-facing security-suite change).
5. **Secret-key coherence** root-cause via a stock-PAL repro (corePKCS11 CMAC/HMAC import OK then
   handle invalid — documented not-asserted; P-256 round-trips through the generic PAL so likely
   corePKCS11's object-list, not the PAL).
6. **Merge to dev** — YOUR milestone call (CLAUDE.md: never auto-merge; `git checkout dev && git
   merge fix/triage-harness-improvements`).

## Pointers

- corePKCS11 source mirror: `/tmp/corePKCS11` (v3.6.4). In-container probes: `/tmp/probe*_core*.py`.
- Pool baseline extraction: `artifacts2/<prov>-shard-*/results.json` → `units[].stdout` tail regex
  (`=+ (.*) in [\d.]+s =+` for summaries; `^FAILED`/`Unexpected CK_RV (CKR_[A-Z_]+)` for buckets).
- Targeted run: `bash docker/test.sh <provider> -- <full/path/to/test.py>` (NOTE: full path, not
  `wycheproof/x.py`). Full provider run: `bash docker/test.sh <provider>`.
- Auto-memory index: `~/.claude/projects/-home-user-src-m-pkcs11-check/memory/MEMORY.md`;
  loop state: `project_issue_triage_loop.md`.
