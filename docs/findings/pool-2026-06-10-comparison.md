# Pool comparison — 2026-06-10 (PARTIAL: wolfpkcs11 ×2 pending)

**Status:** PARTIAL — 19/21 providers. `wolfpkcs11` and `wolfpkcs11-master` are still
running their tail in the live pool and are **absent** from `artifacts/`; this doc will be
completed once those two land.

- **New run:** `artifacts/<provider>-pooled/{results.json,report.jsonl}` (post-merge, fresh)
- **Baseline:** `artifacts2/<provider>-pooled/results.json` (pre-fix OLD pool; pooled present
  for all 19 providers, so no shard aggregation was needed)
- Both treated **read-only**. Counts come from each run's `summary` (results.json),
  cross-checked against per-nodeid terminal verdicts derived from `report.jsonl`.

All deltas are attributed to the intentional changes merged **after** the baseline:
advertised-capability honesty package (claim layer + per-suite CKR allowlist retirement),
vacuous-reject downgrade (8 sites), three-state SigVer/PSS probes, ECDH H9 / PSS
salt-variant / OPERATION_ACTIVE / ML-DSA fixes, reinit-recovery, capability-gating
retirement. See **"Changes NOT in these images"** for what is deferred to the next run.

---

## 1. Summary table (provider × old → new)

Counts: P=pass, F=fail, xf=xfail, skip=skip. Delta = new − base. `tot` delta is uniformly
**+5** because of 5 brand-new tests (4 × `test_ec_import_coherence.py`, 1 ×
`test_mech_coverage.py` registry meta-check) added in this window.

| provider | P (old→new) | F (old→new) | xf (old→new) | skip (old→new) | ΔP | ΔF | Δxf | Δskip |
|---|---|---|---|---|---|---|---|---|
| bouncyhsm | 55388→54196 | 8197→2132 | 8604→15858 | 36439→36448 | −1192 | **−6065** | +7254 | +9 |
| corepkcs11 | 1831→10950 | 22756→142 | 174→1059 | 37064→49679 | +9119 | **−22614** | +885 | +12615 |
| corepkcs11-main | 1831→10950 | 22756→142 | 174→1059 | 37064→49679 | +9119 | −22614 | +885 | +12615 |
| kryoptic | 51383→58614 | 212→137 | 12611→12614 | 44916→37762 | +7231 | −75 | +3 | −7154 |
| kryoptic-fips | 36770→43939 | 194→176 | 11346→11354 | 44719→37565 | +7169 | −18 | +8 | −7154 |
| kryoptic-main | 51382→58613 | 213→138 | 12611→12614 | 44916→37762 | +7231 | −75 | +3 | −7154 |
| nss | 38137→38220 | 234→130 | 1805→1819 | 53311→53323 | +83 | −104 | +14 | +12 |
| nss-main | 36659→36752 | 211→117 | 1724→1727 | 54049→54052 | +93 | −94 | +3 | +3 |
| nss-main-slot0 | 1470→1470 | 61→61 | 194→194 | 710→710 | 0 | 0 | 0 | 0 |
| nss-pqc | 36661→36750 | 209→119 | 1724→1727 | 54049→54052 | +89 | −90 | +3 | +3 |
| nss-pqc-slot0 | 1470→1470 | 61→61 | 194→194 | 710→710 | 0 | 0 | 0 | 0 |
| nss-slot0 | 1440→1440 | 61→61 | 191→191 | 693→693 | 0 | 0 | 0 | 0 |
| opencryptoki | 63175→64438 | 360→212 | 1218→1248 | 33122→31982 | +1263 | −148 | +30 | −1140 |
| opencryptoki-master | 63175→64439 | 360→211 | 1218→1248 | 33122→31982 | +1264 | −149 | +30 | −1140 |
| pkcs11-mock | 736→737 | 290→288 | 70→70 | 31848→31850 | +1 | −2 | 0 | +2 |
| softhsm2 | 44792→44900 | 171→65 | 5021→5024 | 32483→32483 | +108 | −106 | +3 | 0 |
| softhsm2-generated-iv | 44797→44903 | 168→64 | 5021→5024 | 32481→32481 | +106 | −104 | +3 | 0 |
| softhsm2-main | 46963→47064 | 169→63 | 4487→4488 | 31777→31786 | +101 | −106 | +1 | +9 |
| tpm2 | 8323→18146 | 201→112 | 4412→4636 | 68778→58825 | +9823 | −89 | +224 | −9953 |

**Duplicate pairs** (identical config, near-identical results — analysed once):
`corepkcs11`≈`corepkcs11-main`, `kryoptic`≈`kryoptic-main`,
`opencryptoki`≈`opencryptoki-master`, `softhsm2`≈`softhsm2-generated-iv`. The three
`nss-*-slot0` "smoke" variants are tiny and unchanged (0 delta) — expected, they don't
exercise the touched suites.

**Big movers are dominated by capability-gating retirement** (formerly-skipped
wycheproof_ecdsa vectors now run): tpm2 +9999, kryoptic/-fips/-main +7202, opencryptoki
+1149, corepkcs11 +8662 pass on that one file. corepkcs11's −22,614 F is its own story
(see checklist item below).

---

## 2. Expected-shift checklist — verdicts

### 1. tpm2 ACVP SigVer ~135 invalid-vector P→xf "vacuous reject" — **PASS**
`report.jsonl` shows **exactly 135** vacuous-reject xfails, all in
`acvp/test_acvp_rsa.py`, all SigVer-related. File-level delta: `acvp/test_acvp_rsa.py`
pass −135, fail −27, xfail +162 (the 135 vacuous + 27 other clean-error reclassifications).

### 2. bouncyhsm CCM: thousands P→xf; genuine fails == 1,691 EXACTLY — **PASS**
`acvp/aes/test_ccm.py`: fail −5,679, pass −1,028, **xfail +6,707**. Genuine remaining fails
= **1,691 exactly**, broken down (from `reprcrash.message`):
- **1,268** wrong-plaintext (decrypt returned wrong PT)
- **423** forgery (tampered ciphertext/tag accepted)
- 1,268 + 423 = 1,691 ✓. 1,028 of the new xfails are explicitly "vacuous reject".

### 3. kryoptic-fips test_mech_sign hard-fails → xfail (honesty package) — **PARTIAL**
`test_mech_sign.py` itself is **unchanged** (93P/56xf in both runs) — its 20 "advertised but
not operational" xfails were **already present in the baseline image**, so the honesty
package's sign-suite flip predates this baseline. The honesty fail→xfail flips that DID land
in this window are spread across other files (e.g. `test_ecdsa_extended.py` −3F/+3xf,
`test_aes_modes.py` −2F/+2xf, `test_encrypt.py`/`test_interop.py`/`ckr_raw_buffer.py`
−1F/+1xf each). kryoptic-fips's headline +7,169 P / −7,154 skip is **capability-gating
retirement** on `wycheproof_ecdsa.py` (+7,202 pass from retired skips), not the sign suite.
Verdict PARTIAL: honesty xfails confirmed present and the package behaves correctly, but the
specific test_mech_sign delta this checklist anticipated is not in *this* diff (it was earlier).

### 4. Controls (softhsm2 / kryoptic / opencryptoki) per-outcome deltas — **PASS**
**Zero newly-failing nodeids on all three controls.** Every fail-count change is a decrease:
softhsm2 171→65, kryoptic 212→137, opencryptoki 360→212. Sources are all intended:
- fail→pass: `wycheproof_rsa_decrypt.py` (invalid-vector accept downgrade) and
  `wycheproof_ecdh.py` ("ECDH derived a secret for an invalid vector" — the **ECDH H9 fix**).
- fail→xfail: honesty package (`ckr_wrong_key_type_hardening`, `aes_modes`, `ckr_raw_buffer`).
No probabilistic increase on the controls. (softhsm2-generated-iv tracks softhsm2.)

### 5. pkcs11-mock ~290F → 288F (canned-CKA_VALUE class) — **PASS**
**290 → 288** (net −2). Composition: `test_rsa_key_import.py` −2F (→skip),
`test_mech_digest.py` −1F (→xfail), **`test_mech_derive.py` +1F (→ was xfail)** — the +1 is
the regression in item 7.R1 below, partially offsetting the −3 of genuine cleanups.

### 6. OPERATION_NOT_VALIDATED sanctioned-refusal pass+note — **PASS (negative result)**
**NO provider** triggered the sanctioned-refusal pass. Grep for
`refused via sanctioned CKR_OPERATION_NOT_VALIDATED` across all 19 `report.jsonl` files = 0
hits. Expected and recorded: no module in the pool returns CKR_OPERATION_NOT_VALIDATED, so
the v3.2 sanctioned-refusal pass path is dormant (the xfail branch of `claim_refusal_passes`
carries all real cases).

### 7. Crash counts — **PASS (stable)**
Crashing-FILE set is **identical** new vs base for every provider (bouncyhsm 1, kryoptic-fips
5, nss 2, nss-main 3, etc.). **No new crash targets.** The small `summary.crashed`
test-count wobble (e.g. bouncyhsm 7→6) is within-unit and not a new crash unit.

---

## 3. Unexpected-shift triage (severity-ordered)

### R1 — REGRESSION (harness): `test_mech_derive` base-key-gen escapes not-operational xfail → hard FAIL
**Severity: HIGH (the one actionable regression).**
- **Where:** `src/pkcs11_check/testcases/test_mech_derive.py`
- **Providers / count:** **7 fails** — `HKDF_DERIVE` on all 6 NSS variants (nss, nss-main,
  nss-main-slot0, nss-pqc, nss-pqc-slot0, nss-slot0) + `XOR_BASE_AND_DATA` on pkcs11-mock.
- **Baseline → new:** these were **`xfail`** ("advertised derive path is not operational:
  CKR_MECHANISM_INVALID") and are now **`FAIL`**
  (`AssertionError: HKDF base key gen failed: CKR_MECHANISM_INVALID` /
  `Generic secret key gen failed: CKR_MECHANISM_INVALID`).
- **Root cause:** the new claim layer routes the test's `except AssertionError` through
  `claim_refusal_passes(exc, rs, ...)` (test_mech_derive.py:767), which reads `exc.rv` to
  decide pass-vs-xfail (`_capability_claims.py:117/129`). But the **base-key-generation
  precondition** uses a plain `assert rv == CKR_OK, f"HKDF base key gen failed: {rv}"`
  (line 317; same pattern at line 489 for DES) — a bare `AssertionError` with **no `.rv`
  attribute**. When CKM_HKDF_KEY_GEN / generic-secret keygen returns CKR_MECHANISM_INVALID
  (NSS/mock genuinely lack it), `exc.rv` is missing, the claim handler can't classify it,
  and the AssertionError propagates → hard fail.
- **Hypothesis:** intentional-change **side effect** (honesty package wiring), NOT a module
  bug — the module behaviour is unchanged (still CKR_MECHANISM_INVALID) and the baseline
  correctly xfailed it. **Fix direction:** attach `.rv` to the base-key-gen assertions
  (use the `.rv`-carrying assert helper) so the precondition failure is classifiable as
  not-operational and xfails, matching the op-stage path. This is a test-harness fix and is
  also the +1F in the pkcs11-mock 290→288 line (item 5).

### R2 — NEW-TEST findings (not regressions): `test_ec_import_coherence` fails on corepkcs11
**Severity: LOW (expected new coverage).**
- **Where:** `test_ec_import_coherence.py::test_ec_public_key_import_is_coherent`
  `[brainpoolP256r1]`, `[secp256k1]` — 2 fails on **corepkcs11** (and corepkcs11-main).
- This file is **brand-new** in this run (absent from baseline; one of the +5 new tests).
  The "newly failing" flag is purely because the test did not exist before — it is new D1
  coverage surfacing a corepkcs11 EC-import-coherence finding, **not a regression**.
- **Hypothesis:** genuine module finding newly exposed; no action on the harness.

### R3 — PROBABILISTIC NOISE: oracle / overflow pass→fail flips
**Severity: NONE (documented cross-run nondeterminism — see
`docs/findings` precedent + memory `reference_oracle_tests_probabilistic.md`).**
- `security/test_padding_oracle.py`: bouncyhsm (+2: `test_cbc_pad_all_last_block_positions`,
  `test_pkcs1v15_error_uniformity`), nss (`test_oaep_error_uniformity`),
  softhsm2-generated-iv (`test_cbc_pad_all_last_block_positions`).
- `security/test_arithmetic_overflow.py`: kryoptic-main
  (`test_kem_output_template_count_overflow[...]`), nss-pqc
  (`test_template_count_overflow[find_objects_init-0x100000000]`).
- All were `pass` in baseline, `FAIL` now, with **no related code change**. These are
  statistical timing/uniformity and randomized-overflow tests. Tell-tale: kryoptic-main
  shows the overflow flip but kryoptic (same module, different shard luck) does not. **No
  action — verify, don't alarm.**

### R4 — (informational) headline P/skip swings are capability-gating retirement
Not unexpected per se (it's an intended change), but worth flagging as the dominant driver:
formerly skipped `wycheproof_ecdsa.py` vectors now execute → +9,999 (tpm2), +7,202
(kryoptic family), +1,149 (opencryptoki), +8,662 (corepkcs11). corepkcs11's −22,614 F is
the same file: the baseline hard-failed 21,906 vectors on a blanket `CKR_ARGUMENTS_BAD`
(corePKCS11 doesn't really do ECDSA verify); honesty + allowlist retirement now route those
to xfail ("advertised ECDSA verify is not operational") + capability-gating skip, leaving
**0** remaining fails in that file. All intended.

---

## 4. Pending: wolfpkcs11 ×2
`wolfpkcs11` and `wolfpkcs11-master` are not yet in `artifacts/` (live pool tail still
running). When they land, append their summary rows + checklist deltas and flip this doc
from PARTIAL to final. Of note from memory: wolfpkcs11 **stable** ships PQC=0 vs **master**
PQC — expect different ML-DSA/ML-KEM coverage between the two.

## 5. Changes NOT in these pool images (deferred to next run)
The pool images were built **before** these merges, so their shifts are absent here and must
be looked for in the next pool:
- import-skip **Batches 1–2**
- **D1–D3** import-skip determinations (note: the D1 `test_ec_import_coherence.py` *test
  file* IS present — it's one of the +5 new tests — but the broader D1–D3 import-skip
  *reclassifications* are not)
- the **FIPS unwrap** fix (`xfail_if_op_not_operational` in `test_rsa_key_wrapping`)

---

## Verdict roll-up
| # | check | verdict |
|---|---|---|
| 1 | tpm2 SigVer 135 vacuous P→xf | **PASS** (exactly 135) |
| 2 | bouncyhsm CCM 1,691 fails (1,268+423) | **PASS** (exact) |
| 3 | kryoptic-fips sign hard-fail→xfail | **PARTIAL** (already in baseline; honesty flips elsewhere) |
| 4 | controls per-outcome deltas | **PASS** (0 newly-failing) |
| 5 | pkcs11-mock 290F→288F | **PASS** (−2 net) |
| 6 | OPERATION_NOT_VALIDATED sanctioned pass | **PASS** (negative result, 0) |
| 7 | crash-count stability | **PASS** (identical crash-file set) |

**One actionable regression: R1** (test_mech_derive base-key-gen plain-assert escapes the
not-operational xfail routing → 7 hard fails; harness fix = attach `.rv` to the keygen
preconditions). Everything else is intended shift, new-test coverage, or documented
probabilistic noise.
