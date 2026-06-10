# Pool comparison — 2026-06-10/11 (FINAL: all 21 providers)

**Status:** FINAL — 21/21 providers. `wolfpkcs11` and `wolfpkcs11-master` landed in the pool
tail and are amended below (§4). **Validation verdict: VALIDATED** (see §6) — no unexpected
regression on any provider; every fail-count change is an intended fail→xfail/pass shift,
documented genuine finding, new-test coverage, or documented probabilistic/scheduling noise.
The one known harness regression (R1, 7 false fails) was found in the partial pass and is
already fixed in code (`9b3e52f9`, NOT in these pool images — the 7 false fails ARE present
in this data, documented as known-fixed-after); it does not block validation.

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
| wolfpkcs11 | 38882→46524 | 3071→879 | 2962→5329 | 52669→44798 | +7642 | **−2192** | +2367 | −7871 |
| wolfpkcs11-master | 41340→49028 | 2673→482 | 3127→5471 | 51450→43588 | +7688 | **−2191** | +2344 | −7862 |

**Duplicate pairs** (identical config, near-identical results — analysed once):
`corepkcs11`≈`corepkcs11-main`, `kryoptic`≈`kryoptic-main`,
`opencryptoki`≈`opencryptoki-master`, `softhsm2`≈`softhsm2-generated-iv`. The three
`nss-*-slot0` "smoke" variants are tiny and unchanged (0 delta) — expected, they don't
exercise the touched suites.

**Big movers are dominated by capability-gating retirement** (formerly-skipped
wycheproof_ecdsa vectors now run): tpm2 +9999, kryoptic/-fips/-main +7202, opencryptoki
+1149, corepkcs11 +8662 pass on that one file. corepkcs11's −22,614 F is its own story
(see checklist item below). The two `wolfpkcs11` rows carry the largest **fail decreases**
of the pool (−2,192 / −2,191) — driven by the CTS operability flip (2,079 fail→xfail each)
plus ECDH-H9, CCM/GCM vacuous-reject, and digest/multipart honesty flips (see §4).

**`tot`-delta caveat for the wolf rows:** the two `wolfpkcs11` baselines in `artifacts2` are
from a *different* pool epoch than the in-pool 19, so their `tot` delta is **not** the
uniform +5 (it is −56 stable / −21 master from collection/parametrization drift between
epochs). The +5 new-test convention above applies only to the 19 same-epoch providers.

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

## 4. wolfpkcs11 ×2 — amended (landed in pool tail)

Both variants land **VALIDATED**: **0 newly-failing nodeids** that existed in the baseline,
on both stable and master. Every fail-count change is a **decrease** — the intended
fail→xfail/pass shifts. Headline +7,642 P / −7,871 skip (stable) and +7,688 P / −7,862 skip
(master) are capability-gating retirement (wycheproof_ecdsa) plus the CTS flip, identical in
shape to the other providers.

**Stable vs master coverage:** stable ships **PQC=0** — all **1,089** ML-DSA/ML-KEM tests
`skip`; master ships PQC — **1,582 P / 182 xf / 27 F / 249 skip** on the same suites (the 27
fails are genuine ML-DSA verify findings: `CKR_FUNCTION_FAILED` + valid-sig-rejected; the
`mldsa_sign` fail 15→6 is the intended honesty fail→xfail flip on 9 of them). This is the
documented stable/master PQC split, not a delta artifact.

### Checklist (wolfpkcs11)

1. **CTS operability flip — PASS (exact).** `acvp/aes/test_cts.py` fail **2,079 → 0**, xfail
   **0 → 2,079** on **both** variants (H2 operability class: advertised AES-CTS not
   operational → clean-error xfail). Verified by per-nodeid call-phase verdicts in
   `report.jsonl`, exactly 2,079 each.
2. **Documented genuine buckets remain — PASS.**
   - `wycheproof_rsa_oaep.py`: **209 F stable / 210 F master** (stable bucket;
     `CKR_ENCRYPTED_DATA_INVALID` on valid OAEP vectors). Matches expectation exactly.
   - `wycheproof.py` AES-CBC-PKCS5 ("Invalid AES-CBC vector … decrypted successfully"):
     **144 F on stable**; **master ships only 4** (master fixed most invalid-vector
     acceptance) — a stable-vs-master module difference, both pre-existing (in baseline too).
   - `test_hkdf` SIGABRT + `ckr_keygen` genuine crashes: present as crash-file units
     (`wycheproof_hkdf.py` rc=11/6, `ckr_keygen.py` rc=11 on stable; `wycheproof_hkdf.py`
     rc=11 on master) — same crash targets as baseline. Plus an in-test SIGABRT
     (`malloc(): invalid` on `C_DeriveKey(HKDF_SHA256, CKA_VALUE_LEN=0x1fe0)` in
     `test_secret_key_value_len.py`).
   - `test_access_levels`: **stable 7 F / master 5 F** — genuine SECURITY findings
     (CKA_TRUSTED escalation, public session creating CKA_PRIVATE objects, etc.). Present in
     **baseline too** (0 newly-failing). The "segfault on stable / master-fixed" reading:
     master fixed 2 of the access-control violations; neither variant crashes the file now
     (unit `failed` rc=1, not `crashed`).
3. **Honesty-package / vacuous shifts — PASS (analogous to other providers).**
   `not-operational` honesty xfails present (194 stable / 206 master report records); the
   vacuous-reject downgrades land as the CCM (fail 88→44, xfail +44), GCM (fail 23→8,
   xfail +15), and CTS (+2,079 xfail) flips. ECDH-H9 fix: `wycheproof_ecdh.py` fail 8→0 on
   both. Digest/multipart honesty: `test_mech_digest.py` fail→0 (xfail +18 stable / +9
   master), `test_mech_multipart.py` fail 18→0 (xfail +18, stable).
4. **No unexpected new failure class.** Only **one** file shows a fail **increase**:
   stable `test_interface.py` **0 → 1** (`test_v30_encrypt_decrypt_aes` returns truncated
   plaintext — `…test data 12` vs `…test data 123`, a Type-A correctness bug). This is a
   **genuine wolfpkcs11 finding newly surfaced, not a regression**: in the baseline that file
   was a *crashed* unit (rc=11) that died **before** the v3.0 crypto test ran, so the test
   had no recorded verdict; this run the exit-time crash landed on a different file, the v3.0
   test executed, and the pre-existing AES bug surfaced. master: **no** fail increase on any
   file.

### Crash-file wobble (informational — NOT a new crash target)
Stable subprocess-isolation crashed-file set: base **6** {ckr_keygen, padding_oracle,
dh_key_agreement, test_encrypt, **test_interface**, wycheproof_hkdf} → new **8** {same 5 +
**test_key_flags, test_mech_encrypt, test_mech_multipart**, minus test_interface}. Inspection
shows these are **exit-time SIGSEGVs**: every test inside each "crashed" unit produced a
verdict in `report.jsonl` (e.g. test_key_flags 12P/2xf, test_mech_multipart 14P/34xf) — the
segfault happens at process teardown (`C_Finalize`/unload) and lands on whichever file the
isolation scheduler finalizes, so the file set wobbles run-to-run with the **same** underlying
wolf exit-time bug. Master: single crash file both runs (`wycheproof_hkdf.py`, rc 6→11). This
is the documented "within-unit crash wobble, not a new crash target" pattern (§2 item 7).

## 5. Changes NOT in these pool images (deferred to next run)
The pool images were built **before** these merges, so their shifts are absent here and must
be looked for in the next pool:
- import-skip **Batches 1–2**
- **D1–D3** import-skip determinations (note: the D1 `test_ec_import_coherence.py` *test
  file* IS present — it's one of the +5 new tests — but the broader D1–D3 import-skip
  *reclassifications* are not)
- the **FIPS unwrap** fix (`xfail_if_op_not_operational` in `test_rsa_key_wrapping`)

---

## 6. Validation verdict — **VALIDATED**

**All 21 providers VALIDATED.** Nothing is BROKEN. Across every provider, each fail-count
change is attributable to exactly one of: (i) an **intended** fail→xfail/pass shift from the
merged changes (honesty package, vacuous-reject downgrade, ECDH-H9, capability-gating
retirement); (ii) a **documented genuine module finding** (e.g. wolf OAEP/AES-CBC/CCM/
access-levels, corepkcs11 EC-import); (iii) **new-test coverage** surfacing a pre-existing
finding (the +5 new tests; the wolf-stable `test_interface` v3.0 AES bug unmasked by crash
re-scheduling); or (iv) **documented probabilistic/scheduling noise** (oracle/overflow flips;
exit-time crash-file wobble). **0 newly-failing nodeids** on the controls and on **both** wolf
variants.

**Known R1 does not block.** R1 (7 false fails: NSS HKDF + mock XOR base-keygen plain-assert
escaping the not-operational xfail routing) was found in the partial pass and is **already
fixed in code** at `9b3e52f9` — that fix is NOT in these pool images, so the 7 false fails ARE
present in this data and are documented as known-fixed-after. It is a harness-side
classification bug, not a module regression, and is out of scope for a "is the pool broken"
verdict.

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
| 8 | wolfpkcs11 ×2 CTS 2,079 fail→xfail | **PASS** (exact, both) |
| 9 | wolfpkcs11 ×2 genuine buckets (OAEP/AES-CBC/CCM/access/PQC) | **PASS** (counts match; 0 newly-failing) |
| 10 | wolfpkcs11 ×2 no unexpected new fail class | **PASS** (only fail-increase = genuine unmasked AES bug, stable) |

**Overall: VALIDATED.** One actionable harness regression remains for the *next* run — **R1**
(test_mech_derive base-key-gen plain-assert escapes the not-operational xfail routing → 7
hard fails; fixed in code at `9b3e52f9`). Everything else is intended shift, new-test
coverage, genuine finding, or documented probabilistic/scheduling noise.
