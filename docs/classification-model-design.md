# Test-Outcome Classification Model — Design

- **Date:** 2026-05-27
- **Status:** Draft for review
- **Scope:** How every test case in `src/pkcs11_check/testcases/` decides `pass` / `xfail` / `fail` / `skip`, and the work to make the suite consistent with that decision.

## Problem

pkcs11-check is a **provider-general** PKCS#11 suite: it runs against many modules
(SoftHSM2, Kryoptic, NSS softoken, OpenCryptoki, TPM2, BouncyHSM, pkcs11-mock, …)
with no single reference implementation. The four pytest outcomes carry specific
meaning, but a gap analysis (2026-05-27, five region reviews over the whole tree)
found **~250 sites where the applied outcome deviates from the intended model**, in
two opposite directions:

- **Findings hidden** — negative/security tests that do *not* `fail` when the module
  accepts a forbidden/invalid operation (they `xfail`, `note()`, or pass silently). ~46.
- **Provider-incompleteness over-penalized** — positive ops / x509 "MUST" checks that
  hard-`fail` on a clean error a lenient-but-conformant module may legitimately return. ~21+.
- **No `xfail` tier on negative tests** — ~113 negative tests use a binary
  `assert rv in {set}`, which both *passes* a wrong-but-listed code and *fails* a
  wrong-but-unlisted rejection (both should be `xfail`).
- **Neutralized negative vectors** — ~1000 Wycheproof MAC/AEAD/keywrap invalid vectors
  are exercised as *produce* operations and can never test rejection at all.

This design fixes the meaning of each outcome, states one principle that resolves all
the ambiguous cases, and lists the work.

## The model

Classify by **what the module did versus what is correct**. The pivot is *direction*:
the right thing done imperfectly is `xfail`; the wrong thing done (or a crash) is `fail`.

| Verdict | Positive op (valid input, advertised mechanism) | Negative op (must reject invalid input / policy) |
|---|---|---|
| **pass** | `CKR_OK` + correct output/value | rejects with the **expected** spec CKR |
| **xfail** | clean error — advertised but not operational | rejects with **some other** (clean) code |
| **fail** | `CKR_OK` but **wrong** output/value | `CKR_OK`/success **and** it is a crypto-correctness break or a self-contradiction (see rules) |
| **fail** | crash / hang | crash / hang |
| **skip** | capability genuinely absent | capability genuinely absent |

### Core principle

> **Self-contradiction = `fail`. A single honest deviation = `xfail`. Verify the *effect*, not the return code.**

A module that contradicts *itself* — claims a protection then violates it, reports a
success then doesn't honor it, returns two attribute values that cannot both be true —
is unambiguously broken for any provider, so it `fail`s. A module that simply doesn't
implement an optional protection, returns a non-spec rejection code, or reports one
wrong-but-isolated metadata value is making an honest, provider-dependent choice, so it
`xfail`s ("noted deviation — investigate later").

### Outcome definitions

- **`pass`** — the module did the correct, spec-expected thing.
- **`xfail`** — a deviation that is acceptable for *some* conformant provider class:
  a not-operational clean error on a positive op, a non-spec rejection code on a negative
  op, an unenforced optional protection, or an isolated wrong metadata value. `xfail` is
  the **provider-general "flag and investigate later"** bucket — it is recorded, not
  hidden, and it is **never gated on provider identity** (see Non-goals).
- **`fail`** — broken for any provider: a crash/hang, a wrong cryptographic result, or a
  self-contradiction.
- **`skip`** — the capability is genuinely absent (mechanism not advertised, interface
  version too old, optional test data missing). Skips are **only** for missing capability,
  never to hide broken behavior.

## Classification rules by test type

The negative/security cases divide into four kinds. A and B were the original split;
C and D are the *same* self-contradiction principle applied to lifecycle and metadata.

> **Historical note (retired aliases):** the A/B/C/D letters below are kept only as a
> record of the original taxonomy. The canonical machine field is `kind`, whose values are
> the keywords `crypto` (A), `policy` (B), `lifecycle` (C), and `metadata` (D). Code,
> comments, and messages use those keywords — do not introduce the letters in new text.

### Type A — cryptographic correctness → `fail`

The module accepts something that yields a wrong or forgeable cryptographic result.
No claim-check needed; this is broken for any provider.

- Examples: a malformed/invalid-`result` Wycheproof signature **verifies as valid**;
  an invalid-curve / low-order ECDH point **derives a secret**; a wrong-length or
  malformed ciphertext **decrypts**; a known-answer roundtrip returns the **wrong** value.
- Verdict: **`fail`** on acceptance / wrong value.

### Type B — attribute / permission enforcement → self-contradiction

The module is asked to enforce an attribute or permission boundary.

- Examples: reading a `CKA_SENSITIVE=True` key's value; `CKA_EXTRACTABLE` False→True via
  `C_CopyObject`; `CKA_WRAP_WITH_TRUSTED`; `CKA_ENCRYPT/DECRYPT/SIGN=False`.
- Rule:
  1. **Claim-check** — read the protective attribute back (e.g. create with
     `CKA_SENSITIVE=True`, then `read_attributes(…, [CKA_SENSITIVE])`).
     - If the module **did not** honor it (reads `False`/absent, or rejected it at create)
       → it does not claim the protection → **`xfail`** (honest non-support, e.g. NSS softoken).
  2. **Enforcement-check** (only if claimed) — attempt the violation.
     - Violation **succeeds** (value readable / escalation reflected) → **`fail`** (claimed then violated).
     - Violation **rejected** with the expected code → **`pass`**; with another code → **`xfail`**.

### Type C — lifecycle / state → effect-check

The "claim" is the module's own success report on the prior call.

- **use-after-destroy**: `C_DestroyObject(h)` returns `CKR_OK` (claims destroyed) **and** a
  subsequent op on `h` succeeds → contradiction → **`fail`**.
- **read-only attribute write**: `C_SetAttributeValue` on a read-only attribute returns
  `CKR_OK` **and** a read-back shows the value **actually changed** → **`fail`**; returns
  `CKR_OK` but the value is **unchanged** (no-op) → wrong code, no harm → **`xfail`**;
  rejected with the expected code → **`pass`**.

### Type D — metadata → derived-attribute contradiction vs isolated value

- **Derived-attribute contradiction** (two linked attributes that cannot both be true):
  `CKA_NEVER_EXTRACTABLE=False` while `CKA_EXTRACTABLE` was always `False`;
  `CKA_ALWAYS_SENSITIVE` vs `CKA_SENSITIVE` history → **`fail`**.
- **Isolated wrong value** (no contradiction): `CKA_LOCAL=False` on a token-generated key,
  a non-spec `CKA_PRIVATE` default → wrong, but contradicts nothing → **`xfail`**.
- **New tests to add:** explicit derived-attribute invariant checks
  (`NEVER_EXTRACTABLE`↔`EXTRACTABLE`, `ALWAYS_SENSITIVE`↔`SENSITIVE`) — these don't exist
  yet and are the `fail`-on-contradiction half of Type D.

## Mechanism / helpers

The positive side already has `xfail_if_known_ckr(exc, known_ckrs, msg)` and
`is_known_error(exc, rvs)` in `testcases/conftest.py`. We add the **negative-side mirror**
and standardize the claim/effect pattern.

```python
def classify_rejection(rv, expected_rvs, *, label):
    """Negative-op 3-way classifier (provider-general).
       expected code -> pass ; other reject code -> xfail ; CKR_OK -> fail."""
    if rv == CKR_OK:
        pytest.fail(f"{label}: accepted invalid (CKR_OK) -- must reject")
    if rv in expected_rvs:
        return                                   # spec-correct rejection
    pytest.xfail(f"{label}: rejected with {ckr_name(rv)}, expected {names(expected_rvs)}")
```

- **Type A** uses `classify_rejection` / unconditional `pytest.fail` on accepted-invalid;
  no claim-check.
- **Type B** uses a **claim-check** (`read_attributes` of the protective attr) to choose
  between the `fail` (claimed→violated) and `xfail` (not claimed) branches.
- **Type C** uses an **effect-check** (read state back after the operation) rather than
  trusting the return code.
- **`ckr/` `assert_ckr()`** (the single validation point used by ~50 negative call sites)
  and the ~27 standalone `assert rv in {set}` checks must grow the middle `xfail` tier —
  today they only do pass/fail (the N2 gap).

## Non-goals

- **No per-provider configuration, baselines, allowlists, or "known-vulnerable" demotions.**
  The suite stays provider-general. `xfail` is the universal "noted deviation" bucket; we
  do not encode "module X is allowed to do Y."
- **No change to crash-survival / subprocess isolation**, which the gap analysis confirmed
  is already correct (signal-killed children `fail`, expected-crash tests run in subprocess).
- **No reduction of test-vector counts** to work around module limitations.

## Scope of changes (work list from the 2026-05-27 gap analysis)

Counts are approximate; representative sites listed. "Full inventory" = the five region
reports from this session.

### N1 — negative test does not `fail` on acceptance (~46) → apply A/B/C/D
- **Type A `fail`:** invalid-EC-curve OID accepted `security/test_cve_regression.py:681`;
  off-curve/infinity ECDH point `security/test_parameter_validation.py:522`; RSA `e=0`
  `:475`; wrong-length RSA ciphertext accepted `ckr/test_ckr_decrypt.py:169`; wrong-length
  RSA signature verified `ckr/test_ckr_verify.py:144`; AES key + RSA mechanism accepted
  `ckr/test_ckr_{verify:60,sign:53}`; wrong-mechanism verify `CKR_OK` `test_errors.py:289`.
- **Type B self-contradiction:** sensitive value read `test_sensitivity.py:64,117`
  (+ dups `ckr/test_ckr_object.py:122`, `ckr/test_ckr_codes.py:127`,
  `ckr/test_ckr_spec_compliance.py:197`); `EXTRACTABLE` escalation
  `security/test_api_security.py:363`, `security/test_tookan.py:203`; wrap+decrypt
  extraction `security/test_api_security.py:241`, `security/test_tookan.py:268`;
  `CKA_ENCRYPT/DECRYPT=False` `ckr/test_ckr_raw_attrs.py:119,200`; `WRAP_WITH_TRUSTED`
  `test_access_levels.py:962`; `CKA_COPYABLE` escalation `test_attribute_enforcement.py:110`.
  *Note: `test_sensitivity` is wired inverted today — it `xfail`s the violation and
  hard-`fail`s honest non-support; both branches flip.*
- **Type C effect-check:** use-after-destroy `ckr/test_ckr_{object:143,198,255, decrypt:240,
  verify:82, sign:92, codes:193, priority:48}`; read-only `SetAttribute`
  `test_set_attribute.py:109,128,146,161`, `ckr/test_ckr_object.py:167`.
- **Type D:** keep isolated wrong values `xfail`; add derived-attr invariant tests (below).

### N2 — binary negative asserts lacking the `xfail` tier (~113) → 3-way
- `ckr/` `assert_ckr()` DEFAULT-compat path (~50 sites) + ~27 standalone `assert rv in {set}`
  (`ckr/test_ckr_{object,wrap,session,state,raw_args_bad,codes,universal,v30,v32,…}`) +
  `_check_ckr()` ×9 in `ckr/test_ckr_spec_compliance.py:64`.
- Policy suite (~21): `test_key_usage_policy.py:84,111,202,241`;
  `test_ro_session_restrictions.py:259,287,443,675,698,728`;
  `test_session_state_machine.py:417,446,889,940`; `test_so_pin.py:95,109`;
  `test_access_levels.py:508,978,1401`.
- `test_initialize_args.py:293,331`; `test_stateful_sigs.py:603`.
- Action: route through `classify_rejection` so a non-expected reject code → `xfail`.

### P1a — positive / "MUST" hard-`fail` on clean provider-incompleteness (~21) → `xfail`
- x509: absent mandatory attr `x509/test_attribute_parity.py:67-68`; "v3.0+ MUST accept
  CKA_X" `x509/test_core_ops.py:427`; rejected a Limbo-valid cert `x509/test_attributes.py:87`,
  `x509/test_limbo_import.py:155`; sign with valid imported key `x509/test_identity.py:105`;
  search-by-derived-attr empty `x509/test_search.py:104`.
- Profiles: `test_profiles.py:243,295,345,350`.
- v3.0 login robustness: `test_v30_session.py` `C_LoginUser` clean-error sites (~11).

### P1b — positive crypto roundtrip 2nd-leg unguarded (>50) → `xfail` on clean error
- Symmetric helpers `_*_or_xfail` that only `xfail` on `MECHANISM_INVALID`
  (`test_{camellia,aria,des,twofish,blowfish,salsa20,gost}.py`); unguarded decrypt/verify/
  unwrap legs in `test_rsa_extended.py:186,443,592`, `test_metamorphic.py:76`,
  `test_eddsa.py:177`, `test_mech_kem.py:82`, `test_mech_sign_recover.py:71`.
- *Deferred refinement:* a roundtrip where the first leg succeeds and the second returns a
  clean error is arguably a self-contradiction (`fail`); start with the base rule (clean
  error → `xfail`) and revisit if it proves too lenient.

### P2 — wrong metadata values currently `xfail` (~12) → keep `xfail` (Type D isolated)
- `test_attribute_defaults.py:104,150,202,268`; `test_key_flags.py:148,159,190,220,258,298`;
  `test_access_control.py:108`. **Exception:** `NEVER_EXTRACTABLE` invariant
  (`test_key_flags.py:159,190`) is a Type-D *contradiction* → `fail`.
- Genuine wrong-result leaks → `fail`: `test_crossverify_extended.py:169` (GCM mismatch
  swallowed by skip), `test_ecdh_extended.py:440` (failed self-roundtrip xfailed).

### V1 — invalid vector accepted, not failed (3 live) → unconditional `fail`-on-accept
- `wycheproof/test_wycheproof_ecdh.py:273` (gated on empty expected-shared; 107 vectors,
  incl. 6 secp256r1 that run on any P-256 module); `acvp/aes/test_gcm.py:172`
  (GCM-SIV decrypt, no `else: fail`, 13 invalid-tag vectors);
  `wycheproof/test_wycheproof_x25519.py:260` (gated on byte length; latent).

### V2 — Wycheproof negative vectors neutralized (~6 families, ~1000 vectors)
- AES-CMAC `:139`, GMAC `:428`, CCM `:363`, AES-KW `:218` (`test_wycheproof_aes.py`),
  ChaCha20-Poly1305 `test_wycheproof_chacha.py:115`, PBES2 `test_wycheproof_pbes2.py:223`.
- Root cause: invalid vectors are run as *produce* ops (MAC/encrypt/wrap), so a fresh
  correct output never matches the modified expected output and the accept-check can never
  fire. Fix: exercise the **verify/decrypt/unwrap** direction and `fail` on accept (the
  ACVP side already does this).

### P3 / C1 / C2 — localized (~24)
- `test_message_crypto.py:211,212,231,235,292,337` — ungated `except AssertionError:
  pytest.skip` on advertised v3.0 message ops → `xfail` with a CKR list.
- `security/test_cve_regression.py:789` — `except Exception` + "ERROR:" passes → `fail`.
- `ckr/test_ckr_wrap.py:84` (skip masks a finding → `fail`), `ckr/test_ckr_session.py:67`
  (skip for non-capability → `xfail`), `test_object_visibility.py:487` /
  `test_profiles.py:64` (substring CKR match → exact).

### New tests to add
- **Type D derived-attribute invariants:** `CKA_NEVER_EXTRACTABLE` vs `CKA_EXTRACTABLE`
  history; `CKA_ALWAYS_SENSITIVE` vs `CKA_SENSITIVE`; `fail` on internal contradiction.

## Documentation

- Add the decision table + core principle to `CLAUDE.md` (Coding Rules) so the policy is
  stated once and authoritatively, distinguishing **clean known CKR (`xfail`)** from
  **crash/wrong-result/self-contradiction (`fail`)** from **missing capability (`skip`)**.

## Suggested phases (each its own plan/PR)

1. **Helpers + docs** — `classify_rejection`, claim-check/effect-check helpers, the
   `assert_ckr()` `xfail` tier, decision table in `CLAUDE.md`. (Enables everything else.)
2. **V1 + V2** — invalid-vector correctness (highest crypto value; 3 live + ~1000 neutralized).
3. **N1 (A/B/C)** — the security-finding reclassification (claim/effect-checks).
4. **N2 sweep** — binary negative asserts → 3-way.
5. **P1a + P1b** — provider-incompleteness `fail`→`xfail`.
6. **P2/P3/C cleanups + Type-D new tests.**

## Open / deferred

- P1b roundtrip-inconsistency-as-self-contradiction (defer; start with base rule).
- Whether `assert_ckr()`'s DEFAULT vs strict compat modes survive the 3-way change or are
  superseded by `classify_rejection` (decide in Phase 1).

## Refinements: advertised-capability honesty (2026-06-10)

Spec basis (OASIS PKCS#11 v3.2): `C_GetMechanismList` lists mechanisms "supported by a token";
`CK_MECHANISM_INFO.flags` claims per-operation support ("True if the mechanism can be used with
C_SignInit"); `CKR_OPERATION_NOT_VALIDATED` is the sanctioned validation-policy refusal.

1. **Claim layer (test_mech_*):** the registry roundtrip is the canonical operation for the
   advertised capability. Clean refusal with CKR_OPERATION_NOT_VALIDATED → pass + note
   (conformant policy refusal — does not contradict the advertisement). Any other clean CKR →
   xfail via the shared `not_operational_reason` wording (no CKR allowlist; positive-op row).
   Wrong output / crash / non-CKR unchanged (fail / propagate).
2. **Vacuous negative-op reject:** with a canonical probe verdict of NOT_OPERATIONAL, an
   invalid-input "rejection" asserts nothing (the module refuses everything) → xfail
   "vacuous reject", not pass. OPERATIONAL, INCONCLUSIVE, and WRONG_OUTPUT verdicts leave
   the pass untouched: OPERATIONAL rejections are genuine passes; INCONCLUSIVE (staging
   failure, no mechanism evidence) keeps legacy rules; WRONG_OUTPUT surfaces as a finding.

Both refinements are provider-general: discrimination is by return code, probe effect, and
CKO_VALIDATION capability only.

## Refinement (2026-06-14): at-source emission + reason vocabulary

This does not rewrite the model above — it makes the verdict machine-recorded. Tests emit a
structured `Classification` at the decision point via `pkcs11_check.classification.classify()`
(and `fail_as`/`xfail_as`/`assert_correct`), which records the verdict then raises the implied
pytest outcome. See the design spec
[superpowers/specs/2026-06-13-at-source-classification-design.md](superpowers/specs/2026-06-13-at-source-classification-design.md).

- The A/B/C/D self-contradiction classes are now the canonical machine field **`kind`**:
  `crypto`=A, `policy`=B, `lifecycle`=C, `metadata`=D.
- The runtime **reason** vocabulary is the 10 reasons: `wrong_result`, `accepted_invalid`,
  `self_contradiction`, `oracle`, `crash` (→ fail); `not_operational`, `nonspec_reject`,
  `honest_deviation`, `undeclared_capability` (→ xfail); `sanctioned_refusal` (→ pass).
  (`unclassified` is a reserved runtime-gate marker, never emitted by a test.)
  - `undeclared_capability` (xfail, kind=metadata) — the module **performed** an operation /
    key size / mechanism it did **not** advertise, in a benign direction (stronger-than-advertised
    key size, or an unadvertised mechanism that is not in the known-weak set). The advertised
    boundary is inaccurate metadata, but no weak crypto was accepted, so this is a recorded
    deviation, not a `fail`. The security-relevant direction (below-min/weak, or a known-weak
    unadvertised mechanism) is `self_contradiction` → `fail`. This is the over-advertised mirror
    of `not_operational`.
- **Severity** is derived centrally from `(reason, kind)` in `classification.derive_verdict` —
  the single source of truth, replacing per-site severity choices.
