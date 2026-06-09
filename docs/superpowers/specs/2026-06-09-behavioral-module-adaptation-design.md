# Behavioral module adaptation — design (v2, hardened)

**Status:** design (2026-06-09, v2 after 4-perspective adversarial gap analysis)

**Goal:** Remove all provider-identity knowledge from pkcs11-check core. Replace the
per-module CKR-quirk registry with two runtime mechanisms that adapt to what the live
module actually does — never to *which* module it is — without ever hiding a real error
behind a "known-issue" decision.

**Core value:** *Show real errors. Never convert a deviation into a green pass via a
per-module/known-code decision.* No calibration, no CKR-acceptance config (both
automate "accept whatever code the module returned").

> **v2 note.** The naive v1 design hid real errors in four ways the adversarial review
> caught. v2 bakes the mitigations in as hard requirements. Where v1 and v2 disagree, v2
> wins. The four reviewers' reports are the rationale of record.

---

## 1. Gap analysis (corrected)

**Identity surface — the v1 "one place / ~7 sites" claim was wrong.** Actual:

*Functional consumers (break on deletion — same-commit migration):*
1. `conftest.py:177,190` — `unwrap_key_for_mechanism_roundtrip` (`unwrap_template_class_keytype_rejected`). **Positive op → Pillar 1.** Also emits a VENDOR `note` naming OpenCryptoki (181-203).
2. `test_authenticated_wrap.py:82,89` — `_aead_integrity_reject_rvs()` helper (`verify_or_integrity_failure`); used by 3 GCM tamper tests (≈325, 477, 690). **Discrimination → Pillar 2.**
3. `test_authenticated_wrap.py:522,587,588` — `test_aes_key_wrap_bit_flip_detected` (both quirks). **Pillar 2.**
4. `test_authenticated_wrap.py:932,938,939` — `test_ecdh_aes_kw_bit_flip_integrity` (both quirks, inline). **Pillar 2. (v1 map omitted this.)**
5. `security/test_tookan.py:414,416-419` — `test_unwrap_aes_as_des3_rejected` (string-match splice). **Pillar 2.**
6. `ckr/test_ckr_wrap.py:47,362` — `test_wrapping_key_size_range` (`size_range_on_wrap`, gated on `ckr_strict`). **Code-conformance → keep 3-way (NOT discrimination).**

*Adjacent hard-coded identity (v1 missed):*
7. `test_authenticated_wrap.py:827` — `pytest.skip("…OC's CKA_CLASS/CKA_KEY_TYPE quirk")` inlines the OpenCryptoki quirk as a skip. **Convert to negotiation.**
8. `wycheproof/test_wycheproof_aes.py:92-130` — the shipped `_unwrap_aes_kw_adaptive`. Its shape-reject set `{TEMPLATE_INCOMPLETE, TEMPLATE_INCONSISTENT, ATTRIBUTE_VALUE_INVALID, ATTRIBUTE_TYPE_INVALID}` **diverges** from v1's proposed set (which had `ATTRIBUTE_READ_ONLY` but not `TYPE_INVALID`). Unify (below).
9. `test_threading.py:63` — `if "softhsm" not in module.lower()` selects a token-provisioning primitive. **Legitimately general (keep)** but must be on the guard meta-test allowlist.

*Meta-tests (v1 named 1; there are 3):*
- `tests/test_module_quirks.py` — registry meta-test. **Delete with the registry.**
- `tests/test_setup_runtime_capability_guards.py:1817` `test_ckr_wrap_size_range_uses_documented_softhsm2_quirk` — **a finding-hiding meta-test that locks the masking** (asserts softhsm2 `GENERAL_ERROR` → pass). **Rewrite** to assert the new xfail behavior.
- `tests/test_aes_key_wrap_bit_flip_classification.py` — comment references quirks but only exercises `reject_or_classify`; its `GENERAL_ERROR → xfail` assertion **validates** post-migration behavior. **Keep; update comment.**

*Clean layers (good news):* `src/pkcs11_check/raw/` has **no** identity branches (confirmed). `CKA_PUBLIC_EXPONENT` always-included, two-pass buffer retries, op-active recovery are general. `compliance.note(VENDOR)` sites describe observed behavior generally (except #1, part of migration). ~35 `str(p11_config.module)` reads are subprocess-load plumbing — out of scope.

**Two classes of disagreement:** *opposite requirements* (module's clean reject says the request shape is wrong; a spec-equivalent request works → negotiate, no identity) vs *opposite responses* (module returns a wrong-but-clean CKR → for integrity tests, judge the effect; for spec-mandated-code tests, record the wrong code as xfail).

---

## 2. Pillar 1 — Request negotiation (input side), hardened

Helper (`testcases/_negotiation.py`):

```python
def negotiate_request(attempt, variants, *, label) -> tuple[Any, int]:
    # variants[0] MUST be the most spec-conformant request; later variants are
    # EQUALLY-conformant alternatives, never relaxations. Returns (result, idx).
```

**Hard invariants (each enforced by a meta-test):**

- **G1 Canonical-first.** `variants[0]` is the most spec-conformant template. For unwrap it
  **MUST contain `CKA_KEY_TYPE`** (PKCS#11 base v3.0 Table 23 footnote 5: KEY_TYPE is
  mandatory on `C_UnwrapKey`). Only **`CKA_CLASS`** (footnote 1, derivable) may be dropped
  in a later variant. **Never drop `CKA_KEY_TYPE`.** (Fixes `conftest.py:193-195`, which
  currently drops both.) If the canonical variant succeeds, no retry happens and a module
  that *needed* the relaxation is recorded deviant (xfail) — the conformance signal is kept.
- **G2 Shape-reject trigger set** (the only codes that justify a retry):
  `{CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT, CKR_ATTRIBUTE_READ_ONLY,
  CKR_ATTRIBUTE_TYPE_INVALID}`. **`CKR_ATTRIBUTE_VALUE_INVALID` is excluded** — it
  double-books as a legitimate forgery/policy reject (M2). Any **non-shape** reject
  (integrity, length-range, anything else) **propagates immediately** — negotiation never
  swallows a crypto/forgery reject. This set is the single source of truth; the shipped
  `_unwrap_aes_kw_adaptive` is refactored onto it (drops `ATTRIBUTE_VALUE_INVALID`, adds
  `ATTRIBUTE_READ_ONLY`).
- **G3 `CKA_VALUE_LEN` variant is allowlisted, not generic.** It may appear in a variant
  **only** when ALL hold: (a) target `CKA_KEY_TYPE` is in `VALUE_LEN_ON_UNWRAP_OK`
  (footnote-6 does **not** apply — today `{CKK_GENERIC_SECRET}`; **forbidden for `CKK_AES`**),
  (b) the mechanism's recovered length is **determined** (e.g. `CKM_AES_KEY_WRAP`/`_KWP`),
  and (c) the supplied length **equals** that determined length. **Excluded by construction:**
  every length-bearing `C_DeriveKey` mech (`CKM_ECDH1_DERIVE`/`_COFACTOR` — leading-end
  truncation; `CKM_HKDF_DERIVE` Expand; PBKDF2) and every `*_PAD` unwrap mech
  (`CKM_AES_CBC_PAD`, `CKM_AES_KEY_WRAP_PAD`). A meta-test fails if a `CKA_VALUE_LEN`
  variant is generated for an excluded mechanism. (Spec: v3.2 §5.18.4; base Table 11 fn 2/3/6.)
- **G4 Mandatory result verification (positive ops only).** Negotiation runs only with valid
  inputs. After success, the caller **must** confirm the produced key material (read back
  `CKA_VALUE` and byte-compare to expected). If the material is unreadable
  (sensitive/non-extractable), the verdict is **xfail "result unverifiable," never pass**.
  No `if recovered is not None:` silent-skip (the shipped AES-KW test's existing skip is a
  bug to fix). For length-bearing ops the byte-equality check is what catches a silently
  wrong-length derive — so G3's exclusions + G4's read-back are both required.
- **G5 Single-shot recipe ops only.** `negotiate_request` targets atomic `C_UnwrapKey`
  (no operation-active state between variants). It is **not** used for multi-part ops
  (sign/verify Init+Update+Final) until a future revision adds `_cancel_operation` between
  variants. Documented in the contract.
- **G6 Never invoked from a negative/forgery test.** A meta-test asserts the call sites are
  an allowlist of positive helpers.

---

## 3. Pillar 2 — Outcome discrimination (output side), hardened

Helper (`conftest.py`, sibling of `classify_policy_enforcement`/`classify_lifecycle_effect`):

```python
def classify_discrimination(*, valid_accepted, invalid_outcome, label):
    # valid_accepted: bool computed from a VERIFIED positive op (G4-style).
    # invalid_outcome: the invalid leg's result -- a caught exception, OR the
    #   produced object handle (acceptance). NOT a pre-computed bool.
    #   - handle/None produced (CKR_OK)            -> accepted -> security break -> fail
    #   - exception with a clean .rv (is_known_error against CK_RV space) -> rejected
    #   - exception WITHOUT .rv (harness AssertionError / ctypes bug)     -> re-raise
    # verdicts:
    #   not valid_accepted                 -> fail (positive leg broke; undecidable)
    #   valid_accepted & not rejected      -> fail (accepted the tampered input)
    #   valid_accepted & rejected          -> pass (discriminated; code irrelevant)
```

**Hard requirements:**

- **D1 Applies only to integrity/authenticity/type-confusion tests** where the spec mandates
  **no specific** failure code (confirmed: PKCS#11 v3.1 §5.18.4 lists `DEVICE_ERROR`/
  `GENERAL_ERROR`/`FUNCTION_FAILED` among permitted unwrap returns; integrity codes are
  "should"). The wrong code is therefore **not** a conformance violation → discrimination
  → pass is correct. Record the code deviation via `compliance.note` (visible, not a verdict).
- **D2 `invalid_outcome` typing (M5).** The classifier inspects the *exception's `.rv`* via
  `is_known_error`, exactly like `reject_or_classify` (conftest.py:464). A bare
  `except AssertionError: rejected=True` is forbidden — a harness/ctypes `AssertionError`
  (no `.rv`) must re-raise, not count as detection.
- **D3 Acceptance is the break — code-agnostic, material-agnostic.** For AES-KW/GCM/type
  confusion, **any produced handle on the tampered/forged/type-confused input is `fail`**,
  regardless of recovered bytes or readability. (RFC 3394 / AEAD MUST reject; a returned key
  is the violation.) So the sensitive-key edge never bites the invalid leg.
- **D4 Real valid leg, required, negotiation-backed (C1).** Each migrated site must perform
  the **un-tampered** operation and verify it (`valid_accepted` from a real op + material
  compare). Where the valid-leg unwrap uses `CKA_CLASS`/`CKA_KEY_TYPE` (AES-KW, type
  confusion), it **must** go through `negotiate_request` so a strict module (opencryptoki)
  isn't false-failed. **Therefore Pillar 1 lands before Pillar 2.**
- **D5 `valid_accepted=False` ≠ "not operational."** An advertised-but-not-operational
  positive leg stays **xfail** (via the existing `xfail_if_known_ckr`/`_xfail_if_*_runtime_reject`
  guards), routed *before* `classify_discrimination`. A `False` reaching the classifier means
  "CKR_OK but wrong/unverifiable output" — a genuine fail.

---

## 4. Code-conformance carve-out (M4 / Finding 3 / Site 5)

Negative tests where the spec **mandates a specific code** keep the 3-way classifier
(`classify_negative_rv` / `assert_ckr` over `CkrExpectation`): expected code → pass, other
clean code → **xfail** (recorded deviation), `CKR_OK`/crash → fail. These do **not** become
discrimination.

- **`ckr/test_ckr_wrap.py` undersized wrap stays 3-way.** Spec mandates
  `CKR_WRAPPING_KEY_SIZE_RANGE` (C_WrapKey-only, v3.1). Replace the
  `*quirk_extras("size_range_on_wrap")` splice with `assert_ckr(...)`/`classify_negative_rv`
  using the size-range set; softhsm2's `CKR_GENERAL_ERROR` → **xfail** (honest; the project
  doc explicitly refuses to mask this catch-all). Preserve the `--ckr-strict` semantics.
- Length-based invalidity (`CKR_WRAPPED_KEY_LEN_RANGE`, v3.2 SHALL) likewise keeps 3-way.

---

## 5. Delete identity + lock it

- Delete `src/pkcs11_check/testcases/_module_quirks.py` and `tests/test_module_quirks.py`
  in the **same commit** as all 6 functional consumers (else collection errors).
- Rewrite `tests/test_setup_runtime_capability_guards.py:1817` to assert
  `GENERAL_ERROR → xfail`.
- **Grep-zero gate (meta-test):** `grep -rn "_module_quirks|quirk_extras|detect_module|ModuleId|MODULE_QUIRKS"` over `src/` and `tests/` returns **zero**.
- **Guard meta-test** fails on reintroduced masking shapes: (a) the deleted symbols; (b) a
  provider-name string literal *combined with a branch* on `p11_config.module`
  (allowlist: `test_threading.py` token-provisioner, subprocess-path reads); (c)
  `classify_discrimination(` with a **literal** `True`/`False` leg; (d) the
  `if recovered is not None:` material-skip idiom in wrap/unwrap tests.

---

## 6. Files

- **New:** `testcases/_negotiation.py` (`negotiate_request`, `TEMPLATE_SHAPE_REJECTS` (G2),
  `VALUE_LEN_ON_UNWRAP_OK`, the excluded-mechanism allowlist).
- **New helper in `conftest.py`:** `classify_discrimination` (D-series).
- **Modify:** `conftest.py` (`unwrap_key_for_mechanism_roundtrip` → negotiation, KEY_TYPE
  retained), `wycheproof/test_wycheproof_aes.py` (refactor onto `negotiate_request`; fix the
  material-skip), `test_authenticated_wrap.py` (sites 2,3,4,7 + delete `_aead_integrity_reject_rvs`),
  `security/test_tookan.py` (site 5), `ckr/test_ckr_wrap.py` (3-way).
- **Delete:** `_module_quirks.py`, `tests/test_module_quirks.py`.
- **Rewrite:** `tests/test_setup_runtime_capability_guards.py:1817`.

## 7. Testing

- **Meta (no module):** `negotiate_request` (G1 canonical-first incl. KEY_TYPE present; G2
  retries only on shape rejects, never non-shape; G3 no VALUE_LEN variant for excluded mechs;
  G6 not from negative tests); `classify_discrimination` (D2 exc-typing: handle→fail,
  clean-rv→by-valid-leg, no-rv→re-raise; D3 acceptance→fail; D4/D5 valid-leg matrix); the
  grep-zero + guard meta-tests.
- **Module (docker, current code):** opencryptoki (negotiation: unwrap roundtrip + type-confusion
  valid leg pass; **the C1 false-fail regression test**), kryoptic (AEAD/AES-KW forgery →
  pass via discrimination; undersized-wrap unaffected), softhsm2 (undersized wrap → xfail;
  AES-KW no-regression), one PQC module unaffected.

## 8. Order of work (because D4 depends on Pillar 1)

1. `negotiate_request` + meta-tests. 2. Refactor AES-KW + `unwrap_key_for_mechanism_roundtrip`
onto it (KEY_TYPE retained; fix material-skip). 3. `classify_discrimination` + meta-tests.
4. Migrate sites 2,3,4,5,7 (valid legs via negotiation). 5. `test_ckr_wrap` 3-way. 6. Delete
registry + meta-test, rewrite the finding-hiding meta-test, add grep-zero + guard meta-tests.
7. Docker verification on opencryptoki/kryoptic/softhsm2.

## 9. Risks

- **Discrimination too lenient** → mitigated by D4 (operation-backed valid leg) + D3
  (acceptance=fail).
- **Negotiation masks a finding** → G2 (non-shape rejects propagate) + G3 (allowlist) + G4
  (verify result) + G6 (never from negative tests), all meta-tested.
- **Green-count movement** (some pass↔xfail): correct per project philosophy; no stats in
  docs except at release.
- **C1 false-fail of opencryptoki** → the single highest risk; the migration order (Pillar 1
  first) and a dedicated regression test address it.
