# Audit: classifier helpers + assert_ckr 3-way branch (2026-05-28)

> Observational only. No production code changes; fixes are a separate follow-up cycle.

**Scope:** `src/pkcs11_check/testcases/conftest.py`,
`src/pkcs11_check/testcases/ckr/conftest.py`,
`src/pkcs11_check/testcases/ckr/_ckr_spec.py` (with call-site sampling in
`ckr/test_ckr_verify.py`, `ckr/test_ckr_spec_compliance.py`,
`security/test_cve_regression.py`, `security/test_parameter_validation.py`).

**Method:** static read against `dev` HEAD. Cross-checked against `CLAUDE.md`
Test-outcome classification model and the Phase 1-6 design / plan docs.

**Headline:** 0 CRITICAL · 2 HIGH · 2 MEDIUM · 3 LOW. The classifier
infrastructure is sound — the four helpers and `assert_ckr` consistently
implement the pass/xfail/fail model, and `tests/test_classification_helpers.py`
covers the primary branches. The HIGH findings are an active violation of the
provider-neutral-message rule (4 sites with module names in `pytest.xfail()`
text), the MEDIUM findings are one strict-mode contract bug + one DX wording
gap, the LOW findings are forward-compatibility / DRY / latent-risk items.

---

## Classifier consistency

All four helpers (`classify_negative_rv:430`, `reject_or_classify:464`,
`classify_policy_enforcement:493`, `classify_lifecycle_effect:514` in
`conftest.py`) enforce the same model:

| Condition | `classify_negative_rv` | `reject_or_classify` | `classify_policy_enforcement` | `classify_lifecycle_effect` |
|---|---|---|---|---|
| accepted (CKR_OK / exc=None / claimed-and-violated) | `pytest.fail` | `pytest.fail` | `pytest.fail` | `pytest.fail` |
| spec-correct rejection / protection held | `return` | `return` | `return` | `return` |
| honest deviation / not claimed | `pytest.xfail` | `pytest.xfail` | `pytest.xfail` | `pytest.xfail` |

Signatures consistent (keyword-only `label`, compatible `expected_rvs` typing).
Messages always include the actual rv name and the expected set; no provider
identity in any of the four helpers' f-strings. The intentional asymmetry —
the two Type-B/C classifiers have no expected-set because their pivot is a
boolean claim — is correct by design.

---

## HIGH

### H-CLASS-1 — Provider names in `pytest.xfail()` messages  ·  HIGH  ·  RESOLVED 2026-05-29
> **RESOLVED 2026-05-29.** All provider-named xfail messages made provider-neutral;
> the upstream issue number kept in a code comment. A new AST regression test
> (`tests/test_provider_neutral_xfail.py`) scans every `pytest.xfail()` literal in
> `testcases/` and fails on any provider name, so this cannot silently regress.
> **The regression test found 4 sites the manual audit missed** — the PQC tampered-
> signature checks in `test_pqc_sign.py` (×2), `test_hash_ml_dsa.py`, and
> `test_hash_slh_dsa.py`, all naming Kryoptic. Those were routed through
> `xfail_if_known_ckr(..., _SIGN_ERROR_CKRS/_PQC_SIGN_REJECT_RVS, ...)` (which
> already includes `CKR_DEVICE_ERROR`), keeping the noted deviation an xfail while
> a genuine wrong-output break stays a hard fail.
- **Sites:**
  - `src/pkcs11_check/testcases/ckr/test_ckr_verify.py:115` —
    `pytest.xfail("Kryoptic bug: returns CKR_DEVICE_ERROR for verify failure")`
  - `src/pkcs11_check/testcases/ckr/test_ckr_verify.py:141` — same
  - `src/pkcs11_check/testcases/ckr/test_ckr_spec_compliance.py:251` — same
  - `src/pkcs11_check/testcases/security/test_cve_regression.py:263` —
    `pytest.xfail("Module rejects CKA_DERIVE on EC (tpm2-pkcs11 #656)")`
- **Evidence:** `CLAUDE.md` classification model: "`xfail` is the universal
  provider-general 'noted deviation, investigate later' bucket — it is never
  gated on provider identity." All four messages name a specific provider.
  The xfail reason appears in the pytest results output, exposing provider
  identity to consumers of the report.
- **Suggested fix:** drop the three Kryoptic pre-guards entirely (see
  H-CLASS-2 — the 3-way classifier already produces a neutral xfail). For the
  tpm2 site: replace with "Module rejects CKA_DERIVE on EC (clean non-spec
  rejection)" and move the upstream issue number to a code comment.
- **Confidence:** 95%.

### H-CLASS-2 — Pre-emptive `CKR_DEVICE_ERROR` guards duplicate classifier + embed provider names  ·  HIGH  ·  RESOLVED 2026-05-29
> **RESOLVED 2026-05-29.** The three Kryoptic `if rv == CKR_DEVICE_ERROR:
> pytest.xfail("Kryoptic …")` pre-guards in `ckr/test_ckr_verify.py` (×2) and
> `ckr/test_ckr_spec_compliance.py` were deleted; `CKR_DEVICE_ERROR` now flows to
> the provider-neutral xfail band via `_TOKEN_UNIVERSAL`/`assert_ckr` as designed.
> A meta-test (`test_classification_helpers.py::test_device_error_xfails_neutrally`)
> pins the classifier behavior so the guards are not reintroduced.
> Note: removing the pre-guards means **strict mode (`--ckr-strict`)** now correctly
> *fails* on `CKR_DEVICE_ERROR` for a verify mismatch (it is not the spec code); no
> live test depends on the old strict-mode pass, and strict mode is opt-in.
- **Sites:**
  - `ckr/test_ckr_verify.py:114-115` — `if rv == CKR_DEVICE_ERROR: pytest.xfail("Kryoptic bug: ...")`
  - `ckr/test_ckr_verify.py:140-141` — same shape
  - `ckr/test_ckr_spec_compliance.py:250-251` — same shape
- **Evidence:** `CKR_DEVICE_ERROR` is in `_TOKEN_UNIVERSAL` (`_ckr_spec.py:133`),
  which `full_compat()` injects into the full acceptable set for session-using
  functions. When `assert_ckr` / `_check_ckr` is called with `actual =
  CKR_DEVICE_ERROR` in compat mode: it passes the `actual not in full` gate,
  isn't in `spec_codes`, and fires `pytest.xfail(...)` with a neutral message.
  The pre-guards intercept this flow and replace the provider-neutral xfail
  with a provider-named one — the correct classifier branch is unreachable.
- **Suggested fix:** delete the three pre-guard blocks; add a one-line code
  comment "// CKR_DEVICE_ERROR is classified as xfail by assert_ckr via
  _TOKEN_UNIVERSAL" if intent needs preservation.
- **Confidence:** 92%.

---

## MEDIUM

### M-CLASS-3 — `assert_ckr` strict mode ignores `allow_success`  ·  MEDIUM
- **Site:** `src/pkcs11_check/testcases/ckr/_ckr_spec.py:233-239`.
- **Evidence:** strict-mode body is:
  ```python
  if strict:
      if actual not in spec_codes:
          pytest.fail(...)
  ```
  `spec_codes` contains only spec-mandated rejection CKR codes; `CKR_OK` is
  never in `spec_codes`. If a module returns `CKR_OK` for an
  `allow_success=True` entry (e.g. `CKR_VERIFY["init_key_function_not_permitted"]`
  at L1845) and the caller passes `actual = CKR_OK` directly with
  `strict=True`, the function `pytest.fail`s even though `allow_success=True`.
  The compat branch (L242-243) correctly handles this case. Currently no call
  site reaches it (callers pre-guard CKR_OK), so it's latent, but the
  interface contract is violated.
- **Suggested fix:** add `if actual == CKR_OK and expectation.allow_success:
  return` as the first check in the strict branch. Add a meta-test in
  `tests/test_classification_helpers.py` for the case.
- **Confidence:** 85%.

### M-CLASS-4 — `assert_ckr` fail message shows `compat_tuple` not full set  ·  MEDIUM
- **Site:** `_ckr_spec.py:249-254`.
- **Evidence:** the gate at L249 checks `actual not in full` (where `full =
  full_compat(compat_tuple)` injects the three universal tuples), but the
  failure message at L251-253 only lists `compat_tuple`. A developer debugging
  a CKR rejection sees a too-narrow "acceptable set" and can't tell that
  CKR_GENERAL_ERROR / CKR_HOST_MEMORY / etc. are also accepted via the
  universals. Developer-experience issue, not a logic bug.
- **Suggested fix:** append "(+ universal error codes: CKR_GENERAL_ERROR,
  CKR_FUNCTION_FAILED, ...)" to the message, or expand the printed list to the
  full set.
- **Confidence:** 80%.

---

## LOW

### L-CLASS-5 — `kind` field on `CkrExpectation` is sparsely populated and never consumed  ·  LOW
- **Site:** `_ckr_spec.py:181-183`.
- **Evidence:** `kind: str = "policy"` is defaulted on every entry and
  explicitly set to `"crypto"` on exactly 4 entries (L713, L1180, L1822,
  L1862). Grep across `src/pkcs11_check/` returns zero runtime reads of
  `.kind`. The field is not type-checked as `Literal[...]`, so invalid values
  would pass mypy.
- **Suggested fix:** change annotation to
  `Literal['crypto', 'policy', 'lifecycle', 'metadata']`; add a one-line
  docstring "forward-compatibility annotation; not currently consumed at
  runtime". Optionally back-fill obvious entries.
- **Confidence:** 90%.

### L-CLASS-6 — Missing positive-op "advertised but not operational" helper  ·  LOW
- **Sites:** `test_mech_encrypt.py:102-107`, `test_des.py:100-105`,
  `test_aria.py:82-87`, `test_twofish.py:73-78`, `test_blowfish.py:73-78`,
  `test_salsa20.py`, `test_camellia.py`, `test_mech_sign.py`, and ~45 other
  files.
- **Evidence:** the pattern
  ```python
  try:
      op(...)
  except AssertionError as exc:
      xfail_if_known_ckr(exc, SOME_RUNTIME_REJECT_RVS, "advertised but not operational")
  ```
  appears 50+ times. `conftest.py` provides `gen_aes_key_or_xfail`,
  `gen_rsa_keypair_or_xfail`, `gen_ec_keypair_or_xfail` for keygen but no
  equivalent for cipher/sign/verify/derive. Design doc (Phase 5 P1b)
  acknowledges this but defers the wrapper. DRY concern, not correctness.
- **Suggested fix:** add a `call_or_xfail(fn, *args, reject_rvs, label,
  **kwargs)` or contextmanager helper to `conftest.py`. The keygen wrappers
  serve as template.
- **Confidence:** 85%.

### L-CLASS-7 — `reject_or_classify` with plain non-PKCS#11 `AssertionError` routes to `xfail`  ·  LOW
- **Site:** `conftest.py:486-490`.
- **Evidence:** `reject_or_classify` calls `is_known_error(exc, expected_rvs)`.
  For a `CkrAssertionError`, this uses exact `.rv` comparison. For a plain
  `AssertionError` (no `.rv`), it falls back to substring matching on
  `str(exc)`. A coding bug in a recipe (failing internal `assert` with no CKR
  text) would: (1) pass `is_known_error` returning False, (2) enter the xfail
  branch with `name = str(exc)`, (3) produce a misleading xfail. Call sites
  in `test_parameter_validation.py:158` catch `AssertionError` without
  distinguishing. The meta-test suite tests `reject_or_classify` only with
  `CkrAssertionError`.
- **Suggested fix:** narrow call-site catches to `except CkrAssertionError`,
  or add a type guard in `reject_or_classify`: `if not hasattr(exc, "rv") and
  not isinstance(exc, CkrAssertionError): raise`. Add a meta-test.
- **Confidence:** 78%.

---

## `assert_ckr` 3-way branch — full case table

| Case | `actual` | `strict` | Expected | Actual | Correct? |
|---|---|---|---|---|---|
| (a) strict, spec code | in spec_codes | True | pass | falls through | Yes |
| (b) strict, non-spec code | not in spec_codes | True | fail | L234-239 fail | Yes |
| (c) strict, CKR_OK + allow_success | CKR_OK | True | pass | L234 FAILS | **No — M-CLASS-3** |
| (d) compat, CKR_OK + allow_success | CKR_OK | False | pass | L242-243 return | Yes |
| (e) compat, CKR_OK, no allow_success | CKR_OK | False | fail | L244-247 fail | Yes |
| (f) compat, in spec_codes | in spec_codes | False | pass | passes L249+L255 | Yes |
| (g) compat, in full not spec | in full \ spec_codes | False | xfail | L255-260 xfail | Yes |
| (h) compat, outside full | not in full | False | fail | L249-254 fail | Yes (see M-CLASS-4 on message) |

---

## Out of scope / noted not-issues

- **`allow_success=True` on ~30 table entries** — models spec permissiveness,
  not per-provider config. Provider names in source-code comments are
  rationale documentation, not test output.
- **`_check_ckr()` in `test_ckr_spec_compliance.py`** — thin wrapper around
  `classify_negative_rv`; compatible with the 3-way model.
- **`skip_if_mech_param_unsupported` using `pytest.skip`** — IV/nonce
  parameter conventions are optional capability, not broken behavior.
- **`TestSoftHSM2Issue596`, `TestSoftHSM2Issue722` class names** in
  `test_cve_regression.py` — CVE regression identifiers per `CLAUDE.md` rule.
- **Provider names in `_ckr_spec.py` source comments** (L1845, L2989, L4331) —
  rationale documentation; not in output.
- **`assert_ckr` not exposed via `ckr/conftest.py`** — imported directly from
  `_ckr_spec.py` per file; no fixture needed. Intentional.
- **`classify_negative_rv(allow_ok=True)` single call site** — at
  `test_ckr_raw_state.py:53`; legitimate (second `C_*Init` while one active
  may return CKR_OK on auto-cancel). Justified in docstring.

---

## Suggested follow-up

**Immediate (small, high-value):**
1. **H-CLASS-1 + H-CLASS-2** — delete the 3 Kryoptic pre-guards in `test_ckr_verify.py`
   + `test_ckr_spec_compliance.py`; reword the tpm2 message in
   `test_cve_regression.py:263`. The 3-way classifier already does the right
   thing for `CKR_DEVICE_ERROR` (xfail via `_TOKEN_UNIVERSAL`).

**Latent (small, contract correctness):**
2. **M-CLASS-3** — one-line fix in strict branch of `assert_ckr`; add a
   meta-test for the case.

**DX / hygiene (not urgent):**
3. **M-CLASS-4** — expand the failure message in `assert_ckr` compat branch.
4. **L-CLASS-5** — type-annotate `kind` as `Literal[...]`; document it.
5. **L-CLASS-6** — `call_or_xfail` wrapper to DRY 50+ call sites.
6. **L-CLASS-7** — narrow `AssertionError` catches at recipe call sites; add
   meta-test for plain-`AssertionError` path.

Nothing here is urgent. All findings are addressable in small, independent
patches with TDD meta-tests.
