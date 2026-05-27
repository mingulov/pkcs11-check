# PKCS#11 Test-Outcome Classification — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use `- [ ]` checkboxes. Execute phases in order **except Phase 2, which is Phase-1-independent and may land first.**

**Goal:** Make every test case classify `pass`/`xfail`/`fail`/`skip` by one provider-general rule, so real findings stop hiding as `xfail`/`note` and provider-incompleteness stops hard-failing.

**Architecture:** **Table-centric.** Extend the existing `testcases/ckr/_ckr_spec.py` (`CkrExpectation` + the single `assert_ckr()`, already consuming 51 sites) into the one place the fail-vs-xfail *direction* lives, plus two small negative helpers in `conftest.py` built on the existing `is_known_error`/`xfail_if_known_ckr`. Tests *declare intent*; the classifier *decides outcome*. Validated offline by mock-`raw` meta-tests (`tests/*_runtime_classification.py`).

**Tech Stack:** Python 3.13, pytest, pure-ctypes `pkcs11_check.raw`, `uv run`.

**Companion spec:** `docs/classification-model-design.md` (the model + A/B/C/D rules). This plan supersedes that spec's *mechanism* section per the 2026-05-27 audits.

---

## The model (one rule)

- **Positive op:** `CKR_OK`+correct → pass; clean not-operational error → `xfail`; `CKR_OK`+wrong output → `fail`; crash → `fail`; no capability → `skip`.
- **Negative op:** expected spec CKR → pass; other clean reject code → `xfail`; `CKR_OK`/accepted → `fail` **iff** crypto-correctness break (A) or self-contradiction (B/C/D), else `xfail`; crash → `fail`.
- **Core principle:** self-contradiction = `fail`; honest single deviation = `xfail`; **verify the effect, not the return code**. No per-provider config — `xfail` is the universal "noted deviation, investigate later" bucket.

## Approach — alternatives considered (audit 2026-05-27)

| Approach | Verdict |
|---|---|
| Per-test edits + helpers (original spec) | **Rejected as primary** — re-encodes the fail/xfail direction at ~250 sites; that is how today's asymmetries arose (`test_api_security.py:241` xfails a violation its sibling `:387` fails). Wrong altitude. |
| **Table-centric** (extend `_ckr_spec.py`) | **Chosen** — table already exists & is the house idiom; rule lives once; sibling rows adjacent so asymmetry is visible; `rv` carried structurally on `CkrAssertionError.rv`. |
| conftest hookwrapper | Rejected — implicit control flow in the fragile runtest/report hooks; doesn't cut edit count. |
| `@negative` marker | Optional sugar for the N2 tier only; can't express dynamic/probe (Type B/C) cases. |

## Validation model (every phase)

1. **Offline mock-`raw` meta-test per flip** in `tests/*_runtime_classification.py` — drive the function with a fake `raw` returning a chosen `CK_RV`, assert all three branches (`CKR_OK`→`fail`, expected→pass, other→`xfail`). Run `uv run pytest tests/` (no provider). **This is the per-phase acceptance gate.**
2. **Per-provider count delta** from `artifacts/_matrix/provider-summary.json` (`records[].passed/failed/xfailed/skipped`) before/after. "Better" = no new signal/crash `fail`, no finding demoted to `skip`/silent-pass, every `fail`→`xfail` offset by an `xfail` gain (not a `pass` gain).
3. **Provider-neutral messages** — `tests/test_provider_neutral_findings.py` bans `NSS`/`softoken`; helper messages cite the attribute/behavior only.
4. **Reversibility** — each phase is one squashable, independently-revertible PR; the `assert_ckr` change (Phase 1 Task 2) ships only with its meta-tests green.
5. **Doc sync** — any phase that flips a finding documented in `docs/module-issues.md` updates that entry in the same PR.

---

## Phase 1 — Foundation

**Files:** Modify `src/pkcs11_check/testcases/ckr/_ckr_spec.py` (`CkrExpectation`, `assert_ckr`); Modify `src/pkcs11_check/testcases/conftest.py` (helpers, near `xfail_if_known_ckr` ~L391); Create `tests/test_classification_helpers.py`; Modify `CLAUDE.md`.

### Task 1 — Add `kind` to `CkrExpectation`

- [x] **Step 1 — Failing test** in `tests/test_classification_helpers.py`:
```python
from pkcs11_check.testcases.ckr._ckr_spec import CkrExpectation
def test_ckr_expectation_kind_default_policy():
    e = CkrExpectation(function="f", condition="c", spec_ckr=0x70,
                       compat_tuple=(0x70,), spec_ref="r")
    assert e.kind == "policy"
```
- [x] **Step 2 — Run, verify fail.** `uv run pytest tests/test_classification_helpers.py -q` → FAIL (no `kind`).
- [x] **Step 3 — Add field** after `allow_success` in `_ckr_spec.py:177` (keep `frozen=True`):
```python
    kind: str = "policy"
    """'crypto' (correctness) | 'policy' (attribute/permission) | 'lifecycle' (state) | 'metadata'."""
```
- [x] **Step 4 — Run, verify pass.** → PASS.
- [x] **Step 5 — Commit.** `git add -A && git commit -m "Add kind field to CkrExpectation"`

### Task 2 — 3-way `assert_ckr` (the linchpin)

Compat mode today: `==spec`→pass; `in full_compat but !=spec`→**note()+pass**; outside→fail; `CKR_OK` handled at call sites. New: middle band → **`xfail`**; `CKR_OK` → **`fail`** unless `allow_success`. Strict mode unchanged (exact-compliance).

- [x] **Step 1 — Failing meta-tests** (`from _pytest.outcomes import Failed`):
```python
import pytest
from pkcs11_check.testcases.ckr._ckr_spec import CkrExpectation, assert_ckr
from pkcs11_check.raw.types_std import (CKR_OK, CKR_KEY_FUNCTION_NOT_PERMITTED,
                                        CKR_FUNCTION_FAILED, CKR_DEVICE_ERROR)
_E = CkrExpectation(function="C_EncryptInit", condition="key_func_not_permitted",
                    spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
                    compat_tuple=(CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_FUNCTION_FAILED),
                    spec_ref="PKCS#11 v3.1 Sec.5.8.1")
def test_expected_passes():            assert_ckr(_E, CKR_KEY_FUNCTION_NOT_PERMITTED, strict=False)
def test_other_clean_reject_xfails():
    with pytest.raises(pytest.xfail.Exception): assert_ckr(_E, CKR_FUNCTION_FAILED, strict=False)
def test_accepted_invalid_fails():
    with pytest.raises(Failed):              assert_ckr(_E, CKR_OK, strict=False)
def test_outside_set_fails():
    with pytest.raises(Failed):              assert_ckr(_E, CKR_DEVICE_ERROR, strict=False)
def test_allow_success_ok():
    e = CkrExpectation(function="C_Decrypt", condition="cbc_pad", spec_ckr=0x21,
                       compat_tuple=(0x21,), spec_ref="r", allow_success=True)
    assert_ckr(e, CKR_OK, strict=False)
def test_strict_wrong_code_fails():
    with pytest.raises(Failed):              assert_ckr(_E, CKR_FUNCTION_FAILED, strict=True)
```
- [x] **Step 2 — Run, verify the xfail / CKR_OK / allow_success tests FAIL.**
- [x] **Step 3 — Replace the compat `else:` branch** in `_ckr_spec.py:229-246`:
```python
    else:
        if actual == CKR_OK:
            if expectation.allow_success:
                return
            pytest.fail(f"{expectation.function}({expectation.condition}): accepted (CKR_OK) "
                        f"but must reject [{expectation.spec_ref}]")
        full = full_compat(expectation.compat_tuple)
        if actual not in full:
            pytest.fail(f"{expectation.function}({expectation.condition}): got {ckr_name(actual)}, "
                        f"not in acceptable set {[ckr_name(c) for c in expectation.compat_tuple]} "
                        f"[{expectation.spec_ref}]")
        if actual not in spec_codes:
            pytest.xfail(f"{expectation.function}({expectation.condition}): rejected with "
                         f"{ckr_name(actual)}, spec prefers {[ckr_name(c) for c in spec_codes]} "
                         f"[{expectation.spec_ref}]")
```
- [x] **Step 4 — Run, verify pass.** → PASS.
- [x] **Step 5 — Blast-radius check.** `uv run pytest tests/ -k ckr -q 2>&1 | tail -25` → previously-noted deviations now `xfail`; **no new `fail`**. Record the xfail delta in the commit.
- [x] **Step 6 — Commit.** `git commit -am "assert_ckr: 3-way classify (other-reject xfail, CKR_OK fail)"`

### Task 3 — Negative helpers (rv-shaped + exception-shaped)

Two thin helpers in `conftest.py` for sites NOT in the table. `classify_negative_rv` for raw-`rv` sites; `reject_or_classify` for recipe sites that raise on reject / return on success (no `rv`).

- [x] **Step 1 — Failing tests:**
```python
from _pytest.outcomes import Failed
from pkcs11_check.testcases.conftest import classify_negative_rv, reject_or_classify
from pkcs11_check.raw.rv import CkrAssertionError
def _exc(rv):
    e = CkrAssertionError(f"rv={rv}"); e.rv = rv; return e
def test_rv_ok_fails():
    with pytest.raises(Failed): classify_negative_rv(CKR_OK, (CKR_KEY_FUNCTION_NOT_PERMITTED,), label="x")
def test_rv_expected_passes():  classify_negative_rv(CKR_KEY_FUNCTION_NOT_PERMITTED, (CKR_KEY_FUNCTION_NOT_PERMITTED,), label="x")
def test_rv_other_xfails():
    with pytest.raises(pytest.xfail.Exception): classify_negative_rv(CKR_FUNCTION_FAILED, (CKR_KEY_FUNCTION_NOT_PERMITTED,), label="x")
def test_exc_none_is_fail():
    with pytest.raises(Failed): reject_or_classify(None, (CKR_KEY_FUNCTION_NOT_PERMITTED,), label="x")
def test_exc_expected_passes(): reject_or_classify(_exc(CKR_KEY_FUNCTION_NOT_PERMITTED), (CKR_KEY_FUNCTION_NOT_PERMITTED,), label="x")
def test_exc_other_xfails():
    with pytest.raises(pytest.xfail.Exception): reject_or_classify(_exc(CKR_FUNCTION_FAILED), (CKR_KEY_FUNCTION_NOT_PERMITTED,), label="x")
```
- [x] **Step 2 — Run, verify fail** (helpers undefined).
- [x] **Step 3 — Implement** (reuse `is_known_error`, `ckr_name`):
```python
def classify_negative_rv(rv, expected_rvs, *, label, allow_ok=False):
    """Raw-rv negative classifier: CKR_OK -> fail (unless allow_ok);
       rv in expected_rvs -> pass; any other clean reject -> xfail."""
    if rv == CKR_OK:
        if allow_ok:
            return
        pytest.fail(f"{label}: accepted invalid (CKR_OK) -- must reject")
    if rv in expected_rvs:
        return
    pytest.xfail(f"{label}: rejected with {ckr_name(rv)}, expected {[ckr_name(c) for c in expected_rvs]}")

def reject_or_classify(exc, expected_rvs, *, label):
    """Recipe-site negative classifier. exc=None means the op SUCCEEDED (accepted) -> fail;
       a caught CkrAssertionError: rv in expected_rvs -> pass; other clean reject -> xfail."""
    if exc is None:
        pytest.fail(f"{label}: accepted invalid (CKR_OK) -- must reject")
    if is_known_error(exc, expected_rvs):
        return
    rv = getattr(exc, "rv", None)
    name = ckr_name(rv) if rv is not None else str(exc)
    pytest.xfail(f"{label}: rejected with {name}, expected {[ckr_name(c) for c in expected_rvs]}")
```
- [x] **Step 4 — Run, verify pass.** → PASS.
- [x] **Step 5 — Commit.** `git commit -am "Add classify_negative_rv + reject_or_classify negative helpers"`

### Task 4 — Type-B / Type-C self-contradiction classifiers

- [x] **Step 1 — Failing tests:**
```python
from pkcs11_check.testcases.conftest import classify_policy_enforcement, classify_lifecycle_effect
def test_policy_claimed_violated_fails():
    with pytest.raises(Failed): classify_policy_enforcement(claimed=True, violated=True, label="x")
def test_policy_not_claimed_xfails():
    with pytest.raises(pytest.xfail.Exception): classify_policy_enforcement(claimed=False, violated=True, label="x")
def test_policy_claimed_ok_passes(): classify_policy_enforcement(claimed=True, violated=False, label="x")
def test_lifecycle_claimed_effect_fails():
    with pytest.raises(Failed): classify_lifecycle_effect(claimed_success=True, effect_observed=True, label="x")
```
- [x] **Step 2 — Run, verify fail.**
- [x] **Step 3 — Implement:**
```python
def classify_policy_enforcement(*, claimed, violated, label):
    """Type-B: claimed=module reported the protective attribute back; violated=protection breached."""
    if not claimed:
        pytest.xfail(f"{label}: module does not claim the protection (honest non-support)")
    if violated:
        pytest.fail(f"{label}: claimed the protection then violated it (self-contradiction)")

def classify_lifecycle_effect(*, claimed_success, effect_observed, label):
    """Type-C: claimed_success=prior op returned CKR_OK (e.g. destroy); effect_observed=contradiction seen."""
    if not claimed_success:
        pytest.xfail(f"{label}: prior operation did not claim success")
    if effect_observed:
        pytest.fail(f"{label}: success claimed then contradicted (self-contradiction)")
```
- [x] **Step 4 — Run, verify pass.** → PASS.
- [x] **Step 5 — Provider-neutral check.** `uv run pytest tests/test_provider_neutral_findings.py -q` → PASS.
- [x] **Step 6 — Commit.** `git commit -am "Add Type-B/Type-C self-contradiction classifiers"`

### Task 5 — Document the model in CLAUDE.md

- [x] **Step 1 — Add** the model table + core principle to `CLAUDE.md` (Coding Rules), with a one-line note that it **supersedes** "use `pytest.xfail()` for known module bugs" for Type-A / self-contradiction classes; link `docs/classification-model-design.md`.
- [x] **Step 2 — Commit.** `git commit -am "Document test-outcome classification model"`

---

## Phase 2 — V1 + V2 invalid-vector correctness (Phase-1-independent)

**Goal:** an invalid test vector that the module ACCEPTS must `fail`. Uses plain `pytest.fail` (no Phase-1 helpers), so can land first.

### V1 — three live accept-not-failed sites

**Pattern (before → after), `wycheproof/test_wycheproof_ecdh.py:273`:**
```python
# BEFORE: only flags acceptance when the expected shared secret is empty
elif result == "invalid" and not shared_expected:
    invalid_without_shared_derived = True
# AFTER: any successful derive on an invalid vector fails, regardless of shared_expected
elif result == "invalid":
    pytest.fail(f"ECDH derived a secret for an invalid vector {vec_id} (invalid-point accepted)")
```
- [x] **Task 2a** — fix `test_wycheproof_ecdh.py:273` per pattern; add `tests/test_wycheproof_ecdh_guards.py` meta-test that a fake-accept on an `invalid` vector raises `Failed`; commit.
- [ ] **Task 2b** — `acvp/aes/test_gcm.py:172`: add the missing `else: pytest.fail(...)` on the GCM-SIV decrypt-success path for `test_passed is False`; meta-test; commit.
- [ ] **Task 2c** — `wycheproof/test_wycheproof_x25519.py:260`: drop the `len(public_bytes)!=key_size` gate; fail on any successful derive for an `invalid` vector; meta-test; commit.

### V2 — produce-direction families that can't test rejection (~1000 vectors)

**Pattern:** these run invalid MAC/AEAD/keywrap vectors as *produce* ops (`sign_single`/`encrypt_single`/`wrap`), so a fresh correct output never matches the modified expected output and rejection is never tested. Re-frame to the **verify/decrypt/unwrap** direction with `fail`-on-accept (the ACVP side already does this). Land each family as a separate revertible commit with a count delta.
- [ ] **Task 2d** — `test_wycheproof_aes.py` AES-CMAC (`:139`): verify the supplied tag (`C_Verify`), `invalid` accepted → `fail`; meta-test; commit.
- [ ] **Task 2e** — AES-GMAC (`:428`, ~324 vectors): same; commit.
- [ ] **Task 2f** — AES-CCM (`:363`, ~147): decrypt-and-reject; commit.
- [ ] **Task 2g** — AES-KW (`:218`, ~126): unwrap-and-reject; commit.
- [ ] **Task 2h** — `test_wycheproof_chacha.py:115` (~69): decrypt-and-reject; commit.
- [ ] **Task 2i** — `test_wycheproof_hmac.py:234/239`: verify-and-reject; commit.
- [ ] **Task 2j** — `test_wycheproof_pbes2.py:223`: add the `invalid` accept→fail branch (structural; 0 live vectors today); commit.
- [ ] **Task 2k** — (investigate) `test_wycheproof_rsa_decrypt.py` / `rsa_oaep`: confirm invalid-padding vectors are rejected (Bleichenbacher surface); add fail-on-accept if missing; commit.

---

## Phase 3 — N1 (A/B/C) + Type-D new tests (depends Phase 1)

**Goal:** apply the model to the ~46 acceptance sites. One commit per file; each gets a mock-`raw` meta-test asserting the new branch.

### Type A — crypto-correctness → `fail` (no claim-check)
Replace the accept-tolerant branch with `pytest.fail`/`classify_negative_rv(rv, expected, label)` (no `allow_ok`).
- [ ] **Sites:** `security/test_cve_regression.py:681` (invalid EC OID), `security/test_parameter_validation.py:522,475,352` (+4 weak-param: gcm weak-tag/weak-iv/iv-reuse, pss sLen=0, xts identical halves), `ckr/test_ckr_decrypt.py:169` (wrong-len ciphertext; drop `allow_success`), `ckr/test_ckr_verify.py:60,144`, `ckr/test_ckr_sign.py:53`, `test_errors.py:289` (verify wrong-mech; reclassify the `if rv==CKR_OK: pass`), `test_kem.py:755` (CKA_VALUE injection). One task per file; meta-test + commit each.

### Type B — attribute/permission → claim-check (`classify_policy_enforcement`)
**Pattern (canonical, `test_sensitivity.py:64` — currently inverted):**
```python
attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
claimed = attrs.get(CKA_SENSITIVE) is True            # module reported it back
val = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
violated = CKA_VALUE in val                            # read_attributes OMITS sensitive attrs (no raise)
classify_policy_enforcement(claimed=claimed, violated=violated, label="read sensitive key value")
```
- [ ] **Sites:** `test_sensitivity.py:64,117` (+ dup `ckr/test_ckr_object.py:122`, `ckr/test_ckr_codes.py:127`, `ckr/test_ckr_spec_compliance.py:197`), `test_api_security.py:241,363`, `test_tookan.py:203,268`, `ckr/test_ckr_raw_attrs.py:119,200`, `test_access_levels.py:962`, `test_attribute_enforcement.py:110`, `test_kem.py:858`. For copy-escalation, `claimed` = original read-back holds the protective value; `violated` = copy exposes it. One task per file; meta-test + commit.

### Type C — lifecycle → effect-check (`classify_lifecycle_effect`), content-tagged
**Pattern (use-after-destroy):** tag the object with a unique `CKA_LABEL` before destroy; after destroy, the op `claimed_success` = destroy returned `CKR_OK`, `effect_observed` = a subsequent read returns the *tagged* object's content (distinguishes survival from handle reuse).
- [ ] **Sites:** use-after-destroy `ckr/test_ckr_object.py:143,198,255`, `ckr/test_ckr_decrypt.py:240`, `ckr/test_ckr_verify.py:82`, `ckr/test_ckr_sign.py:92`, `ckr/test_ckr_codes.py:193`, `ckr/test_ckr_priority.py:48`, `security/test_handle_reuse.py:54`; read-only setattr (effect = value mutated, readable attrs only) `test_set_attribute.py:109,128,146,161`, `ckr/test_ckr_object.py:167`. One task per file; meta-test + commit.

### Type D — derived-attribute invariant NEW tests → `fail` on contradiction
- [ ] **Task 3z** — Create `src/pkcs11_check/testcases/test_attribute_invariants.py` (suite-generated keys only): `NEVER_EXTRACTABLE` must be `True` when the key was created `EXTRACTABLE=False` and never changed; `ALWAYS_SENSITIVE` vs `SENSITIVE` likewise. Contradiction → `fail`; isolated wrong value elsewhere stays `xfail`. Meta-test + commit. Update `docs/module-issues.md` NSS `NEVER_EXTRACTABLE` entry.

---

## Phase 4 — N2 sweep (~111 binary asserts) (depends Phase 1)

**Goal:** every negative `assert rv in {set}` becomes 3-way. The ~50 `assert_ckr` sites are already fixed by Phase 1 Task 2; this phase covers the **standalone** asserts, `_check_ckr`, and local helpers.

**Pattern (before → after):**
```python
# BEFORE
assert rv in _RO_ERROR_RVS, f"expected RO rejection, got {ckr_name(rv)}"
# AFTER (expected = the spec-preferred code(s); the set's other members become xfail)
classify_negative_rv(rv, (CKR_SESSION_READ_ONLY,), label="create token object on RO session")
```
- [ ] **Per-file tasks** (replace asserts; meta-test the 3 branches; commit each):
  `test_mech_state.py` (14, `_NOT_INIT_RVCS`), `test_errors.py` (13), `ckr/test_ckr_spec_compliance.py:64` (`_check_ckr` ×9 — give it an acceptable-set param or route to `classify_negative_rv`), `test_key_usage_policy.py:84,111,202,241`, `test_ro_session_restrictions.py:259,287,443,675,698,728`, `test_session_state_machine.py:417,446,889,940`, `test_so_pin.py:95,109`, `test_access_levels.py:508,978,1401`, `test_operation_state.py`, `test_verify_signature.py`, `test_reinitialize.py`, `test_session_edge_cases.py`, `test_initialize_args.py:293,331`, `test_stateful_sigs.py:603`, and the 6 `ckr/` raw files (`test_ckr_raw_{state,multipart,attrs}`, `test_ckr_{slot_token,random,destructive}`).
- [ ] **Task 4z — retire local helpers:** migrate/remove the ~7 per-file `*_or_xfail`/`*_negative_rv` reimplementations (`test_kem._xfail_if_kem_negative_rv`, `test_benchmark._xfail_benchmark_operation_reject`, `test_mech_multipart._xfail_multipart_runtime_reject`, `test_multipart_streaming._xfail_streaming_reject`, `security/test_ffi_length_boundary.setup_xfail_if_known_ckr`, `test_fuzz` ×6) onto the shared helpers; commit.

---

## Phase 5 — P1a + P1b: provider-incompleteness `fail` → `xfail` (depends Phase 1)

**Goal:** stop hard-failing a lenient-but-conformant module on a clean error.

**Pattern (P1a, `x509/test_attribute_parity.py`):** split the caller's accumulation into two buckets — `mismatches` (wrong value → `fail`) and `missing_mandatory` (absent → collect); after all attrs, `pytest.fail` if mismatches else `pytest.xfail` if missing_mandatory.
- [ ] **P1a sites:** `x509/test_attribute_parity.py:67-68`, `x509/test_core_ops.py:427` (clean `ATTRIBUTE_*_INVALID` → xfail), `x509/test_attributes.py:87`, `x509/test_limbo_import.py:155`, `x509/test_identity.py:105`, `x509/test_search.py:104`, `test_profiles.py:243,295,345,350`, `test_v30_session.py` `C_LoginUser` clean-error sites (~11). One task per file; meta-test + commit; update `docs/module-issues.md`.
- [ ] **P1b sites:** make the positive second leg (`decrypt`/`verify`/`unwrap`) `xfail` on a clean error via `xfail_if_known_ckr` — `test_{camellia,aria,des,twofish,blowfish,salsa20,gost}.py` (`_*_or_xfail` currently only catch `MECHANISM_INVALID`), `test_rsa_extended.py:186,443,592`, `test_metamorphic.py:76`, `test_eddsa.py:177`, `test_mech_kem.py:82`, `test_mech_sign_recover.py:71`, **PQC/KEM** `test_pqc_sign.py`, `test_hash_slh_dsa.py`, `test_hash_ml_dsa.py`. *Keep `fail` for the dependent-roundtrip self-contradiction case (encrypt→decrypt of the same output).* Meta-test + commit per file.

---

## Phase 6 — P2 / P3 / C cleanups (depends Phase 1)

- [ ] **P3 message-API:** `test_message_crypto.py:211,212,231,235,292,337` and `test_mech_message.py:79,267,364,481,531` — replace ungated `except AssertionError: pytest.skip` with `reject_or_classify`/`xfail_if_known_ckr` (advertised-but-rejecting → `xfail`, not `skip`); commit.
- [ ] **P2 wrong-result leaks → `fail`:** `test_crossverify_extended.py:169` (GCM mismatch swallowed by skip), `test_ecdh_extended.py:440` (failed self-roundtrip xfailed). Isolated metadata defaults (`CKA_LOCAL`, `CKA_PRIVATE` in `test_attribute_defaults.py`, `test_key_flags.py`, `test_access_control.py:108`) **stay `xfail`**; commit.
- [ ] **C cleanups:** `ckr/test_ckr_wrap.py:84` (skip masks finding → `fail`), `ckr/test_ckr_session.py:67` (non-capability skip → `xfail`), `test_object_visibility.py:487` / `test_profiles.py:64` (substring CKR → exact); `security/test_crypto_weakness.py` — classify each `note()`-only site as posture (keep) vs Type-A/B (→ fail); commit.

---

## Self-review

- **Spec coverage:** model (P1 T2/T5), `kind` (P1 T1), A/B/C helpers (P1 T3/T4 → applied P3), Type-D new tests (P3 T3z), V1/V2 (P2), N2 (P4), P1a/P1b (P5), P2/P3/C (P6), validation harness (validation model). All covered.
- **Placeholders:** none — each phase lists exact sites + a shown pattern; per-site code is the pattern applied (repetitive sweep), not vague TODOs.
- **Type consistency:** `assert_ckr(expectation, actual, strict)` unchanged; helpers `classify_negative_rv(rv, expected_rvs, *, label, allow_ok=False)`, `reject_or_classify(exc, expected_rvs, *, label)`, `classify_policy_enforcement(*, claimed, violated, label)`, `classify_lifecycle_effect(*, claimed_success, effect_observed, label)` referenced consistently across phases.
- **Non-goal preserved:** no provider identity in any helper signature or message.

## Execution handoff

Two modes when this is picked up: **(1) subagent-driven** (recommended — fresh subagent per task, review between tasks) or **(2) inline** (executing-plans, batched checkpoints). Phase 2 may run first (Phase-1-independent); otherwise execute phases in order.
