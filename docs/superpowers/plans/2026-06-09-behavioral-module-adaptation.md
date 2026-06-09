# Behavioral Module Adaptation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove all provider-identity knowledge (`_module_quirks.py`) from pkcs11-check, replacing it with runtime request-negotiation (input side) and outcome-discrimination (output side), without hiding any real error.

**Architecture:** Two new units — `negotiate_request` (try spec-equivalent request variants, canonical-first, never on negative tests) and `classify_discrimination` (verify the security effect via a real valid leg + an exception-typed invalid leg). Migrate the 6 functional quirk consumers + 2 adjacent leaks; delete the registry + 1 meta-test; rewrite 1 finding-hiding meta-test; lock with grep-zero + guard meta-tests. **Order matters: negotiation lands first because discrimination's valid legs depend on it (opencryptoki C1).**

**Tech Stack:** Python 3.13, pytest, pure-ctypes PKCS#11 binding. `uv run` prefix mandatory. mypy gate = `uv run mypy src/`. ruff line length 100. Local softhsm2 token for fast iteration: `export SOFTHSM2_CONF=/tmp/softhsm2-audit/softhsm2.conf P11TEST_PIN=1234` (provisioned: slot 0, label audittok). Docker verification: `bash docker/test.sh <module> -- <path>`.

**Spec of record:** `docs/superpowers/specs/2026-06-09-behavioral-module-adaptation-design.md` (v2). Guardrails referenced below as G1–G6 (negotiation) and D1–D5 (discrimination).

---

## File Structure

- **Create** `src/pkcs11_check/testcases/_negotiation.py` — `negotiate_request`, `TEMPLATE_SHAPE_REJECTS` (G2), `VALUE_LEN_ON_UNWRAP_OK`, `MECH_DETERMINED_LENGTH`. One responsibility: adapt a positive request to a module's accepted shape.
- **Modify** `src/pkcs11_check/testcases/conftest.py` — add `classify_discrimination`; rewrite `unwrap_key_for_mechanism_roundtrip` onto `negotiate_request` (KEY_TYPE retained).
- **Modify** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py` — refactor `_unwrap_aes_kw_adaptive` onto `negotiate_request`; fix the material-skip (G4).
- **Modify** `src/pkcs11_check/testcases/test_authenticated_wrap.py` — sites 2/3/4 → discrimination with valid legs; site 7 skip → negotiation; delete `_aead_integrity_reject_rvs`.
- **Modify** `src/pkcs11_check/testcases/security/test_tookan.py` — site 5 → discrimination with negotiation-backed valid leg.
- **Modify** `src/pkcs11_check/testcases/ckr/test_ckr_wrap.py` — undersized wrap → 3-way classifier (xfail), keep `ckr_strict`.
- **Delete** `src/pkcs11_check/testcases/_module_quirks.py`, `tests/test_module_quirks.py`.
- **Rewrite** `tests/test_setup_runtime_capability_guards.py` `test_ckr_wrap_size_range_uses_documented_softhsm2_quirk`.
- **Create** meta-tests: `tests/test_negotiation.py`, `tests/test_classify_discrimination.py`, `tests/test_no_provider_identity.py` (grep-zero + masking-shape guard).

---

### Task 1: `negotiate_request` helper + meta-tests

**Files:**
- Create: `src/pkcs11_check/testcases/_negotiation.py`
- Test: `tests/test_negotiation.py`

- [ ] **Step 1: Write the failing meta-test** `tests/test_negotiation.py`

```python
"""Meta-tests for negotiate_request (Pillar 1). No PKCS#11 module needed."""
from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN, CKK_AES, CKK_GENERIC_SECRET,
    CKM_AES_KEY_WRAP, CKM_ECDH1_DERIVE,
    CKR_TEMPLATE_INCONSISTENT, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ENCRYPTED_DATA_INVALID, CKR_OK,
)
from pkcs11_check.testcases._negotiation import (
    negotiate_request, TEMPLATE_SHAPE_REJECTS, value_len_variant_allowed,
)


def _raise(rv):
    raise CkrAssertionError(f"Unexpected CK_RV; rv={rv}", rv)


def test_canonical_first_no_retry_on_success():
    calls = []
    def attempt(delta):
        calls.append(delta)
        return ("handle", )
    result, idx = negotiate_request(attempt, [{"a": 1}, {"a": 1, "b": 2}], label="t")
    assert idx == 0 and len(calls) == 1  # G1: canonical accepted, no retry


def test_retry_on_shape_reject_then_succeed():
    calls = []
    def attempt(delta):
        calls.append(delta)
        if len(calls) == 1:
            _raise(CKR_TEMPLATE_INCONSISTENT)
        return "ok"
    result, idx = negotiate_request(attempt, [{}, {CKA_VALUE_LEN: 32}], label="t")
    assert idx == 1 and result == "ok"


def test_read_only_is_a_shape_reject():
    assert CKR_ATTRIBUTE_READ_ONLY in TEMPLATE_SHAPE_REJECTS  # G2 union (opencryptoki)


def test_value_invalid_is_NOT_a_shape_reject():
    assert CKR_ATTRIBUTE_VALUE_INVALID not in TEMPLATE_SHAPE_REJECTS  # G2/M2


def test_non_shape_reject_propagates_immediately():
    def attempt(delta):
        _raise(CKR_ENCRYPTED_DATA_INVALID)  # integrity reject -> must NOT retry
    with pytest.raises(CkrAssertionError) as ei:
        negotiate_request(attempt, [{}, {CKA_VALUE_LEN: 32}], label="t")
    assert ei.value.rv == CKR_ENCRYPTED_DATA_INVALID


def test_all_variants_shape_rejected_raises_last():
    def attempt(delta):
        _raise(CKR_ATTRIBUTE_READ_ONLY)
    with pytest.raises(CkrAssertionError):
        negotiate_request(attempt, [{}, {CKA_VALUE_LEN: 32}], label="t")


def test_value_len_variant_allowlist():
    # G3: generic secret + AES-KW (determined length) -> allowed; AES / ECDH -> forbidden
    assert value_len_variant_allowed(CKK_GENERIC_SECRET, CKM_AES_KEY_WRAP) is True
    assert value_len_variant_allowed(CKK_AES, CKM_AES_KEY_WRAP) is False
    assert value_len_variant_allowed(CKK_GENERIC_SECRET, CKM_ECDH1_DERIVE) is False
```

- [ ] **Step 2: Run it, verify it fails** — `uv run python -m pytest tests/test_negotiation.py -q` → ImportError (module missing).

- [ ] **Step 3: Implement** `src/pkcs11_check/testcases/_negotiation.py`

```python
"""Request negotiation (Pillar 1): adapt a positive request to a module's accepted shape.

The module's own clean reject tells us our request shape is wrong; we retry with a
spec-equivalent variant. No provider identity. See the design spec, guardrails G1-G6.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any, TypeVar

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKK_GENERIC_SECRET,
    CKM_AES_KEY_WRAP,
    CKM_AES_KEY_WRAP_KWP,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

T = TypeVar("T")

# G2: the ONLY codes that justify a retry. ATTRIBUTE_VALUE_INVALID is deliberately
# excluded -- it double-books as a legitimate forgery/policy reject. Any non-shape
# reject (integrity, length-range, ...) propagates so negotiation never swallows it.
TEMPLATE_SHAPE_REJECTS: tuple[int, ...] = (
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
)

# G3: key types for which CKA_VALUE_LEN is permitted in a C_UnwrapKey template
# (PKCS#11 base v3.0 Table 11 footnote 6 does NOT apply). CKK_AES is forbidden.
VALUE_LEN_ON_UNWRAP_OK: frozenset[int] = frozenset({int(CKK_GENERIC_SECRET)})

# G3: mechanisms whose recovered length is unambiguously determined, so a supplied
# CKA_VALUE_LEN is a redundant restatement, not a truncation control. Excludes every
# C_DeriveKey length-bearing mech and every *_PAD unwrap mech by omission.
MECH_DETERMINED_LENGTH: frozenset[int] = frozenset(
    {int(CKM_AES_KEY_WRAP), int(CKM_AES_KEY_WRAP_KWP)}
)


def value_len_variant_allowed(key_type: int, mechanism: int) -> bool:
    """G3: a CKA_VALUE_LEN variant is only permitted for an allowlisted (key_type, mech)."""
    return int(key_type) in VALUE_LEN_ON_UNWRAP_OK and int(mechanism) in MECH_DETERMINED_LENGTH


def negotiate_request(
    attempt: Callable[[Mapping[int, Any]], T],
    variants: Sequence[Mapping[int, Any]],
    *,
    label: str,
) -> tuple[T, int]:
    """Try spec-equivalent request variants against the live module, canonical-first.

    ``variants[0]`` MUST be the most spec-conformant request (G1). ``attempt`` runs the
    operation with one variant's template/param delta and returns its result or raises a
    ``CkrAssertionError``. Returns ``(result, winning_index)``.

    Retries to the next variant ONLY on a clean template-shape reject (G2). Any other
    rejection propagates immediately. If every variant is shape-rejected, the last
    exception is re-raised for the caller to classify (xfail). Positive operations only
    (G6); single-shot recipe ops only (G5).
    """
    last_exc: CkrAssertionError | None = None
    for idx, delta in enumerate(variants):
        try:
            return attempt(delta), idx
        except CkrAssertionError as exc:
            if exc.rv not in TEMPLATE_SHAPE_REJECTS:
                raise  # non-shape reject -> never negotiate past it
            last_exc = exc
    assert last_exc is not None  # variants is non-empty by contract
    raise last_exc
```

- [ ] **Step 4: Run tests, verify pass** — `uv run python -m pytest tests/test_negotiation.py -q` → all pass. Then `uv run mypy src/pkcs11_check/testcases/_negotiation.py` and `uv run ruff check src/pkcs11_check/testcases/_negotiation.py tests/test_negotiation.py`.

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/testcases/_negotiation.py tests/test_negotiation.py
git commit -m "feat(testcases): negotiate_request helper (Pillar 1) + meta-tests"
```

---

### Task 2: Refactor AES-KW + `unwrap_key_for_mechanism_roundtrip` onto `negotiate_request`

**Files:**
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py` (`_unwrap_aes_kw_adaptive` ~99-125; material check ~294-300)
- Modify: `src/pkcs11_check/testcases/conftest.py` (`unwrap_key_for_mechanism_roundtrip` ~169-212)

- [ ] **Step 1: Refactor `_unwrap_aes_kw_adaptive`** to call `negotiate_request`. Replace the local `_TEMPLATE_SHAPE_REJECTS` with the imported `TEMPLATE_SHAPE_REJECTS` (this drops `ATTRIBUTE_VALUE_INVALID`, adds `ATTRIBUTE_READ_ONLY`). Build variants canonical-first: variant 0 = base template (already has CKA_KEY_TYPE=CKK_GENERIC_SECRET), variant 1 = base + CKA_VALUE_LEN (only when `value_len is not None`, which the caller already gates to valid vectors). Guard the CKA_VALUE_LEN variant with `value_len_variant_allowed(CKK_GENERIC_SECRET, CKM_AES_KEY_WRAP)` (returns True).

```python
from pkcs11_check.testcases._negotiation import (
    negotiate_request, value_len_variant_allowed,
)

def _unwrap_aes_kw_adaptive(rs, unwrapping_key, wrapped, base_attrs, value_len):
    variants = [dict(base_attrs)]
    if value_len is not None and value_len_variant_allowed(
        base_attrs[CKA_KEY_TYPE], CKM_AES_KEY_WRAP
    ):
        variants.append({**base_attrs, CKA_VALUE_LEN: value_len})

    def attempt(delta):
        return unwrap_key(rs.raw, rs.sh, unwrapping_key, wrapped, CKM_AES_KEY_WRAP, attrs=delta)

    result, _idx = negotiate_request(attempt, variants, label="AES-KW unwrap")
    return result
```

- [ ] **Step 2: Fix the material-skip (G4)** at `test_wycheproof_aes.py` ~294-300. The current `if recovered is not None: assert recovered == msg_expected` silently passes when CKA_VALUE is unreadable. Change to fail-closed: the target generic secret is created extractable, so read-back MUST work for a valid vector — make absence an xfail, never a silent pass.

```python
attrs = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])
recovered = attrs.get(CKA_VALUE)
if recovered is None:
    pytest.xfail(f"AES-KW {vec_id}: unwrapped key material unreadable; cannot verify")
assert recovered == msg_expected, f"AES-KW {vec_id}: unwrapped key material mismatch"
```

- [ ] **Step 3: Rewrite `unwrap_key_for_mechanism_roundtrip`** (conftest.py) onto `negotiate_request`, **retaining CKA_KEY_TYPE** (G1; the current code drops both CKA_CLASS and CKA_KEY_TYPE — that is a spec violation, footnote 5). Variants: [0] full template (canonical, includes CKA_CLASS+CKA_KEY_TYPE); [1] drop **only** CKA_CLASS. Remove the `quirk_extras` / `detect_module` import and the VENDOR `note`-then-retry; the negotiation records the winning variant generally. Keep the optional `value_len` param but route it through `value_len_variant_allowed`.

```python
def unwrap_key_for_mechanism_roundtrip(rs, p11_config, *, unwrapping_key, wrapped_key,
                                       mechanism, attrs, mech_param=None, value_len=None,
                                       purpose="mechanism unwrap roundtrip"):
    from pkcs11_check.raw.recipes import unwrap_key
    from pkcs11_check.testcases._negotiation import negotiate_request, value_len_variant_allowed
    base = dict(attrs)
    variants = [base]
    relaxed = {k: v for k, v in base.items() if k != CKA_CLASS}  # G1: keep CKA_KEY_TYPE
    if relaxed != base:
        variants.append(relaxed)
    if value_len is not None and CKA_KEY_TYPE in base and value_len_variant_allowed(
        base[CKA_KEY_TYPE], int(mechanism)
    ):
        variants = [{**v, CKA_VALUE_LEN: value_len} for v in variants] + variants

    def attempt(delta):
        return unwrap_key(rs.raw, rs.sh, unwrapping_key, wrapped_key, mechanism,
                          attrs=delta, mech_param=mech_param)
    result, _idx = negotiate_request(attempt, variants, label=purpose)
    return result
```

- [ ] **Step 4: Verify no-regression** locally + collect:
```bash
export SOFTHSM2_CONF=/tmp/softhsm2-audit/softhsm2.conf P11TEST_PIN=1234
uv run pkcs11-check test -m /usr/lib/softhsm/libsofthsm2.so --pin 1234 --slot 0 --isolation none --match test_aes_key_wrap src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py
# Expected: 165 passed (unchanged).
uv run mypy src/pkcs11_check/testcases/conftest.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py
uv run python -m pytest tests/ -q -k "not benchmark"   # meta-tests still green
```

- [ ] **Step 5: Commit**
```bash
git add src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py src/pkcs11_check/testcases/conftest.py
git commit -m "refactor(testcases): AES-KW + unwrap roundtrip onto negotiate_request (KEY_TYPE retained, material-skip fixed)"
```

---

### Task 3: `classify_discrimination` helper + meta-tests

**Files:**
- Modify: `src/pkcs11_check/testcases/conftest.py` (add after `classify_lifecycle_effect`)
- Test: `tests/test_classify_discrimination.py`

- [ ] **Step 1: Write the failing meta-test** `tests/test_classify_discrimination.py`

```python
"""Meta-tests for classify_discrimination (Pillar 2). No module needed."""
from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_GENERAL_ERROR
from pkcs11_check.testcases.conftest import classify_discrimination


def _clean(rv):
    return CkrAssertionError("rejected", rv)


def test_discriminated_passes_regardless_of_code():
    # valid accepted + tampered rejected with a catch-all code -> pass (D1/D3)
    classify_discrimination(valid_accepted=True, invalid_outcome=_clean(CKR_DEVICE_ERROR), label="t")
    classify_discrimination(valid_accepted=True, invalid_outcome=_clean(CKR_GENERAL_ERROR), label="t")


def test_accepted_tampered_input_fails():
    with pytest.raises(Exception) as ei:  # pytest.fail raises Failed
        classify_discrimination(valid_accepted=True, invalid_outcome=12345, label="t")  # a handle
    assert "Failed" in type(ei.value).__name__ or "fail" in str(ei.value).lower()


def test_broken_valid_leg_fails():
    with pytest.raises(Exception):
        classify_discrimination(valid_accepted=False, invalid_outcome=_clean(CKR_DEVICE_ERROR), label="t")


def test_non_ckr_assertion_reraises_not_treated_as_reject():
    # D2: a harness AssertionError (no .rv) must re-raise, NOT count as detection
    with pytest.raises(AssertionError):
        classify_discrimination(valid_accepted=True, invalid_outcome=AssertionError("ctypes bug"), label="t")
```

- [ ] **Step 2: Run it, verify it fails** — `uv run python -m pytest tests/test_classify_discrimination.py -q` → ImportError.

- [ ] **Step 3: Implement** in `conftest.py` (mirror `classify_lifecycle_effect` style):

```python
def classify_discrimination(*, valid_accepted: bool, invalid_outcome: Any, label: str) -> None:
    """Outcome-based discrimination classifier (Pillar 2, guardrails D1-D5).

    For integrity/forgery/type-confusion negative tests where the spec mandates no
    specific failure code: the verdict is the security EFFECT, not the CKR.

    Args:
        valid_accepted: the un-tampered operation succeeded AND its result was verified
            (a real, material-checked positive leg). Advertised-but-not-operational
            positive legs are routed to xfail by the caller BEFORE this call (D5).
        invalid_outcome: the invalid leg's outcome -- either the caught exception, or the
            produced object (a handle/bytes) if the module ACCEPTED the bad input.
            * a produced object (not an exception) -> accepted -> break.
            * a CkrAssertionError (clean .rv)       -> rejected (any code, D3).
            * any other exception (no .rv)          -> re-raised (D2: harness bug, not detection).
    """
    if isinstance(invalid_outcome, CkrAssertionError):
        invalid_rejected = True
    elif isinstance(invalid_outcome, BaseException):
        raise invalid_outcome  # D2: not a CK_RV reject -> a harness/ctypes bug, surface it
    else:
        invalid_rejected = False  # D3: a produced handle/object IS acceptance of bad input

    if not valid_accepted:
        pytest.fail(
            f"{label}: the valid/un-tampered operation did not verify -- cannot "
            "distinguish 'detected tampering' from 'cannot do the operation'"
        )
    if not invalid_rejected:
        pytest.fail(f"{label}: accepted the tampered/forged/confused input (security break)")
```
Ensure `CkrAssertionError` and `Any` are imported in conftest.py (CkrAssertionError from `pkcs11_check.raw.rv`).

- [ ] **Step 4: Run tests, verify pass** — `uv run python -m pytest tests/test_classify_discrimination.py -q`; `uv run mypy src/pkcs11_check/testcases/conftest.py`; ruff.

- [ ] **Step 5: Commit**
```bash
git add src/pkcs11_check/testcases/conftest.py tests/test_classify_discrimination.py
git commit -m "feat(testcases): classify_discrimination helper (Pillar 2) + meta-tests"
```

---

### Task 4: Migrate `test_authenticated_wrap.py` forgery sites (2, 3, 4) + convert site 7 skip

**Files:**
- Modify: `src/pkcs11_check/testcases/test_authenticated_wrap.py`

For EACH of the four forgery/tamper tests (`test_aes_key_wrap_bit_flip_detected` ~513; `test_aes_gcm_wrap_bit_flip_detected` ~615; `test_tampered_tag_rejected` ~257; `test_aes_gcm_unwrap_with_different_aad_rejected` ~386; `test_ecdh_aes_kw_bit_flip_integrity` ~830-940): apply the same pattern.

- [ ] **Step 1: Capture the original material** before wrapping: `original = read_attributes(rs.raw, rs.sh, target, [CKA_VALUE]).get(CKA_VALUE)` (targets are created `CKA_EXTRACTABLE=True, CKA_SENSITIVE=False`, so readable).

- [ ] **Step 2: Add the valid leg (D4).** Unwrap the **un-tampered** blob and verify it recovers `original`. For AES-KW / ECDH-AES-KW (templates with CKA_CLASS/CKA_KEY_TYPE) the valid-leg unwrap MUST go through `_unwrap_aes_kw_adaptive`/`unwrap_key_for_mechanism_roundtrip` (negotiation) so opencryptoki is not false-failed (C1). For GCM (attrs carry no CKA_CLASS/KEY_TYPE) call `unwrap_key_authenticated` directly. Route an advertised-but-not-operational valid-leg reject to xfail (D5) via the existing `_xfail_if_wrap_runtime_reject`/`xfail_if_known_ckr` guard **before** computing `valid_accepted`. Example (AES-KW, mirrors the test-design reviewer's snippet):
```python
try:
    good = _unwrap_aes_kw_adaptive(rs, wrap_h, wrapped,
        {CKA_CLASS: CKO_SECRET_KEY, CKA_KEY_TYPE: CKK_AES,
         CKA_EXTRACTABLE: True, CKA_SENSITIVE: False}, value_len=len(original))
except AssertionError as exc:
    _xfail_if_wrap_runtime_reject(exc, f"{label}: AES-KW unwrap not operational on valid blob")
good_value = read_attributes(rs.raw, rs.sh, good, [CKA_VALUE]).get(CKA_VALUE)
destroy_quietly(rs.raw, rs.sh, good)
valid_accepted = good_value is not None and good_value == original
```

- [ ] **Step 3: Replace the quirk-spliced reject classification with discrimination (D3).** Run the tamper, capturing the outcome as exception-or-handle, and classify:
```python
invalid_outcome: Any
try:
    h = unwrap_key(rs.raw, rs.sh, wrap_h, tampered, CKM_AES_KEY_WRAP,
                   attrs={CKA_CLASS: CKO_SECRET_KEY, CKA_KEY_TYPE: CKK_AES,
                          CKA_EXTRACTABLE: True, CKA_SENSITIVE: False})
    invalid_outcome = h  # acceptance of a tampered blob == break
    destroy_quietly(rs.raw, rs.sh, h)
except AssertionError as exc:
    invalid_outcome = exc
classify_discrimination(valid_accepted=valid_accepted, invalid_outcome=invalid_outcome, label=label)
```
Delete the `*quirk_extras(...)` / `_aead_integrity_reject_rvs(...)` / inline `is_known_error(accepted_rvs)` splices from all four tests, and **delete the `_aead_integrity_reject_rvs` helper** (~81-90). Remove the now-unused `quirk_extras`/`_module_quirks` imports from this file.

- [ ] **Step 4: Convert site 7 skip (~827)** `pytest.skip("…OC's CKA_CLASS/CKA_KEY_TYPE quirk")` in `test_ecdh_aes_kw_roundtrip` → use the negotiation helper for the roundtrip unwrap so opencryptoki succeeds instead of skipping. Remove the OpenCryptoki-named skip and its `CKR_ATTRIBUTE_READ_ONLY` check.

- [ ] **Step 5: Verify** — collect + mypy + a softhsm2 run of the file:
```bash
uv run mypy src/pkcs11_check/testcases/test_authenticated_wrap.py
export SOFTHSM2_CONF=/tmp/softhsm2-audit/softhsm2.conf P11TEST_PIN=1234
uv run pkcs11-check test -m /usr/lib/softhsm/libsofthsm2.so --pin 1234 --slot 0 --isolation none src/pkcs11_check/testcases/test_authenticated_wrap.py
# Expected: no new failures vs baseline; forgery tests pass (softhsm2 discriminates).
```

- [ ] **Step 6: Commit**
```bash
git add src/pkcs11_check/testcases/test_authenticated_wrap.py
git commit -m "refactor(testcases): authenticated-wrap forgery sites to discrimination (valid legs via negotiation); drop quirks"
```

---

### Task 5: Migrate `test_tookan.py` type-confusion (site 5)

**Files:**
- Modify: `src/pkcs11_check/testcases/security/test_tookan.py` (`test_unwrap_aes_as_des3_rejected` ~341-459)

- [ ] **Step 1: Add the negotiation-backed valid leg (C1).** After the successful wrap (~362), unwrap the same blob as its **correct** type (CKK_AES) via `unwrap_key_for_mechanism_roundtrip` (negotiation, so opencryptoki's CKA_CLASS/KEY_TYPE reject doesn't false-fail the valid leg), confirm a handle, set `valid_accepted=True`, destroy it.

- [ ] **Step 2: Replace the string-match quirk splice (~413-419) with discrimination (D3).** The type-confused unwrap (request CKK_DES3): any produced handle ⇒ break (`invalid_outcome=handle`), any clean reject ⇒ `invalid_outcome=exc`. `classify_discrimination(valid_accepted=valid_accepted, invalid_outcome=..., label=...)`. Keep the existing wrap-side `_TYPE_CONFUSION_WRAP_INAPPLICABLE_RVS` skip and `_TYPE_CONFUSION_WRAP_RUNTIME_REJECT_RVS` xfail (before discrimination). Remove the `quirk_extras`/`_ckr_name`-splice and the `_module_quirks` import. (Accept the documented minor loss of the `MECHANISM_INVALID`-exclusion sub-check; the valid leg already proves the mechanism unwraps.)

- [ ] **Step 3: Verify** — `uv run mypy src/pkcs11_check/testcases/security/test_tookan.py`; softhsm2 run of the test (expect pass).

- [ ] **Step 4: Commit**
```bash
git add src/pkcs11_check/testcases/security/test_tookan.py
git commit -m "refactor(testcases): tookan type-confusion to discrimination (negotiation-backed valid leg); drop quirk"
```

---

### Task 6: `test_ckr_wrap.py` undersized wrap → 3-way classifier (keep the conformance signal)

**Files:**
- Modify: `src/pkcs11_check/testcases/ckr/test_ckr_wrap.py` (`test_wrapping_key_size_range` ~295-370)

- [ ] **Step 1: Replace the quirk splice (~362)** `*(() if ckr_strict else quirk_extras(p11_config, "size_range_on_wrap"))` with the spec set only, classified 3-way so softhsm2's `CKR_GENERAL_ERROR` becomes **xfail** (not pass). Keep the existing `CKR_OK → pytest.fail` (Type-A) branch. Use `classify_negative_rv(rv, accepted, label=..., allow_ok=False)` with `accepted = (CKR_WRAPPING_KEY_SIZE_RANGE, CKR_KEY_SIZE_RANGE, CKR_WRAPPING_KEY_TYPE_INCONSISTENT, CKR_KEY_TYPE_INCONSISTENT)`; preserve `--ckr-strict` semantics (if `ckr_strict` should promote xfail→fail, gate via `assert_ckr`/the strict flag as the surrounding code does). Remove the `_module_quirks` import.

- [ ] **Step 2: Verify** — softhsm2 run: the undersized wrap test now **xfails** on softhsm2 (was pass). `uv run mypy`.

- [ ] **Step 3: Commit**
```bash
git add src/pkcs11_check/testcases/ckr/test_ckr_wrap.py
git commit -m "refactor(testcases): undersized-wrap stays 3-way; softhsm2 GENERAL_ERROR now honest xfail"
```

---

### Task 7: Delete registry, fix meta-tests, lock de-identification

**Files:**
- Delete: `src/pkcs11_check/testcases/_module_quirks.py`, `tests/test_module_quirks.py`
- Modify: `tests/test_setup_runtime_capability_guards.py` (`test_ckr_wrap_size_range_uses_documented_softhsm2_quirk` ~1817)
- Modify: `src/pkcs11_check/testcases/test_mech_state.py` (stale comment ~71-72)
- Create: `tests/test_no_provider_identity.py`

- [ ] **Step 1: Delete** `_module_quirks.py` and `tests/test_module_quirks.py`.

- [ ] **Step 2: Rewrite the finding-hiding meta-test** at `test_setup_runtime_capability_guards.py:1817`: stub `C_WrapKey → CKR_GENERAL_ERROR` with `module=softhsm2`, assert `test_wrapping_key_size_range` now resolves to **xfail** (deviation recorded), not pass. Rename to `test_ckr_wrap_size_range_general_error_is_xfail`.

- [ ] **Step 3: Update** the stale comment in `test_mech_state.py:71-72` (drop the "register a quirk in `_module_quirks.py`" guidance).

- [ ] **Step 4: Write the guard meta-test** `tests/test_no_provider_identity.py`:

```python
"""Lock the de-identification: no provider-identity branching, no masking shapes."""
from __future__ import annotations
import pathlib, re

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "pkcs11_check"
TESTS = pathlib.Path(__file__).resolve().parent
ALLOWLIST = {  # legitimate non-masking uses (token provisioner, subprocess load)
    "testcases/test_threading.py",
}

def _py_files():
    for root in (SRC, TESTS):
        yield from root.rglob("*.py")

def test_no_deleted_quirk_symbols():
    banned = re.compile(r"\b(_module_quirks|quirk_extras|detect_module|ModuleId|MODULE_QUIRKS)\b")
    bad = [str(p) for p in _py_files() if banned.search(p.read_text())]
    assert not bad, f"reintroduced quirk-registry references: {bad}"

def test_no_literal_discrimination_legs():
    pat = re.compile(r"classify_discrimination\([^)]*(valid_accepted|invalid_outcome)\s*=\s*(True|False)")
    bad = [str(p) for p in _py_files() if pat.search(p.read_text())]
    assert not bad, f"classify_discrimination called with a literal leg (masking smell): {bad}"

def test_no_silent_material_skip():
    pat = re.compile(r"if\s+recovered\s+is\s+not\s+None\s*:")
    bad = [str(p) for p in _py_files() if pat.search(p.read_text())]
    assert not bad, f"silent material-skip idiom in wrap/unwrap tests: {bad}"

def test_no_provider_name_branch_on_module():
    pat = re.compile(r"(if|elif).*\b(softhsm|kryoptic|nss|opencryptoki|tpm2|bouncyhsm)\b.*"
                     r"(p11_config\.module|module\.lower\(\)|in module)")
    bad = []
    for p in _py_files():
        rel = p.relative_to(p.parents[2]).as_posix() if "src" in p.parts else f"testcases/{p.name}"
        if any(a in p.as_posix() for a in ALLOWLIST):
            continue
        if pat.search(p.read_text()):
            bad.append(str(p))
    assert not bad, f"provider-name branch on module path: {bad}"
```
(Adjust the allowlist path computation to the repo layout during implementation; the intent is: only `test_threading.py` may branch on the module name, for token provisioning.)

- [ ] **Step 5: Run the full meta-suite + grep-zero**:
```bash
grep -rn "_module_quirks\|quirk_extras\|detect_module\|ModuleId\|MODULE_QUIRKS" src/ tests/ ; echo "exit=$?  (want: no matches, exit 1 from grep)"
uv run python -m pytest tests/ -q -k "not benchmark"
uv run mypy src/
```
Expected: grep prints nothing; meta-suite green; mypy clean.

- [ ] **Step 6: Commit**
```bash
git add -A
git commit -m "refactor(testcases): delete _module_quirks registry; lock de-identification with guard meta-tests"
```

---

### Task 8: Docker verification (current code, the modules that motivated the quirks)

**Files:** none (verification only).

- [ ] **Step 1: opencryptoki** (negotiation + the C1 false-fail regression):
```bash
bash docker/test.sh opencryptoki -- src/pkcs11_check/testcases/test_authenticated_wrap.py src/pkcs11_check/testcases/security/test_tookan.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py
```
Expected: forgery + type-confusion tests **pass** (valid legs negotiate past `ATTRIBUTE_READ_ONLY`); **no false-fail** of opencryptoki on the valid legs.

- [ ] **Step 2: kryoptic** (discrimination passes on DEVICE_ERROR):
```bash
bash docker/test.sh kryoptic -- src/pkcs11_check/testcases/test_authenticated_wrap.py
```
Expected: AEAD/AES-KW forgery tests **pass** (kryoptic discriminates; its `DEVICE_ERROR` is code-irrelevant now).

- [ ] **Step 3: softhsm2** (undersized wrap → honest xfail; AES-KW no-regression):
```bash
bash docker/test.sh softhsm2 -- src/pkcs11_check/testcases/ckr/test_ckr_wrap.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py
```
Expected: undersized-wrap **xfails** (GENERAL_ERROR, recorded); AES-KW unchanged.

- [ ] **Step 4:** Record outcomes; if any site false-fails, return to the relevant task. When all green, the work is done.

---

## Self-review notes (author)

- **Spec coverage:** G1 (Task 1 canonical-first + Task 2 KEY_TYPE retained), G2 (Task 1 TEMPLATE_SHAPE_REJECTS), G3 (Task 1 value_len_variant_allowed + meta-test), G4 (Task 2 material-skip fix), G5/G6 (Task 1 contract + Task 7 guard), D1-D5 (Task 3 helper + Task 4/5 valid legs), code-conformance carve-out (Task 6), deletion+lock (Task 7), C1 regression (Task 8 step 1). All mapped.
- **Ordering:** negotiation (Tasks 1-2) precedes discrimination valid legs (Tasks 4-5) — satisfies D4/C1.
- **Type consistency:** `negotiate_request(attempt, variants, *, label)`, `classify_discrimination(*, valid_accepted, invalid_outcome, label)`, `value_len_variant_allowed(key_type, mechanism)` used identically across tasks.
