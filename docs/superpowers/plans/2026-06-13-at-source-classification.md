# At-Source Test-Outcome Classification & Per-Provider Reporting — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every `fail`/`xfail` test outcome emit a structured `Classification` at the moment it is decided, carry it to `report.jsonl` on the existing `user_properties` channel, and generate a tiered, size-budgeted per-provider report directly from that structured data.

**Architecture:** A new `classification.py` module (sibling of `compliance.py`) holds a `Classification` record, a single `derive_verdict(reason, kind)` function that encodes the `docs/classification-model-design.md` table, and a `classify()` emit API. The four existing classifier helpers and `assert_ckr` route through it; the ~608 raw `pytest.xfail`/`pytest.fail` sites are migrated to it under a static gate; crashes are emitted runner-side; a report generator rolls the structured records up.

**Tech Stack:** Python 3.13+, `uv`, pytest + pytest-reportlog (`user_properties`), `ruff`, `mypy --strict`. Pure stdlib for the report generator.

**Design:** `docs/superpowers/specs/2026-06-13-at-source-classification-design.md` (commit `71a131fa`).

---

## Conventions for every task

- ALWAYS `uv run` (tools are not on PATH): `uv run pytest …`, `uv run ruff …`, `uv run mypy …`.
- Type annotations on all public functions (`mypy --strict`). Line length 100. `ruff format`.
- Commit after each task. Branch off `dev` first if not already on a feature branch:
  `git checkout dev && git checkout -b feat/at-source-classification` (NEVER work on `main`).
- The CI gate set before any commit: `uv run ruff format --check . && uv run ruff check . && uv run mypy src && uv run pytest tests/ -q`.

---

## File Structure (locked before tasks)

| Path | Responsibility | Task |
|---|---|---|
| `src/pkcs11_check/classification.py` | `Classification` record, `derive_verdict`, store (`record/get_records/clear/serialize`), `classify()`/`xfail_as`/`fail_as` | 0.1–0.3 |
| `src/pkcs11_check/spec_refs.py` | central `(function\|mechanism\|CKR) → v3.2 §` lookup | 1.1 |
| `src/pkcs11_check/plugin.py` | attach `pkcs11_classification` in `makereport`; clear per item; runtime unclassified gate | 0.4, 5.1 |
| `src/pkcs11_check/core/file_runner.py` | emit crash as a `Classification`-shaped record | 6.1 |
| `src/pkcs11_check/testcases/conftest.py` | 4 helpers → `classify()` adapters; new `assert_correct()` | 2.1–2.4, 4.1 |
| `src/pkcs11_check/testcases/ckr/_ckr_spec.py` | `assert_ckr` emits a `Classification` | 2.5 |
| `wycheproof/wycheproof_loader.py`, `acvp/acvp_loader.py`, x509 limbo loader | stamp `source`/`vector_id` | 3.1–3.3 |
| 140 testcase files (608 raw sites) | migrate to `classify()`/`xfail_as`/`fail_as` | Phase 7 |
| `tools/report/` (`extract.py`, `render.py`, `correlate.py`, `__main__.py`) | tiered report generator | Phase 8 |
| `tests/` | `derive_verdict` units; gate meta-tests; golden report | throughout |

---

## Phase 0: The classification core (TDD)

### Task 0.1: `derive_verdict` — the model table as one function

**Files:**
- Create: `src/pkcs11_check/classification.py`
- Test: `tests/test_classification_derive.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_classification_derive.py
import pytest
from pkcs11_check.classification import derive_verdict

@pytest.mark.parametrize("reason,kind,outcome,severity", [
    ("wrong_result", "crypto", "fail", "CRITICAL"),
    ("wrong_result", "metadata", "fail", "MEDIUM"),
    ("accepted_invalid", "crypto", "fail", "CRITICAL"),
    ("accepted_invalid", "policy", "fail", "CRITICAL"),
    ("accepted_invalid", "lifecycle", "fail", "HIGH"),
    ("accepted_invalid", "metadata", "fail", "HIGH"),
    ("self_contradiction", "policy", "fail", "CRITICAL"),
    ("self_contradiction", "lifecycle", "fail", "HIGH"),
    ("self_contradiction", "metadata", "fail", "HIGH"),
    ("oracle", "crypto", "fail", "HIGH"),
    ("crash", None, "fail", "HIGH"),
    ("not_operational", None, "xfail", "LOW"),
    ("nonspec_reject", None, "xfail", "LOW"),
    ("honest_deviation", "metadata", "xfail", "LOW"),
    ("sanctioned_refusal", None, "pass", "INFO"),
    ("unclassified", None, "fail", "HIGH"),
])
def test_derive_verdict(reason, kind, outcome, severity):
    assert derive_verdict(reason, kind) == (outcome, severity)

def test_derive_verdict_rejects_unknown_reason():
    with pytest.raises(ValueError):
        derive_verdict("not_a_reason", None)
```

- [ ] **Step 2: Run it, verify it fails**

Run: `uv run pytest tests/test_classification_derive.py -q`
Expected: FAIL — `ModuleNotFoundError: pkcs11_check.classification`.

- [ ] **Step 3: Implement `derive_verdict`**

```python
# src/pkcs11_check/classification.py
"""At-source test-outcome classification (sibling of compliance.py).

Tests report an OBSERVATION (reason + kind + facts); derive_verdict applies the
docs/classification-model-design.md table to produce (outcome, severity). The record
rides to report.jsonl via user_properties, exactly like compliance notes.
"""
from __future__ import annotations

from typing import Literal

Outcome = Literal["pass", "xfail", "fail"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# reason -> the single outcome it always maps to (a site cannot flip the pivot)
_REASON_OUTCOME: dict[str, Outcome] = {
    "wrong_result": "fail",
    "accepted_invalid": "fail",
    "self_contradiction": "fail",
    "oracle": "fail",
    "crash": "fail",
    "not_operational": "xfail",
    "nonspec_reject": "xfail",
    "honest_deviation": "xfail",
    "sanctioned_refusal": "pass",
    "unclassified": "fail",  # synthetic backlog marker; conservative
}


def _severity(reason: str, kind: str | None) -> Severity:
    if reason == "wrong_result":
        return "CRITICAL" if kind == "crypto" else "MEDIUM"
    if reason in ("accepted_invalid", "self_contradiction"):
        return "CRITICAL" if kind in ("crypto", "policy") else "HIGH"
    if reason in ("oracle", "crash", "unclassified"):
        return "HIGH"
    if reason in ("not_operational", "nonspec_reject", "honest_deviation"):
        return "LOW"
    if reason == "sanctioned_refusal":
        return "INFO"
    raise ValueError(f"unknown reason: {reason!r}")


def derive_verdict(reason: str, kind: str | None) -> tuple[Outcome, Severity]:
    """Apply the classification table. Single source of truth for outcome + severity."""
    if reason not in _REASON_OUTCOME:
        raise ValueError(f"unknown reason: {reason!r}")
    return _REASON_OUTCOME[reason], _severity(reason, kind)
```

- [ ] **Step 4: Run it, verify it passes**

Run: `uv run pytest tests/test_classification_derive.py -q`
Expected: PASS (17 cases).

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/classification.py tests/test_classification_derive.py
git commit -m "feat(classification): derive_verdict — model table as one function"
```

### Task 0.2: The `Classification` record + store

**Files:**
- Modify: `src/pkcs11_check/classification.py`
- Test: `tests/test_classification_store.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_classification_store.py
from pkcs11_check import classification as C

def test_record_get_clear_roundtrip():
    C.clear()
    rec = C.Classification(reason="nonspec_reject", outcome="xfail", severity="LOW",
                           label="ECDSA:verify", actual_ckr="CKR_DEVICE_ERROR")
    C.record(rec)
    got = C.get_records()
    assert len(got) == 1 and got[0].reason == "nonspec_reject"
    C.clear()
    assert C.get_records() == []

def test_serialize_is_json_dicts():
    rec = C.Classification(reason="crash", outcome="fail", severity="HIGH",
                           detail={"signal": "SIGSEGV"})
    out = C.serialize([rec])
    assert out[0]["reason"] == "crash" and out[0]["detail"]["signal"] == "SIGSEGV"
    assert out[0]["schema"] == 1
```

- [ ] **Step 2: Run it, verify it fails**

Run: `uv run pytest tests/test_classification_store.py -q`
Expected: FAIL — `AttributeError: module … has no attribute 'Classification'`.

- [ ] **Step 3: Implement the record + store (append to `classification.py`)**

```python
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class Classification:
    reason: str
    outcome: str
    severity: str
    kind: str | None = None
    label: str = ""
    summary: str = ""
    operation: str | None = None
    mechanism: str | None = None
    expected_ckr: list[str] | None = None
    actual_ckr: str | None = None
    spec_ref: str = ""
    source: str | None = None
    vector_id: str | None = None
    detail: dict[str, Any] | None = None
    schema: int = 1


_records: list[Classification] = []


def record(rec: Classification) -> None:
    _records.append(rec)


def get_records() -> list[Classification]:
    return list(_records)


def clear() -> None:
    _records.clear()


def serialize(records: list[Classification]) -> list[dict[str, Any]]:
    return [asdict(r) for r in records]
```

- [ ] **Step 4: Run it, verify it passes**

Run: `uv run pytest tests/test_classification_store.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/classification.py tests/test_classification_store.py
git commit -m "feat(classification): Classification record + per-test store"
```

### Task 0.3: `classify()` emit API + `xfail_as`/`fail_as`

**Files:**
- Modify: `src/pkcs11_check/classification.py`
- Test: `tests/test_classification_emit.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_classification_emit.py
import pytest
from _pytest.outcomes import Failed, XFailed
from pkcs11_check import classification as C

def test_classify_fail_records_and_raises():
    C.clear()
    with pytest.raises(Failed):
        C.classify("accepted_invalid", kind="crypto", label="RSA:decrypt",
                   operation="C_Decrypt", expected=["CKR_ENCRYPTED_DATA_INVALID"],
                   actual="CKR_OK")
    rec = C.get_records()[-1]
    assert rec.outcome == "fail" and rec.severity == "CRITICAL"
    assert rec.summary  # auto-templated, non-empty

def test_classify_xfail_records_and_raises():
    C.clear()
    with pytest.raises(XFailed):
        C.classify("nonspec_reject", label="ECDSA:verify", actual="CKR_DEVICE_ERROR")
    assert C.get_records()[-1].outcome == "xfail"

def test_classify_pass_returns_without_raising():
    C.clear()
    C.classify("sanctioned_refusal", label="ML-DSA:sign", actual="CKR_OPERATION_NOT_VALIDATED")
    assert C.get_records()[-1].outcome == "pass"

def test_explicit_summary_overrides_template():
    C.clear()
    with pytest.raises(Failed):
        C.classify("wrong_result", kind="crypto", label="x", summary="custom phrase")
    assert C.get_records()[-1].summary == "custom phrase"
```

- [ ] **Step 2: Run it, verify it fails**

Run: `uv run pytest tests/test_classification_emit.py -q`
Expected: FAIL — `AttributeError: … has no attribute 'classify'`.

- [ ] **Step 3: Implement `classify()` (append to `classification.py`)**

```python
import pytest

from pkcs11_check.raw.rv import ckr_name  # int -> "CKR_*" name


def _ckr_names(codes: object) -> list[str] | None:
    if codes is None:
        return None
    if isinstance(codes, int):
        return [ckr_name(codes)]
    return [ckr_name(c) if isinstance(c, int) else str(c) for c in codes]


def _ckr_name(code: object) -> str | None:
    if code is None:
        return None
    return ckr_name(code) if isinstance(code, int) else str(code)


def _template_summary(label: str, expected: list[str] | None, actual: str | None,
                      reason: str) -> str:
    head = label or reason
    if actual and expected:
        return f"{head}: expected {expected}, got {actual}"
    if actual:
        return f"{head}: got {actual}"
    return f"{head}: {reason}"


def classify(
    reason: str,
    *,
    kind: str | None = None,
    label: str = "",
    operation: str | None = None,
    mechanism: str | None = None,
    expected: object = None,
    actual: object = None,
    spec_ref: str | None = None,
    source: str | None = None,
    vector_id: str | None = None,
    summary: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Record a structured verdict, then drive the pytest outcome it implies."""
    outcome, severity = derive_verdict(reason, kind)
    expected_names = _ckr_names(expected)
    actual_name = _ckr_name(actual)
    if summary is None:
        summary = _template_summary(label, expected_names, actual_name, reason)
    if spec_ref is None:
        from pkcs11_check.spec_refs import lookup  # late import; table built in Task 1.1
        spec_ref = lookup(operation, mechanism, expected)
    record(Classification(
        reason=reason, outcome=outcome, severity=severity, kind=kind, label=label,
        summary=summary, operation=operation, mechanism=mechanism,
        expected_ckr=expected_names, actual_ckr=actual_name, spec_ref=spec_ref or "",
        source=source, vector_id=vector_id, detail=detail,
    ))
    if outcome == "fail":
        pytest.fail(summary)
    if outcome == "xfail":
        pytest.xfail(summary)
    # pass: return normally


def fail_as(reason: str, **kw: Any) -> None:
    """Readability wrapper; reason must map to a fail outcome."""
    classify(reason, **kw)


def xfail_as(reason: str, **kw: Any) -> None:
    """Readability wrapper; reason must map to an xfail outcome."""
    classify(reason, **kw)
```

> NOTE: if `pkcs11_check.spec_refs` does not exist yet, temporarily stub `lookup` to return
> `""`; Task 1.1 replaces it. The test above passes `spec_ref` implicitly as `None`, so either
> implement Task 1.1 first or add a 3-line stub `def lookup(*a, **k): return ""` now.

- [ ] **Step 4: Run it, verify it passes**

Run: `uv run pytest tests/test_classification_emit.py -q`
Expected: PASS (4 cases).

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/classification.py tests/test_classification_emit.py
git commit -m "feat(classification): classify() emit API + xfail_as/fail_as"
```

### Task 0.4: Plugin attach + per-item clear

**Files:**
- Modify: `src/pkcs11_check/plugin.py` (the `pytest_runtest_makereport` hook ~line 826 and the
  per-item teardown hook ~line 837 that already calls `clear_notes()`)
- Test: `tests/test_classification_plugin.py`

- [ ] **Step 1: Write the failing test (a tiny in-process pytester run)**

```python
# tests/test_classification_plugin.py
pytest_plugins = ["pytester"]

def test_classification_lands_in_user_properties(pytester):
    pytester.makepyfile(
        test_x="""
        from pkcs11_check import classification as C
        def test_emits():
            try:
                C.classify("nonspec_reject", label="probe", actual="CKR_DEVICE_ERROR")
            except Exception:
                pass
        """
    )
    result = pytester.runpytest_inprocess("-p", "pkcs11_check.plugin")
    reports = result.reprec.getreports("pytest_runtest_logreport")
    call = [r for r in reports if r.when == "call"][0]
    props = dict((k, v) for k, v in call.user_properties)
    assert "pkcs11_classification" in props
    assert props["pkcs11_classification"][0]["reason"] == "nonspec_reject"
```

- [ ] **Step 2: Run it, verify it fails**

Run: `uv run pytest tests/test_classification_plugin.py -q`
Expected: FAIL — `KeyError: 'pkcs11_classification'`.

- [ ] **Step 3: Implement attach + clear (mirror the compliance-notes code in `plugin.py`)**

In `_attach_*`-style helper near `_attach_compliance_notes_to_report` add:

```python
def _attach_classification_to_report(item: "pytest.Item", report: Any) -> None:
    """Attach structured classifications before report-log serializes them."""
    if getattr(report, "when", None) != "call":
        return
    from pkcs11_check.classification import get_records, serialize
    records = serialize(get_records())
    if not records:
        return
    props = list(getattr(report, "user_properties", []) or [])
    props = [(k, v) for (k, v) in props if k != "pkcs11_classification"]
    props.append(("pkcs11_classification", records))
    report.user_properties = props
```

In `pytest_runtest_makereport` (right after `_attach_compliance_notes_to_report(item, report)`):

```python
    _attach_classification_to_report(item, report)
```

In the existing teardown hook that calls `clear_notes()` (≈ line 843), add:

```python
    from pkcs11_check.classification import clear as clear_classifications
    clear_classifications()
```

- [ ] **Step 4: Run it, verify it passes**

Run: `uv run pytest tests/test_classification_plugin.py -q`
Expected: PASS.

- [ ] **Step 5: CI gate + commit**

```bash
uv run ruff format src tests && uv run ruff check src tests && uv run mypy src
git add src/pkcs11_check/plugin.py tests/test_classification_plugin.py
git commit -m "feat(plugin): attach pkcs11_classification to reports + clear per item"
```

---

## Phase 1: Central spec-ref table (OASIS v3.2)

### Task 1.1: `spec_refs.py`

**Files:**
- Create: `src/pkcs11_check/spec_refs.py`
- Test: `tests/test_spec_refs.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_spec_refs.py
from pkcs11_check.spec_refs import lookup

def test_lookup_by_function_is_v32_and_stable():
    ref = lookup("C_Decrypt", "CKM_RSA_PKCS", None)
    assert ref.startswith("PKCS#11 v3.2")
    assert "C_Decrypt" in ref or "RSA" in ref

def test_lookup_unknown_returns_stable_coarse_ref_never_empty_when_op_known():
    ref = lookup("C_Sign", None, None)
    assert ref.startswith("PKCS#11 v3.2")

def test_lookup_nothing_known_returns_empty():
    assert lookup(None, None, None) == ""
```

- [ ] **Step 2: Run it, verify it fails**

Run: `uv run pytest tests/test_spec_refs.py -q`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement the table**

```python
# src/pkcs11_check/spec_refs.py
"""Central PKCS#11 v3.2 spec-reference table. Never fabricate a paragraph: when no precise
section is known, return the stable coarse form (version + function/mechanism).
"""
from __future__ import annotations

_VERSION = "PKCS#11 v3.2"

# (function, mechanism) -> precise section. Populate from the local v3.2 mirror at
# /home/user/src/m/other/pkcs11/ as sections are confirmed. Keep keys conservative.
_PRECISE: dict[tuple[str | None, str | None], str] = {
    ("C_Decrypt", "CKM_RSA_PKCS"): f"{_VERSION} §6.13 (CKM_RSA_PKCS)",
    ("C_Verify", "CKM_ECDSA"): f"{_VERSION} §6.7 (CKM_ECDSA)",
    # … extend as confirmed against the mirror …
}


def lookup(function: str | None, mechanism: str | None, expected: object = None) -> str:
    if (function, mechanism) in _PRECISE:
        return _PRECISE[(function, mechanism)]
    if function and mechanism:
        return f"{_VERSION} · {function} · {mechanism}"
    if function:
        return f"{_VERSION} · {function}"
    if mechanism:
        return f"{_VERSION} · {mechanism}"
    return ""
```

- [ ] **Step 4: Run it, verify it passes**

Run: `uv run pytest tests/test_spec_refs.py -q`
Expected: PASS. Then remove the temporary `lookup` stub from Task 0.3 if one was added.

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/spec_refs.py tests/test_spec_refs.py
git commit -m "feat(spec-refs): central v3.2 reference table; never fabricate"
```

---

## Phase 2: Route the existing helpers through `classify()`

These tasks change helper internals only; their existing call sites stay valid (the helpers
gain one **optional** `kind` param, default `None` → conservative severity).

### Task 2.1: `classify_negative_rv` → `classify()`

**Files:**
- Modify: `src/pkcs11_check/testcases/conftest.py` (`classify_negative_rv`, ~line 762)
- Test: `tests/test_helper_classify_negative_rv.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_helper_classify_negative_rv.py
import pytest
from _pytest.outcomes import Failed, XFailed
from pkcs11_check import classification as C
from pkcs11_check.raw.types_std import CKR_OK, CKR_DEVICE_ERROR, CKR_SIGNATURE_INVALID
from pkcs11_check.testcases.conftest import classify_negative_rv

def test_accepted_invalid_emits_fail():
    C.clear()
    with pytest.raises(Failed):
        classify_negative_rv(CKR_OK, (CKR_SIGNATURE_INVALID,), label="verify", kind="crypto")
    assert C.get_records()[-1].reason == "accepted_invalid"

def test_nonspec_reject_emits_xfail():
    C.clear()
    with pytest.raises(XFailed):
        classify_negative_rv(CKR_DEVICE_ERROR, (CKR_SIGNATURE_INVALID,), label="verify")
    assert C.get_records()[-1].reason == "nonspec_reject"

def test_expected_code_passes_silently():
    C.clear()
    classify_negative_rv(CKR_SIGNATURE_INVALID, (CKR_SIGNATURE_INVALID,), label="verify")
    assert C.get_records() == []  # spec-correct rejection emits nothing
```

- [ ] **Step 2: Run, verify fail** — `uv run pytest tests/test_helper_classify_negative_rv.py -q` → FAIL (old signature, no emit).

- [ ] **Step 3: Reimplement the helper body**

```python
def classify_negative_rv(rv, expected_rvs, *, label, allow_ok=False, kind=None):
    from pkcs11_check import classification as C
    if rv == CKR_OK:
        if allow_ok:
            return
        C.classify("accepted_invalid", kind=kind, label=label, actual=rv,
                   expected=tuple(expected_rvs))
        return  # classify() raises; defensive
    if rv in expected_rvs:
        return
    C.classify("nonspec_reject", kind=kind, label=label, actual=rv,
               expected=tuple(expected_rvs))
```

- [ ] **Step 4: Run, verify pass.** Then run the suites that already use it:
`uv run pytest src/pkcs11_check/testcases/test_remaining_gaps.py -q` (smoke).

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/testcases/conftest.py tests/test_helper_classify_negative_rv.py
git commit -m "refactor(conftest): classify_negative_rv emits structured Classification"
```

### Task 2.2: `reject_or_classify` → `classify()`

**Files:**
- Modify: `src/pkcs11_check/testcases/conftest.py` (`reject_or_classify`, ~line 814)
- Test: `tests/test_helper_reject_or_classify.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_helper_reject_or_classify.py
import pytest
from _pytest.outcomes import Failed, XFailed
from pkcs11_check import classification as C
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_SIGNATURE_INVALID
from pkcs11_check.testcases.conftest import reject_or_classify

def test_no_exception_means_accepted_invalid_fail():
    C.clear()
    with pytest.raises(Failed):
        reject_or_classify(None, (CKR_SIGNATURE_INVALID,), label="verify", kind="crypto")
    assert C.get_records()[-1].reason == "accepted_invalid"

def test_wrong_clean_code_is_nonspec_reject_xfail():
    C.clear()
    exc = CkrAssertionError(CKR_DEVICE_ERROR)  # carries .rv
    with pytest.raises(XFailed):
        reject_or_classify(exc, (CKR_SIGNATURE_INVALID,), label="verify")
    assert C.get_records()[-1].reason == "nonspec_reject"
```

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Reimplement the helper body**

```python
def reject_or_classify(exc, expected_rvs, *, label, kind=None):
    from pkcs11_check import classification as C
    if is_known_error(exc, expected_rvs):
        return  # spec-correct rejection (existing pass path, preserved)
    if exc is None:
        C.classify("accepted_invalid", kind=kind, label=label, actual="CKR_OK",
                   expected=tuple(expected_rvs))
        return
    rv = getattr(exc, "rv", None)
    if rv is not None:
        C.classify("nonspec_reject", kind=kind, label=label, actual=rv,
                   expected=tuple(expected_rvs))
        return
    C.classify("nonspec_reject", kind=kind, label=label,
               summary=f"{label}: rejected with {type(exc).__name__}, expected {list(expected_rvs)}")
```

- [ ] **Step 4: Run, verify pass** + smoke `uv run pytest src/pkcs11_check/testcases/test_blake2.py -q`.

- [ ] **Step 5: Commit** — `refactor(conftest): reject_or_classify emits Classification`.

### Task 2.3: `classify_policy_enforcement` → `classify()` (Type B)

**Files:**
- Modify: `src/pkcs11_check/testcases/conftest.py` (~line 846)
- Test: `tests/test_helper_policy.py`

- [ ] **Step 1: Failing test**

```python
# tests/test_helper_policy.py
import pytest
from _pytest.outcomes import Failed, XFailed
from pkcs11_check import classification as C
from pkcs11_check.testcases.conftest import classify_policy_enforcement

def test_claimed_then_violated_is_self_contradiction_fail():
    C.clear()
    with pytest.raises(Failed):
        classify_policy_enforcement(claimed=True, violated=True, label="CKA_SENSITIVE")
    rec = C.get_records()[-1]
    assert rec.reason == "self_contradiction" and rec.kind == "policy"

def test_not_claimed_is_honest_deviation_xfail():
    C.clear()
    with pytest.raises(XFailed):
        classify_policy_enforcement(claimed=False, violated=False, label="CKA_SENSITIVE")
    assert C.get_records()[-1].reason == "honest_deviation"
```

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Reimplement**

```python
def classify_policy_enforcement(*, claimed, violated, label):
    from pkcs11_check import classification as C
    if claimed and not violated:
        return  # pass: protection claimed and held
    if not claimed:
        C.classify("honest_deviation", kind="policy", label=label,
                   summary=f"{label}: module does not claim the protection (honest non-support)")
        return
    C.classify("self_contradiction", kind="policy", label=label,
               summary=f"{label}: claimed the protection then violated it (self-contradiction)")
```

- [ ] **Step 4: Run, verify pass** + smoke `uv run pytest src/pkcs11_check/testcases/test_remaining_gaps.py -q`.

- [ ] **Step 5: Commit** — `refactor(conftest): classify_policy_enforcement emits Classification`.

### Task 2.4: `classify_lifecycle_effect` → `classify()` (Type C)

**Files:**
- Modify: `src/pkcs11_check/testcases/conftest.py` (~line 867)
- Test: `tests/test_helper_lifecycle.py`

- [ ] **Step 1: Failing test**

```python
# tests/test_helper_lifecycle.py
import pytest
from _pytest.outcomes import Failed, XFailed
from pkcs11_check import classification as C
from pkcs11_check.testcases.conftest import classify_lifecycle_effect

def test_success_then_contradicted_is_self_contradiction_fail():
    C.clear()
    with pytest.raises(Failed):
        classify_lifecycle_effect(claimed_success=True, effect_observed=True, label="destroy")
    rec = C.get_records()[-1]
    assert rec.reason == "self_contradiction" and rec.kind == "lifecycle"

def test_no_success_claim_is_honest_deviation_xfail():
    C.clear()
    with pytest.raises(XFailed):
        classify_lifecycle_effect(claimed_success=False, effect_observed=False, label="destroy")
    assert C.get_records()[-1].reason == "honest_deviation"
```

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Reimplement the helper body**

```python
def classify_lifecycle_effect(*, claimed_success, effect_observed, label):
    from pkcs11_check import classification as C
    if claimed_success and not effect_observed:
        return  # pass: success claimed and honored
    if not claimed_success:
        C.classify("honest_deviation", kind="lifecycle", label=label,
                   summary=f"{label}: prior operation did not claim success")
        return
    C.classify("self_contradiction", kind="lifecycle", label=label,
               summary=f"{label}: success claimed then contradicted (self-contradiction)")
```

- [ ] **Step 4: Run, verify pass.**

- [ ] **Step 5: Commit** — `refactor(conftest): classify_lifecycle_effect emits Classification`.

### Task 2.5: `assert_ckr` / `CkrExpectation` → emit a `Classification`

**Files:**
- Modify: `src/pkcs11_check/testcases/ckr/_ckr_spec.py` (`assert_ckr`, ~line 211)
- Test: `tests/test_assert_ckr_emits.py`

- [ ] **Step 1: Failing test**

```python
# tests/test_assert_ckr_emits.py
import pytest
from _pytest.outcomes import Failed, XFailed
from pkcs11_check import classification as C
from pkcs11_check.raw.types_std import CKR_OK, CKR_DEVICE_ERROR, CKR_DATA_INVALID
from pkcs11_check.testcases.ckr._ckr_spec import CkrExpectation, assert_ckr

EXP = CkrExpectation(function="C_Decrypt", condition="malformed_ct",
                     spec_ckr=CKR_DATA_INVALID, compat_tuple=(CKR_DATA_INVALID,),
                     spec_ref="PKCS#11 v3.2 §6.13", kind="crypto")

def test_accept_is_fail_accepted_invalid():
    C.clear()
    with pytest.raises(Failed):
        assert_ckr(EXP, CKR_OK, strict=False)
    rec = C.get_records()[-1]
    assert rec.reason == "accepted_invalid" and rec.kind == "crypto"
    assert rec.spec_ref == "PKCS#11 v3.2 §6.13"

def test_nonspec_clean_code_is_xfail():
    C.clear()
    with pytest.raises(XFailed):
        assert_ckr(EXP, CKR_DEVICE_ERROR, strict=False)
    assert C.get_records()[-1].reason == "nonspec_reject"
```

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Reimplement `assert_ckr`'s decision points** to call `classify()` with the
`CkrExpectation` fields (`function` → `operation`, `condition` → `label`, `spec_ckr` →
`expected`, `kind`, `spec_ref`). Map: `CKR_OK` and not `allow_success` → `accepted_invalid`;
`actual in spec_codes` → return (pass); `actual in full_compat` but not spec → `nonspec_reject`;
`actual not in full_compat` → `accepted_invalid` is wrong here — it is still a clean code, so
emit `nonspec_reject` (undefined/vendor codes keep the existing fail-on-undefined behaviour via
`kind` unchanged). Preserve `allow_success` + the `CKR_OPERATION_NOT_VALIDATED` →
`sanctioned_refusal` path (advertised-capability-honesty refinement).

- [ ] **Step 4: Run, verify pass** + smoke a ckr file: `uv run pytest src/pkcs11_check/testcases/ckr/test_ckr_verify.py -q`.

- [ ] **Step 5: CI gate + commit** — `refactor(ckr): assert_ckr emits structured Classification`.

---

## Phase 3: Provenance stamping in vector loaders

### Task 3.1: Wycheproof loader stamps `source` + `vector_id`

**Files:**
- Modify: `src/pkcs11_check/testcases/wycheproof/wycheproof_loader.py` (`load_vectors`)
- Test: `tests/test_wycheproof_provenance.py`

- [ ] **Step 1: Failing test**

```python
# tests/test_wycheproof_provenance.py
from pkcs11_check.testcases.wycheproof.wycheproof_loader import load_vectors

def test_vectors_carry_source_and_vector_id():
    vs = load_vectors("aes_gcm_test.json")
    assert vs and vs[0]["_source"] == "wycheproof:aes_gcm_test.json"
    assert vs[0]["_vector_id"] == f"tcId={vs[0]['tcId']}"
```

- [ ] **Step 2: Run, verify fail** (keys absent).

- [ ] **Step 3: In `load_vectors`, after building each test dict, stamp:**

```python
        test["_source"] = f"wycheproof:{filename}"
        test["_vector_id"] = f"tcId={test.get('tcId')}"
```

- [ ] **Step 4: Run, verify pass.**

- [ ] **Step 5: Commit** — `feat(wycheproof): stamp source/vector_id on loaded vectors`.

### Task 3.2: ACVP loader stamps provenance

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/acvp_loader.py` (`load_acvp_vectors`)
- Test: `tests/test_acvp_provenance.py`

- [ ] **Step 1: Failing test** — assert a merged vector has `_source` like `acvp:<algorithm>` and
`_vector_id` like `tcId=<n>` (use an algorithm known to load, e.g. the one used by
`test_acvp_eddsa.py`).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3:** stamp `merged["_source"] = f"acvp:{algorithm}"` and
`merged["_vector_id"] = f"tcId={merged.get('tc_id')}"` in the merge loop.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `feat(acvp): stamp source/vector_id on loaded vectors`.

### Task 3.3: x509 limbo loader stamps `source`/`vector_id` (best-effort)

**Files:**
- Modify: `src/pkcs11_check/testcases/x509/conftest.py` (`load_limbo_testcases`)
- Test: `tests/test_x509_provenance.py`

- [ ] **Step 1: Failing test** — assert each limbo case dict gains `_source="x509:limbo.json"` and
`_vector_id=f"id={tc['id']}"`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3:** stamp the two keys when loading limbo testcases.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `feat(x509): stamp provenance on limbo testcases`.

---

## Phase 4: `assert_correct()` for crypto KAT bare asserts

### Task 4.1: Add `assert_correct()` helper

**Files:**
- Modify: `src/pkcs11_check/testcases/conftest.py`
- Test: `tests/test_assert_correct.py`

- [ ] **Step 1: Failing test**

```python
# tests/test_assert_correct.py
import pytest
from _pytest.outcomes import Failed
from pkcs11_check import classification as C
from pkcs11_check.testcases.conftest import assert_correct

def test_mismatch_is_wrong_result_crypto_fail():
    C.clear()
    with pytest.raises(Failed):
        assert_correct(actual=b"\x01", expected=b"\x02", label="AES-KDF KAT",
                       operation="C_DeriveKey", mechanism="CKM_SP800_108_COUNTER_KDF")
    rec = C.get_records()[-1]
    assert rec.reason == "wrong_result" and rec.kind == "crypto" and rec.severity == "CRITICAL"

def test_match_passes_silently():
    C.clear()
    assert_correct(actual=b"\x01", expected=b"\x01", label="KAT")
    assert C.get_records() == []
```

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement**

```python
def assert_correct(*, actual, expected, label, operation=None, mechanism=None,
                   source=None, vector_id=None):
    """KAT correctness check: equal values pass; a mismatch is wrong_result (crypto)."""
    from pkcs11_check import classification as C
    if actual == expected:
        return
    C.classify("wrong_result", kind="crypto", label=label, operation=operation,
               mechanism=mechanism, source=source, vector_id=vector_id,
               summary=f"{label}: output does not match known answer")
```

- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `feat(conftest): assert_correct for KAT correctness`.

---

## Phase 5: Coverage gates

### Task 5.1: Runtime unclassified gate

**Files:**
- Modify: `src/pkcs11_check/plugin.py` (`_attach_classification_to_report`)
- Test: `tests/test_unclassified_gate.py`

- [ ] **Step 1: Failing test**

```python
# tests/test_unclassified_gate.py
pytest_plugins = ["pytester"]

def test_raw_fail_gets_synthetic_unclassified(pytester):
    pytester.makepyfile(test_x="""
        import pytest
        def test_raw():
            pytest.fail("legacy raw fail")
    """)
    result = pytester.runpytest_inprocess("-p", "pkcs11_check.plugin")
    call = [r for r in result.reprec.getreports("pytest_runtest_logreport") if r.when=="call"][0]
    props = dict(call.user_properties)
    assert props["pkcs11_classification"][0]["reason"] == "unclassified"
```

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Extend `_attach_classification_to_report`** so that when the report outcome is
`failed` or an xfail (skipped with `XFailed`) **and** `get_records()` is empty, inject a synthetic
record: `Classification(reason="unclassified", outcome="fail", severity="HIGH",
summary=<report longrepr message>, detail={"raw": True})`, serialized as the property value.

- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `feat(plugin): synthetic unclassified record for un-migrated outcomes`.

### Task 5.2: Static gate meta-test with shrinking allowlist

**Files:**
- Create: `tests/test_no_raw_xfail_fail.py`
- Create: `tests/_raw_site_allowlist.py` (the 140 not-yet-migrated files)

- [ ] **Step 1: Generate the initial allowlist**

```bash
uv run python - <<'PY'
import subprocess, pathlib
root = "src/pkcs11_check/testcases"
out = subprocess.check_output(
    ["grep","-rlE",r"pytest\.(xfail|fail)\(", root, "--include=*.py"], text=True).split()
skip = {"conftest.py", "_ckr_spec.py"}
files = sorted(f for f in out if pathlib.Path(f).name not in skip)
body = "ALLOWLIST = {\n" + "".join(f"    {f!r},\n" for f in files) + "}\n"
pathlib.Path("tests/_raw_site_allowlist.py").write_text(
    '"""Files still containing raw pytest.xfail/fail. SHRINKS to empty as Phase 7 migrates.\n'
    'When empty, the static gate is fully hard."""\n' + body)
print(f"allowlisted {len(files)} files")
PY
```

- [ ] **Step 2: Write the gate test**

```python
# tests/test_no_raw_xfail_fail.py
import re, subprocess, pathlib
from tests._raw_site_allowlist import ALLOWLIST

ROOT = "src/pkcs11_check/testcases"
SANCTIONED = {"conftest.py", "_ckr_spec.py"}

def _files_with_raw_sites():
    out = subprocess.run(["grep","-rlE",r"pytest\.(xfail|fail)\(",ROOT,"--include=*.py"],
                         capture_output=True, text=True).stdout.split()
    return {f for f in out if pathlib.Path(f).name not in SANCTIONED}

def test_no_raw_sites_outside_allowlist():
    offenders = _files_with_raw_sites() - set(ALLOWLIST)
    assert not offenders, f"raw pytest.xfail/fail must use classify(): {sorted(offenders)}"

def test_allowlist_has_no_stale_entries():
    stale = set(ALLOWLIST) - _files_with_raw_sites()
    assert not stale, f"migrated files still in allowlist — remove them: {sorted(stale)}"
```

- [ ] **Step 3: Run, verify pass** (both tests green at the start: every raw-site file is
allowlisted, no stale entries).

Run: `uv run pytest tests/test_no_raw_xfail_fail.py -q` → PASS.

- [ ] **Step 4: Commit** — `test(gate): static raw-site gate with shrinking allowlist (140 files)`.

---

## Phase 6: Runner-side crash records

### Task 6.1: `file_runner` emits crash as a `Classification`-shaped dict

**Files:**
- Modify: `src/pkcs11_check/core/file_runner.py` (`_status_from_returncode` / crash recording)
- Test: `tests/test_crash_record_shape.py`

- [ ] **Step 1: Failing test** — call the (small, pure) helper that builds a crash record from a
`returncode` and target, assert it returns:

```python
# tests/test_crash_record_shape.py
from pkcs11_check.core.file_runner import crash_classification

def test_sigsegv_crash_record():
    rec = crash_classification(returncode=-11, target="x/test_y.py")
    assert rec["reason"] == "crash" and rec["outcome"] == "fail"
    assert rec["severity"] == "HIGH" and rec["detail"]["signal"] == "SIGSEGV"

def test_timeout_record():
    rec = crash_classification(returncode=None, target="x/test_y.py", timed_out=True)
    assert rec["detail"]["mode"] == "timeout"
```

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Add a pure helper**

```python
_SIGNALS = {-11: "SIGSEGV", -6: "SIGABRT", -5: "SIGTRAP", -4: "SIGILL", -8: "SIGFPE"}

def crash_classification(*, returncode, target, timed_out=False):
    detail = {"mode": "timeout"} if timed_out else {
        "signal": _SIGNALS.get(returncode, f"signal{abs(returncode)}" if returncode else "?"),
        "returncode": returncode,
    }
    return {"schema": 1, "reason": "crash", "outcome": "fail", "severity": "HIGH",
            "kind": None, "label": target, "summary": f"{target}: process crashed",
            "operation": None, "mechanism": None, "expected_ckr": None, "actual_ckr": None,
            "spec_ref": "", "source": None, "vector_id": None, "detail": detail}
```

Then call it where crashed units are recorded so the crash JSON carries this shape.

- [ ] **Step 4: Run, verify pass** + smoke a known-crashing isolated run if available.
- [ ] **Step 5: Commit** — `feat(runner): crash records in Classification shape`.

---

## Phase 7: The big-bang site migration (fan-out)

**608 raw sites across 140 files** (276 `pytest.fail` + 332 `pytest.xfail`). This phase is a
mechanical, parallelizable migration governed by the static gate (Task 5.2). **Use
superpowers:subagent-driven-development** — one subagent per file (batch small files), each
applying the recipe below, then the reviewer removes the file from `ALLOWLIST` and commits.

### The migration recipe (apply per file)

- [ ] **Step A: Read the test file.** For each `pytest.fail(msg)` / `pytest.xfail(msg)`, read the
surrounding code to determine *what the module did*.

- [ ] **Step B: Pick `reason` + `kind` from the message + context using this decision table:**

| Site context | → `reason` | `kind` |
|---|---|---|
| positive op returned CKR_OK but value/KAT wrong (`assert out == expected` style failing) | `wrong_result` | crypto (or metadata for non-crypto values) |
| invalid/forbidden input accepted (`pytest.fail("…accepted…/must reject")`) | `accepted_invalid` | crypto / policy / lifecycle / metadata per the op |
| claimed protection then violated; claimed success then no/!effect; two attrs contradict | `self_contradiction` | policy / lifecycle / metadata |
| distinguishable error-code/timing leak (`pytest.fail("…oracle…/non-uniform…")`) | `oracle` | crypto |
| advertised op cleanly errored (`pytest.xfail("…advertised but not operational…")`) | `not_operational` | crypto (omit if unclear) |
| negative op rejected with a non-spec clean code (`pytest.xfail("rejected with … expected …")`) | `nonspec_reject` | omit/crypto |
| optional protection unenforced / isolated wrong metadata / harmless no-op (`pytest.xfail`) | `honest_deviation` | policy / metadata |
| `CKR_OPERATION_NOT_VALIDATED` clean refusal | `sanctioned_refusal` | — |
| the *harness/binding* refused before the module ran; vector unrepresentable | `pytest.skip(...)` with reason (NOT classify) | — |

- [ ] **Step C: Replace the call.** Examples:

```python
# before
pytest.fail("RSA PKCS#1 decrypt accepted invalid ciphertext")
# after
from pkcs11_check.classification import classify
classify("accepted_invalid", kind="crypto", label="RSA:decrypt",
         operation="C_Decrypt", mechanism="CKM_RSA_PKCS",
         expected=("CKR_ENCRYPTED_DATA_INVALID",), actual="CKR_OK")
```

```python
# before
pytest.xfail(f"ECDSA:key-import: advertised but not operational ({ckr_name(rv)})")
# after
classify("not_operational", kind="crypto", label="ECDSA:key-import",
         operation="C_CreateObject", mechanism="CKM_EC_KEY_PAIR_GEN", actual=rv)
```

For data-driven tests, pass provenance through from the stamped vector:
`source=vec.get("_source"), vector_id=vec.get("_vector_id")`.

- [ ] **Step D: Migrate crypto-KAT bare asserts in this file too** (priority subset): replace
`assert produced == expected` with `assert_correct(actual=produced, expected=expected,
label=…, operation=…, mechanism=…, source=…, vector_id=…)`.

- [ ] **Step E: Remove this file from `tests/_raw_site_allowlist.py`.**

- [ ] **Step F: Run the file's own tests** (against the mock provider, fast):
`uv run pytest <that file> -q` — confirm no collection/import errors and outcomes are sane.

- [ ] **Step G: Run the static gate** to confirm no regression and the allowlist is consistent:
`uv run pytest tests/test_no_raw_xfail_fail.py -q`.

- [ ] **Step H: Commit** — `refactor(testcases): migrate <file> to classify() [N sites]`.

### Batching guidance

- Group the 140 files by suite (`security/`, `ckr/`, `wycheproof/`, `acvp/`, `x509/`, core).
  Dispatch one subagent per file or per small cluster; the reviewer verifies the reason/kind
  choices (this is where the human/agent judgement that the regex lacked now lives).
- After each batch, run the full gate set. The `ALLOWLIST` shrinks monotonically; **Phase 9
  asserts it is empty.**
- Do NOT introduce `pytest.skip` to dodge a real finding — skip is only for genuine
  capability-absence or harness-staging failure (recipe Step B last row).

---

## Phase 8: The report generator

### Task 8.1: `extract.py` — report.jsonl + crashes → grouped records

**Files:**
- Create: `tools/report/extract.py`
- Test: `tests/test_report_extract.py`

- [ ] **Step 1: Failing test**

```python
# tests/test_report_extract.py
import json
from tools.report.extract import extract_groups

def test_groups_by_structured_key(tmp_path):
    rl = tmp_path / "report.jsonl"
    rows = [
        {"$report_type":"TestReport","when":"call","nodeid":"a.py::t1","outcome":"failed",
         "user_properties":[["pkcs11_classification",[{"reason":"accepted_invalid","kind":"crypto",
            "outcome":"fail","severity":"CRITICAL","operation":"C_Decrypt","mechanism":"CKM_RSA_PKCS",
            "expected_ckr":["CKR_ENCRYPTED_DATA_INVALID"],"actual_ckr":"CKR_OK","summary":"x",
            "spec_ref":"PKCS#11 v3.2 §6.13","source":"wycheproof:rsa_test.json","vector_id":"tcId=8"}]]]},
        {"$report_type":"TestReport","when":"call","nodeid":"a.py::t2","outcome":"failed",
         "user_properties":[["pkcs11_classification",[{"reason":"accepted_invalid","kind":"crypto",
            "outcome":"fail","severity":"CRITICAL","operation":"C_Decrypt","mechanism":"CKM_RSA_PKCS",
            "expected_ckr":["CKR_ENCRYPTED_DATA_INVALID"],"actual_ckr":"CKR_OK","summary":"x",
            "spec_ref":"PKCS#11 v3.2 §6.13","source":"wycheproof:rsa_test.json","vector_id":"tcId=9"}]]]},
    ]
    rl.write_text("\n".join(json.dumps(r) for r in rows))
    groups = extract_groups(rl, crashes=[])
    assert len(groups) == 1
    g = groups[0]
    assert g["count"] == 2 and g["severity"] == "CRITICAL"
    assert g["test_file"] == "a.py" and g["reason"] == "accepted_invalid"
    assert "tcId=8" in g["vector_ids"] and "tcId=9" in g["vector_ids"]
```

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement** — read `report.jsonl`, pull `pkcs11_classification` from
`user_properties`, group by the readable key
`(test_file, reason, kind, mechanism, operation, tuple(expected_ckr), actual_ckr)`; accumulate
`count`, sample `nodeids` (first 5), `vector_ids`, `sources`; merge the `crashes` list (already
`Classification`-shaped) as their own groups. Return a list of group dicts.

- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `feat(report): extract grouped records from report.jsonl`.

### Task 8.2: `render.py` — grouped records → capped `<provider>.md`

**Files:**
- Create: `tools/report/render.py`
- Test: `tests/test_report_render.py`

- [ ] **Step 1: Failing test** — feed two groups (one CRITICAL fail, one big xfail bucket of
count 24000) to `render_provider("kryoptic-main", groups)` and assert:
  - severity-first ordering (CRITICAL section before deviations);
  - the xfail bucket is **collapsed** to a single count-line (the 24000 nodeids are NOT all
    listed) — assert `output.count("\n") < 60` (size budget);
  - exact values present: `CKR_OK`, `CKM_RSA_PKCS`, `PKCS#11 v3.2`, the `tcId`s;
  - no `sha1` substring; the `kind` letter alias `(Type A)` present for a crypto fail.

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement** the compact-enriched layout from the spec: header counts line;
`━━ <emoji> <SEVERITY> · fail (n) ━━` sections grouped by `kind`; each finding a `[count]`-prefixed
line + an indented `want … · got … · <spec_ref> · <source> <vector_ids…>` line, top-N per group
with `+N more → .jsonl`; deviations/xfails collapsed to one line per `(reason,kind)`; compliance
+ unclassified + harness-skip one-liners. Render the `kind`→letter alias
(`crypto→A, policy→B, lifecycle→C, metadata→D`).

- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `feat(report): compact-enriched per-provider markdown renderer`.

### Task 8.3: `correlate.py` + `__main__.py` — `_index.md`, `_universal.md`, `.jsonl`, enrichment

**Files:**
- Create: `tools/report/correlate.py`, `tools/report/__main__.py`
- Test: `tests/test_report_correlate.py`

- [ ] **Step 1: Failing test** — given grouped records for 3 providers where the same
`(reason,kind,mechanism)` appears in all 3, assert `correlate(...)` flags it as a universal theme
with `providers==3`; and given a `module-issues.md` snippet, assert a matching group is tagged
`category="KNOWN_ISSUE"`; a fail with no match → `category="PROVIDER_BUG"`,
`routing="PROVIDER_REPORT"`.

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement** `correlate()` (group by `(reason,kind,mechanism)` across providers →
themes + single-provider outliers), `enrich()` (default category/routing from outcome; re-tag
`KNOWN_ISSUE` by matching `module-issues.md` on mechanism/operation/kind; annotate
`SOFT_TOKEN_CAVEAT` for the padding-oracle classes; mark `HARNESS_BUG` candidate when a finding is
identical across all providers), and `__main__.py` that writes per-provider `.md` + `.jsonl`,
`_index.md`, `_universal.md`. Per-provider `.jsonl` = one line per group.

- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `feat(report): cross-provider correlation + index/universal + enrichment`.

### Task 8.4: Golden report test (locks format + size budget)

**Files:**
- Create: `tests/fixtures/report/mini_report.jsonl`, `tests/fixtures/report/expected_provider.md`
- Create: `tests/test_report_golden.py`

- [ ] **Step 1:** write a small fixed `mini_report.jsonl` (≈10 records spanning every `reason`).
- [ ] **Step 2:** run the generator, save output as `expected_provider.md`, eyeball it for the
compact-enriched layout + size budget, commit it as the golden.
- [ ] **Step 3:** test asserts generator output == golden.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `test(report): golden per-provider report fixture`.

---

## Phase 9: Final gate flip + validation

### Task 9.1: Assert the allowlist is empty (static gate fully hard)

- [ ] **Step 1: Confirm migration complete**

```bash
uv run python -c "from tests._raw_site_allowlist import ALLOWLIST; print(len(ALLOWLIST))"
```
Expected: `0`. If non-zero, return to Phase 7 for the remaining files.

- [ ] **Step 2: Add the final assertion to `tests/test_no_raw_xfail_fail.py`**

```python
def test_allowlist_is_empty():
    from tests._raw_site_allowlist import ALLOWLIST
    assert not ALLOWLIST, "migration incomplete — files remain in the raw-site allowlist"
```

- [ ] **Step 3: Run, verify pass.**
- [ ] **Step 4: Commit** — `test(gate): raw-site allowlist empty — static gate fully hard`.

### Task 9.2: Full-suite validation against the mock provider + a real soft-token

- [ ] **Step 1:** run the suite producing a report log against `pkcs11-mock` and `softhsm2`:

```bash
PKCS11_CHECK_REPORT_LOG=/tmp/r.jsonl uv run pkcs11-check test --module <mock> ; \
  uv run python -m tools.report --report-log /tmp/r.jsonl --provider mock --out /tmp/rep
```

- [ ] **Step 2:** assert zero `reason=="unclassified"` in `/tmp/r.jsonl`:

```bash
uv run python -c "import json;print(sum(1 for l in open('/tmp/r.jsonl') if (r:=json.loads(l)).get('\$report_type')=='TestReport' for k,v in (r.get('user_properties') or []) if k=='pkcs11_classification' for c in v if c['reason']=='unclassified'))"
```
Expected: `0`. If non-zero, those nodeids are the migration backlog — fix them.

- [ ] **Step 3:** eyeball `/tmp/rep/mock.md` for the compact-enriched layout + size.
- [ ] **Step 4: Full CI gate set:**

```bash
uv run ruff format --check . && uv run ruff check . && uv run mypy src && uv run pytest tests/ -q
```

- [ ] **Step 5: Commit** any fixups — `chore: at-source classification full-suite validation`.

### Task 9.3: Docs + CLAUDE.md pointer

- [ ] **Step 1:** add a short "At-source classification" subsection to `docs/architecture.md`
linking the spec + this plan; update `docs/classification-model-design.md` to note `kind` is the
canonical field (A/B/C/D are display aliases) and the 9-reason vocabulary.
- [ ] **Step 2:** add a one-line note to `CLAUDE.md` under the classification-model section that
tests emit via `classify()` (no raw `pytest.xfail/fail` in `testcases/`).
- [ ] **Step 3: Commit** — `docs: document at-source classification model + reason vocabulary`.

---

## Self-Review Checklist (run before declaring complete)

- [ ] Every `reason` in the spec's 9-value vocabulary has a `derive_verdict` row + a producer
  (helper, `assert_ckr`, `assert_correct`, runner, or a migrated raw site).
- [ ] `kind` letter aliases (A/B/C/D) appear only in the **renderer**, never as a stored field.
- [ ] No raw `pytest.xfail(`/`pytest.fail(` under `testcases/` outside the sanctioned modules
  (static gate green; allowlist empty).
- [ ] Zero `unclassified` records in a full mock run.
- [ ] Crashes appear as `reason=crash` with a signal/mode `detail`.
- [ ] Provenance (`source`/`vector_id`) present on Wycheproof + ACVP findings.
- [ ] `spec_ref` is v3.2 everywhere; never an invented paragraph.
- [ ] Per-provider `.md` stays within the size budget (golden test) and shows exact values, no
  `sha1`.
- [ ] Full CI gate set passes.

---

## Execution Handoff

Two execution options:

1. **Subagent-Driven (recommended)** — a fresh subagent per task, reviewed between tasks. Best
   here: Phases 0–6 and 8 are TDD infrastructure tasks ideal for single-shot subagents, and
   **Phase 7's 140-file migration is a natural fan-out** — one subagent per file applying the
   recipe, the reviewer checking each `reason`/`kind` choice (the judgement the old regex
   lacked) and removing the file from the allowlist. Uses superpowers:subagent-driven-development.
2. **Inline Execution** — execute tasks in-session with checkpoints (superpowers:executing-plans).
   Best if you want to interleave review tightly with the migration decisions.
