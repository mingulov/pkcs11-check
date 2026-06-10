# Advertised-Capability Honesty Package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the spec `docs/superpowers/specs/2026-06-10-advertised-capability-honesty-design.md`: claim-layer 3-way mapping in `test_mech_*` (CKR_OPERATION_NOT_VALIDATED → pass+note, other clean CKR → xfail, allowlists retired), shared not-operational reason constant, registry coverage meta-check, vacuous-reject downgrade in probe-wired runners (with SigVer/PSS three-state precondition), and classification-model doc amendments.

**Architecture:** Two new helpers in `_operability.py` (`not_operational_reason`, `xfail_vacuous_reject`) plus a new small module `_capability_claims.py` (`claim_refusal_passes`) carry all new classification logic; test files only rewire call sites. The SigVer/PSS bool probes are migrated onto the existing `probe_operability` cache so INCONCLUSIVE staging failures never trigger the vacuous downgrade.

**Tech Stack:** Python 3.13, pytest, ctypes binding (`pkcs11_check.raw`), uv, ruff, mypy --strict. ALWAYS prefix commands with `uv run`. Meta-tests (tests of the harness itself) live in `tests/`; product test cases live in `src/pkcs11_check/testcases/`.

**Git:** Work on a feature branch off `dev`; merge back to `dev` (NEVER `main`):
```bash
cd /home/user/src/m/pkcs11-check
git checkout dev && git checkout -b fix/advertised-capability-honesty
```

**Conventions that apply to every task:** type annotations on all public functions; line length 100; no bare `except Exception`; after each task run the CI gates:
```bash
uv run ruff format src tests && uv run ruff check src tests && uv run mypy src
```

---

### Task 1: `not_operational_reason` + `xfail_vacuous_reject` helpers in `_operability.py`

**Files:**
- Modify: `src/pkcs11_check/testcases/_operability.py`
- Test: `tests/test_operability_vacuous_reject.py` (create)

- [ ] **Step 1: Write the failing meta-tests**

Create `tests/test_operability_vacuous_reject.py`:

```python
"""Meta-tests: shared not-operational reason + vacuous-reject downgrade helper.

A negative-op vector "rejected" by a mechanism whose canonical probe says
NOT_OPERATIONAL was never evaluated -- recording it as pass asserts conformance
that was not tested. xfail_vacuous_reject downgrades exactly that case; all
other probe verdicts leave the legacy pass untouched.
"""

from __future__ import annotations

import pytest

from pkcs11_check.testcases._operability import (
    Operability,
    OperabilityResult,
    not_operational_reason,
    xfail_vacuous_reject,
)


def test_not_operational_reason_wording() -> None:
    """Canonical wording matches the existing classify_kat_clean_error message."""
    assert (
        not_operational_reason("AES_CCM:decrypt", "canonical rejected")
        == "AES_CCM:decrypt: advertised but not operational (canonical rejected)"
    )


def test_vacuous_reject_not_operational_xfails() -> None:
    result = OperabilityResult(Operability.NOT_OPERATIONAL, "canonical CCM decrypt rejected")
    with pytest.raises(pytest.xfail.Exception, match="vacuous reject"):
        xfail_vacuous_reject(result, label="tc42: AES_CCM decrypt")


@pytest.mark.parametrize(
    "status",
    [Operability.OPERATIONAL, Operability.INCONCLUSIVE, Operability.WRONG_OUTPUT],
)
def test_vacuous_reject_other_verdicts_return(status: Operability) -> None:
    """OPERATIONAL/INCONCLUSIVE/WRONG_OUTPUT: rejection of invalid input stays a pass."""
    xfail_vacuous_reject(OperabilityResult(status, "detail"), label="tc42: AES_CCM decrypt")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_operability_vacuous_reject.py -v`
Expected: FAIL — `ImportError: cannot import name 'not_operational_reason'`

- [ ] **Step 3: Implement the helpers**

In `src/pkcs11_check/testcases/_operability.py`, add after `reset_operability_cache()` (line ~91):

```python
def not_operational_reason(probe_key: str, detail: str) -> str:
    """Canonical advertised-but-not-operational wording, shared across suites.

    One wording per (mechanism, operation) probe key lets report readers group
    the claim-layer signal with its corroborating per-vector xfails.
    """
    return f"{probe_key}: advertised but not operational ({detail})"


def xfail_vacuous_reject(result: OperabilityResult, *, label: str) -> None:
    """Downgrade a negative-op "rejection" on a NOT_OPERATIONAL mechanism.

    The module refuses everything, so the invalid input was never evaluated;
    counting the rejection as pass asserts conformance that was never tested
    (gap-analysis leak 1). Returns normally for every other verdict --
    OPERATIONAL rejections are genuine passes and INCONCLUSIVE (staging
    failure, no mechanism evidence) keeps legacy rules.
    """
    if result.status is Operability.NOT_OPERATIONAL:
        pytest.xfail(
            f"{label}: vacuous reject -- mechanism not operational "
            f"({result.detail}); input never evaluated"
        )
```

Then route the existing message in `classify_kat_clean_error` through the constant — replace (line ~111):

```python
        pytest.xfail(f"{label}: advertised but not operational ({result.detail}); vector: {exc}")
```

with:

```python
        pytest.xfail(f"{not_operational_reason(label, result.detail)}; vector: {exc}")
```

- [ ] **Step 4: Run tests to verify they pass (plus existing operability meta-tests for no regression)**

Run: `uv run pytest tests/test_operability_vacuous_reject.py tests/ -k operability -v`
Expected: all PASS (wording is byte-identical, so existing pinned messages keep passing)

- [ ] **Step 5: CI gates + commit**

```bash
uv run ruff format src tests && uv run ruff check src tests && uv run mypy src
git add src/pkcs11_check/testcases/_operability.py tests/test_operability_vacuous_reject.py
git commit -m "feat(operability): shared not_operational_reason + xfail_vacuous_reject helpers"
```

---

### Task 2: claim-layer module `_capability_claims.py`

**Files:**
- Create: `src/pkcs11_check/testcases/_capability_claims.py`
- Test: `tests/test_capability_claims.py` (create)

- [ ] **Step 1: Write the failing meta-tests**

Create `tests/test_capability_claims.py`. Follow the established fake-rs pattern from `tests/test_ecdsa_prehash_operability_classification.py` (SimpleNamespace rs, `CkrAssertionError(msg, int(rv))`):

```python
"""Meta-tests: claim-layer verdict for advertised-but-refused (mech, op) roundtrips.

PKCS#11 v3.2 defines CKR_OPERATION_NOT_VALIDATED for validation-policy refusal
of an advertised operation -- the one spec-sanctioned refusal channel that does
not contradict the advertisement. Sanctioned refusal -> the claim test PASSES
with a compliance note; any other clean CKR -> xfail (advertised but not
operational, no CKR allowlist); non-CKR -> harness bug, propagates.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_OPERATION_NOT_VALIDATED
from pkcs11_check.testcases import _capability_claims as cc


@pytest.fixture(autouse=True)
def _fresh_validation_cache() -> None:
    cc.reset_validation_object_cache()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def _notes_spy(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ComplianceLevel]]:
    captured: list[tuple[str, ComplianceLevel]] = []

    def fake_note(description: str, level: ComplianceLevel, reference: str = "") -> None:
        captured.append((description, level))

    monkeypatch.setattr(cc.compliance, "note", fake_note)
    return captured


def test_sanctioned_refusal_returns_true_and_notes(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _notes_spy(monkeypatch)
    monkeypatch.setattr(cc, "_validation_objects_present", lambda rs: True)
    exc = CkrAssertionError(
        "Unexpected CK_RV CKR_OPERATION_NOT_VALIDATED", int(CKR_OPERATION_NOT_VALIDATED)
    )
    assert cc.claim_refusal_passes(exc, _rs(), probe_key="CKM_ECDSA_SHA1:sign") is True
    assert len(captured) == 1
    description, level = captured[0]
    assert "CKR_OPERATION_NOT_VALIDATED" in description
    assert "CKM_ECDSA_SHA1:sign" in description
    assert level is ComplianceLevel.STANDARD


def test_other_clean_ckr_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _notes_spy(monkeypatch)
    exc = CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))
    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        cc.claim_refusal_passes(exc, _rs(), probe_key="CKM_ECDSA_SHA1:sign")


def test_non_ckr_assertion_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wrong-output asserts and harness bugs must never be classified."""
    _notes_spy(monkeypatch)
    exc = AssertionError("verify returned False after valid sign")
    with pytest.raises(AssertionError, match="verify returned False"):
        cc.claim_refusal_passes(exc, _rs(), probe_key="CKM_ECDSA_SHA1:sign")


def test_validation_object_probe_failure_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enumeration refusal must not crash the verdict -- presence is just 'None'."""

    def boom(*_a: Any, **_k: Any) -> list[int]:
        raise AssertionError("C_FindObjectsInit failed: CKR_ATTRIBUTE_TYPE_INVALID")

    monkeypatch.setattr(cc, "find_objects", boom)
    assert cc._validation_objects_present(_rs()) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_capability_claims.py -v`
Expected: FAIL — module `_capability_claims` does not exist

- [ ] **Step 3: Implement the module**

Create `src/pkcs11_check/testcases/_capability_claims.py`. Mirror the CKO_VALIDATION enumeration imports used by `src/pkcs11_check/testcases/test_validation_objects.py` (`template`, `attr_ulong`, `find_objects` — copy that file's exact import paths):

```python
"""Claim-layer verdict for advertised-but-refused (mechanism, operation) roundtrips.

The test_mech_* registry suites are the per-(mechanism, operation) claim layer:
their roundtrip IS the canonical operation for the advertised capability
(C_GetMechanismList + CK_MECHANISM_INFO flags). A clean refusal of that
roundtrip is classified here:

- CKR_OPERATION_NOT_VALIDATED  the v3.2 spec-sanctioned validation-policy
  refusal; does not contradict the advertisement -> the test PASSES and a
  compliance note records the policy refusal (and whether the token exposes
  CKO_VALIDATION objects -- capability-based, no provider identity).
- any other clean CKR          advertised but not operational -> xfail with
  the shared not_operational_reason wording. No CKR allowlist (model
  positive-op row; same rationale as _operability.classify_kat_clean_error).
- non-CKR exception            wrong-output assert or harness bug -> re-raise.

Design: docs/superpowers/specs/2026-06-10-advertised-capability-honesty-design.md.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check import compliance
from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.raw.recipes import attr_ulong, find_objects, template
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKO_VALIDATION,
    CKR_OPERATION_NOT_VALIDATED,
)
from pkcs11_check.testcases._operability import not_operational_reason

# Cached once per process: whether the token exposes CKO_VALIDATION objects
# (None = the token refused enumeration of that class).
_VALIDATION_CACHE: dict[str, bool | None] = {}


def reset_validation_object_cache() -> None:
    """Test hook: forget the cached CKO_VALIDATION presence."""
    _VALIDATION_CACHE.clear()


def _validation_objects_present(rs: Any) -> bool | None:
    if "present" not in _VALIDATION_CACHE:
        try:
            tmpl = template(attr_ulong(CKA_CLASS, CKO_VALIDATION))
            _VALIDATION_CACHE["present"] = bool(find_objects(rs.raw, rs.sh, tmpl))
        except AssertionError:
            _VALIDATION_CACHE["present"] = None
    return _VALIDATION_CACHE["present"]


def claim_refusal_passes(exc: AssertionError, rs: Any, *, probe_key: str) -> bool:
    """Classify a clean refusal of an advertised (mechanism, operation) roundtrip.

    Returns True for the spec-sanctioned validation-policy refusal
    (CKR_OPERATION_NOT_VALIDATED): the caller must end the test immediately
    (``return``) so it records as PASS; the compliance note carries the
    evidence. Otherwise xfails (any clean CKR) or re-raises (non-CKR).
    """
    rv = getattr(exc, "rv", None)
    if not isinstance(exc, CkrAssertionError) or rv is None:
        raise exc
    if rv == int(CKR_OPERATION_NOT_VALIDATED):
        present = _validation_objects_present(rs)
        compliance.note(
            f"{probe_key}: refused via sanctioned CKR_OPERATION_NOT_VALIDATED "
            f"(validation-policy refusal; CKO_VALIDATION objects present: {present})",
            ComplianceLevel.STANDARD,
            reference="PKCS#11 v3.2 CKR_OPERATION_NOT_VALIDATED / Sec. 4.15",
        )
        return True
    pytest.xfail(not_operational_reason(probe_key, ckr_name(rv)))
```

If `attr_ulong`/`template`/`find_objects` live elsewhere than `pkcs11_check.raw.recipes`, copy the exact imports from `test_validation_objects.py` — do not invent new wrappers.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_capability_claims.py -v`
Expected: 5 PASS

- [ ] **Step 5: CI gates + commit**

```bash
uv run ruff format src tests && uv run ruff check src tests && uv run mypy src
git add src/pkcs11_check/testcases/_capability_claims.py tests/test_capability_claims.py
git commit -m "feat(claims): claim-layer verdict helper -- OPERATION_NOT_VALIDATED pass+note, no CKR allowlist"
```

---

### Task 3: wire `test_mech_sign.py` to the claim layer

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_sign.py`
- Test: `tests/test_mech_sign_claim_classification.py` (create)

- [ ] **Step 1: Write the failing meta-tests**

Create `tests/test_mech_sign_claim_classification.py` (same monkeypatch style as `tests/test_ecdsa_prehash_operability_classification.py`):

```python
"""Meta-tests: test_mech_sign roundtrip routes refusals through the claim layer.

Sanctioned policy refusal -> PASS (+note); any other clean CKR -> xfail
(allowlist retired: previously-unlisted clean codes now xfail too); wrong
output and non-CKR errors still fail/propagate.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_OPERATION_NOT_VALIDATED,
    CKR_SESSION_HANDLE_INVALID,
)
from pkcs11_check.testcases import _capability_claims as cc
from pkcs11_check.testcases import test_mech_sign as tms


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def _entry() -> SimpleNamespace:
    return SimpleNamespace(
        mech_id=0x1,
        mech_name="CKM_TEST_SIGN",
        config=SimpleNamespace(input_constraint=None, param_recipe=None),
    )


def _wire(monkeypatch: pytest.MonkeyPatch, *, sign: Any, verify: Any = lambda *a, **k: True) -> None:
    monkeypatch.setattr(tms, "generate_key_for_sign", lambda *a, **k: (1, 2))
    monkeypatch.setattr(tms, "make_mech_param_or_skip", lambda entry: None)
    monkeypatch.setattr(tms, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(tms, "sign_single", sign)
    monkeypatch.setattr(tms, "verify_single", verify)


def _raise(rv: int, name: str) -> Any:
    def _f(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError(f"Unexpected CK_RV {name}", int(rv))

    return _f


def test_sanctioned_sign_refusal_passes_with_note(monkeypatch: pytest.MonkeyPatch) -> None:
    notes: list[str] = []
    monkeypatch.setattr(
        cc.compliance, "note", lambda d, level, reference="": notes.append(d)
    )
    _wire(
        monkeypatch,
        sign=_raise(int(CKR_OPERATION_NOT_VALIDATED), "CKR_OPERATION_NOT_VALIDATED"),
    )
    tms.TestMechSignRoundtrip().test_roundtrip(_rs(), _entry())  # no exception = PASS
    assert notes and "CKR_OPERATION_NOT_VALIDATED" in notes[0]


def test_unlisted_clean_ckr_now_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Allowlist retirement pinned: SESSION_HANDLE_INVALID was NOT in
    _SIGN_RUNTIME_REJECT_RVS and used to hard-fail; the model's positive-op
    row says any clean refusal is an honest deviation -> xfail."""
    _wire(
        monkeypatch,
        sign=_raise(int(CKR_SESSION_HANDLE_INVALID), "CKR_SESSION_HANDLE_INVALID"),
    )
    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        tms.TestMechSignRoundtrip().test_roundtrip(_rs(), _entry())


def test_verify_false_still_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, sign=lambda *a, **k: b"sig", verify=lambda *a, **k: False)
    with pytest.raises(AssertionError, match="verify failed"):
        tms.TestMechSignRoundtrip().test_roundtrip(_rs(), _entry())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_mech_sign_claim_classification.py -v`
Expected: first two FAIL (sanctioned raises xfail today via allowlist? No — OPERATION_NOT_VALIDATED is NOT in `_SIGN_RUNTIME_REJECT_RVS`, so it re-raises = FAIL; unlisted-code test FAILs with the raised CkrAssertionError). Third may already pass.

- [ ] **Step 3: Rewire the call sites**

In `src/pkcs11_check/testcases/test_mech_sign.py`:

1. Add import: `from pkcs11_check.testcases._capability_claims import claim_refusal_passes`
2. DELETE `_SIGN_RUNTIME_REJECT_RVS` (lines 70-83) and `_xfail_sign_runtime_reject` (lines 105-110); remove now-unused CKR imports flagged by ruff (keep ones still used by `_KAT_IMPORT_CAPABILITY_REJECT_RVS`).
3. Transform EVERY `_xfail_sign_runtime_reject(exc, entry, <op>)` call site. Find them: `grep -n "_xfail_sign_runtime_reject" src/pkcs11_check/testcases/test_mech_sign.py` (4 sites: roundtrip sign line ~154, roundtrip verify ~166, tampered sign ~200, plus the KAT sites with "KAT sign"/"KAT verify"). Each becomes (shown for roundtrip sign; the op string and surrounding code stay as-is at each site):

```python
            except AssertionError as exc:
                if claim_refusal_passes(exc, rs, probe_key=f"{entry.mech_name}:sign"):
                    return
```

Notes per site: the op suffix is the old operation argument with spaces replaced (`"sign"`, `"verify"`, `"KAT sign"` → `"kat-sign"`, `"KAT verify"` → `"kat-verify"`). In `_run_asymmetric_sign_kat` (a helper, not a test method) `return` ends the helper — the calling test then completes as PASS, which is the intended verdict; cleanup is in `finally` blocks and still runs.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_mech_sign_claim_classification.py tests/ -k mech_sign -v`
Expected: all PASS

- [ ] **Step 5: CI gates + commit**

```bash
uv run ruff format src tests && uv run ruff check src tests && uv run mypy src
git add -A && git commit -m "feat(claims): test_mech_sign claim-layer 3-way mapping; retire _SIGN_RUNTIME_REJECT_RVS"
```

---

### Task 4: wire `test_mech_encrypt.py` and `test_mech_digest.py`

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_encrypt.py`, `src/pkcs11_check/testcases/test_mech_digest.py`
- Test: `tests/test_mech_encrypt_claim_classification.py` (create)

- [ ] **Step 1: Write failing meta-tests** — same shape as Task 3 (copy its file as a template): fake `mech_encrypt_entry`, monkeypatch `encrypt_single`/`decrypt_single` in `test_mech_encrypt` (and `digest_single` in `test_mech_digest`); assert sanctioned→pass+note, unlisted clean CKR (use `CKR_SESSION_HANDLE_INVALID`)→xfail, wrong-output assert still fails. For digest, also assert the `None` early-return: a sanctioned refusal makes the calling test return before comparing digests.

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_mech_encrypt_claim_classification.py -v` — Expected: FAIL

- [ ] **Step 3: Rewire**

`test_mech_encrypt.py`: delete `_ENCRYPT_RUNTIME_REJECT_RVS` (lines 58-70). Every site found by `grep -n "xfail_if_known_ckr" src/pkcs11_check/testcases/test_mech_encrypt.py` (2 sites: encrypt, decrypt) becomes:

```python
        except AssertionError as exc:
            if claim_refusal_passes(exc, rs, probe_key=f"{entry.mech_name}:encrypt"):
                return
```

(op suffix `:decrypt` at the decrypt site.)

`test_mech_digest.py`: `_digest_or_xfail` returns `bytes` and cannot end the test, so change its signature to `bytes | None` where `None` = sanctioned refusal:

```python
def _digest_or_xfail(rs: RawSession, entry: MechEntry, data: bytes) -> bytes | None:
    """Digest, or classify a clean refusal at the claim layer.

    Returns None for the sanctioned validation-policy refusal -- callers must
    end the test (PASS; the compliance note carries the evidence).
    """
    try:
        return digest_single(rs.raw, rs.sh, CKM(entry.mech_id), data)
    except AssertionError as exc:
        if claim_refusal_passes(exc, rs, probe_key=f"{entry.mech_name}:digest"):
            return None
        raise AssertionError("unreachable") from exc  # claim_refusal_passes xfails/raises
```

Delete `_DIGEST_RUNTIME_REJECT_RVS`. Every caller (`grep -n "_digest_or_xfail" …`) adds immediately after the call:

```python
        if d is None:
            return
```

(binding the result to a local first if the call was inline).

- [ ] **Step 4: Verify** — `uv run pytest tests/test_mech_encrypt_claim_classification.py -v` and the full meta-suite `uv run pytest tests/ -x -q` — Expected: PASS

- [ ] **Step 5: CI gates + commit**

```bash
uv run ruff format src tests && uv run ruff check src tests && uv run mypy src
git add -A && git commit -m "feat(claims): test_mech_encrypt/digest claim-layer mapping; retire allowlists"
```

---

### Task 5: wire the remaining `test_mech_*` suites

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_derive.py` (`_DERIVE_RUNTIME_REJECT_RVS` lines 91-113), `test_mech_wrap.py` (`_WRAP_RUNTIME_REJECT_RVS` lines 89-114), `test_mech_multipart.py` (`_MULTIPART_RUNTIME_REJECT_RVS` lines 60-84), `test_mech_lifecycle.py` (`_RSA_OAEP_RUNTIME_REJECT_RVS` lines 104-119), `test_mech_sign_recover.py` (`_SIGN_RECOVER_REJECT_RVS` line 33), `test_mech_kem.py` (`_KEM_OP_REJECT_RVS` line 43)
- Test: extend `tests/test_mech_encrypt_claim_classification.py` with one sanctioned-pass + one unlisted-xfail case per suite (parametrize over (module, entry-fixture-shape, monkeypatched op) where practical)

- [ ] **Step 1: Write failing meta-tests** — minimum: sanctioned→pass and unlisted-clean-CKR→xfail for `test_mech_derive` and `test_mech_wrap` (the two with the most distinct flow); the rest are covered by the identical helper.

- [ ] **Step 2: Verify RED** — `uv run pytest tests/test_mech_encrypt_claim_classification.py -v`

- [ ] **Step 3: Rewire each file with the SAME transformation as Tasks 3-4:**

For each file: delete the `*_RUNTIME_REJECT_RVS` tuple and its `_xfail_*` helper; every call site (find with `grep -n "_xfail_derive_runtime_reject\|_xfail_wrap_runtime_reject\|_xfail_multipart_runtime_reject\|RUNTIME_REJECT_RVS\|_REJECT_RVS" src/pkcs11_check/testcases/test_mech_derive.py src/pkcs11_check/testcases/test_mech_wrap.py src/pkcs11_check/testcases/test_mech_multipart.py src/pkcs11_check/testcases/test_mech_lifecycle.py src/pkcs11_check/testcases/test_mech_sign_recover.py src/pkcs11_check/testcases/test_mech_kem.py`) becomes:

```python
        except AssertionError as exc:
            if claim_refusal_passes(exc, rs, probe_key=f"{entry.mech_name}:<op>"):
                return
```

`<op>` per site: derive→`derive`; wrap phases→`wrap`/`unwrap`; multipart→`multipart-<operation>` (operation is the existing argument); lifecycle OAEP→`encrypt`; sign_recover→`sign-recover`; kem→`encapsulate`/`decapsulate` matching the existing site labels. CAREFUL per site:
- If the site is inside a helper function (not the test), apply the `bytes | None` early-return pattern from Task 4's `_digest_or_xfail` instead.
- `conftest.py`'s `CIPHER_OP_RUNTIME_REJECT_RVS` itself is NOT deleted — other non-claim suites (e.g. `test_twofish.py`) still use it; only the `test_mech_*` aliases/call sites change.
- Do NOT touch `_KAT_IMPORT_CAPABILITY_REJECT_RVS`-style setup/import tuples — setup-stage refusals keep their existing helpers (spec scope boundary).

- [ ] **Step 4: Verify** — `uv run pytest tests/ -x -q` — Expected: PASS

- [ ] **Step 5: CI gates + commit**

```bash
uv run ruff format src tests && uv run ruff check src tests && uv run mypy src
git add -A && git commit -m "feat(claims): remaining test_mech_* suites on claim-layer mapping; retire per-suite allowlists"
```

---

### Task 6: three-state SigVer probe (`acvp/test_acvp_rsa.py`)

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_rsa.py` (lines 219-307)
- Test: `tests/test_sigver_probe_three_state.py` (create)

- [ ] **Step 1: Write the failing meta-tests**

```python
"""Meta-tests: SigVer canonical probe is three-state, not bool.

bool collapsed canonical STAGING failure (public-key import refused) into
"not operational", which would let the vacuous-reject downgrade fire with no
mechanism evidence. Three-state: import failure -> INCONCLUSIVE; canonical
verify refusal/False -> NOT_OPERATIONAL; verify True -> OPERATIONAL.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR
from pkcs11_check.testcases._operability import Operability, reset_operability_cache
from pkcs11_check.testcases.acvp import test_acvp_rsa as mod


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    reset_operability_cache()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def _wire(monkeypatch: pytest.MonkeyPatch, *, import_key: Any, verify: Any) -> None:
    monkeypatch.setattr(mod, "import_rsa_public_key_negotiated", import_key)
    monkeypatch.setattr(mod, "verify_single", verify)
    monkeypatch.setattr(mod, "destroy_quietly", lambda *a, **k: None)
    # one canonical valid vector for the probe to find
    monkeypatch.setattr(
        mod,
        "_PKCS15_VER",
        [
            (
                "canon",
                {
                    "mech_name": "SHA1_RSA_PKCS",
                    "mech_int": 6,
                    "expected_pass": True,
                    "n": b"\x01" * 256,
                    "e": b"\x01\x00\x01",
                    "message": b"m",
                    "signature": b"s",
                },
            )
        ],
    )


def test_import_failure_is_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse_import(*_a: Any, **_k: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    _wire(monkeypatch, import_key=refuse_import, verify=lambda *a, **k: True)
    result = mod._pkcs15_sigver_operability(_rs(), "SHA1_RSA_PKCS", 2048)
    assert result.status is Operability.INCONCLUSIVE


def test_verify_refusal_is_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse_verify(*_a: Any, **_k: Any) -> bool:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    _wire(monkeypatch, import_key=lambda *a, **k: 7, verify=refuse_verify)
    result = mod._pkcs15_sigver_operability(_rs(), "SHA1_RSA_PKCS", 2048)
    assert result.status is Operability.NOT_OPERATIONAL


def test_verify_true_is_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, import_key=lambda *a, **k: 7, verify=lambda *a, **k: True)
    result = mod._pkcs15_sigver_operability(_rs(), "SHA1_RSA_PKCS", 2048)
    assert result.status is Operability.OPERATIONAL


def test_no_canonical_vector_is_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, import_key=lambda *a, **k: 7, verify=lambda *a, **k: True)
    result = mod._pkcs15_sigver_operability(_rs(), "SHA256_RSA_PKCS", 4096)
    assert result.status is Operability.INCONCLUSIVE
```

- [ ] **Step 2: Verify RED** — `uv run pytest tests/test_sigver_probe_three_state.py -v` — FAIL (`_pkcs15_sigver_operability` undefined)

- [ ] **Step 3: Implement**

Replace `_PKCS15_SIGVER_OPERATIONAL` dict + `_pkcs15_sigver_operational` (lines 226-261) with a `probe_operability`-cached three-state version:

```python
def _pkcs15_sigver_operability(rs: Any, mech_name: str, key_bits: int) -> OperabilityResult:
    """Canonical (mech, key-bits) SigVer probe: imported public key + single verify.

    INCONCLUSIVE when staging fails (import refused / no canonical vector) --
    no mechanism evidence either way; NOT_OPERATIONAL when the canonical
    known-valid vector is refused or verifies False; OPERATIONAL on True.
    """

    def probe() -> OperabilityResult:
        for _vec_id, vec in _PKCS15_VER:
            if (
                vec["mech_name"] != mech_name
                or not vec["expected_pass"]
                or len(vec["n"]) * 8 != key_bits
            ):
                continue
            pub_key = 0
            try:
                try:
                    pub_key = import_rsa_public_key_negotiated(
                        rs, n=vec["n"], e=vec["e"], attrs={CKA_VERIFY: True}
                    )
                except AssertionError as exc:
                    return OperabilityResult(
                        Operability.INCONCLUSIVE, f"canonical public-key import failed: {exc}"
                    )
                try:
                    ok = verify_single(
                        rs.raw, rs.sh, pub_key, vec["mech_int"], vec["message"], vec["signature"]
                    )
                except AssertionError as exc:
                    return OperabilityResult(
                        Operability.NOT_OPERATIONAL, f"canonical verify rejected: {exc}"
                    )
                if not ok:
                    return OperabilityResult(
                        Operability.NOT_OPERATIONAL, "canonical known-valid vector verifies False"
                    )
                return OperabilityResult(Operability.OPERATIONAL, "canonical verify OK")
            finally:
                destroy_quietly(rs.raw, rs.sh, pub_key)
        return OperabilityResult(
            Operability.INCONCLUSIVE, f"no canonical valid vector for {mech_name}/{key_bits}"
        )

    return probe_operability(f"PKCS15_SIGVER:{mech_name}:{key_bits}", probe)
```

Add imports: `from pkcs11_check.testcases._operability import Operability, OperabilityResult, probe_operability`.

Update the valid-vector consumer (lines 297-305) — behavior-preserving (the old bool `False` covered both new non-OPERATIONAL states):

```python
            if expected_pass and not verified:
                key_bits = len(vec["n"]) * 8
                result = _pkcs15_sigver_operability(rs, mech_name, key_bits)
                if result.status is not Operability.OPERATIONAL:
                    pytest.xfail(
                        f"{vec_id}: {mech_name} canonical known-valid ACVP vector for "
                        f"{key_bits}-bit imported keys does not verify ({result.detail}) "
                        "-- advertised but not operational"
                    )
                pytest.fail(f"{vec_id}: rejected VALID signature")
```

Mirror the same probe/consumer update in `test_rsa_pss_verify` if it calls `_pkcs15_sigver_operational` (check with grep; update identically).

- [ ] **Step 4: Verify** — `uv run pytest tests/test_sigver_probe_three_state.py tests/ -x -q` — PASS

- [ ] **Step 5: CI gates + commit**

```bash
uv run ruff format src tests && uv run ruff check src tests && uv run mypy src
git add -A && git commit -m "feat(probes): ACVP SigVer probe three-state via probe_operability (staging != not-operational)"
```

---

### Task 7: three-state PSS combo probe (`wycheproof/test_wycheproof_rsa_pss.py`)

**Files:**
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py` (lines 120-181, 454-460)
- Test: `tests/test_pss_combo_probe_three_state.py` (create)

- [ ] **Step 1: Write failing meta-tests** — copy Task 6's file shape; monkeypatch `gen_rsa_keypair` / `sign_single` / `verify_single` in the pss module. Cases: keypair-gen refusal → INCONCLUSIVE ("staging"); sign refusal → NOT_OPERATIONAL (the PSS combo itself refused); verify refusal or False → NOT_OPERATIONAL; roundtrip True → OPERATIONAL. Use `reset_operability_cache()` autouse fixture.

- [ ] **Step 2: Verify RED** — `uv run pytest tests/test_pss_combo_probe_three_state.py -v`

- [ ] **Step 3: Implement**

Replace `_PSS_COMBO_OPERATIONAL` dict + `_pss_combo_operational` + `_probe_pss_combo` (lines 120-181) with:

```python
def _pss_combo_operability(
    rs: Any, mechanism: int, hash_mech: int, mgf: int, salt_len: int
) -> OperabilityResult:
    """Self-roundtrip probe for a (mech, hash, mgf, sLen) PSS combo.

    Keypair generation is staging (plain RSA keygen, no PSS involved) -- its
    failure is INCONCLUSIVE, not mechanism evidence. A sign/verify refusal or
    verify-False IS combo evidence -> NOT_OPERATIONAL. Cached per combo via
    probe_operability.
    """

    def probe() -> OperabilityResult:
        pub = priv = 0
        try:
            try:
                pub, priv = gen_rsa_keypair(
                    rs.raw,
                    rs.sh,
                    2048,
                    private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
                    public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
                )
            except AssertionError as exc:
                return OperabilityResult(
                    Operability.INCONCLUSIVE, f"RSA-2048 keypair staging failed: {exc}"
                )
            pss_param = mech_pss(mechanism, hash_mech=hash_mech, mgf=mgf, salt_len=salt_len)
            try:
                sig = sign_single(
                    rs.raw, rs.sh, priv, mechanism, _PSS_PROBE_MESSAGE, mech_param=pss_param
                )
            except AssertionError as exc:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, f"canonical PSS sign rejected: {exc}"
                )
            try:
                ok = verify_single(
                    rs.raw, rs.sh, pub, mechanism, _PSS_PROBE_MESSAGE, sig, mech_param=pss_param
                )
            except AssertionError as exc:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, f"canonical PSS verify rejected: {exc}"
                )
            if not ok:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, "own PSS signature verifies False"
                )
            return OperabilityResult(Operability.OPERATIONAL, "self-roundtrip OK")
        finally:
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)
            if pub:
                destroy_quietly(rs.raw, rs.sh, pub)

    return probe_operability(
        f"RSA_PSS_COMBO:{mechanism}:{hash_mech}:{mgf}:{salt_len}", probe
    )
```

Update the valid-vector consumer (lines 454-460), behavior-preserving:

```python
    if result == "valid" and not verified:
        combo = _pss_combo_operability(rs, mechanism, hash_mech, mgf, s_len)
        if combo.status is not Operability.OPERATIONAL:
            pytest.xfail(
                f"Valid {vec_id} rejected; sign+verify roundtrip with the same "
                f"(mech, hash, mgf, sLen={s_len}) is not operational ({combo.detail})"
            )
        pytest.fail(f"Valid RSA-PSS sig {vec_id} rejected by module")
```

Update any other `_pss_combo_operational` callers identically (grep for them).

- [ ] **Step 4: Verify** — `uv run pytest tests/test_pss_combo_probe_three_state.py tests/ -x -q` — PASS

- [ ] **Step 5: CI gates + commit**

```bash
uv run ruff format src tests && uv run ruff check src tests && uv run mypy src
git add -A && git commit -m "feat(probes): PSS combo probe three-state via probe_operability"
```

---

### Task 8: vacuous-reject downgrade — AEAD, wrap, wycheproof-CCM

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/aes/base_runner_aead.py` (GCM line ~276, CCM line ~430), `src/pkcs11_check/testcases/acvp/aes/test_wrap.py` (KW line ~244, KWP line ~371), `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py` (CCM invalid branch, the `return` after the `result == "valid"` classify block near line 448)
- Test: `tests/test_vacuous_reject_downgrade.py` (create)

Scope note (spec-conformant): only branches with a canonical probe verdict in scope are downgraded. `base_cts.py` / `test_xts.py` ACVP runners have no negative vectors (no `test_passed` branch — verify with grep, then note it in the commit message). The wycheproof CMAC/GMAC/XTS reject branches have NO probe in scope → out of scope (legacy), only the probe-wired CCM path changes.

- [ ] **Step 1: Write the failing meta-tests**

```python
"""Meta-tests: invalid-vector rejections on NOT_OPERATIONAL mechanisms xfail.

tpm2 records 135 SHA-1 SigVer invalid-vector "passes" while rejecting all 27
valid vectors; bouncyhsm CCM records thousands. Those rejections are vacuous
(input never evaluated) -- gap-analysis leak 1, Denis-endorsed downgrade.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_ENCRYPTED_DATA_INVALID, CKR_GENERAL_ERROR
from pkcs11_check.testcases._operability import reset_operability_cache
from pkcs11_check.testcases.acvp.aes import base_runner_aead as aead


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    reset_operability_cache()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: True)


def _vec_invalid_gcm() -> dict[str, Any]:
    return {
        "tag_len_bits": 128,
        "iv": b"\x00" * 12,
        "aad": b"",
        "ct": b"\x00" * 16,
        "tag": b"\x00" * 16,
        "pt_expected": b"",
        "test_passed": False,
    }


def _wire_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(aead, "_import_aes_key", lambda *a, **k: 7)
    monkeypatch.setattr(aead, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(aead, "decrypt_single", refuse)


def test_gcm_invalid_reject_on_dead_mech_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire_not_operational(monkeypatch)  # canonical probe will also refuse -> NOT_OPERATIONAL
    with pytest.raises(pytest.xfail.Exception, match="vacuous reject"):
        aead.run_gcm_decrypt_test(_rs(), "tc-inv", _vec_invalid_gcm())


def test_gcm_invalid_reject_on_live_mech_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """OPERATIONAL mechanism rejecting an invalid tag stays a genuine pass."""
    calls = {"n": 0}

    def reject_vector_only(_raw: Any, _sh: int, _key: int, _mech: Any, ct: bytes, **kw: Any) -> bytes:
        calls["n"] += 1
        if calls["n"] == 1:  # the vector under test
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID", int(CKR_ENCRYPTED_DATA_INVALID)
            )
        return aead.PROBE_PT  # the canonical probe decrypt succeeds

    monkeypatch.setattr(aead, "_import_aes_key", lambda *a, **k: 7)
    monkeypatch.setattr(aead, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(aead, "decrypt_single", reject_vector_only)
    monkeypatch.setattr(aead, "encrypt_single", lambda *a, **k: aead.PROBE_PT)
    aead.run_gcm_decrypt_test(_rs(), "tc-inv", _vec_invalid_gcm())  # returns = PASS
```

NOTE: the second test's probe staging may differ — read `_canonical_aead_probe` (base_runner_aead.py lines ~80-127) and adjust the monkeypatched canonical path so the probe returns OPERATIONAL (e.g. also patch `aead.PROBE_PT`-related encrypt/decrypt as the probe drives them). The assertion that matters: no xfail raised.

- [ ] **Step 2: Verify RED** — `uv run pytest tests/test_vacuous_reject_downgrade.py -v` — first test FAILs (no xfail raised today; the function returns)

- [ ] **Step 3: Implement the five insertions**

Import in each file: `from pkcs11_check.testcases._operability import xfail_vacuous_reject` (extend the existing `_operability` import lists).

`base_runner_aead.py` GCM (lines 275-277):

```python
            if is_known_error(exc, _GCM_DATA_REJECTS):
                if not test_passed:
                    xfail_vacuous_reject(
                        _aead_operability(rs, "AES_GCM", "decrypt"),
                        label=f"{vec_id}: AES_GCM decrypt invalid-tag reject",
                    )
                    return
```

`base_runner_aead.py` CCM (lines 429-431) — same insertion with `_aead_operability(rs, "AES_CCM", "decrypt")` and label `f"{vec_id}: AES_CCM decrypt invalid-tag reject"`.

`test_wrap.py` KW (lines 244-246):

```python
                if not test_passed:
                    xfail_vacuous_reject(
                        _wrap_operability(rs, "AES_KEY_WRAP", "decrypt"),
                        label=f"{vec_id}: AES_KEY_WRAP invalid-ciphertext reject",
                    )
                    return  # module correctly rejected invalid ciphertext
```

`test_wrap.py` KWP (lines 371-373) — same with `"AES_KEY_WRAP_KWP"`.

`wycheproof/test_wycheproof_aes.py` CCM: in the decrypt `except` handler (lines ~431-448), the final `# acceptable: reject of an invalid vector is fine` / `return` becomes:

```python
        # invalid vector rejected -- genuine only if CCM decrypt actually works
        xfail_vacuous_reject(
            _ccm_operability(rs, "AES_CCM", "decrypt"), label=f"AES-CCM {vec_id} invalid reject"
        )
        return
```

(Only for `AssertionError` instances — keep the `TypeError`/`NotImplementedError` flow returning as before; guard with `isinstance(exc, AssertionError)` matching the existing valid-path guard.)

- [ ] **Step 4: Verify** — `uv run pytest tests/test_vacuous_reject_downgrade.py tests/ -x -q` — PASS. Also confirm CTS/XTS have no negative vectors: `grep -n "test_passed" src/pkcs11_check/testcases/acvp/aes/base_cts.py src/pkcs11_check/testcases/acvp/aes/test_xts.py` → expect no hits.

- [ ] **Step 5: CI gates + commit**

```bash
uv run ruff format src tests && uv run ruff check src tests && uv run mypy src
git add -A && git commit -m "feat(classify): vacuous-reject downgrade in probe-wired AEAD/wrap/wycheproof-CCM runners"
```

---

### Task 9: vacuous-reject downgrade — ACVP SigVer + PSS invalid paths

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_rsa.py` (`test_rsa_pkcs15_verify`, lines ~293-305), `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py` (invalid-branch `return`, lines ~432-452)
- Test: extend `tests/test_vacuous_reject_downgrade.py`

- [ ] **Step 1: Write failing meta-tests** — two cases mirroring Task 8: (a) invalid SigVer vector + verify-refusal + canonical probe NOT_OPERATIONAL → xfail "vacuous reject"; (b) same with probe INCONCLUSIVE (import refused) → NO xfail, test passes (the downgrade must not fire without mechanism evidence). Monkeypatch as in Task 6.

- [ ] **Step 2: Verify RED**

- [ ] **Step 3: Implement**

`test_acvp_rsa.py` — in `test_rsa_pkcs15_verify`, after the existing accepted-invalid check, add the explicit vacuous branch:

```python
            if not expected_pass and verified:
                pytest.fail(f"{vec_id}: ACCEPTED INVALID signature - security concern")
            if not expected_pass and not verified:
                key_bits = len(vec["n"]) * 8
                xfail_vacuous_reject(
                    _pkcs15_sigver_operability(rs, mech_name, key_bits),
                    label=f"{vec_id}: {mech_name} invalid-signature reject",
                )
```

(import `xfail_vacuous_reject` from `_operability`). Apply the same pattern in `test_rsa_pss_verify` if it has an invalid-vector path with a probe (grep; if its probe is the Task 7 PSS combo, use that).

`test_wycheproof_rsa_pss.py` — the invalid-branch terminal `return` (after the accepted-invalid handling, line ~452) becomes:

```python
    if result == "invalid":
        ...existing accepted-invalid handling unchanged...
        xfail_vacuous_reject(
            _pss_combo_operability(rs, mechanism, hash_mech, mgf, s_len),
            label=f"{vec_id}: invalid-PSS reject",
        )
        return
```

- [ ] **Step 4: Verify** — `uv run pytest tests/test_vacuous_reject_downgrade.py tests/ -x -q` — PASS

- [ ] **Step 5: CI gates + commit**

```bash
uv run ruff format src tests && uv run ruff check src tests && uv run mypy src
git add -A && git commit -m "feat(classify): vacuous-reject downgrade for SigVer/PSS invalid vectors (probe-gated, INCONCLUSIVE-safe)"
```

---

### Task 10: registry coverage meta-check

**Files:**
- Create: `src/pkcs11_check/testcases/test_mech_coverage.py`
- Test: `tests/test_mech_coverage_metacheck.py` (create)

- [ ] **Step 1: Write the failing meta-test**

```python
"""Meta-test: the coverage check notes advertised-but-unregistered mechanisms."""

from __future__ import annotations

import pytest

from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.testcases.mechanism_catalog import MechanismCatalog, MechEntry
from pkcs11_check.testcases import test_mech_coverage as cov


def test_unregistered_entries_produce_notes(monkeypatch: pytest.MonkeyPatch) -> None:
    notes: list[str] = []
    monkeypatch.setattr(
        cov.compliance, "note", lambda d, level, reference="": notes.append(d)
    )
    catalog = MechanismCatalog(
        {
            0x80000001: MechEntry(
                mech_id=0x80000001,
                mech_name="CKM_VENDOR_THING",
                flags=0x800,
                min_key_size=0,
                max_key_size=0,
                config=None,
            )
        }
    )
    cov._note_registry_blind_spots(catalog)
    assert len(notes) == 1 and "CKM_VENDOR_THING" in notes[0] and "no registry config" in notes[0]
```

- [ ] **Step 2: Verify RED** — `uv run pytest tests/test_mech_coverage_metacheck.py -v`

- [ ] **Step 3: Implement**

Create `src/pkcs11_check/testcases/test_mech_coverage.py`:

```python
"""Registry coverage meta-check (gap-analysis Q2 gap #1).

An advertised mechanism with no registry entry gets no per-(mechanism,
operation) operability verdict from the test_mech_* claim layer. That is a
HARNESS blind spot, not a module deviation -- this test always passes and
makes each blind spot visible as a compliance note, so missing coverage can
never be mistaken for verified conformance.
"""

from __future__ import annotations

import pytest

from pkcs11_check import compliance
from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.fixtures import RawSession
from pkcs11_check.plugin import _ensure_mechanism_catalog
from pkcs11_check.testcases.mechanism_catalog import MechanismCatalog

pytestmark = [pytest.mark.mechanism_coverage]


def _note_registry_blind_spots(catalog: MechanismCatalog) -> int:
    unregistered = catalog.filter_unregistered()
    for entry in unregistered:
        compliance.note(
            f"{entry.mech_name} (0x{entry.mech_id:08x}) advertised but has no mechanism-registry "
            "config -- no per-(mechanism, operation) operability verdict exists (harness blind "
            "spot, not a module deviation)",
            ComplianceLevel.STANDARD,
            reference="docs/findings/advertised-not-operational-gap-analysis.md Q2",
        )
    return len(unregistered)


class TestMechanismRegistryCoverage:
    def test_advertised_mechanisms_have_registry_coverage(
        self, request: pytest.FixtureRequest, p11_module_session: RawSession
    ) -> None:
        """Diff C_GetMechanismList x CK_MECHANISM_INFO flags against the registry."""
        catalog = _ensure_mechanism_catalog(request.config)
        if catalog is None:
            pytest.skip("No mechanism catalog (module mechanisms not enumerated)")
        blind_spots = _note_registry_blind_spots(catalog)
        # Always passes: registration gaps are harness work (registry Phases B-D),
        # surfaced via notes. The count in the assertion message aids report reading.
        assert blind_spots >= 0
```

If `_ensure_mechanism_catalog` cannot be imported from `pkcs11_check.plugin` (check its actual module), use the same accessor `pytest_generate_tests` uses (grep `_ensure_mechanism_catalog` to find its home) — do not build a second catalog path.

- [ ] **Step 4: Verify** — `uv run pytest tests/test_mech_coverage_metacheck.py -v` PASS; also run the product test against the local mock/softhsm2 if configured: `uv run pkcs11-check test --help` is NOT needed — in-repo: `uv run pytest src/pkcs11_check/testcases/test_mech_coverage.py --collect-only -q` to confirm collection.

- [ ] **Step 5: CI gates + commit**

```bash
uv run ruff format src tests && uv run ruff check src tests && uv run mypy src
git add -A && git commit -m "feat(coverage): registry blind-spot meta-check (advertised-but-unregistered -> compliance notes)"
```

---

### Task 11: classification-model doc amendments

**Files:**
- Modify: `CLAUDE.md` (classification table section), `docs/classification-model-design.md`

- [ ] **Step 1: Amend CLAUDE.md** — directly under the classification table, add:

```markdown
Two spec-grounded refinements (design: docs/superpowers/specs/2026-06-10-advertised-capability-honesty-design.md):
- **Sanctioned policy refusal = pass:** in the `test_mech_*` claim layer, a clean refusal with
  `CKR_OPERATION_NOT_VALIDATED` (PKCS#11 v3.2 validation-policy code) is conformant → **pass** +
  `compliance.note`. Any other clean refusal of an advertised (mechanism, operation) stays xfail.
- **Vacuous reject = xfail:** where a canonical operability probe says NOT_OPERATIONAL, a
  negative-op "rejection" never evaluated the input → **xfail**, not pass (INCONCLUSIVE never
  triggers this).
```

- [ ] **Step 2: Amend `docs/classification-model-design.md`** — locate the positive-op and negative-op row definitions; append a subsection:

```markdown
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
   "vacuous reject", not pass. OPERATIONAL and INCONCLUSIVE verdicts leave the pass untouched.

Both refinements are provider-general: discrimination is by return code, probe effect, and
CKO_VALIDATION capability only.
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/classification-model-design.md
git commit -m "docs(model): record sanctioned-refusal pass + vacuous-reject xfail refinements"
```

---

### Task 12: full gates, Docker fresh-verify, merge to dev

**Files:** none new (verification + merge)

- [ ] **Step 1: Full local gate set**

```bash
uv run ruff format --check src tests && uv run ruff check src tests && uv run mypy src
uv run pytest tests/ -q
```
Expected: all green. (Two known CLI meta-tests fail only in colored remote-control shells — if `test_cli`/`test_state_cmd` fail, re-run per the documented workaround: `env -i HOME=$HOME PATH=$PATH TERM=dumb uv run pytest tests/ -q`.)

- [ ] **Step 2: Docker fresh-verify (targeted, NEVER full suite)**

```bash
bash docker/test.sh tpm2 -- src/pkcs11_check/testcases/acvp/test_acvp_rsa.py
bash docker/test.sh bouncyhsm -- src/pkcs11_check/testcases/acvp/aes/test_ccm.py
bash docker/test.sh kryoptic-fips -- src/pkcs11_check/testcases/test_mech_sign.py
bash docker/test.sh softhsm2 -- src/pkcs11_check/testcases/acvp/aes/test_ccm.py
bash docker/test.sh softhsm2 -- src/pkcs11_check/testcases/test_mech_sign.py
bash docker/test.sh kryoptic -- src/pkcs11_check/testcases/test_mech_sign.py
bash docker/test.sh opencryptoki -- src/pkcs11_check/testcases/acvp/aes/test_ccm.py
```

Expected outcomes (check `artifacts/<provider>/report.jsonl`):
- tpm2 SigVer: ~135 invalid-vector passes → xfail "vacuous reject"; valid-vector xfails unchanged; **0 new fails**.
- bouncyhsm CCM: invalid-vector passes → xfail; the **1,691 genuine fails remain fails** (1,268 wrong-plaintext + 423 forgery-accepted) — any drop below that = STOP, the downgrade leaked into real findings.
- kryoptic-fips test_mech_sign: refusals are `CKR_DEVICE_ERROR` → stay xfail (proves the sanctioned-code discrimination does not over-trigger); no pass+note expected unless the module actually returns OPERATION_NOT_VALIDATED.
- softhsm2 / kryoptic / opencryptoki controls: byte-identical outcome counts vs. their previous runs of the same files (operational mechanisms — neither refinement fires).

- [ ] **Step 3: Record results + merge**

Document the before/after counts in the commit message. Then:

```bash
git checkout dev && git merge fix/advertised-capability-honesty
```

(NEVER checkout main. Do not update doc statistics tables — counts go in the commit message only, per CLAUDE.md.)

---

## Self-review checklist (done at plan-writing time)

- Spec component 1 (claim layer) → Tasks 2-5; component 2 (reason constant) → Task 1; component 3 (coverage meta-check) → Task 10; component 4 (downgrade + three-state precondition) → Tasks 6-9 (precondition ordered BEFORE the SigVer/PSS downgrade); component 5 (model docs) → Task 11; spec Testing section → Tasks 1-10 meta-tests + Task 12 docker matrix.
- Names used consistently: `not_operational_reason`, `xfail_vacuous_reject`, `claim_refusal_passes`, `_pkcs15_sigver_operability`, `_pss_combo_operability`, `_note_registry_blind_spots`.
- Known judgment calls an executor must NOT "fix" silently: KAT vectors stay xfail under sanctioned refusal (Denis decision); CMAC/GMAC/XTS wycheproof reject branches stay legacy (no probe in scope); `CIPHER_OP_RUNTIME_REJECT_RVS` in conftest is kept for non-claim suites.
