# Coverage Call Counters & Version Marker Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add call count tracking to coverage.json, fix PQC version markers, and track bootstrap function calls.

**Architecture:** Three independent components: (1) Remove `requires_v32` from 8 sign/verify-only PQC test files, (2) Add bootstrap call snapshotting in fixtures.py before `reset_call_log()`, (3) Enrich api.py with mechanism counts, plugin.py with cumulative counters, and file_runner.py with Counter-based merging. All changes are backward-compatible — existing coverage.json fields unchanged.

**Tech Stack:** Python 3.11+, pytest, collections.Counter, pkcs11_check.raw.api, pkcs11_check.plugin, pkcs11_check.core.file_runner

**Spec:** `docs/superpowers/specs/2026-03-27-coverage-counters-and-marker-fix-design.md`

---

## Task 1: Remove `requires_v32` from Sign/Verify PQC Test Files

**Goal:** Allow ML-DSA/SLH-DSA sign/verify tests to run on modules that advertise PQC mechanisms but negotiate v2.40 interface (e.g., SoftHSM2-main).

**Files:**
- Modify: `src/pkcs11_check/testcases/test_pqc_sign.py:44`
- Modify: `src/pkcs11_check/testcases/test_hash_ml_dsa.py:46`
- Modify: `src/pkcs11_check/testcases/test_hash_slh_dsa.py:46`
- Modify: `src/pkcs11_check/testcases/test_stateful_sigs.py:64`
- Modify: `src/pkcs11_check/testcases/test_cctv_mldsa.py:40`
- Modify: `src/pkcs11_check/testcases/test_acvp_slhdsa.py:50`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa_sign.py:35`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py:34`

- [ ] **Step 1:** Remove `pytest.mark.requires_v32` from each file's `pytestmark`

In each file, change the `pytestmark` line to remove `requires_v32`. Keep all other markers:

`test_pqc_sign.py:44`: `pytestmark = [pytest.mark.pqc, pytest.mark.requires_v32]` → `pytestmark = [pytest.mark.pqc]`

`test_hash_ml_dsa.py:46`: `pytestmark = [pytest.mark.pqc, pytest.mark.requires_v32]` → `pytestmark = [pytest.mark.pqc]`

`test_hash_slh_dsa.py:46`: `pytestmark = [pytest.mark.pqc, pytest.mark.requires_v32]` → `pytestmark = [pytest.mark.pqc]`

`test_stateful_sigs.py:64`: `pytestmark = [pytest.mark.pqc, pytest.mark.requires_v32]` → `pytestmark = [pytest.mark.pqc]`

`test_cctv_mldsa.py:40`: `pytestmark = [pytest.mark.pqc, pytest.mark.requires_v32, pytest.mark.kat, pytest.mark.cctv]` → `pytestmark = [pytest.mark.pqc, pytest.mark.kat, pytest.mark.cctv]`

`test_acvp_slhdsa.py:50`: `pytestmark = [pytest.mark.pqc, pytest.mark.kat, pytest.mark.acvp, pytest.mark.requires_v32]` → `pytestmark = [pytest.mark.pqc, pytest.mark.kat, pytest.mark.acvp]`

`wycheproof/test_wycheproof_mldsa_sign.py:35`: `pytestmark = [pytest.mark.wycheproof, pytest.mark.pqc, pytest.mark.requires_v32]` → `pytestmark = [pytest.mark.wycheproof, pytest.mark.pqc]`

`wycheproof/test_wycheproof_mldsa.py:34`: `pytestmark = [pytest.mark.wycheproof, pytest.mark.requires_v32, pytest.mark.pqc]` → `pytestmark = [pytest.mark.wycheproof, pytest.mark.pqc]`

- [ ] **Step 2:** Verify tests still have `has_mechanism()` guards

Grep each file for `has_mechanism` or `_skip_if_no` to confirm runtime mechanism checks exist:
```bash
uv run ruff check src/pkcs11_check/testcases/test_pqc_sign.py src/pkcs11_check/testcases/test_hash_ml_dsa.py src/pkcs11_check/testcases/test_hash_slh_dsa.py src/pkcs11_check/testcases/test_stateful_sigs.py src/pkcs11_check/testcases/test_cctv_mldsa.py src/pkcs11_check/testcases/test_acvp_slhdsa.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa_sign.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py
```

- [ ] **Step 3:** Commit
```bash
git commit -m 'fix: remove requires_v32 from sign/verify-only PQC tests

PQC mechanisms (ML-DSA, SLH-DSA) can be used through v2.40 API functions
(C_SignInit, C_VerifyInit). The requires_v32 marker should only gate tests
that call v3.2-only functions (C_EncapsulateKey, C_DecapsulateKey). Tests
retain runtime has_mechanism() guards for clean skipping.'
```

---

## Task 2: Add v3.2 Functions to `_MECHANISM_ARG_FUNCS`

**Goal:** Track mechanism usage for KEM and authenticated-wrap operations.

**Files:**
- Modify: `src/pkcs11_check/raw/api.py:116-135`

- [ ] **Step 1:** Add the 4 missing v3.2 functions to `_MECHANISM_ARG_FUNCS`

At `api.py:116`, the current frozenset is missing v3.2 functions. Add them:

```python
_MECHANISM_ARG_FUNCS = frozenset(
    {
        "C_EncryptInit",
        "C_DecryptInit",
        "C_DigestInit",
        "C_SignInit",
        "C_VerifyInit",
        "C_SignRecoverInit",
        "C_VerifyRecoverInit",
        "C_GenerateKey",
        "C_GenerateKeyPair",
        "C_WrapKey",
        "C_UnwrapKey",
        "C_DeriveKey",
        "C_MessageEncryptInit",
        "C_MessageDecryptInit",
        "C_MessageSignInit",
        "C_MessageVerifyInit",
        # v3.2 functions that take CK_MECHANISM_PTR
        "C_EncapsulateKey",
        "C_DecapsulateKey",
        "C_WrapKeyAuthenticated",
        "C_UnwrapKeyAuthenticated",
    }
)
```

- [ ] **Step 2:** Lint
```bash
uv run ruff check src/pkcs11_check/raw/api.py
```

- [ ] **Step 3:** Commit
```bash
git commit -m 'fix: add v3.2 KEM/auth-wrap functions to mechanism tracking set'
```

---

## Task 3: Add Mechanism Counts to `RawPKCS11`

**Goal:** Track per-mechanism invocation counts alongside the existing set.

**Files:**
- Modify: `src/pkcs11_check/raw/api.py:148-151` (init)
- Modify: `src/pkcs11_check/raw/api.py:276-281` (properties and reset)
- Modify: `src/pkcs11_check/raw/api.py:287-297` (_call method)

- [ ] **Step 1:** Add `_mechanism_counts` to `__init__`

At `api.py:148-151`, add the Counter import and field:

```python
from collections import Counter, defaultdict
# ... in __init__:
self._call_log: dict[str, int] = defaultdict(int)
self._used_mechanisms: set[int] = set()
self._mechanism_counts: Counter[int] = Counter()
```

Note: `Counter` import must be added to the file-level imports. Currently only `defaultdict` is imported from collections at line 7.

- [ ] **Step 2:** Add `mechanism_counts` property and update reset

After the existing `used_mechanisms` property at line 276-281:

```python
@property
def mechanism_counts(self) -> dict[int, int]:
    """Per-mechanism invocation counts (CKM int → call count)."""
    return dict(self._mechanism_counts)

def reset_used_mechanisms(self) -> None:
    self._used_mechanisms.clear()
    self._mechanism_counts.clear()
```

- [ ] **Step 3:** Track counts in `_call()`

At `api.py:289-293`, add the count increment:

```python
if name in _MECHANISM_ARG_FUNCS and len(args) >= 2:
    try:
        mech_id = args[1]._obj.mechanism
        self._used_mechanisms.add(mech_id)
        self._mechanism_counts[mech_id] += 1
    except (AttributeError, TypeError):
        pass
```

- [ ] **Step 4:** Lint and type-check
```bash
uv run ruff check src/pkcs11_check/raw/api.py
uv run mypy src/pkcs11_check/raw/api.py
```

- [ ] **Step 5:** Commit
```bash
git commit -m 'feat: add per-mechanism invocation count tracking to RawPKCS11'
```

---

## Task 4: Bootstrap Call Snapshotting in Fixtures

**Goal:** Capture C_Initialize, C_GetSlotList, C_OpenSession, C_Login counts before they are wiped by `reset_call_log()`.

**Files:**
- Modify: `src/pkcs11_check/fixtures.py:77-94` (p11_session fixture)
- Modify: `src/pkcs11_check/fixtures.py:122-133` (RawSession dataclass)
- Modify: `src/pkcs11_check/fixtures.py:188-211` (p11_raw_session fixture)

- [ ] **Step 1:** Add `bootstrap_call_counts` field to RawSession

At `fixtures.py:122-133`, add the field:

```python
@dataclass
class RawSession:
    raw: RawPKCS11
    sh: int
    slot_id: int
    _mechanisms: frozenset[str] | None = field(default=None, repr=False)
    bootstrap_call_counts: dict[str, int] = field(default_factory=dict, repr=False)
```

- [ ] **Step 2:** Snapshot bootstrap in `p11_raw_session` before reset

At `fixtures.py:204-207`, change:

```python
    raw, sh, slot_id, logged_in = _open_raw_session(p11_module, p11_config)
    bootstrap_log = dict(raw.call_log)
    raw.reset_call_log()
    raw.reset_used_mechanisms()
    try:
        yield RawSession(raw, sh, slot_id, bootstrap_call_counts=bootstrap_log)
```

- [ ] **Step 3:** Apply same snapshot in `p11_session`

At `fixtures.py:86-89`, change:

```python
    raw, sh, slot_id, logged_in = _open_raw_session(p11_module, p11_config)
    bootstrap_log = dict(raw.call_log)
    raw.reset_call_log()
    raw.reset_used_mechanisms()
    try:
        yield RawSession(raw, sh, slot_id, bootstrap_call_counts=bootstrap_log)
```

- [ ] **Step 4:** Lint and type-check
```bash
uv run ruff check src/pkcs11_check/fixtures.py
uv run mypy src/pkcs11_check/fixtures.py
```

- [ ] **Step 5:** Commit
```bash
git commit -m 'feat: snapshot bootstrap call counts before reset in fixtures'
```

---

## Task 5: Accumulate Counts in Plugin Teardown and Session Finish

**Goal:** Collect per-test function counts, mechanism counts, detail counts, and bootstrap counts in plugin.py. Emit enriched coverage_data.

**Files:**
- Modify: `src/pkcs11_check/plugin.py:25-33` (stash keys)
- Modify: `src/pkcs11_check/plugin.py:93-103` (pytest_configure)
- Modify: `src/pkcs11_check/plugin.py:283-356` (pytest_runtest_teardown)
- Modify: `src/pkcs11_check/plugin.py:342-356` (_build_stacked_strings → extract helper)
- Modify: `src/pkcs11_check/plugin.py:359-416` (pytest_sessionfinish)

- [ ] **Step 1:** Add new stash keys

At `plugin.py:25-33`, add after existing keys:

```python
_CUMULATIVE_FUNCTION_COUNTS: pytest.StashKey[Counter] = pytest.StashKey()
_CUMULATIVE_MECHANISM_COUNTS: pytest.StashKey[Counter] = pytest.StashKey()
_CUMULATIVE_DETAIL_COUNTS: pytest.StashKey[Counter] = pytest.StashKey()
_BOOTSTRAP_FUNCTION_COUNTS: pytest.StashKey[dict[str, int]] = pytest.StashKey()
_BOOTSTRAP_COLLECTED: pytest.StashKey[bool] = pytest.StashKey()
```

Add `from collections import Counter` at top of file.

- [ ] **Step 2:** Initialize new stash keys in `pytest_configure`

At `plugin.py:98-103`, add:

```python
config.stash[_CUMULATIVE_FUNCTION_COUNTS] = Counter()
config.stash[_CUMULATIVE_MECHANISM_COUNTS] = Counter()
config.stash[_CUMULATIVE_DETAIL_COUNTS] = Counter()
config.stash[_BOOTSTRAP_FUNCTION_COUNTS] = {}
config.stash[_BOOTSTRAP_COLLECTED] = False
```

- [ ] **Step 3:** Collect counts in `pytest_runtest_teardown`

At `plugin.py:311` (inside the `for name in ("p11_raw_session", "p11_session"):` block), after `cumulative.update(rs.raw.call_log.keys())`, add:

```python
                cumulative.update(rs.raw.call_log.keys())
                # Accumulate function call counts
                try:
                    func_counts = session.config.stash[_CUMULATIVE_FUNCTION_COUNTS]
                    func_counts.update(rs.raw.call_log)
                except KeyError:
                    pass
                # Collect bootstrap counts once
                try:
                    if not session.config.stash.get(_BOOTSTRAP_COLLECTED, False):
                        bootstrap = getattr(rs, "bootstrap_call_counts", {})
                        if bootstrap:
                            session.config.stash[_BOOTSTRAP_FUNCTION_COUNTS] = dict(bootstrap)
                            session.config.stash[_BOOTSTRAP_COLLECTED] = True
                except KeyError:
                    pass
```

After `used.update(rs.raw.used_mechanisms)` at line 324, add:

```python
                    used.update(rs.raw.used_mechanisms)
                    # Accumulate mechanism counts
                    mech_counts = session.config.stash.get(_CUMULATIVE_MECHANISM_COUNTS)
                    if mech_counts is not None:
                        mech_counts.update(rs.raw.mechanism_counts)
```

- [ ] **Step 4:** Extract `_build_one_stacked_string` helper and add detail counting

Before `_build_stacked_strings` at line 342, add a single-entry helper:

```python
def _build_one_stacked_string(mech_id: int, subs: dict[str, int]) -> str:
    """Build one stacked string like CKM_RSA_PKCS_OAEP[hashAlg=CKM_SHA256]."""
    from pkcs11_check.raw.api import ckm_name, sub_param_name

    base = ckm_name(mech_id)
    if subs:
        parts = ",".join(f"{k}={sub_param_name(k, v)}" for k, v in sorted(subs.items()))
        return f"{base}[{parts}]"
    return base
```

Update `_build_stacked_strings` to use it:

```python
def _build_stacked_strings(
    detail_set: set[tuple[int, frozenset[tuple[str, int]]]],
) -> list[str]:
    """Build sorted stacked strings like CKM_RSA_PKCS_OAEP[hashAlg=CKM_SHA256]."""
    return sorted(
        _build_one_stacked_string(mech_id, dict(subs_frozen))
        for mech_id, subs_frozen in detail_set
    )
```

In the mechanism detail drain block (lines 329-339), add counting:

```python
        details = drain_mechanism_details()
        if details:
            detail_set = session.config.stash[_CUMULATIVE_MECHANISM_DETAILS]
            detail_counts = session.config.stash.get(_CUMULATIVE_DETAIL_COUNTS)
            for mech_id, subs in details:
                detail_set.add((mech_id, frozenset(subs.items())))
                if detail_counts is not None:
                    detail_str = _build_one_stacked_string(mech_id, subs)
                    detail_counts[detail_str] += 1
```

- [ ] **Step 5:** Emit counts in `pytest_sessionfinish`

In `pytest_sessionfinish` at line 389-404, enrich coverage_data:

```python
    func_counts = config.stash.get(_CUMULATIVE_FUNCTION_COUNTS, Counter())
    mech_counts_raw = config.stash.get(_CUMULATIVE_MECHANISM_COUNTS, Counter())
    detail_counts = config.stash.get(_CUMULATIVE_DETAIL_COUNTS, Counter())
    bootstrap = config.stash.get(_BOOTSTRAP_FUNCTION_COUNTS, {})

    # Resolve mechanism int IDs to names for JSON output
    mech_counts_named: dict[str, int] = {}
    for mech_id, count in mech_counts_raw.items():
        mech_counts_named[ckm_name(mech_id)] = (
            mech_counts_named.get(ckm_name(mech_id), 0) + count
        )

    # Bootstrap functions join called_names
    bootstrap_func_names = set(bootstrap.keys())
    called = sorted((cumulative | bootstrap_func_names) & available)
    uncalled = sorted(available - cumulative - bootstrap_func_names)

    coverage_data: dict[str, Any] = {
        "function_coverage": {
            "available": len(available),
            "called": len(called),
            "called_names": called,
            "called_counts": dict(sorted(func_counts.items())),
            "bootstrap_counts": bootstrap,
            "uncalled_names": uncalled,
        },
        "mechanism_coverage": {
            "available": len(mech_ckm),
            "available_names": mech_ckm,
            "invoked": len(invoked_names),
            "invoked_names": invoked_names,
            "invoked_counts": dict(sorted(mech_counts_named.items())),
            "not_invoked": len(not_invoked),
            "not_invoked_names": not_invoked,
            "invoked_detail": stacked,
            "invoked_detail_counts": dict(sorted(detail_counts.items())),
        },
    }
```

- [ ] **Step 6:** Lint and type-check
```bash
uv run ruff check src/pkcs11_check/plugin.py
uv run mypy src/pkcs11_check/plugin.py
```

- [ ] **Step 7:** Commit
```bash
git commit -m 'feat: accumulate call counts and bootstrap tracking in plugin coverage'
```

---

## Task 6: Merge Counts in File Runner

**Goal:** Sum call counts across isolated test files in `extract_coverage_from_jsonl()`.

**Files:**
- Modify: `src/pkcs11_check/core/file_runner.py:625-687`

- [ ] **Step 1:** Add Counter-based merging to `extract_coverage_from_jsonl`

Replace the function body at `file_runner.py:625-687`:

```python
def extract_coverage_from_jsonl(jsonl_path: Path) -> dict[str, Any] | None:
    """Extract and merge CoverageReport entries from a JSONL artifact."""
    from collections import Counter

    try:
        text = jsonl_path.read_text()
    except (FileNotFoundError, OSError):
        return None

    all_called: set[str] = set()
    all_uncalled: set[str] = set()
    func_available = 0
    all_invoked: set[str] = set()
    all_not_invoked: set[str] = set()
    all_available_mechs: set[str] = set()
    all_detail: set[str] = set()
    # Count-based accumulators
    all_func_counts: Counter[str] = Counter()
    all_bootstrap_counts: Counter[str] = Counter()
    all_mech_counts: Counter[str] = Counter()
    all_detail_counts: Counter[str] = Counter()
    found = False

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("$report_type") != "CoverageReport":
            continue
        found = True
        fc = rec.get("function_coverage", {})
        func_available = max(func_available, fc.get("available", 0))
        all_called.update(fc.get("called_names", []))
        all_uncalled.update(fc.get("uncalled_names", []))
        all_func_counts.update(fc.get("called_counts", {}))
        all_bootstrap_counts.update(fc.get("bootstrap_counts", {}))
        mc = rec.get("mechanism_coverage", {})
        all_available_mechs.update(mc.get("available_names", []))
        all_invoked.update(mc.get("invoked_names", []))
        all_not_invoked.update(mc.get("not_invoked_names", []))
        all_detail.update(mc.get("invoked_detail", []))
        all_mech_counts.update(mc.get("invoked_counts", {}))
        all_detail_counts.update(mc.get("invoked_detail_counts", {}))

    if not found:
        return None

    merged_not_invoked = sorted(all_available_mechs - all_invoked)
    merged_uncalled = sorted(all_uncalled - all_called)
    return {
        "function_coverage": {
            "available": func_available,
            "called": len(all_called),
            "called_names": sorted(all_called),
            "called_counts": dict(all_func_counts),
            "bootstrap_counts": dict(all_bootstrap_counts),
            "uncalled_names": merged_uncalled,
        },
        "mechanism_coverage": {
            "available": len(all_available_mechs),
            "available_names": sorted(all_available_mechs),
            "invoked": len(all_invoked),
            "invoked_names": sorted(all_invoked),
            "invoked_counts": dict(all_mech_counts),
            "not_invoked": len(merged_not_invoked),
            "not_invoked_names": merged_not_invoked,
            "invoked_detail": sorted(all_detail),
            "invoked_detail_counts": dict(all_detail_counts),
        },
    }
```

- [ ] **Step 2:** Lint
```bash
uv run ruff check src/pkcs11_check/core/file_runner.py
```

- [ ] **Step 3:** Commit
```bash
git commit -m 'feat: merge call counts across isolated test files in coverage'
```

---

## Task 7: Verification

**Goal:** Verify all three components work end-to-end.

- [ ] **Step 1:** Run meta-tests
```bash
uv run python -m pytest tests/ -x -q
```
Expected: all existing tests pass.

- [ ] **Step 2:** Run SoftHSM2 smoke test and check coverage.json
```bash
bash local-builds/test.sh softhsm2 -m smoke
python3 -c "
import json
d = json.load(open('artifacts/softhsm2/coverage.json'))
fc = d['function_coverage']
mc = d['mechanism_coverage']
print(f'Functions: {fc[\"called\"]}/{fc[\"available\"]}')
print(f'Bootstrap: {fc.get(\"bootstrap_counts\", {})}')
print(f'Top called:', sorted(fc.get('called_counts', {}).items(), key=lambda x: -x[1])[:5])
print(f'Mechanisms: {mc[\"invoked\"]}/{mc[\"available\"]}')
print(f'Top invoked:', sorted(mc.get('invoked_counts', {}).items(), key=lambda x: -x[1])[:5])
print(f'C_Initialize in called_names:', 'C_Initialize' in fc['called_names'])
"
```
Expected: C_Initialize in `called_names`, `bootstrap_counts` has 4 functions, `called_counts` and `invoked_counts` have non-zero values.

- [ ] **Step 3:** Run SoftHSM2-main Docker to verify marker fix
```bash
bash docker/test.sh softhsm2-main -- src/pkcs11_check/testcases/test_pqc_sign.py src/pkcs11_check/testcases/test_hash_ml_dsa.py
```
Expected: ML-DSA tests pass (not skipped with "Requires v32, module has v2.40").

- [ ] **Step 4:** Run NSS-PQC to verify no regression
```bash
bash docker/test.sh nss-pqc -m smoke
```
Expected: smoke tests pass, coverage.json has count fields.

- [ ] **Step 5:** Commit verification notes
```bash
git commit --allow-empty -m 'chore: verified coverage counters and marker fix across 3 modules'
```
