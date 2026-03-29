# Quality Audit And Semantic Mechanism Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add artifact-driven quality auditing and semantic mechanism selection so pkcs11-check can identify framework-caused gaps and stop selecting mechanisms that cannot satisfy roundtrip test semantics.

**Architecture:** Introduce a dedicated mechanism-selection layer outside the pytest plugin, emit aggregated selection telemetry plus optional per-test mechanism traces, and derive a new `quality.json` artifact from `results.json`, `coverage.json`, and `report.jsonl`. Migrate wrap and encrypt first, then extend the same pattern to sign and multipart tests.

**Tech Stack:** Python 3.11+, pytest, pytest-reportlog JSONL, typer CLI, existing isolated runner/reporting stack

---

## File Map

**Create:**
- `src/pkcs11_check/testcases/mechanism_selection.py`
- `src/pkcs11_check/core/quality_audit.py`
- `tests/test_mechanism_selection.py`
- `tests/test_quality_audit.py`

**Modify:**
- `src/pkcs11_check/plugin.py`
- `src/pkcs11_check/core/file_runner.py`
- `src/pkcs11_check/cli/test_cmd.py`
- `src/pkcs11_check/testcases/mechanism_catalog.py`
- `src/pkcs11_check/testcases/test_mech_wrap.py`
- `src/pkcs11_check/testcases/test_mech_encrypt.py`
- `src/pkcs11_check/testcases/test_mech_sign.py`
- `src/pkcs11_check/testcases/test_mech_multipart.py`
- `tests/test_plugin.py`
- `tests/test_file_runner.py`

## Task 1: Build Semantic Selector Primitives

**Files:**
- Create: `src/pkcs11_check/testcases/mechanism_selection.py`
- Test: `tests/test_mechanism_selection.py`
- Modify: `src/pkcs11_check/testcases/mechanism_catalog.py`

- [ ] **Step 1: Write selector meta-tests**

Add tests covering at least:
- wrap roundtrip rejects `CKF_WRAP` without `CKF_UNWRAP`
- encrypt roundtrip rejects encrypt-only mechanisms
- multipart encrypt rejects `multi_part_supported=False`
- selectors return machine-readable rejection reasons

Example test shape:

```python
def test_wrap_roundtrip_rejects_wrap_only() -> None:
    selected, rejected = select_for_scenario("wrap_roundtrip", [entry])
    assert selected == []
    assert rejected[0].reason.code == "missing_unwrap_flag"
```

- [ ] **Step 2: Run the new selector tests and confirm they fail**

Run:

```bash
uv run python -m pytest tests/test_mechanism_selection.py -q
```

Expected: import or attribute failures because the selector module does not exist yet.

- [ ] **Step 3: Add the selector module**

Implement:
- `SelectionReason`
- `SelectionDecision`
- `select_for_scenario(...)`
- scenario helpers for:
  - `wrap_roundtrip`
  - `encrypt_roundtrip`
  - `sign_verify_roundtrip`
  - `multipart_encrypt_roundtrip`

- [ ] **Step 4: Add thin catalog helpers if needed**

If the cleanest API is on `MechanismCatalog`, add thin wrappers there, but keep the real policy in `mechanism_selection.py`.

- [ ] **Step 5: Re-run selector tests**

Run:

```bash
uv run python -m pytest tests/test_mechanism_selection.py -q
```

Expected: pass.

- [ ] **Step 6: Lint the new selector files**

Run:

```bash
uv run ruff check src/pkcs11_check/testcases/mechanism_selection.py tests/test_mechanism_selection.py src/pkcs11_check/testcases/mechanism_catalog.py
```

- [ ] **Step 7: Commit**

```bash
git add src/pkcs11_check/testcases/mechanism_selection.py \
        src/pkcs11_check/testcases/mechanism_catalog.py \
        tests/test_mechanism_selection.py
git commit -m "Add semantic mechanism selectors"
```

## Task 2: Emit Selection Telemetry From The Plugin

**Files:**
- Modify: `src/pkcs11_check/plugin.py`
- Test: `tests/test_plugin.py`

- [ ] **Step 1: Add failing plugin tests for selection telemetry**

Cover:
- fixture name maps to selection scenario
- selected mechanisms are parametrized from selector output
- aggregated `SelectionReport` is emitted at session finish

Example assertion target:

```python
assert record["$report_type"] == "SelectionReport"
assert record["scenarios"]["wrap_roundtrip"]["rejected_counts"]["missing_unwrap_flag"] == 1
```

- [ ] **Step 2: Run the targeted plugin tests and confirm failure**

Run:

```bash
uv run python -m pytest tests/test_plugin.py -q -k "selection or runtime_skip_reason"
```

- [ ] **Step 3: Replace raw flag-only fixture routing with scenario mapping**

In `plugin.py`:
- keep existing fixture names for compatibility
- map them to scenario names
- call the selector layer instead of `filter_registered(flag)` directly

- [ ] **Step 4: Store aggregated selection telemetry in config stash**

Track, per scenario:
- selected mechanism names
- rejected mechanism names
- rejected counts by reason code

- [ ] **Step 5: Emit `SelectionReport` into report-log**

Mirror the existing `CoverageReport` pattern.

- [ ] **Step 6: Re-run plugin tests**

Run:

```bash
uv run python -m pytest tests/test_plugin.py -q -k "selection or runtime_skip_reason"
```

- [ ] **Step 7: Lint plugin changes**

Run:

```bash
uv run ruff check src/pkcs11_check/plugin.py tests/test_plugin.py
```

- [ ] **Step 8: Commit**

```bash
git add src/pkcs11_check/plugin.py tests/test_plugin.py
git commit -m "Emit mechanism selection telemetry"
```

## Task 3: Build Quality Audit Core

**Files:**
- Create: `src/pkcs11_check/core/quality_audit.py`
- Test: `tests/test_quality_audit.py`

- [ ] **Step 1: Write failing audit tests**

Cover:
- degraded behavior when only `results.json` exists
- better findings when `coverage.json` is present
- best findings when `report.jsonl` and `SelectionReport` are present
- conservative skip classification with `unknown` fallback

Example:

```python
def test_quality_audit_flags_selected_but_not_invoked() -> None:
    audit = build_quality_audit(results=..., coverage=..., selection=...)
    assert audit["mechanism_findings"][0]["kind"] == "selected_but_not_invoked"
```

- [ ] **Step 2: Run the audit tests and confirm failure**

Run:

```bash
uv run python -m pytest tests/test_quality_audit.py -q
```

- [ ] **Step 3: Implement `build_quality_audit(...)`**

Minimum outputs:
- `schema_version`
- `summary`
- `never_passed_nodeids`
- `framework_skip_candidates`
- `selection_findings`
- `mechanism_findings`
- `data_quality_warnings`

- [ ] **Step 4: Add reason classification helpers**

Implement conservative classification for current free-text reasons:
- `missing_capability`
- `framework_constraint`
- `test_data_missing`
- `not_implemented`
- `unknown`

- [ ] **Step 5: Re-run audit tests**

Run:

```bash
uv run python -m pytest tests/test_quality_audit.py -q
```

- [ ] **Step 6: Lint audit code**

Run:

```bash
uv run ruff check src/pkcs11_check/core/quality_audit.py tests/test_quality_audit.py
```

- [ ] **Step 7: Commit**

```bash
git add src/pkcs11_check/core/quality_audit.py tests/test_quality_audit.py
git commit -m "Add quality audit analysis"
```

## Task 4: Wire `quality.json` Into The Runner And CLI

**Files:**
- Modify: `src/pkcs11_check/core/file_runner.py`
- Modify: `src/pkcs11_check/cli/test_cmd.py`
- Test: `tests/test_file_runner.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Add failing runner tests**

Cover:
- isolated run writes `quality.json`
- non-isolated JSON run writes `quality.json`
- audit degrades gracefully when `report.jsonl` is missing
- schema version is present

- [ ] **Step 2: Run the targeted runner tests and confirm failure**

Run:

```bash
uv run python -m pytest tests/test_file_runner.py tests/test_cli.py -q -k "quality or coverage"
```

- [ ] **Step 3: Add extraction helpers in `file_runner.py`**

Implement helpers to read:
- `CoverageReport`
- `SelectionReport`
- optional per-test traces later

Reuse the existing JSONL scan pattern instead of inventing a second parser.

- [ ] **Step 4: Write `quality.json` beside `results.json`**

In isolated mode:
- generate `quality.json` after `report.jsonl` is merged

In non-isolated JSON mode:
- generate `quality.json` after unified post-processing

- [ ] **Step 5: Decide whether to embed `quality` in `results.json`**

If embedding is added, test both the separate file and embedded payload. Keep the standalone artifact either way.

- [ ] **Step 6: Re-run targeted runner tests**

Run:

```bash
uv run python -m pytest tests/test_file_runner.py tests/test_cli.py -q -k "quality or coverage"
```

- [ ] **Step 7: Lint runner and CLI**

Run:

```bash
uv run ruff check src/pkcs11_check/core/file_runner.py src/pkcs11_check/cli/test_cmd.py tests/test_file_runner.py tests/test_cli.py
```

- [ ] **Step 8: Commit**

```bash
git add src/pkcs11_check/core/file_runner.py \
        src/pkcs11_check/cli/test_cmd.py \
        tests/test_file_runner.py \
        tests/test_cli.py
git commit -m "Write quality audit artifacts"
```

## Task 5: Migrate Wrap And Encrypt To Semantic Selectors

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_wrap.py`
- Modify: `src/pkcs11_check/testcases/test_mech_encrypt.py`
- Test: existing product tests plus targeted meta-tests if needed

- [ ] **Step 1: Add or update tests that lock selector usage**

If necessary, add a small meta-test asserting the plugin routes:
- `mech_wrap_entry` via `wrap_roundtrip`
- `mech_encrypt_entry` via `encrypt_roundtrip`

- [ ] **Step 2: Replace ad hoc selection assumptions**

Keep runtime guards where they catch dynamic provider quirks, but move the base
selection policy into semantic selectors.

- [ ] **Step 3: Preserve provider-bug visibility**

Do not add skips for the known SoftHSM2 `DES*_CBC_PAD` wrap failures or the NSS
`RSA_X_509` raw unwrap bug. Those stay as provider findings.

- [ ] **Step 4: Run targeted meta-tests**

Run:

```bash
uv run python -m pytest tests/test_mech_wrap.py tests/test_mechanism_helpers.py tests/test_plugin.py -q
```

- [ ] **Step 5: Run targeted provider checks**

Run:

```bash
bash local-builds/test.sh softhsm2 src/pkcs11_check/testcases/test_mech_wrap.py -q -rs
bash local-builds/test.sh softhsm2 src/pkcs11_check/testcases/test_mech_encrypt.py -q -rs -k 'RSA_X_509'
bash local-builds/test.sh nss-softokn src/pkcs11_check/testcases/test_mech_wrap.py::TestMechWrapRoundtrip::test_wrap_unwrap_aes_key[RSA_X_509] -q
```

Expected:
- wrap-only false failures remain gone
- raw-RSA hint still appears on NSS
- real provider failures stay real

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/testcases/test_mech_wrap.py \
        src/pkcs11_check/testcases/test_mech_encrypt.py \
        tests/test_mech_wrap.py \
        tests/test_mechanism_helpers.py
git commit -m "Use semantic selectors for wrap and encrypt tests"
```

## Task 6: Add Optional Per-Test Mechanism Traces

**Files:**
- Modify: `src/pkcs11_check/plugin.py`
- Modify: `src/pkcs11_check/core/file_runner.py`
- Test: `tests/test_plugin.py`
- Test: `tests/test_file_runner.py`

- [ ] **Step 1: Add failing tests for `PerTestMechanismReport`**

Cover:
- report is emitted only for tests that invoke at least one mechanism
- empty traces are not emitted
- merged audit uses per-test traces when present

- [ ] **Step 2: Run the targeted tests and confirm failure**

Run:

```bash
uv run python -m pytest tests/test_plugin.py tests/test_file_runner.py -q -k "mechanism report or quality"
```

- [ ] **Step 3: Emit per-test mechanism traces in the plugin**

Use per-item teardown data, not session-finish aggregates.

- [ ] **Step 4: Merge traces into the quality audit inputs**

Teach the runner’s JSONL extractor to collect them alongside coverage and selection records.

- [ ] **Step 5: Re-run targeted tests**

Run:

```bash
uv run python -m pytest tests/test_plugin.py tests/test_file_runner.py -q -k "mechanism report or quality"
```

- [ ] **Step 6: Lint**

Run:

```bash
uv run ruff check src/pkcs11_check/plugin.py src/pkcs11_check/core/file_runner.py tests/test_plugin.py tests/test_file_runner.py
```

- [ ] **Step 7: Commit**

```bash
git add src/pkcs11_check/plugin.py src/pkcs11_check/core/file_runner.py tests/test_plugin.py tests/test_file_runner.py
git commit -m "Add per-test mechanism trace reporting"
```

## Task 7: Extend To Sign And Multipart, Then Document

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_sign.py`
- Modify: `src/pkcs11_check/testcases/test_mech_multipart.py`
- Modify: `docs/docker-artifacts.md`
- Modify: `docs/module-issues.md` only if new provider findings are confirmed

- [ ] **Step 1: Route sign and multipart through semantic selectors**

- [ ] **Step 2: Add any missing selector tests**

- [ ] **Step 3: Make `report.jsonl` explicitly documented as a first-class artifact**

Document:
- when it exists
- how it differs from `results.json`
- that `quality.json` prefers it when present

- [ ] **Step 4: Run targeted meta-tests**

Run:

```bash
uv run python -m pytest tests/test_mechanism_selection.py tests/test_quality_audit.py tests/test_plugin.py tests/test_file_runner.py -q
```

- [ ] **Step 5: Run targeted product checks**

Run:

```bash
bash local-builds/test.sh softhsm2 src/pkcs11_check/testcases/test_mech_sign.py -q -rs
bash local-builds/test.sh softhsm2 src/pkcs11_check/testcases/test_mech_multipart.py -q -rs
```

- [ ] **Step 6: Final lint**

Run:

```bash
uv run ruff check src/ tests/
```

- [ ] **Step 7: Final meta-tests**

Run:

```bash
uv run python -m pytest tests/ -q
```

- [ ] **Step 8: Commit**

```bash
git add src/pkcs11_check/testcases/test_mech_sign.py \
        src/pkcs11_check/testcases/test_mech_multipart.py \
        docs/docker-artifacts.md \
        tests/test_mechanism_selection.py \
        tests/test_quality_audit.py \
        tests/test_plugin.py \
        tests/test_file_runner.py
git commit -m "Extend semantic selection and quality audit coverage"
```

## Final Verification

- [ ] **Step 1: Verify focused local behavior**

Run:

```bash
bash local-builds/test.sh softhsm2 src/pkcs11_check/testcases/test_mech_wrap.py -q -rs
bash local-builds/test.sh softhsm2 src/pkcs11_check/testcases/test_mech_encrypt.py -q -rs -k 'RSA_X_509'
```

- [ ] **Step 2: Verify machine-readable artifacts**

Run:

```bash
uv run pkcs11-check test --module /home/user/src/m/pkcs11-check/local-builds/softhsm2/lib/libsofthsm2.so --output json --match RSA_X_509 src/pkcs11_check/testcases/test_mech_wrap.py
```

Expected artifacts:
- `pkcs11-check-results.json`
- `coverage.json`
- `quality.json`
- `report.jsonl`

- [ ] **Step 3: Review remaining findings manually**

Confirm that:
- SoftHSM2 `DES*_CBC_PAD` remains a provider finding
- NSS `CKM_RSA_X_509` unwrap remains a provider finding
- no new framework skip hides those behaviors

- [ ] **Step 4: Optional Docker spot-check**

Run:

```bash
bash docker/test.sh nss-pqc --match RSA_X_509 -- src/pkcs11_check/testcases/test_mech_wrap.py
```

- [ ] **Step 5: Final commit or squash guidance**

If the implementation was done in many commits, keep the functional split unless the user requests squashing.
