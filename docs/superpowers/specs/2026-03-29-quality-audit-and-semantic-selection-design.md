# Quality Audit And Semantic Mechanism Selection Design

## Context

pkcs11-check already has two important building blocks:

- unified machine-readable results via `results.json`
- real mechanism/function invocation tracking via `coverage.json`

That is enough to inspect many failures manually, but it is still not enough to
reliably answer the framework-quality questions that matter most:

- which tests never pass successfully on any backend
- which skips are probably framework-caused rather than capability-caused
- which advertised mechanisms are selected by the framework but never exercised
- which parametrized tests are built on insufficient mechanism semantics

Recent investigation exposed two framework bugs of exactly this type:

- mechanism selection based on `CKF_WRAP` alone for a wrap+unwrap roundtrip test
- variable-length secret-key generation self-skipping because the registry left
  `key_sizes=()` open-ended

The next quality step should therefore combine two tracks:

1. artifact-driven quality auditing
2. semantic mechanism selection for mechanism-driven tests

## Gap Analysis Findings

### 1. Reporting exists, but auditability is still shallow

Current state:

- `results.json` is good for merged summaries
- `report.jsonl` is better for per-test triage
- `coverage.json` shows aggregate invoked functions/mechanisms

Current gaps:

- `results.json` intentionally excludes passed and skipped test entries from
  `units[*].tests`, so it cannot answer "never passed successfully" by itself
- `skip_reasons` are free-text and aggregated, so classification is heuristic
- `coverage.json` is session-wide aggregate data, not per-test attribution
- no schema version exists for the derived machine-readable artifacts
- `report.jsonl` is useful in practice but not yet treated as a first-class,
  explicitly documented quality-analysis input

### 2. Selection logic is still too flag-centric

Current state:

- `plugin.py` parametrizes mechanism fixtures by raw CKF bitmasks
- `MechanismCatalog.filter_registered(flag)` only checks `flags & flag`
- test semantics are implemented in individual test files, not in a reusable
  selection model

Current gaps:

- a roundtrip test can require more semantics than the fixture selector encodes
- selection policy is coupled to pytest fixture names rather than test intent
- there is no reusable representation of "encrypt roundtrip", "wrap roundtrip",
  or "multipart encrypt roundtrip"
- selector rejection reasons are not captured in machine-readable artifacts

### 3. Logging is missing the information needed for quality triage

Current state:

- `CoverageReport` already flows from the plugin into `report.jsonl`

Current gaps:

- no selection telemetry exists
- no structured distinction exists between:
  - missing capability
  - framework constraint
  - test-data absence
  - unimplemented helper path
- framework self-skips are mostly plain `pytest.skip("...")` calls, which makes
  later classification more fragile than it should be

## Design Goals

- make framework-quality issues discoverable from artifacts, not only from
  manual reading
- stop selecting mechanisms for tests whose semantics they cannot satisfy
- keep provider bugs visible; do not convert genuine failures into skips
- keep plugin code thin by moving selection semantics into a dedicated module
- make the new audit layer degrade gracefully when only partial artifacts exist
- add observability without exploding artifact size

## Non-Goals

- redesign the entire result format again
- convert every existing self-skip to structured metadata in one pass
- add per-call tracing of every PKCS#11 function invocation
- migrate every mechanism-driven file in one change

## Proposed Architecture

### A. Dedicated semantic selection layer

Add a new module:

- `src/pkcs11_check/testcases/mechanism_selection.py`

Responsibilities:

- define test-intent selectors on top of `MechanismCatalog`
- centralize selection predicates and rejection reasons
- keep pytest fixture wiring in `plugin.py` thin

Core model:

- `SelectionScenario`
- `SelectionDecision`
- `SelectionReason`

Recommended first scenarios:

- `encrypt_roundtrip`
- `wrap_roundtrip`
- `sign_verify_roundtrip`
- `multipart_encrypt_roundtrip`

Each scenario should validate:

- required CKF flags
- registry presence
- relevant config constraints such as:
  - `input_constraint`
  - `multi_part_supported`
  - `is_keypair`
  - parameter recipe constraints where the test requires helper support

Important rule:

- the selector may reject mechanisms for missing required semantics
- the selector must not reject mechanisms merely because a provider is known to
  behave incorrectly on valid inputs

### B. Selection telemetry

Add a new aggregated JSONL report type:

- `$report_type: "SelectionReport"`

The plugin should emit one aggregated selection report per pytest session, not a
line per candidate.

The report should include:

- fixture/scenario name
- selected mechanism names
- rejected mechanism names with reason codes
- counts by rejection code

This gives post-run audit enough information to answer:

- what the framework considered
- what it selected
- why it rejected the rest

without bloating artifacts.

### C. Optional per-test mechanism traces

The original proposal only used aggregate `coverage.json`. That is too weak for
some of the quality questions.

Refinement:

- keep aggregate `CoverageReport`
- add optional aggregated per-test mechanism usage data derived from teardown
  deltas

Recommended new JSONL report type:

- `$report_type: "PerTestMechanismReport"`

Fields:

- `nodeid`
- `mechanisms_invoked`
- `mechanism_detail`

This should be opt-in or compact by default:

- only emitted when machine-readable reporting is enabled
- only emit non-empty per-test traces

This is enough to correlate:

- selected mechanism
- actual invoked mechanism(s)
- final outcome

and detect selector/runtime mismatches far more reliably.

### D. Quality audit layer

Add a new module:

- `src/pkcs11_check/core/quality_audit.py`

Inputs:

- `results.json`
- `coverage.json` if present
- `report.jsonl` if present
- aggregated `SelectionReport`
- aggregated `PerTestMechanismReport` if present

Outputs:

- `quality.json`
- optional embedding of `quality` into `results.json`

All quality artifacts must include `schema_version`.

Recommended top-level sections in `quality.json`:

- `schema_version`
- `summary`
- `never_passed_nodeids`
- `framework_skip_candidates`
- `selection_findings`
- `mechanism_findings`
- `data_quality_warnings`

Recommended concrete findings:

- tests seen only as `failed` / `error` / `xfailed`, never `passed`
- free-text skip reasons classified as likely:
  - `missing_capability`
  - `framework_constraint`
  - `test_data_missing`
  - `not_implemented`
  - `unknown`
- mechanisms selected by a scenario but never actually invoked
- mechanisms advertised and selected but never successfully exercised
- scenario-level selection mismatches, for example:
  - selected without required CKF partner flag
  - selected with `multi_part_supported=False` for multipart scenario

### E. Structured framework skip metadata

This is not required for phase 1, but the design should leave space for it.

Add a helper module later:

- `src/pkcs11_check/testcases/skipmeta.py`

Goal:

- allow framework-owned self-skips to emit a structured reason code before
  calling `pytest.skip()`

Why not require it up front:

- current tests already use many plain `pytest.skip()` calls
- a hard migration would slow the first useful version

Phase-1 rule:

- the audit uses heuristic classification on free-text reasons
- structured framework skip metadata, when present, overrides heuristics

## Artifact Strategy

### Required artifacts

- `results.json`
- `coverage.json`
- `quality.json`

### First-class raw input artifact

- `report.jsonl`

`report.jsonl` should be explicitly documented as a standard artifact whenever
machine-readable output is enabled. The quality audit should use it when
available and degrade gracefully when only `results.json` and `coverage.json`
exist.

## File Responsibilities

### New files

- `src/pkcs11_check/testcases/mechanism_selection.py`
- `src/pkcs11_check/core/quality_audit.py`
- `tests/test_mechanism_selection.py`
- `tests/test_quality_audit.py`

### Modified files

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

## Rollout Plan

### Phase 1

- build semantic selectors
- emit `SelectionReport`
- implement `quality.json`
- migrate wrap and encrypt scenarios

### Phase 2

- add per-test mechanism traces
- migrate sign and multipart scenarios
- document `report.jsonl` as first-class artifact

### Phase 3

- add structured framework skip helper
- move heuristics to structured skip codes where practical

## Risks And Mitigations

### Artifact bloat

Risk:

- per-test traces can become large on vector-heavy suites

Mitigation:

- emit only non-empty traces
- keep selection telemetry aggregated
- keep `results.json` compact and put richer audit details in `quality.json`

### False framework findings

Risk:

- heuristic skip classification can mislabel provider limitations as framework
  problems

Mitigation:

- classify conservatively
- prefer structured metadata when available
- keep a separate `unknown` bucket

### Over-centralizing plugin logic

Risk:

- selection semantics become hard to test if they stay embedded in pytest hooks

Mitigation:

- put scenario logic in a dedicated selection module
- keep plugin responsible only for fixture-to-scenario mapping and report
  emission

## Verification Strategy

- meta-tests for selector decisions and rejection reasons
- meta-tests for selection telemetry emission
- meta-tests for quality audit classification and degraded-input behavior
- targeted provider validation on wrap/encrypt after migration
- confirm that remaining provider failures stay visible and are not turned into
  framework skips

## Decision Summary

The revised design keeps the original direction, but fixes five weaknesses in
the first draft:

1. add schema versioning
2. treat `report.jsonl` as a first-class audit input
3. move selection semantics into a dedicated module, not just `plugin.py`
4. add optional per-test mechanism traces, not only session aggregate coverage
5. leave a structured path for framework skip metadata instead of relying on
   free-text forever
