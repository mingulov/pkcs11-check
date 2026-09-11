# v0.2.0 finding -> commit coverage map

Commit bodies on `codex/v020-reporting-integrity` almost never name a finding ID (`F1`, `F6`,
...), so traceability from a finding back to the commits that implemented it and the tests that
pin it currently depends on gitignored, workstation-local working briefs. This document is the
tracked record of that mapping for the findings delivered on this branch, as of `32fb085f` (178
commits over `dev`, merge-base `d5c566f9`).

Every commit hash and file path below was checked against the tree (`git show --stat <sha>`,
`git show <sha> -- <path>`, or an open file) while writing this document.

## F1 - honeypot 32-bit `OverflowError`

- **Defect.** `mmap.mmap()` can raise `OverflowError` (rather than `OSError`/`ValueError`) for an
  oversized length on some 32-bit builds; the honeypot's page-size probing loop did not catch it,
  so probing aborted instead of falling back to the next candidate size.
- **Fix.** `src/pkcs11_check/testcases/_probes/honeypot.py:51,55` - `OverflowError` added to the
  caught exception tuple in the fallback loop.
- **Commit.** `6104889e` - "fix: continue honeypot fallback after ssize overflow".
- **Pinning test.** `tests/test_probe_honeypot.py`.

## F2 - p11-kit pre-check guard

- **Defect.** `test_interop_openssl.py`'s p11-kit interop tests invoked the `p11-kit` CLI
  unconditionally, failing (instead of skipping) when it is not installed.
- **Fix.** `src/pkcs11_check/testcases/test_interop_openssl.py:158-159` - `_have_p11kit()` checked
  and `pytest.skip("p11-kit not installed")` raised before the CLI is invoked.
- **Commit.** `1990a9e7` - "fix: skip only p11-kit tests when its CLI is absent".
- **Pinning test.** `tests/test_interop_runtime_classification.py`.

## F3 - NULL function-list entry misclassified as a crash

- **Defect.** `RawPKCS11._load_functions_from_ptr` recorded a name as missing when its function
  pointer was NULL, but left a stale callable behind in `self._funcs` from a previously-loaded
  function table, so a later call could still reach a bad pointer and surface as a crash instead
  of a reported missing function-table entry.
- **Fix.** `src/pkcs11_check/raw/api.py:405-430` (the `pop` is on the line immediately following
  the `missing.add(name)` branch; `raw/api.py:371` is the `_missing_function_list_names`
  attribute declared in `__init__`) - `self._funcs.pop(name, None)` added so a newly-NULL entry
  cannot leave a stale entry behind.
- **Commit.** `fc837cbc` - "fix: preserve function-table deviations before bootstrap".
- **Pinning tests.** `tests/test_function_table_conformance.py`, `tests/test_raw_api.py`,
  `tests/test_operation_state_runtime_classification.py`.

## F6 - readback attribution

- **Defect.** Shared readback helpers reachable from multiple call sites recorded
  `C_GetAttributeValue` findings under whichever mechanism happened to be active in the calling
  test, because `wrap_context_for()` (`src/pkcs11_check/testcases/_provisioning.py:713`) memoises
  its wrap context per session handle. This made `spec_ref` non-deterministic across test
  orderings for any test reaching a shared helper.
- **Fix.** Every readback through a shared helper now passes `inherit_mechanism=False` (see
  `classification.py:326,369,386` for the parameter and its `mechanism is None and
  inherit_mechanism` short-circuit), so the record is emitted with
  `operation="C_GetAttributeValue"`, `mechanism=None`, and the producing mechanism preserved only
  as label/`detail.producer_mechanism` context.
- **Commits** (chronological):
  - `9113e4c2` - "fix: isolate EC readback attribution"
  - `d967f592` - "fix: isolate KDF readback attribution"
  - `7651abfb` - "fix: isolate AES KDF readback attribution"
  - `8f51faa2` - "fix: isolate DH readback attribution"
  - `408dfb8d` - "fix: isolate lifecycle readback attribution"
  - `19a20c5d` - "fix: isolate shared helper readback attribution" (the four remaining shared
    helpers: `_provisioning.py`, `_ec_export.py`, `_rsa_export.py`, `_aes_operability.py`)
  - `c5bddf94` - "fix: normalize operational ECDH peer points" (extends mechanism-free readback
    to operational ECDH peer-point normalization in
    `test_public_session_private_creation.py`/`test_mech_derive.py`/`test_mech_lifecycle.py`)
- **Pinning tests.** `tests/test_f6_shared_helper_attribution.py`,
  `tests/test_f6_ecdh_consumer_normalization.py`, plus the runtime-classification files touched
  alongside each commit above (e.g. `tests/test_dh_key_agreement_runtime_classification.py`,
  `tests/test_ec_import_export_runtime_classification.py`,
  `tests/test_ecdh_known_answer_runtime_classification.py`,
  `tests/test_kdf_runtime_classification.py`).

## F7 - missing attributes no longer fabricate or mask findings

- **Defect.** Provider-backed attribute reads in `src/pkcs11_check/testcases/` subscripted the
  readback dict directly. A provider that omitted an attribute raised an uncaught `KeyError`,
  aborting the test and discarding every other observation already recorded in it; at several
  sites the omission was instead silently normalized into a wrong value (masking a finding) or
  misread as a value the provider never returned (fabricating one) - the most severe case being
  `test_tookan`'s key-type-confusion oracle, which collapsed `MISSING_ATTRIBUTE` to `None` and so
  reported a module that correctly refused the confusion by omitting `CKA_VALUE` as a CRITICAL
  accepted-confusion finding (fixed in `76d50e16`).
- **Fix.** Every such read now routes through the caller-owned `attr_or_record()` presence helper
  (`src/pkcs11_check/testcases/_attribute_values.py`), which returns the value, a `bool`, or the
  `MISSING_ATTRIBUTE` sentinel and lets the caller decide the omission's `reason`/`kind`. An
  AST+symtable taint analyzer, `tests/_attribute_access_guard.py`, statically flags any
  unguarded subscript of a `read_attributes()`-derived dict across the whole testcases tree, and
  `tests/test_required_attribute_access_guard.py::test_all_testcase_sources_have_zero_attribute_access_violations`
  asserts `violations == []` with no `optional_defaults` configured away - an unconfigured
  zero-violation gate, not a suppressed threshold.
- **Commits.** This was migrated incrementally alongside analyzer hardening across roughly 100
  commits between `abf5b7e2` ("test: guard provider attribute access paths", the first commit
  introducing the analyzer) and `afe98f4f` ("test: gate all-source attribute access at zero", the
  commit that finally asserts zero with the gate unconfigured) - run
  `git log --oneline abf5b7e2..afe98f4f` in the framework repo for the full ordered list (105
  commits; a handful are F6/F11 work landed in the same window). The per-domain presence-helper
  migration commits (`route ... attribute reads through presence helper`) are:
  `3606d777`, `b9f4de3f`, `49fdaca0`, `79b29131`, `022c0f58`, `a838122a`, `51fb9b76`, `1306cbe8`,
  `961944c1`, `a2cf5229`, `6b53830b`, `4c9146e9`, `a0c5d6db`. The security-policy hardening
  commit `76d50e16` ("fix: stop missing attributes from inventing or masking security findings")
  is the one that fixes the `test_tookan` CRITICAL-fabrication case above. `3c25b49a` hardens the
  wycheproof missing-value regressions against silent revert.
- **Pinning tests.** `tests/test_required_attribute_access_guard.py` (the analyzer contract and
  the zero-violation release gate) and `tests/test_f7_security_policy.py` (grows from 17 to 43
  tests in `76d50e16`, covering every migrated site class with masking/weakening mutation
  coverage), plus the domain-specific `tests/test_f7_*.py` files added alongside each migration
  commit (e.g. `tests/test_f7_wycheproof.py`, `tests/test_f7_discovery_profiles_trust.py`,
  `tests/test_f7_asymmetric_metadata.py`, `tests/test_f7_object_metadata.py`).

## F11 - classification observability

- **Feature.** An additive `classification_observability` block in the `quality.json` quality
  audit, separately versioned via `F11_CONTRACT_VERSION` (`src/pkcs11_check/core/report_log.py:194`,
  currently `"1"`) so its evolution never bumps the unrelated `quality.json` `schema_version`
  (`src/pkcs11_check/core/quality_audit.py:80`, also currently `"1"`). It reports `unclassified`
  occurrences read from the raw, unrepaired `report.jsonl` stream(s) and never fabricates a zero:
  `status: "unavailable"` renders `unclassified: null` in the artifact and `--` in
  `pkcs11-check report` output (`_format_observability_count` /
  `_classification_observability_section` in `src/pkcs11_check/report/render.py:389,417`);
  `status: "partial"` (a missing or malformed declared source was seen) renders every count as an
  explicit lower bound `>=N`, never as if exact.
- **Commits (slices, per the binding brief referenced in-source comments in
  `core/report_log.py`, `core/quality_audit.py`, and the F11 test modules, held in a gitignored
  workstation-local design brief):**
  - `3100c41c` - "feat: extract raw classification occurrence evidence" (slice A: raw-evidence
    extraction, `core/report_log.py` / `core/_report_records.py`).
  - `94e6f1d1` - "feat: report classification observability in quality audit" (slice B: the
    `classification_observability` block in `build_quality_audit`, wired through
    `core/merge.py`, `cli/test_cmd.py`, `report/render.py`).
  - `32fb085f` - "test: add integrated reporting integrity release gate" (slice D: end-to-end
    integrated test through the real isolated file-runner).
- **Pinning tests.** `tests/test_f11_evidence_extraction.py`, `tests/test_f11_quality_audit.py`,
  `tests/test_f11_quality_extract_wiring.py`, `tests/test_f11_quality_merge.py`,
  `tests/test_f11_quality_render.py`, `tests/test_reporting_integrity_release_gate.py`.

## Findings not covered by this document

- **F8-class machinery (`completion_verified`).** The `completion_verified` field and its
  handling in `core/file_runner.py`/`cli/test_cmd.py` (an explicit `False` for a missing/invalid
  pytest session-finish record) predates this branch - it already exists on `dev`
  (`_completion_verified_for_attempt` and related call sites). It is not a deliverable of
  `codex/v020-reporting-integrity` and is listed here only so its absence above is not mistaken
  for an oversight.
- **F4, F5, F9, F10, F13, F14.** Not present in this repository under any name found during this
  review; no commit, test, or source reference to these IDs was found on this branch or on `dev`.
