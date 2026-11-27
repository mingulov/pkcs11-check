# Interpreting results - why xfail and skip counts are large

A run collects ~110k+ items per module. Most are **skipped** (mechanism not advertised) and most **xfail** is `not_operational`. A high xfail count is **not** a pile of crypto deviations.

## Why fail counts can also be large

The same systemic amplification that inflates xfail also inflates `fail`: one provider trait can turn into thousands of failed vectors. A single capability gap - for example, a module that mishandles an out-of-range EC curve or key size across an entire vector file - multiplies into thousands of `fail` entries.

Both xfail and fail are recorded findings - a difference from the checked expectation - not defects in pkcs11-check. This is current behavior and may change.

## Framework release gate

A pkcs11-check release is gated on reporting integrity and safe continuation, not on making providers appear clean. Provider `fail`/`xfail` results and real crashes are expected evidence and do not by themselves block a framework release. Release validation must show that pkcs11-check:

- classifies observations accurately and preserves serialized findings across setup, call, teardown, retries, and derived reports;
- distinguishes provider behavior from harness defects and does not invent crash attribution;
- continues independent tests safely, recovering damaged shared state before reuse; and
- leaves no unresolved harness defects, lost classifications, or false crash reports in the
  validated release scope.

`unclassified` results are a separate matter and are **not** claimed to be absent. A test whose
provider finding is reported by a bare `AssertionError` arrives as `unclassified` at `fail`/`HIGH`
with its assertion text intact: the observation is retained, counted, and explained by its own
message -- it simply has not yet been migrated to a structured reason and kind. The v0.2.0 confirm
round carried 125 such records across 115 node-ids. Migration of the remainder is tracked for
v0.2.1; `unclassified` is reserved for the runtime gate and is never itself a release gate.

Strict conformance tests retain provider deviations as independent results. Operational tests may continue through capability gaps or non-standard representations only when that behavior is explicitly validated and the separate conformance evidence is not erased.

The v0.2.0 preservation guarantee covers findings already serialized to authoritative artifacts. Observations held only in memory when a worker terminates abruptly cannot be recovered without a separate durable journal and are outside this release guarantee; the worker crash itself remains evidence.

### The per-node-id differential (how release validation is actually done)

Aggregate PASS/FAIL/xfail counts cannot answer the only question that matters at release time: *did this release keep finding what the last one found?* Two releases can report near-identical totals while a hundred findings were silently traded for a hundred others. The evidence that answers it is a **per-(provider, node-id) differential** against a real baseline round.

Index each round's `results/<provider>-shard-N/report.jsonl` into `(provider, node-id) -> {outcome, classification reasons}` (`core/report_log.iter_classification_occurrences` is the shared parser for the classification side), then diff two indexes and read three things:

1. **Findings released** -- every `fail`/`xfail` that became `pass` or `skip`. Each one needs an explicit justification, checked against what the module *actually returned* in the baseline round. The baseline's own `pkcs11_rv_trace` records are the adjudicator: if a baseline finding contradicts the baseline trace, the old record was harness-invented and releasing it is correct. If it agrees with the trace, a real deviation is being hidden.
2. **Findings gained** -- new `fail`/`xfail`. These need the same scrutiny in the other direction: inventing findings against conformant providers is as much a quality loss as hiding them.
3. **Node-id coverage** -- node-ids present in the baseline and absent now. A test that stopped running reports nothing, and reports it as silence rather than as a gap.

This is not a substitute for the meta-test suite, the analyzer gate, or code review -- it is the only check that operates on what the tool actually did to real modules. In v0.2.0 it caught a reporting-integrity defect that six code reviews, nine slice reviews, an all-source analyzer gate and a dedicated strictness audit all missed.

### Never widen an expected-RV set to silence a mis-verdict

The defect above is worth stating as a rule, because the mistake is natural and the failure is silent.

A site was correctly identified as classifying `CKR_FUNCTION_NOT_SUPPORTED` as a provider deviation, which is wrong -- FNS is capability absence at the **function** level, orthogonal to mechanism advertisement. The fix applied was to add `CKR_FUNCTION_NOT_SUPPORTED` to each function's expected-RV set. That removes the deviation, but it does so by making the test **pass** -- and a pass carries no classification record, no reason, and nothing at all in the report. "The module does not implement this function" became indistinguishable from "the module answered this negative op correctly", while the provider's PASS count went up.

**A `pass` asserts that the module did the right thing. If the module did not answer at all, the verdict is a `skip` carrying the reason -- never a `pass`, and never a widened expected-RV set.** The skip keeps the declining function named and visible in skip accounting; the expected-RV set stays reserved for return codes that genuinely answer the question the test asked.

## Counts and retained observations

For ordinary pytest `TestReport` records, `counts` describes logical testcases, not report-log lines. One testcase contributes one conservative outcome across its setup, call, teardown, and retained retry records, in this priority order: `timeout`, `crashed`, `error`, `failed`, `xpassed`, `xfailed`, `passed`, `skipped`. A later pass therefore does not erase an earlier finding, and a cleanup error does not erase the original call-phase evidence. The `tests` list retains each nonpassing observation for inspection, so it can contain more entries than the sum of ordinary testcase counts. Raw `report.jsonl` records remain unchanged and authoritative.

Collection, harness, process, finalization, recovery, and other file-level diagnostics are not ordinary testcase outcomes. Any counts they contribute remain separately additive. Grouped at-source classification reports are also occurrence reports: their `count` is the number of serialized classification occurrences, not a distinct-testcase count.

JUnit output remains unit-oriented: one isolated unit is one `<testcase>`. A completed xfail is retained as public finding evidence in that testcase's `<system-out>` with its count and, when available, nodeid, outcome, and reason; it does not become a JUnit failure or change the existing exit/CI coloring policy. A genuinely all-skipped unit uses `<skipped type="skip">`; a mixed pass/skip unit is not marked wholly skipped.

`IsolatedUnitReport` records delimit retained source chunks and identify their scheduled owner. Their zero-based `attempt` is an ingestion-order marker; on a legacy seeded shard it is only a seed-local boundary, not a recovered historical attempt ID. Physical-file grouping uses collected owner aliases to reconcile equivalent nodeid spellings. Resume remains continuation-only, and daemon-recovery attempts superseded from the active aggregate remain archived in `attempt_history` and `recovery_events` rather than being folded back into the active testcase summary.

## `not_operational` is mostly a capability gap, amplified by vector count

The dominant `not_operational` pattern is an advertised **mechanism** (e.g. `CKM_ECDSA`, `CKM_ECDH`, `CKM_RSA_PKCS`) exercised with an **unsupported curve or key size** (brainpoolP224r1, Montgomery, RSA-1024). PKCS#11 has no per-curve capability flag, so the harness can only discover this by trying; a clean rejection of an unsupported curve is conformant, but it is recorded as a deviation and multiplied by the entire wycheproof/ACVP vector file - so one capability gap becomes thousands of `not_operational` xfails (the same curve produced the identical ~12k count across unrelated modules).

**Read the reasoned buckets, not the raw xfail total:** `honest_deviation`, `nonspec_reject`, in-range `not_operational`, and the `fail` list (`accepted_invalid`, `self_contradiction`, `wrong_result`, `crash`). Those are the findings.

## `crash_limited` and incomplete coverage

When a module crashes repeatedly in one file, the runner abandons that file's remaining tests after `--max-crashes-per-file` (default 10) and records them as `crash_limited` (a skipped-class outcome counted in `total`). `summary.incomplete` is then true and the report shows an INCOMPLETE COVERAGE banner. These tests' true outcome is unknown - re-run to probe them.

**Resume caveat:** resume is continuation-only: it skips every target already attempted in the
saved state, including `crash_limited`, crashed, timed-out, failed, and incomplete targets. Start
a fresh run without `--resume` to clear the prior generation and re-probe any of them.

## `hollow_coverage` - green that did not actually run the operation

`quality.json` carries a `hollow_coverage` list flagging operations whose passing tests did not productively invoke them. For each operation a test declared (via `set_mechanism`), the oracle compares the number of passing tests claiming it against the number of productive (`CKR_OK`) invocations of that operation's function family; a large claimed-pass population with a near-zero ratio means most of those green passes never actually ran the operation. This catches the class of bug where, e.g., `C_Sign` executed only once across thousands of green "sign" tests - the green was hollow. It is a run-quality signal for triage (a `HOLLOW COVERAGE` line in `data_quality_warnings`), not a per-test verdict or a provider-bug accusation; the counts name the operation so a human can adjudicate.
