# Interpreting results - why xfail and skip counts are large

A run collects ~110k+ items per module. Most are **skipped** (mechanism not advertised) and most **xfail** is `not_operational`. A high xfail count is **not** a pile of crypto deviations.

## Why fail counts can also be large

The same systemic amplification that inflates xfail also inflates `fail`: one provider trait can turn into thousands of failed vectors. A single capability gap - for example, a module that mishandles an out-of-range EC curve or key size across an entire vector file - multiplies into thousands of `fail` entries.

Both xfail and fail are recorded findings - a difference from the checked expectation - not defects in pkcs11-check. This is current behavior and may change.

## Counts and retained observations

For ordinary pytest `TestReport` records, `counts` describes logical testcases, not report-log lines. One testcase contributes one conservative outcome across its setup, call, teardown, and retained retry records, in this priority order: `timeout`, `crashed`, `error`, `failed`, `xpassed`, `xfailed`, `passed`, `skipped`. A later pass therefore does not erase an earlier finding, and a cleanup error does not erase the original call-phase evidence. The `tests` list retains each nonpassing observation for inspection, so it can contain more entries than the sum of ordinary testcase counts. Raw `report.jsonl` records remain unchanged and authoritative.

Collection, harness, process, finalization, recovery, and other file-level diagnostics are not ordinary testcase outcomes. Any counts they contribute remain separately additive. Grouped at-source classification reports are also occurrence reports: their `count` is the number of serialized classification occurrences, not a distinct-testcase count.

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
