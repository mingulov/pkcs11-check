# Integration Contract (for tools building on pkcs11-check)

pkcs11-check is designed to be driven by other tooling (CI, dashboards, custom
runners). This document is the **stable surface** those tools may depend on from
**v0.1.3 onward**: the CLI exit codes, the machine-readable artifacts, and the
reusable Python building blocks. Changes here are additive within a minor
series; anything not listed is internal and may change without notice.

## CLI exit codes (`pkcs11-check test` / `doctor`)

| Code | Meaning |
|---|---|
| `0` | Ran successfully; every durable isolated result is verified `passed`/`empty` (xfail/skip are not failures). |
| `1` | Completed but had test failures, crashes, timeouts, escalation/crash-limit residue, or incomplete results (other than harness-only pytest exits `2`, `3`, or `4`), or a `doctor` check failed. |
| `2` | Usage / configuration error (bad flag, unsupported isolation mode, preflight config error), or a pytest harness/incomplete exit (`2`, `3`, or `4`) with no provider finding. |
| `3` | Module not found or not loadable. |

Drive a gate on `0` vs non-zero; distinguish "findings" (`1`) from "couldn't run"
(`2`/`3`) when you need to.

## Machine-readable artifacts (`--output json`)

`pkcs11-check test --output json --output-file results.json` writes, next to
`results.json`:

### `results.json`
```jsonc
{
  "tool": "pkcs11-check",
  "kind": "test-run",
  "summary": {                 // integer counts plus the run-health boolean
    "passed": 0, "failed": 0, "skipped": 0, "xfailed": 0,
    "xpassed": 0, "error": 0, "crashed": 0, "timeout": 0, "total": 0,
    "incomplete": false
  },
  "units": [                   // one per isolated unit (file or test)
    {"target": "src/.../test_x.py", "status": "passed",
     "returncode": 0, "duration_s": 0.0}
  ],
  "attempt_history": [ ... ],  // optional superseded daemon-recovery attempts
  "recovery_events": [ ... ],  // optional confirmed daemon deaths
  "coverage": { ... },         // optional, == coverage.json
  "shards": { ... }            // present only for merged (pooled) runs
}
```
- `status` ∈ `passed | failed | crashed | timeout | empty | escalated | crash_limited`.
  `escalated` means a file-level crash was expanded to per-test isolation;
  `crash_limited` means remaining tests were abandoned after the configured crash budget.
  The durable `escalated` trigger remains a resume-control marker, but its crash/timeout
  return code is reflected as `crashed`/`timeout` (with a corresponding count) in grouped JSON
  and JUnit output, even when its per-test children passed.
  `returncode < 0`
  means the unit's subprocess died on a signal (a crash finding).
- For an isolated attempt with a report log, normal collected pytest exits `0`, `1`, and `5`
  are accepted only when the stream has one valid `SessionStart`/`SessionFinish` pair and the
  finish's integer `exitstatus` exactly matches the subprocess return code. If the finish is
  missing, malformed, duplicated, or mismatched, the unit keeps its collected detail but carries
  `"completion_verified": false` and `"incomplete": true`; the aggregate carries
  `"summary": {"incomplete": true}`. These fields are additive, and an omitted
  `completion_verified` in an older state is read as verified for compatibility except for raw
  pytest exits `2`, `3`, and `4`, which are always treated as unverified.
- Isolated child exits `2`, `3`, and `4` are retained as the unit `returncode` and incomplete
  harness evidence, with the public CLI exit normalized to `2` when no provider finding is
  present. If the same report also contains provider failed/crashed/timeout evidence, that
  finding is retained and takes precedence with public exit `1`. Crashes, Windows crash codes,
  and timeouts remain findings with public exit `1`.
- Non-isolated output applies the same completion rule to its one captured report-log stream:
  only raw exits `0`, `1`, and `5` with exactly one balanced session and a matching finish are
  verified. A missing or mismatched finish adds one typed `HarnessError` with the raw return code
  and makes the public exit `1`; raw `2`/`3`/`4` add the same evidence and return public `2` unless
  provider evidence makes it `1`. A complete raw `5` session is an empty pytest run and returns
  public `2` because the overall pkcs11-check run executed no tests.
- A pytest collection/configuration failure that prevents a unit or run from starting is a
  harness error: it is represented by a failed `CollectReport`, counted under `error`, and marks
  the affected unit and run `incomplete`; it is not a provider fail, xfail, or crash finding. A
  standalone/global collection result also exposes `"completion_verified": false` on its unit.
  The attempt is retained in an atomic state-adjacent collection sidecar so interruption and
  `--resume` cannot erase it; JSON output retains the raw evidence as `report.jsonl`, and JUnit
  renders it as `<error type="collection">` with labeled stderr/stdout diagnostics. Fresh runs
  clear the sidecar and report artifacts. `CollectReport` records with outcome `skipped` remain
  no-tests/skip behavior and are not converted into harness errors.
- `--resume` is continuation-only: every planned target already present in saved results is
  skipped, regardless of status or `completion_verified`; only missing targets run. This means
  failed, crashed, timed-out, unverified, escalated, and crash-limited results are preserved, not
  retried or revalidated. A fresh run without `--resume` is the reset/revalidation boundary and
  clears the state-specific report-record shards, known `report.jsonl`, configured output,
  `quality.json` beside the output, and `coverage.json`/`provisioning.json` beside `report.jsonl`
  before execution. Existing higher infrastructure codes are preserved only when no durable
  provider finding exists; on `--resume`, cached or inline provider evidence takes precedence
  and returns public code `1`.
- A resumed run returns `0` only when every durable result is verified and has status `passed` or
  `empty`; preserved provider findings or incomplete results return `1`, while raw pytest harness
  exits `2`/`3`/`4` without a provider finding return public code `2`. A provider finding retained
  alongside one of those harness exits still returns `1`.
- Daemon recovery can replace a dying provider's result only as the current aggregate verdict.
  The superseded attempt (including report records, output, and process observations) remains in
  `attempt_history`; every confirmed daemon death remains in `recovery_events` and contributes a
  separate synthetic crashed unit. Pending `RecoveryAttempt` sidecar records are validated and
  replayed on resume, so interruption before the next state save cannot erase them.
- The summary classification model (`pass`/`xfail`/`fail`/`skip`) is documented
  in `docs/classification-model-design.md`: a crash or a wrong-accept is `fail`;
  an honest single deviation is `xfail`.

### `coverage.json`
Merged function- and mechanism-coverage:
`{"function_coverage": {"available", "called", "called_names", "called_counts",
"bootstrap_counts", "uncalled_names"}, "mechanism_coverage": {"available",
"available_names", "invoked", "invoked_names", "invoked_counts", "not_invoked",
"not_invoked_names", "invoked_detail", "invoked_detail_counts"}}`.

Mechanism coverage may also include additive state buckets:
`advertised_names`, `selected_names`, `selection_rejected_names`,
`attempted_names`, `accepted_names`, `rejected_cleanly_names`,
`skipped_by_capability_names`, `crashed_names`, and `timeout_names`. These are
the preferred fields for distinguishing registry-only visibility, selected but
unreached mechanisms, clean operational refusals, capability skips, and
crash/timeout outcomes; older `invoked*` fields remain for compatibility.

### `quality.json`
A conservative quality audit (summary counts, per-finding details, warnings)
derived purely from `results.json` + `coverage.json` + the report log. Treat its
top-level `summary` and `findings` as stable; nested detail may grow.
Mechanism findings include a primary `status` plus additive
`telemetry_states`/boolean fields when the richer mechanism buckets are present.

### `report.jsonl`
The raw pytest-reportlog stream (one JSON record per line: TestReport,
CoverageReport, SelectionReport, …). Large; stream it line-by-line. Per-test
CK_RV traces ride in `user_properties` when `--rv-trace` is on. A fresh non-resume run clears the
known path before execution; resumed runs preserve saved per-unit shards and merge them.
Collection/configuration failures add a failed `CollectReport` with `stderr:` and `stdout:`
diagnostics. An unverified pytest attempt adds a separate `HarnessError` record carrying its raw
return code and `completion_verified: false`; it is not encoded as a `CollectReport`. The
state-adjacent collection-attempt sidecar is an internal durable source used to replay this
evidence while resuming; consumers should use `report.jsonl` as the documented raw artifact and
must not reinterpret either harness record as provider findings.
Daemon-recovery evidence uses `RecoveryAttempt` and `RecoveryEvent` records. Consumers that do not
understand custom record types may ignore them, but must not reinterpret them as `TestReport`.
Call-phase `TestReport` records may carry serialized `pkcs11_classification` entries. Their
`reason`/`outcome`/`severity` fields are the source evidence used by the per-provider report;
reserved runtime-gate `unclassified` entries are fail-closed provider evidence, rendered and
included in provider fail/severity totals, while also contributing to a separately labeled
migration-backlog count. Only `harness_error` entries are excluded from provider totals. Consumers
that do not understand `HarnessError` may ignore it safely, but must not reinterpret it as a
provider or collection result.

### JUnit output

With `--output junit`, an unverified isolated unit is emitted as a testcase `<error>` with
`type="incomplete"` and message `report log completion could not be verified`; it increments
the suite's `errors` count rather than `failures` or `skipped`. This is distinct from the
`crashed` and `timeout` error types. Harness evidence is additive: when provider
failed/crashed/timeout evidence coexists with an incomplete or persisted harness error, the
provider testcase remains and a separate `type="incomplete"` testcase is emitted; a provider
finding wins the public exit (`1`) over a same-unit harness-only exit (`2`). Collection evidence
is likewise additive, with a separate `type="collection"` testcase; collection and harness
evidence without provider evidence still produce two independently typed testcases. Suite counts
match the emitted testcases. Each confirmed daemon-recovery event is also emitted as its own
crashed error testcase.

Differential validation accepts complete isolated logs containing multiple balanced
`SessionStart`/`SessionFinish` pairs and global custom records. A failed `CollectReport`, an
unbalanced session, or a `TestReport` outside an active session is rejected as incomplete.

### Sharded runs
`pkcs11-check shard-units` plans N balanced file batches; run each batch
(`PKCS11_CHECK_TARGETS`), then `pkcs11-check merge-shards` reproduces the
single-run artifacts (a split→merge round-trip is exact).

### Coverage comparison
`pkcs11-check compare-coverage BASELINE CANDIDATE` compares mechanism coverage
state buckets from artifact directories or coverage/results JSON files. Add
`--fail-on-loss` for CI-style gates that should exit 1 when the candidate loses
a baseline state for the same provider.

## Reusable Python building blocks

- **`pkcs11_check.raw`** - a pure-ctypes PKCS#11 binding (no C build) with
  v2.40/v3.0/v3.1/v3.2 interface negotiation and PQC mechanisms. Usable
  standalone to call any module.
- **`pkcs11_check.core.quality_audit`** - pure artifact analysis helpers,
  including `build_quality_audit()` and
  `compare_mechanism_coverage_states()` for provider-local baseline/candidate
  mechanism-state loss checks.
- **The pytest plugin** (`pkcs11_check.plugin`, entry point `pkcs11-check`) -
  registers the markers, fixtures (`p11_module`, `p11_module_session`,
  `p11_raw_session`, `p11_config`), and `--p11-module/--p11-pin/--p11-slot/...`
  options, so the product test cases can run inside an external pytest session.
  Note: `--p11-module/--p11-pin/--p11-slot` are the pytest-plugin option names
  (used when invoking `pytest` directly); the `pkcs11-check test` CLI uses the
  shorter `--module/--pin/--slot` names.
- **`pkcs11_check.core.preflight`** - crash-safe capability probing
  (`run_preflight_subprocess` → `CapabilityManifest`).

## Stability commitment

Within the `0.1.x` series these are additive-only: new exit codes are not
introduced for existing conditions, new JSON keys may be added but existing keys
keep their meaning, and the marker/fixture/option names above are kept. The
default profile of a bare `pkcs11-check test` and any change to it is called out
in the CHANGELOG.
