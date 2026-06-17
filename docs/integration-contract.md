# Integration Contract (for tools building on pkcs11-check)

pkcs11-check is designed to be driven by other tooling (CI, dashboards, custom
runners). This document is the **stable surface** those tools may depend on from
**v0.1.3 onward**: the CLI exit codes, the machine-readable artifacts, and the
reusable Python building blocks. Changes here are additive within a minor
series; anything not listed is internal and may change without notice.

## CLI exit codes (`pkcs11-check test` / `doctor`)

| Code | Meaning |
|---|---|
| `0` | Ran successfully; no failing/crashing/timed-out tests (xfail/skip are not failures). |
| `1` | Completed but had test failures, crashes, or timeouts (findings present), or a `doctor` check failed. |
| `2` | Usage / configuration error (bad flag, unsupported isolation mode, preflight config error). |
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
  "summary": {                 // integer counts
    "passed": 0, "failed": 0, "skipped": 0, "xfailed": 0,
    "xpassed": 0, "error": 0, "crashed": 0, "timeout": 0, "total": 0
  },
  "units": [                   // one per isolated unit (file or test)
    {"target": "src/.../test_x.py", "status": "passed",
     "returncode": 0, "duration_s": 0.0}
  ],
  "coverage": { ... },         // optional, == coverage.json
  "shards": { ... }            // present only for merged (pooled) runs
}
```
- `status` ∈ `passed | failed | crashed | timeout | empty`. `returncode < 0`
  means the unit's subprocess died on a signal (a crash finding).
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
CK_RV traces ride in `user_properties` when `--rv-trace` is on.

### Sharded runs
`pkcs11-check shard-units` plans N balanced file batches; run each batch
(`PKCS11_CHECK_TARGETS`), then `pkcs11-check merge-shards` reproduces the
single-run artifacts (a split→merge round-trip is exact). See
`docs/docker-artifacts.md`.

### Coverage comparison
`pkcs11-check compare-coverage BASELINE CANDIDATE` compares mechanism coverage
state buckets from artifact directories or coverage/results JSON files. Add
`--fail-on-loss` for CI-style gates that should exit 1 when the candidate loses
a baseline state for the same provider.

## Reusable Python building blocks

- **`pkcs11_check.raw`** — a pure-ctypes PKCS#11 binding (no C build) with
  v2.40/v3.0/v3.1/v3.2 interface negotiation and PQC mechanisms. Usable
  standalone to call any module.
- **`pkcs11_check.core.quality_audit`** — pure artifact analysis helpers,
  including `build_quality_audit()` and
  `compare_mechanism_coverage_states()` for provider-local baseline/candidate
  mechanism-state loss checks.
- **The pytest plugin** (`pkcs11_check.plugin`, entry point `pkcs11-check`) —
  registers the markers, fixtures (`p11_module`, `p11_module_session`,
  `p11_raw_session`, `p11_config`), and `--p11-module/--p11-pin/--p11-slot/...`
  options, so the product test cases can run inside an external pytest session.
- **`pkcs11_check.core.preflight`** — crash-safe capability probing
  (`run_preflight_subprocess` → `CapabilityManifest`).

## Stability commitment

Within the `0.1.x` series these are additive-only: new exit codes are not
introduced for existing conditions, new JSON keys may be added but existing keys
keep their meaning, and the marker/fixture/option names above are kept. The
default profile of a bare `pkcs11-check test` and any change to it is called out
in the CHANGELOG.
</content>
