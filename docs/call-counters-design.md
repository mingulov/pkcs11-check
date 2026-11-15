# Complete PKCS#11 call counters - reference

Shipped feature reference. The call counters count every `C_*` call made
through the loaded module - by function name and `CK_RV`, attributed to one of
four scope buckets - so that run totals match an external observer's counts.
Per-test window entries ride `report.jsonl`'s `user_properties` and one session
record per process rides the same stream; the extractor folds both into a
`call_counters` block in `results.json`. Always on, no flag; secret-safe by
construction.

## Context

The suite already funnels (almost) every `C_*` call through a single choke
point: `RawPKCS11._call(name, *args)` at `raw/api.py`. Entry to `_call` counts
the call; the integer result of `func(*args)` records the `CK_RV` - *before*
`_to_ckr()`, so the value the module actually returned is observable at one
place. The two calls that cannot pass through `_call` - `C_GetInterface` and
`C_GetFunctionList` inside `_load_from_lib`, which run before the funclist
exists - are counted explicitly as entry-plus-exit pairs. A call that crashes
the process inside the module therefore counts with no RV.

Attribution is a bucket stack in the single owner module
`core/call_counters.py` (the only module that owns counter state; `raw/api.py`
imports it, never the reverse). The pytest plugin windows each test with
wrapper hooks; probe children, which run in their own processes, flatten their
counters through the existing coverage-file channel and the parent folds them
in. The report pipeline preserves `user_properties` and extra JSONL record
types for free, and the pooled shard merge concatenates `report.jsonl`
byte-for-byte, so the extractor can recompute merged counters from the merged
stream exactly as it does for coverage.

## Goals

1. Record complete per-run counters: every `C_*` call through the module, by
   function and `CK_RV`, in four scope buckets, so run totals match an
   external observer's counts.
2. Always on. No CLI option, no env switch, no per-run configuration.
3. Attribute calls to their phase: per-test window entries plus one session
   record per process in `report.jsonl`, merged into `results.json` on the
   isolated, `--isolation none`, and merge paths alike.
4. Reconcile loudly: run totals equal the sum of buckets; retries, crashed
   children, and lost probes are accounted by explicit rules, never silently.
5. Never record secret material (PINs, key bytes, plaintext, `CKA_VALUE`).
   Counters carry only function names, RV ints/names, and counts.

## Non-goals

- **No diffing / regression-comparison tooling.** The consumer of this data
  performs the diff. We only produce the counters; the comparison recipe below
  shows which fields to compare and which caveats apply.
- **No change to any test's outcome.** The counters are observational. They
  never influence pass/xfail/fail/skip, and the classification model is
  untouched.
- **No change to in-test `pkcs11_rv_trace` output.** The rv-trace feature is
  untouched; the two ride side by side.
- **No change to `_call_log` / `reset_call_log` semantics.** Resetting the
  call log does not clear the global counters.
- **No off switch.** Always-on is the design, not a missing flag.

## Schema

### Serialized counters (the shape everything reuses)

```json
{"total_calls": 0, "buckets": {"<bucket>": {"calls": 0, "by_fn": {"<fn>": {
  "calls": 0, "by_rv": {"<rv-int>": {"name": "<CKR_...>", "count": 0}}}}}}}
```

- Buckets, functions, and RVs with zero calls are omitted (sparse).
- RV keys are decimal integer strings (`"0"`, `"49"`); `name` comes from
  `ckr_name` with a hex fallback for unknown codes.
- `sum(by_rv) <= calls` per function: entry increments `calls`, exit adds the
  RV, so a call that never returns counts with no RV row.
- Invariant: `total_calls` equals the sum of the per-bucket `calls`.

### `results.json` block

```json
{"complete": true, "total_calls": 0,
 "by_bucket": {<serialized counters>},
 "probes_lost": 0,
 "by_process": [{"pid": 0, "isolation": "<mode>", "total_calls": 0,
                 "complete": true}]}
```

- `by_bucket` is the serialized shape above; the top-level `total_calls`
  equals `by_bucket.total_calls`, which equals the sum of its buckets.
- `complete` is true iff every `(target, attempt)` group is complete. A group
  is complete iff a session record exists for it AND no fallback per-test
  deltas were folded in AND session `probes_lost` is zero.
- `by_process` carries one row per pid that contributed a session record or
  fallback deltas; `isolation` is the `PKCS11_CHECK_ISOLATION` value that
  process saw.
- The block is absent (not empty) when the JSONL predates this feature, so old
  artifacts stay clean.

### Session record (`CallCountersReport`)

One JSONL record per process, emitted at session finish (including the
early-return branch, and after the teardown `C_Finalize` so that call is
included): `$report_type`, `pid`, `isolation` (env value, default
`"unknown"`), `probes_lost` (there is no `probes_completed` field), plus the
serialized counters of everything that process recorded.

### Per-test entry (`pkcs11_call_counters`)

A `user_properties` entry on the teardown report: `pid` plus the serialized
baseline-to-now window diff (setup-phase calls in `setup_teardown`, body
calls in `test`). Setup/call reports predate the computation and always carry
nothing. No entry is attached when the window holds no calls. A skip in setup
still yields a setup-only entry.

### Child wire format

Probe children flatten to `[[fn, rv_or_null, count], ...]`, sorted by
function name, then RV ascending with the unreturned row last per function.
Bucket attribution is dropped - the ingesting parent applies its own active
bucket. `rv null` marks calls that never returned. Garbage rows are ignored
without raising.

## Buckets

The four bucket strings, exactly: `test`, `setup_teardown`,
`session_provisioning`, `module_init`.

- `test` - the test-body phase, between fixture setup and teardown (pushed by
  the call-phase wrapper hook).
- `setup_teardown` - fixture setup and teardown phases (pushed by the setup
  and teardown wrapper hooks).
- `session_provisioning` - the default bucket, used whenever the stack is
  empty: session fixtures, key provisioning, and anything else outside a
  pushed bucket.
- `module_init` - module lifecycle: the `load_module` body, the
  `P11Module.reinitialize` body, and the session-teardown `C_Finalize`.
  That is `C_GetInterface` and/or `C_GetFunctionList` from `from_lib`, one
  `C_Initialize` from `load_module` (plus `reinitialize`'s
  `C_Finalize`/`C_Initialize` and the teardown `C_Finalize`).

The stack nests: the innermost pushed bucket wins and the previous bucket is
restored on exit (every push is a try/finally context manager, so a raising
phase cannot unbalance it). Pushing an unknown name raises `ValueError`.

Attribution is window-truthful, not origin-truthful: session-fixture or
provisioning work that executes inside a test window lands in `test` or
`setup_teardown`, so `session_provisioning` typically holds only
out-of-window traffic and is often sparse.

## Exclusions

Counted nowhere, by design:

- Preflight/doctor/recovery helper subprocesses (own processes,
  harness-internal).
- The openssl-interop grandchild binary (third-party, uninstrumentable).
- Operator-supplied external provision commands and token-mint tools
  (third-party, uninstrumentable - same class as openssl-interop).

Everything else the harness spawns is either folded in (probe children via
the coverage channel) or accounted as lost: a probe child whose counters
cannot be recovered increments `probes_lost` and flips its group - and hence
the run - to `complete: false`.

## Comparison recipe

To compare the counters of two runs (no tool is shipped; the consumer diffs):

1. Check `complete` on both blocks first. If either is false, read
   `probes_lost` and `by_process[].complete` to see what is missing before
   trusting any delta.
2. Compare `total_calls`, then each bucket's `calls`. A module-load change
   shows in `module_init`; a fixture change in `setup_teardown`; a test-body
   change in `test`.
3. Drill into `by_fn` / `by_rv` for the drifted bucket. Mechanism-behavior
   changes typically show as RV shifts under an unchanged call count.
4. Sanity-check the invariant `total_calls == sum(buckets)` on each block; a
   mismatch means a corrupt or hand-edited artifact, not a module change.
5. Caveats:
   - Retried units count twice: two session records in one group are both
     real calls and both are summed.
   - Never sum session records and per-test entries for the same pid: entries
     whose pid has a session record in the group are superseded and folded
     only as the crashed/timed-out fallback.
   - `by_process` rows differ legitimately across isolation modes (one pid in
     `none`, one per unit otherwise); compare `total_calls`, not row counts.
   - Merged counters are recomputed from the concatenated JSONL, so a merged
     block equals its shards modulo retries - it is never a sum of shard
     `results.json` blocks.
   - The crashed/timed-out fallback (per-test deltas folded without a
     session record) is a lower bound: calls outside any test window are
     missing.
   - Per-test entries never include the post-window teardown `C_Finalize`
     (the session record does), so entry sums reconcile with session totals
     modulo that call plus any out-of-window traffic.
   - `by_process[].isolation` records the raw `--isolation` flag value
     (e.g. `"auto"`), not the effective per-unit mode.

## Design

Small seams, each following an existing pattern.

### 1. Capture - `raw/api.py`, `_ckr_ctypes.py`, `raw_session.py`

- `_call`: `record_call(name)` immediately before the module invocation
  (after funclist resolution, so an unavailable function counts nothing),
  `record_return(name, result)` after `result = int(func(*args))`. No
  signature or return-value changes.
- `_load_from_lib`: `record_call`/`record_return` pairs around the
  `C_GetInterface` and `C_GetFunctionList` direct sites (a raising attempt
  counts entry-only).
- `_ckr_ctypes.call_func`: entry/exit recording around the raw ctypes call,
  so the CKR probes count without a `RawPKCS11` instance.
- `raw_session.py`: a counting `CDLL` proxy for `ctx.lib` (wraps `C_*`
  attributes, forwards `restype`/`argtypes`/`errcheck` sets, ignores
  non-`C_*` attributes) plus an explicit entry/exit pair for its own
  `C_GetFunctionList`; `counting_cdll()` wraps direct-symbol handles in
  probes that bypass `ctx.lib`.

### 2. Buckets - `core/loader.py`, `_plugin_finalize.py`, `_plugin_counters.py`

- `load_module` and `P11Module.reinitialize` bodies run inside
  `counted_bucket("module_init")`, as does the teardown `C_Finalize`.
- `_plugin_counters.py` holds three pytest wrapper hooks
  (`setup`/`call`/`teardown`, all `wrapper=True, tryfirst=True`): setup
  stashes a baseline snapshot and pushes `setup_teardown`; call pushes
  `test`; teardown pushes `setup_teardown` again and diffs baseline-to-now
  in a finally. A `makereport` wrapper attaches the stashed entry.
- Every hook starts with the `p11_module`-absent guard and the testcase-item
  guard, so meta-test runs pass through untouched and their report streams
  stay byte-identical.
- `plugin.py` registers the module in `pytest_configure` and emits the
  session record in `pytest_sessionfinish` on both the early-return branch
  and after `_finalize_on_teardown`.

### 3. Child channel - `_probes/`, `_subprocess_preamble.py`, `_raw_subprocess.py`

- `write_coverage(..., call_counters=None, probes_lost=0)` gains the
  optional flattened payload key plus the child's own lost count;
  `session.py` and `raw_session.py` probes pass `flatten_current()` and
  their `probes_lost()`.
- Both ingest functions fold the key in via `ingest_child_counts` under the
  parent's active bucket, accumulate the payload's `probes_lost`, and return
  whether usable counters were recovered (new return; existing callers may
  ignore it).
- `runner.py` calls `note_lost_probe()` exactly when ingest reports no
  usable counters (missing/corrupt coverage file included - ingest never
  raises).
- Below the probe child: the isolation grandchild writes a private coverage
  path the probe child ingests; the fork child (untransmittable via
  `os._exit` by design) is accounted lost by its reaping parent; the
  threading workload child prints a `P11_CALL_COUNTERS_JSON:` stdout marker
  the parent folds in, accounting lost when it is absent or unusable.

### 4. Extraction - `_jsonl_extract.py`, `_report_writers.py`, `file_runner.py`, `test_cmd.py`, `merge.py`

- `extract_call_counters_from_jsonl` segments the stream by
  `IsolatedUnitReport` (target, attempt) provenance exactly like the
  classification-occurrence iterator (reset at `SessionStart`; a malformed
  marker resets to unattributed; never raises). Reconciliation per group:
  sum every session record; fold a buffered per-test entry only when its pid
  has no session record in that group. Malformed records are ignored.
- `write_isolated_json_report(..., call_counters=None)` sets
  `payload["call_counters"]` when truthy; the isolated path extracts per
  unit JSONL and passes it in.
- `PKCS11_CHECK_ISOLATION` carries the mode to the session record: the
  runner sets the `--isolation` flag value for unit children, `test_cmd`
  sets `"none"` for the in-process path (restored afterwards with the other
  run-scoped keys).
- The none path embeds counters where it embeds coverage; `merge.py`
  recomputes from the concatenated merged JSONL.

## File-change map

| File | Change |
|---|---|
| `core/call_counters.py` | Counter state owner: bucket stack, record/snapshot/diff, serialize/flatten/merge, child ingest, lost-probe count. |
| `raw/api.py` | `_call` entry/exit recording; two `record_direct_call` sites in `_load_from_lib`. |
| `core/loader.py` | `load_module` and `reinitialize` bodies in `module_init`. |
| `_plugin_finalize.py` | Teardown `C_Finalize` in `module_init`. |
| `_plugin_counters.py` | Setup/call/teardown wrapper hooks, per-test entry attach, session-record builder/emitter. |
| `plugin.py` | Register `_plugin_counters`; emit the session record on both session-finish paths. |
| `testcases/_probes/_emit.py` | `write_coverage(..., call_counters=None)` payload key. |
| `testcases/_probes/session.py`, `raw_session.py` | Pass `flatten_current()`; counting CDLL proxy + explicit `C_GetFunctionList` record. |
| `testcases/_probes/_ckr_ctypes.py` | Entry/exit recording in `call_func`. |
| `testcases/_subprocess_preamble.py`, `_raw_subprocess.py` | Ingest child counters; usable-counters boolean return. |
| `testcases/_probes/runner.py` | `note_lost_probe()` when ingest reports unusable. |
| `core/_jsonl_extract.py` | `extract_call_counters_from_jsonl`; none-path embedding. |
| `core/_report_writers.py` | `write_isolated_json_report(..., call_counters=None)` payload key. |
| `core/file_runner.py`, `cli/test_cmd.py` | Per-unit extraction + pass-through; `PKCS11_CHECK_ISOLATION` env on both paths. |
| `core/merge.py` | Merged `call_counters` recomputed from concatenated JSONL. |

## Enabling

There is none: the counters are always on. `PKCS11_CHECK_ISOLATION` is set by
the runner itself (the `--isolation` flag value for unit children, `"none"`
for the in-process path) and read back by the session record; it is plumbing,
not configuration.
