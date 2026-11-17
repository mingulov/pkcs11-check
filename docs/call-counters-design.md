# Complete PKCS#11 call counters - reference

Shipped feature reference. The call counters count every `C_*` call made
through the loaded module - by function name and `CK_RV`, attributed to one of
five scope buckets and to the module id bound to the handle the call passed
through - so that run totals match an external observer's counts for fully
recovered executions. Anything less is fail-visible: named losses and
`complete: false`, or a loud warning for preflight persistence failures
(see Durability).
Per-test window entries ride `report.jsonl`'s `user_properties` and one session
record per process rides the same stream, each carrying the process
`worker_uuid`; the extractor folds both into a `call_counters` block in
`results.json`. Always on, no flag; secret-safe by construction.

## Context

The suite already funnels (almost) every `C_*` call through a single choke
point: `RawPKCS11._call(name, *args)` at `raw/api.py`. Entry to `_call` counts
the call; the integer result of `func(*args)` records the `CK_RV` - *before*
`_to_ckr()`, so the value the module actually returned is observable at one
place. The two calls that cannot pass through `_call` - `C_GetInterface` and
`C_GetFunctionList` inside `_load_from_lib`, which run before the funclist
exists - are counted explicitly as entry-plus-exit pairs. A call that crashes
the process inside the module therefore counts with no RV.

Attribution is two-level (a process-global phase plus thread-local regions)
in the single owner module `core/call_counters.py` (the only module that owns
counter state; `raw/api.py` imports it, never the reverse). Identity adds two
more axes: every call carries its handle's module id (bound before the first
loader C call; see Module identity), and every record carries the process
`worker_uuid`. The pytest plugin windows each test with wrapper hooks; probe
children, which run in their own processes, flatten their counters through
the existing coverage-file channel and the parent folds them in. The report
pipeline preserves `user_properties` and extra JSONL record types for free,
and the pooled shard merge concatenates `report.jsonl` byte-for-byte for
coverage while counters merge from the per-shard JSONL extracts (fresh
provenance per shard).

## Goals

1. Record complete per-run counters: every `C_*` call through the module, by
   function and `CK_RV`, in five scope buckets and split by module id, so
   run totals match an external observer's counts for fully recovered
   executions (anything less is fail-visible per Durability).
2. Always on. No CLI option, no env switch, no per-run configuration.
3. Attribute calls to their phase: per-test window entries plus one session
   record per process in `report.jsonl`, merged into `results.json` on the
   isolated, `--isolation none`, and merge paths alike.
4. Reconcile loudly: run totals equal the sum of modules, each module the
   sum of its buckets; retries, crashed children, and lost probes are
   accounted by explicit rules, never silently.
5. Never record secret material (PINs, key bytes, plaintext, `CKA_VALUE`).
   Counters carry only module ids, function names, RV ints/names, counts,
   and process identity.

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

Module-first: `{total_calls, by_module{module: {calls, buckets}}}`.

```json
{"total_calls": 0, "by_module": {"<module>": {"calls": 0,
  "buckets": {"<bucket>": {"calls": 0, "by_fn": {"<fn>": {
  "calls": 0, "by_rv": {"<rv-int>": {"name": "<CKR_...>", "count": 0}}}}}}}}}
```

- Modules, functions, and RVs with zero calls are omitted (sparse);
  every module block present carries all five bucket keys with zero
  buckets explicit (`{"calls": 0, "by_fn": {}}`), while parsers accept
  any subset (sparse parses, uniform emits).
- RV keys are decimal integer strings (`"0"`, `"49"`); `name` comes from
  `ckr_name` with a hex fallback for unknown codes. A non-decimal,
  negative, or boolean RV key fails its whole record closed (never
  coerced), so a malformed leaf cannot silently shift totals.
- `sum(by_rv) <= calls` per function: entry increments `calls`, exit adds the
  RV, so a call that never returns counts with no RV row.
- Invariant: `total_calls` equals the sum of the per-module `calls`, and
  each module's `calls` equals the sum of its buckets.
- Legacy rc1 blocks (`{total_calls, buckets}`) still parse: readers
  normalize them to the `""` unknown module, never inferred to a real id.

RV name conflicts resolve deterministically in `merge_module_first`: on a
leaf-name conflict prefer the non-`0x` (symbolic) name, ties to the
lexicographically smallest. Observed names are kept (no rewriting), so both
merge orders yield the identical leaf including the name.

### `results.json` block

```json
{"complete": true, "total_calls": 0,
 "by_module": {<serialized counters>},
 "probes_lost": 0,
 "by_process": [{"pid": 0, "isolation": "<mode>", "total_calls": 0,
                 "complete": true}]}
```

- `by_module` is the serialized shape above; the top-level `total_calls`
  equals `by_module.total_calls`, which equals the sum of its modules.
- `complete` is true iff every group is complete. Groups are namespaced by
  SessionStart scope and `IsolatedUnitReport` (target, attempt) provenance,
  above that by round, and merged output ANDs the shards. A group is
  complete iff an authoritative session reconciles clean: a session
  record exists AND no fallback per-test deltas were folded in AND no
  partial was folded in AND no loss dispositions it AND session
  `probes_lost` is zero. A round is complete iff every effective group
  in it is complete; the global flag ANDs the rounds (see the
  completeness formula under Normative contracts).
- A segment with test reports but zero counters data in an opened,
  unfinished session scope (typically a first-test crash) emits an EMPTY
  group, which flips the run to `complete: false` instead of vanishing. A
  crash during FIRST fixture setup leaves no reports at all, so a segment
  with only a plain marker (no `reason`/`skipped` static-skip provenance)
  and zero reports/counters in an opened, unfinished scope emits the same
  EMPTY group. A finished scope with zero counters predates the feature
  and contributes nothing, as does a static-skip marker with zero reports.
- `by_process` carries one row per (round, pid, module) that contributed a
  session record, fallback deltas, or partial counts; `isolation` is the
  stamped `PKCS11_CHECK_ISOLATION` value (session stamp wins, else the
  first fallback entry's stamp, else `"unknown"` for unstamped
  bare-pytest traffic). Rows carry `worker_uuid`
  when the records provided one, `round` (the raw run id) iff more than one
  distinct round appears among the block's rows, `shard` (merged output
  only) iff more than one distinct shard appears, and `module` iff more
  than one distinct module appears among the block's rows (same conditional
  rule, decided per block); single-round single-shard single-module output
  reads exactly like rc1 on every row key.
- `by_round` maps each round's run id to its own block with the exact
  top-level shape (`complete`, `total_calls`, `by_module`, `probes_lost`,
  `by_process`); the top level stays the GLOBAL roll-up across rounds.
  Merged `by_round` keys are shard-namespaced (`"<label>/<run id>"`, with
  a conditional `@sha8` suffix on colliding basenames - see Rounds).
- The block is absent (not empty) when the JSONL carries no counters data
  and no executed-but-counterless segment, so old artifacts stay clean.

### Session record (`CallCountersReport`)

One JSONL record per process, emitted at session finish (including the
early-return branch, and after the teardown `C_Finalize` so that call is
included): `$report_type`, `pid`, `worker_uuid` (the process identity,
minted once per process), `isolation` (env value, default `"unknown"`),
`probes_lost` (there is no `probes_completed` field), `run_id`
(the invocation's id, omitted - never null - when the env seed is absent),
plus the module-first counters of everything that process recorded.

### Per-test entry (`pkcs11_call_counters`)

A `user_properties` entry on the teardown report: `pid`, `worker_uuid`,
`isolation` (stamped from the environment, `"unknown"` when unstamped),
plus the module-first baseline-to-now window diff (setup-phase calls in
`setup_teardown`, body calls in `test`), plus `run_id` under the same
omit-when-absent rule as the session record, plus the window's
folded-probe receipts. Setup/call reports predate the computation and
always carry nothing. No entry is attached when the window holds no
calls. A skip in setup still yields a setup-only entry.

### Child wire format

Probe children flatten to `[[module, fn, rv_or_null, count], ...]`, sorted
by module, then function name, then RV ascending with the unreturned row
last per function. Bucket attribution is dropped - the ingesting parent
applies its own active bucket - while the module id is kept so absorbed
traffic stays attributable. `rv null` marks calls that never returned.
Legacy 3-column rows still parse (folded under `""`). Garbage rows are
ignored without raising.

## Rounds

Each `pkcs11-check test` invocation is one round. Resume appends new rounds
to the same `report.jsonl` while overwriting `results.json`, so without
round attribution the merged totals could not be split back per invocation.

- Generation: `test_cmd` mints exactly one run id per invocation -
  `<UTC-timestamp-microseconds>Z-p<pid>-<uuid4hex8>` (e.g.
  `20261115T120345123456Z-p12345-a1b2c3d4`). The timestamp+pid prefix stays
  readable and sortable; the random nonce carries uniqueness, so a frozen
  clock or wall-clock rollback can never fuse two invocations.
  Timestamp+pid+random only (no secrets, no machine identity) - and
  `test_cmd` seeds `PKCS11_CHECK_RUN_ID` late, immediately before
  `run_isolated_pytest_units` (isolated path) or the in-process
  `pytest.main` (none path), with the same save/restore bookkeeping as the
  isolation key. A stale caller-provided value is dropped before
  preflight/collection run, so those subprocesses never inherit it.
- Forwarding: the runner threads the seed into each unit child's plugin env
  under the same guarded rule as the isolation key (explicit value wins, a
  preset is preserved, absent stays absent); confirmation and escalation
  children inherit it from the base env. The session record and per-test
  entries read it at build time.
- Grouping: the run scope sits ABOVE the session scope - groups are keyed
  (run, scope, target, attempt) and pid reconciliation is run-scoped, so a
  pid reused across invocations never fuses and a same-pid entry from
  another round is never superseded.
- Implicit round: records without `run_id` (pre-round artifacts,
  direct-pytest runs) fold into the `""` round, which also owns C2 empty
  groups (a counterless report names no round, so `""` doubles as "round
  unknown"). Old artifacts therefore yield exactly one `""` round with
  byte-compatible totals. A record whose `run_id` is present but not a
  non-empty string is malformed and skipped whole (fail-closed, like I2).
- Merge namespacing: `by_round` maps merge under `"<label>/<run id>"`
  flat keys, so identical run ids on two shards (a CI-matrix same-second
  same-pid collision) never fuse. The label is the shard dir basename, or
  `"<basename>@<sha8(resolved-absolute-path)>"` when basenames collide
  (legit layouts like `hostA/shard` + `hostB/shard` are disambiguated,
  never rejected or fused); the suffix derives from the path alone, so it
  is deterministic and merge-order independent. The merged top level stays
  the GLOBAL roll-up with rows sorted by (shard, round, uuid, pid, module),
  and module, bucket, function, and RV maps are recursively canonicalized
  so `json.dumps` output is byte-identical across merge orders.

Final-label collisions between a generated label and a literal basename
(e.g. a generated `shard@h` vs a literal `shard@h` dir) resolve with a
`@2`/`@3`/... counter suffix, assigned in sorted-by-resolved-path order so
numbering never depends on CLI arg order. Identical resolved dirs share one
label (same dir passed twice still fuses).
- Fingerprint ignoring: the run id matches the `PKCS11_` fingerprint prefix
  but is plumbing, not configuration, so it joins the isolation key in both
  ignored sets - resume across run ids (the normal case: every invocation
  seeds a fresh one) never invalidates state or policy.

## Buckets

The five bucket strings, exactly: `test`, `setup_teardown`,
`session_provisioning`, `module_init`, `preflight`.

- `test` - the test-body phase, between fixture setup and teardown (pushed by
  the call-phase wrapper hook).
- `setup_teardown` - fixture setup and teardown phases (pushed by the setup
  and teardown wrapper hooks).
- `session_provisioning` - the default bucket, used whenever no phase or
  region is active: session fixtures, key provisioning, and anything else
  outside an attributed scope.
- `module_init` - module lifecycle: the `load_module` body, the
  `P11Module.reinitialize` body, and the session-teardown `C_Finalize`.
  That is `C_GetInterface` and/or `C_GetFunctionList` from `from_lib`, one
  `C_Initialize` from `load_module` (plus `reinitialize`'s
  `C_Finalize`/`C_Initialize` and the teardown `C_Finalize`).
- `preflight` - preflight census and recovery children only, synthesized
  by the parent (never recorded live, never doctor); see Preflight
  counting below. A buckets-first block carrying `preflight` is
  malformed, never guessed.

Attribution is two-level. The process-global PHASE is set by the pytest
setup/call/teardown hooks (sequential, so phases never nest) and restored on
exit via try/finally, so a raising phase cannot unbalance it. The
thread-local REGION stack (`counted_bucket`) nests per thread and wins over
the phase within its own thread only, so overlapping regions in other
threads stay isolated while worker threads still inherit the phase. Setting
an unknown name raises `ValueError`. Entry/exit pairs bind the exit to the
bucket captured at entry, so a mid-call bucket switch cannot split one call
across two buckets.

Attribution is window-truthful, not origin-truthful: session-fixture or
provisioning work that executes inside a test window lands in `test` or
`setup_teardown`, so `session_provisioning` typically holds only
out-of-window traffic and is often sparse.

## Module identity

Every call carries the module id bound to the handle it passed through.
`RawPKCS11` binds its lib path in `__init__`, before `_load_from_lib` runs,
so even the loader's own `C_GetInterface` / `C_GetFunctionList` calls
attribute to it; the id is immutable for the handle's life. Raw-ctypes probe
paths (the counting CDLL proxy, `_ckr_ctypes.call_func`, the explicit
`C_GetFunctionList` record, `v30_session`'s funclist-built handle) bind the
child's module path at construction. Handles built from a bare function-list
pointer without an explicit id - and direct `record_*` calls outside any
handle - count under the `""` unknown module, which is never inferred to a
real id: unknown stays unknown through folding, merging, and row tags.

Proxy vs backend: a proxied provider and its backend are different modules
with different paths, so a process that talks through both (proxy handle
plus a direct backend handle, e.g. for setup or comparison) splits its
counters by leg rather than blending them. The wire rows, session records,
and per-test entries all carry the split; `by_process` rows gain the
`module` tag exactly when the block holds more than one module.

Process identity is the `worker_uuid`, minted once per process (fork-safe:
a child that inherits a minted value remints on first use) and carried on
every session record and per-test entry. PIDs stay metadata only. Durable
registration of the uuid is covered under Durability below.

## Exclusions

Counted nowhere, by design:

- `doctor` and the pytest-plugin manifest re-probe (harness-internal
  helpers outside any run; their children inherit a scrubbed env, so they
  can neither register nor flush -- even when a caller exports a counters
  dir, which the `test` CLI drops outright in favor of its own run-owned
  dir and `doctor` never sets).
- Collection/discovery `--collect-only` children (no report-log channel,
  fixtures never run, no provider calls -- inert even with an identity).
- The openssl-interop grandchild binary (third-party, uninstrumentable).
- The openssl-interop direct children in `test_interop_openssl.py`: the
  `openssl list -providers -provider pkcs11` CLI call (with the target as
  `PKCS11_PROVIDER_MODULE`) and the `p11-kit list-modules` call
  (third-party, uninstrumentable - same class as the grandchild).
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
2. Compare `total_calls`, then each module's `calls`, then each bucket's.
   A module-load change shows in `module_init`; a fixture change in
   `setup_teardown`; a test-body change in `test`. A proxy-vs-backend
   comparison starts at the module split, not the buckets.
3. Drill into `by_fn` / `by_rv` for the drifted bucket. Mechanism-behavior
   changes typically show as RV shifts under an unchanged call count.
4. Sanity-check the invariant `total_calls == sum(modules)`, each module
   `calls == sum(buckets)`, on each block; a mismatch means a corrupt or
   hand-edited artifact, not a module change.
5. Caveats:
   - Retried units count twice: two session records from distinct
     producers in one group are both real calls and both are summed. A
     uuid-bearing repeat of an already-folded `(run, worker_uuid)` is a
     torn-append retry, not a retry, and folds first-wins (uuid-less
     legacy repeats keep summing).
   - Never sum session records and per-test entries for the same pid: entries
     whose pid has a session record in the group are superseded and folded
     only as the crashed/timed-out fallback.
   - `by_process` rows differ legitimately across isolation modes (one pid in
     `none`, one per unit otherwise) and across module counts (one row per
     module when mixed); compare `total_calls`, not row counts.
   - Merged counters come from the per-shard JSONL extracts (fresh
     provenance per shard), then summed/ANDed/concatenated with
     conditional `round`/`shard`/`module` tags on the `by_process` rows,
     plus the per-round blocks under shard-namespaced `by_round` keys - it
     is never a sum of shard `results.json` blocks, and both merge orders
     yield the identical block.
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

- `_call`: the bucket is captured once, then `record_call(name)` immediately
  before the module invocation (after funclist resolution, so an unavailable
  function counts nothing) and `record_return(name, result)` after
  `result = int(func(*args))`, both under the captured bucket and the
  handle's bound module id. No signature or return-value changes.
- `_load_from_lib` / `_get_interface_function_list_ptr`:
  `record_call`/`record_return` pairs around the `C_GetInterface` and
  `C_GetFunctionList` direct sites (a raising attempt counts entry-only),
  each pair bound to its entry-captured bucket and the already-bound module
  id (`__init__` binds before loading, so loader calls attribute to it).
- `_ckr_ctypes.call_func`: entry/exit recording around the raw ctypes call
  under the entry-captured bucket (overridable via the keyword-only
  `bucket`) and the `make_caller`-bound module, so the CKR probes count
  without a `RawPKCS11` instance.
- `raw_session.py`: a counting `CDLL` proxy for `ctx.lib` (wraps `C_*`
  attributes, forwards `restype`/`argtypes`/`errcheck` sets, ignores
  non-`C_*` attributes; each call binds both halves to the entry-captured
  bucket, overridable via the keyword-only `bucket`, and the proxy-bound
  module) plus an explicit entry/exit pair for its own `C_GetFunctionList`;
  `counting_cdll()` wraps direct-symbol handles in probes that bypass
  `ctx.lib`. `probe_main_raw` binds the child's module path everywhere and
  publishes it on `RawCtypesContext.module_path` for `make_caller` and
  `v30_session` call sites.

### 2. Buckets - `core/loader.py`, `_plugin_finalize.py`, `_plugin_counters.py`

- `load_module` and `P11Module.reinitialize` bodies run inside
  `counted_bucket("module_init")`, as does the teardown `C_Finalize`.
- `_plugin_counters.py` holds three pytest wrapper hooks
  (`setup`/`call`/`teardown`, all `wrapper=True, tryfirst=True`): setup
  stashes a baseline snapshot and sets the `setup_teardown` phase; call sets
  the `test` phase; teardown sets `setup_teardown` again and diffs
  baseline-to-now in a finally. A `makereport` wrapper attaches the stashed
  entry.
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
  their `probes_lost()`. The session-probe teardown snapshots the legacy
  fields BEFORE `C_CloseSession`/`C_Finalize` and writes ONCE after, so
  cleanup traffic is counted, legacy bytes are unchanged, and a cleanup
  crash writes nothing (the launcher accounts the child as lost).
- Both ingest functions ignore malformed legacy sections without raising,
  fold the key in via `ingest_child_counts` under the parent's active
  bucket (keeping each row's module; legacy 3-column rows land under `""`),
  accumulate the payload's `probes_lost`, and return whether usable
  counters were recovered (new return; existing callers may ignore it).
- `runner.py` calls `note_lost_probe()` exactly when ingest reports no
  usable counters (missing/corrupt coverage file included - ingest never
  raises). Ordering guarantee: coverage ingest plus loss accounting run
  BEFORE the optional diagnostic rv-trace recording, so a poisoned trace
  marker can never bypass counter ingestion; the shared trace parser
  additionally skips undecodable markers per marker (`JSONDecodeError`,
  `RecursionError`, `ValueError`) without changing valid-trace behavior.
- Below the probe child: the isolation grandchild writes a private coverage
  path the probe child ingests; the fork child (untransmittable via
  `os._exit` by design) is accounted lost by its reaping parent; the
  threading workload child prints a `P11_CALL_COUNTERS_JSON:` stdout marker
  the parent folds in, accounting lost when it is absent or unusable.

### 4. Extraction - `_jsonl_extract.py`, `_report_writers.py`, `file_runner.py`, `test_cmd.py`, `merge.py`

- `extract_call_counters_from_jsonl` segments the stream by SessionStart
  scope and `IsolatedUnitReport` (target, attempt) provenance exactly like
  the classification-occurrence iterator (reset at `SessionStart`; a
  malformed marker resets to unattributed; never raises). Reconciliation
  per group: sum every session record (uuid-bearing repeats of an
  already-folded `(run, worker_uuid)` fold first-wins as torn-append
  retries; uuid-less legacy repeats keep summing); fold a buffered
  per-test entry only when its pid has no session record in that group
  (inheriting the entry isolation stamp); fold staged partials only for
  producers with no authoritative session in the run; dispose staged losses by
  source-association anchor (never stream position); emit an empty group
  for an executed-but-counterless unfinished segment. Counters validate through
  the frozen schema predicates and normalize to module-first (legacy to
  `""`); validation is fail-closed: known buckets only, decimal RV keys,
  exact totals at every level, `sum(by_rv) <= calls`, well-formed
  `worker_uuid` when present; a violating record is skipped whole, and a
  malformed `user_properties` container is ignored without raising. Rows
  render per (round, pid, module) with conditional `module` tags and the
  record uuid (session wins over entries).

A two-record marker lookahead keeps merged-writer framing from creating a
fictitious startup-loss group: a marker immediately followed by
`SessionStart` AND re-stated identically after the bookend (same target and
attempt - the merged writer always duplicates the new scope's own `(unit, 0)`
marker) belongs to the NEW scope (applied after the bookend). A marker
naming a different `(target, attempt)` than the following scope's marker is
a genuine attempt marker - a truncated attempt before the next attempt's
bookend - and stays in the current scope, as do marker+EOF,
marker+`TestReport`, and static-skip markers (explicit never-executed
provenance never moves), so `C2`/`C2b` still fire for genuinely counterless
segments. Any residual ambiguity defaults to visible incompleteness (an
empty group), never silent loss.
- `write_isolated_json_report(..., call_counters=None)` sets
  `payload["call_counters"]` when truthy; the isolated path extracts per
  unit JSONL and passes it in.
- `PKCS11_CHECK_ISOLATION` carries the mode to the session record: the
  runner sets the `--isolation` flag value for unit children, `test_cmd`
  sets `"none"` for the in-process path (restored afterwards with the other
  run-scoped keys). `PKCS11_CHECK_RUN_ID` rides the same bridge with one
  fresh id per invocation, seeded before preflight (a stale caller value
  is dropped first and restored after); the census, recovery probes, and
  unit rounds share it. The isolation, run-id, counters, and preflight
  evidence keys are all ignored by the state and policy fingerprints, so
  seeding never invalidates resume.
- The none path embeds counters where it embeds coverage; `merge.py`
  extracts each shard JSONL in fresh state, then sums totals/modules/losses,
  ANDs `complete`, merges the `by_round` maps under shard-namespaced keys,
  and concatenates the `by_process` rows with conditional round/shard/module
  tags (untagged single-module-shard rows gain their shard's proven module
  when the merge holds more than one; sorted for order independence).
  A repeated shard label (same resolved dir twice) fuses only an
  identical snapshot; any difference refuses loud with `ValueError`.

## File-change map

| File | Change |
|---|---|
| `core/call_counters.py` | Counter state owner: phase + thread-local regions, module-keyed record/snapshot/diff, module-first uniform-5 serialize/flatten, child ingest (4-col + legacy 3-col), worker-uuid allocation, lost-probe count. |
| `core/counters_schema.py` | Frozen rc2 contracts: shape predicates, legacy normalization, module-first merge/canonicalize, identity allocators. |
| `raw/api.py` | Per-handle module id bound in `__init__` before loader C calls; `_call` entry/exit recording; `record_call`/`record_return` pairs around the `C_GetInterface` site in `_get_interface_function_list_ptr` and the `C_GetFunctionList` site in `_load_from_lib`. |
| `core/loader.py` | `load_module` and `reinitialize` bodies in `module_init`. |
| `_plugin_finalize.py` | Teardown `C_Finalize` in `module_init`. |
| `_plugin_counters.py` | Setup/call/teardown wrapper hooks, per-test entry attach, session-record builder/emitter (both carry `worker_uuid`). |
| `plugin.py` | Register `_plugin_counters`; emit the session record on both session-finish paths. |
| `testcases/_probes/_emit.py` | `write_coverage(..., call_counters=None)` payload key (`[module, fn, rv, count]` rows). |
| `testcases/_probes/session.py`, `raw_session.py`, `v30_session.py` | Pass `flatten_current()`; counting CDLL proxy + explicit `C_GetFunctionList` record; module path threaded through every child record site and `RawCtypesContext.module_path`. |
| `testcases/_probes/_ckr_ctypes.py` | Entry/exit recording in `call_func` with the `make_caller`-bound module. |
| `testcases/_subprocess_preamble.py`, `_raw_subprocess.py` | Ingest child counters; usable-counters boolean return. |
| `testcases/_probes/runner.py` | `note_lost_probe()` when ingest reports unusable. |
| `core/_jsonl_extract.py` | `extract_call_counters_from_jsonl` (module-first fold, legacy→`""`, conditional tags, uuid rows); none-path embedding. |
| `core/_report_writers.py` | `write_isolated_json_report(..., call_counters=None)` payload key. |
| `core/file_runner.py`, `cli/test_cmd.py` | Per-unit extraction + pass-through; `PKCS11_CHECK_ISOLATION` env on both paths; per-invocation `PKCS11_CHECK_RUN_ID` seed, forwarding, and fingerprint ignores. |
| `core/merge.py` | Merged `call_counters` from per-shard extracts (summed/ANDed, conditional round/shard/module tags, namespaced `by_round`). |
| `core/_counters_durability.py` (rc2 Task 3) | Registry/sidecar/journal files, gap collection, orphan sweep, seal/fence admission barrier, recovery supplements. |
| `core/call_counters.py` (rc2 Task 3) | `CounterPersistenceError`, self-registration, K/boundary/exit flushes, window publish, atomic ingest, probe seqnos, receipt ledger. |
| `core/_jsonl_extract.py` (rc2 Task 3) | Partial/lost fold, keyed staging with authoritative precedence, receipt union into `probes_detail`, `lost_processes`, disposition rows. |
| `core/file_runner.py`, `core/_run_state.py`, `core/_run_units.py` (rc2 Task 3) | Spawn identity, per-attempt collection, supplements, resume barrier + rerun skips, `counters_dir` state record, fingerprint ignores. |
| `testcases/_probes/runner.py`, `session.py`, `raw_session.py`, `_emit.py` (rc2 Task 3) | Probe seqno/receipts, probe sidecar flush-then-delete, grandchildren registry strip. |
| `core/preflight.py` (rc2 Task 4) | `PreflightCounters` engagement, scrubbed child env, re-bucket synthesis, crashed/timeout/error collection, retained evidence appends, harness-error manifest reason. |
| `core/recovery.py`, `cli/test_cmd.py`, `core/_run_state.py` (rc2 Task 4) | Recovery env auto-engage; start-seeded run id, census engagement, evidence splice + results refresh, failed-preflight reports; evidence-path fingerprint ignore. |
| `core/_jsonl_extract.py` (rc2 Task 4) | Session role parse (fail-closed) + conditional `role` row tags. |

## Enabling

There is none: the counters are always on. `PKCS11_CHECK_ISOLATION` is set by
the runner itself (the `--isolation` flag value for unit children, `"none"`
for the in-process path) and read back by the session record; it is plumbing,
not configuration. `PKCS11_CHECK_RUN_ID` is likewise minted by the CLI (one
fresh id per invocation) and read back by the session record and per-test
entries for round attribution.

Durability (below) is always on under the `test` CLI, which allocates a
run-owned counters dir before preflight on every invocation (a per-series
`<state>.counters.{nonce}/` sibling for isolated runs, covered by the
state guard; a fresh tempdir for `--isolation none`, removed afterwards;
the state's recorded dir on resume). Fresh runs retire the previous
series' dir with its state, so no run ever reuses another series'
directory. `PKCS11_CHECK_COUNTERS_DIR` carries that dir to
children; it is plumbing, not an opt-in -- a caller-exported value is
dropped (restored afterwards), never honored. Outside the CLI (bare
`pytest`, direct API use) the variable stays env-opt-in: without it every
durability entry point is inert and counter behavior is unchanged.

## Durability (rc2 Task 3)

Every in-scope call is counted exactly once, or its process is explicitly
identified as having unrecoverable counter evidence. That is the contract
for fully recovered executions; the known persistence residuals are a
warn-only preflight evidence failure under I/O pathology (no loss record,
loud warning), a possibly-undercounted `probes_lost` scalar when a
producer dies before emitting its session record (gap recovery still
folds the counts and the lost record still forces `complete: false`;
only this diagnostic scalar can read low), and the documented
triple-fault probe shape (fail-visible via its lost record). The
machinery lives in
`core/_counters_durability.py` (files, collection, sweep, fence) with the
recording half in `core/call_counters.py` (registration, flushing,
publishing, atomic ingest) and assembly in `core/_jsonl_extract.py`
(partial/lost fold, keyed staging, receipt union).

### Child side: registration, sidecar, journal

The first provider call self-registers the process: an O_EXCL
`registrations/<worker_uuid>.json` file carrying run id, unit, attempt,
role, pid, birth token, timestamp, and sidecar path. Registration precedes
the first admitted call, so a torn registry proves zero-loss. A sealed
directory or an I/O failure raises `CounterPersistenceError` out of the
recording call, blocking provider entry rather than undercounting.

Evidence persists as two files per producer (identity + nonce names, one
writer each, no locks): `<uuid>-<nonce>.partial.json` holds the
in-progress snapshot (tmp + replace), and `<uuid>-<nonce>.windows.jsonl`
appends one record per published test window. Flushes happen every ten
calls (K bound, per producer), at test-window boundaries, and at exit,
under the counters lock with a dirty flag covering every evidence
mutation; a pid guard keeps a forked child from touching its parent's
files (it re-registers with a fresh identity). The journal appends first,
the in-progress accumulator resets second, and the sidecar (carrying
`journal_seq`, the journal length reflected in the reset) flushes third,
so every crash interleaving is sound: journaled-but-unflushed windows are
excluded from the collected gap because their calls are still in the
flushed snapshot. No fsync is used: scope is process death (page cache
survives it); machine crash can lose the unflushed tail.

Per-test entries carry the window's folded-probe receipts (since the
setup mark) and the session record carries all of them; the teardown
hook publishes the window to the journal. Persistence failures in the
hooks warn loudly without failing the test: verdicts stay untouched, and
the collector names the unrecovered tail with a lost record.

### Parent side: collection, sweep, seal, fence

After each attempt the parent collects that unit's producers into the
child JSONL before caching (live producers skipped untouched; committed
producers consumed silently via delete-after-commit; dead producers yield
a gap-only partial plus an identity-bearing lost record). The gap is the
in-progress snapshot plus journaled windows with no matching JSONL
entry; torn tails drop benignly while torn middle lines, truncated
journals, and missing disambiguators surface `conflict`. Torn registries
with a surviving sidecar are adopted via the sidecar's identity; without
one they are zero-loss absent. Consumed files are deleted, so collection
is idempotent, and extractor dedup makes even a crash between append and
consume benign.

The orphan sweep deletes only provably consumable files (committed
producers, barrier-collected runs other than the current one, torn files
with no adoptable evidence, sidecar-less journals) and retains live
producers' files plus unattributed other-run evidence; it is idempotent.
The admission barrier seals registration before a resume sweep, collects
every unclaimed producer, and fences live ones: only a pid whose live
birth matches the registry is signaled, through an incarnation-pinning
handle (pidfd on Linux, process handle on Windows) with the birth
re-verified immediately before the signal. Unverifiable producers report
`unresolved` with a warning and are never signaled; resume skips their
units' reruns, reports them, and never assumes quiescence. A seal that
cannot be established fails the resume before any provider work: running
without proven quiescence is never allowed. The collected plan stages to
`barrier-staging.json` (atomically) before any source file is consumed,
so a controller death between the barrier and its application loses
nothing -- the next barrier reloads the staging and the plan re-applies
idempotently. A plan that cannot land in full fails the resume loudly
with the staging retained for retry.

Requeued recovery attempts archive their session records into per-unit
supplements next to the state file; each rerun's cache prepends them, so
the archived attempt folds as its own scope instead of staying dropped.

### Probe channel: seqno receipts and sidecar fallback

Each probe launch assigns a parent-side seqno, echoed by the child in its
coverage receipt alongside propagated grandchild receipts; the parent
accepts the receipt only on an exact (uuid, seq) match and unions all of
them into `probes_detail` (folded) at assembly. A torn coverage file
falls back to the probe sidecar: its counts fold as partial evidence
with the receipt suppressed, and the launcher still flags the loss. A
present-but-mismatched receipt rejects the payload fail-closed; a
missing receipt folds legacy-style with no receipt recorded. Every
commit is flush-then-delete: the parent checkpoint must persist before
the probe sidecar goes, and the sidecar is retained on flush failure.
Retained orphans are adopted at collection under the parent uuid --
suppressed when the parent's durable receipts already cover the
probe, otherwise folded into the parent's partial with the receipt
claimed -- so below-K ingests survive a worker death. Probe and
workload grandchildren never touch the registry (their identity env is
stripped at spawn): their channel is receipts-or-marker only, so their
evidence can never double-count against a parent's sidecar.

### Staging and precedence at assembly

Authoritative sessions supersede same-producer partials (both input
orders; superseded partials leave no vacuous group behind); repeats fold
first-wins (partials and, for uuid-bearing sessions, torn-append
retries alike); a stale loss naming a producer with validated same-run
authority reconciles away before anchoring (healed by a rerun or a
re-collected sidecar), while pid-only losses never reconcile and
independent losses stay fail-visible. Surviving losses reconcile
globally by producer identity with repeats deduped and conflicting end
states surfaced as `conflict`. The scope index rebases to the assembly
scope. `lost_processes` and
`probes_detail` render only when non-empty, top-level and per-round, and
merge carries both (lost rows shard-tagged past one shard, details
unioned). A producer that died with zero recoverable evidence still
names itself with a loss record; a validated zero-call normal exit stays
silent.

## Preflight counting (rc2 Task 4)

The CLI census probe and the recovery liveness probes count through the
standard choke point into durability sidecars (role `preflight`); the
parent collects each child into synthesized `preflight`-bucket records.
The child records under its natural buckets (loader traffic in
`module_init`, the census under the default phase) and the parent
re-buckets every module's functions and RVs under `preflight` with
totals preserved exactly -- synthesis, not recording, so the four live
buckets are untouched. A clean exit with evidence yields the
authoritative synth (session-shaped, `role: preflight`,
`isolation: none`, this run's id); a dead child with evidence yields a
gap-only partial plus an identity-bearing loss; no evidence after
possible provider entry yields a pid-bearing loss -- except
`module_unloadable` with no registration, which proves the provider was
never entered and stays silent. An `ok` manifest with no registration
is impossible without a counting break, so it trips a loud `unknown`
loss rather than silence. A `PreflightNote` heads every non-trivial
outcome; it explains, never replaces, the evidence.

Role semantics on rows: `unit` (and absent) stays untagged; `retry`,
`confirmation`, and `preflight` render. A present-but-unknown role
fails its record closed, so a forged tag never folds. Dead-preflight
partials carry `role: preflight` plus `isolation: none` next to their
`unit` (`preflight` for the census, `recovery` for liveness probes),
so their rows read as the dead preflight child instead of an unknown
ordinary unit; losses still carry `unit` only. Collection is
non-consuming: the parent retains (appends and closes) the JSONL scope
first and deletes the source sidecars only on success, so a failed
append leaves the files for a later pass (a repeated collection
returns the same records, and the extractor's first-wins session
fold keeps a torn-append retry exact).

One run id is seeded before preflight and shared by the census,
recovery probes, and unit rounds (a stale caller value is dropped
first and restored after). The evidence file accumulates beside the
state file for isolated runs (reset on fresh starts, so stale rounds
never fold in) and rides a temp file for `--isolation none`. The none
path splices the evidence into the pytest JSONL before assembly; the
isolated path splices it into the merged `report.jsonl` after the run
and refreshes the `call_counters` block. Failed preflights keep their
counter-only JSONL evidence too (as `report.jsonl` for JSON output,
plus the `call_counters` block for crashed/timed-out runs); rich/junit
outputs carry no counter artifacts, so preflight evidence drops there
exactly like unit counters.

`CounterPersistenceError` routes explicitly per surface: the preflight
child maps it to an error manifest with reason `counter_persistence`
(the triggering provider call never ran -- record-before-invoke -- so
the census is harness-incomplete, never unloadable); the CLI maps that
reason to exit 2 with the harness message; the pytest plugin warns
without failing the test; probe children never raise it (stripped
identity, best-effort sidecars -- a lost sidecar degrades to the
parent's lost-probe accounting, and genuine probe harness faults keep
using the existing `HARNESS_ERROR:` marker). Collection and evidence
writes warn and continue: counter plumbing never fails a run.

## Structure (rc2 Task 5)

Isolation stamps, uniform emission, association-anchored loss
disposition, and identity-fused merging. The stamp lives in
`_plugin_counters.py`, uniform serialization in
`core/call_counters.py`, the C2b interplay in
`core/_jsonl_extract.py`, and the merge gate in `core/merge.py`.

### Isolation stamps

Every per-test entry stamps `isolation` from the environment
(`"unknown"` when unstamped, as in bare-pytest runs). Crash-fallback
rows inherit the stamp: the session stamp wins when session evidence
exists for the pid, else the first folded entry's stamp, else
`"unknown"`. A present-but-mistyped stamp reads `"unknown"` --
isolation is informational, never fail-closed.

### Uniform emission

Emitters (session records, per-test entries, sidecar snapshots,
journal windows) write all five bucket keys on every module block
present, with zero buckets explicit; functions and RVs stay sparse,
and empty counters still emit no module blocks at all. Parsers accept
any subset of buckets, so legacy sparse records fold to identical
totals and flags. Extracted and merged output is the faithful
canonicalized union of its inputs (never padded): legacy shapes read
back sparse, rc2 shapes read back uniform, and healthy-path totals
stay byte-identical apart from the added zero keys.

### C2b association anchoring

A lost record covers a marked segment only on a source-association
match: a local origin (absent or empty) plus the segment's own unit
and attempt. The staged stream position wins among matches (the
collector appends into its own segment); otherwise the earliest
matching marked scope anchors, so prepended and reordered records
still dispose their execution. The worker identity rides along as the
disposition identity (dedup, row end states) but never gates the
match. Cross-source decoys never suppress the backstop: they key
their own group from the staged scope plus their own unit and
attempt. Legacy records without an association keep positional
grouping; foreign-origin records (no producer writes that field)
anchor to nothing -- they stay groupless with their run riding the
lost entry, visibly incomplete, and never disposition local rows.
The entry `scope_index` is assembly-assigned from the anchor in
every case; the record's provisional value is ignored, never fatal.
A surviving lost record is a terminal disposition: it keeps its group
incomplete (fail-visible). A stale loss naming a producer with
validated same-run authority reconciles away before anchoring instead
of covering anything. `unresolved` losses from fencing flow through
the same disposition -- resume skips their units' conflicting reruns
instead of assuming quiescence (see Durability above).

### Merge identity fusion

Labels are unique per resolved shard dir, so a repeated label is the
same shard extracted twice: an identical snapshot fuses to the first
copy with only `complete` still ANDed, while any difference refuses
loud with `ValueError` (the shard mutated between extractions --
concurrent-mutation evidence, in the same refuse-loud family as the
N-001 and overlap refusals). Never a silent subset fuse and never a
whole-block merge of a partially overlapping aggregate: both would
double-count the repeated contributions. Distinct shards always fuse,
even on uuid collision. Labels count distinct resolved paths, so a
repeated dir keeps the plain basename. Output stays byte-canonical:
key-sorted modules, buckets, functions, and RVs with rows in (shard,
round, uuid, pid, module, bytes) order, so both merge orders -- and a
duplicated input -- yield identical bytes.

### Reading the block

`probes_lost` counts probe children with unrecoverable counters,
authoritative for retained session records and a lower bound when a
producer dies before emitting its session record; `probes_detail` sits
next to it with one `{worker_uuid, probe_seq, status}` row per folded
receipt, uncapped and absent when empty. Any surviving named loss keeps
its group, its round, and the run incomplete.

Coverage and counters are different instruments: function and
mechanism coverage record admission (which functions and mechanisms
ran, feeding capability gating and the hollow-pass oracle), while
call counters record exact per-call volumes with RV breakdowns.
Compare volumes across runs with counters, never with coverage
counts.

The unknown residual stays explicit: calls without a handle count
under the `""` module, unstamped traffic under `"unknown"`
isolation, unseeded records in the `""` round -- unknown stays
unknown through folding, merging, and row tags, never inferred to a
real value.

Window attribution is window-truthful, not origin-truthful: a
per-test entry diffs the baseline taken at setup end against the
counters at teardown end (setup and teardown phases in
`setup_teardown`, the body in `test`), so provisioning work inside a
window lands in that window's buckets. Entries fold only for pids
with no session record in the group -- a lower bound, since
out-of-window traffic (including the post-window teardown
`C_Finalize`) is missing.

Roles reuse the observation vocabulary: a session `role` of `retry`,
`confirmation`, or `preflight` renders on the row while `unit`
(default, and absent) stays untagged, and a partial `role` renders
the same way (dead-preflight partials carry `preflight`). Entries
and losses carry `unit` instead -- their frozen shapes have no role
key.

Completeness in one line: reconciled effective contributions plus
unresolved losses -- a group is complete iff an authoritative
contribution reconciles clean with zero lost probes, zero effective
losses, and zero conflicts; rounds AND their groups and the global
flag ANDs the rounds (see the completeness formula under Normative
contracts).

## Normative contracts (rc2) - frozen by Task 1

This section is the frozen contract for the rc2 counter-gap work (plan v8,
codex R4-R7 dispositions). `core/counters_schema.py` is its executable form;
later tasks consume that module verbatim. Three rules govern every shape:

- Sparse parses, uniform emits: parsers accept any subset of buckets and any
  missing optional key; rc2 emitters write the full shape.
- Old records and artifacts keep parsing: every new key is optional on
  ingest and every new shape additive. New output writes `by_module` only
  (below); readers accept legacy `by_bucket` blocks by normalizing them to
  the `""` module. Rounds nest modules in a single direction; no
  module-to-round duplication exists.
- Counters-only: provider behavior, verdicts, and retention are untouched.

### Bucket sets per level

The five bucket strings, exactly: `test`, `setup_teardown`,
`session_provisioning`, `module_init`, `preflight`. `preflight` attributes
preflight census and recovery children only (never doctor, which sets no
counter state).

| Level | Buckets on emit | Buckets on parse |
|---|---|---|
| Per-module block, rc2 records | all five keys always (Task 5) | any subset of the five |
| Per-module block, Task 2-4 records | sparse, except preflight synth/partial rebucketing which emits all five | any subset of the five |
| Legacy buckets-first block | n/a (rc1 output) | subset of the rc1 four; a buckets-first block carrying `preflight` is malformed, never guessed |

### Record types

| Record | Wire form | Required fields | Optional fields |
|---|---|---|---|
| Session | `$report_type: CallCountersReport` | `pid`, `probes_lost`, `total_calls`, counters | `isolation`, `run_id`, `worker_uuid`, `role`, `receipts` |
| Per-test entry | `pkcs11_call_counters` user property | `pid`, `total_calls`, counters | `run_id`, `worker_uuid`, `isolation` (Task 5), `receipts` |
| Sidecar-partial | `$report_type: CallCountersPartial` (gap-only) | `worker_uuid`, `truncated: true`, `total_calls`, counters | `run_id`, `unit`, `attempt`, `pid`, `receipts`, `role`, `isolation` |
| Preflight-synth | session-shaped, `role: preflight` | session fields | session optionals; counters must be module-first with only `preflight` content (other buckets absent or zero-call) |
| Lost | `$report_type: CallCountersLost` (never counts) | `end_state`, `scope_index` | identity (`worker_uuid` and/or `pid`, at least one), `run_id`, `unit`, `attempt`, `origin_shard` |
| Registry file | `registrations/<worker_uuid>.json` | `worker_uuid`, `run_id`, `unit`, `attempt`, `pid`, `role`, `timestamp`, `sidecar`, `birth_token` | none |

Counters on session, entry, and partial records are exactly one of
`buckets` (legacy shape) or `by_module` (module-first shape); both or
neither is malformed. A lost record carrying any counts key
(`total_calls`, `buckets`, `by_module`, `probes_lost`, `truncated`,
`receipts`) is malformed. A sidecar file contains exactly one
partial-record JSON object. Preflight-synth records are distinguished from
ordinary session records by `role`, not by a separate wire type.

### Block shapes

Module-first block: `{total_calls, by_module{module: {calls, buckets}}}`.
The plan's `{total, ...}` shorthand maps to the rc1 key names
(`total_calls` at the top, `calls` nested). Totals are exact at both
levels; inner buckets follow the serialized contract (decimal RV keys,
exact function sums, `sum(by_rv) <= calls`).

Results blocks (top level and every `by_round` entry) carry
`{complete, total_calls, by_module, probes_lost, by_process}` where
`by_module` is a module-first block. The outer `by_module` names the
results subtree (replacing rc1's `by_bucket`); the inner `by_module` is
the module map. Legacy `by_bucket` blocks normalize to the `""` unknown
module and are never inferred to a real module id.

`by_process` rows: `{pid, total_calls, isolation, complete}` required,
plus optional `worker_uuid`, `module`, `role`, `truncated`, `end_state`,
`round`, `shard`. One row per (round, process, module) that contributed;
`module` appears iff more than one distinct module occurs among the
block's rows (same conditional rule as `round`/`shard`), so
single-module output reads exactly like rc1 on every row key. `role`
reuses the observation vocabulary with `unit` omitted (`retry`,
`confirmation`, `preflight` are written). `truncated: true` marks a
lower-bound row (partial evidence); `end_state` names an abnormal or
unresolved end and is absent on clean rows. PIDs are metadata only;
`worker_uuid` is the identity.

`lost_processes[]` (full lost identities) and `probes_detail[]`
(`{worker_uuid, probe_seq, status: folded}`; no other status is emitted)
sit next to the `probes_lost` int at the top level and in every
per-round block. `probes_lost` is authoritative for retained session
records and a lower bound when a producer dies before emitting its
session record. Both lists are uncapped and absent when empty, so
legacy blocks stay byte-identical.

### Identity keys

| Key | Tuple | Built by |
|---|---|---|
| Sidecar / registry | `(run_id, unit, attempt, worker_uuid)` + filename nonce | `sidecar_identity` |
| Receipt | `(worker_uuid, probe_seq)` | `receipt_key` |
| Session authority | `(worker_uuid)` | `session_authority_key` |
| Test supersede | `(worker_uuid, nodeid)` (nodeid from the enclosing report) | `test_supersede_key` |
| Source association | `(origin_shard, unit, attempt, worker_uuid?)` | `source_association` |
| Scope | `(scope, target, attempt)` | `scope_key` |
| Merge | `(shard, run_id, worker_uuid)` | `merge_key` |

The named helpers are schema and contract-test reference constructors
for these shapes; production keys the same fields inline where it keys
them (receipts, supersede, scope) and keys merges by resolved shard
label instead.

### Enums

- `end_state`: `crashed`, `timeout`, `killed`, `unknown`, `unresolved`,
  `conflict`.
- `role`: `unit` (default, omitted on rows), `retry`, `confirmation`,
  `preflight`.
- Probe `status`: `folded` (counts included). Only `folded` is emitted.
- Contribution kind: `authoritative`, `partial`, `absent`.

### Completeness formula

Completeness is computed over reconciled effective contributions plus
unresolved losses. Superseded partials and lost records are excluded and
never poison the verdict: a stale partial plus a valid authoritative
session for the same producer contributes the authoritative counts. A
group is complete iff an authoritative contribution reconciles clean
with zero lost probes, zero effective losses, and zero conflicts; a
partial-only group is incomplete. A round is complete iff every
effective group in it is complete; global `complete` ANDs the rounds.

### Merge rules

Merge extracts each shard JSONL in fresh state, sums totals, buckets,
and losses, fusing identical blocks under one resolved shard label (so
passing one shard dir twice still fuses), refusing the same label with
any difference, and always summing distinct labels even on uuid
collision,
ANDs `complete`, namespaces `by_round` under `"<label>/<run id>"`, tags
rows conditionally, and emits byte-canonical output (key-sorted modules,
buckets, functions, and RVs, so plain `json.dumps` is order-independent).
Rows sort by (shard, round, worker_uuid-or-pid, module, row bytes).

### Precedence tables

Staging (per identity, deterministic): authoritative records supersede
partials; staged partials survive missing-source fallbacks (absence is
classified only after consulting staging); disposition metadata combines
without duplicating contributions; conflicting purported terminals for
one identity surface an explicit `conflict` end state (never a silent
pick). A full entry supersedes a same-`(worker_uuid, nodeid)` partial.

C2b suppression: a lost record suppresses the C2b empty group only on a
scope-anchored match -- the assembly re-derives output scopes from
stream segmentation and matches staged evidence via the source
association `(origin_shard, unit, attempt, worker_uuid?)`, never by
bare tuples across scopes/rounds and never by stream position (lost
evidence buffers across the full pass, so prepended and reordered
records match). Cross-source decoys never suppress. A lost record whose
association matches no stream segment keys its own group from its
`(run_id, scope_index, unit, attempt)`. The `scope_index` on a JSONL
record is the collector's provisional assignment; on disagreement the
re-derived scope wins and the record's value is ignored (never fatal).

Receipts: bounded to un-retired probes on session records and per-test
entries; superseding records union superseded receipts, recursively to
grandchildren. Handoff: no eager clear -- an in-progress window is
overwritten only by the next window's first snapshot -- with at most
K=10 unflushed windows per producer.

### Receipts, registry files, birth tokens, scope index

Receipts are `{worker_uuid, probe_seq}` pairs minted per folded probe.
Registry files are per-process (`registrations/<worker_uuid>.json`,
O_EXCL create) with self-describing content; a torn file reads as
absent, which is provably zero-loss because registration causally
precedes the first provider call, and invalid JSON is skipped. The
birth token is the OS process-birth id (Linux `/proc` starttime,
Windows creation time, macOS equivalent); a mismatch or an unavailable
token reports unresolved and no signal is ever sent. The scope index is
assembly-assigned: every reference is rebased together at assembly and
legacy sources keep their existing C2b behavior (retained, never
guessed).

### Secret-freedom and fingerprint plumbing

Records carry counters plus identity only -- never PINs, credentials, or
parameters -- enforced by key-set validators and the secret-key scan.
All `PKCS11_CHECK_*` plumbing keys (isolation, run id, counter sidecar
directory) are ignored by the state and policy fingerprints, so seeding
or reseeding them never invalidates resume.
