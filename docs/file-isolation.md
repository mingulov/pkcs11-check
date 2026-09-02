# Isolated Modes

`pkcs11-check test` now defaults to resumable isolated execution for crash-prone modules:

```bash
uv run pkcs11-check test \
  --module /path/to/module.so \
  --isolation auto
```

or:

```bash
uv run pkcs11-check test \
  --module /path/to/module.so \
  --isolation file
```

or:

```bash
uv run pkcs11-check test \
  --module /path/to/module.so \
  --isolation test
```

## What it does

- Expands the requested pytest targets into an ordered list of files or individual pytest nodeids.
- Collects pytest item metadata in a short-lived helper subprocess so `auto` can use
  real marker names instead of source-text scans.
- Probes PKCS#11 capabilities in a short-lived helper subprocess and passes the
  resulting manifest into pytest instead of loading the module during collection.
- Runs each unit in a fresh `python -m pytest` subprocess.
- Writes progress to `.pkcs11-check-isolation-state.json` by default.
- Learns crash-prone files in `.pkcs11-check-isolation-policy.json` by default and
  promotes them to per-test isolation in later `--isolation auto` runs.
- Continues past a crashing unit because the unit process, not the main runner, dies.
- Creates parent directories for `--state-file` automatically.

Mode summary:

- `--isolation auto`: CLI default and safe default, using per-file isolation unless a file is marked
  `subprocess_per_test` or was previously promoted by the adaptive policy file
- `--isolation file`: one subprocess per file
- `--isolation test`: one subprocess per collected pytest test nodeid
- `--isolation none`: fastest path, but it falls back to in-process `pytest.main(...)` and is not
  crash-safe

An explicit `path::node` target remains that exact node unit in `auto`, even if collection finds
the module-level `subprocess` marker. A bare file target remains file-isolated; a
`subprocess_per_test` file is still expanded to one unit per collected node.

`test` mode is slower, but it gives much better crash attribution and lets the
runner preserve each attempted test independently on resume.
`auto` is the best default recovery mode when you want safety without paying full
per-test cost across the entire target set.
If a file crashes or times out during an `auto` run, the runner now escalates that
same file to per-test isolation immediately for the rest of the current run.
Once an escalated file reaches the configured per-file crash budget, the runner
marks the remaining test units from that file as `crash_limited` and moves on.

## Resume The Saved Plan

Use `--resume` to run only planned targets that have never been attempted in the saved state:

```bash
uv run pkcs11-check test \
  --module /path/to/module.so \
  --isolation file \
  --resume
```

Resume is continuation, not revalidation: it keeps the saved unit plan and skips every planned
target that already appears in saved results, regardless of status or `completion_verified`.
Only targets missing from saved results run. Failed, crashed, timed-out, unverified,
`escalated`, and `crash_limited` targets are not retried by `--resume`; use a fresh run without
`--resume` when those targets must be revalidated. An escalated parent remains in the saved
results while any missing expanded child still runs.
Fresh non-resume runs reset the state and remove the state-specific report-record shards, known
`report.jsonl`, configured output, `quality.json` beside the output, and `coverage.json`/
`provisioning.json` beside `report.jsonl` before starting, so prior-generation evidence cannot
appear current.

When an isolated attempt writes a report log, normal collected pytest exits `0`, `1`, and `5`
must have one valid `SessionStart`/`SessionFinish` pair whose integer `exitstatus` matches the
subprocess return code. Missing, malformed, duplicated, or mismatched session completion is
recorded additively as incomplete and makes the run non-green, while retaining the detail that
was collected. Its attempted target is preserved on `--resume`; it is not automatically blamed or
retried as a crash/timeout, escalated, or added to adaptive crash policy for that reason alone.
Older state files remain
compatible: an omitted `completion_verified` field is treated as verified.

An `escalated` result is retained in state so resume does not discard the file-level crash or
timeout trigger. Grouped JSON and JUnit derive that trigger's effective `crashed`/`timeout`
status from its return code even if all expanded child units pass. Such a run remains non-green.

When daemon recovery re-runs units that completed while the provider was dying, the retry replaces
their current aggregate verdict but does not erase the superseded attempt. The original result,
report records, output, and process observations remain in `attempt_history`; each confirmed daemon
death remains in `recovery_events` and counts as a separate crash in JSON/JUnit. The append-only
`<state-file>.recovery.jsonl` sidecar closes the window before the next state save and is
validated/replayed on resume. A malformed nonblank sidecar fails closed.

The state file records a fingerprint of the run configuration, so `--resume` refuses to reuse
results when the fingerprint changes. By default the fingerprint covers pkcs11-check's own
environment (the `P11TEST_` and `PKCS11_` namespaces) plus the module path and test-data
provenance; it does not include a provider's own configuration environment (for example a
token-directory or config-file variable), because those names are provider-specific and
pkcs11-check stays provider-neutral. If you change such a variable between runs and want the
change to invalidate a `--resume` (rather than silently reuse results from the old
configuration), name it via `PKCS11_CHECK_FINGERPRINT_ENV_KEYS` (comma-separated, exact keys)
or `PKCS11_CHECK_FINGERPRINT_ENV_PREFIXES`:

```bash
PKCS11_CHECK_FINGERPRINT_ENV_KEYS=MYHSM_CONFIG,MYHSM_TOKENDIR \
  uv run pkcs11-check test --module /path/to/module.so --isolation file --resume
```

If you want the run to stop immediately when it hits a bad unit, use:

```bash
uv run pkcs11-check test \
  --module /path/to/module.so \
  --isolation file \
  --stop-on-failure
```

Start a fresh run without `--resume` after fixing a problem when the affected targets need
revalidation.

## State File

The default state file is:

```text
.pkcs11-check-isolation-state.json
```

You can override it:

```bash
uv run pkcs11-check test \
  --module /path/to/module.so \
  --isolation file \
  --state-file /tmp/pkcs11-check-bouncyhsm.json
```

Starting a fresh run without `--resume` clears prior isolated state/report artifacts and overwrites
the old state file immediately.

## Adaptive Policy File

The default adaptive policy file is:

```text
.pkcs11-check-isolation-policy.json
```

`--isolation auto` uses it to remember files that previously crashed or timed out
for the same backend fingerprint. Those files are promoted to per-test isolation
on later runs while the rest of the target set stays at file granularity. Fresh
crashes in the current run are also escalated immediately without waiting for a
second invocation.

Use `--max-crashes-per-file` to cap how many crashing per-test units the runner
will attribute before skipping the rest of that file:

```bash
uv run pkcs11-check test \
  --module /path/to/module.so \
  --isolation auto \
  --max-crashes-per-file 2
```

`0` disables the cap and keeps running every collected nodeid from an escalated file.

You can override it:

```bash
uv run pkcs11-check test \
  --module /path/to/module.so \
  --isolation auto \
  --policy-file /tmp/pkcs11-check-policy.json
```

## Reports And State Inspection

Isolated modes can now emit aggregated machine-readable reports too:

```bash
uv run pkcs11-check test \
  --module /path/to/module.so \
  --isolation auto \
  --output json
```

```bash
uv run pkcs11-check test \
  --module /path/to/module.so \
  --isolation file \
  --output junit \
  --output-file /tmp/pkcs11-check.xml
```

For isolated runs:

- `--output json` writes an aggregated `pkcs11-check-results.json`
- `--output junit` writes an aggregated `pkcs11-check-results.xml`
- `--output rich` keeps console-only output

In JSON, an unverified unit carries `"completion_verified": false` and `"incomplete": true`,
and the aggregate carries `summary.incomplete: true`; the latter is also true for timeout or
crash-limited runs. In JUnit, the same unit is an `<error type="incomplete">` with message
`report log completion could not be verified` and counts as an error, not a failure or skip.
Recovered runs may also include top-level `attempt_history` and `recovery_events`; those are
evidence, not alternate current unit verdicts.

You can inspect saved state or adaptive policy files directly:

```bash
uv run pkcs11-check state .pkcs11-check-isolation-state.json
uv run pkcs11-check state .pkcs11-check-isolation-policy.json
uv run pkcs11-check state --output json .pkcs11-check-isolation-state.json
```

## Scope And Limits

- `--sessions` is ignored in isolated modes.
- The normal `--timeout` value is still passed through to pytest as per-test timeout.
- The file runner also has an outer subprocess timeout so a dead file runner does not hang forever.
- `--max-crashes-per-file` defaults to `10` in `test` and `auto` isolation; `0` disables it.
- Resume safety checks include the requested units, pytest arguments, relevant environment,
  and file/module metadata. A changed test file or changed module binary invalidates the old state.
- Adaptive policy keys off backend-relevant inputs only: module/interface/slot/manifest/env, not the
  current target list. That lets different target selections reuse the same crash knowledge.

Use `file` when:

- the provider is crash-prone but you still want decent speed
- failures cluster by file or fixture setup

Use `auto` when:

- you want the run to recover from token/module crashes
- you are using the default `pkcs11-check test` path
- you want the runner to keep file-level speed for most tests
- you want existing `subprocess` files kept on the file-isolated path
- you want existing `subprocess_per_test` files promoted automatically
- you want files that crashed earlier on the same backend to be promoted automatically

Use `test` when:

- you need precise crash attribution
- you want resume to preserve attempted tests and run only missing nodes
- a single file contains both crashing and useful tests

Use `none` when:

- you explicitly want the old fastest path
- you trust the backend not to crash the pytest process
- you are debugging runner overhead rather than backend stability

## Environment Variables For Isolation Mode

The isolation mode and related options can be driven via environment variables, which is
useful when an external wrapper or conftest sets them before invoking `pkcs11-check test`:

```bash
P11TEST_ISOLATION=auto \
pkcs11-check test --module /path/to/module.so src/pkcs11_check/testcases/test_aead.py
```

```bash
P11TEST_ISOLATION=file \
pkcs11-check test --module /path/to/module.so src/pkcs11_check/testcases/ckr/test_ckr_codes.py
```

```bash
P11TEST_ISOLATION=test \
pkcs11-check test --module /path/to/module.so src/pkcs11_check/testcases/test_aead.py
```

Useful companion variables:

```bash
P11TEST_ISOLATION=file
P11TEST_RESUME=1
P11TEST_STOP_ON_FAILURE=1
P11TEST_STATE_FILE=/tmp/pkcs11-check-state.json
P11TEST_POLICY_FILE=/tmp/pkcs11-check-policy.json
P11TEST_MAX_CRASHES_PER_FILE=2
```

## Provider Example

Once you have a provider library built and a token set up, point `--module` at the shared
library and choose an isolation mode:

```bash
pkcs11-check test \
  --module /path/to/module.so \
  --pin 1234 \
  --isolation file \
  src/pkcs11_check/testcases/ckr
```

For network-backed providers that require connection environment variables, set them
before invoking the CLI:

```bash
PROVIDER_CFG='...' \
pkcs11-check test \
  --module /path/to/module.so \
  --pin 1234 \
  --isolation file \
  src/pkcs11_check/testcases/ckr
```
