# Isolated Modes

`p11test test` now supports resumable isolated modes for crash-prone modules:

```bash
uv run p11test test \
  --module /path/to/module.so \
  --isolation auto
```

or:

```bash
uv run p11test test \
  --module /path/to/module.so \
  --isolation file
```

or:

```bash
uv run p11test test \
  --module /path/to/module.so \
  --isolation test
```

## What it does

- Expands the requested pytest targets into an ordered list of files or individual pytest nodeids.
- Probes PKCS#11 capabilities in a short-lived helper subprocess and passes the
  resulting manifest into pytest instead of loading the module during collection.
- Runs each unit in a fresh `python -m pytest` subprocess.
- Writes progress to `.p11test-isolation-state.json` by default.
- Learns crash-prone files in `.p11test-isolation-policy.json` by default and
  promotes them to per-test isolation in later `--isolation auto` runs.
- Continues past a crashing unit because the unit process, not the main runner, dies.
- Creates parent directories for `--state-file` automatically.

Mode summary:

- `--isolation auto`: safe default, using per-file isolation unless a file is marked
  `subprocess_per_test` or was previously promoted by the adaptive policy file
- `--isolation file`: one subprocess per file
- `--isolation test`: one subprocess per collected pytest test nodeid

`test` mode is slower, but it gives much better crash attribution and lets the
runner skip only the one crashing test on resume instead of rerunning a whole file.
`auto` is the best default recovery mode when you want safety without paying full
per-test cost across the entire target set.
If a file crashes or times out during an `auto` run, the runner now escalates that
same file to per-test isolation immediately for the rest of the current run.
Once an escalated file reaches the configured per-file crash budget, the runner
marks the remaining test units from that file as `crash_limited` and moves on.

## Resume From The Broken Place

Use `--resume` to continue from the first unit that did not finish cleanly:

```bash
uv run p11test test \
  --module /path/to/module.so \
  --isolation file \
  --resume
```

The runner treats `passed`, `empty`, and `crash_limited` units as complete. Files
that failed, crashed, or timed out are rerun on resume.
In `--isolation auto`, resume keeps the saved unit plan from the state file. Fresh
non-resume runs are the point where newly learned policy promotions take effect.

If you want the run to stop immediately when it hits a bad unit, use:

```bash
uv run p11test test \
  --module /path/to/module.so \
  --isolation file \
  --stop-on-failure
```

Then rerun with `--resume` after fixing or investigating the problem.

## State File

The default state file is:

```text
.p11test-isolation-state.json
```

You can override it:

```bash
uv run p11test test \
  --module /path/to/module.so \
  --isolation file \
  --state-file /tmp/p11test-bouncyhsm.json
```

Starting a fresh run without `--resume` overwrites the old state file immediately.

## Adaptive Policy File

The default adaptive policy file is:

```text
.p11test-isolation-policy.json
```

`--isolation auto` uses it to remember files that previously crashed or timed out
for the same backend fingerprint. Those files are promoted to per-test isolation
on later runs while the rest of the target set stays at file granularity. Fresh
crashes in the current run are also escalated immediately without waiting for a
second invocation.

Use `--max-crashes-per-file` to cap how many crashing per-test units the runner
will attribute before skipping the rest of that file:

```bash
uv run p11test test \
  --module /path/to/module.so \
  --isolation auto \
  --max-crashes-per-file 2
```

`0` disables the cap and keeps running every collected nodeid from an escalated file.

You can override it:

```bash
uv run p11test test \
  --module /path/to/module.so \
  --isolation auto \
  --policy-file /tmp/p11test-policy.json
```

## Reports And State Inspection

Isolated modes can now emit aggregated machine-readable reports too:

```bash
uv run p11test test \
  --module /path/to/module.so \
  --isolation auto \
  --output json
```

```bash
uv run p11test test \
  --module /path/to/module.so \
  --isolation file \
  --output junit \
  --output-file /tmp/p11test.xml
```

For isolated runs:

- `--output json` writes an aggregated `p11test-results.json`
- `--output junit` writes an aggregated `p11test-results.xml`
- `--output rich` keeps console-only output

You can inspect saved state or adaptive policy files directly:

```bash
uv run p11test state .p11test-isolation-state.json
uv run p11test state .p11test-isolation-policy.json
uv run p11test state --output json .p11test-isolation-state.json
```

## Scope And Limits

- `--sessions` is ignored in isolated modes.
- The normal `--timeout` value is still passed through to pytest as per-test timeout.
- The file runner also has an outer subprocess timeout so a dead file runner does not hang forever.
- `--max-crashes-per-file` defaults to `3` in `test` and `auto` isolation; `0` disables it.
- Resume safety checks include the requested units, pytest arguments, relevant environment,
  and file/module metadata. A changed test file or changed module binary invalidates the old state.
- Adaptive policy keys off backend-relevant inputs only: module/interface/slot/manifest/env, not the
  current target list. That lets different target selections reuse the same crash knowledge.

Use `file` when:

- the provider is crash-prone but you still want decent speed
- failures cluster by file or fixture setup

Use `auto` when:

- you want the run to recover from token/module crashes
- you want the runner to keep file-level speed for most tests
- you want existing `subprocess` files kept on the file-isolated path
- you want existing `subprocess_per_test` files promoted automatically
- you want files that crashed earlier on the same backend to be promoted automatically

Use `test` when:

- you need precise crash attribution
- you want resume to skip only one bad test
- a single file contains both crashing and useful tests

## Local Helper Script

`local-builds/test.sh` can now opt into the same modes:

```bash
P11TEST_ISOLATION=auto \
bash local-builds/test.sh qryptotoken src/p11test/testcases/test_aead.py
```

```bash
P11TEST_ISOLATION=file \
bash local-builds/test.sh bouncyhsm src/p11test/testcases/ckr/test_ckr_codes.py
```

```bash
P11TEST_ISOLATION=test \
bash local-builds/test.sh qryptotoken src/p11test/testcases/test_aead.py
```

Some crash-prone providers now default to `auto` isolation automatically when the
user does not override the mode:

- `nss-softokn`
- `qryptotoken`

Those provider defaults use a stable state file under `/tmp`, for example:

```text
/tmp/p11test-nss-softokn-isolation-state.json
```

and a matching adaptive policy file, for example:

```text
/tmp/p11test-nss-softokn-isolation-policy.json
```

You can still override the default explicitly:

```bash
P11TEST_ISOLATION=none bash local-builds/test.sh nss-softokn -k ckr
P11TEST_ISOLATION=auto bash local-builds/test.sh nss-softokn -k ckr
P11TEST_ISOLATION=file bash local-builds/test.sh qryptotoken -x
P11TEST_ISOLATION=test bash local-builds/test.sh qryptotoken src/p11test/testcases/test_aead.py
```

Useful companion variables:

```bash
P11TEST_ISOLATION=file
P11TEST_RESUME=1
P11TEST_STOP_ON_FAILURE=1
P11TEST_STATE_FILE=/tmp/p11test-bouncyhsm.json
P11TEST_POLICY_FILE=/tmp/p11test-bouncyhsm-policy.json
P11TEST_MAX_CRASHES_PER_FILE=2
```

The shell helper supports the common local workflow options in isolation mode:

- file or nodeid targets
- `-k` / `--match`
- `-o` / `--output`
- `--output-file`
- `-v`
- `-x` / `--stop-on-failure`
- `--destructive`

For arbitrary pytest flags, use `uv run p11test test ...` directly.

## BouncyHSM Local Example

For local BouncyHSM, the stable path today is the LiteDb-backed server mode:

```bash
mkdir -p local-builds/bouncyhsm/data
cd local-builds/bouncyhsm/server
ASPNETCORE_ENVIRONMENT=Docker \
ASPNETCORE_URLS=http://127.0.0.1:5011 \
BouncyHsm_LiteDbPersistentRepositorySetup__DbFilePath=$PWD/../data/BouncyHsm.db \
BouncyHsm_BouncyHsmSetup__TcpEndpoint__Endpoint=127.0.0.1:8765 \
dotnet BouncyHsm.dll
```

Create a token:

```bash
curl -X POST http://127.0.0.1:5011/Slot \
  -H "Content-Type: application/json" \
  -d '{"IsHwDevice":false,"Description":"p11test","Token":{"Label":"p11test","SerialNumber":"0001","UserPin":"1234","SoPin":"12345678"}}'
```

Point the native shim at the local TCP endpoint and run the isolated mode:

```bash
BOUNCY_HSM_CFG_STRING='Server=127.0.0.1;Port=8765;' \
uv run p11test test \
  --module local-builds/bouncyhsm/lib/libbouncyhsm_pkcs11.so \
  --pin 1234 \
  --isolation file \
  src/p11test/testcases/ckr
```

The same flow also works through the local helper:

```bash
BOUNCY_HSM_CFG_STRING='Server=127.0.0.1;Port=8765;' \
P11TEST_ISOLATION=file \
bash local-builds/test.sh bouncyhsm src/p11test/testcases/ckr/test_ckr_codes.py
```
