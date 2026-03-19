# Per-File Isolation Mode

`p11test test` now supports a resumable per-file isolation mode for crash-prone modules:

```bash
uv run p11test test \
  --module /path/to/module.so \
  --isolation file
```

## What it does

- Expands the requested pytest targets into an ordered list of files or nodeids.
- Probes PKCS#11 capabilities in a short-lived helper subprocess and passes the
  resulting manifest into pytest instead of loading the module during collection.
- Runs each unit in a fresh `python -m pytest` subprocess.
- Writes progress to `.p11test-isolation-state.json` by default.
- Continues past a crashing file because the file process, not the main runner, dies.
- Creates parent directories for `--state-file` automatically.

This is not full per-test isolation. It is a practical regression mode for unstable modules while the deeper pytest integration is still unfinished.

## Resume From The Broken Place

Use `--resume` to continue from the first unit that did not finish cleanly:

```bash
uv run p11test test \
  --module /path/to/module.so \
  --isolation file \
  --resume
```

The runner treats only `passed` and `empty` units as complete. Files that failed, crashed, or timed out are rerun on resume.

If you want the run to stop immediately when it hits a bad file, use:

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

## Scope And Limits

- `--isolation file` currently supports only `--output rich`.
- `--sessions` is ignored in file isolation mode.
- The normal `--timeout` value is still passed through to pytest as per-test timeout.
- The file runner also has an outer subprocess timeout so a dead file runner does not hang forever.
- Resume safety checks include the requested units, pytest arguments, relevant environment,
  and file/module metadata. A changed test file or changed module binary invalidates the old state.

## Local Helper Script

`local-builds/test.sh` can now opt into the same mode:

```bash
P11TEST_ISOLATION=file \
bash local-builds/test.sh bouncyhsm src/p11test/testcases/ckr/test_ckr_codes.py
```

Some crash-prone providers now default to file isolation automatically when the
user does not override the mode:

- `nss-softokn`
- `qryptotoken`

Those provider defaults use a stable state file under `/tmp`, for example:

```text
/tmp/p11test-nss-softokn-isolation-state.json
```

You can still override the default explicitly:

```bash
P11TEST_ISOLATION=none bash local-builds/test.sh nss-softokn -k ckr
P11TEST_ISOLATION=file bash local-builds/test.sh qryptotoken -x
```

Useful companion variables:

```bash
P11TEST_ISOLATION=file
P11TEST_RESUME=1
P11TEST_STOP_ON_FAILURE=1
P11TEST_STATE_FILE=/tmp/p11test-bouncyhsm.json
```

The shell helper supports the common local workflow options in isolation mode:

- file or nodeid targets
- `-k` / `--match`
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
