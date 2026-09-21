# Configuration

Settings merge from up to three layers, but **not every key reads every
layer** -- the `Layers` column on each table below is the contract. When a lower
layer is dead for a key, providing it there has no effect; `test` prints a
`Warning` naming the ignored setting instead of silently mis-scoping the run.

Layer shorthands: **CLI** (the `test` flag, or the global flag for `log_level`),
**env** (`P11TEST_<NAME>`), **TOML** (a key in `pkcs11_check.toml`),
**default** (built-in). Precedence among the live layers is CLI > env > TOML >
default. Keys are `snake_case` in TOML and in environment variables; the
matching CLI flags are `kebab-case` (`key_inject` becomes `--key-inject`).
Some keys have no CLI flag at all (`disabled_tests_file`, the dead keys).

To see what one invocation will actually use, run it with `--show-config`:

```console
$ pkcs11-check test --module /usr/lib/softhsm/libsofthsm2.so --show-config
```

It prints every key with its effective value and the winning source, then exits
without touching the module. Secrets render as `set`/`unset`, never values.

The TOML file is read from `pkcs11_check.toml` **in the current working directory**. There is no `--config` flag and no search of parent directories or home: if the file is not in the directory you run from, it is not read. That is the single most common reason a TOML setting appears to be ignored. (The next most common: the key's layers are CLI-only -- see below.)

A minimal file (only live TOML keys -- `module` and `slot` in TOML would be
ignored, with a warning):

```toml
disabled_tests_file = "disabled-tests.txt"
key_inject = "unwrap"
```

## Connecting to the module

| Setting | Env | Default | Layers | Meaning |
|---|---|---|---|---|
| `module` | `P11TEST_MODULE` | *(required)* | CLI only | Path to the PKCS#11 shared library. Required `--module` flag; env/TOML are never read. |
| `slot` | `P11TEST_SLOT` | `0` | CLI only | Slot **index** into the present-token slot list, not a raw slot ID. NSS uses slot 1. Only `--slot` applies; env/TOML are silently dead without the warning this file describes. |
| `pin` | `P11TEST_PIN` | none | CLI > env > TOML | User PIN. When unset, `C_Login` is never called. `--pin` bridges into the child environment. |
| `so_pin` | `P11TEST_SO_PIN` | none | CLI > env > TOML | Security Officer PIN, for the tests that need a genuine `CKU_SO` session. Without it those tests fall back to guessing the user PIN. |
| `interface` | `P11TEST_INTERFACE` | `auto` | CLI only | Interface version to request: `auto`, `2.40`, `3.0`, `3.1`, `3.2`. Only `--interface` applies. |

PINs are never logged, printed, or passed on a command line that another process could read; they travel to test subprocesses through the environment only.

## Selecting what runs

| Setting | Env | Default | Layers | Meaning |
|---|---|---|---|---|
| `disabled_tests_file` | `P11TEST_DISABLED_TESTS_FILE` | auto-discovered | env > TOML | File of node-ids to exclude, one per line. There is no CLI flag; `--ignore-disabled-tests` skips the baseline for one run. When unset, a `disabled-tests.txt` in the resolved data directory is picked up automatically and the run says so. |
| `destructive` | `P11TEST_DESTRUCTIVE` | `false` | CLI > env > TOML | Allow tests that can modify or destroy token state. |
| `skip_unsupported` | `P11TEST_SKIP_UNSUPPORTED` | `true` | none (locked on) | Skip tests whose mechanism the module does not advertise. Always on; it cannot be disabled from any layer. |

The disabled-tests file holds pytest node-ids, one per line; `#` starts a comment. Node-ids always use forward slashes, on every platform, so a file written on Linux matches on Windows. Build one with `list-tests`:

```console
$ pkcs11-check list-tests --match "rsa_signature" > disabled-tests.txt
```

`list-tests` reads this same setting and, by default, **excludes** node-ids the baseline already disables, so its output matches what `test` would actually run. Pass `--include-disabled` to list them anyway, which is how you audit an existing baseline.

A configured path that does not exist is an error (exit 2), never a silent full run.

## Timeouts

| Setting | Env | Default | Layers | Meaning |
|---|---|---|---|---|
| `timeout_operation` | `P11TEST_TIMEOUT_OPERATION` | `30` | none (no reader) | Dead key: nothing reads it; per-operation timeouts are unimplemented. |
| `timeout_test` | `P11TEST_TIMEOUT_TEST` | `180` | none (no reader) | Dead key: nothing reads it. The live knob is the `--timeout` flag (default 180), which coincidentally equals this default. |

The per-test `--timeout` (default 180s) is a freeze/runaway safety net, not a cap on slow work: the slowest legitimate tests (ACVP AES MCT, ~100k chained operations) take around 110s on transport-bound modules.

## Output and diagnostics

| Setting | Env | Default | Layers | Meaning |
|---|---|---|---|---|
| `output` | `P11TEST_OUTPUT` | `rich` | CLI only | `rich`, `json`, or `junit`. Only `--output` applies. |
| `log_level` | `P11TEST_LOG_LEVEL` | `INFO` | CLI only | Standard Python level name. Only the global `--log-level` flag applies. |
| `rv_trace` | `P11TEST_RV_TRACE` | `false` | CLI > env > TOML | Record every `CK_RV` per test. See [rv-trace-design.md](rv-trace-design.md). The `PKCS11_CHECK_RV_TRACE` switch (below) also enables it. |
| `rv_trace_compact` | `P11TEST_RV_TRACE_COMPACT` | none | CLI > env > TOML | Keep only the last N trace entries instead of all. |

## Key provisioning

Only relevant when importing key material rather than generating it on-token. Full design in the key-provisioning documents.

| Setting | Env | Default | Layers | Meaning |
|---|---|---|---|---|
| `key_inject` | `P11TEST_KEY_INJECT` | `off` | CLI > env > TOML | `off`, `unwrap`, or `force-unwrap`. Anything else fails validation. |
| `wrap_key_source` | `P11TEST_WRAP_KEY_SOURCE` | `bootstrap` | CLI > env > TOML | `bootstrap` generates a KEK; `configured` uses one you supply. |
| `wrap_key_label` | `P11TEST_WRAP_KEY_LABEL` | none | CLI > env > TOML | Find the configured KEK by `CKA_LABEL`. |
| `wrap_key_handle` | `P11TEST_WRAP_KEY_HANDLE` | none | CLI > env > TOML | Find the configured KEK by object handle. |
| `wrap_key_value` | `P11TEST_WRAP_KEY_VALUE` | none | CLI > env > TOML | Symmetric KEK as hex; must decode to 16, 24 or 32 bytes, validated when the config is built. |
| `wrap_mech` | `P11TEST_WRAP_MECH` | auto | CLI > env > TOML | Override the negotiated unwrap mechanism, e.g. `CKM_RSA_AES_KEY_WRAP`. |
| `wrap_rsa_bits` | `P11TEST_WRAP_RSA_BITS` | `2048` | CLI > env > TOML | RSA KEK size. |
| `wrap_oaep_hash` | `P11TEST_WRAP_OAEP_HASH` | `auto` | CLI > env > TOML | `auto`, `sha1`, or `sha256`. |
| `allow_external_provision` | `P11TEST_ALLOW_EXTERNAL_PROVISION` | `false` | CLI > env > TOML | Opt-in acknowledgement for external-tool provisioning. |
| `external_provision_cmd` | `P11TEST_EXTERNAL_PROVISION_CMD` | none | CLI > env > TOML | Command template; placeholders `{keyfile}`, `{label}`, `{key_type}`, `{key_class}`. |

## Recovery for daemon-backed providers

CLI flags only (`--recover-mode`, `--recover-cmd`); off by default, and a default run behaves exactly as if the feature did not exist.

| Flag | Default | Meaning |
|---|---|---|
| `--recover-mode` | `off` | `off`, `wait` (pause for an external supervisor to restart the daemon), or `cmd` (run `--recover-cmd`). |
| `--recover-cmd` | none | Command to restart the provider. Run as an argument list, never through a shell. Supplying it implies `--recover-mode cmd`. Also reads `P11TEST_RECOVER_CMD`. |

Detection is a liveness probe between test units, never a list of error codes: modules return `CKR_DEVICE_ERROR` and similar during normal operation, so an error-code trigger would fire constantly on healthy modules. Configured hint RVs only decide *when* to probe, never that the daemon is dead. Units that failed while the daemon was going down are re-run against the restarted daemon and their false failures dropped; a unit that repeatedly kills the daemon is quarantined instead of retried forever. The daemon death itself is always recorded as a finding.

A daemon that is reachable but degraded -- answering, only ever more slowly -- is **not** detected. That needs a different signal than reachability.

## Environment variables that are not settings

These are switches, with no TOML or CLI equivalent.

| Variable | Meaning |
|---|---|
| `PKCS11_CHECK_NO_COLLECTION_CACHE=1` | Bypass the collection cache. First thing to try if test collection behaves oddly. |
| `PKCS11_CHECK_RV_TRACE` | Switch the probe subprocesses read for the CK_RV trace. Distinct from `P11TEST_RV_TRACE`, which is the `rv_trace` setting above. |
| `PKCS11_CHECK_RV_TRACE_COMPACT` | Ring-buffer window size the probe subprocesses read. |

## When a setting seems to be ignored

1. Check the `Layers` column above -- or run with `--show-config`. A CLI-only key (`slot`, `interface`, `module`, `output`, `log_level`) never reads env/TOML, and a dead key (`timeout_operation`, `timeout_test`, `max_sessions`, `skip_unsupported`) is read from nowhere; `test` warns when it sees one provided, naming the live knob to use instead.
2. Check precedence among the *live* layers -- a CLI flag beats the env var, which beats the TOML file. An old `P11TEST_*` exported in your shell silently wins over the file you are editing.
3. Check the working directory -- `pkcs11_check.toml` is read from the directory you run in, and nowhere else.
4. Check the key spelling -- an unknown key is rejected with a validation error naming it, so a typo fails the run rather than being quietly dropped.
5. For anything collection-related, re-run with `PKCS11_CHECK_NO_COLLECTION_CACHE=1`.

Note: `max_sessions` has no table row because it has no live layer and no live knob -- nothing reads it, and the `--sessions` flag is likewise ignored. It is kept only so old TOML files still parse.
