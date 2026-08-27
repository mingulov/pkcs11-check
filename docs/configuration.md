# Configuration

Every setting can be given three ways, and they merge in this order (first wins):

1. **CLI flag** -- `--slot 1`
2. **Environment variable** -- `P11TEST_SLOT=1`, always the setting name upper-cased with a `P11TEST_` prefix
3. **TOML file** -- `disabled_tests_file = "..."` in `pkcs11_check.toml`
4. built-in default

The TOML file is read from `pkcs11_check.toml` **in the current working directory**. There is no `--config` flag and no search of parent directories or home: if the file is not in the directory you run from, it is not read. That is the single most common reason a TOML setting appears to be ignored.

Keys are `snake_case` in TOML and in environment variables; the matching CLI flags are `kebab-case` (`disabled_tests_file` becomes `--disabled-tests-file`).

A minimal file:

```toml
module = "/usr/lib/softhsm/libsofthsm2.so"
slot = 0
disabled_tests_file = "disabled-tests.txt"
```

## Connecting to the module

| Setting | Env | Default | Meaning |
|---|---|---|---|
| `module` | `P11TEST_MODULE` | *(required)* | Path to the PKCS#11 shared library. |
| `slot` | `P11TEST_SLOT` | `0` | Slot **index** into the present-token slot list, not a raw slot ID. NSS uses slot 1. |
| `pin` | `P11TEST_PIN` | none | User PIN. When unset, `C_Login` is never called. |
| `so_pin` | `P11TEST_SO_PIN` | none | Security Officer PIN, for the tests that need a genuine `CKU_SO` session. Without it those tests fall back to guessing the user PIN. |
| `interface` | `P11TEST_INTERFACE` | `auto` | Interface version to request: `auto`, `2.40`, `3.0`, `3.1`, `3.2`. |

PINs are never logged, printed, or passed on a command line that another process could read; they travel to test subprocesses through the environment only.

## Selecting what runs

| Setting | Env | Default | Meaning |
|---|---|---|---|
| `disabled_tests_file` | `P11TEST_DISABLED_TESTS_FILE` | auto-discovered | File of node-ids to exclude, one per line. When unset, a `disabled-tests.txt` in the resolved data directory is picked up automatically and the run says so. |
| `destructive` | `P11TEST_DESTRUCTIVE` | `false` | Allow tests that can modify or destroy token state. |
| `skip_unsupported` | `P11TEST_SKIP_UNSUPPORTED` | `true` | Skip tests whose mechanism the module does not advertise. |

The disabled-tests file holds pytest node-ids, one per line; `#` starts a comment. Node-ids always use forward slashes, on every platform, so a file written on Linux matches on Windows. Build one with `list-tests`:

```console
$ pkcs11-check list-tests --match "rsa_signature" > disabled-tests.txt
```

`list-tests` reads this same setting and, by default, **excludes** node-ids the baseline already disables, so its output matches what `test` would actually run. Pass `--include-disabled` to list them anyway, which is how you audit an existing baseline.

A configured path that does not exist is an error (exit 2), never a silent full run.

## Timeouts

| Setting | Env | Default | Meaning |
|---|---|---|---|
| `timeout_operation` | `P11TEST_TIMEOUT_OPERATION` | `30` | Per-operation timeout, seconds. |
| `timeout_test` | `P11TEST_TIMEOUT_TEST` | `180` | Per-test timeout, seconds. A freeze/runaway safety net, not a cap on slow work: the slowest legitimate tests (ACVP AES MCT, ~100k chained operations) take around 110s on transport-bound modules. |

## Output and diagnostics

| Setting | Env | Default | Meaning |
|---|---|---|---|
| `output` | `P11TEST_OUTPUT` | `rich` | `rich` or `json`. |
| `log_level` | `P11TEST_LOG_LEVEL` | `INFO` | Standard Python level name. |
| `rv_trace` | `P11TEST_RV_TRACE` | `false` | Record every `CK_RV` per test. See [rv-trace-design.md](rv-trace-design.md). |
| `rv_trace_compact` | `P11TEST_RV_TRACE_COMPACT` | none | Keep only the last N trace entries instead of all. |

## Key provisioning

Only relevant when importing key material rather than generating it on-token. Full design in the key-provisioning documents.

| Setting | Env | Default | Meaning |
|---|---|---|---|
| `key_inject` | `P11TEST_KEY_INJECT` | `off` | `off`, `unwrap`, or `force-unwrap`. |
| `wrap_key_source` | `P11TEST_WRAP_KEY_SOURCE` | `bootstrap` | `bootstrap` generates a KEK; `configured` uses one you supply. |
| `wrap_key_label` | `P11TEST_WRAP_KEY_LABEL` | none | Find the configured KEK by `CKA_LABEL`. |
| `wrap_key_handle` | `P11TEST_WRAP_KEY_HANDLE` | none | Find the configured KEK by object handle. |
| `wrap_key_value` | `P11TEST_WRAP_KEY_VALUE` | none | Symmetric KEK as hex; must decode to 16, 24 or 32 bytes, validated when the config is built. |
| `wrap_mech` | `P11TEST_WRAP_MECH` | auto | Override the negotiated unwrap mechanism, e.g. `CKM_RSA_AES_KEY_WRAP`. |
| `wrap_rsa_bits` | `P11TEST_WRAP_RSA_BITS` | `2048` | RSA KEK size. |
| `wrap_oaep_hash` | `P11TEST_WRAP_OAEP_HASH` | `auto` | `auto`, `sha1`, or `sha256`. |
| `allow_external_provision` | `P11TEST_ALLOW_EXTERNAL_PROVISION` | `false` | Opt-in acknowledgement for external-tool provisioning. |
| `external_provision_cmd` | `P11TEST_EXTERNAL_PROVISION_CMD` | none | Command template; placeholders `{keyfile}`, `{label}`, `{key_type}`, `{key_class}`. |

## Recovery for daemon-backed providers

CLI flags only (`--recover-mode`, `--recover-cmd`); off by default, and a default run behaves exactly as if the feature did not exist.

| Flag | Default | Meaning |
|---|---|---|
| `--recover-mode` | `off` | `off`, `wait` (pause for an external supervisor to restart the daemon), or `cmd` (run `--recover-cmd`). |
| `--recover-cmd` | none | Command to restart the provider. Run as an argument list, never through a shell. Supplying it implies `--recover-mode cmd`. |

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

1. Check precedence -- a CLI flag beats the env var, which beats the TOML file. An old `P11TEST_*` exported in your shell silently wins over the file you are editing.
2. Check the working directory -- `pkcs11_check.toml` is read from the directory you run in, and nowhere else.
3. Check the key spelling -- an unknown key is rejected with a validation error naming it, so a typo fails the run rather than being quietly dropped.
4. For anything collection-related, re-run with `PKCS11_CHECK_NO_COLLECTION_CACHE=1`.
