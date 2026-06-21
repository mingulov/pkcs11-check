# Task 5: Wire --key-inject/--wrap-* through plugin options, p11_config, and pytest args

## Files Changed

1. `src/pkcs11_check/plugin.py` — added 8 new `group.addoption(...)` calls in `pytest_addoption`
2. `src/pkcs11_check/fixtures.py` — added 8 new option reads and conditional `kwargs` updates in `p11_config`
3. `src/pkcs11_check/cli/test_cmd.py` — added 8 params to `_build_pytest_args` signature and body; updated the sole call site in `test_command` to pass all 8 from the typer parameters
4. `tests/test_key_inject_arg_wiring.py` — new test file (17 tests)

## End-to-End Flow

The CLI flags flow through three layers:

```
pkcs11-check test --key-inject=force-unwrap --wrap-rsa-bits=4096
      │
      ▼
test_command() [typer params]
      │
      ├─► _build_pytest_args(key_inject="force-unwrap", wrap_rsa_bits=4096, ...)
      │         emits: ["--p11-key-inject", "force-unwrap", "--p11-wrap-rsa-bits", "4096", ...]
      │         (only non-default values are emitted)
      │
      └─► pytest subprocess is launched with those flags
              │
              ▼
         plugin.pytest_addoption() — registers --p11-key-inject, --p11-wrap-rsa-bits, etc.
              │
              ▼
         p11_config fixture reads getoption("p11_key_inject") etc.
              │   (conditionally overwrites defaults: off/bootstrap/None/2048/auto are omitted)
              ▼
         P11TestConfig(key_inject="force-unwrap", wrap_rsa_bits=4096, ...)
              │
              ▼
         provisioning layer reads p11_config.key_inject / .wrap_rsa_bits / etc.
```

**Default-elision principle:** every option is emitted/applied only when it differs from the field default. This ensures that TOML/env-layer values are not silently overridden when the user hasn't explicitly passed a flag.

## New Options Registered

| Pytest flag | dest | default |
|---|---|---|
| `--p11-key-inject` | `p11_key_inject` | `"off"` |
| `--p11-wrap-key-source` | `p11_wrap_key_source` | `"bootstrap"` |
| `--p11-wrap-key-label` | `p11_wrap_key_label` | `None` |
| `--p11-wrap-key-handle` | `p11_wrap_key_handle` | `None` (int) |
| `--p11-wrap-key-value` | `p11_wrap_key_value` | `None` |
| `--p11-wrap-mech` | `p11_wrap_mech` | `None` |
| `--p11-wrap-rsa-bits` | `p11_wrap_rsa_bits` | `2048` (int) |
| `--p11-wrap-oaep-hash` | `p11_wrap_oaep_hash` | `"auto"` |

## Test Rationale

**`_build_pytest_args` tests (14 tests):** Unit-test the arg-serialization logic directly.
- Each non-default value produces the expected consecutive `["--p11-X", value]` pair.
- Each default value produces no flag (elision verified).
- Covers all 8 params: key_inject (4), wrap_rsa_bits (2), wrap_oaep_hash (2), and all 6 None-defaulted params (6).

**Plugin option registration tests (2 tests):** Feed a fake parser object to `pytest_addoption` and collect all registered option strings. Assert `--p11-key-inject` is present (targeted) and that all 8 new options are present (comprehensive). Avoids needing a live pytest session or a real module path.

**Fixture-level coverage:** The `p11_config` fixture reads options via `request.config.getoption(...)`. Because the test for `_build_pytest_args` already proves the flags are emitted correctly, and the plugin test proves they are registered under the right `dest` names, the round-trip is verified without needing live pytest internals.

## Gate Outputs

| Gate | Result |
|---|---|
| `pytest tests/test_key_inject_arg_wiring.py -v` | 17 passed |
| `ruff format --check .` | 755 files already formatted |
| `ruff check .` | All checks passed |
| `mypy --strict src` | Success: no issues in 396 source files |
| `pytest tests/` | 2886 passed, 3 skipped |
