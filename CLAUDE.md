# p11test

CLI-first PKCS#11 test suite with segfault survival, interface forcing, and pytest plugin.

## Quick Reference

- **Language:** Python 3.11+
- **Package manager:** uv
- **Build backend:** hatchling (src/ layout)
- **CLI framework:** typer + rich
- **Config:** pydantic-settings (TOML + CLI + env)
- **Testing:** pytest (meta-tests in `tests/`, product test cases in `src/p11test/testcases/`)
- **Linting:** ruff
- **Type checking:** mypy --strict

## Commands

```bash
uv run p11test version              # check CLI works
uv run p11test test --help          # run CLI
uv run pytest tests/                # run meta-tests (p11test's own tests)
uv run ruff check src/ tests/       # lint
uv run ruff format src/ tests/      # format
uv run mypy src/                    # type check
```

## Architecture

### Two test directories
- `src/p11test/testcases/` — the PRODUCT: PKCS#11 tests run against hardware/software modules
- `tests/` — META-TESTS: tests for p11test's own code (config parsing, isolation logic, CLI)

### Core modules
- `core/loader.py` — PKCS#11 interface negotiation (C_GetInterfaceList, C_GetInterface, fallback to C_GetFunctionList)
- `core/isolation.py` — subprocess-based test execution for segfault survival
- `core/timeout.py` — per-operation, per-test, global timeout management
- `core/session.py` — session lifecycle, multi-session control
- `config.py` — four-layer config: CLI > env > TOML > defaults
- `plugin.py` — pytest11 entry point, registers fixtures and collection hooks
- `cli/app.py` — typer app, routes to test/info/list/version subcommands

### Key design decisions
- All PKCS#11 calls execute in isolated subprocesses (multiprocessing spawn). A segfault in the loaded .so only kills that subprocess.
- Interface negotiation tries v3.2 first, falls back to 3.0, then 2.40. `--interface` forces a specific version.
- Test cases are native pytest tests with custom fixtures (p11_session, p11_module, etc.)
- Tests auto-skip when the detected interface version doesn't support them (@pytest.mark.requires_v30, etc.)

## Conventions

- Type annotations on all public functions (mypy strict)
- `ruff` for formatting and linting — no other formatters
- Imports sorted by ruff (isort-compatible)
- Line length: 100
- Test files prefixed with `test_`
- Use `rich.console` for all CLI output (no bare print)
- Config values: snake_case in TOML/Python, kebab-case for CLI flags
- PIN values are never logged, printed, or included in error messages
