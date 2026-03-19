# pkcs11-check Project Overview

CLI-first PKCS#11 test suite with segfault survival, interface forcing, and pytest plugin.

## Tech Stack
- Python 3.11+, uv (package manager), hatchling (build backend, src/ layout)
- CLI: typer + rich
- Config: pydantic-settings (TOML + CLI + env)
- Testing: pytest, pytest-xdist
- PKCS#11 binding: python-pkcs11 (v2.40; fork planned for v3.x)
- Isolation: multiprocessing (spawn) for segfault survival
- Linting: ruff, Type checking: mypy --strict

## Structure
- `src/pkcs11-check/` — the package
  - `cli/` — typer CLI (app.py, test_cmd.py, info_cmd.py, list_cmd.py)
  - `core/` — engine (loader.py, isolation.py, timeout.py, session.py)
  - `testcases/` — PRODUCT: PKCS#11 tests run against hardware/software modules
  - `config.py` — pydantic-settings config
  - `plugin.py` — pytest11 entry point
  - `fixtures.py` — pytest fixtures
- `tests/` — META-TESTS: tests for pkcs11-check's own code
- `docs/superpowers/specs/` — design specification
- `docs/superpowers/plans/` — implementation plans
