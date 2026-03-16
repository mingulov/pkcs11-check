# Code Style & Conventions

- Type annotations on all public functions (mypy strict mode)
- ruff for formatting AND linting (no other formatters)
- Line length: 100
- Imports sorted by ruff (isort-compatible)
- Test files prefixed with `test_`
- Use `rich.console` for all CLI output (no bare print)
- Config values: snake_case in TOML/Python, kebab-case for CLI flags
- PIN values are NEVER logged, printed, or included in error messages
- `from __future__ import annotations` in all files
