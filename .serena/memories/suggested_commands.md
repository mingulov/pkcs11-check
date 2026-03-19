# Suggested Commands

## Run CLI
```bash
uv run pkcs11-check version
uv run pkcs11-check test --help
uv run pkcs11-check info --help
uv run pkcs11-check list
```

## Testing
```bash
uv run pytest tests/ -v                    # meta-tests (pkcs11-check's own tests)
uv run pytest src/pkcs11-check/testcases/ \     # product tests against a PKCS#11 module
  --p11-module=/path/to/module.so --p11-pin=1234 -v
```

## Quality
```bash
uv run ruff check src/ tests/              # lint
uv run ruff format src/ tests/             # format
uv run mypy src/                           # type check
```

## Dependencies
```bash
uv sync --all-extras                       # install/update all deps
uv add <package>                           # add a dependency
```
