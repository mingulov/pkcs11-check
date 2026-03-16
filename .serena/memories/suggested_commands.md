# Suggested Commands

## Run CLI
```bash
uv run p11test version
uv run p11test test --help
uv run p11test info --help
uv run p11test list
```

## Testing
```bash
uv run pytest tests/ -v                    # meta-tests (p11test's own tests)
uv run pytest src/p11test/testcases/ \     # product tests against a PKCS#11 module
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
