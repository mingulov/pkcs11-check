# What to do when a task is completed

1. Run ruff: `uv run ruff check src/ tests/ --fix && uv run ruff format src/ tests/`
2. Run mypy: `uv run mypy src/`
3. Run meta-tests: `uv run pytest tests/ -v`
4. Commit changes with a descriptive message
