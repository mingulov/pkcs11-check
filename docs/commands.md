# Commands Reference

## Standard commands (always use `uv run` prefix)

```bash
uv run pkcs11-check version              # check CLI works
uv run python -m pytest tests/test_python_source_syntax.py tests/test_security_subprocess_regressions.py tests/test_subprocess_result_policy.py  # fast syntax/generated-subprocess gate
uv run python -m pytest tests/           # run meta-tests
uv run ruff check src/ tests/            # lint
uv run ruff format src/ tests/           # format
uv run mypy src/                         # type check
```

> **Never** run bare `ruff`, `mypy`, or `pytest` — they are inside the uv venv.

The fast syntax/generated-subprocess gate covers ordinary Python syntax under
`src/` and `tests/`, plus representative dynamically generated child scripts
used by crash-survival tests. It does not replace provider runs; it prevents
broken local test code from being counted as provider evidence.

## Running the suite against a module

```bash
uv run pkcs11-check test --p11-module /path/to/module.so --p11-pin 1234
```

### Test profiles (marker selection)

```bash
uv run pkcs11-check test --p11-module <so> -m smoke                              # ~27 tests, ~5s
uv run pkcs11-check test --p11-module <so> -m "not (wycheproof or acvp or cctv or stress or fuzz or slow)"  # ~2300 tests, ~30s
uv run pkcs11-check test --p11-module <so> -m "wycheproof or acvp or cctv"       # ~72K vectors only
uv run pkcs11-check test --p11-module <so>                                        # full: ~75K tests
```

### Fast vs full: long-running test cases (`slow`)

A small set of individually long-running cases (RSA-4096 ops/keygen, DSA/DH
parameter generation, AES large-multiblock, leak/churn/fuzz loops) carry
`@pytest.mark.slow`. They are *not* the high-count vector files (wycheproof/acvp
are thousands of fast cases and stay in the basic run). The `pkcs11-check test`
command has convenience flags:

```bash
uv run pkcs11-check test -m <module> --skip-slow   # basic/fast: -m "not slow"
uv run pkcs11-check test -m <module> --only-slow   # only the long-running cases
uv run pkcs11-check test -m <module>               # full: everything (default)
```

`--skip-slow`/`--only-slow` compose with `--marker` (e.g. `--marker acvp
--skip-slow` → `-m "(acvp) and (not slow)"`). The full profile still runs every
case — `slow` is a *selection* profile, never a way to hide a finding.

## Test vector data

```bash
uv run pkcs11-check fetch-data --status      # show what's present/missing
uv run pkcs11-check fetch-data all           # fetch all sources (~800 MB)
uv run pkcs11-check fetch-data wycheproof    # fetch individual source
uv run pkcs11-check fetch-disabled           # fetch disabled-tests baseline
```

## Artifact comparison

```bash
uv run pkcs11-check compare-coverage artifacts3/wolfpkcs11-pooled artifacts/wolfpkcs11-pooled --fail-on-loss
uv run pkcs11-check compare-coverage old/coverage.json new/coverage.json --output json
```

`compare-coverage` compares provider-local mechanism coverage state buckets
(`accepted`, `attempted`, `rejected_cleanly`, crash/timeout, and compatibility
`invoked`) and exits 1 with `--fail-on-loss` if the candidate lost a baseline
state. Use it before trusting a speed change that rearranges sharding, skips, or
fast paths.

## Per-provider classification report

Roll at-source classifications (and runner-side crash findings) up into per-provider
conformance reports. Run after a test run that produced a `report.jsonl` (the `test_cmd`
JSON path sets `PKCS11_CHECK_REPORT_LOG` so the plugin writes one).

```bash
# Single provider (bare paths; --provider names it; --results-json adds crash findings):
uv run python -m tools.report --report-log /path/report.jsonl \
    --results-json /path/results.json --provider <name> --out <dir>

# Multi-provider (repeat NAME=path; writes _index.md + _universal.md too):
uv run python -m tools.report \
    --report-log nss=/p/nss.jsonl --report-log softhsm2=/p/sh.jsonl --out <dir>
```

Flags: `--report-log` (path, or `NAME=path`, repeatable), `--results-json` (optional, same
forms, for crash/timeout findings), `--provider` (names the provider for the single bare-path
form), `--out` (output directory). Writes `<provider>.md` + `<provider>.jsonl` per provider, and
`_index.md` + `_universal.md` when more than one provider is given. See
[../tools/report/README.md](../tools/report/README.md).

## Provider builds & the Docker test matrix

Local provider builds (`local-builds/`), the Docker target matrix
(`docker/` + the pooled `test_pool.py` runner), and result-comparison tooling live in
the **development workspace** (`pkcs11-check-ws`), not in this repo. See the workspace
docs for building providers and running the Docker conformance matrix.
