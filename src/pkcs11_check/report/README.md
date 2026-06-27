# pkcs11_check.report - per-provider classification reports

Rolls the **at-source classifications** emitted by the test suite (see
[`pkcs11_check.classification`](../classification.py) and
[docs/architecture.md](../../../docs/architecture.md) "At-source test-outcome classification") up into
human-readable, severity-first conformance reports - one per provider, plus cross-provider
correlation when several providers are passed.

## Pipeline

```
report.jsonl + results.json
        │  extract.py   group findings on a readable key
        ▼
   groups[]
        │  correlate.py (enrich)  add category/routing + caveats from known-issue text
        │  correlate.py (correlate)  find universal themes across providers
        ▼
   render.py   compact severity-first markdown
        │  __main__.py   CLI: read inputs, write the output files
        ▼
<provider>.md / <provider>.jsonl  (+ _index.md / _universal.md)
```

- **extract** (`extract.py`) - reads the pytest report log, pulls each call-phase report's
  `pkcs11_classification` finding list out of `user_properties`, folds in runner-side crash
  findings, and groups them on a *readable* tuple key (no hashes):
  `(test_file, reason, kind, mechanism, operation, expected_ckr, actual_ckr)`. Each group keeps a
  `count`, sample `nodeids`, sorted unique `vector_ids` (capped with a `+N` overflow marker),
  `sources`, and first-member metadata.
- **render** (`render.py`) - emits the compact provider markdown: a counts line, crash and fail
  sections ordered by severity (`🔴 CRITICAL` → `🟠 HIGH` → `🟡 MEDIUM` → `⚪ LOW`) grouped within
  each by finding `kind` keyword (crypto/policy/lifecycle/metadata), a single collapsed `🟡 deviations · xfail`
  section (one count line per xfail reason with a top example, never the full enumeration), and `⚪`
  one-liners for sanctioned-refusal compliance and the unclassified backlog. The fail sections plus
  the folded tail stay near one screen even at thousands of findings.
- **correlate** (`correlate.py`) - `enrich()` annotates each group in place with a triage
  `category` / `routing` (fails → `PROVIDER_BUG`/`PROVIDER_REPORT`, xfails → `deviation`/`DOCS_ONLY`,
  unclassified → `HARNESS_OR_UNMIGRATED`/`HARNESS_FIX`, a known-issue match → `KNOWN_ISSUE`)
  and flags the soft-token padding-oracle caveat. `correlate()` finds *universal themes* - the same
  `(reason, kind, mechanism)` signature seen across two or more providers - plus single-provider
  *outliers*.
- **CLI** (`__main__.py`) - `pkcs11-check-report` (also `python -m pkcs11_check.report`); flags and
  usage in [docs/commands.md](../../../docs/commands.md) "Per-provider classification report".

## Record schema

Each finding is one serialized `pkcs11_check.classification.Classification` (`schema: 1`):

| field | meaning |
|---|---|
| `reason` | one of the 10 reasons (`wrong_result`, `accepted_invalid`, `self_contradiction`, `oracle`, `crash`, `not_operational`, `nonspec_reject`, `honest_deviation`, `undeclared_capability`, `sanctioned_refusal`) plus the reserved `unclassified` runtime-gate marker |
| `outcome` | `pass` / `xfail` / `fail`, derived from `reason` |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`, derived from `(reason, kind)` |
| `kind` | `crypto`=A / `policy`=B / `lifecycle`=C / `metadata`=D (or `null`) |
| `label`, `summary` | human-readable identifier and one-line description |
| `operation`, `mechanism` | PKCS#11 function and mechanism, when known |
| `expected_ckr`, `actual_ckr` | CKR names (resolved from codes) for negative ops |
| `spec_ref` | OASIS PKCS#11 v3.2 reference from `pkcs11_check.spec_refs.lookup` (never fabricated) |
| `source`, `vector_id` | test-vector provenance (e.g. Wycheproof/ACVP id) |
| `detail` | optional structured extras (e.g. crash signal/returncode) |

Crash findings are not emitted in-test (the process is dead); they are built runner/report-side by
`pkcs11_check.core.file_runner.crash_classification` from `results.json` and have the same shape.

## Output files

- `<provider>.md` - compact, severity-first markdown (the report).
- `<provider>.jsonl` - one enriched group per line (machine-readable backing data).
- `_index.md` - counts table per provider + top universal themes + links (multi-provider only).
- `_universal.md` - full cross-provider correlation (universal themes + outliers) (multi-provider
  only).
