# Production Disabled Baseline Design

**Date:** 2026-03-31
**Status:** Draft
**Scope:** Phase 1 release-mode deselection with one repo-default global baseline

## Summary

This design intentionally narrows the earlier generic test-selection idea.
Phase 1 is not a full selector engine. It is a release-mode mechanism that
lets `pkcs11-check` honor one committed repo-default disabled baseline while
preserving existing skip and xfail semantics.

Runtime behavior stays simple:

- one fixed repo-default disabled file
- exact pytest nodeids only at runtime
- disabled tests are deselected, not skipped
- default runs honor the baseline
- an explicit opt-out exists for full-truth runs
- no target overlays in phase 1
- no invert/debug mode in phase 1

Baseline generation stays offline:

- read `artifacts/*/report.jsonl` as the primary machine-readable source
- optionally consult `results.json` as fallback or summary input
- generate candidate exact nodeids
- review and edit manually
- commit the final file to the repo

## Problem

The project needs a practical beta/release path before the full multi-provider
test matrix is green. The release path must be reproducible and easy to review,
but it must not redefine what normal skips and xfails mean inside the suite.

This leads to two separate concerns:

1. **Runtime deselection** for release-facing runs
2. **Offline baseline generation** from existing artifacts

These concerns should stay separate. The runner enforces the committed file.
The helper proposes candidates. The committed file remains authoritative.

## Goals

- Provide one committed repo-default disabled baseline.
- Honor that baseline by default in `pkcs11-check test`.
- Allow an explicit opt-out for full-truth runs.
- Work in all isolation modes: `none`, `file`, `test`, `auto`.
- Keep disabled tests out of execution and out of the skipped bucket.
- Support exact parametrized test variants via exact nodeids.
- Allow manual additions and removals regardless of how the helper generated
  the initial candidate list.
- Invalidate isolated resume state when the baseline changes.

## Non-Goals

- No runtime support for globs, marker expressions, or mask syntax.
- No target-specific overlays in phase 1.
- No runtime invert/debug mode in phase 1.
- No attempt to reinterpret existing skip or xfail semantics.
- No reliance on internal per-state cache directories as public input.

## Product Boundary

This feature is a **release-mode deselection system**, not a general-purpose
selection language.

- Existing skips still mean real runtime reasons such as missing mechanisms,
  unsupported interface version, missing data, or destructive/thread-safety
  gating.
- Existing xfails stay separate. They continue to represent known issues where
  the suite intentionally uses xfail today.
- The new baseline is a separate deselection bucket. Disabled tests may appear
  as `deselected`, but they must not appear as `skipped`.
- The runtime never decides whether a test "deserves" to be disabled. It only
  enforces the committed baseline file.

## Architecture

### 1. Repo-Default Baseline File

Add one committed default file:

- `config/disabled-tests.txt`

Format:

- one exact pytest nodeid per line
- comments allowed with `#`
- blank lines ignored
- duplicate entries allowed and deduplicated on load

Examples:

```text
# single test
src/pkcs11_check/testcases/test_encrypt.py::test_roundtrip

# one parametrized variant only
src/pkcs11_check/testcases/acvp/aes/test_cfb.py::test_acvp_aes_cfb[AES-enc-tc1021]
```

Phase 1 runtime does exact nodeid matching only. Mask syntax such as
`*something*` is not part of the runtime contract. If future authoring helpers
accept masks, they must resolve them offline into exact nodeids before writing
this file.

### 2. Runtime Loader

Add a dedicated runtime module:

- `src/pkcs11_check/core/test_selection.py`

Responsibilities:

- load `config/disabled-tests.txt`
- normalize comments/blank lines/duplicates
- expose `disabled_nodeids: set[str]`
- expose a stable fingerprint based on file path and file metadata or content
- provide small helpers used by CLI, plugin, and isolated runner code

Phase 1 does not need pattern compilation, marker matching, or target-overlay
merging logic.

### 3. Default-On Runtime Behavior

`pkcs11-check test` should honor the repo-default disabled baseline by default.

An explicit opt-out flag should disable this behavior for full-truth runs, for
example:

- `--ignore-disabled-tests`

The default-on behavior matches the user's stated release/beta workflow. The
opt-out preserves access to the full suite.

Config may expose the default path, but the default file should be discoverable
without requiring extra per-user setup.

## Isolation-Mode Semantics

### `--isolation none`

Use the existing plugin deselection mechanism:

- write the exact nodeids to a temp file or point directly to the repo-default
  file if safe to do so
- set `PKCS11_CHECK_DESELECT_FILE`
- let `plugin.py:pytest_collection_modifyitems()` perform exact deselection

This path already matches exact nodeids only, which is exactly what phase 1
needs.

### `--isolation test`

Disabled nodeids must be removed before units are scheduled. Disabled tests
must never become subprocess units.

### `--isolation file`

Use collection metadata to determine disabled nodeids by file.

- fully-disabled files are never spawned
- mixed files receive a per-file deselect file
- subprocesses still execute only the non-disabled tests from that file

### `--isolation auto`

Same as file/test behavior above, plus adaptive isolation.

Important requirement:

- if a file escalates from file-level to test-level units, the newly created
  test units must still be filtered against the baseline

### Crash-Recovery / Iterative Deselect

If crash-recovery deselection is active, it must merge with the committed
baseline rather than replacing it. The release baseline remains in force during
all retries.

## Resume and State

The disabled baseline must be part of isolated-run fingerprinting.

If `config/disabled-tests.txt` changes, old resume state is stale and must be
rejected.

The internal cache directory:

- `.<state-file>.report-records/`

is an implementation detail. It may help tooling or recovery, but it must not
become the primary contract for baseline generation or runtime behavior.

## Artifact-Driven Baseline Generation

Phase 1 baseline generation happens offline.

Primary input:

- `artifacts/<provider>/report.jsonl`

Why:

- it preserves per-test nodeids for skipped, xfailed, xpassed, failed, passed,
  and setup-related records
- it is the only existing artifact that can reliably reconstruct large exact
  nodeid sets across outcome classes

Secondary input:

- `artifacts/<provider>/results.json`

Use only as fallback/helper:

- `results.json` is useful for summaries and for some non-passing test details
- it is not sufficient on its own to reconstruct the full skipped-test nodeid
  set

Not primary:

- `coverage.json` is aggregate mechanism/function coverage only
- `.<state-file>.report-records/` is internal cache output keyed by unit hash

## Helper Script

Add one offline helper:

- `scripts/generate-disabled-tests.py`

Responsibilities:

- scan `artifacts/*/report.jsonl`
- optionally allow provider selection
- optionally allow outcome selection such as `failed,error,crashed,timeout`,
  or any other classes the user wants to mine
- emit exact nodeids only
- write stable sorted output

Design principle:

- the helper is advisory
- the committed disabled file is authoritative

This separation lets the user manually add any nodeids they want, regardless of
how the helper chose candidates.

## Validation and Error Handling

### Runtime

- If default-on mode is active and the repo-default disabled file is missing,
  fail fast with a clear error and mention the opt-out flag.
- Ignore blank lines and comments.
- Deduplicate repeated nodeids silently.
- Do not emit noisy unmatched-nodeid warnings during normal runs. Partial runs,
  `-k`, `-m`, or explicit target selection make "unmatched" ambiguous.

### Helper / Lint Path

If stale-entry or unmatched-entry validation is wanted later, add it to the
offline helper or a dedicated lint command. Do not make normal test execution
pay that cost or noise penalty.

## Testing Strategy

Add meta-tests in `tests/` for:

- loader behavior for comments, blanks, duplicates, and missing-file handling
- default-on behavior
- opt-out behavior
- exact-match behavior for single parametrized variants
- `isolation=none` plugin deselection
- `isolation=test` removal before scheduling
- `isolation=file` mixed-file deselection and full-file suppression
- `isolation=auto` filtering plus escalated-unit preservation
- crash-recovery merge with baseline deselection
- resume-state invalidation when the baseline changes
- deselected tests counted as deselected, never skipped

Add helper tests for:

- extraction from synthetic `report.jsonl`
- fallback or summary behavior with `results.json`
- outcome filtering
- stable sorted output

## Future Extensions

These are explicitly deferred:

- target-specific overlay files
- runtime masks/patterns/markers
- runtime debug/invert mode
- automatic stale-entry cleanup in the main runner

When target-specific overlays are added later, they should be layered on top of
the same exact-nodeid runtime model instead of replacing it.

## Recommended File Set

Create:

- `docs/superpowers/specs/2026-03-31-production-disabled-baseline-design.md`
- `src/pkcs11_check/core/test_selection.py`
- `scripts/generate-disabled-tests.py`
- `tests/test_test_selection.py`

Modify:

- `src/pkcs11_check/cli/test_cmd.py`
- `src/pkcs11_check/plugin.py`
- `src/pkcs11_check/core/file_runner.py`
- optionally `pkcs11_check.toml` if the default path should be surfaced there

## Why This Replaces The Earlier Generic Draft

The earlier draft attempted to solve several later-phase concerns at once:

- runtime patterns and markers
- target overlays
- debug/invert mode
- broader selector semantics

That made the design too generic for the actual beta/release problem. Phase 1
should solve the narrow release need cleanly first, then expand later if still
necessary.
