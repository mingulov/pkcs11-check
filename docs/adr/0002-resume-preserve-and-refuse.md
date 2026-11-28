# ADR 0002: Resume preserves prior results; foreign state is refused aside

Status: accepted (shipped in 0.3.2).

## Context

Resume startup-check failures (manifest preflight, login probe crash or
timeout) used to overwrite `results.json` and `report.jsonl`,
discarding the prior run's evidence. Resuming another provider's state
merged foreign evidence into the current report without marking it.

## Decision

- On resume with loadable state, a startup failure is appended, not
  overwritten: units, results, and observations merge, the evidence
  blob appends to the JSONL, and counters re-fold from the appended
  JSONL (the JSONL stays the counters source). Resume-without-state
  and fresh runs keep their exact old shape; exit codes are untouched.
- A resume pointed at a different module's state is refused: the prior
  summary is kept, and the refusal summary lands beside it as
  `<stem>.refused<suffix>` (JSON output only), deterministically, so
  automation can find it. The quarantine helper fails closed on
  unknown boundaries.
- States saved before the module snapshot existed cannot tell modules
  apart until one unit completes; they merge as before (documented in
  the changelog known limitations).

## Consequences

- Operators never lose a prior report to a failed resume; refusals are
  visible and machine-findable instead of silent merges.
- Resume output shape depends on history by design; tooling that reads
  prior summaries must tolerate the appended failure entry and the
  sidecar refusal file.
