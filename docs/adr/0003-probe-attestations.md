# ADR 0003: Per-worker probe attestations bind digests to publications

Status: accepted (shipped in 0.3.2).

## Context

Crash recovery must re-establish which probe evidence a publication
covers without re-guessing it. Volume cover alone cannot tie a
replacement publication version to the evidence it claims.

## Decision

At session emission the counters plugin appends one attestation record
per worker (`attestations-<worker>.jsonl` in the counters directory):
run id, worker uuid, the session publication digest, and per folded
probe its worker uuid, probe sequence, and digest. Collection binds an
adjudicated digest to a receipt the winning publication claims;
persisted entries carry the authorizing receipt set plus canonical
identity, so a retry re-establishes authority by identity match while
a replacement converges only under strict scope agreement plus full
cover. A missing winner or report holds, never proceeds. Attestation
writes never raise: I/O or shape failures warn and skip.

## Consequences

- Retries converge without re-guessing; replacements cannot silently
  adopt foreign evidence.
- Attestation files are small append-only JSONL beside the sidecars;
  collectors must tolerate missing or malformed ones (warn-only, hold
  instead of converge).
