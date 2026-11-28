# ADR 0001: Default counter flush cadence K=20

Status: accepted (shipped in 0.3.2).

## Context

Call counters persist a sidecar snapshot every K evidence units (one
unit per recorded call entry, call return, or zero-call mutation;
ingests add their row counts).
Per-call persistence (K=1) costs about 100 microseconds per call,
which multiplies into hours on call-dense runs (measured on a
call-dense KAT suite: tens of minutes at K=1 on early versions,
past an hour once counting grew). K=1 remains the right choice
for crash forensics, where the last calls before death are themselves
evidence reconciled against an external tracer.

## Decision

The default is K=20: snapshots batch about twenty counter updates
(roughly ten calls). A crashed run can lose up to 19 unflushed tail
units, always flagged incomplete, never silently exact. K=1 stays
available per run through `PKCS11_CHECK_COUNTERS_FLUSH_K` for crash
forensics. Garbage knob values fall back to literal 1: a knob typo
must err toward more evidence, never less.

## Consequences

- Call-dense runs finish much faster; finished runs keep exact totals.
- Crash forensics against an external tracer must set K=1 explicitly;
  the tracer guide documents this.
- Behavior tests stay pinned to K=1 through the shared fixture, so the
  exactness contract is tested at the strictest cadence; one dedicated
  test covers the K>1 crash shape (flushed window plus memory-only
  unit yields the exact partial plus a killed-lost record).
