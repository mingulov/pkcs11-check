# Round evidence toolkit (status and honest scope)

Small repo-side toolkit for gating CI provider rounds. It ships in the
package, but it currently has **no active CI consumer**: end-to-end
release-job wiring (E5) waits on p11lab publishing `checker-round.yml`.
Until then the toolkit is diagnostic-only — useful for local
experimentation, not enforcing anything.

## Commands

- `pkcs11-check evidence-export <report.jsonl> <ledger.jsonl>` — fold one
  lane's raw report stream into a canonical `ledger.jsonl`, stamping the
  lane/provider identity headers (`--lane/--lane-os/--lane-arch`,
  `--framework-sha`, `--p11lab-sha`, `--image-digest`). See
  `evidence-export --help` for the full option list.
- `pkcs11-check evidence-admit <ledger.jsonl> --roster <roster.json>
  --obligations <catalog.json>` — admit a lane ledger against its
  predeclared roster and obligation inventory (`summary` or `json` output).
- `pkcs11-check evidence-compare <baseline.jsonl> <candidate.jsonl>` —
  compare two ledgers for one lane under rotation deltas, with quorum
  repeats (`--quorum-min-repeats`, `--quorum-frac`).

## Receipt checks: what `verify_round_receipt.py` actually verifies

`scripts/verify_round_receipt.py <receipt.json> --lock <lock.json>
--expect-fw <sha>` checks the receipt's **file shape and linkage only**:

- required fields present with the pinned shapes (64-hex digests,
  non-empty identities, non-empty lanes object, lock-pin equality);
- `bundle_identity` recomputed from the lane digests listed *in the
  receipt itself* (bundle binding).

It deliberately performs **no artifact I/O**: it never downloads a
`ledger.jsonl` and never recomputes an `evidence_digest` from ledger
bytes. A receipt whose digests don't match the uploaded artifacts still
passes as long as the shapes and the binding are self-consistent.
Ledger-byte recomputation enforcement is E5 release-job wiring and does
not exist yet. See the script's own docstring for the pinned contract.

## Relationship to the 0.3.0 changelog

The `[0.3.0]` changelog entry lists "receipt verification" among the
shipped toolkit. Read that entry with this page: what shipped verifies
shape and linkage, not recorded digests. The `[0.3.1]` entry carries the
qualified wording.
