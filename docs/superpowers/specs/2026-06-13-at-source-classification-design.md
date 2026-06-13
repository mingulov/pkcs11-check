# At-Source Test-Outcome Classification & Per-Provider Reporting — Design

- **Date:** 2026-06-13
- **Status:** Draft for review
- **Supersedes (for classification):** the post-hoc pipeline in
  `docs/superpowers/plans/2026-06-13-per-failure-triage.md` (extract → regex-group →
  auto-classify → manual deep-dive). That plan's `_index.md:102` already records the
  hand-off: *"remaining UNKNOWNs will be classified by a different (in-tool) workflow."*
  This is that workflow.
- **Builds on:** `docs/classification-model-design.md` (the pass/xfail/fail model and the
  A/B/C/D self-contradiction rules), the advertised-capability-honesty refinements, and
  the existing `compliance.py` + RV-trace `user_properties` plumbing.

## Problem

pkcs11-check runs a provider-general suite against many PKCS#11 modules and produces, per
provider, tens of thousands of `pass`/`xfail`/`fail`/`crash` outcomes. The information that
explains *why* a test failed — direction, expected vs. actual `CK_RV`, the spec basis, the
self-contradiction `kind`, the source vector — is **fully known at the moment the test
decides its outcome**, but it is flattened into a free-text string passed to
`pytest.xfail("…")` / `pytest.fail("…")` and thrown away.

A separate post-hoc pipeline then tries to *reconstruct* that structure with regex over the
message strings. It does not work well:

- **2,284 / 5,063 verdict records are `UNKNOWN`** and **605 have `direction=OTHER`** — ~3,000
  outcomes the regex could not classify.
- The two **CRITICAL** findings in the produced report are tagged `direction=OTHER` (they are
  bare `assert` KAT comparisons the regex cannot read).
- Reports are **lossy** (`signal N`, `RSA-N`, `CKR_OK` redacted for grouping) and **bloated**
  (347 KB for one provider), and they show opaque `sha1:…#ph` signatures to readers.

The fix is to classify **at the source**: the test (via shared helpers) records a structured
verdict where it already has the facts, the verdict rides to `report.jsonl` on the proven
`user_properties` channel, and the report becomes a trivial roll-up instead of a
regex-and-manual reverse-engineering loop.

## Goals & principles

1. **Observation in, verdict out.** A test site reports *what the module did* (the facts).
   One central function applies the `docs/classification-model-design.md` table to decide
   `outcome` / `severity` and calls pytest. A site cannot mis-set the fail-vs-xfail pivot.
2. **KISS / DRY.** One verdict function; one emission path (reuse `compliance.py`'s pattern);
   spec references in one central table; severity derived, never hand-typed per site.
3. **Provider-general.** No per-provider config, baselines, or allowlists. `xfail` remains the
   universal "noted deviation, investigate later" bucket. (Unchanged from the model doc.)
4. **The test emits facts + the model verdict; the report adds context.** A test cannot know
   if a deviation is a known issue, an upstream bug, or a harness artifact — those are
   cross-cutting judgments assigned at the report layer.
5. **Tiered, size-budgeted output.** On CI this is thousands of records; the human summary
   must stay readable and the machine artifact must be parseable.

## The classification model

Three small fields. Every fail/xfail emits all three; `kind` is optional for some reasons.

### `outcome` (3)

`pass` · `xfail` · `fail`. Must agree with pytest's own outcome (enforced — see Coverage gates).

### `reason` (9) — each maps to exactly one `outcome`

| `reason` | `outcome` | The module… |
|---|---|---|
| `wrong_result` | fail | returned success on valid input but the **output value is wrong** (crypto KAT mismatch, or a wrong non-crypto value) |
| `accepted_invalid` | fail | **accepted** invalid/forbidden input it must reject (forgery verifies, bad ciphertext decrypts, off-curve point derives, forbidden attribute combo created) |
| `self_contradiction` | fail | **claimed** a property/success then **violated or did not honor it** (claimed protection then leaked; reported success then no effect / no output; two attributes/interfaces that cannot both be true) |
| `oracle` | fail | rejected, but via a **distinguishable channel** (error code *or* timing) that leaks a secret |
| `crash` | fail | crashed, hung, or had to be killed (assigned runner-side) |
| `not_operational` | xfail | cleanly errored on an **advertised** positive op — advertised but not operational |
| `nonspec_reject` | xfail | rejected a negative op, but with a **non-spec (clean) code** |
| `honest_deviation` | xfail | left an **optional** protection unenforced, returned an **isolated** wrong metadata value, or performed a harmless no-op |
| `sanctioned_refusal` | pass | refused with `CKR_OPERATION_NOT_VALIDATED` (conformant validation-policy refusal) → pass + compliance note |

Because `reason → outcome` is fixed, the migration cannot accidentally flip a `fail` to an
`xfail`: choosing the wrong `reason` is a visible, reviewable error, and `derive_verdict`
enforces the mapping.

### `kind` (4) — the domain (replaces the A/B/C/D letters)

`crypto` · `policy` · `lifecycle` · `metadata`. This is a 1:1 alias for the model doc's
self-contradiction classes (A=crypto, B=policy, C=lifecycle, D=metadata; see
`classification-model-design.md:70`). The **letters are retired as the primary label** — they
mean nothing to a provider maintainer or a fresh agent — but the report renders the legacy
letter parenthetically for continuity, e.g. `self_contradiction · policy (Type B)`.

`kind` is **required** for `wrong_result`, `accepted_invalid`, and `self_contradiction` — it
selects severity and, for self-contradiction, names the broken invariant — and **optional** for
`crash` and the three xfail reasons, whose severity is flat.

### Severity — derived once from `(reason, kind)`

A single pure mapping (`derive_verdict`), unit-tested, the only place severity is decided:

| reason · kind | severity |
|---|---|
| `wrong_result` · crypto | CRITICAL |
| `wrong_result` · metadata | MEDIUM |
| `accepted_invalid` · crypto / policy | CRITICAL |
| `accepted_invalid` · lifecycle / metadata | HIGH |
| `self_contradiction` · crypto / policy | CRITICAL |
| `self_contradiction` · lifecycle / metadata | HIGH |
| `oracle` · crypto | HIGH *(report may annotate CRITICAL for a full decryption oracle, or SOFT_TOKEN_CAVEAT)* |
| `crash` | HIGH *(CRITICAL if it interrupts an otherwise-correct auth/op)* |
| `not_operational` | LOW |
| `nonspec_reject` | LOW |
| `honest_deviation` | LOW / INFO |
| `sanctioned_refusal` | INFO |

### The `Classification` record

Emitted into `user_properties` under key `pkcs11_classification`. `provider` and `nodeid`
already live on the pytest report and are **not** duplicated.

```jsonc
{
  "schema": 1,
  "outcome": "fail",                         // pass | xfail | fail
  "reason": "accepted_invalid",              // controlled vocab, 9 values
  "kind": "crypto",                          // crypto | policy | lifecycle | metadata | null
  "severity": "CRITICAL",                    // derived from (reason, kind)
  "summary": "invalid PKCS#1 v1.5 ciphertext decrypts (Bleichenbacher)",  // one human line
  "operation": "C_Decrypt",                  // C_* function, or null
  "mechanism": "CKM_RSA_PKCS",               // CKM_*, or null
  "expected_ckr": ["CKR_ENCRYPTED_DATA_INVALID"],  // or null
  "actual_ckr": "CKR_OK",                    // or null
  "spec_ref": "PKCS#11 v3.2 §2.1.8",         // from the central table; never fabricated
  "source": "wycheproof:rsa_pkcs1_2048_test.json",  // provenance, or null
  "vector_id": "tcId=45",                    // canonical upstream id, or null
  "detail": null                             // reason-specific extras (see below)
}
```

`detail` carries reason-specific specifics without new top-level fields:

- `oracle` → the leak channel and observed distribution, e.g. `{"channel": "error_code",
  "codes": {"CKR_ENCRYPTED_DATA_INVALID": 12, "CKR_FUNCTION_FAILED": 4}}` or
  `{"channel": "timing", "ratio": 3.2}`.
- `crash` → `{"signal": "SIGSEGV", "returncode": -11}` or `{"mode": "timeout"}` (runner-side).
- otherwise `null`.

**Not emitted at source** (assigned at the report layer): `category`
(`PROVIDER_BUG` / `HARNESS_BUG` / `KNOWN_ISSUE` / `UPSTREAM_BUG` / `SOFT_TOKEN_CAVEAT` /
`SPEC_AMBIGUITY`) and `routing`. A test cannot know these.

### Gap-analysis validation (whole-tree sweep, 2026-06-13)

Four parallel surveys (security/, ckr/+conformance, crypto-vectors, core-behavioral)
enumerated ~190 distinct failure modes. The model fit 87–96% cleanly per slice. Every
non-fit resolved to a clarification below — **no new reason was required beyond `oracle`.**

- **Timing side-channels** (Lucky13, Minerva, RSA-decrypt timing) → `oracle`; channel recorded
  in `detail`. Not a separate reason.
- **Crash subtypes** (SIGSEGV / SIGABRT / timeout / OOM) → `crash`; signal/mode in `detail`,
  taken from the runner's returncode. Not separate reasons.
- **"Advertised but the op refuses"** → `not_operational` (xfail). The
  advertised-capability-honesty model already adjudicated this; it is **not** a new
  `advertisement_mismatch` fail. Two *query* interfaces disagreeing (list says supported,
  `C_GetMechanismInfo` flags say no; a `CKO_PROFILE` claims a function it lacks) →
  `self_contradiction` · metadata.
- **"CKR_OK but no output written / op not terminated / IV not written back"** →
  `self_contradiction` · lifecycle ("reported success then did not honor it").
- **Wrong non-crypto value** (e.g. `pulSize` wrong after `CKR_BUFFER_TOO_SMALL`, wrong
  attribute default) → `wrong_result` · metadata (isolated) or `self_contradiction` · metadata
  (contradicts a second attribute).
- **Harness/binding-layer rejection** (the Python binding refused before the module ran; a KAT
  that can never pass) → **`skip`** with a reason in `detail`, never a provider finding. See
  "Harness artifacts" below.
- **Non-determinism** (valid-but-non-canonical RFC6979 `k`) → `honest_deviation`. A
  systematically wrong KAT across all providers is a report-layer verification concern, not a
  reason.
- **Resource/handle leaks** → out of scope **by design**, not merely untested. Leak and
  exhaustion analysis (memory, file descriptors, handle slots) belongs to an *external*
  observer (valgrind / ASan / `/proc` or RSS monitoring) for which **pkcs11-check is only the
  workload generator** — it is never a test-outcome `reason`. If such analysis is wanted, it is
  a separate tool wrapping a pkcs11-check run, not a change to this classifier.

### Special cases

- **Crashes are classified runner-side.** A segfaulted process cannot emit a `user_property`.
  `core/file_runner.py` already records `returncode < 0` and identifies the culprit
  (`_status_from_returncode` / `_identify_crash_culprit`). The report merges these crash
  records (as `reason=crash`, `detail.signal=…`) with the structured classifications from
  `report.jsonl`. This module's only crash change is to emit the merged record in the
  `Classification` shape.
- **Harness artifacts → `skip`.** When the test detects that *it* (not the module) could not
  stage the case — the binding rejected the parameters, a vector is unrepresentable — it emits
  `skip` with `detail={"harness": "<why>"}`. The report lists these in a separate
  "harness-staging skips" line, never as provider findings, and a meta-audit flags
  suspicious volumes. (This honors the model rule that `skip` is only for "cannot test".)
- **`xpassed` effectively disappears.** Imperative classification (`classify()` →
  `pytest.xfail`) fires only *after* the module's clean error is observed, so the xfail path is
  never reached when the op succeeds — it simply `pass`es. With the single remaining
  `@pytest.mark.xfail` decorator removed, there is no declarative-xfail source of `xpassed`, so
  the old Phase-3 xpassed audit is moot. Detecting "a recorded deviation became operational" is
  therefore a run-over-run **diff** concern (deferred; see Non-goals), not an outcome.

## Emission mechanism

Mirror `compliance.py` exactly — the proven path that already reaches `report.jsonl`:

- **New module `src/pkcs11_check/classification.py`** (sibling of `compliance.py`): a
  module-global list, `record(rec)`, `get_records()`, `clear()`, `serialize(...)`. Holds the
  records emitted during one test.
- **`derive_verdict(reason, kind) -> (outcome, severity)`** — the single source of truth for
  the model table. Pure, unit-tested.
- **A single emit API** that all sites funnel through, e.g.
  `classify(reason, *, kind=None, label, operation=None, mechanism=None, expected=None,
  actual=None, spec_ref=None, source=None, vector_id=None, summary=None, detail=None)`. It
  builds the record, calls `derive_verdict`, `record()`s it, then calls the right
  `pytest.fail/xfail` (or returns for pass). Thin convenience wrappers `xfail_as(reason, …)` /
  `fail_as(reason, …)` exist for readability but route through the same emit API.
  `label` matches the existing helpers' argument so their call sites are unchanged. `summary`
  **defaults to a template** built from `label`/`operation`/`mechanism`/`expected`/`actual`
  (e.g. `"{label}: expected {expected}, got {actual}"`); a site passes an explicit `summary`
  only for richer phrasing — so the 608-site migration carries no per-site prose burden.
- **The four existing helpers stay** (`classify_negative_rv`, `reject_or_classify`,
  `classify_policy_enforcement`, `classify_lifecycle_effect` in `testcases/conftest.py`) and
  become thin adapters: they already compute the branch; they now translate it to a `reason`
  and call `classify()`. **Their call signatures do not change**, so their ~21 call sites are
  untouched. `assert_ckr`/`CkrExpectation` (`testcases/ckr/_ckr_spec.py`, 121 sites) emit
  field-for-field (it already holds `function`, `condition`, `spec_ckr`, `spec_ref`, `kind`).
- **Plugin attach + clear.** In `plugin.py`'s `pytest_runtest_makereport`, attach
  `("pkcs11_classification", serialize(get_records()))` next to the existing compliance/rv-trace
  attaches; in the existing per-item teardown hook, `clear()` (exactly as `clear_notes()`).

`compliance` remains a **separate stream** (it annotates conformant behavior, usually on a
pass). The two are siblings, rendered in separate report sections.

## Coverage gates (what makes "big-bang" verifiable)

Two gates turn "we migrated everything" into an enforced invariant:

1. **Static gate** (meta-test in `tests/`): zero `pytest.xfail(` / `pytest.fail(` occurrences
   under `src/pkcs11_check/testcases/` outside the sanctioned modules
   (`classification.py`, `conftest.py`, `ckr/_ckr_spec.py`). This drives the **608 raw sites
   (276 fail + 332 xfail across 140 files)** to zero and prevents regressions permanently.
2. **Runtime gate** (`makereport`): any `fail`/`xfail` reaching the report **without** a
   classification gets a synthetic `reason="unclassified"` record auto-injected → the report is
   always 100% covered, and a meta-test asserts zero `unclassified`. The remaining
   `unclassified` count *is* the live migration backlog. (It inspects completed call-phase
   reports; a crashed unit has none and is instead covered by the runner-side crash merge.)

### Bare `assert`s — option A now, with KAT asserts prioritized

The 608 raw `xfail/fail` sites + the 121 `assert_ckr` sites are in scope now. The ~2,254 bare
`assert`s (mostly positive-op correctness) are **not** raw `xfail/fail` calls, so the static
gate does not cover them. They are handled by the runtime gate: a failing bare assert surfaces
as a counted `unclassified` record — visible backlog, never silent. They migrate to an
`assert_correct(...)` emitter (→ `wrong_result`/`accepted_invalid`) in a fast-follow.

**Exception (priority):** the **crypto KAT-comparison asserts** (`assert digest == expected`,
`assert derived == kat`) are exactly where the two real CRITICAL findings hid as `OTHER`. These
migrate **in this pass**, immediately after the raw-site sweep, via `assert_correct`.

## Provenance

Stamp `source` + `vector_id` onto each vector at the loader choke-points (DRY — one place per
suite), and have `classify()` read them through:

- **Wycheproof** — `wycheproof/wycheproof_loader.py::load_vectors()`. Carries upstream `tcId`;
  stamp `source=f"wycheproof:{filename}"`, `vector_id=f"tcId={tcId}"`.
- **ACVP** — `acvp/acvp_loader.py::load_acvp_vectors()` (+ per-suite helpers). Carries `tc_id`
  and `algorithm`; stamp likewise.
- **x509** — `load_limbo_testcases()` carries `id`; hand-written cert tests stamp the testdata
  filename best-effort.
- **CCTV** — per-file loaders; best-effort.

Where a loader does not stamp, `source`/`vector_id` are `null` and the report falls back to the
suite inferred from the nodeid path.

## Spec references

- **Standard = OASIS PKCS#11 v3.2** everywhere (the latest). Existing `CkrExpectation` refs say
  v3.1 and are migrated to v3.2 (section numbers differ between versions).
- **One central `spec_refs` table** keyed by `(function | mechanism | CKR-condition) → v3.2 §`.
  A site supplies `operation`/`mechanism`/`expected_ckr`; the table resolves `spec_ref`. No
  per-test hand-typing of paragraph numbers.
- **Never fabricate.** If the table has no precise §, the report cites the stable, reliable form
  `v3.2 · C_Decrypt · CKM_RSA_PKCS` and stops. The table can be cross-checked against the local
  v3.2 mirror at `/home/user/src/m/other/pkcs11/`.

## Output — three tiers, size-budgeted

| Tier | File | Granularity | Discipline |
|---|---|---|---|
| Human triage | `reports/<provider>.md` | grouped findings | **capped**: all CRITICAL/HIGH fails (top-N per group, "+N more → .jsonl"); MEDIUM/LOW + **all** xfails collapsed to one count-line per `(reason, kind)`. ~1 screen even at thousands. |
| Machine canonical | `reports/<provider>.jsonl` | one record **per group** | group key = readable tuple `test_file · reason · kind · mechanism · operation · expected · actual` + `count` + sample nodeids/vector_ids. Bounded. Convertible to CSV/SARIF later. |
| Raw | `report.jsonl` (pytest) | per-nodeid | already exists; ultimate drill-down |

- **Grouping is exact** (structured fields), so the report shows a **readable group key, never a
  `sha1`**.
- **`reports/_index.md`** — tiny: per-provider counts table + top themes + links.
- **`reports/_universal.md`** — cross-provider correlation (same `reason`+`kind`+`mechanism`
  across N providers). This is the highest-value output and is also the **harness safety net**:
  a finding that appears identically across all providers is flagged as a harness-bug candidate
  for verification (the "trust the test" check).
- **Compliance notes** render in their own section; **`unclassified`** and
  **harness-staging skips** each get a one-line meter.

Each per-provider `.md` follows the approved "compact enriched" layout: severity-first,
grouped by `kind`, exact values + `spec_ref` + provenance on a second indented line.

## Report-layer enrichment

Computed from the structured records (one shared module), not at source:

- **`category`** default `PROVIDER_BUG` for fails / "deviation" for xfails; re-tagged
  `KNOWN_ISSUE` by reconciling against `docs/module-issues.md` (matched on
  mechanism/operation/`kind`, not keyword regex); `SOFT_TOKEN_CAVEAT` annotated for the
  universal soft-token classes (e.g. padding oracles); `HARNESS_BUG` candidate from
  cross-provider correlation.
- **`routing`** derived from `category` (`PROVIDER_REPORT` / `HARNESS_FIX` / `DOCS_ONLY`).

## Components

- `src/pkcs11_check/classification.py` — record type, `record/get/clear/serialize`,
  `derive_verdict`, `classify()` + `xfail_as`/`fail_as`. *(new)*
- `src/pkcs11_check/spec_refs.py` — the central `(function|mechanism|CKR) → v3.2 §` table. *(new)*
- `src/pkcs11_check/plugin.py` — attach `pkcs11_classification`; runtime unclassified gate. *(edit)*
- `src/pkcs11_check/core/file_runner.py` — emit crash records in `Classification` shape. *(edit)*
- `src/pkcs11_check/testcases/conftest.py` — four helpers become `classify()` adapters;
  `assert_correct()` added. *(edit)*
- `src/pkcs11_check/testcases/ckr/_ckr_spec.py` — `assert_ckr` emits a `Classification`. *(edit)*
- `wycheproof/wycheproof_loader.py`, `acvp/acvp_loader.py`, x509 limbo loader — stamp
  provenance. *(edit)*
- The 608 raw sites across 140 files — migrate to `classify()`/`xfail_as`/`fail_as`. *(edit, bulk)*
- `tools/report/` (or `docs/findings/.../scripts/`) — the tiered report generator reading
  `report.jsonl`. *(new; replaces the regex `group.py`/`classify.py`/manual deep-dive)*
- `tests/` — `derive_verdict` unit tests; static + runtime gate meta-tests; a golden report test. *(new)*

## Testing strategy

- Unit-test `derive_verdict` over the full `(reason, kind)` matrix.
- Static gate meta-test (no raw `xfail/fail` outside sanctioned modules).
- Runtime gate meta-test (no `unclassified` records in a representative run).
- Golden test: a fixed small `report.jsonl` → expected `.md` + `.jsonl` (locks format + size
  budget).
- Spec-ref table meta-test: every referenced § resolves against the local v3.2 mirror.

## What this retires

- The regex `group.py` (direction heuristic), `classify.py` `AUTO_RULES`, Phase 6 manual
  deep-dive, the `UNKNOWN`/`OTHER` buckets, and opaque `sha1` signatures.
- `reconcile.py` (KNOWN_ISSUE) and `correlate.py` (cross-provider) survive in spirit but read
  structured fields.

## Non-goals / deferred

- Resource-leak / nondeterminism test families (no driver today).
- SARIF/CSV converters off `<provider>.jsonl` (trivial later if CI tooling wants them).
- Run-over-run regression diffing of reports.
- Migrating the full ~2,254 bare-assert tail beyond the prioritized crypto-KAT subset (fast-follow).

## Open questions

- Final home of the report generator: `tools/report/` vs. the existing
  `docs/findings/per-failure-triage/scripts/`. (Leaning `tools/report/` since it is now a
  product feature, not a one-off analysis.)
- Whether `assert_ckr`'s strict vs. compat modes both survive once everything emits a
  `Classification`, or strict folds into the same path. (Decide during implementation Phase 1.)
