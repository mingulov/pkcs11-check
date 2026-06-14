# Advertised-capability honesty package — design

Date: 2026-06-10. Status: approved by Denis (brainstorming session); revised after code
review (claim-layer mechanism corrected, model-doc amendments and probe preconditions added).
Supersedes the open question from `docs/findings/advertised-not-operational-gap-analysis.md`
("should advertised-but-not-operational be fail? a separate test? FIPS-only?").

## Resolved classification question (decision record)

**Advertised-but-not-operational classifies as `xfail`, not `fail`.** Spec basis (OASIS
PKCS#11 v3.2, local mirror):

- `C_GetMechanismList` returns "mechanism types **supported** by a token";
  `CK_MECHANISM_INFO.flags` makes the claim per-operation (`CKF_SIGN` = "True if the
  mechanism can be used with `C_SignInit`"). Advertising + refusing every use contradicts
  the token's own metadata.
- The spec sanctions refusal channels: `CKR_MECHANISM_INVALID` ("the mechanism specified
  cannot be used in the selected token with the selected function") and, in v3.2,
  `CKR_OPERATION_NOT_VALIDATED` ("the requested operation violates one or more of the
  token's validation policies") with `CKO_VALIDATION` objects to declare the policy.
- Therefore the deviation lives in the **metadata / error code** (over-advertisement, or
  `CKR_DEVICE_ERROR` instead of a sanctioned code), while the refusal itself is the right
  direction (safe, honest — e.g. FIPS *requires* refusing SHA-1 sign). Under the model's
  pivot ("right thing done imperfectly = xfail"), this is xfail. No security consequence
  (callers get a clean error and can fall back) → not a policy/lifecycle/metadata self-contradiction.
- **Why only `CKR_OPERATION_NOT_VALIDATED` earns pass+note, not `CKR_MECHANISM_INVALID`:**
  an *advertised* mechanism refusing with "cannot be used in the selected token with the
  selected function" contradicts the advertisement itself (self-inconsistent metadata
  pair) — that stays xfail. A policy refusal does not contradict the advertisement: the
  capability exists, policy forbids the operation, and v3.2 defines exactly this code for
  exactly this case.
- **Known conservatism:** the v3.2 text continues "Tokens may choose to return a more
  specific error (like CKR_ATTRIBUTE_VALUE_INVALID or CKR_DATA_LEN_RANGE)" — so a policy
  refusal via another code is also spec-blessed. We deliberately give pass+note only to
  `CKR_OPERATION_NOT_VALIDATED`, because any other code is indistinguishable from
  breakage without provider knowledge; those remain the recorded xfail.
- The "separate test" is the existing `test_mech_*` registry layer; this package
  strengthens it rather than adding a parallel one (approach A, chosen over a dedicated
  `test_capability_claims.py` (B) and report-layer-only aggregation (C)).

Denis decisions, 2026-06-10: severity = capability dishonesty → xfail;
`CKR_OPERATION_NOT_VALIDATED` refusal in the claim test → pass + `compliance.note`
(rv alone suffices — the note *records* whether the token exposes `CKO_VALIDATION`
objects but does not require one; the stricter pass-only-with-declared-validation option
was offered and not chosen); scope = full coherence package; KAT vectors stay **xfail**
even under sanctioned refusal (the claim-layer test is the analytical verdict; per-vector
xfails are corroborating evidence for later analysis, recorded not hidden).

## Components

### 1. Claim-layer 3-way mapping (`test_mech_*` registry suites)

The `test_mech_*` suites do not use `_operability.py` probes; their per-(mechanism,
operation) **roundtrip is itself the canonical operation**, and the refusal code is
already available as `exc.rv` on the `CkrAssertionError`. No new probe layer and no
`OperabilityResult` change is needed. The suites classify the roundtrip outcome:

| Roundtrip outcome | Verdict |
|---|---|
| OK + correct output | pass |
| clean refusal, `exc.rv == CKR_OPERATION_NOT_VALIDATED` | **pass** + `compliance.note(level=STANDARD)` ("validation-policy refusal via sanctioned code"; the note records whether the token exposes `CKO_VALIDATION` objects — capability-based enrichment, no provider identity) |
| clean refusal, any other code | xfail with the shared not-operational reason (component 2) |
| OK + wrong output / crash / non-CKR | fail / propagate |

**This retires the claim-layer per-CKR runtime-reject allowlists**
(`_SIGN_RUNTIME_REJECT_RVS`, `_ENCRYPT_RUNTIME_REJECT_RVS`, …): today an unlisted clean
code mid-roundtrip hard-fails; under the table it xfails. That is the model's positive-op
row applied with the roundtrip as canonical evidence — the same "no CKR allowlist"
rationale `_operability.py` already established — and at these sites it supersedes the
CLAUDE.md "every CKR check must list SPECIFIC acceptable return codes" rule (which
remains in force for negative-op assertions). Scope boundary: the table covers the
canonical operation itself; **setup-stage** refusals (key generation/import for the
roundtrip) keep their existing helpers and verdicts.

(Considered and deferred: routing the roundtrip outcome through `probe_operability` so
the claim layer and KAT runners share one cache and probe keys. Not required for this
package; revisit if cross-suite verdict reuse becomes useful.)

### 2. Shared probe-key reason constant

New helper `not_operational_reason(probe_key, detail)` in `_operability.py` producing the
canonical wording (`"{probe_key}: advertised but not operational ({detail})"`). The ~20
probe-keyed "advertised but …" message sites route through it; `test_mech_*` derives the
same probe-key format from (mechanism, operation) names without using the probe cache, so
report readers can group the single per-(mech,op) claim signal with its corroborating
per-vector xfails. Sites without a probe key (one-off helpers) keep their wording.

### 3. Coverage meta-check (new test alongside `test_mech_probe.py`)

Computes advertised (mechanism, operation) pairs from `C_GetMechanismList` ×
`C_GetMechanismInfo` flags, diffs against the mechanism registry (via
`MechanismCatalog.filter_unregistered`), and emits one `compliance.note` per
advertised-but-unregistered pair. Registration is what's checked — scenario-level
deselection does not count as a blind spot. The test **passes** — a registry blind spot
is a harness gap made visible, not a module deviation. Closes gap-analysis Q2 gap #1.

### 4. Vacuous-reject downgrade (Denis-endorsed; gap-analysis leak 1)

In the probe-wired runners — `base_runner_aead`, `acvp/aes/test_wrap`, `base_cts`,
`test_xts`, `wycheproof_aes`, ACVP SigVer probe, PSS combo — when the canonical verdict
for the (mechanism, direction) is `NOT_OPERATIONAL`, negative-vector rejections classify
as `xfail` "vacuous reject — mechanism not operational, input never evaluated" instead of
`pass`. Operational mechanisms untouched (probe gates the downgrade); crashes still fail;
`INCONCLUSIVE` keeps legacy rules.

**Precondition:** `_pkcs15_sigver_operational` (acvp/test_acvp_rsa.py) and
`_pss_combo_operational` (test_wycheproof_rsa_pss.py) currently return `bool`, collapsing
canonical **staging** failure (key import/keygen refused) into "not operational". Before
wiring the downgrade into them, upgrade both to three-state (NOT_OPERATIONAL /
OPERATIONAL / INCONCLUSIVE, e.g. return `OperabilityResult`) so staging failures are
INCONCLUSIVE and never trigger the vacuous downgrade.

Expected honest count shift: tpm2 ~135 SHA-1 SigVer passes→xfail; bouncyhsm CCM thousands
of invalid-vector passes→xfail.

### 5. Classification-model doc amendments (same change, not after)

Component 1 carves a pass out of the positive-op xfail cell (sanctioned policy refusal)
and component 4 refines the negative-op pass cell (vacuous reject → xfail). Amend in the
same merge so the ONE RULE stays consistent with shipped behavior:

- CLAUDE.md classification table: footnote the two refinements.
- `docs/classification-model-design.md`: add the sanctioned-refusal pass row and the
  vacuous-reject rule with the spec citations above.

## Out of scope

- Import-skip→xfail audit (32 `pytest.skip("Cannot import …")` sites) — separate queue
  item (gap-analysis leak 2), not part of this package.
- Mechanism-registry Phases B–D (registry completeness itself) — the meta-check makes the
  blind spots visible; filling them is the longer arc.

## Testing

TDD meta-tests first (RED before implementation), in `tests/`:

1. Claim-layer mapping: fake roundtrip refusals with `rv=CKR_OPERATION_NOT_VALIDATED` vs
   `rv=CKR_DEVICE_ERROR` → pass+note vs xfail; allowlist retirement pinned (previously
   unlisted clean code now xfails, wrong output still fails).
2. Three-state upgrade of the SigVer/PSS probes: staging failure → INCONCLUSIVE (legacy
   rules), canonical refusal → NOT_OPERATIONAL, canonical OK → OPERATIONAL.
3. Vacuous-reject downgrade per wired runner (NOT_OPERATIONAL → negative reject xfails;
   OPERATIONAL → negative reject still passes; crash still fails; INCONCLUSIVE → legacy).
4. Coverage meta-check against a synthetic mechanism list / registry diff.
5. Reason-constant linkage (claim-layer xfail and KAT xfail share the probe key).

CI gates: `ruff format --check`, `ruff check`, `mypy --strict`, meta-test suite (full
gate set per `feedback_ci_gates`).

Docker fresh-verify (targeted, `bash docker/test.sh <provider> -- <file>`):

- kryoptic-fips: likely refuses with `CKR_DEVICE_ERROR`, not the sanctioned code → claim
  test stays xfail, proving the discrimination works both ways.
- tpm2 ACVP SigVer: 135 vacuous passes → xfail.
- bouncyhsm CCM, wolfpkcs11 CTS: vacuous invalid-vector passes → xfail; the 1,691 genuine
  CCM fails must remain fails.
- Controls: softhsm2 / kryoptic / opencryptoki byte-identical (operational mechanisms —
  downgrade never triggers).
