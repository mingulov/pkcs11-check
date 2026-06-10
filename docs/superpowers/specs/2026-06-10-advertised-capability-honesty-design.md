# Advertised-capability honesty package — design

Date: 2026-06-10. Status: approved by Denis (brainstorming session).
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
  (callers get a clean error and can fall back) → not a Type B/C/D self-contradiction.
- The "separate test" is the existing `test_mech_*` registry layer; this package
  strengthens it rather than adding a parallel one (approach A, chosen over a dedicated
  `test_capability_claims.py` (B) and report-layer-only aggregation (C)).

Denis decisions, 2026-06-10: severity = capability dishonesty → xfail;
`CKR_OPERATION_NOT_VALIDATED` refusal in the claim test → pass + `compliance.note`;
scope = full coherence package; KAT vectors stay **xfail** even under sanctioned refusal
(the claim-layer test is the analytical verdict; per-vector xfails are corroborating
evidence for later analysis, recorded not hidden).

## Components

### 1. Probe result carries the refusal RV (`testcases/_operability.py`)

`OperabilityResult` gains `rv: int | None = None` — the canonical operation's refusal
code when the verdict is `NOT_OPERATIONAL` (None otherwise / when not applicable). No new
enum state; `classify_kat_clean_error` behavior is unchanged for KAT consumers
(sanctioned-ness only matters at the claim layer). Probe sites populate `rv` from the
canonical `CkrAssertionError`.

KAT vectors on a sanctioned-refusing mechanism still xfail, with the sanctioned code
named in the message.

### 2. Claim-layer 3-way mapping (`test_mech_*` registry suites)

The per-(mechanism, operation) registry tests classify the canonical probe verdict:

| Canonical outcome | Verdict |
|---|---|
| OPERATIONAL (correct output) | pass |
| clean refusal, `rv == CKR_OPERATION_NOT_VALIDATED` | **pass** + `compliance.note` ("validation-policy refusal via sanctioned code"; the note records whether the token exposes `CKO_VALIDATION` objects — capability-based enrichment, no provider identity) |
| clean refusal, any other code | xfail with the shared not-operational reason (component 3) |
| WRONG_OUTPUT / crash / non-CKR | fail / propagate |

Nothing weakens Type A–D; crashes and wrong output stay hard fails everywhere.

### 3. Shared probe-key reason constant

New helper `not_operational_reason(probe_key, detail)` in `_operability.py` producing the
canonical wording (`"{probe_key}: advertised but not operational ({detail})"`). The ~18
scattered "advertised but …" message sites that have a probe key route through it so
report readers can group the single per-(mech,op) claim signal with its corroborating
per-vector xfails. Sites without a probe key (one-off helpers) keep their wording.

### 4. Coverage meta-check (new test alongside `test_mech_probe.py`)

Computes advertised (mechanism, operation) pairs from `C_GetMechanismList` ×
`C_GetMechanismInfo` flags, diffs against the mechanism registry
(`mechanism_helpers.py` / `mechanism_registry/`), and emits one `compliance.note` per
advertised-but-unprobed pair. The test **passes** — a registry blind spot is a harness
gap made visible, not a module deviation. Closes gap-analysis Q2 gap #1.

### 5. Vacuous-reject downgrade (Denis-endorsed; gap-analysis leak 1)

In the probe-wired runners — `base_runner_aead`, `acvp/aes/test_wrap`, `base_cts`,
`test_xts`, `wycheproof_aes`, ACVP SigVer probe, PSS combo — when the canonical verdict
for the (mechanism, direction) is `NOT_OPERATIONAL`, negative-vector rejections classify
as `xfail` "vacuous reject — mechanism not operational, input never evaluated" instead of
`pass`. Operational mechanisms untouched (probe gates the downgrade); crashes still fail;
`INCONCLUSIVE` keeps legacy rules.

Expected honest count shift: tpm2 ~135 SHA-1 SigVer passes→xfail; bouncyhsm CCM thousands
of invalid-vector passes→xfail.

## Out of scope

- Import-skip→xfail audit (32 `pytest.skip("Cannot import …")` sites) — separate queue
  item (gap-analysis leak 2), not part of this package.
- Mechanism-registry Phases B–D (registry completeness itself) — the meta-check makes the
  blind spots visible; filling them is the longer arc.

## Testing

TDD meta-tests first (RED before implementation), in `tests/`:

1. Sanctioned-RV pass mapping: fake probe returning NOT_OPERATIONAL with
   `rv=CKR_OPERATION_NOT_VALIDATED` vs `rv=CKR_DEVICE_ERROR` → pass+note vs xfail.
2. `OperabilityResult.rv` population from the canonical CkrAssertionError.
3. Vacuous-reject downgrade per wired runner (NOT_OPERATIONAL → negative reject xfails;
   OPERATIONAL → negative reject still passes; crash still fails).
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
