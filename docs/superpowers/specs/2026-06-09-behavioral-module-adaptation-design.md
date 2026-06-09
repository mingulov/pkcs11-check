# Behavioral module adaptation — design

**Status:** design (2026-06-09)

**Goal:** Remove all provider-identity knowledge from pkcs11-check core. Replace the
per-module CKR-quirk registry with two runtime mechanisms that adapt to whatever the
live module actually does — never to *which* module it is — without ever hiding a real
error behind a "known-issue" decision.

**Core value (the rule everything below serves):** *Show real errors. Never convert a
deviation into a green pass via a per-module/known-code decision.* The thing that hides
real errors is any mechanism of the form "accept code X as OK for module Y." We delete
that mechanism and do not replace it with a smarter version of the same (no calibration,
no CKR-acceptance config).

---

## 1. Problem & gap analysis

Two genuinely different situations hide under "modules disagree":

- **Opposite *requirements* (input side).** The module tells you, via a clean reject,
  that your request *shape* is wrong, and there is a spec-equivalent request it will
  accept. Example: AES-KEY-WRAP unwrap into a generic secret — NSS *requires*
  `CKA_VALUE_LEN`; softhsm2/opencryptoki *reject* it as `CKR_ATTRIBUTE_READ_ONLY`. The
  module's own response disambiguates → adapt **generally, no identity**.
- **Opposite *responses* (output side).** The module returns a wrong-but-clean CKR for a
  negative test. Example: kryoptic returns `CKR_DEVICE_ERROR` for *any* verify/integrity
  failure; softhsm2 returns `CKR_GENERAL_ERROR` for an undersized wrap key. These codes
  are **catch-alls** — accepting them as "the expected reject" is exactly what risks
  hiding a real error.

**Current state.** Provider identity lives in exactly one place:
`src/pkcs11_check/testcases/_module_quirks.py` — a `ModuleId` enum, `detect_module()`
(library-path string matching), and a `MODULE_QUIRKS` table of **3 quirks**:

| quirk key | module | what it accepts | class |
|---|---|---|---|
| `verify_or_integrity_failure` | kryoptic | `CKR_DEVICE_ERROR` on verify/AEAD/ICV reject | opposite response (catch-all) |
| `unwrap_template_class_keytype_rejected` | opencryptoki | `CKR_ATTRIBUTE_READ_ONLY` on CKA_CLASS/KEY_TYPE in unwrap template | opposite requirement |
| `size_range_on_wrap` | softhsm2 | `CKR_GENERAL_ERROR` on undersized wrap key | opposite response (catch-all) |

**Consumers (the entire identity surface — ~7 call sites):**
- `conftest.py` `unwrap_key_for_mechanism_roundtrip` → `unwrap_template_class_keytype_rejected`
  (a *positive* roundtrip; retries without CKA_CLASS/KEY_TYPE).
- `test_authenticated_wrap.py` (3 sites) → `verify_or_integrity_failure` +
  `unwrap_template_class_keytype_rejected` (bit-flip / forgery *discrimination* tests).
- `security/test_tookan.py` → `unwrap_template_class_keytype_rejected` (type-confusion reject).
- `ckr/test_ckr_wrap.py` → `size_range_on_wrap` (undersized-wrap reject).

`p11_config.module` is inspected **only** in `_module_quirks.py:66`. There is no other
provider-identity branching in the codebase. So de-identification is fully contained.

The consumer sites already use the 3-way classifier (`reject_or_classify`) but **splice
the module's wrong code into the accepted-CKR list** to force a pass. Removing that splice
is the heart of the migration.

---

## 2. Architecture — two runtime mechanisms + a deletion

### Pillar 1 — Request negotiation (input side)

A reusable helper that tries an ordered list of **spec-equivalent request variants**
against the live module and returns the first one it accepts, recording which won.

```python
def negotiate_request(
    attempt: Callable[[Mapping[int, Any]], T],   # runs the op with a template/param delta
    variants: Sequence[Mapping[int, Any]],        # ordered deltas; variants[0] = minimal
    *,
    shape_reject_rvs: tuple[int, ...] = TEMPLATE_SHAPE_REJECTS,
    label: str,
) -> tuple[T, int]:                               # (result, winning-variant-index)
```

Behaviour and **hard guards**:
- Try `variants[0]` first (the minimal/canonical request). Lenient modules succeed here
  and never retry.
- Retry the next variant **only** when the failure is a clean *shape* reject
  (`TEMPLATE_INCOMPLETE/INCONSISTENT`, `ATTRIBUTE_READ_ONLY/TYPE_INVALID/VALUE_INVALID`).
- Any **non-shape** rejection (e.g. an integrity failure) propagates immediately — it is
  not a request-shape problem, so it must reach normal classification. **Forgery
  detection is never swallowed by negotiation.**
- **Positive operations only.** Negotiation is invoked with valid inputs. It is never
  applied to a forged/invalid input — restating a length/shape for a forged blob could
  let a module recover a wrongly-sized object and "accept" material it should reject.
  (This is the bug found and fixed during the AES-KW work.)
- The caller **verifies the produced result** (recovered key material / output) after a
  successful negotiation. A wrong result is a `fail`, not a pass.
- If *every* variant is cleanly rejected → the caller classifies it as an operational
  deviation (`xfail`), not a fail.

`negotiate_request` consults **no module identity** — only the CKR the module just
returned. It generalises the AES-KW adaptive unwrap (already shipped) and the
opencryptoki CKA_CLASS/KEY_TYPE retry. Variants may be **template deltas** or
**mechanism-param deltas** (e.g. explicit `CK_EDDSA_PARAMS` vs NULL), so it covers the
param-form disagreements too. Mechanism *aliases* are out of scope until a real case
needs them (YAGNI).

### Pillar 2 — Outcome-based classification (output side)

For negative tests whose point is a **security/crypto effect** (forgery rejected,
tampering detected, dangerous op refused), the verdict depends on **what the module did,
not which code it named**:

```python
def classify_discrimination(
    *, valid_accepted: bool, invalid_rejected: bool, label: str
) -> None:
    # valid_accepted and invalid_rejected -> pass  (module discriminated correctly)
    # not invalid_rejected (forged/invalid ACCEPTED) -> fail  (real crypto break)
    # not valid_accepted (cannot do the valid case) -> fail   (positive leg broken)
```

- `invalid_rejected` is **true for any clean rejection** — `DEVICE_ERROR`,
  `GENERAL_ERROR`, `ENCRYPTED_DATA_INVALID`, `WRAPPED_KEY_INVALID`, … are all equally
  acceptable, because the test is "did it refuse the bad input," not "did it name the
  refusal." A crash still `fail`s (caught by the isolation runner). A *capability*
  absence (mechanism not supported) `skip`s, established before the discrimination check.
- This is the direct answer to the catch-all-code worry: **we stop interpreting the
  catch-all code entirely.** There is no "accept `DEVICE_ERROR`" decision to hide a real
  error behind — a real error is the *accepted* tampered input (`fail`) or the broken
  valid leg (`fail`).
- **Discrimination requires both legs.** A test that only attempts the invalid leg cannot
  tell "rejected because it detected tampering" from "rejected because it can't do the op
  at all." Each migrated site must establish the **valid leg** (the un-tampered
  input is accepted) so a vague reject code cannot mask a non-checking module. Where a
  site lacks a valid leg, add it (small, local).

For negative tests that are genuinely about **code conformance** (the spec mandates a
*specific* CKR for a specific bad input — e.g. `C_GenerateKey(bad size)` →
`CKR_ATTRIBUTE_VALUE_INVALID`), keep the existing 3-way classifier
(`classify_negative_rv` / `reject_or_classify` / `assert_ckr`): expected code → pass,
other clean code → **xfail** (recorded deviation), `CKR_OK`/crash → fail. These already
behave provider-generally; they only need the `*quirk_extras(...)` splices removed.

### Pillar 3 — Delete `_module_quirks.py`

Remove `ModuleId`, `detect_module`, `MODULE_QUIRKS`, `quirk_extras`, `known_quirk_keys`,
and the `tests/test_module_quirks.py` meta-test. No code asks "which module is this."

### Explicitly excluded (and why)

- **Runtime CKR "calibration"** (probe known-bad, learn the module's reject code, then
  accept it everywhere): rejected. It *automates* "accept whatever code the module
  returned," which is the masking we are removing — and a catch-all like `DEVICE_ERROR`
  would let a genuinely-broken `DEVICE_ERROR` through. Outcome classification (Pillar 2)
  achieves the goal — correct modules pass — without ever trusting a code.
- **External CKR-acceptance config** (operator declares "code X is OK for my module"):
  rejected for the same reason. The only external config that stays is the *vendor
  mechanism map* (naming unknown mechanisms) — a non-masking purpose, specified
  separately.

---

## 3. Migration map (per site)

| site | mechanism | change |
|---|---|---|
| `conftest.py` `unwrap_key_for_mechanism_roundtrip` | Pillar 1 | retry-without-CKA_CLASS/KEY_TYPE gated on a clean **shape reject** (behaviour), not `quirk_extras`. Add optional `value_len` negotiation too if needed. |
| `test_authenticated_wrap.py` bit-flip / forgery unwrap | Pillar 2 (discrimination) | establish the valid-unwrap leg; assert the bit-flipped unwrap is rejected (any clean error / no usable key) → `classify_discrimination`. Drop both `*quirk_extras(...)` splices. |
| `test_authenticated_wrap.py` `_aead_integrity_reject_rvs` | Pillar 2 (discrimination) | replace the reject-RV set + quirk with an outcome check on the AEAD tag (valid decrypts, tampered rejected). |
| `security/test_tookan.py` type-confusion unwrap | Pillar 2 (discrimination) | assert the type-confused unwrap is rejected (any clean error) → drop quirk. |
| `ckr/test_ckr_wrap.py` undersized wrap | Pillar 2 (discrimination) | assert the undersized key produces **no wrap output** (refused, any clean code) → drop quirk. Keep the `--ckr-strict` path strict if present. |

Each migration is verified on the module that motivated the quirk (kryoptic / opencryptoki
/ softhsm2) via `docker/test.sh <module> -- <path>` plus a lenient module (softhsm2) for
no-regression. Expected: the previously-quirked module now **passes** (it does discriminate),
with no module-identity code involved.

---

## 4. Files

- **New:** `src/pkcs11_check/testcases/_negotiation.py` — `negotiate_request` +
  `TEMPLATE_SHAPE_REJECTS`. (Or fold into `conftest.py` if it stays small.)
- **New helper in `conftest.py`:** `classify_discrimination(...)` (sibling of
  `classify_policy_enforcement` / `classify_lifecycle_effect`).
- **Modify:** `conftest.py` (`unwrap_key_for_mechanism_roundtrip`),
  `test_authenticated_wrap.py`, `security/test_tookan.py`, `ckr/test_ckr_wrap.py`,
  `wycheproof/test_wycheproof_aes.py` (refactor the shipped adaptive unwrap onto
  `negotiate_request`).
- **Delete:** `src/pkcs11_check/testcases/_module_quirks.py`, `tests/test_module_quirks.py`.
- **Docs:** `docs/module-issues.md` — keep the *behavioural* notes (what each module does)
  but remove any implication that the harness keys off identity.

## 5. Testing

- **Meta-tests (no module):** unit-test `negotiate_request` (minimal-first; retries only on
  shape rejects; never on non-shape rejects; positive-only) and `classify_discrimination`
  (pass/fail/edge table). Replace the deleted quirk meta-test with a **guard meta-test**
  that greps the codebase for any reintroduced provider-identity branching (`detect_module`,
  library-name string matching) and fails if found — locking the de-identification.
- **Module verification (docker):** kryoptic (AEAD/wrap forgery → pass via discrimination),
  opencryptoki (unwrap template → pass via negotiation), softhsm2 (undersized wrap → pass
  via discrimination + AES-KW no-regression), plus one PQC module unaffected.

## 6. Risks

- **Outcome classification too lenient.** Mitigated by the two-leg requirement: a module
  that "rejects everything" fails the valid leg; a module that "accepts everything" fails
  the invalid leg. Both legs required at each migrated site.
- **Negotiation masking a finding.** Mitigated by: positive-ops only, non-shape rejects
  propagate, produced result verified, all-variants-rejected → xfail. Locked by meta-tests.
- **Green-count movement.** Some sites may move pass↔xfail as honesty improves; per the
  project philosophy this is correct, not a regression. No statistics are updated in docs
  except at release.
