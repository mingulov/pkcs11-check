# Gap analysis: "advertised but not operational → xfail" (FIPS prompt, 2026-06-10)

Triggered by Denis's question on the kryoptic-fips reclassifications (`e38f4e5a` ECDSA-prehash
SHA-1, `90dcb7cc` RSA encrypt/interop): *should this be a separate test? FIPS only? shouldn't ANY
internal failure of an advertised mechanism be xfail and never pass?*

## Q1 — Is this FIPS-only? **No — provider-general; FIPS is one cause among six observed.**

| Provider | Advertised-but-not-operational evidence | Cause |
|---|---|---|
| kryoptic-fips | CKM_ECDSA_SHA1 sign, CKM_RSA_PKCS encrypt refuse (CKR_DEVICE_ERROR) | FIPS 140-3 policy |
| tpm2 | SHA1_RSA_PKCS verify with imported public keys rejects **all 27/27 valid** ACVP vectors | TPM SHA-1 restriction |
| bouncyhsm | AES-CCM decrypt: every valid KAT vector rejects (ENCRYPTED_DATA_INVALID) | unimplemented path |
| corePKCS11 | secret-key (CMAC/HMAC) import "succeeds" then every use fails | minimal impl |
| wolfpkcs11 | AES-CTS advertised, all 2,079 vectors refused | unimplemented |
| opencryptoki | OAEP hash/MGF combos advertised, refused per-combo | partial impl |

A FIPS-only test would mislabel 5 of these 6. The pattern must stay cause-neutral and
provider-general. **Optional enrichment:** PKCS#11 3.2 validation objects (CKO_VALIDATION,
already exercised by `test_validation_objects.py`) let the xfail message note the token's claimed
validation ("token claims FIPS 140-3 level N") when present — capability-based, no provider
identity.

## Q2 — Should it be a separate test? **It substantially already is: the `test_mech_*` registry suites.**

`test_mech_encrypt/sign/digest/derive/wrap/keygen/...` walk the mechanism registry
(`mechanism_helpers.py`) against `C_GetMechanismList` and produce exactly ONE legible
`"{mech} advertised but {op} is not operational"` xfail per (mechanism, operation) — that is the
separate, per-mechanism signal. The KAT suites' per-vector xfails are then corroborating evidence,
not the primary signal.

**Gaps in the separate-test layer:**

1. **Registry completeness** (mechanism-tests Phases B–D still pending): an advertised mechanism
   with NO registry entry gets no per-mech operability verdict at all. → Add a coverage
   meta-check: one test that diffs `C_GetMechanismList` against the registry and reports
   unprobed advertised mechanisms (so blind spots are visible instead of silent).
2. **No cross-link**: KAT-suite xfail messages and `test_mech_*` xfails use similar but not
   identical wording; report readers can't easily see they are the same deviation. → Shared
   message constant / probe key in the reasons.

## Q3 — "Any internal failure of an advertised mechanism should be xfail, never pass." **Two leak classes found where it ends up as pass or skip instead.**

### Leak 1 (biggest): vacuous negative-op passes on a NOT_OPERATIONAL mechanism

When the canonical probe (`_operability.py`) says NOT_OPERATIONAL, *invalid*-vector rejections
still count as **pass** ("module rejected invalid input") — but the module never evaluated the
input; it refuses everything. Concrete: tpm2 records **135 SHA-1 SigVer invalid-vector passes**
while rejecting 27/27 valid vectors proves verify never works; bouncyhsm CCM records thousands of
invalid-vector "passes" with a non-operational decrypt. These passes assert conformance that was
never tested.

**Fix direction (Denis-endorsed):** where a canonical probe verdict exists and is
NOT_OPERATIONAL, classify negative-op rejections as `xfail` ("vacuous reject — mechanism not
operational, input never evaluated"), not pass. Scope: the probe-wired runners
(`base_runner_aead`, `acvp/aes/test_wrap`, `base_cts`, `test_xts`, `wycheproof_aes`), the ACVP
SigVer probe, the PSS combo probe. Effect: converts false confidence into recorded deviation;
operational mechanisms are untouched (probe gates the downgrade).

### Leak 2: setup skips on advertised mechanisms

~32 `pytest.skip("Cannot import …")` sites treat key-import refusal as a capability skip. After
the negotiation work (H6), a *negotiated* import that fails for ALL storage shapes on a module
that ADVERTISES the mechanism is "advertised but not operational", not "capability absent" —
the model reserves skip for genuinely absent capability. corePKCS11 secret-key import is the
documented precedent. → Audit those sites: where the mechanism is advertised and negotiation
exhausted, prefer xfail over skip. (Care: raw-import support is genuinely optional for some
object classes; only the negotiated-exhausted case qualifies.)

### Consistent with the existing model

- Positive-op row: clean error = xfail — unchanged.
- `INCONCLUSIVE` probe (setup could not stage the canonical op) keeps legacy rules — unchanged.
- Lenient-init-but-safe-op xfail (a4ca5891) — same direction.
- Crash/wrong-output stay hard FAIL everywhere; nothing in this analysis weakens crypto–D.

## Recommended execution order

1. **Vacuous-reject downgrade** in probe-wired suites (evidence-rich: tpm2 SigVer, bouncyhsm CCM,
   wolfpkcs11 CTS). TDD meta-tests per runner.
2. **Coverage meta-check** for advertised-but-unprobed mechanisms (closes the registry blind spot).
3. **Import-skip→xfail audit** of the 32 sites (negotiated-exhausted + advertised only).
4. (Low) **Validation-object annotation** in not-operational xfail messages.
