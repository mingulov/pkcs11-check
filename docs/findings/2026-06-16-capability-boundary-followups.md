# Capability-boundary honesty - follow-ups (2026-06-16)

Shipped (feat/capability-boundary-honesty): capability_for, skip_unless_capability (with its
first adopter in test_ec_curves), the `route_in_range_not_operational` helper +
`undeclared_capability` reason, RSA over-delivery probe + pure verdict helper (all four
BoundaryCase values), report capability-audit summary (detail propagated through
extract._new_group).

Wired but not yet adopted: `route_in_range_not_operational` (in-range FNS/KEY_SIZE_RANGE/
MECHANISM_INVALID → recorded xfail) has no functional-test caller yet, so no IN_RANGE
contradiction records are emitted in practice and the audit's `claimed_refused` stays 0 until
its first adopter lands (item 2 below). The over-delivery probe currently runs only the RSA
below-min case live; EC/AES are deferred (item 1).

Deferred / next:
1. **Boundary-probe family expansion** - wire the EC curve-boundary and AES short-key cases
   in test_capability_boundary.py (verdict helper already covers them), then HMAC, DES/3DES,
   Camellia/ARIA, KDFs, PQC.
2. **`route_in_range_not_operational` first adopter** - wire it into a functional test (the
   ECDSA sign path is the natural candidate, since it is now gated IN_RANGE). This requires
   reconciling its narrow reject set (FNS/KEY_SIZE_RANGE/MECHANISM_INVALID) with the existing
   per-test reject sets that also xfail `CKR_FUNCTION_FAILED` (e.g. `_ECDSA_SIGN_REJECT_RVS`):
   decide whether FUNCTION_FAILED is an in-range not-operational deviation or a hard finding,
   then adopt consistently.
3. **Guardrail adoption** - migrate remaining name-only `has_mechanism` gates that have a
   meaningful key-size/flag to `skip_unless_capability`, incrementally, with a meta-test per site.
3. **Operation-FNS go-straight** - when an in-range op returns FNS, retry a bounded set of
   alternative templates/call shapes (negotiated-import pattern applied to the operation, not
   just import) before settling on the recorded xfail, so a recoverable "wrong parameters" case
   is driven to a pass instead of parked in the investigation bucket.
4. **Converge the FNS audit with the coverage meta-check** (advertised-capability-honesty Task 10):
   join the in-range contradiction candidates with the C_GetMechanismList advertised-but-unregistered
   diff into one capability-honesty report section.
5. **Setup-FNS go-straight** - reconsider whether create_object_negotiated setup-FNS should attempt
   a provision/generate path per provider, as kmsp11 now does.
