# Capability-boundary honesty — follow-ups (2026-06-16)

Shipped (feat/capability-boundary-honesty): capability_for, skip_unless_capability +
in-range not-operational routing, undeclared_capability reason, RSA over-delivery probe +
pure verdict helper (all four BoundaryCase values), report capability-audit summary,
ECDSA first adopter.

Deferred / next:
1. **Boundary-probe family expansion** — wire the EC curve-boundary and AES short-key cases
   in test_capability_boundary.py (verdict helper already covers them), then HMAC, DES/3DES,
   Camellia/ARIA, KDFs, PQC.
2. **Guardrail adoption** — migrate remaining name-only `has_mechanism` gates that have a
   meaningful key-size/flag to `skip_unless_capability`, incrementally, with a meta-test per site.
3. **Operation-FNS go-straight** — when an in-range op returns FNS, retry a bounded set of
   alternative templates/call shapes (negotiated-import pattern applied to the operation, not
   just import) before settling on the recorded xfail, so a recoverable "wrong parameters" case
   is driven to a pass instead of parked in the investigation bucket.
4. **Converge the FNS audit with the coverage meta-check** (advertised-capability-honesty Task 10):
   join the in-range contradiction candidates with the C_GetMechanismList advertised-but-unregistered
   diff into one capability-honesty report section.
5. **Setup-FNS go-straight** — reconsider whether create_object_negotiated setup-FNS should attempt
   a provision/generate path per provider, as kmsp11 now does.
