# Import-skip audit: `pytest.skip("Cannot import …")` → xfail candidates

Audit of the ~32 setup-stage import-refusal `pytest.skip` sites flagged as **leak 2** in
[advertised-not-operational-gap-analysis.md](advertised-not-operational-gap-analysis.md).

**Question this doc answers:** which of these skips hide an *advertised-but-not-operational*
mechanism (model says **xfail**, never skip) versus a *genuinely-absent* capability (skip is
correct)? Per the classification model (CLAUDE.md, `docs/classification-model-design.md`), skip is
reserved for capability GENUINELY absent. After the H6 negotiation work
(`create_object_negotiated` + `import_*_negotiated` in `testcases/conftest.py` + `_negotiation.py`),
a **negotiated** import that fails for ALL storage shapes on a module that **advertises** the
mechanism is "advertised but not operational" → **xfail**, not skip. Raw (non-negotiated) import of
some object classes is genuinely optional → those skips are legitimate.

Analysis only — **no code changes this round**. The execution plan at the end drives implementation.

---

## 1. The deciding test (applied to every site)

A site is **category A (xfail-qualifying)** iff ALL hold:

1. **Advertised gate passed** — a `has_mechanism(<mech>)` (or `needs_function`) gate guards the test
   *before* the import, so the mechanism the import sets up for IS advertised.
2. **Import is the canonical capability path** — the imported key is the subject key for the
   advertised operation (verify/sign/decrypt/derive/wrap), not incidental wrong-type scaffolding.
3. **Skip fires after import exhaustion on a code that is NOT a genuine-absence signal** — i.e. the
   CKR is in the *broad* "import-unsupported" bucket (`CKR_ATTRIBUTE_VALUE_INVALID`,
   `CKR_TEMPLATE_INCONSISTENT`, `CKR_FUNCTION_FAILED`, `CKR_DEVICE_ERROR`, `CKR_MECHANISM_INVALID`,
   `CKR_ARGUMENTS_BAD`…), NOT a true capability-absence code (`CKR_CURVE_NOT_SUPPORTED`,
   `CKR_DOMAIN_PARAMS_INVALID`).

The pivotal discovery: several EC/Edwards/Montgomery sites already **split** the reject into two
branches — a `_CURVE_UNSUPPORTED_CKRS` branch (legitimate, C) and a broad
`_…_IMPORT_UNSUPPORTED_CKRS` branch (the leak, A). Only the **broad** branch is category A.

A site is **mechanical** (A-mech) if it already calls a `*_negotiated` importer (only the
skip→xfail swap is needed); it **needs wiring** (A-wire) if it still calls a raw `import_*` /
`create_object` recipe and must be moved onto the negotiated importer first.

---

## 2. Site inventory and categorization

`grep -rn "pytest.skip" src/pkcs11_check/testcases/ | grep -iE "import|cannot"` plus the
skip-on-import helper definitions (`_skip_*_import_*`, `_skip_kat_import_capability_reject`,
`_skip_rsa_public_import_reject`, `_skip_or_xfail_*_import_reject`, `_skip_if_import_unsupported`,
`_skip_if_*_capability_reject`). Session/PIN/write-protected skips and mechanism-not-advertised
setup skips are excluded as out of scope (they are correct by construction).

### Category A — QUALIFIES for xfail (advertised mechanism, negotiated-exhausted or trivially-negotiable import)

| # | File:line | Skip message | Import path | Gate | Fix |
|---|---|---|---|---|---|
| A1 | `acvp/test_acvp_rsa.py:104` (`_skip_rsa_public_import_reject`, called :305 / :367) | `RSA public key import failed: …` | `import_rsa_public_key_negotiated` | `has_mechanism(mech_name)` :295/:357 | **mechanical** |
| A2 | `wycheproof/test_wycheproof_rsa.py:224` (skip at :226) | `Cannot import RSA {bits}-bit public key: …` | `import_rsa_public_key_negotiated` | `has_mechanism(name)` (`_skip_unless_mechanism`) | **mechanical** |
| A3 | `wycheproof/test_wycheproof_rsa_pss.py:424` (skip at :426) | `Cannot import RSA {bits}-bit public key: …` | `import_rsa_public_key_negotiated` | `has_mechanism(name)` | **mechanical** |
| A4 | `wycheproof/test_wycheproof.py:582` (RSA) | `Cannot import RSA public key on this module` | `import_rsa_public_key_negotiated` | `has_mechanism(name)` :91 | **mechanical** |
| A5 | `wycheproof/test_wycheproof_ecdsa.py:373` (**broad branch only**) | `Cannot import EC key for {curve}: …` | `import_ec_public_key_negotiated` | `has_mechanism("ECDSA")` :309 | **mechanical** (split: keep :371 as C) |
| A6 | `wycheproof/test_wycheproof_aes.py:245` (unwrap), `:336` (wrap), `:570` (XTS) | `Cannot import AES {…} key` | `import_secret_key_negotiated` | `has_mechanism("AES_KEY_WRAP"/"…KWP"/"AES_XTS")` :223/:313/:545 | **mechanical** |
| A7 | `wycheproof/test_wycheproof_ed25519.py:107`, `:157`, `:252` (**broad branch only**) | `Cannot import EdDSA/Ed25519/Ed448 public key: …` | `import_eddsa_public_key_with_supported_encoding` (multi-encoding negotiator) | `has_mechanism("EDDSA")` :115/:211 | **mechanical** (split: keep :105/:155/:250 as C) |
| A8 | `acvp/test_acvp_eddsa.py:154`, `:287` (**broad branch only**) | `Cannot import EdDSA public key for {curve}: …` | `import_eddsa_public_key_with_supported_encoding` | `has_mechanism("EDDSA")` :212/:271 | **mechanical** (split: curve-unsupported stays C) |
| A9 | `test_mech_sign.py:88` (`_skip_kat_import_capability_reject`, called :245 RSA priv, :257 RSA pub, :376 secret) | `{mech}: cannot import {obj} for KAT setup: …` | raw `import_rsa_private_key` / `import_rsa_public_key` / `import_secret_key` | registry `mech_*_entry` fixture = advertised | **needs wiring** → `import_*_negotiated` |
| A10 | `wycheproof/test_wycheproof_rsa_siggen.py:143` (`_skip_or_xfail_rsa_private_import_reject`) | `Cannot import RSA private key ({bits}-bit, {sha}): …` | raw `import_rsa_private_key` | `has_mechanism` (siggen mech) | **needs wiring** → `import_rsa_private_key_negotiated` |
| A11 | `wycheproof/test_wycheproof_rsa_oaep.py:325` (`_skip_or_xfail_rsa_oaep_private_import_reject`) | `Cannot import RSA {bits}-bit private key for OAEP: …` | raw `import_rsa_private_key` | `has_mechanism("RSA_PKCS_OAEP")` | **needs wiring** → `import_rsa_private_key_negotiated` |
| A12 | `wycheproof/test_wycheproof_rsa_decrypt.py:152` (skip at :152) | `Cannot import RSA {bits}-bit private key: …` | raw `import_rsa_private_key` | `has_mechanism("RSA_PKCS")` | **needs wiring** → `import_rsa_private_key_negotiated` |
| A13 | `wycheproof/test_wycheproof.py:365`, `:513` (EC) | `Cannot import EC public key on this module: …` | raw `import_ec_public_key` | `has_mechanism(name)` :91 | **needs wiring** → `import_ec_public_key_negotiated` |
| A14 | `acvp/test_acvp_ecdsa.py:263` | `Cannot import EC public key for {curve}: …` | raw `import_ec_public_key` | `has_mechanism(mech_name)` :249 | **needs wiring** (split: curve-unsupported branch stays C) |
| A15 | `test_cctv_rfc6979.py:104` (`_skip_or_xfail_cctv_ec_import_reject`, broad branch) | `Cannot import {label}: …` | raw `import_ec_public_key` | `has_mechanism("ECDSA_SHA256")` :121/:165 | **needs wiring** → `import_ec_public_key_negotiated` |
| A16 | `acvp/test_acvp_slhdsa.py:101` (`_skip_if_import_unsupported`) | `Cannot import SLH-DSA {label}: …` | raw `import_pqc_*` | `has_mechanism` (SLH-DSA mech) | **needs wiring** (no negotiated PQC importer yet — see plan) |
| A17 | `wycheproof/test_wycheproof_dsa.py:228` | `Cannot import DSA public key` | raw `import_dsa_public_key` | `has_mechanism(name)` :188 | **needs wiring** (no negotiated DSA importer; low priority — DSA rare) |
| A18 | `wycheproof/test_wycheproof_hkdf.py:119` | `Cannot import IKM key for HKDF` | raw `create_object` (generic secret) | `has_mechanism("HKDF_DERIVE")` :86 | **needs wiring** → `create_object_negotiated` / `import_secret_key_negotiated` |
| A19 | `wycheproof/test_wycheproof_chacha.py:97` | `Cannot import ChaCha20 key` | raw `create_object` | `has_mechanism("CHACHA20_POLY1305")` :71 | **needs wiring** → `import_secret_key_negotiated` |

**Note on the A5/A7/A8/A14 splits:** these sites already separate a true-absence branch
(`CKR_CURVE_NOT_SUPPORTED` / `CKR_DOMAIN_PARAMS_INVALID` → keep as skip, category C) from a broad
import-failure branch (`CKR_ATTRIBUTE_VALUE_INVALID` etc. → xfail, category A). Only the **broad**
branch moves to xfail. The cross-check in §3 shows why this granularity is essential: on tpm2 the
NIST P-curves (secp256r1/384r1/521r1) — which ECDSA advertisement implies — hit the broad branch.

### Category B — LEGITIMATE skip (raw-import genuinely optional / negotiation inapplicable)

| # | File:line | Skip message | Why legitimate |
|---|---|---|---|
| B1 | `wycheproof/test_wycheproof_mlkem_encaps_modulus.py:178` | `module does not support raw ML-KEM encapsulation-key import + encapsulate` | Has its **own** capability probe `_raw_ek_import_supported` (:113) that tests a *known-valid* ek roundtrip first; raw ek-import + encapsulate is explicitly optional per spec. Skip fires only when the optional raw path is genuinely unavailable — capability-probe-gated, not advertised-not-operational. |
| B2 | `ckr/test_ckr_wrap.py:248` | `Module rejected generic-secret key import for wrap test: …` | The generic-secret import is **wrong-type scaffolding** for a negative wrap test (CKM_AES_KEY_WRAP needs an AES key; this imports a generic-secret deliberately). The subject mechanism (AES_KEY_WRAP) is gated/operational; the incidental generic-secret import is optional. Not the canonical capability path. |
| B3 | `ckr/test_ckr_wrap.py:318` | `…undersized wrap key import…` | Same as B2 — deliberately-undersized scaffolding key for a negative size-check test, not the capability under test. |
| B4 | `wycheproof/test_wycheproof_x25519.py:218`, `:222` (`_MONTGOMERY_PRIVATE_IMPORT_UNSUPPORTED_CKRS` branch) | `Cannot import Montgomery private key: …` | **UNCLEAR-leaning-B**: ECDH1_DERIVE is gated (:176), but X25519/X448 raw *private*-key import is a distinct optional capability from ECDH-over-named-curves, and no `import_ec_private_key_negotiated` exists. The `result=="invalid"` branch already returns (vacuous). Treat as B unless §3-style evidence shows a module advertising X25519 KAS yet refusing canonical private import. (Reclassify to A only with negotiation wiring + evidence.) |
| B5 | `wycheproof/test_wycheproof_ecdh.py:282`, `:286` | `Cannot import EC private key for ECDH: …` | Same shape as B4 — raw EC *private*-key import, no negotiated importer, ECDH-over-named-curve optional vs the gated `ECDH1_DERIVE`. B pending negotiation wiring + evidence. |

### Category C — LEGITIMATE skip (capability genuinely absent / test-data shape)

| # | File:line | Skip message | Why legitimate |
|---|---|---|---|
| C1 | `wycheproof/test_wycheproof_ecdsa.py:371` (`_CURVE_UNSUPPORTED_CKRS` branch) | `Cannot import EC key for {curve}: …` | `CKR_CURVE_NOT_SUPPORTED` / `CKR_DOMAIN_PARAMS_INVALID` = the specific curve is genuinely absent (brainpool, secp256k1 on a NIST-only module). Capability absent. |
| C2 | `wycheproof/test_wycheproof_ed25519.py:105`/`:155`/`:250` (`_CURVE_UNSUPPORTED_CKRS` branch) | `Cannot import {Ed*} public key: …` | Curve genuinely absent. |
| C3 | `acvp/test_acvp_eddsa.py` curve-unsupported branch (:111 setup probe) | `Curve {curve} not supported: …` | Curve genuinely absent. |
| C4 | `acvp/test_acvp_slhdsa.py:69`, `acvp/test_acvp_eddsa.py:69`, `acvp/test_acvp_ecdsa.py:53` (module-import guards) | `… library not available` | Optional Python dependency / test-vector library absent. |
| C5 | `wycheproof/test_wycheproof_x25519.py:191`, `:197`; `test_wycheproof_ecdh.py:247` | `Cannot decode {enc} … vector: {TypeError…}` | **Vector-decode** failure (Python-side), no module call. Test-data shape. |
| C6 | `x509/test_limbo_import.py:129`, `:266` | `Failed to decode … PEM` | Vector PEM decode (Python `pem_to_der` returns empty), no module call. Test-data shape. |
| C7 | `wycheproof/test_wycheproof_mldsa_context.py:164` | `vector lacks an importable private+public key` | The *vector* has no key material (`priv is None or pub is None`); the import-failure case already **xfails** at :162 (`ML-DSA … import not operational`). Test-data shape. |
| C8 | `acvp/test_acvp_ecdsa.py:357` (`_DETERMINISTIC_ECDSA_SKIP`) | deterministic-ECDSA not a PKCS#11 mechanism | Capability not expressible in PKCS#11. |
| C9 | `wycheproof/test_wycheproof_dsa.py:200`, `:210` | `DSA sig cannot be represented as P1363` / `Incomplete DSA public key` | Vector shape / representation, not module refusal. |
| C10 | `test_cctv_rfc6979.py` curve/`has_mechanism` setup skips | `ECDSA_SHA256 not supported …` | Mechanism not advertised — correct setup skip. |

### Category D — UNCLEAR (needs evidence before deciding)

| # | File:line | Skip message | What evidence decides it |
|---|---|---|---|
| D1 | `acvp/test_acvp_ecdh.py:441` | `Cannot extract public key point for ECDH` | Is this a module readback refusal (`CKR_*` on `C_GetAttributeValue` of `CKA_EC_POINT`) or a vector-shape gap? If the module *generated* the keypair (capability present) but cannot export the point, that is a self-contradiction (closer to Type C/fail) — needs the exact CKR. Currently raw `import_ec_public_key`-adjacent. Inspect whether it follows a successful `EC_KEY_PAIR_GEN`. |
| D2 | `wycheproof/test_wycheproof_x25519.py:218/:222`, `test_wycheproof_ecdh.py:282/:286` (the **B4/B5** rows) | `Cannot import EC/Montgomery private key…` | Whether a module that advertises `ECDH1_DERIVE` (and X25519/X448 specifically) refuses the canonical private-key import for the **named curve it advertises** (→ A) vs an unsupported curve (→ C). Needs per-curve CKR breakdown like §3, plus a negotiated EC-private importer to exhaust shapes first. Listed as B above pending that evidence. |
| D3 | `acvp/test_acvp_slhdsa.py` runtime branch overlap (`_PQC_IMPORT_RUNTIME_FAILURE_RVS` = `CKR_FUNCTION_FAILED`) | `SLH-DSA {label} import failed with non-specific CKR` (xfail) vs `Cannot import …` (skip) | The skip set `_PQC_IMPORT_UNSUPPORTED_RVS` may overlap genuine not-operational codes; confirm which CKRs PQC modules (nss-pqc) actually return so the A16 skip→xfail split lands on the right boundary. |

---

## 3. Cross-check against `artifacts2/` baselines (READ-ONLY)

Scanned every provider's `report.jsonl` for `outcome=="skipped"` records whose `longrepr` carries
a category-A skip message. Counts are per-provider (shard and `-pooled` dirs agree; one figure
shown). This confirms real providers DO hit these skips **while advertising the mechanism** — i.e.
the leak is live, not hypothetical.

### Cross-check 1 — A5 `test_wycheproof_ecdsa.py:373` (`Cannot import EC key for {curve}`), broad branch

This is the highest-volume leak. Per-curve/CKR breakdown (the deciding granularity):

- **tpm2** (`tpm2-pooled`): **~22k** skips total under this message. Critically, the broad branch
  (`CKR_ATTRIBUTE_VALUE_INVALID`) catches the **advertised NIST curves**: `secp256r1` ~2,332,
  `secp384r1` ~2,880, `secp521r1` ~1,620. tpm2 advertises ECDSA, the negotiated import of P-256 is
  refused → today **skip**, model says **xfail** (advertised but not operational). The
  `secp256k1`/brainpool counts on the same provider are the legitimate-C portion.
- **kryoptic** (`kryoptic-pooled` and `kryoptic-fips/main`): **~15k** skips — but breakdown shows
  these are `secp224r1`, `secp256k1`, brainpool* under `CKR_ATTRIBUTE_VALUE_INVALID` (curves
  kryoptic genuinely lacks) → mostly legitimate-C. Kryoptic's NIST P-256/384/521 verify operationally
  (not in the skip set), so kryoptic's share is correctly mostly C. This is exactly why the A-vs-C
  split must be per-CKR-and-per-curve, not whole-site.
- **wolfpkcs11** (`wolfpkcs11-pooled`): **~13.9k** under this message; mixture as above.
- **opencryptoki** (`opencryptoki-pooled`): **~2,234**, mostly `secp224k1`/`secp160*` with
  `CKR_FUNCTION_FAILED` (genuine absence, C) plus a single `secp192k1` `CKR_CURVE_NOT_SUPPORTED`.

**Verdict:** the leak is real and large on tpm2 specifically (the NIST P-curves under the broad
CKR). The mechanical swap MUST preserve the `_CURVE_UNSUPPORTED_CKRS` (C) branch and only downgrade
the broad `_EC_PUBLIC_IMPORT_UNSUPPORTED_CKRS` branch to xfail.

### Cross-check 2 — A1 `acvp/test_acvp_rsa.py:104` (`RSA public key import failed`)

- **kryoptic-fips** (`kryoptic-fips-pooled`): **216** skips. kryoptic-fips advertises the RSA SigVer
  mechanisms (`has_mechanism(mech_name)` passed) yet the negotiated public-key import is refused →
  today **skip**, model says **xfail** (advertised but not operational; consistent with the
  documented kryoptic-fips FIPS-policy refusals in the gap analysis). Mechanical swap.
- No other provider hits this message in the baseline (negotiated RSA public import otherwise
  succeeds), so this is a focused, low-risk first mechanical conversion.

### Cross-check 3 — A4/A13 `test_wycheproof.py` (`Cannot import RSA/EC public key on this module`)

- **corePKCS11** (`corepkcs11-pooled`, the documented secret-key-import precedent provider):
  EC: **988** `Cannot import EC public key on this module` skips (A13, raw `import_ec_public_key`,
  ECDSA advertised); RSA-family: **201** `Cannot import RSA …` skips (A4/A2/A3 share the substring).
  corePKCS11 advertises these mechanisms but its minimal store refuses the imports → today **skip**,
  model says **xfail**. This is the H6/corePKCS11 precedent named in the gap analysis, now quantified.
- **tpm2**: EC **988** + RSA private **72** + RSA **12** on the raw-import sites — same leak class.
- **wolfpkcs11**: **244** `Cannot import EC public key on this module`.

**Verdict:** A4 is mechanical (already negotiated) and A13 is needs-wiring (raw `import_ec_public_key`
→ `import_ec_public_key_negotiated`); both fire on advertised mechanisms across corePKCS11 / tpm2 /
wolfpkcs11. Converting them turns ~1,200 corePKCS11 false "capability-absent" skips into honest
"advertised-but-not-operational" xfails.

*(All counts rounded where >1000; exact figures: tpm2 ECDSA-curve skips 21,906; kryoptic 15,074;
wolfpkcs11 13,930; opencryptoki 2,234; corePKCS11 EC 988 / RSA 201; kryoptic-fips RSA-SigVer 216.)*

---

## 4. Recommended execution plan

Order = lowest-risk, highest-evidence first. The xfail wording must be the shared
`not_operational_reason(probe_key, detail)` from `_operability.py` (so report readers group the
import-stage signal with the op-stage `claim_refusal_passes` / `classify_kat_clean_error` xfails for
the same mechanism). Each batch is TDD: add a meta-test asserting the *outcome class* before the swap.

**Batch 1 — mechanical swaps, already-negotiated (lowest risk, strongest evidence):**
A1, A2, A3, A4, A6. Swap the helper's `pytest.skip(...)` for
`pytest.xfail(not_operational_reason(f"{mech_name}:import", ckr_name(exc.rv)))` (or a thin
`import_refusal_xfail(exc, *, probe_key)` wrapper added to `_operability.py` mirroring
`claim_refusal_passes`). Evidence: kryoptic-fips RSA (216), corePKCS11 RSA (201). Keep the existing
`xfail_if_known_ckr` runtime-reject branches untouched.

**Batch 2 — mechanical swaps with a split to preserve (A5, A7, A8, A14):** convert ONLY the broad
`_…_IMPORT_UNSUPPORTED_CKRS` branch to xfail; leave the `_CURVE_UNSUPPORTED_CKRS` branch as skip
(category C). This is the highest-volume batch (tpm2 NIST-curve leak) and the one most likely to
move counts, so land it with a dedicated meta-test that pins: curve-unsupported CKR → skip; broad
CKR on an advertised curve → xfail.

**Batch 3 — needs-wiring, RSA/EC private + public raw importers (A9, A10, A11, A12, A13, A15):**
first move the raw `import_rsa_private_key` / `import_rsa_public_key` / `import_ec_public_key` calls
onto the existing negotiated importers (`import_rsa_private_key_negotiated`,
`import_rsa_public_key_negotiated`, `import_ec_public_key_negotiated`), THEN swap skip→xfail. A9
(`test_mech_sign` KAT) is the cleanest target — its op stage already routes through
`claim_refusal_passes`, so wiring the setup stage to the same `not_operational_reason` closes the
setup/op asymmetry on one mechanism family.

**Batch 4 — needs new negotiated importers (A16 SLH-DSA, A17 DSA, A18 HKDF/secret, A19 ChaCha):**
A18/A19 can reuse `import_secret_key_negotiated` / `create_object_negotiated` (cheap). A16 (PQC) and
A17 (DSA) have no negotiated importer yet; defer until D3 (PQC CKR boundary) is resolved and weigh
DSA's low value (A17 is the lowest priority — DSA is near-obsolete).

**Leave alone (do NOT touch):**
- All of category B (B1–B5) and C (C1–C10): legitimate skips. In particular keep B1's
  `_raw_ek_import_supported` probe and the EdDSA/ECDSA `_CURVE_UNSUPPORTED_CKRS` branches as skip.
- The vector-decode skips (C5/C6/C9) and module-import guards (C4) — no module involvement.
- The "wrong-type scaffolding" wrap skips (B2/B3) — not the capability under test.

**Resolve before touching (D-items):** D1 (`acvp_ecdh:441` point-extract — get the CKR; may be a
Type-C self-contradiction = fail, not xfail), D2 (X25519/X448 private import — needs per-curve CKR
evidence + a negotiated EC-private importer that does not yet exist), D3 (PQC import CKR boundary).

**Meta-test approach:** for each batch, add a unit test that drives the helper with a synthetic
`CkrAssertionError` and asserts `pytest.xfail` is raised with `not_operational_reason` wording for
broad codes, and `pytest.skip` for genuine-absence codes — mirroring the existing
`_operability` / `_capability_claims` unit tests. Do NOT gate on provider identity. Then re-run the
pooled matrix and confirm the converted skips reappear as xfails (not as new fails) by re-scanning
`artifacts/` report.jsonl outcomes for the same nodeids.

---

## 5. Summary

- **Total in-scope import/decode skip sites examined:** 32 distinct sites (some helpers guard
  multiple call sites; some sites carry a two-branch split).
- **Category A (xfail-qualifying):** 19 sites — **5 mechanical** (A1–A4, A6 + the broad branch of
  A5/A7/A8 are mechanical too), **the rest need negotiation wiring** (A9–A19). The A5/A7/A8/A14
  splits keep their curve-unsupported sub-branch in C.
- **Category B (legitimate, raw-import optional):** 5 (B1–B5; B4/B5 cross-listed as D2).
- **Category C (legitimate, capability/test-data absent):** 10 (C1–C10).
- **Category D (needs evidence):** 3 (D1–D3).
- **Cross-check confirms the leak is live:** tpm2 (~22k EC-curve skips, NIST P-curves in the broad
  branch = A), corePKCS11 (988 EC + 201 RSA = the documented precedent), kryoptic-fips (216 RSA
  SigVer) all skip imports while advertising the mechanism. The A-vs-C boundary is **per-CKR**
  (broad import-failure → A; `CKR_CURVE_NOT_SUPPORTED`/`CKR_DOMAIN_PARAMS_INVALID` → C), which is why
  the split-branch sites must not be converted wholesale.
