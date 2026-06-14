# PKCS#11 conformance findings — consolidated summary (2026-06-10)

Executive view of the genuine **module** findings surfaced/characterized by pkcs11-check during the
2026-06-09/10 triage loop, plus the **harness** (pkcs11-check) improvements shipped and the open
decisions. Per-module detail lives in `module-issues.md`; per-finding writeups in `findings/*.md`;
triage reasoning in `issues-triage.md`. All harness fixes are on `dev`.

Classification model (one rule, provider-general): `CKR_OK`+correct = **pass**; clean error on an
advertised mechanism = **xfail** (recorded deviation, not hidden); `CKR_OK`+wrong output / crash /
self-contradiction (crypto/policy/lifecycle/metadata) = **fail**; capability genuinely absent = **skip**.

---

## 1. Genuine module conformance findings (to report upstream)

| Provider | Finding | Class | Severity |
|---|---|---|---|
| **wolfpkcs11** | Digest path leaks a raw wolfSSL error (`-132`, `0x…ff7c`) as the `CK_RV` instead of a defined `CKR_*` (whole SHA-2/SHA-3 digest path, ~309) | spec violation (non-`CKR_*` return) | High |
| **wolfpkcs11** | AES-CCM decrypt does not authenticate — accepts invalid tags (`423×`) and returns plaintext+unstripped-tag (no MAC verify) | crypto/auth break | **Critical** |
| **wolfpkcs11** | RSA-OAEP rejects valid edge-case vectors despite an operational combo: empty-message (`msglen=0`, ~125), 3-prime RSA keys (54), near-max length (~15) — others decrypt them fine | correctness (OAEP decoder edge cases) | Medium |
| **wolfpkcs11** | AES-CBC-PAD accepts non-PKCS#5 padding (BadPadding 141 + NoPadding 3) | padding-validation deviation | Medium |
| **wolfpkcs11** | Output-buffer size-protocol violations: `C_GetMechanismList` reports count 1 (real 65); `C_GetAttributeValue` writes 13B past a 1B buffer (OOB write); `C_WrapKey` reports garbage required length | §5.2 buffer protocol + OOB write | High |
| **wolfpkcs11** | `CKA_MODIFIABLE=False` mutability constraint ignored (`C_SetAttributeValue` accepted) | policy self-contradiction | Medium |
| **wolfpkcs11** | Crashes on normal input: `test_wycheproof_hkdf` SIGABRT (after 10 valid vectors), `test_ckr_keygen` SIGSEGV, `test_access_levels` SIGSEGV (SO-login path). *Stable; master fixes most — report vs master.* | crash | High |
| **bouncyhsm** | AES-CCM decrypt does not authenticate (same no-auth class as wolfpkcs11): accepts invalid tags + returns unstripped tag bytes (~423 forgery + ~1,268 wrong-plaintext on full suite) | crypto/auth break | **Critical** |
| **bouncyhsm** | SIGSEGV on `C_GetAttributeValue` after `C_DestroyObject` — native shim checks RPC status `rv` instead of the method return `rvMethod`, dereferences `envelope.Data` on a stale handle (root-caused in `bouncy-pkcs11.c`) | crash (shim bug) | High |
| **bouncyhsm** | `C_VerifyFinal(empty sig)` → `CKR_ARGUMENTS_BAD` leaves the verify op active (no termination) | lifecycle | Medium |
| **kryoptic** | `C_Verify`/`C_VerifyFinal` of a wrong-**length** signature (`CKR_SIGNATURE_LEN_RANGE`) does not terminate the operation (spec: "always terminates") → `CKR_OPERATION_ACTIVE` cascade on the next op | lifecycle | High |
| **opencryptoki** | Multipart `C_VerifyFinal(empty sig)` → `CKR_ARGUMENTS_BAD` leaves the verify op active (single-shot `C_Verify` terminates correctly) | lifecycle | Medium |
| **opencryptoki** | AES-CBC-PAD accepts non-PKCS#5 padding (same 144 as wolfpkcs11) | padding-validation deviation | Medium |
| **opencryptoki** | AES-CTR `ulCounterBits = 0` / `129` accepted (out of `[1,128]`) | parameter-validation deviation | Low |
| **tpm2-pkcs11** | `C_VerifyFinal(empty sig)` leaves the verify op active; recovery needs close+reopen (v2.40, no `C_SessionCancel`) | lifecycle | Medium |
| **tpm2-pkcs11** | `test_fork_after_initialize` times out (daemon/TPM connection does not survive fork+re-Initialize) | robustness (daemon) | Low |
| **tpm2-pkcs11** | ACVP RSA SigVer with imported keys: 27/27 valid SHA-1 vectors rejected — advertised-but-not-operational for imported-key SHA-1 (now xfail) | not-operational deviation | Low |
| **NSS softoken** | SIGSEGV: MAC mechanism (`CKM_SHA256_HMAC`/`CKM_AES_CMAC`) with an RSA key — `NSC_SignInit` skips key-type validation, `sftk_MAC_Create` uses uninitialized `PORT_New` → dereferences garbage `destroy_func` (root-caused; reported upstream, assessed out-of-threat-model) | crash (heap-state-dependent) | Medium |
| **NSS softoken** | `CKM_RSA_X_509` unwrap takes key bytes from the leading (not trailing) end of the decrypted block | correctness | Medium |
| **corePKCS11** | Silent EC curve rebind: `C_CreateObject` accepts a curve then stores/uses a different one (secp256k1/brainpoolP256r1 → unusable) | lifecycle self-contradiction | Medium |
| **corePKCS11** | Secret-key import advertised but not operational (CMAC/HMAC sign → `KEY_TYPE_INCONSISTENT`, readback → `OBJECT_HANDLE_INVALID`) | not-operational deviation | Low |
| **softhsm2** | `C_SignInit/C_VerifyInit(CKM_ECDSA, RSA key)` lenient (returns `CKR_OK`) but the terminal op safely refuses — lazy-but-safe key-type validation (only provider that defers it) | deviation (xfail) | Low |
| **pkcs11-mock** | Stores a canned 12-byte `CKA_VALUE` for every imported cert → readback contradiction (lifecycle). *Test fixture, not a real module — expected.* | n/a (fixture) | — |

---

## 2. Harness (pkcs11-check) improvements shipped this session (`dev`)

These are **false-fail eliminations** — provider-general fixes where the suite mis-classified
spec-legal or not-operational behavior as a hard failure:

- **Advertised-but-not-operational (FIPS) class** — positive-op tests (ECDSA-prehash, RSA
  encrypt/interop) hard-failed when an advertised mechanism cleanly refused at runtime
  (kryoptic-FIPS: SHA-1 deprecated, RSA PKCS#1 v1.5 key-transport restricted → `CKR_DEVICE_ERROR`).
  New `_signature_policy.xfail_if_op_not_operational` classifies the clean refusal as xfail; wrong
  output / crash still fail. Verified kryoptic-fips → 0 failed, non-FIPS → no regression.
  *(Gap-analysis `advertised-not-operational-gap-analysis.md`: not FIPS-only — 6 causes; pattern is
  cause-neutral.)*
- **Wrong-key-type continuation** — `C_SignInit(ECDSA, RSA)` lenient-init + safe op-refusal now
  xfails (was hard-fail), discriminating from a produced-signature break (still fail).
- **ECDH / RSA-PSS / RSA-PKCS#1 v1.5 decrypt** (co-session) — invalid-vector "acceptance" tests
  were verify/decrypt-direction mis-expectations (on-curve encoding-invalidity; anti-Bleichenbacher
  mitigation; deterministic PSS sLen=0). Reframed to fail only on a real crypto break.
- **ML-DSA sign** (co-session) — untransmitted-context vectors skipped; lenient malformed-key
  signing xfailed. nss `mldsa_sign` 14F → 0F.
- **Operability probe (H2)** + storage-shape import negotiation (H6) + per-combo OAEP probe (H3) —
  earlier in the loop; eliminated ~22.6k corePKCS11 KAT false-fails and the bouncyhsm CCM/CTS noise.
- **CI ruff-format gate** restored (28 drifted files); doc over-claims corrected (wolfpkcs11
  OAEP/CBC-PAD "→0", opencryptoki verify-final "PASS").

---

## 3. Decisions (Denis, 2026-06-10)

- ✅ **C1–C3 UB probes = KEEP** ("crashes are findings"). The lying-buffer / NULL-deref probes stay;
  their crashes are reported as findings, not removed. Flag CLOSED.
- **Hardening checks** (GCM weak-params: 32-bit tag / short IV / IV-reuse; EdDSA invalid-key accept;
  SetAttribute non-atomicity; AES-CBC-PAD lax padding; wrong-key-type init-only) = **no preference →
  left as-is** (`fail`, spec permits the behavior but the strict check is retained).

---

## 4. Not findings (correct/expected behavior the suite must not flag)

- **kryoptic-FIPS clean refusals** of SHA-1 sigs / RSA PKCS#1 v1.5 key transport — correct FIPS
  140-3 policy → xfail (advertised but not operational), not a module bug.
- **UB-provoked crashes** (lying `ulDataLen`/`template_count` = `2^64-1` against a small buffer,
  NULL+nonzero-length) — harness-provoked undefined behavior per the PKCS#11 caller contract; the
  probes are retained (decision above) but the crashes are a *caller-contract* matter, not pure
  module conformance.
- **Deduplication / capability-absent skips** — legitimate (mechanism not advertised; identical
  PKCS#11 operation inputs).

---

## 5. Open follow-ups (next session — see `SESSION-RESTORE.md`)

1. `test_rsa_key_wrapping` FIPS (3F) — failure is on the private-key **unwrap** (`C_UnwrapKey`,
   key transport), not the public wrap; wrap the 3 unwrap sites with `xfail_if_op_not_operational`.
2. Gap-analysis recs: vacuous negative-op-reject downgrade on NOT_OPERATIONAL mechanisms; registry
   coverage meta-check; import-skip→xfail audit.
3. nss `mldsa_verify` 8F (determine real crypto vs deviation); opencryptoki AES-CBC-PKCS5 144 writeup.
4. Hardening reclassification (open); `dev → main` promotion (Denis only).
