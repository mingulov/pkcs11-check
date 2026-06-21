# Key-Provisioning Phase 2 — Private-Key Injection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provision RSA and EC private keys into a token via `C_UnwrapKey` (PKCS#8 DER payload) when `C_CreateObject` is unavailable/prohibited, mirroring the Phase-1 secret-key path, so sign/decrypt/derive KAT sites run on no-create modules instead of hard-failing.

**Architecture:** Two per-key-type entry points in `testcases/_provisioning.py` (`provision_rsa_private_key`, `provision_ec_private_key`) resolve **create → unwrap → skip**. The create path is byte-identical to today's `import_*_private_key_negotiated` call (so `create_available` modules are never perturbed — a create failure there is still a real finding). The unwrap path PKCS#8-DER-encodes the private key (new `raw/key_encoding.py`) and reuses the Phase-1 `build_wrap_context` + `WrapStrategy` machinery (envelope/AES-KWP carry the ~1.2 KB RSA payload; OAEP is too small for RSA but fits EC). Private keys are sensitive → no value-integrity readback; record a `compliance.note` of the injection method instead.

**Tech Stack:** Python 3.12+, `cryptography` 46 (PKCS#8 encode/decode), pytest, pure-ctypes `pkcs11_check.raw`.

## Global Constraints

- **NEVER wrap `CKR_*` / `CKA_*` / `CKM_*` / `CKK_*` / `CKO_*` constants in `int()`.** They are already `int` subclasses. Use the bare constant. (Recurring review finding in Phase 1.)
- **The layer must never hide a finding.** Injection affects only *setup*; the target-operation verdict is unchanged. Injection failure → `pytest.skip` (never a target-op `fail`). A create failure on a `create_available` module is re-raised, never re-routed to unwrap.
- **`provision_*` is for VALID key material only.** Negative tests that provision invalid material to probe creation-rejection MUST keep calling `import_*`/`create_object` directly. Do not migrate those.
- **`tests/` is module-free.** No test in `tests/` may load a real PKCS#11 module. Use monkeypatched fake raw-sessions + synthetic results (see `tests/test_import_ec_private_key_negotiated.py` and the Phase-1 `tests/test_provision_secret_key.py` for the recipe). Real-module validation is controller-run (Task 7), not a gate test.
- **EC unwrap template MUST OMIT `CKA_EC_PARAMS`** (empirically `CKR_ATTRIBUTE_READ_ONLY` on softhsm2 — it is derived from the PKCS#8 payload). Likewise the RSA unwrap template MUST OMIT all CRT component attrs (`CKA_MODULUS`, `CKA_PRIVATE_EXPONENT`, `CKA_PRIME_1/2`, `CKA_EXPONENT_1/2`, `CKA_COEFFICIENT`, `CKA_PUBLIC_EXPONENT`).
- **All gates must pass before each commit:** `uv run ruff format --check .`, `uv run ruff check .`, `uv run mypy --strict src`, `uv run pytest tests/`.
- Type annotations on all public functions. Line length 100. `uv run` prefix for all tooling.

**Empirical basis (validated 2026-06-21 on softhsm2 local build via `/tmp/p2_probe.py`):** `C_UnwrapKey` with `CKM_RSA_AES_KEY_WRAP` + nested OAEP (SHA-1) accepts a **PKCS#8 DER** payload and produces a working `CKO_PRIVATE_KEY` for both RSA-2048 (~1218 B payload) and EC P-256 (~138 B); proven by signing with the injected key and verifying against the known public key.

---

### Task 1: PKCS#8 DER encoders

**Files:**
- Create: `src/pkcs11_check/raw/key_encoding.py`
- Test: `tests/test_key_encoding.py`

**Interfaces:**
- Produces:
  - `rsa_pkcs8_from_crt(*, n: bytes, e: bytes, d: bytes, p: bytes, q: bytes, dmp1: bytes, dmq1: bytes, iqmp: bytes) -> bytes` — DER-encoded PKCS#8 (PrivateKeyInfo), `NoEncryption`.
  - `ec_pkcs8_from_private(*, scalar: bytes, ec_params: bytes, key_type: int) -> bytes` — DER-encoded PKCS#8 for `CKK_EC` (named-curve OID in `ec_params`), `CKK_EC_EDWARDS` (Ed25519/Ed448), and `CKK_EC_MONTGOMERY` (X25519/X448). Raises `ValueError` for an unsupported `key_type` or an unresolvable curve OID.

**Implementation notes (the engineer knows `cryptography` but not this domain):**
- RSA: build `rsa.RSAPublicNumbers(int.from_bytes(e,"big"), int.from_bytes(n,"big"))`, then `rsa.RSAPrivateNumbers(p=int(p), q=int(q), d=int(d), dmp1=int(dmp1), dmq1=int(dmq1), iqmp=int(iqmp), public_numbers=...)` (all `int.from_bytes(x,"big")`), `.private_key()`, then `.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())`.
- EC named-curve: resolve the curve from the DER OID in `ec_params`. cryptography exposes `cryptography.hazmat.primitives.asymmetric.ec.get_curve_for_oid(ObjectIdentifier)`; parse the OID from the DER (`ec_params` is `06 len <oid-bytes>` — decode with `cryptography.x509.ObjectIdentifier` via the `asn1`/`der` of the contained OID, or use `cryptography.hazmat.primitives.serialization.load_der_public_key` is NOT applicable). Simplest robust path: decode the OID with a tiny DER reader (tag `0x06`), dotted-string it, build `ObjectIdentifier(dotted)`, call `get_curve_for_oid`. Then `ec.derive_private_key(int.from_bytes(scalar,"big"), curve).private_bytes(DER, PKCS8, NoEncryption())`.
- Edwards: `Ed25519PrivateKey.from_private_bytes(scalar)` (32 B) or `Ed448PrivateKey.from_private_bytes(scalar)` (57 B); pick by `len(scalar)`. PKCS#8-encode.
- Montgomery: `X25519PrivateKey.from_private_bytes(scalar)` / `X448PrivateKey.from_private_bytes(scalar)` by length. PKCS#8-encode.
- Keep imports local to the functions if it helps mypy/ruff; module-level is fine.

- [ ] **Step 1: Write failing tests** — round-trip each encoder through `cryptography.serialization.load_der_private_key` and assert the recovered numbers/raw-bytes match the inputs.

```python
# tests/test_key_encoding.py
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
from pkcs11_check.raw.key_encoding import ec_pkcs8_from_private, rsa_pkcs8_from_crt
from pkcs11_check.raw.types_std import CKK_EC, CKK_EC_EDWARDS, CKK_EC_MONTGOMERY


def _b(i: int) -> bytes:
    return i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")


def test_rsa_pkcs8_round_trips() -> None:
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = k.private_numbers()
    pub = n.public_numbers
    der = rsa_pkcs8_from_crt(
        n=_b(pub.n), e=_b(pub.e), d=_b(n.d), p=_b(n.p), q=_b(n.q),
        dmp1=_b(n.dmp1), dmq1=_b(n.dmq1), iqmp=_b(n.iqmp),
    )
    loaded = serialization.load_der_private_key(der, password=None)
    assert loaded.private_numbers().d == n.d


def test_ec_named_curve_pkcs8_round_trips() -> None:
    k = ec.generate_private_key(ec.SECP256R1())
    scalar = k.private_numbers().private_value.to_bytes(32, "big")
    p256_oid_der = bytes.fromhex("06082a8648ce3d030107")
    der = ec_pkcs8_from_private(scalar=scalar, ec_params=p256_oid_der, key_type=CKK_EC)
    loaded = serialization.load_der_private_key(der, password=None)
    assert loaded.private_numbers().private_value == k.private_numbers().private_value


def test_ed25519_pkcs8_round_trips() -> None:
    k = ed25519.Ed25519PrivateKey.generate()
    raw = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                          serialization.NoEncryption())
    der = ec_pkcs8_from_private(scalar=raw, ec_params=b"", key_type=CKK_EC_EDWARDS)
    loaded = serialization.load_der_private_key(der, password=None)
    assert loaded.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                               serialization.NoEncryption()) == raw


def test_x25519_pkcs8_round_trips() -> None:
    k = x25519.X25519PrivateKey.generate()
    raw = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                          serialization.NoEncryption())
    der = ec_pkcs8_from_private(scalar=raw, ec_params=b"", key_type=CKK_EC_MONTGOMERY)
    loaded = serialization.load_der_private_key(der, password=None)
    assert loaded.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                               serialization.NoEncryption()) == raw
```

- [ ] **Step 2: Run, verify they fail** (`uv run pytest tests/test_key_encoding.py -x` → ImportError/NameError).
- [ ] **Step 3: Implement `key_encoding.py`** per the notes above.
- [ ] **Step 4: Run tests → pass; run all four gates.**
- [ ] **Step 5: Commit** `feat(provisioning): PKCS#8 DER encoders for RSA + EC private keys`.

---

### Task 2: Real `ProvisioningProfile._probe_private`

**Files:**
- Modify: `src/pkcs11_check/testcases/_provisioning.py:247-249` (replace the stub)
- Test: `tests/test_provisioning_profile_private.py`

**Interfaces:**
- Consumes: `_CREATE_PROHIBITED_RVS`, `CkrAssertionError`, `CKR_FUNCTION_NOT_SUPPORTED` (already imported in the module).
- Produces: `_probe_private(self, obj_class)` returns one of `"create_available" | "create_absent" | "create_prohibited"`, mirroring `_probe_secret` (line 220) but using a valid throwaway **EC P-256 private key** import (small, universally valid) destroyed on success.

**Implementation:** Mirror `_probe_secret`. Import a valid P-256 private key via `import_ec_private_key` (raw recipe) with a fixed test scalar + the P-256 OID; map `CKR_FUNCTION_NOT_SUPPORTED → create_absent`, `rv in _CREATE_PROHIBITED_RVS → create_prohibited`, success → `destroy_quietly` + `create_available`; re-raise anything else. Use a deterministic valid scalar (e.g. `b"\x01"*32` reduced — or generate one with `ec.derive_private_key`). Keep `obj_class` parameter (drop the `# noqa: ARG002`, now used only for symmetry — actually keep a single private probe regardless of obj_class value since "private" is the only caller).

- [ ] **Step 1: Write failing test** — monkeypatch `import_ec_private_key` to (a) succeed → assert `create_available` + `destroy_quietly` called; (b) raise `CkrAssertionError(CKR_FUNCTION_NOT_SUPPORTED)` → assert `create_absent`; (c) raise `CKR_TEMPLATE_INCONSISTENT` → assert `create_prohibited`; (d) raise an unexpected CKR → assert it propagates. Follow the fake-`rs` pattern from `tests/test_provisioning_profile.py` (Phase 1).
- [ ] **Step 2: Run → fail** (stub returns `create_available` always).
- [ ] **Step 3: Implement** the real probe.
- [ ] **Step 4: Run → pass; gates.**
- [ ] **Step 5: Commit** `feat(provisioning): real private-key create-availability probe`.

---

### Task 3: `provision_rsa_private_key`

**Files:**
- Modify: `src/pkcs11_check/testcases/_provisioning.py` (add after `provision_secret_key`)
- Test: `tests/test_provision_rsa_private_key.py`

**Interfaces:**
- Consumes: `build_wrap_context`, `DEFAULT_STRATEGIES`, `profile_for`, `rsa_pkcs8_from_crt` (Task 1), `compliance.note`, recipe `unwrap_key`, conftest `import_rsa_private_key_negotiated`.
- Produces:

```python
def provision_rsa_private_key(
    rs: Any, cfg: Any, *,
    n: bytes, e: bytes, d: bytes, p: bytes, q: bytes,
    dmp1: bytes, dmq1: bytes, iqmp: bytes,
    attrs: dict[Any, Any], label: str,
) -> int: ...
```

**Behavior (mirror `provision_secret_key`, lines 511-616):**
1. `mode = getattr(cfg, "key_inject", "off")`.
2. If `mode != "force-unwrap"` and `create_verdict("private") == "create_available"`: `return import_rsa_private_key_negotiated(rs, n=n, e=e, d=d, p=p, q=q, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp, attrs=attrs)` — **byte-identical create path**.
3. `mode == "off"` → `pytest.skip(f"{label}: Module does not implement C_CreateObject")`.
4. `ctx = build_wrap_context(rs, cfg)`; `None` → skip `"no wrapping path"`.
5. strategy by `ctx.strategy_name`; size-cap check against `len(pkcs8)` (RSA ~1.2 KB → OAEP rejected, envelope/KWP accepted); over cap → skip `"no usable wrap mechanism for this target size"`.
6. `pkcs8 = rsa_pkcs8_from_crt(n=…, …)`.
7. `unwrap_template = {CKA_CLASS: CKO_PRIVATE_KEY, CKA_KEY_TYPE: CKK_RSA}` then merge **only the non-component attrs** from `attrs` (i.e. the caller's `attrs` here are usage flags like `CKA_SIGN`/`CKA_DECRYPT`/`CKA_TOKEN` — they contain no CRT components, so merge them all; the components live in the dedicated kwargs, never in `attrs`). Do NOT add any `CKA_MODULUS`/CRT attrs.
8. `handle = unwrap_key(rs.raw, rs.sh, unwrap_handle, pkcs8, strategy.unwrap_mech, attrs=unwrap_template, mech_param=strategy.unwrap_mech_param(ctx))`.
9. `compliance.note(f"{label}: private key provisioned via C_UnwrapKey ({ctx.strategy_name})", ComplianceLevel.INFO?)` — use the existing `compliance.note` signature; no value-integrity readback (sensitive).
10. `return handle`.

- [ ] **Step 1: Write failing module-free tests** using a fake `rs` whose `unwrap_key`/`import_*` are monkeypatched. Cover: (a) `create_available` → calls `import_rsa_private_key_negotiated`, returns its handle, never builds a wrap context; (b) `force-unwrap` + a fake context whose strategy round-trips → calls `unwrap_key` with a template that has `CKA_CLASS=CKO_PRIVATE_KEY`+`CKA_KEY_TYPE=CKK_RSA` and **no** CRT attrs, payload equals `rsa_pkcs8_from_crt(...)`; (c) `off` + create-absent → `pytest.skip`; (d) wrap-context `None` → skip. Mirror `tests/test_provision_secret_key.py`.
- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run → pass; gates.**
- [ ] **Step 5: Commit** `feat(provisioning): provision_rsa_private_key (create→unwrap→skip)`.

---

### Task 4: `provision_ec_private_key`

**Files:**
- Modify: `src/pkcs11_check/testcases/_provisioning.py`
- Test: `tests/test_provision_ec_private_key.py`

**Interfaces:**
- Produces:

```python
def provision_ec_private_key(
    rs: Any, cfg: Any, *,
    ec_params: bytes, value: bytes, key_type: int,
    attrs: dict[Any, Any], label: str,
) -> int: ...
```

**Behavior:** Same shape as Task 3, with:
- create path: `import_ec_private_key_negotiated(rs, ec_params=ec_params, value=value, key_type=key_type, attrs=attrs)`.
- `pkcs8 = ec_pkcs8_from_private(scalar=value, ec_params=ec_params, key_type=key_type)`.
- **unwrap template = `{CKA_CLASS: CKO_PRIVATE_KEY, CKA_KEY_TYPE: key_type}` + caller `attrs`, with `CKA_EC_PARAMS` and `CKA_VALUE` STRIPPED** (CKA_EC_PARAMS is READ_ONLY on unwrap — empirically `CKR_ATTRIBUTE_READ_ONLY`; CKA_VALUE comes from the payload). The caller's `attrs` are usage flags; still defensively strip `CKA_EC_PARAMS`/`CKA_VALUE` if present.
- If `ec_pkcs8_from_private` raises `ValueError` (unsupported curve/type) on the unwrap path → `pytest.skip(f"{label}: no PKCS#8 encoding for this key type")`.
- `compliance.note` on success; no readback.

- [ ] **Step 1: Write failing module-free tests** — analogous to Task 3, asserting the unwrap template has NO `CKA_EC_PARAMS` and payload equals `ec_pkcs8_from_private(...)`; plus a test that an unsupported `key_type` on the unwrap path → `pytest.skip`.
- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run → pass; gates.**
- [ ] **Step 5: Commit** `feat(provisioning): provision_ec_private_key (omit CKA_EC_PARAMS on unwrap)`.

---

### Task 5: Migrate Wycheproof + ACVP private-key KAT sites

**Files (migrate the private-key import at each line; preserve every existing `except`/skip/curve-gate handler):**
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_decrypt.py:184` (RSA) — needs `p11_config` in scope (it is `p11_config` fixture; confirm name).
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_oaep.py:416` (RSA)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_siggen.py:206` (RSA; vector already carries PKCS#8 but the call uses CRT components — keep passing CRT kwargs)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py:277` (EC, `key_type=CKK_EC`)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_x25519.py:253` (EC Montgomery, `key_type=CKK_EC_MONTGOMERY`)
- `src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py:316` (EC)
- `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py:434` (EC Edwards, `key_type=CKK_EC_EDWARDS`; currently bare `import_ec_private_key` — add the `p11_config` fixture to the test signature if absent)

**Worked example (RSA decrypt):** replace
```python
priv = import_rsa_private_key_negotiated(rs, n=n, e=e, d=d, p=p, q=q,
                                         dmp1=dmp1, dmq1=dmq1, iqmp=iqmp,
                                         attrs={CKA_DECRYPT: True})
```
with
```python
priv = provision_rsa_private_key(rs, p11_config, n=n, e=e, d=d, p=p, q=q,
                                 dmp1=dmp1, dmq1=dmq1, iqmp=iqmp,
                                 attrs={CKA_DECRYPT: True},
                                 label="wycheproof RSA decrypt KAT")
```
Add `from pkcs11_check.testcases._provisioning import provision_rsa_private_key` (or `provision_ec_private_key`). Ensure the test function receives the `p11_config` fixture (most KAT functions already do via the shared-session fixture; add the parameter if missing). **Do not** alter the surrounding `try/except CkrAssertionError`/curve-availability logic; `pytest.skip` raised by `provision_*` is `BaseException` and flies past `except AssertionError`/`except CkrAssertionError` handlers unchanged (verified in Phase 1).

- [ ] **Step 1:** For each file, read the site + its test-function signature; confirm the `p11_config` fixture name and the `rs` variable.
- [ ] **Step 2:** Apply the substitution (RSA → `provision_rsa_private_key`, EC → `provision_ec_private_key` with the right `key_type`). Add imports.
- [ ] **Step 3:** Run the module-free guard tests + `uv run pytest tests/` (these files have no module-free unit coverage; rely on the gate suite for import/syntax). Run all four gates.
- [ ] **Step 4: Commit** `refactor(provisioning): route wycheproof+acvp private KAT setup through provision_*`.

---

### Task 6: Migrate hand-built private-key KAT sites

**Files:**
- `src/pkcs11_check/testcases/test_mech_sign.py:340` (RSA) and `:422` (EC/Edwards — `key_type` chosen by OID prefix; pass through)
- `src/pkcs11_check/testcases/test_oaep_parameter_fidelity.py:89` (RSA, runtime-generated key)
- `src/pkcs11_check/testcases/test_rsa_key_import.py:193` (RSA, runtime-generated key — `test_imported_private_key_signs`; NOT line 153 which tests import itself)
- `src/pkcs11_check/testcases/test_cctv_rfc6979.py:229` (EC P-256, bare `import_ec_private_key`)

Same substitution pattern as Task 5. For sites that currently use the bare `import_ec_private_key` (no negotiated wrapper), pass `ec_params` + `value` (the raw scalar) + `key_type` to `provision_ec_private_key`; the create path inside the helper uses `import_ec_private_key_negotiated`, which is the negotiation-capable superset (no behavior loss for create_available modules). Preserve the existing comments explaining the spec path; update them to note provisioning routing.

- [ ] **Step 1-2:** Read each site; apply substitution; add imports + `p11_config` fixture where missing.
- [ ] **Step 3:** Run `uv run pytest tests/` + all four gates.
- [ ] **Step 4: Commit** `refactor(provisioning): route hand-built private KAT setup through provision_*`.

---

### Task 7: Controller real-module validation (NOT a gate test)

**This task is executed by the controller (you), not a subagent, and produces no committed test.** It is the Phase-2 analogue of Phase-1's softhsm2 force-unwrap validation.

- [ ] Set up a fresh softhsm2 token (local build `/home/user/src/os/SoftHSMv2/src/lib/.libs/libsofthsm2.so`, which advertises `CKM_RSA_AES_KEY_WRAP`).
- [ ] Run, with `--key-inject=force-unwrap`, a representative slice: `wycheproof/test_wycheproof_rsa_decrypt.py`, `wycheproof/test_wycheproof_ecdh.py`, `acvp/test_acvp_eddsa.py` (or the controller harness `/tmp/p2_probe.py` extended to exercise `provision_rsa_private_key`/`provision_ec_private_key` directly).
- [ ] Confirm: each KAT **passes via the unwrap path** (not skipped), the injected key signs/decrypts/derives correctly, and `--key-inject=unwrap` on the same module takes the **create** path (verdict `create_available`) — i.e. injection does not perturb a normal module.
- [ ] Record results in the SDD ledger. Any failure → systematic-debugging, fix on the branch, re-review the fix.

---

## Notes / deferred

- **PQC (ML-DSA/SLH-DSA/ML-KEM) and DH/X9.42 private sites are NOT migrated in Phase 2.** Their unwrap payload format is module-specific and no current no-create docker target (freehsm-c/kmsp11/pico-hsm) implements those mechanisms, so unwrap is not viable there. Phase 4's broad sweep routes them through a **create-or-skip** wrapper (clean skip on no-create), which is the correct degradation. Recorded here so Phase 4 picks them up.
- **Provisioning-method structured recording** (the `ran_via_unwrap` counter + report) is **Phase 3**. Phase 2 emits a `compliance.note` only; Phase 3 adds the structured accumulator without changing `provision_*` signatures.
- After Task 7 passes, run the final whole-branch review (most-capable model) per subagent-driven-development, then merge to `dev` via finishing-a-development-branch.
