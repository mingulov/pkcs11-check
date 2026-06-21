# Key-Provisioning Injection Layer — Design Spec

**Date:** 2026-06-21
**Status:** Design (approved in brainstorming; pending spec review)
**Repo:** `pkcs11-check` (framework), branch `dev`
**Related:** the `C_CreateObject`-unavailable mis-classification (321 `unclassified/HIGH` in
`wycheproof/test_wycheproof.py` + `acvp/test_acvp_ecdsa.py`, ~30 more in sibling files);
`testcases/conftest.py::skip_unless_create_object_supported`; `testcases/_negotiation.py`.

---

## 1. Problem & Goal

KAT/vector and other object-dependent tests need a **specific, given** key (or object) in the
token to exercise an operation. Today that setup goes through `C_CreateObject` (plaintext import).
On modules that do not implement `C_CreateObject`, the import raises and the dependent tests either
**mis-classify** (the 321 `unclassified/HIGH` hard-fails) or skip inconsistently.

**Providers in the matrix that lack `C_CreateObject`** (2026-06-21 pool): `freehsm-c` (46,956
skips — actually a one-line export bug, temporary), `kmsp11` (19,423 — cloud-KMS proxy, durable),
`pico-hsm` (1,303 — OpenSC sc-hsm, durable). The **durable, real-world** driver is broader:
production high-security HSMs routinely **prohibit plaintext secret/private-key import** and
**mandate wrapped import** via `C_UnwrapKey`. A conformance suite must be able to provision KAT
material on such modules.

**Goal:** a configurable **key-provisioning layer** that gets a setup object into the token by the
best available means — `C_CreateObject`, else (opt-in) `C_UnwrapKey` under a wrapping key, else a
clean, well-classified skip — applied across **all** setup-create sites, with a per-module
provisioning capability profile and report.

**Non-goals / hard limits (PKCS#11 facts, not suite limitations):**
- **Public keys, certificates, and data objects have no provider-general alternative to
  `C_CreateObject`.** `C_UnwrapKey` produces only secret/private keys; there is no unwrap-public,
  generate-certificate, or import-cert. Verify-only KATs (public key only) and cert/data tests
  therefore **create-or-skip**.
- **EC keys cannot be a wrapping key** (no base-PKCS#11 EC encrypt/unwrap mechanism). RSA is the
  bootstrap wrapping key; symmetric (AES-KWP) is the other option.

## 2. Object-class provisioning matrix

| Class | Setup sites (approx) | Injectable without `C_CreateObject`? | Strategy |
|---|---|---|---|
| Secret (AES/HMAC) | 43 sites / 25 files | **yes** — `C_UnwrapKey` | create → unwrap → skip |
| Private (EC/RSA/PQC) | ~11 sites | **yes** — `C_UnwrapKey` (sign/decrypt/ECDH KATs that ship the private key) | create → unwrap → skip |
| Public (EC/RSA/DSA/PQC) | ~36 sites | **no** | create → skip |
| Certificate (`CKO_CERTIFICATE`) | 23 lines / 6 files | **no** | create → skip |
| Data (`CKO_DATA`) | 168 lines / 21 files | **no** (already has `skip_if_data_objects_unsupported`) | create → skip |

The "operation-flip" insight: many tests that look public-facing actually ship the **private**
key — ACVP SigGen (sign), Wycheproof RSA *decrypt* vectors, ECDH — and private keys are
unwrappable. Those are rescued. Fixed **verify** vectors (public key only) are not.

## 3. Architecture

New module **`src/pkcs11_check/testcases/_provisioning.py`** (sibling to `_negotiation.py`).

### 3.1 `ProvisioningProfile`
Probed once per session, cached on the `RawSession` (`rs`). Pure capability detection, no provider
identity. For each object class it derives a **create-availability verdict** from a **valid,
representative `C_CreateObject` probe** (a small valid AES key for `secret`; a valid throwaway
EC/RSA private key for `private`; cleaned up via `destroy_quietly` on success):

| Probe outcome on **valid** material | Verdict | Why |
|---|---|---|
| `CKR_OK` | `create_available` | plaintext create works → use create; later create failures surface as findings |
| `CKR_FUNCTION_NOT_SUPPORTED` | `create_absent` | function not implemented → unwrap-or-skip |
| clean refusal (e.g. `CKR_TEMPLATE_INCONSISTENT` / `CKR_FUNCTION_NOT_PERMITTED` / `CKR_KEY_UNEXTRACTABLE` on **valid** material) | `create_prohibited` | module **policy** forbids plaintext import (the high-security-HSM case) → unwrap-or-skip |

Deciding create-availability **once, from a valid-material probe**, is what keeps the layer safe: a
per-call create failure on a `create_available` module is a **real finding** (surfaces normally),
never silently re-routed to unwrap. The profile also records whether `C_UnwrapKey` works and which
wrapping strategies are bootstrappable (RSA keygen + a wrap mech + `CKA_UNWRAP`; or readable AES
keygen; etc.).

### 3.2 Entry points
```python
def provision_secret_key(rs, key_type, value, attrs, *, label) -> int      # handle, or pytest.skip
def provision_private_key(rs, key_spec, *, label) -> int                   # EC/RSA/PQC private
# NO provision_public_key / provision_certificate / provision_data:
# public/cert/data stay explicit create-or-skip via the profile.
```
Resolution is driven by the profile's create-availability verdict + the configured mode:
- verdict `create_available` → **`create`** (a later create failure is a real finding, not an
  unwrap trigger).
- verdict `create_absent` / `create_prohibited` → **`unwrap`** if inject is enabled and a wrapping
  path exists, else **`skip`**.
- mode `force-unwrap` → **`unwrap`** without attempting create at all (validation; and deployers
  whose HSM is known to prohibit plaintext import, avoiding a guaranteed-refused create call).

**`provision_*` is for VALID key material only** — it is the "get me this fixture object" path.
Tests that intentionally provision *invalid* material to probe creation-rejection (e.g. an
out-of-range key) MUST keep calling `create_object`/`import_*` directly: those test creation and
must not be re-routed through unwrap (whose rejection behaviour differs). Injection is **invisible
to the test verdict**: a test provisioned via unwrap still passes/fails on the *target operation*
exactly as via create. The **unwrap template mirrors the create template minus value-bearing attrs**
(`CKA_VALUE`/`CKA_VALUE_LEN` come from the wrapped blob, not the template). Provisioned objects and
the bootstrap wrapping keypair are **session objects** (`CKA_TOKEN=False`), destroyed by the
caller's existing teardown / at file end. Plain `import_secret_key`/`create_object`/`import_*`
recipes stay unchanged; the public-key negotiated importers (`import_*_negotiated`) compose
orthogonally (they negotiate *template shape*; provisioning chooses the *injection method*).

### 3.3 `WrapContext` + extensible `WrapStrategy` registry
Built once per session when inject is enabled; holds the wrapping key + a software-side wrap
function. **`WrapStrategy` is a pluggable protocol** (so new algorithms are a one-class extension):
```python
class WrapStrategy(Protocol):
    name: str
    def probe(self, profile) -> bool: ...                 # usable on this module?
    def max_target_size(self) -> int | None: ...          # None = unbounded
    def wrap(self, pub_material, target_bytes) -> bytes: ...   # software side -> blob
    unwrap_mech: CKM
    def unwrap_params(self) -> Any: ...
```
The context selects the first usable strategy by preference (config-overridable via `--wrap-mech`),
respecting `max_target_size` for the target.

## 4. Wrapping-strategy ladder

Selected by `ProvisioningProfile` + target size:

1. **`RsaAesKeyWrap`** (`CKM_RSA_AES_KEY_WRAP`, envelope) — **primary.** RSA-OAEP-wrap an ephemeral
   AES KEK + AES-KWP-wrap the target, one `C_UnwrapKey`. **Any key size** (incl. ~1.2 KB RSA
   private keys) — and the **RSA bootstrap key size is independent of the target**, because RSA
   only wraps the 32-byte KEK; **RSA-2048 suffices** regardless of target size (the AES-KWP layer
   carries the large payload). Verified buildable in software (`cryptography`) and advertised by
   softhsm2/opencryptoki.
2. **`RsaOaep`** (`CKM_RSA_PKCS_OAEP`) — fallback for **small** targets only (≤ modulus − 2·hashlen
   − 2: 190/318/446 B for RSA-2048/3072/4096). Fits AES/HMAC and EC private keys; **cannot** fit RSA
   private keys.
3. **`AesKwp`** (`CKM_AES_KEY_WRAP_KWP`) + symmetric KEK — any size. KEK obtained via readable
   `C_GenerateKey(AES, SENSITIVE=False, EXTRACTABLE=True)` (read back its value) or via
   `--wrap-key-value`. For AES-KWP-only modules.
4. **(future) `MlKemKemDem`** — worst-case path for **PQC-only modules** with no RSA wrapping.
   KEM-DEM: module generates an ML-KEM keypair → encapsulate to its public key → AES-KWP-wrap the
   target under the shared secret → `C_DecapsulateKey` + `C_UnwrapKey`. Framework plumbing
   (`C_EncapsulateKey`/`C_DecapsulateKey`, `CKM_ML_KEM`) already exists; **blocked only on a
   software-side ML-KEM source** (`cryptography` 46 does not yet expose ML-KEM). Documented as a
   future registry rung; slots in with no changes elsewhere.
5. **none viable → skip** (`"no wrapping path"`), recorded in the provisioning report.

EC keys are intentionally **not** a wrapping strategy (no standard EC encrypt/unwrap mechanism).

### 4.1 `CKM_RSA_AES_KEY_WRAP` blob (software construction)
`blob = RSA-OAEP(pub, T) ‖ AES-KWP(T, target)` where `T` is a fresh AES-256 KEK. **The software
OAEP params (MGF1 hash, hash alg, empty label) MUST be byte-identical to the
`CK_RSA_AES_KEY_WRAP_PARAMS.pOAEPParams` passed to the module** — any mismatch fails the unwrap;
fix the params to `CKM_SHA256`/`CKG_MGF1_SHA256`/`CKZ_DATA_SPECIFIED` empty-label and assert the
round-trip in the meta-tests. The param structs (`CK_RSA_AES_KEY_WRAP_PARAMS`,
`CK_RSA_PKCS_OAEP_PARAMS`) already exist in `raw/types_std.py`. Target encoding: secret keys = raw
`CKA_VALUE` bytes; private keys = PKCS#8 DER. Built with `cryptography`
(`OAEP` + `aes_key_wrap_with_padding` + `private_bytes(PKCS8, DER, NoEncryption)`).

## 5. Configuration surface

Deployment config (provider-general — like `--pin`/`--p11-slot`; **never** per-module hardcoding),
in `config.py::P11TestConfig`:

| Flag / TOML | Default | Meaning |
|---|---|---|
| `--key-inject {off,unwrap,force-unwrap}` | `off` | `off`: create → skip. `unwrap`: create → unwrap → skip. `force-unwrap`: unwrap → skip (no create attempt). |
| `--wrap-key-source {bootstrap,configured}` | `bootstrap` | self-generated wrapping key vs a pre-loaded one. |
| `--wrap-key-label` / `--wrap-key-handle` | — | configured in-token wrapping key. |
| `--wrap-key-value <hex>` | — | only for a **symmetric** configured KEK (software-side wrap). |
| `--wrap-mech <CKM>` | auto | override the auto-selected unwrap mechanism. |
| `--wrap-rsa-bits {2048,3072,4096}` | `2048` | bootstrap RSA size. Default 2048: in the envelope, RSA wraps only the 32-byte KEK, so size is independent of target. Bump only if the `RsaOaep` *fallback* must directly wrap a 191–318 B target (e.g. a large HMAC key) on a module lacking `CKM_RSA_AES_KEY_WRAP`. |

## 6. Classification & correctness rules (integrity-critical)

- **Injection never hides a finding.** It affects only *setup*; the target-operation verdict is
  unchanged. A KAT that runs via unwrap and then produces wrong output is still a real `fail`.
- **Injection failure → `skip`** (capability absent for provisioning), never a target-op `fail`,
  with specific reasons: `"Module does not implement C_CreateObject"`, `"Module prohibits plaintext
  key import (policy)"`, `"no wrapping path"`, `"unwrap mechanism absent"`, `"target too large for
  available wrap mechanism"`, `"no wrapping key: not logged in"`.
- **A `create_available` module never silently routes to unwrap.** If a specific `provision_*`
  create fails on a `create_available` module, that is a real finding and is re-raised to the
  caller's normal classification — `provision_*` swallows nothing.
- **Value-integrity check:** when the injected key is non-sensitive, read back `CKA_VALUE` and
  assert it equals the vector before running the op (catches a buggy unwrap corrupting setup). When
  sensitive, trust the wrap/unwrap roundtrip and record a `compliance.note` of the injection method.
- Provisioning method (create vs unwrap-via-`<mech>`) is recorded for transparency.

## 7. Visibility — capability profile + provisioning report

- `ProvisioningProfile` drives every setup site; per-class create-absence/prohibition is recorded
  by **one dedicated conformance test** (e.g. `test_provisioning_capability.py`) as a single
  **`xfail` / `honest_deviation`** ("core `C_CreateObject` not available for class X") — `C_CreateObject`
  is a base-spec function, so its absence is a recorded conformance deviation, **not** a crypto/policy
  `fail`, and not thousands of silent skips. The dependent tests still `skip` (capability absent);
  this is the one *visible* record of the cause.
- A **provisioning report** rides in the run artifacts (like coverage): per module,
  `ran_via_create / ran_via_unwrap / skipped_no_path`, by object class — making the currently
  invisible 47k/19k/1.3k skips explicit.

## 8. Default vs opt-in

- **Default (always):** `C_CreateObject` absent → clean, well-classified **skip** — fixes the 321 +
  ~30 mis-classifications with no matrix-number surprises.
- **Opt-in (`--key-inject=unwrap`):** try unwrap-injection before skipping, so a deployer with a
  wrapping-capable HSM actually runs the tests.

## 9. Testing & validation

- **Force-unwrap on a full module (primary validation):** run secret/private KAT sites against
  **softhsm2** (supports both create *and* `CKM_RSA_AES_KEY_WRAP`/OAEP/AES-KWP) with
  `--key-inject=force-unwrap` → create is skipped and every KAT must still **pass via the unwrap
  path**, with the value-integrity check holding. Validates injection end-to-end with **zero
  dependence on a no-create provider**. opencryptoki is a second such module. A negative validation
  also runs with `--key-inject=unwrap` on softhsm2 and confirms it took the **create** path (verdict
  `create_available`), i.e. inject does not perturb a normal module.
- **Unit/meta-tests** in `tests/`: `ProvisioningProfile` per-class probe; `WrapStrategy` selection
  by profile+size (envelope chosen for RSA-private, OAEP rejected on size, AES-KWP fallback);
  software blob construction round-trips (software-wrap → software-unwrap); FNS→skip gate; config
  parsing.
- **Real no-create providers** (freehsm-c/kmsp11/pico-hsm) validate the **clean-skip** path and the
  report; where their unwrap happens to work, that is bonus coverage (not required).
- All standard gates: `ruff format --check`, `ruff`, `mypy --strict`, full `pytest tests/`.

## 10. Phasing (drives the implementation plan)

1. **Core + secret keys + default skip.** `ProvisioningProfile` (per-class probe), `WrapContext` +
   `RsaAesKeyWrap`/`RsaOaep`/`AesKwp` strategies, `provision_secret_key`, config. Migrate wycheproof
   secret-key classes + acvp secret sites. Make the 321 + ~30 skip cleanly by default. Force-unwrap
   validation on softhsm2.
2. **Private-key injection.** `provision_private_key` (sign / RSA-decrypt / ECDH), PKCS#8 target
   encoding, per-key-type unwrap templates. Migrate those KAT sites.
3. **Visibility.** Provisioning report + dedicated create-absent finding + per-class probe surfaced.
4. **Broad sweep.** Remaining setup-create sites (public/cert/data → clean profile-driven skip);
   audit the 82 `create_object` setup sites and route the setup ones through the profile.
5. **(future) `MlKemKemDem` strategy** once a software ML-KEM source is available.

## 11. Risks & open questions

- **Software ML-KEM** unavailable in `cryptography` 46 → ML-KEM rung deferred (Phase 5).
- **Target encoding for private-key unwrap** (PKCS#8 vs raw) is mechanism/spec-defined; validate
  per key type against softhsm2 during Phase 2.
- **`CKM_RSA_AES_KEY_WRAP` parameter marshalling** — the param structs already exist
  (`CK_RSA_AES_KEY_WRAP_PARAMS`, `CK_RSA_PKCS_OAEP_PARAMS` in `raw/types_std.py`); the OAEP params
  must match the software blob exactly (§4.1), covered by the round-trip meta-tests.
- **Bootstrap key lifecycle**: generated once per test file (session object, cached on `rs`,
  `CKA_UNWRAP=True`), destroyed at file end; per test for `p11_raw_session` files. Per-file
  subprocess isolation means it cannot be shared across files — one keygen per file-process on a
  no-create module under inject (acceptable, opt-in; RSA-2048 keeps it cheap).
- **Login state**: bootstrap keypair gen and private-key unwrap may require a logged-in session /
  `CKA_PRIVATE`. When `p11_config.pin` is `None` the layer cannot bootstrap a private unwrap key →
  it reports no wrapping path → `skip` (recorded), never a hang or a fail.
- **`create_prohibited` probe side-effect**: the profile's valid-material create probe creates a
  throwaway object on `create_available` modules; it is destroyed immediately (`destroy_quietly`)
  and uses `CKA_TOKEN=False`.
- **Performance**: one RSA-2048 keygen per file on no-create modules under inject; negligible.
