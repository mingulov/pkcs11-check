# craton-hsm-core — Docker target feasibility (2026-06-14)

**Verdict: NOT-FEASIBLE in-process for pkcs11-check.** The target was added, fully debugged
to the point where the image builds and `C_Initialize` succeeds, then **removed** after a
runtime-proven, fundamental incompatibility: craton's in-process PKCS#11 mode keeps token
authentication state **in memory per process**, so a token provisioned in one process is not
visible in any other. pkcs11-check runs each test *file* in its own subprocess (segfault
survival), so every subprocess would see a fresh, unprovisioned token and fail at `C_Login`.

Repo: `https://github.com/craton-co/craton-hsm-core` (Apache-2.0, no release tags; built from
`main@d3203bf`). Pure-Rust software HSM (SoftHSMv2 rewrite). cdylib **package** `craton-hsm`,
**lib** `craton_hsm` → `libcraton_hsm.so`.

## The fatal limitation — the PKCS#11 `.so` is entirely in-memory (source + runtime proof)

craton **does** have a complete persistence layer — `EncryptedStore` (redb, AES-256-GCM under
a user-PIN-derived PBKDF2 key, `src/store/encrypted_store.rs`), `ObjectStore::with_persistence`
+ `set_persist_key` + `load_from_store` (`src/store/attributes.rs`). The catch: **it is wired
nowhere in the production path — only in `tests/persistence.rs`.**

1. **Objects are never persisted by the module.** `C_Initialize` (`functions.rs:310`) does
   `Arc::new(HsmCore::new(&config))`. `HsmCore::try_new` (`core.rs:146`) **hardcodes
   `object_store: ObjectStore::new()` (in-memory) and never reads `config.token.persist_objects`.**
   It never constructs `ObjectStore::with_persistence(...)`. So in the PKCS#11 `.so`,
   `persist_objects = true` is a **no-op** — no config or env can change this; it needs a code change.
2. **Token auth/init-state is never persisted, anywhere.** `Token::new_with_config`
   (`token.rs:175-176`) always constructs `so_pin_hash: None` / `user_pin_hash: None`. Only
   **lockout counters** are persisted (`persist_lockout` → `LockoutStore`); a repo-wide grep for
   serialization of `so_pin_hash`/`user_pin_hash` returns nothing (not even in tests).
3. **Runtime proof** (two consecutive `pkcs11-tool` calls = two processes, same filesystem):
   - process 1 `--init-token --so-pin SoPin1234` → `Token successfully initialized`
   - process 2 `--init-pin --so-pin SoPin1234` → `C_Login failed: CKR_TOKEN_NOT_RECOGNIZED (0xe1)`
   (`error.rs:132` maps `TokenNotInitialized → CKR_TOKEN_NOT_RECOGNIZED`.) The token from
   process 1 does not exist in process 2.

pkcs11-check runs each test *file* in its own subprocess (segfault survival), so a token
provisioned at build time (or by any prior process) is invisible at run time → every login
fails. craton's multi-process story is its **gRPC daemon** (`craton-hsm-daemon`); the
in-process `.so` is single-process and, at `main@d3203bf`, fully in-memory.

**No setting fixes this.** Making craton in-process usable for the suite needs an UPSTREAM
change: wire `ObjectStore::with_persistence` into `HsmCore` on `persist_objects=true`, AND add
token-init-state persistence (which does not exist). A suite-side per-subprocess token-init
hook would violate the project's no-per-provider-special-casing principle.

## This is a craton BUG (docs/config promise persistence the code doesn't deliver)

craton's own docs document `persist_objects` as working:
- `docs/fork-safety.md:51`: "When persistence is enabled (`persist_objects = true`), the
  `EncryptedStore` acquires an exclusive file lock … at `C_Initialize` time."
- `docs/tested-platforms.md`: "Persistent storage (redb) ✅ ✅ ✅"; `docs/install.md` documents
  `storage_path` + `persistence.enabled=true`.

But **both** production entry points — the PKCS#11 `.so` AND the gRPC daemon
(`*/daemon/.../main.rs: HsmCore::new(&hsm_config)`) — go through `HsmCore::try_new`, which
hardcodes the in-memory `ObjectStore::new()` and never reads `persist_objects`. Only
`tests/persistence.rs` / `tests/crypto_vectors_phase2.rs` construct `ObjectStore::with_persistence`
directly (bypassing `HsmCore`), so the unit tests pass while the integration is missing — no
test catches that `persist_objects` is a silent no-op. **Conclusion:** file persistence is
designed, documented, and unit-tested, but the wiring into `HsmCore` was forgotten. Worth an
upstream report.

## Resolution chosen: Option A — auto-init token from config (patch)

Rather than fix persistence (objects + the absent token-auth persistence), the suite only needs
each subprocess to present a *provisioned* token. A small craton patch
(`docker/craton-hsm/patches/`) adds `[security] initial_so_pin` / `initial_user_pin` config
fields and, in `Token::new_with_config`, sets the SO/user PIN hashes + `initialized` flags from
them — so every process self-provisions identically at `C_Initialize`. The suite logs in and
generates its own keys in-memory per test file (no cross-process persistence needed). This is a
provisioning patch (not bug-hiding); craton's crypto behavior is tested unmodified.

## What WAS solved (recipe, for any future daemon-mode attempt)

These were all real and are resolved — only the persistence limitation is fatal:

1. **Build:** `cargo build --release -p craton-hsm` (hyphenated package; `--workspace` also
   builds `pkcs11-spy` and pulls protoc/cmake via the daemon/awslc features). Mirrors the
   kryoptic two-stage Rust build; no OpenSSL stage (RustCrypto default backend).
2. **Integrity (POST):** `C_Initialize` runs `run_post()`, whose first step is
   `check_integrity()`. Our locally-built `.so` is unsigned (embedded public key is the
   all-zeros placeholder), so it refuses to start unless
   `CRATON_HSM_INTEGRITY_BYPASS=unsafe-dev-only` is set (craton's documented dev/test escape
   hatch). With it set, POST passes (all KATs OK).
3. **Config path must be RELATIVE:** `validate_config_path` runs the same path-safety check as
   `storage_path` and **rejects absolute paths**, so `CRATON_HSM_CONFIG=/etc/...` →
   `CKR_GENERAL_ERROR`. Use craton's default lookup of `craton_hsm.toml` in the CWD.
4. **`storage_path` must be relative** too (same validator).
5. **PIN complexity:** `validate_pin` requires `>= PIN_MIN_CHAR_CLASSES (2)` character classes
   and `>= PIN_MIN_DISTINCT_BYTES (3)` distinct bytes; digit-only PINs (`1234`, `12345678`)
   are rejected `CKR_PIN_INVALID`. Multi-class PINs (e.g. `SoPin1234`, `UserPin1`) pass.

## Recommendation

- **Dropped** from the docker matrix (compose / test-all.sh / test_pool.py / provider-sources)
  to avoid an all-login-fail target. NetHSM is the delivered new target in this round.
- If craton is wanted later, the path is its **gRPC daemon + a daemon-client PKCS#11 module**
  (a different integration than the in-process `.so`), or an upstream change that persists
  token auth in the in-process mode. Both are out of scope here.
