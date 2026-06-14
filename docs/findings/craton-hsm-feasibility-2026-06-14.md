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

## The fatal limitation (source + runtime evidence)

- `src/token/token.rs:175-176` — `Token::new_with_config` always constructs
  `so_pin_hash: RwLock::new(None)` and `user_pin_hash: RwLock::new(None)`.
- Only **lockout counters** are persisted (`persist_lockout` → `LockoutStore`); a repo-wide
  grep for serialization of `so_pin_hash`/`user_pin_hash` to the `EncryptedStore` returns
  nothing. `persist_objects = true` persists token **objects** (keys), NOT the SO/user PIN.
- **Runtime proof:** in the build, two consecutive `pkcs11-tool` calls (two processes):
  - process 1 `--init-token --so-pin SoPin1234` → `Token successfully initialized`
  - process 2 `--init-pin --pin … --so-pin SoPin1234` → `C_Login failed: CKR_TOKEN_NOT_RECOGNIZED (0xe1)`
  The SO PIN set in process 1 is gone in process 2.

This is by design: craton's multi-process story is its **gRPC daemon** (`craton-hsm-daemon`),
where one long-running process holds token state and clients connect. The in-process `.so` is
a single-process backend. pkcs11-check's isolation model is multi-process, so it cannot share
a provisioned token through the in-process module.

A craton-specific per-subprocess token-init hook in the suite would be required, which
violates the project's no-per-provider-special-casing principle. So craton is dropped here.

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
