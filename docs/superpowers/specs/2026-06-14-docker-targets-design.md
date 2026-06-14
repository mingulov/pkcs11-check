# New Docker Targets (craton-hsm, NetHSM, jcardsim spike) — Design

**Date:** 2026-06-14
**Status:** Draft for review
**Scope:** Add new PKCS#11 module targets to the docker test matrix, under a hard
no-network-at-runtime constraint. Decided scope: build **craton-hsm-core** and
**NetHSM** end-to-end; run a time-boxed **jcardsim/OpenSC** build spike before
committing to that (heavy) stack. **`google/native-pkcs11` is dropped** (not feasible).

---

## 0. Background: the no-network constraint (already shipped)

Requirement: *every* test container — existing and new — must run with **no external
network access** at run time, so a module that shipped hidden telemetry cannot phone
home. This is already implemented and merged on `dev`:

- `network_mode: none` added to the shared `x-common: &common` anchor in
  `docker/docker-compose.test.yml`, so all 23 existing services (and every new one that
  merges `<<: *common`) inherit it.
- Safe because the suite makes **zero outbound calls at run time** (vectors mounted
  read-only, artifacts to a mounted volume). `none` keeps the **loopback** interface, so
  localhost-only helper daemons (bouncyhsm HTTP server, tpm2 swtpm/abrmd) still work.
- **Build-time** network (git clone / curl / cargo / apt) is a separate phase and is
  unaffected — `docker compose run --build` builds with network, then runs isolated.
- Verified: `docker compose config` valid; all services render `network_mode: none`.

New targets inherit this for free. Any client-server module therefore **must co-locate
its server and the PKCS#11 module in one container, talking over `127.0.0.1`** (the
bouncyhsm/tpm2 pattern).

## 1. The established "new target" pattern (what every target must touch)

1. `docker/<name>/Dockerfile` — two-stage (builder with network → slim runtime). Must
   `COPY docker/fault-proxy.c` + `COPY docker/install-test-tools.sh` and run the latter
   (installs p11-kit, pkcs11-provider, fault-proxy).
2. `docker/<name>/run-<name>.sh` — only if a daemon/server must start before the suite;
   it sets `PKCS11_CHECK_MODULE` then execs `/app/docker/run-pkcs11-check.sh`.
3. `docker/docker-compose.test.yml` — a `test-<name>:` service merging `<<: *common`
   (inherits volumes + `network_mode: none`), with `PKCS11_CHECK_ARTIFACT_DIR` and
   `PKCS11_CHECK_PIN`.
4. `docker/test-all.sh` — add the name to `ALL_PROVIDERS` (or `HEAVY_PROVIDERS`).
5. `docker/provider-sources.toml` — `[sources.*]` + `[targets.<name>]` pins.

Module path is conveyed via `ENV PKCS11_CHECK_MODULE` (in-process modules) or set in the
run script (daemon-backed modules).

---

## 2. Target A — craton-hsm-core (FEASIBLE, low effort, build now)

**What:** pure-Rust PKCS#11 v3.0 software HSM (a SoftHSMv2 rewrite). In-process
`libcraton_hsm.so`, **no daemon, no network**. License Apache-2.0. No release tags →
build from `main`.

**Mirrors:** `docker/kryoptic/Dockerfile.main` (two-stage Rust build), minus the
OpenSSL-from-source stage (craton's default backend is RustCrypto, pure Rust).

**Build:**
- Stage 1 `rust:latest`: `git clone` the repo at the pinned commit; `cargo build
  --release` of **the root crate only** (NOT `--workspace` — the optional gRPC daemon
  needs `protoc`, and the `awslc`/`fips` features need `cmake`; default features =
  `rustcrypto-backend`, exactly what we want). Artifact: `target/release/libcraton_hsm.so`.
- Stage 2 `python:3.14-slim`: copy the `.so` to `/usr/lib/libcraton_hsm.so`; run
  `install-test-tools.sh` (provides `pkcs11-tool` via opensc for init); create a writable
  storage dir (`/var/lib/craton`); init the token.
- Token init (Dockerfile RUN, like kryoptic):
  `pkcs11-tool --module … --init-token --label pkcs11-check --so-pin 12345678`
  then `--init-pin --pin 1234 --so-pin 12345678`.
- Optional minimal `craton_hsm.toml` (storage_path, slot_count=1) at
  `CRATON_HSM_CONFIG` — library falls back to secure defaults if absent.
- ENV: `PKCS11_CHECK_MODULE=/usr/lib/libcraton_hsm.so`, `PKCS11_CHECK_PIN=1234`.
- **No run-script** (in-process). CMD = the standard
  `run-with-artifacts.sh → run-pkcs11-check.sh`.

**Expected coverage:** broad — RSA 2048/3072/4096, ECDSA P-256/P-384, Ed25519, AES-256
GCM/CBC/CTR, SHA-2 family, ECDH; **PQC**: ML-KEM-768, ML-DSA-44/65/87, SLH-DSA, hybrid
X25519+ML-KEM.

**Risks:** (1) default-slot assumption for `--init-token` (no `--slot` in upstream docs)
— smoke-test in build; a minimal TOML may be needed. (2) `redb` storage path must be
writable inside the image. (3) restrict build to the root crate to avoid protoc/cmake.

**provider-sources.toml:** `repo = github.com/craton-co/craton-hsm-core`, `kind =
git_branch`, `selector = main`, pin `commit = d3203bf1…` (no tags; CHANGELOG 0.9.1).

## 3. Target B — NetHSM (FEASIBLE-WITH-CAVEATS, medium effort, build now)

**What:** Nitrokey NetHSM — a REST-API HSM. The PKCS#11 module `libnethsm_pkcs11.so`
(Rust, tag `v2.2.0`) talks to the NetHSM server (keyfender) over HTTPS. Co-located in one
container over `127.0.0.1`, this complies with `network_mode: none`.

**Mirrors:** `docker/bouncyhsm/` (local HTTP server + wait + provision + run).

**Build (layering — to be confirmed by a short build check, see risks):**
- Stage 1 `rust:slim`: `git clone --branch v2.2.0
  github.com/Nitrokey/nethsm-pkcs11`; `cargo build --release` →
  `libnethsm_pkcs11.so`.
- Final stage: derive from `nitrokey/nethsm:testing` (ships the keyfender server) and add
  Python 3 + uv + `install-test-tools.sh` on top; **or**, if that base is too constrained,
  use `python:3.x-slim` and `COPY --from` the keyfender binary + `/data` seed out of the
  testing image. The spec's preferred path is *base-on-nethsm-testing*; the plan includes a
  build check to pick the working layering.
- Copy `libnethsm_pkcs11.so` → `/usr/lib/`. Write `/etc/nitrokey/p11nethsm.conf` with
  `url: https://127.0.0.1:8443/api/v1`, `danger_insecure_cert: true`, **both** an
  `operator:` and an `administrator:` credential block. With both present the module logs
  in as operator by default and **auto-escalates to administrator only for actions that
  need it (e.g. `C_GenerateKeyPair`)** — so the suite generates keys in-process; no REST
  key pre-provisioning is required.
- ENV: `PKCS11_CHECK_MODULE=/usr/lib/libnethsm_pkcs11.so`,
  `PKCS11_CHECK_PIN=<operator-password>`.

**`docker/nethsm/run-nethsm.sh`:**
```
trap 'kill keyfender' EXIT
start keyfender bound to 127.0.0.1:8443 (background, log to /tmp)
poll GET https://127.0.0.1:8443/api/v1/health/state  (curl -sk) until reachable
if state == Unprovisioned:            # idempotent guard (/data persists)
    PUT /api/v1/provision {unlockPassphrase, adminPassphrase, systemTime=$(date -u)}
poll until state == Operational
(admin) create the Operator user the .so will use
# keys are generated in-suite via C_GenerateKeyPair (module auto-escalates to admin),
# so no REST key generation is needed; optionally seed one key as a smoke check
export PKCS11_CHECK_MODULE=/usr/lib/libnethsm_pkcs11.so
exec bash /app/docker/run-pkcs11-check.sh
```
Provisioning via `nitropy`/`nethsm-sdk-py` (`pip install nethsm`) or raw `curl -k`. Only the
device provision + Operator-user creation happen over REST; key material is created by the
suite itself.

**Expected coverage (corrected — broader than first thought):** **keygen YES** via
`C_GenerateKeyPair`/`C_GenerateKey` (admin-escalated: RSA, EC P256/P384/P521/secp256k1/
Brainpool, EdDSA — brainpool/secp256k1 need NetHSM firmware ≥ v3.0); **sign YES** (RSA-PKCS,
RSA-PSS, ECDSA, EdDSA, with module-side or pre-hash SHA variants); **encrypt YES** (AES-CBC,
RSA-PKCS); **decrypt YES** (AES-CBC, RSA raw/PKCS/OAEP all-SHA); **C_GenerateRandom YES**;
admin-gated object create/destroy/set-`CKA_ID`. **Genuinely absent (skip by capability):**
**`C_Verify`** and **`C_Digest`** — hard-stubbed *by design* (a remote HSM exposes neither
public-key verify nor hashing; both are done client-side), plus **wrap/unwrap/derive** and
`C_InitToken`/`C_InitPIN`. These are real capability-absences → **skip**, exactly per
"capability genuinely absent → skip". Note for sign tests: round-trip verification must use
an off-module/software verify with the public key, since the module's `C_Verify` is absent.

**Risks:** (1) keyfender packaging/layering (heaviest unknown — the build check resolves
it). (2) provisioning determinism: `systemTime` must be set (NetHSM refuses ops with an
unset clock); guard provision behind the `Unprovisioned` state check; a documented `406
Accept-header` quirk may need a relaxed header / pinned client. (3) pin a NetHSM **server
tag/digest** known-good for RSA-PKCS (v3.0 had a PKCS1 bug; v3.1/v4.0 fine) and ≥ v3.0 for
brainpool/secp256k1 keygen. (4) keygen depends on the `administrator:` block being present
in `p11nethsm.conf` — if omitted, keygen fails; the build/run must include it.

**provider-sources.toml:** `[sources.nethsm_pkcs11_release] git_tag v2.2.0`;
`[sources.nethsm_server] docker_image nitrokey/nethsm:testing` (tag/digest-pinned — a
deliberate exception to source-build, noted in the manifest comment, since keyfender is an
OCaml/MirageOS stack that is not a simple from-source build).

## 4. Target C — jcardsim / vsmartcard / OpenSC (FEASIBLE-WITH-CAVEATS, HIGH — spike first)

**What:** a simulated ISO-7816 PKI smartcard exposed as PKCS#11 — a *new target class* the
suite lacks (smartcard timing/APDU limits/restrictive error codes). Chain (all localhost):
`opensc-pkcs11.so → pcscd → vpcd/libifdvpcd.so (TCP 127.0.0.1:35963) → vpicc (jcardsim
JVM) → IsoApplet`.

Heaviest target in the repo (more than tpm2): a 3-daemon chain (pcscd + JVM simulator +
the suite) across **two toolchains** (Java + C/autotools) on the Python base. **So we run a
time-boxed build spike, not a full integration, in this round.**

**Spike goal — validate the two assumptions that gate a full build:**
1. **Build:** does IsoApplet `v0.6.1` compile against the jcardsim Maven jar
   (`com.klinec:jcardsim`, Apache-2.0) **without the Oracle Java Card SDK**? (jcardsim
   bundles `javacard.framework.*`, so `javac -cp jcardsim.jar IsoApplet/src/**.java`
   should suffice — this avoids the only proprietary dependency. Must be proven.)
2. **Runtime + crash model:** does the chain produce a working reader
   (`opensc-tool --list-readers` shows "Virtual PCD") with a provisioned RSA/EC key via
   `pkcs15-init`, and **how does the suite's crash/fault model behave** when the "module"
   (`opensc-pkcs11.so`) stays alive and a fault surfaces as `CKR_DEVICE_*` / reader
   disconnect rather than `returncode < 0`? (The runner's `_status_from_returncode`
   assumes in-process native crashes.)

**Spike deliverable:** `docker/jcardsim/Dockerfile.spike` + a short findings note
(`docs/findings/jcardsim-spike-2026-06-…md`) with a **go/no-go** and, if go, the concrete
`run-jcardsim.sh` + wiring for a follow-up full-integration plan. **Not** added to
`test-all.sh` until the spike passes.

**Licenses:** OpenSC LGPL-2.1 (sep `.so`) ✓; vsmartcard GPL-3.0 (sep daemon) ✓; jcardsim
Apache-2.0 (Maven Central) ✓; IsoApplet GPL-3.0 — copyleft but a separate runtime applet
artifact, not linked ✓; **Oracle Java Card SDK proprietary — must NOT be baked in**
(avoided via the jcardsim-jar compile).

**Expected coverage (if integrated):** RSA 2048/3072/4096 (PKCS1 sign, raw decrypt;
host-side hashing via OpenSC), ECDSA (secp256r1/384r1/brainpool/k1). No symmetric, no
on-card digest, no ECDH.

**Source pins:** OpenSC `0.27.1`; vsmartcard `virtualsmartcard-0.10`; jcardsim
`com.klinec:jcardsim 3.0.5.0+`; IsoApplet `v0.6.1`.

---

## 5. Validation approach

- I author all artifacts (Dockerfiles, run scripts, compose/test-all/provider-sources
  edits). `docker compose config` is validated locally after wiring.
- Full image **builds/runs are heavy and need build-time network** → run by the user via
  `./docker/test.sh craton-hsm` / `./docker/test.sh nethsm` (and the spike via a direct
  `docker build -f docker/jcardsim/Dockerfile.spike`). Per repo convention, statistics are
  **not** committed to docs from these runs (official-release only).
- No regressions to existing targets: the only shared-file change already made is the
  `network_mode: none` anchor (verified). New services are additive.

## 6. Out of scope / explicitly dropped

- **`google/native-pkcs11`** — no Linux backend; `C_GenerateKeyPair`/`C_CreateObject`
  stubbed to `CKR_FUNCTION_NOT_SUPPORTED`; empty token; sign-only even in theory. Dropped.
- **jcardsim full integration** — gated behind the spike's go/no-go.
- Updating module-issues.md / stats — only after deliberate official runs.

## 7. Open questions for review

1. NetHSM layering preference — OK to **base the final image on `nitrokey/nethsm:testing`**
   (add Python on top) with a build check, falling back to copying keyfender into
   `python:slim` only if needed?
2. craton storage persistence — keep token storage **inside the image** (`/var/lib/craton`,
   ephemeral per run) rather than a mounted volume? (Matches other in-process targets;
   each run starts clean.)
3. jcardsim spike time-box — target a single Dockerfile.spike + findings note this round,
   no compose wiring until go. Acceptable?
