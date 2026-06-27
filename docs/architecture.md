# Architecture

## Two test directories

- `src/pkcs11_check/testcases/` - the PRODUCT: PKCS#11 tests run against hardware/software modules
- `tests/` - META-TESTS: tests for pkcs11-check's own code (config parsing, markers, CLI)

## Test vector data (`data/`)

- `src/pkcs11_check/testcases/data/sources.toml` - tracked manifest: pinned commits, SHA-256 checksums, include filters (ships in wheel)
- `data/.gitignore` - tracked, ignores extracted directories
- `data/wycheproof/`, `data/cctv/`, `data/acvp/`, `data/x509-limbo/` - gitignored, fetched by `pkcs11-check fetch-data`
- Own test data (mechanism_vectors, KAT JSONs) stays in `src/pkcs11_check/testcases/data/` (tracked)
- Override data location with `PKCS11_CHECK_DATA_DIR` env var

## Core modules

- `core/loader.py` - PKCS#11 module loading with v2.40/v3.0/v3.1/v3.2 interface negotiation
- `core/file_runner.py` - main isolated runner for `auto|file|test`, with resume, adaptive promotion, and aggregated reports
- `core/preflight.py` - collection-safe capability probe written through a helper subprocess manifest
- `core/collection.py` - pytest item metadata collection for marker-aware isolation planning
- `core/isolation.py` - lower-level `spawn` helper retained for focused tests and future integration
- `config.py` - four-layer config: CLI > env > TOML > defaults
- `plugin.py` - pytest11 entry point, registers markers, fixtures, collection hooks
- `fixtures.py` - p11_raw_session / p11_session (function-scoped, fresh session per test), p11_module_session (module-scoped, self-healing for fast verification tests), p11_module, p11_config, p11_interface_version
- `testcases/conftest.py` - shared helpers: get_pin_bytes(), extract_ec_point()
- `testcases/ckr/` - CKR error coverage tests (102 tests, 21 files). Use `--ckr-strict` for exact spec compliance

## Raw PKCS#11 access (`pkcs11_check.raw`)

Pure Python ctypes binding - no C compilation. All 68 v2.40 functions + v3.0 message-based + v3.2 KEM functions. Returns raw CK_RV integers.

```python
from pkcs11_check.raw.api import RawPKCS11
raw = RawPKCS11.from_lib("/path/to/module.so")
rv = raw.C_GetTokenInfo(slot_id, byref(token_info))
```

Use in subprocess for NULL/segfault tests (`subprocess.run([sys.executable, "-c", script])`).

## Local builds (`local-builds/`)

- `providers/<name>.sh` - one file per token with `build()` and `setup()` functions
- `build.sh` - dispatcher: `bash local-builds/build.sh kryoptic [branch]`
- `test.sh` - dispatcher: `bash local-builds/test.sh kryoptic [pytest-args]`
- `reset.sh` - reset token data: `bash local-builds/reset.sh kryoptic`

## Test categories

Core: interface, slot, object, mechanism, encrypt, sign, digest, errors
Cross-verification: AES-ECB/GCM, RSA PKCS/PSS/OAEP, ECDSA, EdDSA, HMAC, digest
NIST KAT: SHA family, AES-ECB from SP 800-38A
Wycheproof: ECDSA, RSA, ECDH, DSA, AES, HMAC, EdDSA, ChaCha20, X25519/X448, HKDF
PQC (v3.2): ML-KEM, ML-DSA, SLH-DSA
Key management: import, export, copy, wrap/unwrap, derive, KEM
Security: attribute fuzz, Tookan vectors, handle reuse, padding oracle, ECDSA nonce, RNG stats
CVE regression: 29 tests across NSS, SoftHSM2, TPM2, OpenCryptoki, BouncyHSM, Kryoptic
CKR spec compliance: exact return code verification per PKCS#11 standard
Interop: OpenSSL pkcs11-provider, p11-kit proxy
Stress: 1000-cycle ops, threading, resource exhaustion, DB concurrent writes
Fuzz: Hypothesis property tests, attribute template fuzzer

See [test-universe.md](test-universe.md) for the current collected product-test
counts by group and the AES-CTS single-provider maximum.
See [interpreting-results.md](interpreting-results.md) for guidance on why xfail and fail counts can be large.

## Docker test matrix

- `test-softhsm2` / `test-softhsm2-generated-iv` / `test-softhsm2-main` - SoftHSM2 2.7.0 / generated-IV simulator / main
- `test-kryoptic` / `test-kryoptic-main` / `test-kryoptic-fips` - Kryoptic v1.5.1 / main / FIPS
- `test-nss` / `test-nss-pqc` / `test-nss-main` - Fedora NSS packages / NSS official source tags / NSS source tip
- `test-opencryptoki` / `test-opencryptoki-master` - OpenCryptoki 3.27.0 / master
- `test-wolfpkcs11` / `test-wolfpkcs11-master` - wolfPKCS11 v2.0.0-stable / master with PKCS#11 v3.2 ML-DSA/ML-KEM enabled
- `test-corepkcs11` - corePKCS11 v3.6.4 MbedTLS software mock with a test adapter
- `test-optee-pkcs11` - OP-TEE 4.10.0 `qemu_v8` heavy/manual target running in guest Linux against `libckteec.so`
- `test-tpm2` - source-built tpm2-pkcs11 1.10.0 + swtpm
- `test-bouncyhsm` - BouncyHSM 2.1.1
- `test-pkcs11-mock` - pkcs11-mock v2.0.0 stub

## Key design decisions

- `pkcs11_check.raw` is the sole PKCS#11 access layer: pure ctypes, v2.40-v3.2 interface negotiation, PQC mechanisms, generated type/metadata from vendored PKCS#11 headers
- `pkcs11-check test` defaults to `--isolation auto`; explicit `--isolation none` is the unsafe fast path
- **Provider/proxy-restart recovery (bounded wait-and-reconnect):** when a *proxied* provider crashes and pkcs11-proxy-ng restarts it, the surviving client module returns a connection-lost CK_RV for the whole restart window (`CKR_CRYPTOKI_NOT_INITIALIZED`, a stale `CKR_SESSION_HANDLE_INVALID` / `CKR_SESSION_CLOSED`, or a transport `CKR_DEVICE_ERROR` / `CKR_DEVICE_REMOVED`) - or a transport `OSError`. A restart is **not instantaneous**, so the session fixtures (`fixtures._open_or_reinit`, used by `p11_session`/`p11_raw_session` bootstrap and the `p11_module_session` health-check reopen) bridge it with a **bounded wait-and-reconnect loop**: reconnect (`C_Finalize` + `C_Initialize`), re-open + re-login, capped exponential backoff between attempts, until the provider returns or a time **and** attempt budget is exhausted (`_RECONNECT_*` constants in `fixtures.py` - no CLI/env knob by design). It is applied **only at the fixture open/login layer**, never inside a test-body assertion path, because those same codes are legitimate negative-test outcomes (e.g. some providers return `CKR_DEVICE_ERROR` for a rejected signature). The crash-triggering test still records its own real result; recovery only un-cascades *subsequent* tests, and every reconnect is surfaced (`UserWarning` + `reinit_count` → report.jsonl). The loop is bounded so a genuinely dead provider fails as a finding, never hangs. For a directly-loaded module a provider crash is a real SIGSEGV handled by `--isolation auto` instead (see CLAUDE.md execution model). Regression: `tests/test_reinit_recovery.py` (fakes) + `testcases/test_reinitialize.py::test_harness_recovers_lost_init_at_bootstrap` (real module).
- **Normal-teardown `C_Finalize` (release per-process resources):** the plugin's `pytest_sessionfinish` (in `plugin.py`) calls `C_Finalize` once per test process on the way out - after every test outcome **and** the coverage report are already recorded - so stateful shared backends (e.g. a wolfTPM fwTPM that leaks one SRK transient per file) release per-process resources instead of relying on OS exit. It is fully guarded so a slow/failing/crashing `C_Finalize` cannot change any test's verdict (segfault-survival model): a non-OK rv or any raise is caught best-effort (like `P11Module.reinitialize`), a Python-level hang (spin-wait in a ctypes callback or any stall that yields to the CPython eval loop) is bounded by a SIGALRM watchdog (`_TEARDOWN_FINALIZE_TIMEOUT_S`) - note that a module stuck *inside* native C code is NOT interrupted by SIGALRM; that is backstopped by the outer per-file subprocess deadline - and the outcome is recorded **only** via an additive `TeardownFinalize` report-log record (`outcome`/`rv`/`rv_name`/`reinit_count`/`error`) - never via `classify()`/`fail`/`xfail`, so a compliant provider is never false-accused and a finding is never hidden. No double-finalize: recovery always re-inits, so the library is live at teardown, and an idempotency flag makes a repeated `sessionfinish` a no-op. Regression: `tests/test_teardown_finalize.py`.
- `p11_session` fixture does explicit `login()` / `logout()` per test to avoid `UserAlreadyLoggedIn` cascading
- Tests auto-skip on absent capability: `@pytest.mark.needs_function("C_X")` skips when the module lacks a v3.x function (`C_EncapsulateKey`, `C_*Message*`, `C_LoginUser`, `C_SessionCancel`, ...); in-test `rs.has_mechanism(...)` skips when a mechanism is absent. Interface version is reporting-only.
- Mechanism availability checked at runtime via `rs.has_mechanism(name)` on `RawSession`
- PQC tests always provide `CKA_PARAMETER_SET` (ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-128s defaults)
- PIN tests marked `@destructive` to prevent token lockout (OpenCryptoki, TPM)

## Writing new tests

### Template

```python
"""CKM_EXAMPLE tests - short description."""
from __future__ import annotations
from typing import Any
import pytest
from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.recipes import gen_aes_key, encrypt_single, destroy_quietly
from pkcs11_check.raw.types_std import CKM_AES_CTR, CKR_OK

pytestmark = [pytest.mark.encrypt]

class TestExample:
    def test_roundtrip(self, p11_raw_session: RawSession) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CTR"):
            pytest.skip("CKM_AES_CTR not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_CTR, b"test data here!")
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
```

> When the AES key is a **fixture** (not the test's subject), prefer
> `gen_aes_key_or_xfail(rs, 256)` over the raw recipe - see "Classification & setup helpers" below.

### Key fixtures

- `p11_raw_session` - function-scoped: fresh C_OpenSession + C_Login per test. Fields: `rs.raw`, `rs.sh`, `rs.slot_id`, `rs.has_mechanism(name)`, `rs.mechanisms`. Use for tests that test session lifecycle, login/logout/PIN behavior, or otherwise need a fresh session per invocation.
- `p11_module_session` - module-scoped session reused across all tests in the file, with self-healing health check (C_GetSessionInfo) before each test that triggers a transparent reopen if a prior test closed the session or logged out. Per-test call_log / used_mechanisms are reset for accurate coverage. **Use this for read-only verification tests (Wycheproof, ACVP vectors, ...).** On providers with expensive C_Login this saves ~47 ms/test (OpenCryptoki SWToken's PBKDF2-based PIN derivation) to ~80 ms/test (BouncyHSM's TCP RPC). Concrete impact on the ECDSA Wycheproof file (28 915 tests): OpenCryptoki 42 min → 47 s; BouncyHSM 56 min → 2 min.
- `p11_session` - legacy alias, also yields `RawSession` (function-scoped)
- `p11_module` - loaded PKCS#11 module (session-scoped)
- `p11_config` - merged config (session-scoped)
- `p11_interface_version` - negotiated version string

When in doubt, prefer `p11_module_session` for new verification tests and only fall back to `p11_raw_session` when the test depends on session lifecycle.

### Patterns

Always check mechanism availability:
```python
if not rs.has_mechanism("MECHANISM_NAME"):
    pytest.skip("CKM_MECHANISM_NAME not supported")
```

Always destroy objects in `finally`:
```python
key = gen_aes_key(rs.raw, rs.sh, 256)
try:
    # test logic
finally:
    destroy_quietly(rs.raw, rs.sh, key)
```

Compliance notes for above-spec behavior:
```python
from pkcs11_check.compliance import ComplianceLevel, note
note("Module does X above spec Y", ComplianceLevel.VENDOR)
```

### Classification & advertised-but-not-operational helpers

The classification model (CLAUDE.md "Test-outcome classification model"; full rules in
[classification-model-design.md](classification-model-design.md)) is enforced through shared
helpers - **use these instead of hand-rolling per-CKR allowlists or bare `pytest.skip`/`xfail`**:

- **Setup keys via the `_or_xfail` helpers, not the raw recipes** (`testcases/conftest.py`):
  `gen_aes_key_or_xfail(rs, bits, *, attrs=None, sh=None)`,
  `gen_rsa_keypair_or_xfail`, `gen_ec_keypair_or_xfail`, `hmac_sign_or_xfail`. Each prechecks
  `has_mechanism` (→ `skip` when the mechanism is genuinely absent) and, when the mechanism is
  advertised but `C_GenerateKey`/the op cleanly refuses, `xfail`s "advertised but not operational"
  instead of hard-failing. Raw `gen_aes_key`/`gen_rsa_keypair` (from `raw.recipes`) are only for
  sites whose subject *is* keygen (e.g. `test_mech_keygen`, key-size-range tests).
- **Claim layer for `test_mech_*` op refusals:** `claim_refusal_passes(exc, rs, *, probe_key)`
  (`testcases/_capability_claims.py`) - a clean op refusal classifies as pass+note for the
  spec-sanctioned `CKR_OPERATION_NOT_VALIDATED`, else `xfail` via `not_operational_reason`; non-CKR
  propagates. No per-CKR allowlists.
- **Operability probes** (`testcases/_operability.py`): `probe_operability(key, fn)` caches a
  canonical KAT verdict per (mechanism, direction) - `OPERATIONAL` / `NOT_OPERATIONAL` /
  `INCONCLUSIVE` (staging failed) / `WRONG_OUTPUT`. `classify_kat_clean_error(...)` and
  `xfail_vacuous_reject(result, *, label)` (a negative-vector "rejection" on a NOT_OPERATIONAL
  mechanism never evaluated its input → xfail, not pass) consume it. `not_operational_reason`
  gives the shared wording so KAT-vector xfails group with the per-(mech,op) claim signal.
- **Negative-op classification** (`testcases/conftest.py` / `ckr/_ckr_spec.py`):
  `reject_or_classify(exc, expected_rvs, *, label)` / `classify_negative_rv(...)` (rejection with
  the expected spec CKR = pass, some other clean code = xfail, accepted-invalid = fail);
  `assert_ckr()` (3-way) for table-driven sites; `classify_policy_enforcement` (policy) /
  `classify_lifecycle_effect` (lifecycle) for self-contradiction checks.

**Import-skip rule:** a *negotiated* import that fails for all storage shapes on a module that
*advertises* the mechanism is "advertised but not operational" → `xfail`, never `skip`. Use the
`import_*_negotiated` helpers (`testcases/conftest.py`); skip is only for genuinely-absent
capability.

## At-source test-outcome classification

Tests emit a structured *classification* at the decision point - the moment a test decides what the
module did - instead of flattening the verdict into a free-text `pytest.fail`/`pytest.xfail` string.
### Emission API (`pkcs11_check.classification`)

```python
from pkcs11_check import classification as C
C.classify(reason, *, kind=…, label, operation, mechanism, expected, actual,
           spec_ref, source, vector_id, summary, detail)
```

`classify()` builds the `Classification` record, stores it in the per-test collector, and **then
raises the implied pytest outcome** (`pytest.fail` for a fail reason, `pytest.xfail` for an xfail
reason; a pass reason returns normally). Thin typed wrappers `fail_as(reason, **kw)` and
`xfail_as(reason, **kw)` (both `-> NoReturn`) guard that the reason matches the intended outcome.
KAT output equality is checked with `assert_correct(*, actual, expected, label, …)`
(`testcases/conftest.py`): equal values pass; a mismatch emits a `wrong_result`/`crypto` record and
fails. The existing `classify_*` / `assert_ckr` helpers now route through this same machinery.

### The model

- **outcome** ∈ {`pass`, `xfail`, `fail`}
- **reason** ∈ {`wrong_result`, `accepted_invalid`, `self_contradiction`, `oracle`, `crash` (→ fail);
  `not_operational`, `nonspec_reject`, `honest_deviation`, `undeclared_capability` (→ xfail);
  `sanctioned_refusal` (→ pass)}
- **kind** ∈ {`crypto`, `policy`, `lifecycle`, `metadata`} - the canonical machine field for the
  self-contradiction class
- **severity** is *derived* from `(reason, kind)` in `classification.derive_verdict` - the single
  source of truth for the outcome/severity table (no per-site severity literals)

### Transport to `report.jsonl`

Each emission rides to `report.jsonl` on the pytest `user_properties` key `pkcs11_classification`
(the same mechanism used by compliance notes and rv-trace). `plugin.py`
(`_attach_classification_to_report`) attaches the serialized records to the call-phase report and
clears the collector on teardown. **Crashes** are converted runner-side via
`core/file_runner.crash_classification` because the crashed process is dead and cannot self-emit.
Spec references come from the central `pkcs11_check.spec_refs.lookup` table (OASIS PKCS#11 v3.2;
precise sections only when confirmed against the local mirror, otherwise a truthful coarse form -
never fabricated).

### Gates

- **Static gate** ([../tests/test_no_raw_xfail_fail.py](../tests/test_no_raw_xfail_fail.py)) forbids
  raw `pytest.xfail(`/`pytest.fail(` under `testcases/` (outside the sanctioned `conftest.py` /
  `_ckr_spec.py`), forbids any test emitting the reserved `unclassified` reason, and asserts the
  migration allowlist is now empty - so the gate is fully hard.
- **Runtime gate** (plugin): any testcase that ends as fail/xfail without an emitted record gets a
  synthetic `reason="unclassified"` record auto-injected, so coverage is always 100% and the
  remaining bare-assert tail shows up as a visible backlog rather than silently uncovered.

### Report generator (`pkcs11_check.report` / `pkcs11-check-report`)

Rolls the records up into per-provider reports: `<provider>.md` (compact, severity-first, grouped by
`kind`) + `<provider>.jsonl` (one enriched group per line); with more than one
provider it also writes `_index.md` (counts table + top themes) and `_universal.md` (cross-provider
correlation). See [../src/pkcs11_check/report/README.md](../src/pkcs11_check/report/README.md) and
[commands.md](commands.md) for invocation.

## PKCS#11 Specification

OASIS spec in Markdown is not vendored in this repository. When working from a local checkout of
the OASIS PKCS#11 spec, useful files include `rsa.md`, `aes.md`, `elliptic_curves.md`,
`ml_dsa.md`, `slh-dsa.md`, `session_mgmt_functions.md`, and `function_return_values.md`.
