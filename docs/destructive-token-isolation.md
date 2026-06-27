# Destructive-test token isolation - design note

Status: **design / follow-up.** The immediate mitigation (marking the
persistent-state-mutating tests `@destructive`) is already applied; the
throwaway-token provisioner described here is not yet built.

## Background - the bug this prevents

`test_ffi_null_pointer.py::TestNullPinBuffer::test_set_pin_null_new_pin` calls
`C_SetPIN` with the **real current user PIN** as the old PIN and a NULL new-PIN
pointer. On Kryoptic this mutates/corrupts the stored user PIN (see
[module-issues.md](module-issues.md), Kryoptic "C_SetPIN with NULL new-PIN"),
so every later `C_Login("1234")` fails `CKR_PIN_INCORRECT` and the token locks
(`CKR_PIN_LOCKED`) after ~8 attempts. Because Kryoptic's token is a single
shared on-disk SQLite DB and the per-unit runner never reprovisions it, one
unit poisons every following unit (units 61→267 all error). SoftHSM2 is
unaffected (it rejects the NULL new PIN and/or enforces no hard lockout).

Root cause of the *regression*: commit `1406e01` corrected the old-PIN ctypes
cast (`c_void_p` → `CK_UTF8CHAR_PTR`). Before that the call raised a Python
`ArgumentError` and never reached the module, so the PIN was never touched -
which is why earlier runs "worked".

## Why `@destructive` alone is not the whole fix

`@destructive` (gated by `--p11-destructive` in `plugin.py`) means default runs
**skip** these tests - that stops the lockout for the common case. But a
*destructive* run (`PKCS11_CHECK_DESTRUCTIVE=1`) still executes them against the
shared token and will still lock it. To make destructive runs usable
end-to-end, the persistent-state mutators must run against a **disposable
token**, never the shared session token.

## What actually needs isolation

`destructive` ≠ "needs a fresh token". Two kinds:

| Kind | Examples | Touches persistent token DB? | Needs throwaway token? |
|------|----------|------------------------------|------------------------|
| Persistent-state mutators | `C_SetPIN`, `C_InitPIN`, `C_InitToken` | yes - corrupts/locks DB | **yes** |
| Library/session-state only | `C_Finalize`/`C_Initialize`, interface renegotiation (`test_reinitialize.py`) | no - resets library state | no |

Only the ~5 tests in `TestNullPinBuffer` + `TestNullInitToken` strictly need a
throwaway token today. Routing *all* destructive tests through one anyway (where
cheap) is a reasonable policy because it makes the suite order-independent - but
it is optional, not required.

## There is no universal "make a token" primitive

`P11TestConfig` (config.py) carries only `module` / `slot` / `pin` - it has no
notion of where a module's token state lives. Token storage differs per module,
so provisioning is necessarily **per-module**. Three tiers:

| Tier | Modules | State location | Throwaway strategy | Cost |
|------|---------|----------------|--------------------|------|
| 1. Relocatable file-backed | kryoptic (`KRYOPTIC_CONF`→sqlite), softhsm2 (`SOFTHSM2_CONF`→tokendir), nss (cert-DB dir) | a file/dir behind an env var | temp conf → temp DB → `C_InitToken`/`C_InitPIN` fresh | cheap, per-test OK |
| 2. Daemon / server / system | opencryptoki (`pkcsslotd`, `/var/lib/opencryptoki`), bouncyhsm (.NET server over TCP) | daemon / remote server | admin path: free slot / server API | heavier, module-specific |
| 3. Not a file token | tpm2 (state in TPM/swtpm), pkcs11-mock (stateless) | hardware/simulator, or nothing | reprovision-after, or skip | N/A |

Tier 1 is exactly the set of modules that *enforce* destructive consequences
(PIN lockout, object wipe), so a **Tier-1-only** implementation already solves
the real problem. tpm2/mock don't lock, so they don't need it.

## Proposed design

1. **Per-provider provisioner.** A small interface, e.g.
   `provision_throwaway_token(provider) -> ThrowawayToken{module, slot, pin, env}`,
   with implementations selected by provider kind. Tier 1 writes a temp
   `KRYOPTIC_CONF`/`SOFTHSM2_CONF` (or NSS dir) under `tmp_path`, initializes a
   fresh token + user PIN, and yields the handle; teardown removes the temp dir.
2. **Config addition.** Add an optional field describing the token backend
   (e.g. `provider_kind` or `token_conf_env`) so the provisioner can be chosen.
   This is the missing piece that makes it real work rather than a one-liner.
3. **`throwaway_token` fixture** (function-scoped - fresh per test; file
   provisioning is cheap enough). Requested only by the mutator tests.
4. **Subprocess plumbing.** Extend `run_with_coverage(script, env=...)` (in
   `_subprocess_preamble.py`) to merge the provisioner's env into the child;
   it already builds its own `env` dict, so this is a ~3-line change.
5. **Fallback ladder** per tier: Tier 1 clone/fresh → Tier 2 admin-reset /
   free-slot → Tier 3 reprovision-the-whole-token-after, or capability-skip.
   A skip here is a legitimate "missing capability" skip (the harness cannot
   safely isolate), not suppression of a bug.

## Sequencing

- **Done:** `@destructive` on `TestNullPinBuffer` + `TestNullInitToken`
  (branch `fix/destructive-pin-token-tests`). Default runs no longer lock.
- **Next:** Tier-1 `throwaway_token` fixture + config field; route the 5 mutator
  tests through it so destructive runs are usable on kryoptic/softhsm/nss.
- **Later:** Tier 2/3 provisioners or capability-skips.
