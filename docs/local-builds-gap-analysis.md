# Local Builds Gap Analysis

Date: 2026-03-19

## Scope

This check focused on the recent runner changes:

- collection-safe PKCS#11 preflight manifest
- optional isolated modes via `p11test test --isolation auto|file|test`
- `local-builds/test.sh` integration with the new runner path
- adaptive isolation policy persistence across repeated local runs
- same-run file-to-test escalation in `auto`

The goal was not to prove that every module passes the whole product suite. The goal was to separate:

- runner regressions
- local helper regressions
- module-specific product failures or native crashes

Follow-up: after this validation, `local-builds/test.sh` was updated to auto-enable
`auto` isolation for `nss-softokn` and `qryptotoken` unless the user explicitly
overrides `P11TEST_ISOLATION` or passes `--isolation`.

## Fix Included In This Validation

`local-builds/test.sh` now preserves explicit pytest file/nodeid targets in the default non-isolated path.

Before this fix, a command such as:

```bash
bash local-builds/test.sh softhsm2 src/p11test/testcases/test_interface.py::TestInterfaceV30::test_v30_interface_negotiated -q
```

still expanded to the entire `src/p11test/testcases/` tree. That made targeted validation misleading and much slower than intended.

## Commands Used

Representative commands from this validation:

```bash
bash local-builds/test.sh kryoptic -q --tb=no
bash local-builds/test.sh softhsm2 -q --tb=no
bash local-builds/test.sh nss-softokn -q --tb=no
bash local-builds/test.sh pkcs11-mock -q --tb=no
bash local-builds/test.sh qryptotoken -q --tb=no

P11TEST_ISOLATION=auto \
P11TEST_STATE_FILE=/tmp/p11test-nss-crash-resume.json \
bash local-builds/test.sh nss-softokn \
  src/p11test/testcases/test_wycheproof_pbkdf2.py \
  src/p11test/testcases/test_interface.py

P11TEST_ISOLATION=auto \
P11TEST_STATE_FILE=/tmp/p11test-qryptotoken-crash-resume.json \
bash local-builds/test.sh qryptotoken \
  src/p11test/testcases/test_aead.py \
  src/p11test/testcases/test_interface.py
```

For BouncyHSM, the local server was started manually and a manifest-heavy slice was used instead of a full suite run.

## Results

| Provider | Local helper path | Result | Notes |
| --- | --- | --- | --- |
| SoftHSM2 | default `local-builds/test.sh` | Full suite completed | `22796 passed, 6303 skipped, 658 xfailed, 1 warning` in `109.12s` |
| Kryoptic | default `local-builds/test.sh` | Full suite completed | `21712 passed, 7665 skipped, 380 xfailed, 1 warning` in `80.84s` |
| NSS softokn | default `local-builds/test.sh` | Full suite crashed | Segfault in `test_wycheproof_pbkdf2.py` around 70% |
| NSS softokn | `P11TEST_ISOLATION=auto` | Crash contained | `test_wycheproof_pbkdf2.py` recorded as `crashed`, next file still ran and passed |
| qryptotoken | default `local-builds/test.sh` | Full suite aborted | Abort in `test_aead.py` almost immediately |
| qryptotoken | `P11TEST_ISOLATION=auto` | Crash contained | `test_aead.py` recorded as `crashed`, next file still ran and exposed a real `MechanismInvalid` failure |
| pkcs11-mock | default `local-builds/test.sh` | Full suite completed with massive product errors | `47 failed, 74 passed, 309 skipped, 29327 errors` |
| BouncyHSM | manual local server + default helper | Targeted manifest-heavy slice completed | `837 passed, 8 skipped, 121 xfailed, 2 failed` in `128.73s`; no loader/collection crash |
| OpenCryptoki | local helper only | Not fully revalidated in this pass | Provider still requires manual `pkcsslotd` startup and token init |

## What The New Functionality Proved

### 1. Collection safety is materially better

The new preflight manifest path no longer dies in pytest collection for the checked providers. BouncyHSM was the most important proof point here: the run went through the separate preflight helper, then collected and executed the selected tests normally.

### 2. The local helper integration works

`local-builds/test.sh` can now:

- run targeted files or nodeids directly in the default path
- opt into the isolated runner with `P11TEST_ISOLATION=auto|file|test`
- pass through `P11TEST_POLICY_FILE` when a provider needs a dedicated adaptive policy store
- preserve provider environment such as `NSS_LIB_PARAMS`, `SOFTHSM2_CONF`, and `BOUNCY_HSM_CFG_STRING`

### 3. File isolation does the right thing on real native crashes

This was validated with two different providers:

- NSS softokn:
  - `test_wycheproof_pbkdf2.py` crashed with return code `-11`
  - `test_interface.py` still ran afterwards and passed
  - state file recorded `crashed` then `passed`
- qryptotoken:
  - `test_aead.py` aborted with return code `-6`
  - `test_interface.py` still ran afterwards and produced a normal product failure
  - state file recorded `crashed` then `failed`

That is the strongest evidence from this pass that the new file-isolation path is useful in practice, not just in unit tests.

## Real Gaps Found

### 1. Default local runs are now split by provider stability

After the follow-up helper change, crash-prone providers no longer need a manual
`P11TEST_ISOLATION=auto` for the common path:

- `nss-softokn` defaults to `auto`
- `qryptotoken` defaults to `auto`
- provider-default isolated runs also get provider-specific `/tmp` state and policy files
- stable fast providers like `softhsm2` and `kryoptic` still default to in-process mode

That is the right shape for the local helper. The remaining gap is broader
provider automation, not the isolation default itself.

### 2. Not every local provider is a good full-suite regression target

`pkcs11-mock` is too incomplete for full-suite regression use. The helper path is fine, but the product matrix is overwhelmingly red. It should be treated as a targeted validation backend, not a full-suite baseline.

Recommendation:

- use `pkcs11-mock` only for focused CKR/interface/null-parameter tests

### 3. Some local providers still require manual service orchestration

`bouncyhsm` and `opencryptoki` are not yet first-class unattended local providers.

- BouncyHSM still needs a manually started server and slot bootstrap
- OpenCryptoki still needs `pkcsslotd` and token init outside the helper

Recommendation:

- add provider-specific `setup_runtime()` support to `local-builds/`
- only then treat them as full local regression targets

### 4. The docs still overstate some local targets

Older planning/docs still imply that `nss-softokn` is a routine local full-suite regression target. That is not true in the current tree unless file isolation is used.

Recommendation:

- keep `softhsm2` and `kryoptic` as the primary local full-suite gates
- move `nss-softokn` to `P11TEST_ISOLATION=auto` guidance
- describe `qryptotoken` and `pkcs11-mock` as targeted or crash-prone validation backends

## Practical Conclusion

The new runner functionality is good enough to keep.

What is clearly working:

- preflight manifest and collection-safe capability detection
- `local-builds/test.sh` integration
- explicit target passing in the local helper
- file isolation as a real crash-containment tool

What is not yet true:

- all local providers are stable full-suite targets in default mode
- all local providers are fully automated

The safe current local regression baseline is:

```bash
bash local-builds/test.sh softhsm2 -q
bash local-builds/test.sh kryoptic -q
```

For crash-prone providers, the helper now chooses file isolation automatically,
but the explicit form is still valid:

```bash
P11TEST_ISOLATION=auto bash local-builds/test.sh nss-softokn ...
P11TEST_ISOLATION=auto bash local-builds/test.sh qryptotoken ...
```

For BouncyHSM and OpenCryptoki, local use is still possible, but the service lifecycle remains a separate gap from the runner changes validated here.
