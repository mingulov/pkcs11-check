# OP-TEE PKCS#11 Docker Target - Design

**Date:** 2026-06-06
**Topic:** Add an OP-TEE PKCS#11 TA provider target that can run
`pkcs11-check` inside an OP-TEE QEMU guest and publish normal Docker artifacts.

## Context

The existing Docker matrix runs providers whose PKCS#11 module is loadable in
the test container itself. OP-TEE is different: the userland module is
`libckteec.so`, and it is only the Cryptoki bridge into the OP-TEE PKCS#11
trusted application. A meaningful target therefore needs a Linux guest booted
with OP-TEE, `/dev/tee*`, `tee-supplicant`, and the PKCS#11 TA, not just an
x86_64 build of `libckteec.so`.

The current OP-TEE source evidence is:

- Latest stable tag check on 2026-06-06: `OP-TEE/manifest`,
  `OP-TEE/optee_client`, and `OP-TEE/optee_os` latest stable tag is `4.10.0`.
- The `4.10.0` `qemu_v8.xml` manifest pins `build` to `4.10.0`, QEMU to
  `v10.0.0`, TF-A to `v2.14.0`, Mbed TLS to `mbedtls-3.6.5`, U-Boot to
  `v2025.07`, and Buildroot to `2025.05`.
- OP-TEE documentation describes the PKCS#11 driver as `libckteec.so`, loaded
  after OP-TEE is compiled with the PKCS#11 TA and `tee-supplicant` is running.
  Its example reports `Cryptoki version 2.40`.
- `optee_client` `4.10.0` and main both define
  `CK_PKCS11_VERSION_MAJOR 2`, `CK_PKCS11_VERSION_MINOR 40`, and
  `CK_PKCS11_VERSION_PATCH 1`.
- Source scans of `optee_client/libckteec` and `optee_os/ta/pkcs11` found no
  `C_GetInterface`, `C_GetInterfaceList`, `CK_FUNCTION_LIST_3*`,
  `C_WrapKeyAuthenticated`, `C_EncapsulateKey`, `C_DecapsulateKey`, exact
  `CKM_SHA3`, `CKM_ML_DSA`, or `CKM_ML_KEM` symbols.
- The TA has broad v2.40 coverage: RSA PKCS/OAEP/PSS, ECDSA, ECDH, EdDSA,
  AES ECB/CBC/CBC-PAD/CTR/GCM/CMAC, AES wrap/unwrap, SHA/MD5 digest, HMAC,
  generic secret, and key generation.

Conclusion: OP-TEE is a valuable provider target, but the target is PKCS#11
2.40. OASIS 3.2 support would be a separate upstream provider-development
project, not a Docker build flag.

## Goals

1. Add a reproducible, explicitly pinned Docker target named
   `test-optee-pkcs11`.
2. Build OP-TEE QEMU v8 from the latest stable OP-TEE release, not a moving
   branch.
3. Run `pkcs11-check` inside the OP-TEE normal-world guest against
   `/usr/lib/libckteec.so`.
4. Emit the standard Docker artifacts:
   `artifacts/optee-pkcs11/console.log`, `results.json`, `state.json`, and
   `policy.json`.
5. Preserve crash and hang evidence. A kernel panic, secure-world panic,
   assertion, QEMU timeout, or guest runner timeout must fail the Docker target.
6. Keep PIN handling clean: public test PINs are acceptable, but do not echo
   PIN values into serial logs or machine-readable artifacts.
7. Keep the target opt-in and heavy/manual; it must not become part of the
   default Docker smoke matrix.

## Non-Goals

- Do not force `--interface 3.0` or `--interface 3.2`; OP-TEE currently exposes
  a v2.40 provider.
- Do not add NVIDIA DRIVE OS PKCS#11 to this target. NVIDIA can be a later
  manual/external target if DRIVE hardware and SDK binaries are available.
- Do not vendor OP-TEE source into this repository.
- Do not add provider-specific skips, xfails, or allowlists for OP-TEE findings.
  The general pkcs11-check classification model still applies.
- Do not update release statistics or `docs/docker-provider-results.md` with
  OP-TEE counts until a deliberate full validation run exists.

## Approach Considered

### Option A - Native x86_64 `libckteec.so`

Build `optee_client/libckteec` for x86_64 and run it directly in Docker.

Rejected. `libckteec.so` talks to the OP-TEE kernel device and PKCS#11 TA. A
host-only build would test missing-device behavior, not the provider.

### Option B - OP-TEE `xtest` only

Build OP-TEE QEMU and run OP-TEE's own `xtest` PKCS#11 tests.

Rejected as the main target. `xtest` is useful as a prerequisite smoke check,
but it does not run pkcs11-check, does not produce pkcs11-check artifacts, and
does not exercise this suite's classification and crash-survival behavior.

### Option C - QEMU guest runs pkcs11-check against `libckteec.so`

Build OP-TEE QEMU v8, mount a prepared pkcs11-check runtime into the guest, run
a guest-side runner that initializes the token and invokes pkcs11-check.

Chosen. This is the only option that tests the real OP-TEE provider while still
fitting the existing Docker artifact contract.

## Docker Shape

Add:

- `docker/optee-pkcs11/Dockerfile`
- `docker/optee-pkcs11/run-optee-pkcs11.sh`
- `docker/optee-pkcs11/optee-pkcs11.exp`
- `docker/optee-pkcs11/guest-runner.py`
- `docker/optee-pkcs11/build-guest-site.sh`

Add a Compose service:

```yaml
test-optee-pkcs11:
  build:
    context: ..
    dockerfile: docker/optee-pkcs11/Dockerfile
    args:
      OPTEE_REF: "4.10.0"
  environment:
    PKCS11_CHECK_ARTIFACT_DIR: /artifacts/optee-pkcs11
    PKCS11_CHECK_MODULE: /usr/lib/libckteec.so
    PKCS11_CHECK_PIN: "1234"
    PKCS11_CHECK_SLOT: "0"
    PKCS11_CHECK_INTERFACE: "2.40"
```

The service must be runnable through:

```bash
bash docker/test.sh optee-pkcs11 -- src/pkcs11_check/testcases/test_interface.py
```

It must not be added to `DEFAULT_PROVIDERS` or `ALL_PROVIDERS`. Because OP-TEE
is significantly heavier than the current providers, `docker/test-all.sh --all`
should not pick it up silently. Add a separate `HEAVY_PROVIDERS` list containing
`optee-pkcs11`; `docker/test-all.sh optee-pkcs11` should recognize it, and an
explicit `--heavy` or `--all-heavy` flag can opt into the whole heavy list.

## Build Design

The Dockerfile uses a builder stage that installs OP-TEE build prerequisites,
`repo`, `expect`, QEMU build dependencies, and Python packaging tools. It then:

1. Creates an OP-TEE checkout with
   `repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml -b 4.10.0`.
2. Runs `repo sync -j4 --no-clone-bundle`.
3. Builds toolchains with `make -C build toolchains`.
4. Builds OP-TEE QEMU v8 with:
   - `CFG_PKCS11_TA=y`
   - `CFG_PKCS11_TA_ALLOW_DIGEST_KEY=y`
   - `CFG_PKCS11_TA_AUTH_TEE_IDENTITY=y`
   - `CFG_PKCS11_TA_CHECK_VALUE_ATTRIBUTE=y`
   - `CFG_PKCS11_TA_RSA_X_509=y`
   - `CFG_PKCS11_TA_HEAP_SIZE=(128 * 1024)` initially
   - `QEMU_VIRTFS_ENABLE=y`
   - `QEMU_PSS_ENABLE=y`
   - `BR2_PACKAGE_PYTHON3=y`
   - `BR2_PACKAGE_OPENSC=y` for a lightweight module sanity check

The OP-TEE source defaults already enable several PKCS#11 TA options. The
Docker build must still pass the flags explicitly so the target is auditable,
and so `RSA_X_509` and the larger heap do not depend on platform defaults.

`make check` is not the target's final command. A small `xtest` subset may run
as a build or runtime smoke check if it catches broken OP-TEE boot early, but
the provider target succeeds or fails based on the pkcs11-check guest runner.

## Guest Runtime Packaging

Buildroot 2025.05 provides Python 3.13.3. pkcs11-check dependencies include
native aarch64 wheels (`cffi`, `cryptography`, `psutil`, `pydantic-core`,
`tomli`), so the target should not try to re-run `uv sync` in the guest.

Instead, `build-guest-site.sh` prepares a frozen aarch64 site directory:

1. `uv build --wheel`
2. `uv export --frozen --no-dev --no-emit-project --format requirements.txt --no-hashes`
3. `uv pip install --target /opt/pkcs11-check-site --python-version 3.13 --python-platform aarch64-manylinux2014 --only-binary :all: -r requirements.txt dist/*.whl`

The previous audit proved this shape is viable: the installed site tree was
about 41 MiB and native `.so` files were aarch64. Do not execute the generated
`site/bin/pkcs11-check` script in the guest, because its shebang points to the
host virtualenv. The guest runner must use:

```bash
PYTHONPATH=/mnt/pkcs11-check/site python3 /mnt/pkcs11-check/guest-runner.py
```

## QEMU Runner Design

The runner should be modeled on OP-TEE's `qemu-check.exp`, but it needs to run
pkcs11-check and publish artifacts. It should:

1. Start QEMU with normal-world serial on stdio and secure-world serial written
   to `serial1.log`.
2. Add 9p mounts for:
   - a read-only pkcs11-check runtime/share directory
   - a writable artifact directory
   - a per-run writable secure-storage directory mounted as `/var/lib/tee`
3. Boot to a root shell.
4. Confirm `tee-supplicant` is running; start it if the image did not.
5. Mount the 9p directories.
6. Run a cheap sanity check:
   `pkcs11-tool --module /usr/lib/libckteec.so --show-info` or equivalent raw
   probe, with no secret values on the command line.
7. Run `guest-runner.py`.
8. Capture the guest runner exit code and shut QEMU down.
9. Copy or leave `serial0.log` and `serial1.log` under
   `artifacts/optee-pkcs11/`.

The expect script must fail on:

- Linux kernel panic
- secure-world assertion or panic (`TC:` panic/assertion lines)
- guest boot timeout
- pkcs11-check timeout
- missing `results.json`
- guest runner non-zero exit

It must not use `|| true` or translate failures into a green Docker result.

## Guest Runner Design

`guest-runner.py` owns the OP-TEE token bootstrap and the pkcs11-check
invocation. It should:

1. Import pkcs11-check from the mounted site tree.
2. Use `pkcs11_check.raw` directly to call:
   - `C_Initialize`
   - `C_InitToken` on slot 0 with a public SO PIN
   - `C_OpenSession`
   - `C_Login(CKU_SO)`
   - `C_InitPIN`
   - `C_Logout`
   - `C_Finalize`
3. Treat `CKR_TOKEN_NOT_RECOGNIZED`, `CKR_TOKEN_NOT_PRESENT`, or a missing slot
   as a setup failure.
4. Accept an already-initialized disposable token only if the per-run secure
   storage directory was intentionally reused; the default run uses fresh
   storage and should initialize cleanly.
5. Set `P11TEST_PIN` or construct `pkcs11-check test --pin` in-process, then
   call the CLI entrypoint. The process command line visible in serial logs
   should stay `python3 /mnt/pkcs11-check/guest-runner.py`, not
   `pkcs11-check test --pin 1234 ...`.
6. Pass through `PKCS11_CHECK_EXTRA_ARGS` and `PKCS11_CHECK_TARGETS` using the
   same shell-quoting contract as `docker/run-pkcs11-check.sh`.

PIN values are public test constants. The reason to keep them out of command
echo and artifacts is not confidentiality of `1234`; it is harness hygiene and
consistency with the repo rule that PINs are not logged.

## Artifact Contract

At the end of a run, the host should see:

- `artifacts/optee-pkcs11/console.log` - Docker-level combined output
- `artifacts/optee-pkcs11/serial0.log` - normal-world UART
- `artifacts/optee-pkcs11/serial1.log` - secure-world UART
- `artifacts/optee-pkcs11/results.json`
- `artifacts/optee-pkcs11/state.json`
- `artifacts/optee-pkcs11/policy.json`

If pkcs11-check crashes a guest userspace process, the normal pkcs11-check
isolation model should record that as a test crash and continue inside the
guest. If OP-TEE, the kernel, or QEMU crashes, the Docker target fails because
the provider environment died.

## Gap Analysis

### Interface gap

OP-TEE is v2.40 only today. This means v3 message tests and v3.2 KEM/PQC tests
should naturally skip based on interface and mechanisms. The target must not
pretend to be a v3 provider.

### Runtime gap

There is no pure x64 OP-TEE PKCS#11 runtime. The Docker target must boot QEMU
and run tests in the guest.

### Packaging gap

Buildroot does not provide the exact Python dependency graph pkcs11-check uses.
Mounting a frozen aarch64 site tree is simpler and more reproducible than
adding many Buildroot Python packages.

### Logging gap

Expect scripts echo sent commands and serial logs are retained as artifacts. The
guest runner must avoid putting PIN values in commands typed over serial.

### Speed gap

QEMU TCG and OP-TEE boot/build time make this a heavy target. It should be
manual at first. Pooled/sharded Docker execution is not appropriate until a
single full run proves the guest environment is stable and until per-run secure
storage isolation is understood.

### State gap

OP-TEE secure storage persists in `/var/lib/tee`. The target must mount a
fresh per-run secure-storage directory by default, otherwise token state and
destructive tests can contaminate later runs.

### Failure classification gap

Provider crashes inside pkcs11-check subprocesses are findings and should be
recorded. Environment crashes outside pkcs11-check control are harness failures
only if the runner cannot produce a coherent result. The expect wrapper must
distinguish these by whether `results.json` exists and whether QEMU itself
remained alive.

## Implementation Pieces

1. **Source manifest update**
   - Add OP-TEE manifest/client/os/buildroot component pins to
     `docker/provider-sources.toml`.

2. **Docker image**
   - Add `docker/optee-pkcs11/Dockerfile`.
   - Build OP-TEE QEMU v8 at `4.10.0`.
   - Build/mount the aarch64 pkcs11-check site tree.

3. **Guest runner**
   - Add `guest-runner.py`.
   - Unit-test argument construction and PIN redaction behavior with normal
     meta-tests if the helper has non-trivial parsing logic.

4. **Expect/QEMU wrapper**
   - Add `optee-pkcs11.exp` and `run-optee-pkcs11.sh`.
   - Preserve serial logs and propagate real exit status.

5. **Compose integration**
   - Add `test-optee-pkcs11` to `docker/docker-compose.test.yml`.
   - Keep it out of the default provider list.
   - Add `HEAVY_PROVIDERS=(optee-pkcs11)` to `docker/test-all.sh`.
   - Keep `--all` unchanged; add a separate explicit heavy flag if a full heavy
     matrix command is useful.

6. **Docs**
   - Add `optee-pkcs11` to `docs/commands.md` provider examples.
   - Update `docs/architecture.md` Docker matrix list.
   - Do not add result statistics until full validation exists.

## Validation Plan

Use incremental checks because full OP-TEE builds are slow.

1. Local checks after adding scripts:
   - `uv run ruff check docker/optee-pkcs11/guest-runner.py tests/`
   - `uv run mypy src/ tests/` if any typed project code changes
   - targeted pytest meta-tests for helper parsing/redaction, if added

2. Docker build smoke:
   - `bash docker/test.sh optee-pkcs11 --match test_interface -- src/pkcs11_check/testcases/test_interface.py`

3. Provider smoke:
   - inspect `artifacts/optee-pkcs11/console.log`
   - inspect `serial0.log` and `serial1.log` for kernel/secure-world panics
   - verify `results.json`, `state.json`, and `policy.json` exist
   - verify artifacts do not contain the PIN literal in command echoes

4. Broader run:
   - run selected mechanism files for RSA, ECDSA, AES, digest, HMAC, and token
     initialization/lifecycle.

5. Full validation:
   - run `bash docker/test.sh optee-pkcs11`
   - only after this succeeds as a coherent run, consider adding a row to
     `docs/docker-provider-results.md`.

## Review Notes

- The target's first success criterion is "real provider under OP-TEE QEMU",
  not high pass count.
- Any OP-TEE mechanism behavior discovered by pkcs11-check should be recorded as
  provider findings, not patched around in tests.
- If OP-TEE build time becomes excessive, add cache mounts or a split
  builder/runtime image. Do not shorten validation by dropping tests silently.
- If QEMU runner instability dominates results, fix the runner before trusting
  provider statistics.
