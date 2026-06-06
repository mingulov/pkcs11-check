# OP-TEE PKCS#11 Docker Target Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a heavy/manual Docker provider target that runs `pkcs11-check` inside an OP-TEE QEMU v8 guest against `/usr/lib/libckteec.so` and emits standard artifacts.

**Architecture:** A Docker service builds OP-TEE `qemu_v8` at release `4.10.0`, prepares an aarch64 Python site tree for `pkcs11-check`, boots the OP-TEE normal-world guest under QEMU, mounts the test runtime and artifact directories over 9p, initializes a disposable OP-TEE PKCS#11 token in guest Python, then invokes the normal `pkcs11-check` CLI in-process. The target is directly runnable with `docker/test.sh optee-pkcs11` but excluded from default and normal `--all` matrix runs.

**Tech Stack:** Python 3.13 in the guest, Python 3.14 in the Docker build host image if needed for `uv`, OP-TEE `4.10.0`, QEMU v8 from OP-TEE manifest, Buildroot `2025.05`, `expect`, bash, Docker Compose, `uv run`, `pytest`, `ruff`, `mypy --strict` when project code changes.

**Companion spec:** `docs/superpowers/specs/2026-06-06-optee-pkcs11-docker-target-design.md`.

---

## Current decisions

- OP-TEE is treated as a PKCS#11 v2.40 target. Do not force `--interface 3.0` or `--interface 3.2`.
- Latest stable release pin for this implementation is OP-TEE `4.10.0`, verified on 2026-06-06 from upstream tags.
- `qemu_v8.xml` pins QEMU `v10.0.0`, TF-A `v2.14.0`, Mbed TLS `mbedtls-3.6.5`, U-Boot `v2025.07`, and Buildroot `2025.05`.
- `Buildroot 2025.05` is intentionally used even though later 2025.05.x tags exist, because the OP-TEE release manifest pins `refs/tags/2025.05`.
- The guest runner must avoid echoing PIN values into serial commands. Use `P11TEST_PIN` inside Python rather than typing `pkcs11-check test --pin 1234` over serial.
- Public test PINs are acceptable for this disposable target. PIN hygiene still matters because repo rules forbid PIN leakage in logs and errors.
- `test-optee-pkcs11` is a heavy/manual target. It is callable by name but must not be in `DEFAULT_PROVIDERS` or ordinary `ALL_PROVIDERS`.
- Do not update exact result statistics in `docs/docker-provider-results.md` until a deliberate full OP-TEE validation run exists.

## File structure

| Path | Action | Responsibility |
|---|---|---|
| `docker/optee-pkcs11/Dockerfile` | Create | Build OP-TEE QEMU v8 and the aarch64 `pkcs11-check` guest runtime |
| `docker/optee-pkcs11/build-guest-site.sh` | Create | Produce `/opt/pkcs11-check-site` for guest Python 3.13/aarch64 |
| `docker/optee-pkcs11/guest-runner.py` | Create | Initialize OP-TEE token and invoke the `pkcs11-check` CLI in-process |
| `docker/optee-pkcs11/optee-pkcs11.exp` | Create | Boot QEMU, mount 9p shares, run guest Python, detect panic/timeout |
| `docker/optee-pkcs11/run-optee-pkcs11.sh` | Create | Host-side wrapper, artifact setup, expect invocation, result validation |
| `docker/docker-compose.test.yml` | Modify | Add `test-optee-pkcs11` service |
| `docker/test-all.sh` | Modify | Add `HEAVY_PROVIDERS` and `--heavy`/`--all-heavy` handling |
| `docker/provider-sources.toml` | Modify | Add OP-TEE source pins and target metadata |
| `docs/commands.md` | Modify | Document direct OP-TEE heavy-target invocation |
| `docs/architecture.md` | Modify | Add OP-TEE to Docker matrix architecture as a heavy QEMU target |
| `docs/docker-artifacts.md` | Modify | Add OP-TEE-specific serial artifacts to the existing contract |
| `tests/test_optee_guest_runner.py` | Create | Unit-test guest runner argument parsing, no-PIN command rendering, and env handling |

Files not touched:
- `src/pkcs11_check/testcases/`: no OP-TEE-specific skips or behavior changes.
- `docs/docker-provider-results.md`: no OP-TEE counts until a full validation run exists.
- `main` branch: all work stays on `dev`.

---

## Phase 1: Guest runner helpers first

### Task 1: Add RED tests for guest-runner pure helper behavior

**Files:**
- Create: `tests/test_optee_guest_runner.py`

- [ ] **Step 1: Create import scaffolding for a script in a hyphenated directory**

Create `tests/test_optee_guest_runner.py` with this starting content:

```python
"""Meta-tests for the OP-TEE PKCS#11 guest runner."""

from __future__ import annotations

import importlib.util
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
GUEST_RUNNER = ROOT / "docker/optee-pkcs11/guest-runner.py"


def load_guest_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("optee_guest_runner", GUEST_RUNNER)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def make_env(**overrides: str) -> Mapping[str, str]:
    env = {
        "PKCS11_CHECK_MODULE": "/usr/lib/libckteec.so",
        "PKCS11_CHECK_PIN": "1234",
        "PKCS11_CHECK_SO_PIN": "87654321",
        "PKCS11_CHECK_SLOT": "0",
        "PKCS11_CHECK_INTERFACE": "2.40",
        "PKCS11_CHECK_ARTIFACT_DIR": "/mnt/artifacts",
    }
    env.update(overrides)
    return env
```

- [ ] **Step 2: Add parsing and command tests**

Append these tests:

```python
def test_build_cli_args_uses_artifact_files_and_targets() -> None:
    runner = load_guest_runner()
    args = runner.build_cli_args(
        make_env(
            PKCS11_CHECK_EXTRA_ARGS="--timeout 30 --match test_interface",
            PKCS11_CHECK_TARGETS="src/pkcs11_check/testcases/test_interface.py",
        )
    )

    assert args[:2] == ["test", "--module"]
    assert "/usr/lib/libckteec.so" in args
    assert "--interface" in args
    assert "2.40" in args
    assert "--slot" in args
    assert "0" in args
    assert "--output" in args
    assert "json" in args
    assert "--output-file" in args
    assert "/mnt/artifacts/results.json" in args
    assert "--state-file" in args
    assert "/mnt/artifacts/state.json" in args
    assert "--policy-file" in args
    assert "/mnt/artifacts/policy.json" in args
    assert "--timeout" in args
    assert "30" in args
    assert "--match" in args
    assert "test_interface" in args
    assert args[-1] == "src/pkcs11_check/testcases/test_interface.py"


def test_build_cli_args_defaults_to_testcases_dir() -> None:
    runner = load_guest_runner()
    args = runner.build_cli_args(make_env(PKCS11_CHECK_TARGETS=""))

    assert args[-1] == "src/pkcs11_check/testcases/"


def test_render_serial_command_never_contains_pin() -> None:
    runner = load_guest_runner()
    env = make_env(PKCS11_CHECK_PIN="1234", PKCS11_CHECK_SO_PIN="87654321")

    rendered = runner.render_serial_command(env)

    assert "guest-runner.py" in rendered
    assert "1234" not in rendered
    assert "87654321" not in rendered
    assert "--pin" not in rendered


def test_pin_env_is_set_only_for_cli_call(monkeypatch: object) -> None:
    runner = load_guest_runner()
    captured: dict[str, str | None] = {}

    def stub_main() -> None:
        import os

        captured["pin"] = os.environ.get("P11TEST_PIN")

    monkeypatch.setattr(runner, "pkcs11_cli_main", stub_main)

    exit_code = runner.run_pkcs11_check_cli(make_env(), ["test", "--module", "/usr/lib/libckteec.so"])

    assert exit_code == 0
    assert captured["pin"] == "1234"
```

- [ ] **Step 3: Run tests and confirm RED**

```bash
uv run pytest -q tests/test_optee_guest_runner.py
```

Expected while `guest-runner.py` does not exist:

```text
FAILED tests/test_optee_guest_runner.py::test_build_cli_args_uses_artifact_files_and_targets
FAILED tests/test_optee_guest_runner.py::test_build_cli_args_defaults_to_testcases_dir
FAILED tests/test_optee_guest_runner.py::test_render_serial_command_never_contains_pin
FAILED tests/test_optee_guest_runner.py::test_pin_env_is_set_only_for_cli_call
```

### Task 2: Implement guest-runner.py pure helpers and token bootstrap

**Files:**
- Create: `docker/optee-pkcs11/guest-runner.py`

- [ ] **Step 1: Add script header, imports, constants, and helper functions**

Create `docker/optee-pkcs11/guest-runner.py` with:

```python
#!/usr/bin/env python3
"""Guest-side OP-TEE PKCS#11 runner for Docker validation."""

from __future__ import annotations

import os
import shlex
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from pkcs11_check.cli.app import main as pkcs11_cli_main
from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    get_slot_ids,
    login_user,
    logout_quietly,
    open_session,
)
from pkcs11_check.raw.recipes import init_pin, init_token
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKR_OK,
    CKU_SO,
)


DEFAULT_MODULE = "/usr/lib/libckteec.so"
DEFAULT_SLOT = "0"
DEFAULT_INTERFACE = "2.40"
DEFAULT_ARTIFACT_DIR = "/mnt/artifacts"
DEFAULT_TARGET = "src/pkcs11_check/testcases/"
DEFAULT_TOKEN_LABEL = "pkcs11-check"


def _shlex_split(value: str | None) -> list[str]:
    if not value:
        return []
    return shlex.split(value)


def _artifact_path(env: Mapping[str, str], name: str) -> str:
    artifact_dir = Path(env.get("PKCS11_CHECK_ARTIFACT_DIR", DEFAULT_ARTIFACT_DIR))
    return str(artifact_dir / name)


def build_cli_args(env: Mapping[str, str]) -> list[str]:
    module = env.get("PKCS11_CHECK_MODULE", DEFAULT_MODULE)
    slot = env.get("PKCS11_CHECK_SLOT", DEFAULT_SLOT)
    interface = env.get("PKCS11_CHECK_INTERFACE", DEFAULT_INTERFACE)

    args = [
        "test",
        "--module",
        module,
        "--interface",
        interface,
        "--slot",
        slot,
        "--isolation",
        env.get("PKCS11_CHECK_ISOLATION", "auto"),
        "--output",
        "json",
        "--output-file",
        _artifact_path(env, "results.json"),
        "--state-file",
        _artifact_path(env, "state.json"),
        "--policy-file",
        _artifact_path(env, "policy.json"),
    ]

    timeout = env.get("PKCS11_CHECK_TIMEOUT")
    if timeout:
        args.extend(["--timeout", timeout])

    max_crashes = env.get("PKCS11_CHECK_MAX_CRASHES_PER_FILE")
    if max_crashes:
        args.extend(["--max-crashes-per-file", max_crashes])

    category = env.get("PKCS11_CHECK_CATEGORY")
    if category:
        args.extend(["--category", category])

    match = env.get("PKCS11_CHECK_MATCH")
    if match:
        args.extend(["--match", match])

    marker = env.get("PKCS11_CHECK_MARKER")
    if marker:
        args.extend(["--marker", marker])

    if env.get("PKCS11_CHECK_DESTRUCTIVE", "0") != "0":
        args.append("--destructive")

    args.extend(_shlex_split(env.get("PKCS11_CHECK_EXTRA_ARGS")))
    targets = _shlex_split(env.get("PKCS11_CHECK_TARGETS"))
    args.extend(targets if targets else [DEFAULT_TARGET])
    return args


def render_serial_command(env: Mapping[str, str]) -> str:
    python_path = env.get("PKCS11_CHECK_SITE", "/mnt/pkcs11-check/site")
    runner = env.get("PKCS11_CHECK_GUEST_RUNNER", "/mnt/pkcs11-check/guest-runner.py")
    return f"PYTHONPATH={shlex.quote(python_path)} python3 {shlex.quote(runner)}"
```

- [ ] **Step 2: Add token bootstrap**

Append:

```python
def initialize_token(env: Mapping[str, str]) -> None:
    module = env.get("PKCS11_CHECK_MODULE", DEFAULT_MODULE)
    slot_index = int(env.get("PKCS11_CHECK_SLOT", DEFAULT_SLOT))
    so_pin = env.get("PKCS11_CHECK_SO_PIN", "87654321").encode("utf-8")
    user_pin = env.get("PKCS11_CHECK_PIN", "1234").encode("utf-8")
    token_label = env.get("PKCS11_CHECK_TOKEN_LABEL", DEFAULT_TOKEN_LABEL)

    raw = RawPKCS11.from_lib(module)
    session = 0
    try:
        expect_rv(raw.C_Initialize(None), CKR_OK)
        slots = get_slot_ids(raw, token_present=True)
        if slot_index >= len(slots):
            raise RuntimeError(f"slot index {slot_index} not present")
        slot_id = slots[slot_index]
        init_token(raw, slot_id, so_pin, token_label)
        session = open_session(raw, slot_id, int(CKF_SERIAL_SESSION | CKF_RW_SESSION))
        login_user(raw, session, int(CKU_SO), so_pin)
        init_pin(raw, session, user_pin)
    finally:
        if session:
            logout_quietly(raw, session)
            close_session_quietly(raw, session)
        raw.C_Finalize(None)
```

Implementation note: this default expects a fresh per-run secure-storage directory. If reused storage is later needed, add a separate explicit env switch and tests for that behavior. Do not silently ignore failed initialization.

- [ ] **Step 3: Add CLI invocation and main**

Append:

```python
def run_pkcs11_check_cli(env: Mapping[str, str], args: Sequence[str]) -> int:
    original_argv = sys.argv[:]
    original_pin = os.environ.get("P11TEST_PIN")
    had_pin = "P11TEST_PIN" in os.environ
    try:
        os.environ["P11TEST_PIN"] = env.get("PKCS11_CHECK_PIN", "1234")
        sys.argv = ["pkcs11-check", *args]
        try:
            pkcs11_cli_main()
        except SystemExit as exc:
            code = exc.code
            if code is None:
                return 0
            if isinstance(code, int):
                return code
            return 1
        return 0
    finally:
        sys.argv = original_argv
        if had_pin:
            os.environ["P11TEST_PIN"] = original_pin or ""
        else:
            os.environ.pop("P11TEST_PIN", None)


def main() -> int:
    env = os.environ
    artifact_dir = Path(env.get("PKCS11_CHECK_ARTIFACT_DIR", DEFAULT_ARTIFACT_DIR))
    artifact_dir.mkdir(parents=True, exist_ok=True)
    initialize_token(env)
    return run_pkcs11_check_cli(env, build_cli_args(env))


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run the helper tests and lint the script**

```bash
uv run pytest -q tests/test_optee_guest_runner.py
uv run ruff check docker/optee-pkcs11/guest-runner.py tests/test_optee_guest_runner.py
```

Expected: pytest passes; ruff passes. If mypy complains about the test monkeypatch type, annotate the fixture correctly instead of using `Any`.

- [ ] **Step 5: Commit phase 1**

```bash
git add docker/optee-pkcs11/guest-runner.py tests/test_optee_guest_runner.py
git commit -m "docker: add optee guest runner helpers"
```

---

## Phase 2: Build guest site tree

### Task 3: Add build-guest-site.sh

**Files:**
- Create: `docker/optee-pkcs11/build-guest-site.sh`

- [ ] **Step 1: Create the script**

Create `docker/optee-pkcs11/build-guest-site.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

site_dir="${1:-/opt/pkcs11-check-site}"
work_dir="${PKCS11_CHECK_GUEST_SITE_WORK:-/tmp/pkcs11-check-guest-site}"

rm -rf "$site_dir" "$work_dir"
mkdir -p "$site_dir" "$work_dir"

uv build --wheel --out-dir "$work_dir/dist"
uv export \
    --frozen \
    --no-dev \
    --no-emit-project \
    --format requirements.txt \
    --no-hashes \
    --output-file "$work_dir/requirements.txt"

uv pip install \
    --target "$site_dir" \
    --python-version 3.13 \
    --python-platform aarch64-manylinux2014 \
    --only-binary :all: \
    --requirements "$work_dir/requirements.txt" \
    "$work_dir"/dist/*.whl

find "$site_dir" -type f -name '*.so' -print0 |
    xargs -0 -r file |
    tee "$work_dir/native-files.txt"

if grep -v 'aarch64' "$work_dir/native-files.txt" | grep -q '\.so'; then
    echo "non-aarch64 native extension found in guest site" >&2
    exit 1
fi
```

- [ ] **Step 2: Make it executable**

```bash
chmod +x docker/optee-pkcs11/build-guest-site.sh
```

- [ ] **Step 3: Run a local packaging smoke**

```bash
tmp_site="$(mktemp -d)"
bash docker/optee-pkcs11/build-guest-site.sh "$tmp_site/site"
du -sh "$tmp_site/site"
find "$tmp_site/site" -type f -name '*.so' -exec file {} + | head -20
rm -rf "$tmp_site"
```

Expected:
- `du` prints a site tree around tens of MiB.
- `file` output for native extensions says `aarch64`.
- no generated `site/bin/pkcs11-check` shebang is used by the runtime path.

- [ ] **Step 4: Commit**

```bash
git add docker/optee-pkcs11/build-guest-site.sh
git commit -m "docker: add optee guest site builder"
```

---

## Phase 3: Dockerfile and OP-TEE build

### Task 4: Add Dockerfile for OP-TEE QEMU target

**Files:**
- Create: `docker/optee-pkcs11/Dockerfile`

- [ ] **Step 1: Create the Dockerfile**

Create `docker/optee-pkcs11/Dockerfile`:

```dockerfile
# OP-TEE PKCS#11 QEMU target.
#
# Build args:
#   OPTEE_REF       OP-TEE manifest branch/tag

FROM debian:trixie

ARG OPTEE_REF="4.10.0"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    android-sdk-libsparse-utils \
    autoconf \
    automake \
    bc \
    bison \
    build-essential \
    ca-certificates \
    ccache \
    cpio \
    curl \
    device-tree-compiler \
    expect \
    file \
    flex \
    gawk \
    gcc-aarch64-linux-gnu \
    gcc-arm-linux-gnueabihf \
    git \
    libglib2.0-dev \
    libpixman-1-dev \
    libssl-dev \
    libtool \
    make \
    ninja-build \
    pkg-config \
    python-is-python3 \
    python3 \
    python3-cryptography \
    python3-pip \
    python3-pyelftools \
    python3-venv \
    repo \
    rsync \
    unzip \
    uuid-dev \
    wget \
    xz-utils \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /optee
RUN repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml -b "$OPTEE_REF" && \
    repo sync -j"$(nproc)" --no-clone-bundle

RUN make -C build toolchains

RUN make -C build \
    CFG_PKCS11_TA=y \
    CFG_PKCS11_TA_ALLOW_DIGEST_KEY=y \
    CFG_PKCS11_TA_AUTH_TEE_IDENTITY=y \
    CFG_PKCS11_TA_CHECK_VALUE_ATTRIBUTE=y \
    CFG_PKCS11_TA_RSA_X_509=y \
    CFG_PKCS11_TA_HEAP_SIZE='(128 * 1024)' \
    QEMU_VIRTFS_ENABLE=y \
    QEMU_PSS_ENABLE=y \
    BR2_PACKAGE_PYTHON3=y \
    BR2_PACKAGE_OPENSC=y \
    all

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src/pkcs11_check/__init__.py src/pkcs11_check/__init__.py
COPY third_party/ third_party/
COPY docker/optee-pkcs11/build-guest-site.sh docker/optee-pkcs11/build-guest-site.sh
RUN bash docker/optee-pkcs11/build-guest-site.sh /opt/pkcs11-check-site

COPY . .

RUN chmod +x \
    /app/docker/optee-pkcs11/build-guest-site.sh \
    /app/docker/optee-pkcs11/run-optee-pkcs11.sh \
    /app/docker/optee-pkcs11/optee-pkcs11.exp

ENV PKCS11_CHECK_MODULE=/usr/lib/libckteec.so
ENV PKCS11_CHECK_PIN=1234
ENV PKCS11_CHECK_SO_PIN=87654321
ENV PKCS11_CHECK_SLOT=0
ENV PKCS11_CHECK_INTERFACE=2.40

CMD ["bash", "/app/docker/run-with-artifacts.sh", "bash", "/app/docker/optee-pkcs11/run-optee-pkcs11.sh"]
```

Implementation note: if `repo` is not packaged in Debian trixie in the build environment, replace that package with:

```dockerfile
RUN curl -fsSL https://storage.googleapis.com/git-repo-downloads/repo -o /usr/local/bin/repo && \
    chmod +x /usr/local/bin/repo
```

Only make that change after a real Docker build proves the package is absent.

- [ ] **Step 2: Build to the first real failure**

```bash
docker compose -f docker/docker-compose.test.yml build test-optee-pkcs11
```

Expected after compose service is added in phase 5: the image starts OP-TEE build. If the build fails on missing packages, add only the package named by the error and rerun. If OP-TEE build flags have changed, verify against `build/qemu_v8.mk` and `optee_os/ta/pkcs11` before editing.

Do not commit this phase until the Dockerfile at least parses and begins the OP-TEE checkout/build.

---

## Phase 4: QEMU host wrapper and expect script

### Task 5: Add host wrapper

**Files:**
- Create: `docker/optee-pkcs11/run-optee-pkcs11.sh`

- [ ] **Step 1: Create wrapper**

Create `docker/optee-pkcs11/run-optee-pkcs11.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

artifact_dir="${PKCS11_CHECK_ARTIFACT_DIR:-/artifacts/optee-pkcs11}"
share_dir="${PKCS11_CHECK_OPTEE_SHARE_DIR:-/tmp/optee-pkcs11-share}"
secure_dir="${PKCS11_CHECK_OPTEE_SECURE_DIR:-/tmp/optee-pkcs11-secure}"
site_dir="${PKCS11_CHECK_GUEST_SITE_DIR:-/opt/pkcs11-check-site}"

rm -rf "$share_dir" "$secure_dir"
mkdir -p "$artifact_dir" "$share_dir/artifacts" "$secure_dir"

cp -a "$site_dir" "$share_dir/site"
cp /app/docker/optee-pkcs11/guest-runner.py "$share_dir/guest-runner.py"

python3 - <<'PY' > "$share_dir/runner.env"
from __future__ import annotations

import os
import shlex

names = [
    "PKCS11_CHECK_MODULE",
    "PKCS11_CHECK_PIN",
    "PKCS11_CHECK_SO_PIN",
    "PKCS11_CHECK_SLOT",
    "PKCS11_CHECK_INTERFACE",
    "PKCS11_CHECK_ISOLATION",
    "PKCS11_CHECK_TIMEOUT",
    "PKCS11_CHECK_CATEGORY",
    "PKCS11_CHECK_MATCH",
    "PKCS11_CHECK_MARKER",
    "PKCS11_CHECK_MAX_CRASHES_PER_FILE",
    "PKCS11_CHECK_DESTRUCTIVE",
    "PKCS11_CHECK_EXTRA_ARGS",
    "PKCS11_CHECK_TARGETS",
]
print("export PKCS11_CHECK_ARTIFACT_DIR=/mnt/pkcs11-check/artifacts")
for name in names:
    if name in os.environ:
        print(f"export {name}={shlex.quote(os.environ[name])}")
PY

export PKCS11_CHECK_OPTEE_SHARE_DIR="$share_dir"
export PKCS11_CHECK_OPTEE_SECURE_DIR="$secure_dir"

qemu_extra_args=(
    -fsdev "local,id=fsdev0,path=$share_dir,security_model=none"
    -device "virtio-9p-device,fsdev=fsdev0,mount_tag=host"
    -fsdev "local,id=fsdev1,path=$secure_dir,security_model=mapped-xattr"
    -device "virtio-9p-device,fsdev=fsdev1,mount_tag=secure"
)
printf -v qemu_extra '%q ' "${qemu_extra_args[@]}"
qemu_extra="${qemu_extra% }"

cp /app/docker/optee-pkcs11/optee-pkcs11.exp /optee/build/qemu-check.exp
chmod +x /optee/build/qemu-check.exp

make -C /optee/build \
    QEMU_EXTRA_ARGS="$qemu_extra" \
    DUMP_LOGS_ON_ERROR=y \
    check

cp -a "$share_dir/artifacts/." "$artifact_dir/"
cp /optee/out/bin/serial0.log "$artifact_dir/serial0.log"
cp /optee/out/bin/serial1.log "$artifact_dir/serial1.log"

for required in results.json state.json policy.json serial0.log serial1.log; do
    if [[ ! -s "$artifact_dir/$required" ]]; then
        echo "missing OP-TEE artifact: $artifact_dir/$required" >&2
        exit 1
    fi
done
```

- [ ] **Step 2: Make executable**

```bash
chmod +x docker/optee-pkcs11/run-optee-pkcs11.sh
```

### Task 6: Add expect script

**Files:**
- Create: `docker/optee-pkcs11/optee-pkcs11.exp`

- [ ] **Step 1: Add expect script**

Create `docker/optee-pkcs11/optee-pkcs11.exp`:

```tcl
#!/usr/bin/env expect
set timeout 900

log_user 0
log_file -a -noappend "serial0.log"

proc fail {message} {
    puts stderr $message
    exit 1
}

proc wait_prompt {} {
    expect {
        -re {/# } { return }
        -re {Kernel panic|panic|PANIC|ASSERTION|Assertion} { fail "OP-TEE/QEMU panic while waiting for prompt" }
        timeout { fail "timeout waiting for OP-TEE guest prompt" }
        eof { fail "QEMU exited before guest prompt" }
    }
}

open "serial1.log" "w+"
spawn -open [open "|tail -f serial1.log"]
set teecore $spawn_id

spawn sh -c "$::env(QEMU) $::env(QEMU_CHECK_ARGS)"
expect {
    -re {Kernel panic|panic|PANIC|ASSERTION|Assertion} { fail "OP-TEE/QEMU panic during boot" }
    timeout { fail "timeout booting OP-TEE guest" }
    eof { fail "QEMU exited before login" }
    "ogin:" {}
}
send -- "root\r\r"
wait_prompt

send -- "export LD_LIBRARY_PATH=/lib:/lib/arm-linux-gnueabihf\r"
wait_prompt
send -- "mkdir -p /mnt/pkcs11-check /var/lib/tee\r"
wait_prompt
send -- "mount -t 9p -o trans=virtio,version=9p2000.L host /mnt/pkcs11-check\r"
wait_prompt
send -- "mount -t 9p -o trans=virtio,version=9p2000.L secure /var/lib/tee\r"
wait_prompt
send -- "pgrep tee-supplicant >/dev/null || tee-supplicant -d /dev/tee0 &\r"
wait_prompt
send -- ". /mnt/pkcs11-check/runner.env && pkcs11-tool --module /usr/lib/libckteec.so --show-info >/mnt/pkcs11-check/artifacts/pkcs11-tool-info.txt\r"
wait_prompt
send -- "cd /mnt/pkcs11-check && . ./runner.env && PYTHONPATH=/mnt/pkcs11-check/site python3 /mnt/pkcs11-check/guest-runner.py; echo OPTEE_PKCS11_EXIT:\\$?\r"

expect {
    -re {OPTEE_PKCS11_EXIT:([0-9]+)} {
        set rc $expect_out(1,string)
        if {$rc ne "0"} {
            fail "guest runner failed with exit $rc"
        }
    }
    -re {Kernel panic|panic|PANIC|ASSERTION|Assertion} { fail "OP-TEE/QEMU panic during pkcs11-check" }
    timeout { fail "timeout running pkcs11-check in OP-TEE guest" }
    eof { fail "QEMU exited during pkcs11-check" }
}

wait_prompt
send -- "sync\r"
wait_prompt
send -- "poweroff -f\r"
expect {
    eof { exit 0 }
    timeout { exit 0 }
}
```

Implementation note: this intentionally uses OP-TEE's `check` target path, not `run-only`. `run-only` launches TCP serial terminals via `launch-terminal`, which is unsuitable for Docker. The wrapper replaces the checkout's `qemu-check.exp` inside the disposable image so `make check` still computes and exports `QEMU` and `QEMU_CHECK_ARGS`, while the custom script runs `pkcs11-check` instead of `xtest`.

- [ ] **Step 2: Smoke-check shell syntax**

```bash
bash -n docker/optee-pkcs11/run-optee-pkcs11.sh
expect -n docker/optee-pkcs11/optee-pkcs11.exp
```

Expected: no syntax errors. If `expect -n` is unavailable locally, run it inside the target container during Docker validation.

- [ ] **Step 3: Commit phase 4**

```bash
git add docker/optee-pkcs11/run-optee-pkcs11.sh docker/optee-pkcs11/optee-pkcs11.exp
git commit -m "docker: add optee qemu runner"
```

---

## Phase 5: Compose, source manifest, and matrix integration

### Task 7: Add compose service

**Files:**
- Modify: `docker/docker-compose.test.yml`

- [ ] **Step 1: Add service comment to the header**

In the "Additional/experimental" header comment, add:

```yaml
#   docker compose -f docker/docker-compose.test.yml run test-optee-pkcs11
```

- [ ] **Step 2: Add service after `test-corepkcs11` or under Additional implementations**

Add:

```yaml
  # OP-TEE PKCS#11 TA 4.10.0 (QEMU v8 guest, v2.40)
  test-optee-pkcs11:
    <<: *common
    build:
      context: ..
      dockerfile: docker/optee-pkcs11/Dockerfile
      args:
        OPTEE_REF: "4.10.0"
    environment:
      PKCS11_CHECK_ARTIFACT_DIR: /artifacts/optee-pkcs11
      PKCS11_CHECK_MODULE: /usr/lib/libckteec.so
      PKCS11_CHECK_INTERFACE: "2.40"
      PKCS11_CHECK_PIN: "1234"
      PKCS11_CHECK_SO_PIN: "87654321"
      PKCS11_CHECK_SLOT: "0"
```

- [ ] **Step 3: Validate compose config**

```bash
docker compose -f docker/docker-compose.test.yml config --services | grep '^test-optee-pkcs11$'
```

Expected:

```text
test-optee-pkcs11
```

### Task 8: Add heavy provider handling

**Files:**
- Modify: `docker/test-all.sh`

- [ ] **Step 1: Add `HEAVY_PROVIDERS` after `ALL_PROVIDERS`**

```bash
HEAVY_PROVIDERS=(
    optee-pkcs11
)
```

- [ ] **Step 2: Add helper that checks both regular and heavy lists**

Replace `_is_provider()` with:

```bash
_contains_provider() {
    local name="${1#test-}"
    shift
    local t
    for t in "$@"; do
        [[ "$name" == "$t" ]] && return 0
    done
    return 1
}

_is_provider() {
    local name="${1#test-}"
    _contains_provider "$name" "${ALL_PROVIDERS[@]}" && return 0
    _contains_provider "$name" "${HEAVY_PROVIDERS[@]}" && return 0
    return 1
}
```

- [ ] **Step 3: Add flag handling**

In argument parsing, after `--all`, add:

```bash
    elif [[ "$arg" == "--heavy" || "$arg" == "--all-heavy" ]]; then
        providers=("${HEAVY_PROVIDERS[@]}")
```

Keep `--all` unchanged. Do not append heavy providers to regular `ALL_PROVIDERS`.

- [ ] **Step 4: Validate parser behavior without running Docker**

Use a dry-run helper by temporarily invoking the script with a harmless unrecognized shared argument and stopping before Docker is not available is not built into the script. Instead, inspect with shellcheck if available and run one direct help path:

```bash
bash -n docker/test-all.sh
bash docker/test-all.sh --help >/tmp/pkcs11-check-test-all-help.txt || true
```

Expected:
- `bash -n` succeeds.
- The script does not have a dedicated `--help` mode today; do not add one unless needed.

### Task 9: Add source manifest entries

**Files:**
- Modify: `docker/provider-sources.toml`

- [ ] **Step 1: Add OP-TEE source entries near other provider sources**

Add:

```toml
[sources.optee_manifest_release]
kind = "git_tag"
repo = "https://github.com/OP-TEE/manifest.git"
selector = "4.10.0"
commit = "6d5849d5c1e4054980bf430ce1e96ebd0f532590"
commit_date = "2026-04-17T09:59:45Z"
role = "optee_qemu_v8_manifest"

[sources.optee_os_release]
kind = "git_tag"
repo = "https://github.com/OP-TEE/optee_os.git"
selector = "4.10.0"
commit = "753afbbee1682f5d16fd30e87b31058a4fd4f4b8"
commit_date = "2026-04-17T09:49:20Z"
role = "optee_secure_world_and_pkcs11_ta"

[sources.optee_client_release]
kind = "git_tag"
repo = "https://github.com/OP-TEE/optee_client.git"
selector = "4.10.0"
commit = "9f5e90918093c1d1cd264d8149081b64ab7ba672"
commit_date = "2026-01-05T08:42:34Z"
role = "optee_libckteec"

[sources.optee_build_release]
kind = "git_tag"
repo = "https://github.com/OP-TEE/build.git"
selector = "4.10.0"
commit = "53bfd321ee7fd47e450fb88c04b08ea27819f9bc"
commit_date = "2026-04-14T11:39:40Z"
role = "optee_qemu_v8_build"

[sources.optee_test_release]
kind = "git_tag"
repo = "https://github.com/OP-TEE/optee_test.git"
selector = "4.10.0"
commit = "88c93e87a5c172363ee986ded036a25cafcc9d2c"
commit_date = "2026-03-19T12:52:46Z"
role = "optee_xtest_reference"

[sources.optee_examples_release]
kind = "git_tag"
repo = "https://github.com/linaro-swg/optee_examples.git"
selector = "4.10.0"
commit = "934c7edb74a26e90f68024cf441073528444177f"
commit_date = "2025-12-29T16:12:43Z"
role = "optee_example_reference"

[sources.optee_buildroot_manifest_pin]
kind = "git_tag"
repo = "https://github.com/buildroot/buildroot.git"
selector = "2025.05"
commit = "fcde5363aa35220a1f201159a05de652ec6f811f"
commit_date = "2025-06-09T20:21:47Z"
role = "optee_manifest_buildroot_pin"

[sources.optee_qemu_manifest_pin]
kind = "git_tag"
repo = "https://github.com/qemu/qemu.git"
selector = "v10.0.0"
commit = "7c949c53e936aa3a658d84ab53bae5cadaa5d59c"
commit_date = "2025-04-22T13:32:33Z"
role = "optee_manifest_qemu_pin"
```

The commit dates above were fetched from the GitHub commits API on 2026-06-06. If any ref changes during later source-refresh work, rerun that lookup and update the dates from source evidence rather than inventing release-day dates.

- [ ] **Step 2: Add target entry**

Add:

```toml
[targets.optee_pkcs11]
service = "test-optee-pkcs11"
provider = "OP-TEE PKCS#11 TA"
release_source = "optee_manifest_release"
supporting_sources = [
  "optee_os_release",
  "optee_client_release",
  "optee_build_release",
  "optee_test_release",
  "optee_examples_release",
  "optee_buildroot_manifest_pin",
  "optee_qemu_manifest_pin",
]
openssl = "not OpenSSL-based: OP-TEE manifest uses Mbed TLS mbedtls-3.6.5"
build_features = "OP-TEE qemu_v8 with CFG_PKCS11_TA, digest-key, TEE-identity auth, check-value, RSA_X_509, enlarged TA heap, virtfs, persistent secure storage, Buildroot Python 3"
build_evidence = "planned heavy/manual Docker target; build validation pending"
```

- [ ] **Step 3: Parse the TOML**

```bash
uv run python - <<'PY'
from pathlib import Path
import tomllib

tomllib.loads(Path("docker/provider-sources.toml").read_text())
print("ok")
PY
```

Expected:

```text
ok
```

### Task 10: Commit integration metadata

- [ ] **Step 1: Commit compose, matrix, and source manifest**

```bash
git add docker/docker-compose.test.yml docker/test-all.sh docker/provider-sources.toml
git commit -m "docker: register optee pkcs11 heavy target"
```

---

## Phase 6: Documentation

### Task 11: Update command docs

**Files:**
- Modify: `docs/commands.md`

- [ ] **Step 1: Add provider name**

In `### Available providers`, add `optee-pkcs11` under a heavy/manual note, not in the normal provider list.

Add command examples:

```bash
bash docker/test.sh optee-pkcs11 -- src/pkcs11_check/testcases/test_interface.py
bash docker/test-all.sh --heavy -- src/pkcs11_check/testcases/test_interface.py
```

State that OP-TEE is QEMU-backed and slow, so it is excluded from default and normal `--all`.

### Task 12: Update architecture docs

**Files:**
- Modify: `docs/architecture.md`

- [ ] **Step 1: Add Docker matrix bullet**

In `## Docker test matrix`, add:

```markdown
- `test-optee-pkcs11` - OP-TEE 4.10.0 PKCS#11 TA through `libckteec.so`, run inside an OP-TEE QEMU v8 guest; heavy/manual target, v2.40.
```

### Task 13: Update artifact docs

**Files:**
- Modify: `docs/docker-artifacts.md`

- [ ] **Step 1: Add OP-TEE serial artifacts**

In the artifact contract section, add that OP-TEE additionally emits:

```markdown
- `serial0.log` - normal-world UART from the OP-TEE QEMU guest
- `serial1.log` - secure-world UART from the OP-TEE QEMU guest
- `pkcs11-tool-info.txt` - lightweight guest-side `libckteec.so` sanity probe
```

Do not add OP-TEE result counts.

### Task 14: Commit documentation

```bash
git add docs/commands.md docs/architecture.md docs/docker-artifacts.md
git commit -m "docs: document optee pkcs11 docker target"
```

---

## Phase 7: Verification

### Task 15: Run local static/test checks

- [ ] **Step 1: Run targeted tests**

```bash
uv run pytest -q tests/test_optee_guest_runner.py
```

Expected: passes.

- [ ] **Step 2: Run lint**

```bash
uv run ruff check docker/optee-pkcs11/guest-runner.py tests/test_optee_guest_runner.py
```

Expected: passes.

- [ ] **Step 3: Run shell syntax checks**

```bash
bash -n docker/optee-pkcs11/build-guest-site.sh
bash -n docker/optee-pkcs11/run-optee-pkcs11.sh
bash -n docker/test-all.sh
```

Expected: all pass.

- [ ] **Step 4: Run compose config check**

```bash
docker compose -f docker/docker-compose.test.yml config --services | grep '^test-optee-pkcs11$'
```

Expected: prints `test-optee-pkcs11`.

### Task 16: Run Docker build smoke

- [ ] **Step 1: Build OP-TEE image**

```bash
docker compose -f docker/docker-compose.test.yml build test-optee-pkcs11
```

Expected: image builds. If this takes hours, keep a separate terminal log and do not call the target validated until the build exits zero.

- [ ] **Step 2: Run a narrow provider smoke**

```bash
bash docker/test.sh optee-pkcs11 --timeout 120 -- src/pkcs11_check/testcases/test_interface.py
```

Expected:
- command exits zero or with real pkcs11-check findings captured in `results.json`;
- `artifacts/optee-pkcs11/results.json` exists;
- `artifacts/optee-pkcs11/state.json` exists;
- `artifacts/optee-pkcs11/policy.json` exists;
- `artifacts/optee-pkcs11/serial0.log` exists;
- `artifacts/optee-pkcs11/serial1.log` exists.

If the guest or QEMU environment dies before producing artifacts, fix the runner or OP-TEE build. Do not classify an environment failure as a provider result.

- [ ] **Step 3: Check for forbidden PIN leakage**

```bash
if grep -R "1234\\|87654321" artifacts/optee-pkcs11/console.log artifacts/optee-pkcs11/serial0.log artifacts/optee-pkcs11/serial1.log; then
    echo "PIN leaked into OP-TEE artifacts" >&2
    exit 1
fi
```

Expected: no output and exit zero. If `pkcs11-tool` or OP-TEE itself prints PIN material, remove that command path or redact before artifact publication.

### Task 17: Inspect results and decide next breadth

- [ ] **Step 1: Summarize smoke result**

```bash
uv run python - <<'PY'
from pathlib import Path
import json

path = Path("artifacts/optee-pkcs11/results.json")
data = json.loads(path.read_text())
summary = data.get("summary", data)
print(summary)
PY
```

Expected: a coherent summary object. Do not copy exact counts into release docs unless this is declared a full release validation run.

- [ ] **Step 2: Run selected mechanism files if smoke is coherent**

```bash
bash docker/test.sh optee-pkcs11 --timeout 180 -- \
    src/pkcs11_check/testcases/test_digest.py \
    src/pkcs11_check/testcases/test_mech_digest.py \
    src/pkcs11_check/testcases/test_sign_verify.py \
    src/pkcs11_check/testcases/test_encrypt_decrypt.py \
    src/pkcs11_check/testcases/test_wrap_unwrap.py
```

Expected: coherent pkcs11-check artifacts. Failures and crashes are findings unless they are QEMU/OP-TEE environment failures that prevent artifact generation.

### Task 18: Final branch review

- [ ] **Step 1: Inspect git diff**

```bash
git diff --stat HEAD~5..HEAD
git diff --check HEAD~5..HEAD
git status --short
```

Expected:
- no whitespace errors;
- only OP-TEE target, docs, tests, compose, and source manifest files changed;
- no unrelated dirty files staged.

- [ ] **Step 2: Do not merge to main**

If this work is on a feature branch, merge to `dev` only:

```bash
git checkout dev
git merge <feature-branch-name>
```

Do not merge to `main`.

---

## Known risk register

- OP-TEE build time may be long. Treat this as a heavy target and optimize caching only after correctness is proven.
- The expect script may need adjustment if OP-TEE changes the 9p tag names currently defined in `common.mk` as `host` and `secure`. Verify against `/optee/build/common.mk` during implementation.
- `C_InitToken` may fail if OP-TEE secure storage is not fresh. Default wrapper deletes the per-run secure-storage directory; if a reused storage mode is added later, it needs explicit env naming and tests.
- `pkcs11-tool --show-info` is only a sanity probe. If it blocks or prints unexpected sensitive data, remove it and rely on raw Python preflight.
- Exact commit dates in `provider-sources.toml` must be source-grounded. If GitHub commit-date lookup is not performed during implementation, use evidence wording that says the refs were verified and avoid pretending exact dates are known.
- A provider crash inside pkcs11-check subprocess isolation is a provider finding. A kernel panic, secure-world panic, QEMU exit, guest boot timeout, or missing result file is a harness/environment failure to fix before statistics are trusted.
