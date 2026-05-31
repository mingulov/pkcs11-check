"""Threading / concurrency conformance tests.

PKCS#11 v3.2 Sec.5.4: an application may call the library concurrently from
multiple threads **only** if it initialized with ``CK_C_INITIALIZE_ARGS``
carrying ``CKF_OS_LOCKING_OK`` (or four application mutex callbacks). With NULL
``pInitArgs`` the application promises single-threaded use and the library
"need not perform any synchronization" -- so concurrent access is **undefined
behavior** and a crash is permitted.

pkcs11-check's shared-session fixtures initialize every module with
``C_Initialize(None)`` (single-threaded mode), so concurrency MUST NOT be
exercised on the shared session -- doing so is the *harness* violating its own
declared contract, not a module bug (see docs/module-issues.md). These tests
therefore run their concurrent workload in a dedicated **child process** that
performs its own ``C_Initialize``:

- ``TestConcurrentUnderOSLocking`` -- init with ``CKF_OS_LOCKING_OK`` then hammer
  concurrent ``C_GenerateKey`` / ``C_Digest`` / ``C_GenerateRandom``. This is the
  spec-valid multi-threaded contract, so a crash (``returncode < 0``) is a
  genuine module thread-safety **finding** (FAIL). A module that cannot lock
  (``CKR_CANT_LOCK``) is skipped (capability genuinely absent).
- ``TestConcurrentNullInitUBProbe`` -- init with NULL ``pInitArgs`` then access
  concurrently == documented misuse. A crash here is *permitted* by the spec, so
  it is recorded as ``xfail`` (not a conformance failure); a module that survives
  is noted as robust-beyond-spec. SoftHSM2 crashes ~always at high thread counts
  here -- this probe reliably reproduces and documents that, and pins the harness
  contract.

Both classes run the workload in a child subprocess, so a crash kills only the
child and is observed via its return code -- the test file's own process never
segfaults, so this file no longer produces a spurious file-level ``crashed`` in
the matrix. Marked ``@destructive`` (each child runs ``C_Initialize`` /
``C_Finalize`` and concurrent ``C_GenerateKey`` mutates/contends token state) and
``@stress``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

pytestmark = [pytest.mark.stress, pytest.mark.destructive]


def _make_throwaway_softhsm_token(p11_config: Any, tmp_path: Path) -> str | None:
    """Provision a disposable SoftHSM2 token; return its SOFTHSM2_CONF path.

    Concurrent ``C_GenerateKey`` that crashes mid-write corrupts a file-backed
    token (``CKR_TOKEN_NOT_RECOGNIZED`` for every later test). So the crash-prone
    workloads must NOT run against the shared session token. For SoftHSM2 (a
    relocatable file-backed token, Tier 1 in docs/destructive-token-isolation.md)
    we mint a throwaway token in ``tmp_path`` -- a crash then damages only that.

    Returns ``None`` when the module is not SoftHSM2 or ``softhsm2-util`` is
    absent (no portable throwaway primitive for that module); callers decide
    whether to fall back to the shared token or skip.
    """
    module = str(p11_config.module)
    if "softhsm" not in module.lower() or shutil.which("softhsm2-util") is None:
        return None
    conf = tmp_path / "softhsm2.conf"
    tokens = tmp_path / "tokens"
    tokens.mkdir(parents=True, exist_ok=True)
    conf.write_text(
        f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\n"
    )
    pin = p11_config.pin.get_secret_value() if p11_config.pin else "1234"
    env = dict(os.environ)
    env["SOFTHSM2_CONF"] = str(conf)
    proc = subprocess.run(
        # fmt: off
        [
            "softhsm2-util",
            "--init-token",
            "--slot",
            "0",
            "--label",
            "pkcs11-check-thread",
            "--pin",
            pin,
            "--so-pin",
            "12345678",
        ],
        # fmt: on
        env=env,
        capture_output=True,
        text=True,
    )
    return str(conf) if proc.returncode == 0 else None


# Fixed child script: ALL parameters arrive via environment variables (no code
# interpolation, and the PIN is never embedded in source or printed). It runs
# its own C_Initialize so it is independent of the parent's NULL-init module.
_WORKLOAD_SCRIPT = r"""
import concurrent.futures
import ctypes
import os
import sys

from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    get_slot_ids,
    login_user,
    open_session,
)
from pkcs11_check.raw.recipes import destroy_quietly, digest_single, gen_aes_key, generate_random
from pkcs11_check.raw.types_std import (
    CK_C_INITIALIZE_ARGS,
    CKF_OS_LOCKING_OK,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_SHA256,
    CKR_CANT_LOCK,
    CKR_OK,
    CKU_USER,
)

MODULE = os.environ["P11_THREAD_MODULE"]
SLOT_INDEX = int(os.environ.get("P11_THREAD_SLOT", "0"))
THREADS = int(os.environ["P11_THREAD_THREADS"])
ITERS = int(os.environ["P11_THREAD_ITERS"])
WORKLOAD = os.environ["P11_THREAD_WORKLOAD"]
LOCKING = os.environ.get("P11_THREAD_LOCKING") == "1"
_pin = os.environ.get("P11_THREAD_PIN", "")
PIN = _pin.encode() if _pin else None
FLAGS = CKF_SERIAL_SESSION | CKF_RW_SESSION

raw = RawPKCS11.from_lib(MODULE)
if LOCKING:
    args = CK_C_INITIALIZE_ARGS()
    args.flags = int(CKF_OS_LOCKING_OK)
    rv = int(raw.C_Initialize(ctypes.byref(args)))
    if rv == int(CKR_CANT_LOCK):
        print("SKIP_CANT_LOCK")
        sys.exit(0)
    assert rv == int(CKR_OK), hex(rv)
else:
    rv = int(raw.C_Initialize(None))
    assert rv == int(CKR_OK), hex(rv)

slots = get_slot_ids(raw)
slot = slots[SLOT_INDEX] if SLOT_INDEX < len(slots) else slots[0]


def _op(sh):
    if WORKLOAD == "keygen":
        k = gen_aes_key(raw, sh, 256)
        destroy_quietly(raw, sh, k)
    elif WORKLOAD == "digest":
        digest_single(raw, sh, CKM_SHA256, b"concurrent-digest-payload")
    elif WORKLOAD == "random":
        generate_random(raw, sh, 32)
    else:
        raise SystemExit("unknown workload: " + WORKLOAD)


def worker(_n):
    sh = open_session(raw, slot, FLAGS)
    try:
        if PIN is not None:
            try:
                login_user(raw, sh, CKU_USER, PIN)
            except Exception:
                pass
        for _ in range(ITERS):
            _op(sh)
    finally:
        close_session_quietly(raw, sh)
    return 0


with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
    list(pool.map(worker, range(THREADS)))

raw.C_Finalize(None)
print("OK")
"""


def _run_threaded_workload(
    p11_config: Any,
    *,
    locking: bool,
    workload: str,
    threads: int,
    iters: int,
    softhsm2_conf: str | None = None,
    timeout: float = 120.0,
) -> tuple[int | None, str, str]:
    """Run the concurrent workload in a child process.

    Returns ``(returncode, stdout, stderr)``. ``returncode`` is ``None`` on
    timeout (a hang under concurrency), ``< 0`` on a crash signal, ``0`` on a
    clean finish. The PIN is passed via the environment, never embedded in the
    script source or echoed. When ``softhsm2_conf`` is given the child runs
    against that disposable token (so a crash cannot corrupt the shared one).
    """
    env = dict(os.environ)
    if softhsm2_conf is not None:
        env["SOFTHSM2_CONF"] = softhsm2_conf
    env["P11_THREAD_MODULE"] = str(p11_config.module)
    env["P11_THREAD_SLOT"] = str(p11_config.slot if p11_config.slot is not None else 0)
    env["P11_THREAD_THREADS"] = str(threads)
    env["P11_THREAD_ITERS"] = str(iters)
    env["P11_THREAD_WORKLOAD"] = workload
    env["P11_THREAD_LOCKING"] = "1" if locking else "0"
    env["P11_THREAD_PIN"] = p11_config.pin.get_secret_value() if p11_config.pin else ""
    try:
        result = subprocess.run(
            [sys.executable, "-c", _WORKLOAD_SCRIPT],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return None, "", "TIMEOUT"
    return result.returncode, result.stdout.strip(), result.stderr.strip()


_WORKLOADS = ["keygen", "digest", "random"]


class TestConcurrentUnderOSLocking:
    """Concurrency under the spec-valid CKF_OS_LOCKING_OK contract.

    A crash or hang here is a genuine module thread-safety FINDING.
    """

    @pytest.mark.parametrize("workload", _WORKLOADS)
    def test_concurrent_workload_os_locking(
        self, p11_config: Any, workload: str, tmp_path: Path
    ) -> None:
        # Use a throwaway token where we can isolate one (SoftHSM2), so even a
        # crash finding here cannot poison the shared token; other modules fall
        # back to the configured token (a conformant module does not corrupt it).
        conf = _make_throwaway_softhsm_token(p11_config, tmp_path)
        rc, stdout, stderr = _run_threaded_workload(
            p11_config, locking=True, workload=workload, threads=16, iters=100, softhsm2_conf=conf
        )
        if "SKIP_CANT_LOCK" in stdout:
            pytest.skip(
                "module returned CKR_CANT_LOCK for CKF_OS_LOCKING_OK "
                "(no multi-threaded support advertised)"
            )
        if rc is None:
            pytest.fail(
                f"{workload}: module HUNG under CKF_OS_LOCKING_OK concurrency "
                f"(timeout) -- a spec-valid multi-threaded contract must make progress"
            )
        if rc < 0:
            pytest.fail(
                f"{workload}: module SIGSEGV (signal {-rc}) under CKF_OS_LOCKING_OK "
                f"concurrency -- a spec-valid multi-threaded contract MUST be "
                f"crash-safe. stderr: {stderr}"
            )
        assert "OK" in stdout, (
            f"{workload}: child did not finish cleanly under CKF_OS_LOCKING_OK "
            f"(rc={rc}); stdout={stdout!r} stderr={stderr!r}"
        )


class TestConcurrentNullInitUBProbe:
    """Reliable reproducer for the NULL-init concurrent-access crash.

    NULL pInitArgs + multi-threaded access is undefined behavior per PKCS#11
    Sec.5.4 (the application declared single-threaded), so a crash is *permitted*
    and is NOT a conformance failure -- it is recorded as ``xfail``. A module that
    survives is robust beyond spec (``pass``). This pins the harness contract and
    explains why a module may appear to "crash" if concurrency is run on the
    shared NULL-initialized session.
    """

    def test_null_init_concurrent_keygen_is_ub(self, p11_config: Any, tmp_path: Path) -> None:
        # This probe crashes the module ~always, which corrupts a file-backed
        # token -- so it MUST run against a disposable token. If we cannot
        # isolate one for this module, skip rather than risk the shared token.
        conf = _make_throwaway_softhsm_token(p11_config, tmp_path)
        if conf is None:
            pytest.skip(
                "NULL-init concurrency crash probe (documented misuse per PKCS#11 "
                "Sec.5.4, not a provider crash finding) needs an isolatable throwaway "
                "token (SoftHSM2); refusing to risk corrupting the shared token"
            )
        rc, stdout, stderr = _run_threaded_workload(
            p11_config, locking=False, workload="keygen", threads=32, iters=200, softhsm2_conf=conf
        )
        if rc is None:
            pytest.xfail(
                "module hung under NULL-init concurrency -- undefined behavior "
                "per PKCS#11 Sec.5.4 (app declared single-threaded), not a "
                "conformance bug; use CKF_OS_LOCKING_OK for multi-threaded access"
            )
        if rc < 0:
            pytest.xfail(
                f"module SIGSEGV (signal {-rc}) under NULL-init concurrency -- "
                f"undefined behavior per PKCS#11 Sec.5.4 (app declared "
                f"single-threaded), not a conformance bug; use CKF_OS_LOCKING_OK "
                f"for multi-threaded access"
            )
        if "OK" not in stdout:
            pytest.xfail(
                f"module errored (rc={rc}) under NULL-init concurrency -- "
                f"undefined behavior per PKCS#11 Sec.5.4; stderr={stderr!r}"
            )
        # Reached only if the module survived documented misuse: robust beyond spec.
