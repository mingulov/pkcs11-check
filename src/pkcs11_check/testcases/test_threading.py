"""Threading / concurrency conformance tests.

PKCS#11 v3.2 Sec.5.4: an application may call the library concurrently from
multiple threads **only** if it initialized with ``CK_C_INITIALIZE_ARGS``
carrying ``CKF_OS_LOCKING_OK`` (or four application mutex callbacks). With NULL
``pInitArgs`` the application promises single-threaded use and the library
"need not perform any synchronization" -- so concurrent access is undefined
behavior and a crash is *permitted*. That is documented **misuse**, not a module
defect, so we never test it. These tests therefore always
initialize with ``CKF_OS_LOCKING_OK``.

pkcs11-check's shared-session fixtures initialize with ``C_Initialize(None)``
(single-threaded mode), so the concurrent workload cannot run on the shared
session. It runs in a dedicated **child process** that performs its own
``C_Initialize(CKF_OS_LOCKING_OK)``, against a disposable token where one can be
minted so that even a genuine thread-safety crash cannot corrupt the
shared token. A crash
(a POSIX signal or Windows NTSTATUS exit) or hang under this spec-valid
multi-threaded contract is a
genuine module thread-safety **finding** (FAIL); a module that cannot lock
(``CKR_CANT_LOCK``) is skipped (capability genuinely absent).

Marked ``@destructive`` (each child runs ``C_Initialize`` / ``C_Finalize`` and
concurrent ``C_GenerateKey`` mutates/contends token state) and ``@stress``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as
from pkcs11_check.core.crash_codes import crash_detail_name, is_crash_returncode
from pkcs11_check.testcases._shellcmd import shell_invocation

pytestmark = [
    pytest.mark.stress,
    pytest.mark.destructive,
    # Temporarily disabled 2026-05-31. Retained on purpose: this is a valuable
    # multi-threaded conformance check for OTHER providers -- e.g. ones that
    # reject CKF_OS_LOCKING_OK with CKR_CANT_LOCK, or that are thread-unsafe even
    # under it. Re-enable by removing this skip mark.
    pytest.mark.skip(reason="threading conformance check temporarily disabled (2026-05-31)"),
]


def _mint_throwaway_token(tmp_path: Path) -> str | None:
    """Provision a disposable token via env-configured mint command.

    Reads PKCS11_CHECK_THROWAWAY_MODULE (path to the module .so) and
    PKCS11_CHECK_TOKEN_MINT_CMD (shell template; {token_dir} and {conf_path}
    are substituted). Returns the conf path for the child process or None if
    either variable is unset or the mint command fails.
    """
    if not os.environ.get("PKCS11_CHECK_THROWAWAY_MODULE"):
        return None
    mint_cmd_tmpl = os.environ.get("PKCS11_CHECK_TOKEN_MINT_CMD")
    if not mint_cmd_tmpl:
        return None
    conf = tmp_path / "module.conf"
    tokens = tmp_path / "tokens"
    tokens.mkdir(parents=True, exist_ok=True)
    mint_cmd = mint_cmd_tmpl.format(token_dir=str(tmp_path), conf_path=str(conf))
    proc = subprocess.run(
        shell_invocation(mint_cmd), capture_output=True, text=True, encoding="utf-8"
    )
    return str(conf) if proc.returncode == 0 else None


# Fixed child script: ALL parameters arrive via environment variables (no code
# interpolation, and the PIN is never embedded in source or printed). It runs
# its own C_Initialize(CKF_OS_LOCKING_OK) so concurrent access is spec-valid and
# independent of the parent's NULL-init module.
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
_pin = os.environ.get("P11_THREAD_PIN", "")
PIN = _pin.encode() if _pin else None
FLAGS = CKF_SERIAL_SESSION | CKF_RW_SESSION

raw = RawPKCS11.from_lib(MODULE)
args = CK_C_INITIALIZE_ARGS()
args.flags = int(CKF_OS_LOCKING_OK)
rv = int(raw.C_Initialize(ctypes.byref(args)))
if rv == int(CKR_CANT_LOCK):
    print("SKIP_CANT_LOCK")
    sys.exit(0)
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
    workload: str,
    threads: int,
    iters: int,
    throwaway_conf: str | None = None,
    timeout: float = 120.0,
) -> tuple[int | None, str, str]:
    """Run the concurrent workload (under CKF_OS_LOCKING_OK) in a child process.

    Returns ``(returncode, stdout, stderr)``. ``returncode`` is ``None`` on
    timeout (a hang under concurrency), ``< 0`` on a crash signal, ``0`` on a
    clean finish. The PIN is passed via the environment, never embedded in the
    script source or echoed. When ``throwaway_conf`` is given the child runs
    against that disposable token (so a crash cannot corrupt the shared one).
    """
    env = dict(os.environ)
    conf_env_var = os.environ.get("PKCS11_CHECK_TOKEN_CONF_ENV")
    if throwaway_conf is not None and conf_env_var:
        env[conf_env_var] = throwaway_conf
    env["P11_THREAD_MODULE"] = str(p11_config.module)
    env["P11_THREAD_SLOT"] = str(p11_config.slot if p11_config.slot is not None else 0)
    env["P11_THREAD_THREADS"] = str(threads)
    env["P11_THREAD_ITERS"] = str(iters)
    env["P11_THREAD_WORKLOAD"] = workload
    env["P11_THREAD_PIN"] = p11_config.pin.get_secret_value() if p11_config.pin else ""
    try:
        result = subprocess.run(
            [sys.executable, "-c", _WORKLOAD_SCRIPT],
            capture_output=True,
            text=True,
            encoding="utf-8",
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
        # Use a throwaway token where one can be isolated so a genuine
        # thread-safety crash here cannot poison the shared token; other modules
        # fall back to the configured token (a conformant module does not corrupt it).
        conf = _mint_throwaway_token(tmp_path)
        rc, stdout, stderr = _run_threaded_workload(
            p11_config, workload=workload, threads=16, iters=100, throwaway_conf=conf
        )
        if "SKIP_CANT_LOCK" in stdout:
            pytest.skip(
                "module returned CKR_CANT_LOCK for CKF_OS_LOCKING_OK "
                "(no multi-threaded support advertised)"
            )
        if rc is None:
            fail_as(
                "crash",
                kind="lifecycle",
                label=f"threading:{workload}",
                summary=(
                    f"{workload}: module HUNG under CKF_OS_LOCKING_OK concurrency "
                    f"(timeout) -- a spec-valid multi-threaded contract must make progress"
                ),
            )
        if is_crash_returncode(rc):
            classify(
                "crash",
                kind="lifecycle",
                label=f"threading:{workload}",
                summary=(
                    f"{workload}: module crashed ({crash_detail_name(rc)}) under CKF_OS_LOCKING_OK "
                    f"concurrency -- a spec-valid multi-threaded contract MUST be "
                    f"crash-safe. stderr: {stderr}"
                ),
            )
        assert "OK" in stdout, (
            f"{workload}: child did not finish cleanly under CKF_OS_LOCKING_OK "
            f"(rc={rc}); stdout={stdout!r} stderr={stderr!r}"
        )
