"""CKR destructive token operation tests.

Tests that require modifying token state (InitToken, SetPIN, InitPIN).
Each test runs in subprocess with a TEMPORARY throwaway token to avoid
damaging the main test token.

Marked @destructive - skipped unless --p11-destructive is passed.

The destructive child logic lives in the ``ckr_destructive`` probe module
(``_probes/ckr_destructive.py``), launched via ``run_probe`` at ``Level.INIT``; the parent
mints a disposable token, points the module config at the child via the
``PKCS11_CHECK_TOKEN_CONF_ENV``-named env var, and classifies the child's ``CKR:0x...`` line
here (never inside the child) via ``_classify_destructive_ckr``.  These probes provision and
log into their OWN throwaway token with hardcoded test SO/user PINs; the configured
``p11_config`` PIN is never read, embedded, or forwarded (Invariant I3).
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator

import pytest

from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_PIN_INCORRECT,
    CKR_PIN_LEN_RANGE,
    CKR_PIN_TOO_WEAK,
    CKR_SESSION_EXISTS,
    CKR_TOKEN_NOT_INITIALIZED,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._shellcmd import shell_invocation
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = [pytest.mark.access, pytest.mark.subprocess, pytest.mark.destructive]


def _classify_destructive_ckr(out: str, expected_rvs: tuple[int, ...], *, label: str) -> None:
    """Parent-side 3-way classifier over a child script's ``CKR:0x...`` line.

    The destructive probes run in a subprocess and print ``CKR:0x{rv:08x}`` for
    the negative op under test. Classification happens here (not via an in-child
    ``assert``) so a non-spec clean reject becomes ``xfail`` instead of crashing
    the child and being mislabeled as a crash:

    - ``CKR_OK`` (the forbidden/invalid op was accepted) -> ``fail``,
    - ``rv in expected_rvs`` (spec) -> ``pass``,
    - any other clean reject code -> ``xfail``.
    """
    rv: int | None = None
    for line in out.splitlines():
        if line.startswith("CKR:0x"):
            rv = int(line.removeprefix("CKR:"), 16)
            break
    assert rv is not None, f"{label}: no CKR line in child output: {out!r}"
    classify_negative_rv(rv, expected_rvs, label=label)


def _mint_throwaway_token() -> tuple[str, str, str] | None:
    """Provision a disposable token using env-configured mint command.

    Reads PKCS11_CHECK_THROWAWAY_MODULE (path to module .so) and
    PKCS11_CHECK_TOKEN_MINT_CMD (shell template; {token_dir} and {conf_path}
    are substituted). Returns (module_path, conf_path, token_dir) or None if
    either variable is unset or the mint command fails; callers skip the test.
    """
    module_path = os.environ.get("PKCS11_CHECK_THROWAWAY_MODULE")
    mint_cmd_tmpl = os.environ.get("PKCS11_CHECK_TOKEN_MINT_CMD")
    if not module_path or not mint_cmd_tmpl:
        return None
    token_dir = tempfile.mkdtemp(prefix="pkcs11_check_ckr_")
    conf_path = os.path.join(token_dir, "module.conf")
    mint_cmd = mint_cmd_tmpl.format(token_dir=token_dir, conf_path=conf_path)
    proc = subprocess.run(shell_invocation(mint_cmd), capture_output=True, check=False)
    if proc.returncode != 0:
        shutil.rmtree(token_dir, ignore_errors=True)
        return None
    return module_path, conf_path, token_dir


@contextlib.contextmanager
def _conf_env(conf_path: str) -> Iterator[None]:
    """Point the module's config env var (PKCS11_CHECK_TOKEN_CONF_ENV) at ``conf_path``.

    ``run_probe`` inherits the parent's ``os.environ`` into the child, so the module's
    config file (e.g. ``SOFTHSM2_CONF``) is exposed to the child by temporarily setting the
    named env var here and restoring it afterward. This carries the throwaway-token config
    path only -- never a PIN (Invariant I3).
    """
    conf_env_var = os.environ.get("PKCS11_CHECK_TOKEN_CONF_ENV")
    if not conf_env_var:
        yield
        return
    had_prev = conf_env_var in os.environ
    prev = os.environ.get(conf_env_var)
    os.environ[conf_env_var] = conf_path
    try:
        yield
    finally:
        if had_prev and prev is not None:
            os.environ[conf_env_var] = prev
        else:
            os.environ.pop(conf_env_var, None)


def _run_destructive(probe: str) -> tuple[int, str, str]:
    """Run a destructive probe against a temporary throwaway token."""
    mint_result = _mint_throwaway_token()
    if mint_result is None:
        pytest.skip(
            "throwaway-token capability not configured "
            "(set PKCS11_CHECK_THROWAWAY_MODULE and PKCS11_CHECK_TOKEN_MINT_CMD)"
        )
    module, conf_path, token_dir = mint_result
    try:
        with _conf_env(conf_path):
            result = run_probe(
                "ckr_destructive",
                {"module_path": module, "probe": probe},
                timeout=15,
                coverage="session",
            )
    finally:
        shutil.rmtree(token_dir, ignore_errors=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestInitTokenErrors:
    """C_InitToken error conditions."""

    def test_init_token_session_exists(self) -> None:
        """C_InitToken with open session -> CKR_SESSION_EXISTS."""
        rc, out, err = _run_destructive("init_token_session_exists")
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        _classify_destructive_ckr(
            out, (CKR_SESSION_EXISTS,), label="C_InitToken with an open session"
        )

    def test_init_token_wrong_so_pin(self) -> None:
        """C_InitToken with wrong SO PIN -> CKR_PIN_INCORRECT."""
        rc, out, err = _run_destructive("init_token_wrong_so_pin")
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        _classify_destructive_ckr(
            out, (CKR_PIN_INCORRECT,), label="C_InitToken with a wrong SO PIN"
        )


class TestSetPINErrors:
    """C_SetPIN error conditions."""

    def test_set_pin_wrong_old(self) -> None:
        """C_SetPIN with wrong old PIN -> CKR_PIN_INCORRECT."""
        rc, out, err = _run_destructive("set_pin_wrong_old")
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        _classify_destructive_ckr(out, (CKR_PIN_INCORRECT,), label="C_SetPIN with a wrong old PIN")


class TestInitPINErrors:
    """C_InitPIN error conditions."""

    def test_init_pin_not_logged_in(self) -> None:
        """C_InitPIN without SO login -> CKR_USER_NOT_LOGGED_IN."""
        rc, out, err = _run_destructive("init_pin_not_logged_in")
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        _classify_destructive_ckr(
            out, (CKR_USER_NOT_LOGGED_IN,), label="C_InitPIN without SO login"
        )

    def test_init_pin_short_pin(self) -> None:
        """C_InitPIN with 1-byte PIN -> CKR_PIN_TOO_WEAK or related PIN error."""
        rc, out, err = _run_destructive("init_pin_short_pin")
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        _classify_destructive_ckr(
            out,
            (CKR_PIN_TOO_WEAK, CKR_PIN_LEN_RANGE, CKR_PIN_INCORRECT, CKR_ARGUMENTS_BAD),
            label="C_InitPIN with a 1-byte PIN (weak/too-short)",
        )

    def test_init_pin_token_not_initialized(self) -> None:
        """C_InitPIN on uninitialized token -> CKR_TOKEN_NOT_INITIALIZED."""
        module = os.environ.get("PKCS11_CHECK_THROWAWAY_MODULE")
        if not module:
            pytest.skip("throwaway module not configured (PKCS11_CHECK_THROWAWAY_MODULE unset)")
        token_dir = tempfile.mkdtemp(prefix="pkcs11_check_ckr_uninit_")
        # This test writes a file-based uninitialized-token config and therefore
        # assumes the configured throwaway module uses file-based token storage.
        conf_path = os.path.join(token_dir, "module.conf")
        with open(conf_path, "w") as f:
            f.write(f"directories.tokendir = {token_dir}/tokens\n")
            f.write("objectstore.backend = file\n")
        os.makedirs(os.path.join(token_dir, "tokens"), exist_ok=True)

        try:
            with _conf_env(conf_path):
                result = run_probe(
                    "ckr_destructive",
                    {"module_path": module, "probe": "init_pin_token_not_initialized"},
                    timeout=15,
                    coverage="session",
                )
        finally:
            shutil.rmtree(token_dir, ignore_errors=True)

        if result.returncode != 0:
            raise AssertionError(f"Crash: {result.stderr[-300:]}")
        if "NO_SLOTS" in result.stdout:
            pytest.skip("No slots available on uninitialized token")
        assert "OK" in result.stdout
        _classify_destructive_ckr(
            result.stdout,
            (CKR_TOKEN_NOT_INITIALIZED, CKR_USER_NOT_LOGGED_IN),
            label="C_InitPIN on an uninitialized token",
        )
