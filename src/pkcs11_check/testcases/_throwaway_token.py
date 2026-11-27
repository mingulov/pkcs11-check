"""Sacrificial-token capability, minting, reset, and child sessions (QC11).

Destructive administration (InitToken/InitPIN/SetPIN, lockout-counter burning,
PIN mutation) runs ONLY on sacrificial tokens behind the explicit three-variable
capability below, plus the ``destructive`` marker on the test. A missing
capability skips with an explicit reason; there is never a live-token fallback.

Invariant I3: nothing here reads, embeds, or forwards the configured/live PIN.
Children receive only PIN-free params; hardcoded test PINs live in the child
probe module (``_probes/token_admin.py``).
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import AbstractContextManager
from typing import Any, NamedTuple

import pytest

from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._shellcmd import shell_invocation

THROWAWAY_MODULE_ENV = "PKCS11_CHECK_THROWAWAY_MODULE"
TOKEN_MINT_CMD_ENV = "PKCS11_CHECK_TOKEN_MINT_CMD"
TOKEN_CONF_ENV_NAME = "PKCS11_CHECK_TOKEN_CONF_ENV"

ChildOutput = tuple[int, str, str]


class ThrowawayCapability(NamedTuple):
    module_path: str
    mint_cmd_template: str
    conf_env_var: str


class MintedToken(NamedTuple):
    module_path: str
    conf_path: str
    token_dir: str
    prefix: str


class ThrowawayMintError(Exception):
    """The mint command failed or produced no token config artifact."""


class ThrowawayResetError(Exception):
    """Sacrificial-token reset was refused or failed; always loud."""


def throwaway_capability() -> ThrowawayCapability | None:
    """Return the sacrificial-token capability, or None when any part is missing."""
    module_path = os.environ.get(THROWAWAY_MODULE_ENV)
    mint_cmd_template = os.environ.get(TOKEN_MINT_CMD_ENV)
    conf_env_var = os.environ.get(TOKEN_CONF_ENV_NAME)
    if not module_path or not mint_cmd_template or not conf_env_var:
        return None
    return ThrowawayCapability(
        module_path=module_path,
        mint_cmd_template=mint_cmd_template,
        conf_env_var=conf_env_var,
    )


def require_throwaway_capability() -> ThrowawayCapability:
    """Return the capability, skipping with an explicit reason when missing."""
    cap = throwaway_capability()
    if cap is None:
        pytest.skip(
            "sacrificial-token capability not configured "
            "(set PKCS11_CHECK_THROWAWAY_MODULE, PKCS11_CHECK_TOKEN_MINT_CMD "
            "and PKCS11_CHECK_TOKEN_CONF_ENV); refusing destructive admin"
        )
    return cap


def mint_throwaway_token(cap: ThrowawayCapability, *, prefix: str) -> MintedToken:
    """Provision a disposable token; raise ThrowawayMintError on any failure."""
    token_dir = tempfile.mkdtemp(prefix=prefix)
    conf_path = os.path.join(token_dir, "module.conf")
    mint_cmd = cap.mint_cmd_template.format(token_dir=token_dir, conf_path=conf_path)
    proc = subprocess.run(shell_invocation(mint_cmd), capture_output=True, check=False)
    if proc.returncode != 0:
        shutil.rmtree(token_dir, ignore_errors=True)
        tail = proc.stderr.decode("utf-8", errors="replace")[-300:]
        raise ThrowawayMintError(f"mint command failed with exit {proc.returncode}: {tail}")
    if not os.path.isfile(conf_path):
        shutil.rmtree(token_dir, ignore_errors=True)
        raise ThrowawayMintError(
            f"mint command succeeded but produced no conf artifact at {conf_path}"
        )
    return MintedToken(
        module_path=cap.module_path,
        conf_path=conf_path,
        token_dir=token_dir,
        prefix=prefix,
    )


def reset_throwaway_token(minted: MintedToken) -> None:
    """Destroy a minted token's directory; refuse anything outside containment."""
    real_dir = os.path.realpath(minted.token_dir)
    real_tmp = os.path.realpath(tempfile.gettempdir())
    if real_dir == real_tmp or not real_dir.startswith(real_tmp + os.sep):
        raise ThrowawayResetError(
            f"containment: refusing to reset outside the temp dir: {minted.token_dir!r}"
        )
    if os.path.basename(real_dir)[: len(minted.prefix)] != minted.prefix:
        raise ThrowawayResetError(
            f"prefix: refusing to reset {minted.token_dir!r} (expected prefix {minted.prefix!r})"
        )
    real_conf = os.path.realpath(minted.conf_path)
    if real_conf != real_dir and not real_conf.startswith(real_dir + os.sep):
        raise ThrowawayResetError(
            f"containment: conf {minted.conf_path!r} escapes {minted.token_dir!r}"
        )
    if not os.path.isdir(real_dir):
        raise ThrowawayResetError(f"token dir already gone or missing: {minted.token_dir!r}")
    try:
        shutil.rmtree(real_dir)
    except OSError as exc:
        raise ThrowawayResetError(f"reset failed for {minted.token_dir!r}: {exc}") from exc
    if os.path.exists(real_dir):
        raise ThrowawayResetError(f"reset failed for {minted.token_dir!r}: still exists")


@contextlib.contextmanager
def throwaway_token(cap: ThrowawayCapability, *, prefix: str) -> Iterator[MintedToken]:
    """Mint a sacrificial token, yield it, and reset it loudly on exit."""
    try:
        minted = mint_throwaway_token(cap, prefix=prefix)
    except ThrowawayMintError as exc:
        pytest.skip(f"sacrificial-token mint failed ({exc}); destructive legs untestable")
    try:
        yield minted
    finally:
        reset_throwaway_token(minted)


@contextlib.contextmanager
def throwaway_conf_env(cap: ThrowawayCapability, conf_path: str) -> Iterator[None]:
    """Point the module's config env var at ``conf_path`` (config path only, never a PIN)."""
    var = cap.conf_env_var
    had_prev = var in os.environ
    prev = os.environ.get(var)
    os.environ[var] = conf_path
    try:
        yield
    finally:
        if had_prev and prev is not None:
            os.environ[var] = prev
        else:
            os.environ.pop(var, None)


SessionFactory = Callable[..., AbstractContextManager["MintedToken"]]
LaunchProbe = Callable[..., ChildOutput]


@contextlib.contextmanager
def admin_session(cap: ThrowawayCapability, *, prefix: str) -> Iterator[MintedToken]:
    """Yield one freshly minted sacrificial token with its config env var pointed at it."""
    with throwaway_token(cap, prefix=prefix) as minted:
        with throwaway_conf_env(cap, minted.conf_path):
            yield minted


def launch_admin_probe(
    minted: MintedToken,
    probe: str,
    params: Mapping[str, Any],
    *,
    p11_config: Any,
    timeout: int = 15,
) -> ChildOutput:
    """Run one child probe against a minted token (fake-first seam for orchestration)."""
    merged = {"module_path": minted.module_path, "probe": probe, **params}
    result = run_probe(
        "token_admin",
        merged,
        timeout=timeout,
        coverage="session",
        interface=getattr(p11_config, "interface", "auto"),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()
