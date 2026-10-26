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

QC11c (below) adds sacrificial reset semantics: after provisioning, a fresh
InitToken must destroy exactly the resettable data (user PIN, canary objects)
while the token stays functional.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from typing import Any

import pytest

from pkcs11_check.classification import Classification, record_as
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKF_TOKEN_INITIALIZED,
    CKF_USER_PIN_INITIALIZED,
    CKR_ARGUMENTS_BAD,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_PIN_LEN_RANGE,
    CKR_PIN_TOO_WEAK,
    CKR_SESSION_EXISTS,
    CKR_TOKEN_NOT_INITIALIZED,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_PIN_NOT_INITIALIZED,
)
from pkcs11_check.testcases import _throwaway_token as throwaway
from pkcs11_check.testcases._probes import token_admin
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._shellcmd import shell_invocation
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.test_so_pin import (
    _assess_provision_journey,
    _raise_qc11c_fail_grades,
    _raise_strongest_qc11c,
)

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


def _run_destructive(probe: str, *, interface: str) -> tuple[int, str, str]:
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
                interface=interface,
            )
    finally:
        shutil.rmtree(token_dir, ignore_errors=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestInitTokenErrors:
    """C_InitToken error conditions."""

    def test_init_token_session_exists(self, p11_config: Any) -> None:
        """C_InitToken with open session -> CKR_SESSION_EXISTS."""
        rc, out, err = _run_destructive(
            "init_token_session_exists", interface=getattr(p11_config, "interface", "auto")
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        _classify_destructive_ckr(
            out, (CKR_SESSION_EXISTS,), label="C_InitToken with an open session"
        )

    def test_init_token_wrong_so_pin(self, p11_config: Any) -> None:
        """C_InitToken with wrong SO PIN -> CKR_PIN_INCORRECT."""
        rc, out, err = _run_destructive(
            "init_token_wrong_so_pin", interface=getattr(p11_config, "interface", "auto")
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        _classify_destructive_ckr(
            out, (CKR_PIN_INCORRECT,), label="C_InitToken with a wrong SO PIN"
        )


class TestSetPINErrors:
    """C_SetPIN error conditions."""

    def test_set_pin_wrong_old(self, p11_config: Any) -> None:
        """C_SetPIN with wrong old PIN -> CKR_PIN_INCORRECT."""
        rc, out, err = _run_destructive(
            "set_pin_wrong_old", interface=getattr(p11_config, "interface", "auto")
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        _classify_destructive_ckr(out, (CKR_PIN_INCORRECT,), label="C_SetPIN with a wrong old PIN")


class TestInitPINErrors:
    """C_InitPIN error conditions."""

    def test_init_pin_not_logged_in(self, p11_config: Any) -> None:
        """C_InitPIN without SO login -> CKR_USER_NOT_LOGGED_IN."""
        rc, out, err = _run_destructive(
            "init_pin_not_logged_in", interface=getattr(p11_config, "interface", "auto")
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        _classify_destructive_ckr(
            out, (CKR_USER_NOT_LOGGED_IN,), label="C_InitPIN without SO login"
        )

    def test_init_pin_short_pin(self, p11_config: Any) -> None:
        """C_InitPIN with 1-byte PIN -> CKR_PIN_TOO_WEAK or related PIN error."""
        rc, out, err = _run_destructive(
            "init_pin_short_pin", interface=getattr(p11_config, "interface", "auto")
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        _classify_destructive_ckr(
            out,
            (CKR_PIN_TOO_WEAK, CKR_PIN_LEN_RANGE, CKR_PIN_INCORRECT, CKR_ARGUMENTS_BAD),
            label="C_InitPIN with a 1-byte PIN (weak/too-short)",
        )

    def test_init_pin_token_not_initialized(self, p11_config: Any) -> None:
        """C_InitPIN on uninitialized token -> CKR_TOKEN_NOT_INITIALIZED."""
        module = os.environ.get("PKCS11_CHECK_THROWAWAY_MODULE")
        if not module:
            pytest.skip("throwaway module not configured (PKCS11_CHECK_THROWAWAY_MODULE unset)")
        token_dir = tempfile.mkdtemp(prefix="pkcs11_check_ckr_uninit_")
        # This test writes a file-based uninitialized-token config and therefore
        # assumes the configured throwaway module uses file-based token storage.
        conf_path = os.path.join(token_dir, "module.conf")
        with open(conf_path, "w", encoding="utf-8") as f:
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
                    interface=getattr(p11_config, "interface", "auto"),
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


# --- QC11c: sacrificial reset semantics (#52.8) ---------------------------------

_QC11C_CANONICAL_OLD_USER_AFTER_RESET = (
    int(CKR_USER_PIN_NOT_INITIALIZED),
    int(CKR_PIN_INCORRECT),
)


def _assess_sacrificial_reset(trace: token_admin.AdminTrace) -> list[Classification]:
    """Assess one reset trace: reset destroys exactly the resettable data."""
    by_name: dict[str, int] = {}
    for step in trace.steps:
        by_name.setdefault(step.name, step.rv)
    by_flag = dict(trace.flags)
    records: list[Classification] = []
    label = "QC11c sacrificial reset"
    detail: dict[str, Any] = {
        "steps": {step.name: ckr_name(step.rv) for step in trace.steps},
        "inv": list(trace.inv_objects),
    }
    # F1: token-info reads that went undefined FAIL, even when the functional
    # legs passed (same doctrine as R19-04 phase-two snapshots).
    records.extend(token_admin.undefined_snapshot_records(trace, label=label, detail=detail))
    reset_rv = by_name.get("reset_init_token")
    assert reset_rv is not None, f"{label}: missing reset_init_token step"
    if reset_rv != int(CKR_OK):
        if not (is_standard_ckr(reset_rv) or is_vendor_defined_ckr(reset_rv)):
            records.append(
                record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"{label}: reset_init_token",
                    operation="C_InitToken",
                    mechanism=None,
                    inherit_mechanism=False,
                    actual=reset_rv,
                    summary=f"{label}: reset returned undefined CK_RV",
                    detail=detail,
                )
            )
        else:
            records.append(
                record_as(
                    "not_operational",
                    label=f"{label}: reset_init_token",
                    operation="C_InitToken",
                    mechanism=None,
                    inherit_mechanism=False,
                    actual=reset_rv,
                    summary=f"{label}: unexercised reset: refused with {ckr_name(reset_rv)}",
                    detail=detail,
                )
            )
        return records
    so_rv = by_name.get("so_login")
    assert so_rv is not None, f"{label}: missing so_login step"
    so_ok = so_rv == int(CKR_OK)
    if not so_ok:
        if not (is_standard_ckr(so_rv) or is_vendor_defined_ckr(so_rv)):
            records.append(
                record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"{label}: so_login",
                    operation="C_Login",
                    mechanism=None,
                    inherit_mechanism=False,
                    actual=so_rv,
                    summary=f"{label}: SO login returned undefined CK_RV",
                    detail=detail,
                )
            )
        else:
            records.append(
                record_as(
                    "not_operational",
                    label=f"{label}: so_login",
                    operation="C_Login",
                    mechanism=None,
                    inherit_mechanism=False,
                    actual=so_rv,
                    summary=f"{label}: SO login refused after reset with {ckr_name(so_rv)}",
                    detail=detail,
                )
            )
    old = by_name.get("old_user_after_reset")
    assert old is not None, f"{label}: missing old_user_after_reset step"
    if old == int(CKR_OK):
        records.append(
            record_as(
                "accepted_invalid",
                kind="lifecycle",
                label=f"{label}: old_user_after_reset",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                expected=_QC11C_CANONICAL_OLD_USER_AFTER_RESET,
                actual=old,
                summary=f"{label}: user PIN survived reset",
                detail=detail,
            )
        )
    elif not (is_standard_ckr(old) or is_vendor_defined_ckr(old)):
        records.append(
            record_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: old_user_after_reset",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                actual=old,
                summary=f"{label}: old-user probe returned undefined CK_RV",
                detail=detail,
            )
        )
    elif old not in _QC11C_CANONICAL_OLD_USER_AFTER_RESET:
        records.append(
            record_as(
                "nonspec_reject",
                label=f"{label}: old_user_after_reset",
                operation="C_Login",
                mechanism=None,
                inherit_mechanism=False,
                expected=_QC11C_CANONICAL_OLD_USER_AFTER_RESET,
                actual=old,
                summary=f"{label}: old user PIN rejected with {ckr_name(old)}",
                detail=detail,
            )
        )
    if so_ok:
        if not trace.inv_objects:
            records.append(
                record_as(
                    "not_operational",
                    label=f"{label}: inventory",
                    operation="C_FindObjects",
                    mechanism=None,
                    inherit_mechanism=False,
                    summary=f"{label}: canary inventory unreadable after reset",
                    detail=detail,
                )
            )
        elif trace.inv_objects[-1] > 0:
            records.append(
                record_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label=f"{label}: inventory",
                    operation="C_FindObjects",
                    mechanism=None,
                    inherit_mechanism=False,
                    summary=f"{label}: canary survived reset",
                    detail=detail,
                )
            )
    after_reset = by_flag.get("after_reset_init_token")
    if after_reset is not None and not (after_reset & int(CKF_TOKEN_INITIALIZED)):
        records.append(
            record_as(
                "honest_deviation",
                kind="metadata",
                label=f"{label}: after_reset_init_token",
                operation="C_GetTokenInfo",
                mechanism=None,
                inherit_mechanism=False,
                summary=f"{label}: TOKEN_INITIALIZED unset after successful reset",
                detail=detail,
            )
        )
    if after_reset is not None and (after_reset & int(CKF_USER_PIN_INITIALIZED)):
        records.append(
            record_as(
                "honest_deviation",
                kind="metadata",
                label=f"{label}: after_reset_init_token",
                operation="C_GetTokenInfo",
                mechanism=None,
                inherit_mechanism=False,
                summary=f"{label}: USER_PIN_INITIALIZED still set after reset",
                detail=detail,
            )
        )
    return records


def _run_qc11c_reset_node(
    cap: throwaway.ThrowawayCapability,
    p11_config: Any,
    *,
    _session_factory: throwaway.SessionFactory = throwaway.admin_session,
    _launch: throwaway.LaunchProbe = throwaway.launch_admin_probe,
) -> None:
    with _session_factory(cap, prefix="pkcs11_check_qc11c_") as minted:
        rc1, out1, err1 = _launch(minted, "qc11c_journey", {}, p11_config=p11_config)
        provision = token_admin.check_child_output(rc1, out1, err1, label="QC11c reset/provision")
        records_p, reached = _assess_provision_journey(provision)
        if not reached:
            assert records_p, "QC11c reset: unreached provision without any record"
            _raise_strongest_qc11c(records_p)
            return
        rc2, out2, err2 = _launch(minted, "qc11c_reset", {}, p11_config=p11_config)
        # R19-02 collect-then-judge: when the reset leg would skip, provision
        # FAIL grades preempt the skip.
        reset_raw = token_admin.parse_child_output(rc2, out2, err2, label="QC11c reset")
        if token_admin.trace_skip_reason(reset_raw, no_slots="fail") is not None:
            _raise_qc11c_fail_grades(records_p)
        reset = token_admin.gate_child_trace(reset_raw, label="QC11c reset", no_slots="fail")
        records_r = _assess_sacrificial_reset(reset)
        _raise_strongest_qc11c(records_p + records_r)


class TestSacrificialResetSemantics:
    """Reset destroys exactly the resettable data (QC11c)."""

    def test_reset_destroys_only_resettable_data(self, p11_config: Any) -> None:
        cap = throwaway.require_throwaway_capability()
        _run_qc11c_reset_node(cap, p11_config)
