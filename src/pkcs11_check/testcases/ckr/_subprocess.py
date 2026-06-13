"""Shared helpers for CKR subprocess probes."""

from __future__ import annotations

import textwrap

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

_SETUP_XFAIL_PREFIX = "SETUP_XFAIL:"
# A child probe that observed a genuine break (e.g. a wrong-key operation that
# actually produced output) emits BREAK: and the parent hard-fails it.
_BREAK_PREFIX = "BREAK:"
# A child probe that observed a clean, safe deviation (e.g. a module lenient at
# *Init but that still SAFELY refused at the terminal operation, leaving no
# usable operation behind) emits DEVIATION_XFAIL: and the parent records it as
# an xfail -- a noted deviation, not a hard failure.
_DEVIATION_XFAIL_PREFIX = "DEVIATION_XFAIL:"

_RV_TRACE_SETUP = """\
import atexit as _p11check_atexit
import json as _p11check_json
import os as _p11check_os


def _p11check_rv_trace_enabled():
    _value = _p11check_os.environ.get("PKCS11_CHECK_RV_TRACE", "")
    if _value.strip().lower() in ("1", "true", "yes", "on"):
        return True
    return bool(_p11check_os.environ.get("PKCS11_CHECK_RV_TRACE_COMPACT"))


def _p11check_rv_trace_maxlen():
    _value = _p11check_os.environ.get("PKCS11_CHECK_RV_TRACE_COMPACT")
    if not _value:
        return None
    try:
        _maxlen = int(_value)
    except ValueError:
        return None
    return _maxlen if _maxlen > 0 else None


if _p11check_rv_trace_enabled():
    raw.enable_rv_trace(maxlen=_p11check_rv_trace_maxlen())

    def _p11check_emit_rv_trace():
        try:
            print(
                "P11_RV_TRACE_JSON:"
                + _p11check_json.dumps(raw.rv_trace, separators=(",", ":")),
                flush=True,
            )
        except (OSError, TypeError, ValueError):
            pass

    _p11check_atexit.register(_p11check_emit_rv_trace)
"""

_SESSION_CLEANUP_SETUP = """\
import atexit as _p11check_atexit

_p11check_cleaned = False


def _p11check_cleanup_session():
    global _p11check_cleaned
    if _p11check_cleaned:
        return
    _p11check_cleaned = True
    try:
        {raw_var}.C_CloseSession({session_var})
    except Exception:
        pass
    try:
        {raw_var}.C_Finalize(None)
    except Exception:
        pass


_p11check_atexit.register(_p11check_cleanup_session)
"""

_CTYPES_RV_TRACE_SETUP = """\
import atexit as _p11check_atexit
import json as _p11check_json
import os as _p11check_os
from pkcs11_check.raw.rv import ckr_name as _p11check_ckr_name

_p11check_rv_trace = []


def _p11check_rv_trace_enabled():
    _value = _p11check_os.environ.get("PKCS11_CHECK_RV_TRACE", "")
    if _value.strip().lower() in ("1", "true", "yes", "on"):
        return True
    return bool(_p11check_os.environ.get("PKCS11_CHECK_RV_TRACE_COMPACT"))


def _p11check_record_rv(fn, rv):
    if not _p11check_rv_trace_enabled():
        return
    _rv = int(rv)
    _p11check_rv_trace.append(
        {
            "i": len(_p11check_rv_trace),
            "fn": fn,
            "rv": _rv,
            "rv_name": _p11check_ckr_name(_rv),
        }
    )


def _p11check_emit_rv_trace():
    if not _p11check_rv_trace_enabled():
        return
    if not _p11check_rv_trace:
        return
    try:
        print(
            "P11_RV_TRACE_JSON:"
            + _p11check_json.dumps(_p11check_rv_trace, separators=(",", ":")),
            flush=True,
        )
    except (OSError, TypeError, ValueError):
        pass


_p11check_atexit.register(_p11check_emit_rv_trace)
"""


def ckr_subprocess_rv_trace_setup(indent: str = "") -> str:
    """Return child-script code that emits RV traces for a global ``raw``."""
    return textwrap.indent(_RV_TRACE_SETUP, indent) if indent else _RV_TRACE_SETUP


def ckr_subprocess_cleanup_setup(
    *, raw_var: str = "raw", session_var: str = "sh", indent: str = ""
) -> str:
    """Return child-script code that finalizes a raw session at normal exit."""
    setup = _SESSION_CLEANUP_SETUP.format(raw_var=raw_var, session_var=session_var)
    return textwrap.indent(setup, indent) if indent else setup


def ckr_ctypes_subprocess_rv_trace_setup(indent: str = "") -> str:
    """Return child-script code that records RVs for direct ctypes calls."""
    return textwrap.indent(_CTYPES_RV_TRACE_SETUP, indent) if indent else _CTYPES_RV_TRACE_SETUP


def assert_ckr_subprocess_ok(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
) -> None:
    """Classify CKR child-process results without hiding provider crashes."""
    assert_subprocess_completed(rc, stdout, stderr, context=context)
    for line in stdout.splitlines():
        if line.startswith(_SETUP_XFAIL_PREFIX):
            # Child setup (keygen/Init) cleanly errored before the probe could run:
            # advertised capability not operational -> xfail.
            xfail_as(
                "not_operational",
                label=context,
                summary=line.removeprefix(_SETUP_XFAIL_PREFIX).strip(),
            )
    for line in stdout.splitlines():
        if line.startswith(_BREAK_PREFIX):
            # Child observed a genuine break: a forbidden/wrong-key operation that
            # actually produced output (claimed-protection-then-violated /
            # wrong-result) -> self-contradiction.
            fail_as(
                "self_contradiction",
                kind="crypto",
                label=context,
                summary=f"{context}: {line.removeprefix(_BREAK_PREFIX).strip()}",
            )
    for line in stdout.splitlines():
        if line.startswith(_DEVIATION_XFAIL_PREFIX):
            # Child observed a clean, safe deviation (lenient at *Init but still
            # SAFELY refused at the terminal op) -> honest deviation -> xfail.
            xfail_as(
                "honest_deviation",
                label=context,
                summary=line.removeprefix(_DEVIATION_XFAIL_PREFIX).strip(),
            )
    if "OK" not in stdout:
        # Child neither completed its probe nor emitted a classified marker:
        # treat the missing OK as an incomplete/crashed probe.
        fail_as(
            "crash",
            label=context,
            summary=(
                f"{context}: child subprocess did not emit an OK marker; "
                f"stdout: {stdout[-300:]}; stderr: {stderr[-300:]}"
            ),
        )
