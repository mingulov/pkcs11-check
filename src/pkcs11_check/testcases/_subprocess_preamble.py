"""Shared subprocess session preamble for PKCS#11 test scripts.

Generates Python code strings that set up a PKCS#11 session in a subprocess.
Used by test files that need crash-safe isolation via subprocess.run().

PIN handling: the user PIN is NEVER interpolated into the generated script
source (that would expose it in the child process argv via ``ps``/``/proc`` and
in any traceback). Instead the PIN is passed to the child through the
``_P11CHECK_PIN`` environment variable and read inside the child via
``os.environ``. Callers must run the script through :func:`run_with_coverage`
with the ``pin`` argument so the env var is injected.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from typing import Any

from pkcs11_check.testcases._subprocess_trace import record_subprocess_rv_trace

# Environment variable carrying the user PIN into the child subprocess. The PIN
# is passed here (not interpolated into the script) so it never appears in the
# child argv or in any generated source string. Mirrors the redaction handling
# already applied to PIN-bearing env keys in ``core/file_runner.py``.
_P11CHECK_PIN_ENV = "_P11CHECK_PIN"

# A probe subprocess that hangs (the module did not return on the probe input)
# is surfaced via this marker on stderr + a sentinel returncode, so the parent's
# assert_subprocess_completed classifies the hang as a crash-class finding rather
# than letting subprocess.TimeoutExpired escape as a record-less runtime-gate leak.
SUBPROCESS_TIMEOUT_MARKER = "_P11CHECK_SUBPROCESS_TIMEOUT"
SUBPROCESS_TIMEOUT_RC = 124  # conventional timeout exit code (GNU timeout)


def _as_text(stream: str | bytes | None) -> str:
    """Decode a possibly-bytes subprocess stream to text (TimeoutExpired captures)."""
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode(errors="replace")
    return stream


_subprocess_call_counts: Counter[str] = Counter()
_subprocess_mechanism_counts: Counter[str] = Counter()


def pin_from_config(p11_config: Any) -> str | None:
    """Return the configured user PIN as a plain ``str`` (or None).

    Centralises the ``SecretStr`` unwrap so call sites can pass the PIN to
    :func:`run_with_coverage` without sprinkling ``get_secret_value()`` (and
    the accompanying leak surface) across every test. The returned value is
    only ever forwarded into the child env by the runner, never embedded in a
    script string.
    """
    pin = getattr(p11_config, "pin", None)
    if pin is None:
        return None
    value: str = pin.get_secret_value()
    return value


def run_with_coverage(
    script: str, timeout: int = 15, *, pin: str | None = None
) -> tuple[int, str, str]:
    """Run subprocess script with coverage capture.

    When ``pin`` is provided it is injected into the child environment under
    ``_P11CHECK_PIN`` rather than embedded in the script text, so the PIN never
    appears in the child argv or in the generated source. The preamble emitted
    by :func:`subprocess_session_preamble` reads it from that env var.
    """
    cov_fd, cov_path = tempfile.mkstemp(suffix=".json", prefix="p11cov_")
    os.close(cov_fd)
    env = {**os.environ, "_P11CHECK_SUBPROCESS_COVERAGE": cov_path}
    if pin is not None:
        env[_P11CHECK_PIN_ENV] = pin

    try:
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as exc:
        # The module hung on the probe input: the child is killed, but
        # TimeoutExpired must NOT escape as a record-less runtime-gate leak.
        # Surface a timeout marker on stderr so assert_subprocess_completed
        # classifies the hang as a (crash-class) finding -- a module must reject
        # impossible inputs, not hang on them.
        out = _as_text(exc.stdout)
        err = (_as_text(exc.stderr) + f"\n{SUBPROCESS_TIMEOUT_MARKER}:{timeout}s").strip()
        rc = SUBPROCESS_TIMEOUT_RC

    try:
        with open(cov_path) as f:
            data: Any = json.load(f)
        _subprocess_call_counts.update(data.get("call_log", {}))
        for k, v in data.get("mechanism_counts", {}).items():
            _subprocess_mechanism_counts[k] += v
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass  # Subprocess may have crashed (segfault) -- coverage file not written
    finally:
        try:
            os.unlink(cov_path)
        except OSError:
            pass

    record_subprocess_rv_trace(out, err)
    return rc, out.strip(), err.strip()


def get_preamble_subprocess_coverage() -> tuple[Counter[str], Counter[str]]:
    """Return accumulated subprocess coverage and clear it."""
    func = Counter(_subprocess_call_counts)
    mech = Counter(_subprocess_mechanism_counts)
    _subprocess_call_counts.clear()
    _subprocess_mechanism_counts.clear()
    return func, mech


def subprocess_session_preamble(
    module_path: str,
    slot_id: int | None = None,
    pin: str | None = None,
    *,
    extra_imports: str = "",
    slot_label: str | None = None,
) -> str:
    """Return Python code that sets up a PKCS#11 session.

    After executing the returned code, these variables are available:
    - ``raw``: RawPKCS11 instance (initialized)
    - ``sh``: int session handle (opened, logged in if pin provided)
    - ``slot_id``: int slot used

    Call ``cleanup()`` to close the session and finalize the module.

    The PIN is NOT interpolated into the returned source. When ``pin`` is not
    ``None`` the script logs in by reading the PIN from the ``_P11CHECK_PIN``
    environment variable; the caller must supply that PIN via
    :func:`run_with_coverage`'s ``pin`` argument. String inputs
    (``module_path``, ``slot_label``) are encoded with ``json.dumps`` so labels
    containing quotes/backslashes/newlines cannot break or inject into the
    generated source.

    Args:
        module_path: Path to the PKCS#11 .so module.
        slot_id: Explicit slot ID. If None, uses first available slot.
        pin: User PIN for login. If None, skips login. The value itself is NOT
            embedded in the script -- only its presence selects the login path.
        extra_imports: Additional import lines to include in the script.
        slot_label: If set, filter slots by token label substring.
    """
    if slot_id is not None:
        slot_discovery = f"slot_id = {slot_id}"
    elif slot_label is not None:
        # json.dumps produces a safe, escaped Python string literal -- a label
        # containing quotes/backslashes/newlines cannot break or inject code.
        slot_discovery = (
            f"slots = get_slot_ids(raw, label={json.dumps(slot_label)})\n"
            f"if not slots:\n"
            f"    slots = get_slot_ids(raw)\n"
            f"slot_id = slots[0]"
        )
    else:
        slot_discovery = "slot_id = get_slot_ids(raw)[0]"

    login_line = ""
    if pin is not None:
        # Read the PIN from the environment at runtime; never embed it in source.
        login_line = (
            f"import os as _os\n"
            f"_pin = _os.environ.get({json.dumps(_P11CHECK_PIN_ENV)})\n"
            f"if _pin is not None:\n"
            f"    login_user(raw, sh, CKU_USER, _pin.encode())\n"
        )

    extra_block = ""
    if extra_imports:
        extra_block = f"{extra_imports}\n"

    return (
        f"import atexit as _atexit\n"
        f"import json as _json\n"
        f"import os as _os\n"
        f"from pkcs11_check.raw.api import RawPKCS11\n"
        f"from pkcs11_check.raw.bootstrap import (\n"
        f"    close_session_quietly, get_slot_ids, login_user, open_session,\n"
        f")\n"
        f"from pkcs11_check.raw.types_std import (\n"
        f"    CKF_RW_SESSION, CKF_SERIAL_SESSION,\n"
        f"    CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_OK, CKU_USER,\n"
        f")\n"
        f"{extra_block}"
        f"\n"
        f"def _p11check_rv_trace_enabled():\n"
        f"    _value = _os.environ.get('PKCS11_CHECK_RV_TRACE', '')\n"
        f"    if _value.strip().lower() in ('1', 'true', 'yes', 'on'):\n"
        f"        return True\n"
        f"    return bool(_os.environ.get('PKCS11_CHECK_RV_TRACE_COMPACT'))\n"
        f"\n"
        f"\n"
        f"def _p11check_rv_trace_maxlen():\n"
        f"    _value = _os.environ.get('PKCS11_CHECK_RV_TRACE_COMPACT')\n"
        f"    if not _value:\n"
        f"        return None\n"
        f"    try:\n"
        f"        _maxlen = int(_value)\n"
        f"    except ValueError:\n"
        f"        return None\n"
        f"    return _maxlen if _maxlen > 0 else None\n"
        f"\n"
        f"\n"
        f"raw = RawPKCS11.from_lib({json.dumps(module_path)})\n"
        f"if _p11check_rv_trace_enabled():\n"
        f"    raw.enable_rv_trace(maxlen=_p11check_rv_trace_maxlen())\n"
        f"\n"
        f"    def _p11check_emit_rv_trace():\n"
        f"        try:\n"
        f"            print(\n"
        f"                'P11_RV_TRACE_JSON:'\n"
        f"                + _json.dumps(raw.rv_trace, separators=(',', ':')),\n"
        f"                flush=True,\n"
        f"            )\n"
        f"        except (OSError, TypeError, ValueError):\n"
        f"            pass\n"
        f"\n"
        f"    _atexit.register(_p11check_emit_rv_trace)\n"
        f"\n"
        f"rv = raw.C_Initialize(None)\n"
        f"assert rv in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED), "  # audit-ok: init idempotency
        f'f"C_Initialize: 0x{{rv:08x}}"\n'
        f"\n"
        f"{slot_discovery}\n"
        f"sh = open_session(raw, slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION)\n"
        f"{login_line}"
        f"\n"
        f"_p11check_cleaned = False\n"
        f"\n"
        f"def cleanup():\n"
        f"    global _p11check_cleaned\n"
        f"    if _p11check_cleaned:\n"
        f"        return\n"
        f"    _p11check_cleaned = True\n"
        f"    _cov_path = _os.environ.get('_P11CHECK_SUBPROCESS_COVERAGE')\n"
        f"    if _cov_path:\n"
        f"        try:\n"
        f"            _json.dump({{\n"
        f"                'call_log': raw.call_log,\n"
        f"                'mechanism_counts': "
        f"{{str(k): v for k, v in raw.mechanism_counts.items()}},\n"
        f"            }}, open(_cov_path, 'w'))\n"
        f"        except (OSError, TypeError, ValueError):\n"
        f"            pass\n"
        f"    close_session_quietly(raw, sh)\n"
        f"    raw.C_Finalize(None)\n"
        f"\n"
        f"_atexit.register(cleanup)\n"
    )
