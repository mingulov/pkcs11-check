"""Parent-side launcher: run a _probes module in a fresh subprocess.

Replaces the ``run_with_coverage`` / ``run_raw_script`` launch paths for probe
modules.  PIN travels only via ``_P11CHECK_PIN`` env (I3).  Coverage is routed
to the correct accumulator by the ``coverage`` argument (I6).  The rv-trace is
recorded by ``record_subprocess_rv_trace`` (I7).  Timeouts are converted to rc
124 + ``SUBPROCESS_TIMEOUT_MARKER`` on stderr (I8).  The child is launched via
``python -m pkcs11_check.testcases._probes.<probe>`` (I11, no shell).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from pkcs11_check.core.process_observation import (
    build_process_observation,
    record_process_observation,
)
from pkcs11_check.core.subprocess_trace import record_subprocess_rv_trace
from pkcs11_check.testcases._probes.params import ProbeParams
from pkcs11_check.testcases._raw_subprocess import ingest_raw_subprocess_coverage
from pkcs11_check.testcases._subprocess_preamble import (
    SUBPROCESS_TIMEOUT_MARKER,
    SUBPROCESS_TIMEOUT_RC,
    ingest_subprocess_coverage,
)


def _as_text(stream: str | bytes | None) -> str:
    """Decode a possibly-bytes subprocess stream to text.

    ``TimeoutExpired.stdout`` / ``.stderr`` can be ``bytes`` even when
    ``subprocess.run`` is called with ``text=True``; the exception is raised
    mid-``communicate()`` before decoding completes.  This mirrors the same
    helper in ``_subprocess_preamble.py``.
    """
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode(errors="replace")
    return stream


@dataclass(frozen=True)
class ProbeResult:
    """Return value of :func:`run_probe`."""

    returncode: int
    stdout: str
    stderr: str
    observation: dict[str, object] | None = None


def run_probe(
    probe: str,
    params: Mapping[str, Any],
    *,
    pin: str | None = None,
    timeout: int = 15,
    coverage: Literal["session", "raw"] = "session",
) -> ProbeResult:
    """Launch a _probes module in a subprocess and return its result.

    Args:
        probe: Module name under ``pkcs11_check.testcases._probes`` (e.g. ``"session"``).
        params: Probe parameters dict.  Must include ``"module_path"``.  Must NOT contain
            any PIN-bearing key (``ProbeParams.dump`` raises ``PinInParamsError`` if one
            is found — Invariant I3).
        pin: User PIN.  Forwarded to the child via ``_P11CHECK_PIN`` env only (I3).
        timeout: Subprocess timeout in seconds.  Exceeded -> rc 124 + timeout marker (I8).
        coverage: ``"session"`` routes ingested coverage to the preamble accumulators
            (``ingest_subprocess_coverage``); ``"raw"`` routes to the raw accumulators
            (``ingest_raw_subprocess_coverage``) — Invariant I6.

    Returns:
        :class:`ProbeResult` with ``returncode``, ``stdout``, ``stderr``.

    Raises:
        PinInParamsError: if ``params`` contains a PIN-bearing key.
    """
    payload = ProbeParams.dump(params)  # raises PinInParamsError on PIN keys (I3)

    env = dict(os.environ)
    if pin is not None:
        env["_P11CHECK_PIN"] = pin
    else:
        env.pop("_P11CHECK_PIN", None)

    params_fd, params_path = tempfile.mkstemp(suffix=".json", prefix="p11probe-")
    cov_fd, cov_path = tempfile.mkstemp(suffix=".json", prefix="p11cov-")
    os.close(cov_fd)
    env["_P11CHECK_SUBPROCESS_COVERAGE"] = cov_path

    rc: int | None = None
    out: str = ""
    err: str = ""
    timed_out = False

    try:
        with os.fdopen(params_fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)

        cmd = [sys.executable, "-m", f"pkcs11_check.testcases._probes.{probe}", params_path]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=env,
                timeout=timeout,
            )
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            # TimeoutExpired.stdout/.stderr can be bytes even with text=True
            # (raised mid-communicate() before decoding) -- use _as_text (I8).
            timed_out = True
            out = _as_text(exc.stdout)
            err = _as_text(exc.stderr) + f"\n{SUBPROCESS_TIMEOUT_MARKER}:{timeout}s\n"  # I8
            rc = SUBPROCESS_TIMEOUT_RC

        record_subprocess_rv_trace(out, err)  # I7

        if coverage == "raw":
            ingest_raw_subprocess_coverage(cov_path)  # I6
        else:
            ingest_subprocess_coverage(cov_path)  # I6

        observation = build_process_observation(probe, "probe", 0, rc, timed_out=timed_out)
        record_process_observation(observation)
        return ProbeResult(returncode=rc, stdout=out, stderr=err, observation=observation)
    finally:
        # The params file is a standalone-repro artifact, useful only for a
        # failed probe. Retain it only when the debug env var is set AND the probe
        # failed; otherwise always delete it. Now that run_probe drives real
        # probes, expected crash(rc<0)/timeout(124) outcomes are routine, so
        # unconditional on-failure retention would accumulate p11probe-*.json in
        # TMPDIR without bound. The coverage temp is always removed.
        keep_params = (
            rc is not None and rc != 0 and bool(os.environ.get("PKCS11_CHECK_KEEP_PROBE_PARAMS"))
        )
        to_remove = [cov_path] if keep_params else [cov_path, params_path]
        for p in to_remove:
            try:
                os.unlink(p)
            except OSError:
                pass
