"""Shared helpers for CKR subprocess probes."""

from __future__ import annotations

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.testcases._probes.honeypot import SETUP_XFAIL_PREFIX
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

_SETUP_XFAIL_PREFIX = SETUP_XFAIL_PREFIX  # single source: the probe-layer sentinel
# A child probe that observed a genuine break (e.g. a wrong-key operation that
# actually produced output) emits BREAK: and the parent hard-fails it.
_BREAK_PREFIX = "BREAK:"
# A child probe that observed a clean, safe deviation (e.g. a module lenient at
# *Init but that still SAFELY refused at the terminal operation, leaving no
# usable operation behind) emits DEVIATION_XFAIL: and the parent records it as
# an xfail -- a noted deviation, not a hard failure.
_DEVIATION_XFAIL_PREFIX = "DEVIATION_XFAIL:"


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
