"""A CliRunner whose captured output carries no ANSI escape sequences.

CLI tests here assert on message CONTENT ("PKCS#11 preflight error",
'"fingerprint": "abc123"', "0 node-ids matched"), never on presentation. Rich's default
highlighter styles substrings inside those messages -- notably any run of digits -- so
`"PKCS#11 preflight error" in result.output` fails against the actual bytes

    PKCS#\x1b[1;36m11\x1b[0m preflight error

That is not a defect in the CLI: Rich strips styling for a non-tty, so a normal pipe is
unaffected, and a user who exports FORCE_COLOR is asking for colour. It is a defect in an
assertion that compares a plain string against styled output.

A fixture cannot fix this. The CLI's consoles are module-level (`console = Console()` in
each cli/*_cmd.py), so each one's colour system is resolved from the environment at IMPORT
time. Rich re-reads the environment for `is_terminal` afterwards, but the colour system --
which is what decides whether escapes are emitted -- is already fixed, so unsetting
FORCE_COLOR from a fixture that runs after collection changes nothing.

Stripping at the runner boundary keeps every existing assertion working, makes the whole
suite independent of the caller's terminal environment, and means a test added later cannot
reintroduce the trap.
"""

from __future__ import annotations

import re
from typing import Any

from typer.testing import CliRunner

# Matches CSI sequences (colour, bold, cursor moves), which is all Rich emits here.
_ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def strip_ansi(text: str) -> str:
    """Return `text` with ANSI CSI escape sequences removed."""
    return _ANSI_CSI.sub("", text)


class PlainCliRunner(CliRunner):
    """`CliRunner` that removes ANSI escapes from the captured streams.

    `Result.output` is derived from `output_bytes`, and `stdout`/`stderr` from their own
    byte attributes, so all three are rewritten to keep them consistent with each other.
    """

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        result = super().invoke(*args, **kwargs)
        for attribute in ("stdout_bytes", "stderr_bytes", "output_bytes"):
            raw = getattr(result, attribute, None)
            if isinstance(raw, bytes):
                cleaned = strip_ansi(raw.decode("utf-8", "replace")).encode("utf-8")
                object.__setattr__(result, attribute, cleaned)
        return result
