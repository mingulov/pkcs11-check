"""Make console output UTF-8 safe on Windows.

rich emits non-ASCII marks (checkmarks, dashes, box-drawing). On a Windows console
whose code page is cp1252 (the GitHub Actions default, and many real terminals),
writing them raises ``UnicodeEncodeError: 'charmap' codec can't encode … '\\u2713'``.
Reconfiguring stdout/stderr to UTF-8 -- which encodes every character rich produces --
avoids the crash. No-op off Windows and where a stream cannot be reconfigured.
"""

from __future__ import annotations

import sys


def ensure_utf8_streams() -> None:
    """Reconfigure stdout/stderr to UTF-8 on Windows; no-op elsewhere."""
    if sys.platform != "win32":
        return
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            pass
