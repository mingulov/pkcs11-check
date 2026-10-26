"""Portable shell invocation for opt-in operator hooks (token-mint commands)."""

from __future__ import annotations

import sys


def shell_invocation(command: str) -> list[str] | str:
    """Return the argv (POSIX) or command line (win32) to run ``command``."""
    if sys.platform == "win32":
        # Single string: subprocess renders argv lists via list2cmdline, which
        # backslash-escapes inner quotes and breaks cmd parsing; /s makes cmd
        # strip exactly the outer pair and run the rest verbatim.
        return f'cmd /s /c "{command}"'
    return ["/bin/sh", "-c", command]
