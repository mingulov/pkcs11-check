"""Portable shell invocation for opt-in operator hooks (token-mint commands)."""

from __future__ import annotations

import sys


def shell_invocation(command: str) -> list[str]:
    """Return the argv to run ``command`` through the platform's default shell."""
    if sys.platform == "win32":
        return ["cmd", "/c", command]
    return ["/bin/sh", "-c", command]
