"""Platform helpers for the raw ctypes layer (Windows DLL search path)."""

from __future__ import annotations

import os
import sys


def windows_dll_directory(lib_path: str) -> str | None:
    """Directory to add to the Windows DLL search path so a module's dependent DLLs resolve.

    A provider .dll often ships bundled dependencies (e.g. its own OpenSSL) alongside it; on
    Windows (py3.8+) ``ctypes.CDLL`` no longer searches the module's own directory for those,
    so the caller must ``os.add_dll_directory`` it first. Returns ``None`` when not applicable:
    on POSIX (``ctypes.CDLL`` resolves dependents itself) or where ``os.add_dll_directory`` is
    absent, or if the resolved directory does not exist.
    """
    if sys.platform != "win32" or not hasattr(os, "add_dll_directory"):
        return None
    directory = os.path.dirname(os.path.abspath(lib_path))
    return directory if directory and os.path.isdir(directory) else None
