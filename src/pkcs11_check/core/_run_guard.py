"""Inter-process guards for run artifacts (F-038).

Two `test` runs sharing one directory used to delete each other's state and
outputs: fixed CWD defaults plus a fresh-run reset with no lock. The guard
holds one OS file lock per artifact path (POSIX flock / Windows LockFile via
msvcrt) from the first reset to run end. A second run sharing any artifact is
refused before it can reset or write anything.

Lock files (`<name>.lock` next to each guarded path) stay on disk after
release: the OS drops the lock on close/process death, so they can never go
stale, and they are never unlinked (unlink-while-another-opens races).
"""

from __future__ import annotations

import contextlib
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

_POLL_SECONDS = 0.05


class RunArtifactsLockedError(RuntimeError):
    """Raised when another live run holds a needed artifact guard."""

    def __init__(self, guard_path: Path, target: Path) -> None:
        super().__init__(
            f"another run holds the artifact guard for {target} "
            f"({guard_path.name}); wait for it to finish or rerun with a "
            "different --state-file and --output-file in separate directories"
        )
        self.guard_path = guard_path
        self.target = target


def guard_path_for(target: Path) -> Path:
    """Return the guard-file path protecting one artifact path."""
    resolved = target.resolve(strict=False)
    return resolved.parent / (resolved.name + ".lock")


def _try_lock(fh: BinaryIO) -> bool:
    """Attempt one non-blocking lock; True when held."""
    fileno = fh.fileno()
    if sys.platform == "win32":
        try:
            msvcrt.locking(fileno, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    try:
        fcntl.flock(fileno, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _unlock(fh: BinaryIO) -> None:
    fileno = fh.fileno()
    if sys.platform == "win32":
        with contextlib.suppress(OSError):
            msvcrt.locking(fileno, msvcrt.LK_UNLCK, 1)
    else:
        with contextlib.suppress(OSError):
            fcntl.flock(fileno, fcntl.LOCK_UN)


@contextlib.contextmanager
def _locked_guard(guard_path: Path, target: Path, *, timeout: float) -> Iterator[None]:
    """Hold the OS lock for one guard file, failing fast or after `timeout`."""
    # The run is committed to writing beside the guard; create the directory
    # the run itself would create (idempotent, race-safe with exist_ok). A
    # refused run may leave an empty directory behind; that litter is benign.
    guard_path.parent.mkdir(parents=True, exist_ok=True)
    with guard_path.open("a+b") as fh:
        fh.seek(0, 2)
        if fh.tell() == 0:
            # Byte-range locks need a byte to lock (Windows); harmless on POSIX.
            # A rare concurrent double-write only duplicates a marker line.
            fh.write(b"pkcs11-check run-artifact guard\n")
            fh.flush()
        deadline = time.monotonic() + timeout
        while True:
            if _try_lock(fh):
                break
            if time.monotonic() >= deadline:
                raise RunArtifactsLockedError(guard_path, target)
            time.sleep(_POLL_SECONDS)
        try:
            yield
        finally:
            _unlock(fh)


@contextlib.contextmanager
def run_artifact_guard(*paths: Path | None, timeout: float = 0.0) -> Iterator[None]:
    """Hold inter-process guards for run artifact paths (F-038).

    Acquires one OS lock per path, in sorted order. `None` entries are
    skipped (unset outputs). With `timeout=0` (default) a contended guard
    raises RunArtifactsLockedError immediately; with `timeout>0` acquisition
    polls until the deadline (KeyboardInterrupt-friendly, unlike a raw
    blocking flock). Partial acquisition unwinds: if a later path contends,
    earlier ones are released before raising.
    """
    targets = sorted({path.resolve(strict=False) for path in paths if path is not None}, key=str)
    pairs = sorted(
        {(guard_path_for(target), target) for target in targets},
        key=lambda pair: str(pair[0]),
    )
    with contextlib.ExitStack() as stack:
        for guard, target in pairs:
            stack.enter_context(_locked_guard(guard, target, timeout=timeout))
        yield
