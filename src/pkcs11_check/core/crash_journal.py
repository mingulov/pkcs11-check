"""Crash-journal helpers: persist + summarize the per-unit CK_RV write-ahead
journals that pinpoint the C_* call a module crashed in.

Opt-in (off by default) via ``PKCS11_CHECK_RV_TRACE_JOURNAL_DIR``: when set, the
isolated runner gives each unit's subprocess a journal path under that dir, so a
crash leaves an unmatched ``call`` record on disk = the crashing call. This module
provides the filesystem-safe unit slug used for the path and a read-only summary
over a journal dir. See docs/rv-trace-design.md (Phase 4).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pkcs11_check.raw.api import read_crash_journal


def unit_journal_slug(unit: str) -> str:
    """Filesystem-safe slug for a pytest unit (a file path or a nodeid)."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", unit) or "unit"


def summarize_crash_journals(journal_dir: Path) -> list[dict[str, Any]]:
    """One entry per journal that ended mid-call (a crash/kill), newest call kept.

    A journal whose calls all completed (every ``call`` has a matching ``ret``)
    is a clean run and is skipped. For a crashed one, the unmatched trailing
    ``call`` is the crash payload; we return it plus the journal's name and path
    (so the caller can show a relative link). Sorted by filename for stable output.
    """
    out: list[dict[str, Any]] = []
    if not journal_dir.is_dir():
        return out
    for path in sorted(journal_dir.glob("*.jsonl")):
        try:
            _completed, last_incomplete = read_crash_journal(path)
        except OSError:
            continue
        if last_incomplete is None:
            continue  # journal completed cleanly -- no crash recorded here
        out.append({"journal": path.name, "path": str(path), **last_incomplete})
    return out
