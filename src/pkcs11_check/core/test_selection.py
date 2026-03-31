"""Production disabled-baseline loading helpers."""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class DisabledBaseline:
    """Normalized disabled-baseline contents plus a stable fingerprint."""

    source_path: Path
    disabled_nodeids: frozenset[str]
    fingerprint: str


def parse_disabled_nodeids(text: str) -> list[str]:
    """Parse exact nodeids from a comment-friendly text file."""
    nodeids: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            continue
        nodeids.append(line)
        seen.add(line)
    return nodeids


def _baseline_fingerprint(path: Path, text: str) -> str:
    payload = f"{path.resolve()}\n{text}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_disabled_baseline(path: Path | None) -> DisabledBaseline | None:
    """Load the configured disabled-baseline file."""
    if path is None:
        return None
    try:
        text = path.read_text()
    except FileNotFoundError as exc:
        msg = f"disabled baseline file not found: {path}"
        raise FileNotFoundError(msg) from exc
    nodeids = parse_disabled_nodeids(text)
    return DisabledBaseline(
        source_path=path,
        disabled_nodeids=frozenset(nodeids),
        fingerprint=_baseline_fingerprint(path, text),
    )


def write_deselect_file(nodeids: Iterable[str]) -> Path:
    """Materialize an exact-nodeid deselect file for pytest/plugin use."""
    unique_sorted = sorted({nodeid for nodeid in nodeids if nodeid})
    fd, raw_path = tempfile.mkstemp(prefix="pkcs11-check-deselect-", suffix=".txt")
    path = Path(raw_path)
    os.close(fd)
    path.write_text("".join(f"{nodeid}\n" for nodeid in unique_sorted))
    return path
