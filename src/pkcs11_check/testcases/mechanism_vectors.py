"""Load mechanism KAT vectors from JSON files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_VECTOR_DIR = Path(__file__).parent / "data" / "mechanism_vectors"


def load_vectors(filename: str) -> list[dict[str, Any]]:
    """Load all vectors from a JSON file."""
    path = _VECTOR_DIR / filename
    if not path.exists():
        return []
    data: dict[str, Any] = json.loads(path.read_text())
    result: list[dict[str, Any]] = data.get("vectors", [])
    return result


def load_positive_vectors(filename: str) -> list[dict[str, Any]]:
    """Load only positive (expected-pass) vectors."""
    return [v for v in load_vectors(filename) if v.get("type") == "positive"]


def load_negative_vectors(filename: str) -> list[dict[str, Any]]:
    """Load only negative (expected-fail) vectors."""
    return [v for v in load_vectors(filename) if v.get("type") == "negative"]


def available_vector_files() -> list[str]:
    """List all JSON vector files in the data directory."""
    if not _VECTOR_DIR.exists():
        return []
    return sorted(f.name for f in _VECTOR_DIR.glob("*.json"))
