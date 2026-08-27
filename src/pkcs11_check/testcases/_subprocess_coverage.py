"""Shared normalization for child-to-parent subprocess coverage payloads."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


def normalize_mechanism_counts(value: Any) -> Counter[int]:
    """Return positive mechanism counts with JSON object keys restored to integer IDs."""
    normalized: Counter[int] = Counter()
    if not isinstance(value, dict):
        return normalized
    for raw_mechanism, raw_count in value.items():
        try:
            mechanism = int(raw_mechanism)
        except (TypeError, ValueError):
            continue
        if type(raw_count) is int and raw_count > 0:
            normalized[mechanism] += raw_count
    return normalized


def normalize_mechanism_rv_counts(value: Any) -> dict[int, Counter[int]]:
    """Restore nested JSON mechanism/RV keys to integer counters."""
    normalized: defaultdict[int, Counter[int]] = defaultdict(Counter)
    if not isinstance(value, dict):
        return dict(normalized)
    for raw_mechanism, raw_counts in value.items():
        try:
            mechanism = int(raw_mechanism)
        except (TypeError, ValueError):
            continue
        if not isinstance(raw_counts, dict):
            continue
        for raw_rv, raw_count in raw_counts.items():
            try:
                rv = int(raw_rv)
            except (TypeError, ValueError):
                continue
            if type(raw_count) is int and raw_count > 0:
                normalized[mechanism][rv] += raw_count
    return dict(normalized)
