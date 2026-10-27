"""Ledger schema v1 (cross-task contract, exact).

Header record ``{"record": "header", ...}`` (first line, exactly one):
``schema_v: 1``, ``lane/lane_os/lane_arch: str``,
``framework_sha/p11lab_sha: str`` (opaque identity echoes from the
orchestrator; empty string allowed, never checked by admission -- the receipt
layer owns identity),
``image_digest/corpus_hash/disabled_hash/planned_collection_hash/
raw_stream_sha256: str``, ``planned_count/raw_stream_bytes/malformed_lines:
int``, ``counters: {str: int}`` (the 9 outcomes + ``missing``,
``child_crash``, ``child_timeout``, ``incomplete``), ``created_by: str``.

Case record ``{"record": "case", ...}`` (ONE ROW PER OCCURRENCE -- case x
phase x attempt; never collapse): ``node_id`` (normalized forward slashes),
``phase: str``, ``attempt: int`` (1-based), ``attempts_total: int``,
``shard_id: str``, ``outcome`` (Outcome name), ``duration_ms: int``,
``reason/class_reason/category/ckr_expected/ckr_actual/mechanism/
stimulus_rev/oracle_rev/reach/effect/cleanup/termination: str`` (empty string
when the source record lacks the facet), ``flags: list[str]``.

``load_ledger`` rejects: wrong/missing schema_v, missing/non-first header,
unsorted rows, duplicate (node_id, phase, attempt), unknown outcome names.

Ledger bytes are stable: ``json.dumps(sort_keys=True)`` one record per line,
header first, rows sorted by (node_id, phase, attempt).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pkcs11_check.core.run_metrics import RESULT_OUTCOME_KEYS

LEDGER_SCHEMA_VERSION = 1


class Outcome(StrEnum):
    """Ledger outcome vocabulary: the 9 run-metrics keys plus ``missing``."""

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    XFAILED = "xfailed"
    XPASSED = "xpassed"
    ERROR = "error"
    CRASHED = "crashed"
    TIMEOUT = "timeout"
    CRASH_LIMITED = "crash_limited"
    MISSING = "missing"


if {member.value for member in Outcome} != set(RESULT_OUTCOME_KEYS) | {"missing"}:
    raise AssertionError("Outcome drifted from run_metrics.RESULT_OUTCOME_KEYS")

#: Every counter key a v1 header carries: the 9 outcome keys plus the four
#: attribution/observability keys owned downstream (missing/incomplete by
#: admission/comparison, child_crash/child_timeout by the merge layer).
COUNTER_KEYS: tuple[str, ...] = (
    *RESULT_OUTCOME_KEYS,
    "missing",
    "child_crash",
    "child_timeout",
    "incomplete",
)


def zero_counters() -> dict[str, int]:
    """Return a fresh all-zero v1 counter mapping."""
    return {key: 0 for key in COUNTER_KEYS}


@dataclass(frozen=True)
class LedgerHeader:
    """First line of a ledger: lane identity plus stream totals."""

    schema_v: int
    lane: str
    lane_os: str
    lane_arch: str
    framework_sha: str
    p11lab_sha: str
    image_digest: str
    corpus_hash: str
    disabled_hash: str
    planned_collection_hash: str
    planned_count: int
    raw_stream_bytes: int
    raw_stream_sha256: str
    malformed_lines: int
    counters: dict[str, int]
    created_by: str

    def to_record(self) -> dict[str, Any]:
        """Serialize this header to its canonical JSONL record dict."""
        return {
            "record": "header",
            "schema_v": self.schema_v,
            "lane": self.lane,
            "lane_os": self.lane_os,
            "lane_arch": self.lane_arch,
            "framework_sha": self.framework_sha,
            "p11lab_sha": self.p11lab_sha,
            "image_digest": self.image_digest,
            "corpus_hash": self.corpus_hash,
            "disabled_hash": self.disabled_hash,
            "planned_collection_hash": self.planned_collection_hash,
            "planned_count": self.planned_count,
            "raw_stream_bytes": self.raw_stream_bytes,
            "raw_stream_sha256": self.raw_stream_sha256,
            "malformed_lines": self.malformed_lines,
            "counters": dict(self.counters),
            "created_by": self.created_by,
        }

    @classmethod
    def from_record(cls, record: Mapping[str, Any], *, line_number: int) -> LedgerHeader:
        """Build a header from a parsed ledger line, failing loud on bad types."""
        label = f"ledger line {line_number}"
        counters = record.get("counters")
        if not isinstance(counters, Mapping):
            raise ValueError(f"{label}: header counters is not an object")
        merged = zero_counters()
        for key, value in counters.items():
            if not isinstance(key, str) or type(value) is not int:
                raise ValueError(f"{label}: header counters has a non-int value")
            if key in merged:
                merged[key] = value
        return cls(
            schema_v=_require_int(record, "schema_v", label),
            lane=_require_str(record, "lane", label),
            lane_os=_require_str(record, "lane_os", label),
            lane_arch=_require_str(record, "lane_arch", label),
            framework_sha=_require_str(record, "framework_sha", label),
            p11lab_sha=_require_str(record, "p11lab_sha", label),
            image_digest=_require_str(record, "image_digest", label),
            corpus_hash=_require_str(record, "corpus_hash", label),
            disabled_hash=_require_str(record, "disabled_hash", label),
            planned_collection_hash=_require_str(record, "planned_collection_hash", label),
            planned_count=_require_int(record, "planned_count", label),
            raw_stream_bytes=_require_int(record, "raw_stream_bytes", label),
            raw_stream_sha256=_require_str(record, "raw_stream_sha256", label),
            malformed_lines=_require_int(record, "malformed_lines", label),
            counters=merged,
            created_by=_require_str(record, "created_by", label),
        )


@dataclass(frozen=True)
class LedgerRow:
    """One ledger case row: a single case x phase x attempt occurrence."""

    node_id: str
    phase: str
    attempt: int
    attempts_total: int
    shard_id: str
    outcome: Outcome
    duration_ms: int
    reason: str
    class_reason: str
    category: str
    ckr_expected: str
    ckr_actual: str
    mechanism: str
    stimulus_rev: str
    oracle_rev: str
    reach: str
    effect: str
    cleanup: str
    termination: str
    flags: list[str]

    @property
    def sort_key(self) -> tuple[str, str, int]:
        """Return the (node_id, phase, attempt) ordering key."""
        return (self.node_id, self.phase, self.attempt)

    def to_record(self) -> dict[str, Any]:
        """Serialize this row to its canonical JSONL record dict."""
        return {
            "record": "case",
            "node_id": self.node_id,
            "phase": self.phase,
            "attempt": self.attempt,
            "attempts_total": self.attempts_total,
            "shard_id": self.shard_id,
            "outcome": self.outcome.value,
            "duration_ms": self.duration_ms,
            "reason": self.reason,
            "class_reason": self.class_reason,
            "category": self.category,
            "ckr_expected": self.ckr_expected,
            "ckr_actual": self.ckr_actual,
            "mechanism": self.mechanism,
            "stimulus_rev": self.stimulus_rev,
            "oracle_rev": self.oracle_rev,
            "reach": self.reach,
            "effect": self.effect,
            "cleanup": self.cleanup,
            "termination": self.termination,
            "flags": list(self.flags),
        }

    @classmethod
    def from_record(cls, record: Mapping[str, Any], *, line_number: int) -> LedgerRow:
        """Build a row from a parsed ledger line, failing loud on bad types."""
        label = f"ledger line {line_number}"
        outcome = record.get("outcome")
        if not isinstance(outcome, str):
            raise ValueError(f"{label}: unknown outcome {outcome!r}")
        try:
            outcome_value = Outcome(outcome)
        except ValueError:
            raise ValueError(f"{label}: unknown outcome {outcome!r}") from None
        flags = record.get("flags")
        if not isinstance(flags, list) or not all(isinstance(f, str) for f in flags):
            raise ValueError(f"{label}: row flags is not a list of strings")
        return cls(
            node_id=_require_str(record, "node_id", label),
            phase=_require_str(record, "phase", label),
            attempt=_require_int(record, "attempt", label),
            attempts_total=_require_int(record, "attempts_total", label),
            shard_id=_require_str(record, "shard_id", label),
            outcome=outcome_value,
            duration_ms=_require_int(record, "duration_ms", label),
            reason=_require_str(record, "reason", label),
            class_reason=_require_str(record, "class_reason", label),
            category=_require_str(record, "category", label),
            ckr_expected=_require_str(record, "ckr_expected", label),
            ckr_actual=_require_str(record, "ckr_actual", label),
            mechanism=_require_str(record, "mechanism", label),
            stimulus_rev=_require_str(record, "stimulus_rev", label),
            oracle_rev=_require_str(record, "oracle_rev", label),
            reach=_require_str(record, "reach", label),
            effect=_require_str(record, "effect", label),
            cleanup=_require_str(record, "cleanup", label),
            termination=_require_str(record, "termination", label),
            flags=list(flags),
        )


def _require_str(record: Mapping[str, Any], key: str, label: str) -> str:
    value = record.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{label}: field {key!r} is not a string")
    return value


def _require_int(record: Mapping[str, Any], key: str, label: str) -> int:
    value = record.get(key)
    if type(value) is not int:
        raise ValueError(f"{label}: field {key!r} is not an int")
    return value
