"""Evidence admission: 8 predicates gating lane ledgers for round comparison.

Row-blob canonicalization (PINNED -- E3 and P11Lab reuse verbatim):

- The row mapping is the EXACT ``LedgerRow`` mapping: every schema field of
  the row and nothing else. E1 models ``LedgerRow`` as a dataclass, so the
  mapping is ``{field.name: getattr(row, field.name) for field in
  fields(row)}`` with ``Outcome`` normalized to its string value (no
  ``"record"`` discriminator, no enrichment, no defaults). ``Mapping`` rows
  are dumped as given.
- Per-row blob: ``json.dumps(mapping, sort_keys=True, separators=(",", ":"),
  ensure_ascii=True).encode("utf-8")`` -- key order normalized by
  ``sort_keys`` only; list values (e.g. ``flags``) keep their order.
- Shard blob: the shard's row-blobs sorted byte-wise, joined by single
  ``b"\\n"`` with NO trailing newline.
- ``sha256``: hex digest of the shard blob. Empty shard = sha256 of ``b""``
  (``e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855``).
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from typing import Any

from pkcs11_check.core.evidence.obligations import ObligationInventory
from pkcs11_check.core.evidence.schema import LedgerHeader, LedgerRow, Outcome

#: sha256 of ``b""`` -- the pinned digest of an empty input to
#: ``shard_digest``. Direct ``shard_digest([])`` use only: zero-record roster
#: shards are rejected at construction, so this digest is unreachable via
#: ``admit_lane`` (an absent shard always fails ``roster_complete``).
EMPTY_SHARD_SHA256 = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True)
class ShardExpectation:
    """Predeclared evidence for one shard: row count plus pinned blob digest."""

    records: int
    sha256: str

    def __post_init__(self) -> None:
        """Reject zero-record shards: every roster shard must carry rows."""
        if self.records < 1:
            raise ValueError(
                "ShardExpectation records must be >= 1 "
                f"(got {self.records}); absent shards fail roster_complete, "
                "they are never predeclared empty"
            )


@dataclass(frozen=True)
class PredeclaredRoster:
    """The roster is the single authority for what evidence a lane must carry.

    ``required_identity`` names the header fields that must be non-empty for
    the ``provenance_present`` predicate.
    """

    lane: str
    shards: Mapping[str, ShardExpectation]
    required_identity: tuple[str, ...] = ("lane", "framework_sha")


@dataclass(frozen=True)
class AdmissionVerdict:
    """Admission outcome: every failure names its predicate; warnings never fail."""

    admitted: bool
    failures: list[str]
    warnings: list[str]


def _as_mapping(row: LedgerRow | Mapping[str, Any]) -> dict[str, Any]:
    """Return the EXACT row mapping: all schema fields, no enrichment.

    ``LedgerRow`` becomes its field mapping with ``Outcome`` normalized to
    its value, so dataclass and mapping rows hash byte-identically.
    """
    if isinstance(row, Mapping):
        mapping = dict(row)
    else:
        mapping = {field.name: getattr(row, field.name) for field in fields(row)}
    outcome = mapping.get("outcome")
    if isinstance(outcome, Outcome):
        mapping["outcome"] = outcome.value
    return mapping


def row_blob(row: LedgerRow | Mapping[str, Any]) -> bytes:
    """Return the canonical per-row blob (pinned formula, see module docstring)."""
    return json.dumps(
        _as_mapping(row), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def shard_digest(rows: Sequence[LedgerRow | Mapping[str, Any]]) -> str:
    """Return the hex sha256 over a shard's sorted row-blobs.

    Empty input hashes ``b""`` (the pinned empty-shard edge).
    """
    return hashlib.sha256(b"\n".join(sorted(row_blob(row) for row in rows))).hexdigest()


def _outcome_name(value: Any) -> str | None:
    """Normalize a row outcome to its bucket name; None when missing/mistyped/empty."""
    if isinstance(value, Outcome):
        return value.value
    if isinstance(value, str) and value:
        return value
    return None


def admit_lane(
    header: LedgerHeader,
    rows: Sequence[LedgerRow],
    roster: PredeclaredRoster,
    obligations: ObligationInventory,
) -> AdmissionVerdict:
    """Admit a lane ledger: ALL 8 predicates must pass for ``admitted=True``.

    Pure function: no I/O. ``roster.lane`` is informational -- no predicate
    compares it to ``header.lane``; provenance checks required-identity
    non-emptiness only. Unselected catalog cases surface as
    ``unselected_obligation`` warnings (sorted, warn-only).
    """
    mappings = [_as_mapping(row) for row in rows]
    failures: list[str] = []
    failures.extend(_check_roster_complete(mappings, roster))
    failures.extend(_check_zero_malformed(header))
    failures.extend(_check_typed_fields(mappings))
    failures.extend(_check_session_framing(header, mappings))
    failures.extend(_check_occurrence_preserved(mappings))
    failures.extend(_check_observability_complete(header))
    failures.extend(_check_provenance_present(header, roster))
    failures.extend(_check_obligations_executed(mappings, obligations))
    warnings = [f"unselected_obligation: {case_id}" for case_id in sorted(obligations.unselected)]
    return AdmissionVerdict(admitted=not failures, failures=failures, warnings=warnings)


def _check_roster_complete(mappings: list[dict[str, Any]], roster: PredeclaredRoster) -> list[str]:
    """Every roster shard present with exact count + digest; no undeclared extras."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for mapping in mappings:
        shard = mapping.get("shard_id")
        key = shard if isinstance(shard, str) else f"<non-str shard_id: {type(shard).__name__}>"
        groups.setdefault(key, []).append(mapping)
    problems: list[str] = []
    for shard_id, expected in roster.shards.items():
        if shard_id not in groups:
            problems.append(
                f"roster_complete: roster shard {shard_id!r} missing from rows -- no partial credit"
            )
            continue
        present = groups[shard_id]
        if len(present) != expected.records:
            problems.append(
                f"roster_complete: shard {shard_id!r} has {len(present)} rows, "
                f"roster expects {expected.records}"
            )
            continue
        digest = shard_digest(present)
        if digest != expected.sha256:
            problems.append(
                f"roster_complete: shard {shard_id!r} digest mismatch: "
                f"rows hash {digest}, roster expects {expected.sha256}"
            )
    for shard_id in sorted(groups):
        if shard_id not in roster.shards:
            problems.append(
                f"roster_complete: undeclared extra shard {shard_id!r} "
                f"({len(groups[shard_id])} rows)"
            )
    return problems


def _check_zero_malformed(header: LedgerHeader) -> list[str]:
    """Any malformed ledger line fails admission."""
    if header.malformed_lines > 0:
        return [f"zero_malformed: header reports {header.malformed_lines} malformed line(s)"]
    return []


def _check_typed_fields(mappings: list[dict[str, Any]]) -> list[str]:
    """Every row carries present, correctly-typed outcome/node_id/phase/attempt."""
    bad: list[int] = []
    for index, mapping in enumerate(mappings):
        node_id = mapping.get("node_id")
        phase = mapping.get("phase")
        attempt = mapping.get("attempt")
        if (
            _outcome_name(mapping.get("outcome")) is None
            or not isinstance(node_id, str)
            or not node_id
            or not isinstance(phase, str)
            or not phase
            or type(attempt) is not int
            or attempt < 1
        ):
            bad.append(index)
    if not bad:
        return []
    shown = ", ".join(f"row {index}" for index in bad[:10])
    extra = f" (+{len(bad) - 10} more)" if len(bad) > 10 else ""
    return [
        f"typed_fields: {len(bad)} row(s) with missing/mistyped "
        f"outcome/node_id/phase/attempt: {shown}{extra}"
    ]


def _check_session_framing(header: LedgerHeader, mappings: list[dict[str, Any]]) -> list[str]:
    """Header counters agree with the row multiset, bucket-by-bucket plus total."""
    observed: Counter[str] = Counter()
    for mapping in mappings:
        name = _outcome_name(mapping.get("outcome"))
        observed[name if name is not None else "<untyped>"] += 1
    problems: list[str] = []
    int_values = 0
    for bucket, expected in header.counters.items():
        if type(expected) is not int:
            problems.append(
                f"session_framing: bucket {bucket!r} counter is not an int: {expected!r}"
            )
            continue
        int_values += 1
        got = observed.get(bucket, 0)
        if got != expected:
            problems.append(
                f"session_framing: bucket {bucket!r} header says {expected}, rows have {got}"
            )
    if int_values == len(header.counters) and sum(header.counters.values()) != len(mappings):
        problems.append(
            f"session_framing: header counters sum to {sum(header.counters.values())}, "
            f"rows number {len(mappings)}"
        )
    return problems


def _check_occurrence_preserved(mappings: list[dict[str, Any]]) -> list[str]:
    """Every (node_id, phase) group holds exactly attempts {1..N} of N rows."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for mapping in mappings:
        node_id = mapping.get("node_id")
        phase = mapping.get("phase")
        node_key = (
            node_id if isinstance(node_id, str) else f"<non-str node_id: {type(node_id).__name__}>"
        )
        phase_key = phase if isinstance(phase, str) else f"<non-str phase: {type(phase).__name__}>"
        groups.setdefault((node_key, phase_key), []).append(mapping)
    problems: list[str] = []
    for (node_id, phase), members in sorted(groups.items()):
        totals: list[Any] = [member.get("attempts_total") for member in members]
        if any(type(total) is not int for total in totals):
            problems.append(
                f"occurrence_preserved: group ({node_id!r}, {phase!r}) has non-int attempts_total"
            )
            continue
        first: int = totals[0]
        if any(total != first for total in totals):
            problems.append(
                f"occurrence_preserved: group ({node_id!r}, {phase!r}) disagrees on attempts_total"
            )
            continue
        attempts: list[Any] = [member.get("attempt") for member in members]
        if any(type(attempt) is not int for attempt in attempts) or sorted(attempts) != list(
            range(1, first + 1)
        ):
            problems.append(
                f"occurrence_preserved: group ({node_id!r}, {phase!r}) has {len(members)} "
                f"row(s), attempts_total={first}, observed attempts={attempts!r}"
            )
    return problems


def _check_observability_complete(header: LedgerHeader) -> list[str]:
    """No incomplete observations survive to admission (missing key fails closed)."""
    incomplete = header.counters.get("incomplete")
    if incomplete is None or type(incomplete) is not int or incomplete > 0:
        detail = "missing" if incomplete is None else repr(incomplete)
        return [f"observability_complete: header 'incomplete' counter is {detail} (must be 0)"]
    return []


def _check_provenance_present(header: LedgerHeader, roster: PredeclaredRoster) -> list[str]:
    """Every roster-required identity field is non-empty in the header."""
    missing = []
    for name in roster.required_identity:
        value = getattr(header, name, None) if isinstance(name, str) else None
        if not isinstance(value, str) or not value:
            missing.append(name)
    if not missing:
        return []
    return [f"provenance_present: header identity field(s) empty or missing: {missing!r}"]


def _check_obligations_executed(
    mappings: list[dict[str, Any]], obligations: ObligationInventory
) -> list[str]:
    """Every profile-selected obligation member appears as a row node_id.

    Namespace assumption (R32): catalog/profile authors use ledger node-id
    strings as case IDs, so the match is EXACT string equality against
    ``node_id`` -- any mismatch fails closed (FAIL, never warn), since a
    silently dropped obligation is dropped coverage evidence. Single-lane
    drops still surface downstream at compare as removed-regressions; this
    predicate closes the both-lanes-absent hole compare cannot see.
    """
    present = {mapping.get("node_id") for mapping in mappings}
    return [
        f"obligations_executed: selected case {case_id!r} has no rows"
        for case_id in sorted(obligations.members)
        if case_id not in present
    ]
