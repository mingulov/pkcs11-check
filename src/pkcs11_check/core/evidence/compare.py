"""Same-lane semantic-ledger comparator with rotation-delta admission.

Compares two ledgers for ONE lane (baseline vs candidate) after E2
admission: groups rows by exact ``(node_id, phase)``, combines repeat
attempts under a quorum policy, applies rotation deltas
(``ComparisonAdmissionV1``), and emits a verdict whose regressions and
unstable entries gate red. Header counters are ignored except
``incomplete`` (fail-closed pre-check); rows are the evidence.

Disposition rank, worst-order (PINNED): passed=0, skipped=1, xfailed=2,
failed=3, xpassed=3, error=4, crashed=5, crash_limited=5, timeout=6.
``missing`` never appears as a row outcome; hand-built input carrying it
ranks 7 (worst, fail closed).

New-test surfacing lives here via the added-ID rule (candidate-only keys);
E2's ``obligations_executed`` covers only the both-lanes-absent hole.

Rename boundary (R22): a removal delta and an addition delta whose
fingerprints DIFFER are independent covered operations, never a rename;
rename-hood is claimed ONLY by equal-fingerprint pairing (validated
exclusively 1:1). The gate enforces paperwork validity plus reality
match, never cross-key semantic equivalence -- fuzzy rename detection
would false-red on genuinely independent delete+add pairs.

OUT OF SCOPE (explicitly not implemented here): baseline
freshness/replay (receipt/E4 domain); settle-N identical ledgers
(orchestration, p11lab side); traceback-excerpt CONTENT (raw-stream
access, p11lab side -- fw summaries carry LOCATORS); QEMU/platform
masking (admission/provenance); stop rules for repeats.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from pkcs11_check.core.evidence.schema import LedgerHeader, LedgerRow, Outcome

#: Version string a rotation-delta bundle must carry (ComparisonAdmissionV1).
DELTA_BUNDLE_VERSION = "ComparisonAdmissionV1"

#: Worst-order disposition rank over outcome VALUE strings (PINNED).
DISPOSITION_RANK: dict[str, int] = {
    "passed": 0,
    "skipped": 1,
    "xfailed": 2,
    "failed": 3,
    "xpassed": 3,
    "error": 4,
    "crashed": 5,
    "crash_limited": 5,
    "timeout": 6,
    "missing": 7,
}

#: Outcomes that gate red: moves within this set in EITHER direction are
#: regressions (harness-attribution churn is never a clean improvement).
RED_OUTCOMES = frozenset({"failed", "xpassed", "error", "crashed", "crash_limited", "timeout"})

#: Outcome values a delta fingerprint position may carry (every known outcome).
_KNOWN_OUTCOMES = frozenset(outcome.value for outcome in Outcome)

#: Positions of a 7-tuple fingerprint (see :func:`fingerprint`).
_FINGERPRINT_LEN = 7


@dataclass(frozen=True)
class QuorumPolicy:
    """Repeat-attempt combination policy (attempt-level flake handling)."""

    min_repeats: int = 3
    quorum_frac: float = 2 / 3
    disagree_is_unstable: bool = True


@dataclass(frozen=True)
class Delta:
    """One rotation-delta entry: claimed old->new fingerprint for a case key."""

    lane: str
    case_id: str
    phase: str
    old_fp: tuple[str, ...] | str  # fp 7-tuple or "absent" (addition only)
    new_fp: tuple[str, ...] | str  # fp 7-tuple or "absent" (removal only)
    reason: str
    ttl: int


@dataclass(frozen=True)
class RotationDeltas:
    """A reviewed rotation bundle: versioned delta entries, TTL 1 each."""

    version: str  # must == "ComparisonAdmissionV1"
    entries: tuple[Delta, ...]


@dataclass(frozen=True)
class Regression:
    """One verdict-negative finding (header, delta, or per-key)."""

    node_id: str
    phase: str
    old: tuple[str, ...] | str
    new: tuple[str, ...] | str  # "absent" allowed
    axis: str


@dataclass(frozen=True)
class ComparisonVerdict:
    """Comparator outcome: negative iff regressions or unstable is non-empty."""

    regressions: list[Regression]
    improvements: list[Regression]
    unstable: list[str]  # "node_id::phase:axis" entries
    counts: Mapping[str, int]  # compared/regressions/improvements/
    # unstable/deltas_applied/deltas_stale


def fingerprint(row: LedgerRow) -> tuple[str, ...]:
    """Return the compared semantic fingerprint of one ledger row.

    ``(outcome, reason, class_reason, category, ckr_expected, ckr_actual,
    termination)`` with the outcome VALUE string. ``duration_ms``,
    ``shard_id`` and ``attempt`` are intentionally excluded
    (permitted-nondeterministic).
    """
    return (
        row.outcome.value,
        row.reason,
        row.class_reason,
        row.category,
        row.ckr_expected,
        row.ckr_actual,
        row.termination,
    )


def _rank(outcome: str) -> int:
    """Return the worst-order rank of an outcome VALUE string (loud if unknown)."""
    try:
        return DISPOSITION_RANK[outcome]
    except KeyError:
        raise ValueError(f"compare: unknown outcome {outcome!r}") from None


def _canonical_fp_key(fp: tuple[str, ...]) -> str:
    """Return the deterministic tie-break serialization of one fingerprint."""
    return json.dumps(fp, separators=(",", ":"), ensure_ascii=True)


def combine_attempts(
    rows: Sequence[LedgerRow], policy: QuorumPolicy
) -> tuple[tuple[str, ...], list[str]]:
    """Combine one ``(node_id, phase)`` group's attempts into one fingerprint.

    Sorts by attempt (order-independent verdicts) and rejects empty input.
    Unanimous groups return ``(fp, [])``. Otherwise the combined fingerprint
    is the worst-rank one (ties break toward the lexicographically smallest
    canonical-JSON fingerprint, deterministic across lanes). Findings:
    ``first_attempt`` iff the earliest attempt differs from a unanimous
    later steady state; ``unstable`` iff the policy marks disagreement
    unstable or the quorum is unmet (fewer than ``min_repeats`` attempts or
    the top fingerprint below ``quorum_frac``); else ``disagree`` (bare
    marker -- disagreement is never silent).
    """
    if not rows:
        raise ValueError("combine_attempts: empty input")
    ordered = sorted(rows, key=lambda row: row.attempt)
    fps = [fingerprint(row) for row in ordered]
    if all(fp == fps[0] for fp in fps):
        return fps[0], []
    worst = max(_rank(fp[0]) for fp in fps)
    combined = min((fp for fp in fps if _rank(fp[0]) == worst), key=_canonical_fp_key)
    findings: list[str] = []
    rest = fps[1:]
    if len(fps) >= 2 and all(fp == rest[0] for fp in rest) and fps[0] != rest[0]:
        findings.append("first_attempt")
    top = max(fps.count(fp) for fp in set(fps))
    quorum_met = len(fps) >= policy.min_repeats and top / len(fps) >= policy.quorum_frac
    if policy.disagree_is_unstable or not quorum_met:
        findings.append("unstable")
    elif "first_attempt" not in findings:
        findings.append("disagree")
    return combined, findings


def _check_fp_side(
    errors: list[str], tag: str, side: str, value: tuple[str, ...] | str
) -> str | None:
    """Classify one delta fp side as concrete/absent, recording shape errors."""
    if isinstance(value, str):
        if value == "absent":
            return "absent"
        errors.append(f"shape: {tag} {side} is not a 7-tuple nor 'absent': {value!r}")
        return None
    if (
        isinstance(value, tuple)
        and len(value) == _FINGERPRINT_LEN
        and all(isinstance(part, str) for part in value)
        and value[0] in _KNOWN_OUTCOMES
    ):
        return "concrete"
    errors.append(f"shape: {tag} {side} is not a 7-tuple nor 'absent': {value!r}")
    return None


def validate_deltas(deltas: RotationDeltas) -> list[str]:
    """Validate a rotation bundle against ComparisonAdmissionV1 verbatim.

    Returns error strings (each names its rule); empty means valid. Checks:
    version; per-entry ttl == 1; concrete identity (non-empty lane/case_id/
    phase, no ``*`` or ``{...}`` templates); fp shapes (7-tuple of str with
    a known outcome, or ``"absent"`` with old-absent/addition and
    new-absent/removal positions, both-absent rejected); change-deltas
    differing in exactly one fp position; rename candidates (removal old_fp
    equal to addition new_fp) pairing exclusively 1:1; no duplicate
    ``(lane, case_id, phase)``; non-empty reason.
    """
    errors: list[str] = []
    if deltas.version != DELTA_BUNDLE_VERSION:
        errors.append(
            f"version: RotationDeltas version {deltas.version!r} != {DELTA_BUNDLE_VERSION!r}"
        )
    seen: set[tuple[str, str, str]] = set()
    removals_by_fp: dict[tuple[str, ...], list[int]] = {}
    additions_by_fp: dict[tuple[str, ...], list[int]] = {}
    for index, entry in enumerate(deltas.entries):
        tag = f"entry {index} ({entry.lane!r},{entry.case_id!r},{entry.phase!r})"
        for name, value in (
            ("lane", entry.lane),
            ("case_id", entry.case_id),
            ("phase", entry.phase),
        ):
            if not isinstance(value, str) or not value:
                errors.append(f"identity: {tag} has empty/non-string {name}")
            elif "*" in value or ("{" in value and "}" in value):
                errors.append(f"identity: {tag} {name} uses a wildcard/template: {value!r}")
        identity = (entry.lane, entry.case_id, entry.phase)
        if all(isinstance(part, str) for part in identity):
            key = (entry.lane, entry.case_id, entry.phase)
            if key in seen:
                errors.append(f"duplicate: {tag} repeats an earlier (lane, case_id, phase)")
            else:
                seen.add(key)
        if type(entry.ttl) is not int or entry.ttl != 1:
            errors.append(f"ttl: {tag} has ttl {entry.ttl!r}, must be 1")
        if not isinstance(entry.reason, str) or not entry.reason:
            errors.append(f"reason: {tag} has empty/non-string reason")
        old_kind = _check_fp_side(errors, tag, "old_fp", entry.old_fp)
        new_kind = _check_fp_side(errors, tag, "new_fp", entry.new_fp)
        if old_kind == "absent" and new_kind == "absent":
            errors.append(f"shape: {tag} has old_fp and new_fp both 'absent'")
        if old_kind == "concrete" and new_kind == "concrete":
            old_fp = entry.old_fp
            new_fp = entry.new_fp
            assert isinstance(old_fp, tuple) and isinstance(new_fp, tuple)
            differing = sum(1 for old, new in zip(old_fp, new_fp) if old != new)
            if differing != 1:
                errors.append(
                    f"single-axis: {tag} change-delta differs in {differing} "
                    "fp positions, must be exactly 1"
                )
        if old_kind == "concrete" and new_kind == "absent":
            old_fp = entry.old_fp
            assert isinstance(old_fp, tuple)
            removals_by_fp.setdefault(old_fp, []).append(index)
        if old_kind == "absent" and new_kind == "concrete":
            new_fp = entry.new_fp
            assert isinstance(new_fp, tuple)
            additions_by_fp.setdefault(new_fp, []).append(index)
    for fp, removal_indexes in removals_by_fp.items():
        if fp in additions_by_fp:
            addition_indexes = additions_by_fp[fp]
            if len(removal_indexes) > 1 or len(addition_indexes) > 1:
                errors.append(
                    f"rename: fp {fp!r} pairs {len(removal_indexes)} removal(s) with "
                    f"{len(addition_indexes)} addition(s), must be 1:1"
                )
    return errors


def _group_rows(rows: Sequence[LedgerRow]) -> dict[tuple[str, str], list[LedgerRow]]:
    """Group rows by exact ``(node_id, phase)`` (ledgers arrive pre-normalized).

    No re-normalization happens here. A group whose members disagree on
    ``attempts_total`` raises ``ValueError`` (identity/counting loss).
    """
    groups: dict[tuple[str, str], list[LedgerRow]] = {}
    for row in rows:
        groups.setdefault((row.node_id, row.phase), []).append(row)
    for key, members in groups.items():
        totals = {member.attempts_total for member in members}
        if len(totals) > 1:
            raise ValueError(
                f"compare_lanes: group {key!r} disagrees on attempts_total "
                f"{sorted(totals)} (identity/counting loss)"
            )
    return groups


def _header_incomplete(header: LedgerHeader) -> bool:
    """Whether a header fails the fail-closed incomplete pre-check."""
    value = header.counters.get("incomplete")
    return not isinstance(value, int) or value > 0


def _precheck_verdict(axis: str) -> ComparisonVerdict:
    """Return the single-regression verdict for a fail-closed pre-check."""
    return ComparisonVerdict(
        regressions=[Regression(node_id="", phase="", old="absent", new="absent", axis=axis)],
        improvements=[],
        unstable=[],
        counts={
            "compared": 0,
            "regressions": 1,
            "improvements": 0,
            "unstable": 0,
            "deltas_applied": 0,
            "deltas_stale": 0,
        },
    )


def _key_unstable_entry(
    node_id: str,
    phase: str,
    base_findings: list[str],
    base_count: int,
    cand_findings: list[str],
    cand_count: int,
) -> str | None:
    """Return the rule-5 instability entry for one matched key, if any.

    Any finding on either side, a first-attempt finding on exactly one
    side (compared separately per A-9), or an attempt-count change yields
    an unstable entry (axis ``first_attempt`` for the exactly-one-side
    flip, else ``attempts``). These checks run for EVERY matched key --
    delta coverage excuses the disposition/fingerprint verdict only, never
    instability (F1).
    """
    if ("first_attempt" in base_findings) != ("first_attempt" in cand_findings):
        return f"{node_id}::{phase}:first_attempt"
    if base_findings or cand_findings or base_count != cand_count:
        return f"{node_id}::{phase}:attempts"
    return None


def _one_sided_unstable_entry(node_id: str, phase: str, present_findings: list[str]) -> str | None:
    """Return the rule-5 instability entry for one covered one-sided key, if any.

    Mirrors :func:`_key_unstable_entry` with the absent side contributing no
    findings: a present-side ``first_attempt`` pattern yields the
    ``first_attempt`` axis (the exactly-one-side flip), any other present-side
    finding yields ``attempts``. Coverage excuses the add/remove transition
    only, never within-key attempt disagreement (F1r/R26).
    """
    if "first_attempt" in present_findings:
        return f"{node_id}::{phase}:first_attempt"
    if present_findings:
        return f"{node_id}::{phase}:attempts"
    return None


def _key_disposition_verdict(
    node_id: str,
    phase: str,
    base_fp: tuple[str, ...],
    cand_fp: tuple[str, ...],
) -> tuple[Regression | None, Regression | None]:
    """Return the (regression, improvement) pair for one instability-free key."""
    old_outcome = base_fp[0]
    new_outcome = cand_fp[0]
    if base_fp == cand_fp:
        return None, None
    if old_outcome != new_outcome and old_outcome in RED_OUTCOMES and new_outcome in RED_OUTCOMES:
        return (
            Regression(node_id, phase, base_fp, cand_fp, "outcome"),
            None,
        )
    if _rank(new_outcome) > _rank(old_outcome):
        return (
            Regression(node_id, phase, base_fp, cand_fp, "outcome"),
            None,
        )
    if _rank(new_outcome) < _rank(old_outcome):
        return (
            None,
            Regression(node_id, phase, base_fp, cand_fp, "outcome"),
        )
    if old_outcome != new_outcome:
        # Unreachable: same-rank pairs (failed/xpassed, crashed/crash_limited)
        # are both red and handled above; kept loud rather than silent.
        return (
            Regression(node_id, phase, base_fp, cand_fp, "outcome"),
            None,
        )
    return (
        Regression(node_id, phase, base_fp, cand_fp, "fingerprint"),
        None,
    )


def compare_lanes(
    baseline: tuple[LedgerHeader, list[LedgerRow]],
    candidate: tuple[LedgerHeader, list[LedgerRow]],
    deltas: RotationDeltas,
    quorum: QuorumPolicy,
) -> ComparisonVerdict:
    """Compare two same-lane ledgers under rotation deltas and a quorum policy.

    Same-lane gate, fail-closed pre-checks (either header incomplete,
    empty candidate, empty baseline), delta validation (invalid paperwork
    raises ``ValueError``), per-``(node_id, phase)`` comparison with delta
    coverage, and frozen-union added/removed handling. Verdict-negative
    iff regressions or unstable is non-empty.
    """
    base_header, base_rows = baseline
    cand_header, cand_rows = candidate
    if base_header.lane != cand_header.lane:
        raise ValueError(
            "compare_lanes: cross-lane compare is caller error: "
            f"{base_header.lane!r} vs {cand_header.lane!r}"
        )
    if _header_incomplete(base_header) or _header_incomplete(cand_header):
        return _precheck_verdict("incomplete")
    if not cand_rows:
        return _precheck_verdict("empty_candidate")
    if not base_rows:
        return _precheck_verdict("empty_baseline")
    problems = validate_deltas(deltas)
    if problems:
        raise ValueError(f"compare_lanes: invalid deltas: {'; '.join(problems)}")
    base_groups = _group_rows(base_rows)
    cand_groups = _group_rows(cand_rows)
    base_combined = {
        key: (*combine_attempts(members, quorum), len(members))
        for key, members in base_groups.items()
    }
    cand_combined = {
        key: (*combine_attempts(members, quorum), len(members))
        for key, members in cand_groups.items()
    }

    regressions: list[Regression] = []
    improvements: list[Regression] = []
    unstable: list[str] = []
    applied = 0
    stale = 0
    covered: set[tuple[str, str]] = set()
    compare_on_top: set[tuple[str, str]] = set()

    for entry in deltas.entries:
        key = (entry.case_id, entry.phase)
        if entry.lane != base_header.lane:
            # Foreign paperwork: stale, but the key still compares normally.
            regressions.append(
                Regression(entry.case_id, entry.phase, entry.old_fp, entry.new_fp, "stale_delta")
            )
            stale += 1
            continue
        base_fp = base_combined[key][0] if key in base_combined else None
        cand_fp = cand_combined[key][0] if key in cand_combined else None
        old_absent = entry.old_fp == "absent"
        new_absent = entry.new_fp == "absent"
        if not old_absent and not new_absent:
            old_fp = entry.old_fp
            new_fp = entry.new_fp
            assert isinstance(old_fp, tuple) and isinstance(new_fp, tuple)
            if base_fp == old_fp and cand_fp == new_fp:
                applied += 1
                covered.add(key)
            else:
                regressions.append(
                    Regression(entry.case_id, entry.phase, old_fp, new_fp, "stale_delta")
                )
                stale += 1
                if cand_fp is None or (cand_fp != old_fp and cand_fp != new_fp):
                    compare_on_top.add(key)
                else:
                    covered.add(key)
        elif not old_absent and new_absent:
            if base_fp == entry.old_fp and cand_fp is None:
                applied += 1
            else:
                regressions.append(
                    Regression(
                        entry.case_id, entry.phase, entry.old_fp, entry.new_fp, "stale_delta"
                    )
                )
                stale += 1
            covered.add(key)
        else:  # addition: old absent, new concrete (both-absent rejected above)
            if base_fp is None and cand_fp == entry.new_fp:
                applied += 1
            else:
                regressions.append(
                    Regression(
                        entry.case_id, entry.phase, entry.old_fp, entry.new_fp, "stale_delta"
                    )
                )
                stale += 1
            covered.add(key)

    for key in sorted(set(base_combined) | set(cand_combined)):
        node_id, phase = key
        if key in base_combined and key in cand_combined:
            base_fp, base_findings, base_count = base_combined[key]
            cand_fp, cand_findings, cand_count = cand_combined[key]
            unstable_entry = _key_unstable_entry(
                node_id,
                phase,
                base_findings,
                base_count,
                cand_findings,
                cand_count,
            )
            if unstable_entry is not None:
                unstable.append(unstable_entry)
                # Rule 5 ELSE: disposition/fingerprint rules apply only to
                # stable keys; an unstable key carries no disposition verdict.
                continue
            if key in covered and key not in compare_on_top:
                # F1: coverage excuses the disposition/fingerprint verdict
                # only; the instability checks above always run.
                continue
            regression, improvement = _key_disposition_verdict(node_id, phase, base_fp, cand_fp)
            if regression is not None:
                regressions.append(regression)
            if improvement is not None:
                improvements.append(improvement)
        elif key in covered and key not in compare_on_top:
            # F1r/R26: the present side's within-key findings judge stability
            # BEFORE the covered add/remove transition is excused.
            if key in base_combined:
                _, present_findings, _ = base_combined[key]
            else:
                _, present_findings, _ = cand_combined[key]
            one_sided = _one_sided_unstable_entry(node_id, phase, present_findings)
            if one_sided is not None:
                unstable.append(one_sided)
            continue
        elif key in base_combined:
            base_fp, _, _ = base_combined[key]
            regressions.append(Regression(node_id, phase, base_fp, "absent", "removed"))
        else:
            cand_fp, _, _ = cand_combined[key]
            if cand_fp[0] in {"passed", "skipped"}:
                improvements.append(Regression(node_id, phase, "absent", cand_fp, "added"))
            else:
                regressions.append(Regression(node_id, phase, "absent", cand_fp, "added"))

    return ComparisonVerdict(
        regressions=regressions,
        improvements=improvements,
        unstable=unstable,
        counts={
            "compared": len(set(base_combined) | set(cand_combined)),
            "regressions": len(regressions),
            "improvements": len(improvements),
            "unstable": len(unstable),
            "deltas_applied": applied,
            "deltas_stale": stale,
        },
    )
