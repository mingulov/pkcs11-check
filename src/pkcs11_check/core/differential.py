"""N-way differential cross-provider oracle.

For a DETERMINISTIC vector (a known-answer test - Wycheproof/ACVP/CCTV KATs), every
conformant provider must reach the same verdict. Running the same node-id across N
providers and flagging the odd-one-out is a low-false-positive finder: the minority on a
deterministic vector is a suspect (wrong crypto, a spurious rejection, or a crash). This
module is the pure agreement check; the CLI feeds it per-provider node-id -> outcome maps
from the pooled report artifacts. Capability skips are excluded (a legitimate provider
difference, not a crypto disagreement).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from pkcs11_check.core.nodeids import normalize_nodeid
from pkcs11_check.core.report_log import map_report_outcome

# Test-level (node-id) verdict -> broad comparison class. Distinct from
# compare_results.status_class, which maps unit-level statuses. "xfail" is kept its own
# class: on a deterministic KAT a clean deviation still disagrees with providers that passed.
_OUTCOME_CLASS: dict[str, str] = {
    "passed": "pass",
    "xpassed": "pass",
    "failed": "failure",
    "crashed": "failure",
    "timeout": "failure",
    "error": "failure",
    "xfailed": "xfail",
    "skipped": "skipped",
    "empty": "skipped",
    "crash_limited": "skipped",
    "escalated": "skipped",
}

# Classes that count as "the provider actually ran this vector" (a comparable verdict).
_ATTEMPTED_CLASSES = frozenset({"pass", "failure", "xfail"})


@dataclass(frozen=True)
class ProviderDisagreement:
    """One node-id where providers that ran it did not reach the same verdict."""

    nodeid: str
    outcomes: dict[str, str]  # provider -> outcome class (only providers that attempted)
    majority: str  # the majority class, or "tie" when there is no single majority
    minority_providers: list[str]  # the odd ones out (all attempters when "tie")


def _outcome_class(status: str) -> str:
    return _OUTCOME_CLASS.get(status, "unknown")


def _attempted_outcomes(
    per_provider_outcomes: Mapping[str, Mapping[str, str]], nodeid: str
) -> dict[str, str]:
    return {
        provider: outcome_class
        for provider, outcomes in per_provider_outcomes.items()
        if nodeid in outcomes
        and (outcome_class := _outcome_class(outcomes[nodeid])) in _ATTEMPTED_CLASSES
    }


def load_provider_outcomes(records: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    """Extract a node-id -> unified-outcome map from one provider's report.jsonl records.

    Uses the ``call`` phase outcome (with wasxfail mapping); a test that only reached a
    ``setup`` skip is recorded as skipped. Later phases win over an earlier setup skip.
    """
    outcomes: dict[str, str] = {}
    for rec in records:
        if rec.get("$report_type") != "TestReport":
            continue
        raw_nodeid = rec.get("nodeid")
        raw_outcome = rec.get("outcome")
        if not isinstance(raw_nodeid, str) or not isinstance(raw_outcome, str):
            continue
        nodeid = normalize_nodeid(raw_nodeid).strip()
        if not nodeid:
            continue
        when = rec.get("when")
        if when == "call":
            outcomes[nodeid] = map_report_outcome(raw_outcome, rec.get("wasxfail"))
        elif when == "setup" and raw_outcome in {"failed", "skipped"}:
            outcomes.setdefault(nodeid, map_report_outcome(raw_outcome, rec.get("wasxfail")))
    return outcomes


def is_kat_nodeid(nodeid: str) -> bool:
    """Return whether nodeid belongs to an explicitly supported deterministic suite."""
    head = normalize_nodeid(nodeid).split("::", 1)[0]
    rooted = "/" + head.lstrip("/")
    if "/testcases/wycheproof/" in rooted or "/testcases/acvp/" in rooted:
        return True
    parent, separator, filename = rooted.rpartition("/")
    return (
        bool(separator)
        and parent.endswith("/testcases")
        and filename.startswith("test_cctv_")
        and filename.endswith(".py")
    )


def comparable_nodeids(
    per_provider_outcomes: Mapping[str, Mapping[str, str]],
    *,
    min_providers: int = 2,
    nodeid_filter: frozenset[str] | None = None,
) -> frozenset[str]:
    """Return node IDs attempted by at least ``min_providers`` providers."""
    all_nodeids = {nodeid for outcomes in per_provider_outcomes.values() for nodeid in outcomes}
    if nodeid_filter is not None:
        all_nodeids &= nodeid_filter
    return frozenset(
        nodeid
        for nodeid in all_nodeids
        if len(_attempted_outcomes(per_provider_outcomes, nodeid)) >= min_providers
    )


def comparison_components(
    per_provider_outcomes: Mapping[str, Mapping[str, str]],
    *,
    nodeids: Iterable[str],
) -> tuple[frozenset[str], ...]:
    """Return provider components joined by shared attempted node IDs."""
    adjacency: dict[str, set[str]] = {provider: set() for provider in per_provider_outcomes}
    for nodeid in nodeids:
        participants = set(_attempted_outcomes(per_provider_outcomes, nodeid))
        for provider in participants:
            adjacency[provider].update(participants - {provider})

    remaining = set(adjacency)
    components: list[frozenset[str]] = []
    while remaining:
        pending = [min(remaining)]
        component: set[str] = set()
        while pending:
            provider = pending.pop()
            if provider in component:
                continue
            component.add(provider)
            pending.extend(adjacency[provider] - component)
        remaining -= component
        components.append(frozenset(component))
    return tuple(sorted(components, key=lambda component: tuple(sorted(component))))


def find_disagreements(
    per_provider_outcomes: Mapping[str, Mapping[str, str]],
    *,
    min_providers: int = 2,
    nodeid_filter: frozenset[str] | None = None,
) -> list[ProviderDisagreement]:
    """Flag node-ids where providers that ran them disagree on the verdict.

    Args:
        per_provider_outcomes: provider name -> {node-id -> raw outcome string}.
        min_providers: minimum providers that must have ATTEMPTED (non-skip) a node-id
            for it to be comparable.
        nodeid_filter: if given, only these node-ids are considered (e.g. restrict to
            deterministic KAT suites for soundness).

    Returns disagreements sorted by node-id.
    """
    disagreements: list[ProviderDisagreement] = []
    for nodeid in sorted(
        comparable_nodeids(
            per_provider_outcomes,
            min_providers=min_providers,
            nodeid_filter=nodeid_filter,
        )
    ):
        attempted = _attempted_outcomes(per_provider_outcomes, nodeid)
        if len(set(attempted.values())) <= 1:
            continue  # unanimous verdict

        counts = Counter(attempted.values())
        top_count = counts.most_common(1)[0][1]
        majority_classes = [cls for cls, n in counts.items() if n == top_count]
        if len(majority_classes) == 1:
            majority = majority_classes[0]
            minority = sorted(p for p, c in attempted.items() if c != majority)
        else:
            majority = "tie"
            minority = sorted(attempted)
        disagreements.append(
            ProviderDisagreement(
                nodeid=nodeid,
                outcomes=dict(attempted),
                majority=majority,
                minority_providers=minority,
            )
        )
    return disagreements
