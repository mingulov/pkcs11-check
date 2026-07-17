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

from pkcs11_check.core.report_log import map_report_outcome

# Node-id path fragments of the deterministic known-answer-test suites. Restricting the
# differential check to these is the sound default: a KAT has one correct verdict, so a
# cross-provider disagreement is a real odd-one-out (not legitimate provider variation).
KAT_SUITE_FRAGMENTS: tuple[str, ...] = ("wycheproof", "acvp", "cctv", "x509")

# Test-level (node-id) outcome -> broad class. Distinct from compare_results.status_class,
# which maps unit-level statuses. "xfail" is kept its own class: on a deterministic KAT a
# clean deviation still disagrees with providers that passed.
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


def load_provider_outcomes(records: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    """Extract a node-id -> unified-outcome map from one provider's report.jsonl records.

    Uses the ``call`` phase outcome (with wasxfail mapping); a test that only reached a
    ``setup`` skip is recorded as skipped. Later phases win over an earlier setup skip.
    """
    outcomes: dict[str, str] = {}
    for rec in records:
        if str(rec.get("$report_type", "TestReport")) != "TestReport":
            continue
        nodeid = str(rec.get("nodeid", "")).strip()
        if not nodeid:
            continue
        when = str(rec.get("when", ""))
        if when == "call":
            outcomes[nodeid] = map_report_outcome(
                str(rec.get("outcome", "passed")), rec.get("wasxfail")
            )
        elif when == "setup" and str(rec.get("outcome", "")) == "skipped":
            outcomes.setdefault(nodeid, "skipped")
    return outcomes


def is_kat_nodeid(nodeid: str) -> bool:
    """True if the node-id is in a deterministic KAT suite (the sound differential target)."""
    head = nodeid.split("::", 1)[0]
    return any(frag in head for frag in KAT_SUITE_FRAGMENTS)


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
    all_nodeids: set[str] = set()
    for outcomes in per_provider_outcomes.values():
        all_nodeids.update(outcomes)
    if nodeid_filter is not None:
        all_nodeids &= nodeid_filter

    disagreements: list[ProviderDisagreement] = []
    for nodeid in sorted(all_nodeids):
        attempted: dict[str, str] = {}
        for provider, outcomes in per_provider_outcomes.items():
            if nodeid not in outcomes:
                continue
            cls = _outcome_class(outcomes[nodeid])
            if cls in _ATTEMPTED_CLASSES:
                attempted[provider] = cls
        if len(attempted) < min_providers:
            continue
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
