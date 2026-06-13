"""At-source test-outcome classification for pkcs11-check.

Tests emit a structured :class:`Classification` record at the moment they decide
``fail``/``xfail``/``pass``, instead of flattening everything into a free-text
``pytest.fail``/``pytest.xfail`` string.  This is the foundation of the migration
to at-source classification and is a sibling of :mod:`pkcs11_check.compliance`.

The model table is encoded once in :func:`derive_verdict`: given a provider-general
``reason`` (and an optional finding ``kind``) it returns the ``(outcome, severity)``
pair.  :func:`classify` is the emit API used by tests — it builds the record, stores
it in the per-test collector, and raises ``pytest.fail``/``pytest.xfail`` as needed.

Usage in tests::

    from pkcs11_check import classification as C

    C.classify("accepted_invalid", kind="crypto", label="RSA:decrypt",
               operation="C_Decrypt", expected=[CKR_ENCRYPTED_DATA_INVALID],
               actual=rv)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

Outcome = Literal["pass", "xfail", "fail"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_REASON_OUTCOME: dict[str, Outcome] = {
    "wrong_result": "fail",
    "accepted_invalid": "fail",
    "self_contradiction": "fail",
    "oracle": "fail",
    "crash": "fail",
    "not_operational": "xfail",
    "nonspec_reject": "xfail",
    "honest_deviation": "xfail",
    "sanctioned_refusal": "pass",
    "unclassified": "fail",
}


def _severity(reason: str, kind: str | None) -> Severity:
    if reason == "wrong_result":
        return "CRITICAL" if kind == "crypto" else "MEDIUM"
    if reason in ("accepted_invalid", "self_contradiction"):
        return "CRITICAL" if kind in ("crypto", "policy") else "HIGH"
    if reason in ("oracle", "crash", "unclassified"):
        return "HIGH"
    if reason in ("not_operational", "nonspec_reject", "honest_deviation"):
        return "LOW"
    if reason == "sanctioned_refusal":
        return "INFO"
    raise ValueError(f"unknown reason: {reason!r}")


def derive_verdict(reason: str, kind: str | None) -> tuple[Outcome, Severity]:
    """Return the ``(outcome, severity)`` for a ``reason``/``kind`` pair.

    Raises ``ValueError`` for an unknown ``reason``.
    """
    if reason not in _REASON_OUTCOME:
        raise ValueError(f"unknown reason: {reason!r}")
    return _REASON_OUTCOME[reason], _severity(reason, kind)


@dataclass
class Classification:
    """A single at-source classification record emitted by a test."""

    reason: str
    outcome: str
    severity: str
    kind: str | None = None
    label: str = ""
    summary: str = ""
    operation: str | None = None
    mechanism: str | None = None
    expected_ckr: list[str] | None = None
    actual_ckr: str | None = None
    spec_ref: str = ""
    source: str | None = None
    vector_id: str | None = None
    detail: dict[str, Any] | None = None
    schema: int = 1


# Global collector for the current test run.
_records: list[Classification] = []


def record(rec: Classification) -> None:
    """Record a classification for the current test."""
    _records.append(rec)


def get_records() -> list[Classification]:
    """Return all classification records collected so far."""
    return list(_records)


def clear() -> None:
    """Clear collected records (call between tests)."""
    _records.clear()


def serialize(records: list[Classification]) -> list[dict[str, Any]]:
    """Serialize classification records into JSON-safe artifact dicts."""
    return [asdict(r) for r in records]
