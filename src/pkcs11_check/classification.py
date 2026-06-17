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

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import Any, Literal, NoReturn, cast

import pytest

from pkcs11_check.raw.rv import ckr_name

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
    "undeclared_capability": "xfail",  # over-advertised: performed more than advertised, benign
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
    if reason in ("not_operational", "nonspec_reject", "honest_deviation", "undeclared_capability"):
        return "LOW"
    if reason == "sanctioned_refusal":
        return "INFO"
    # guards a reason present in _REASON_OUTCOME but missing a severity rule here
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


def _ckr_names(codes: object) -> list[str] | None:
    if codes is None:
        return None
    if isinstance(codes, int):
        return [ckr_name(codes)]
    items = cast("Iterable[object]", codes)
    return [ckr_name(c) if isinstance(c, int) else str(c) for c in items]


def _ckr_name(code: object) -> str | None:
    if code is None:
        return None
    return ckr_name(code) if isinstance(code, int) else str(code)


def _template_summary(
    label: str, expected: list[str] | None, actual: str | None, reason: str
) -> str:
    head = label or reason
    if actual and expected:
        return f"{head}: expected {expected}, got {actual}"
    if actual:
        return f"{head}: got {actual}"
    if expected:
        return f"{head}: expected {expected}"
    return f"{head}: {reason}"


def classify(
    reason: str,
    *,
    kind: str | None = None,
    label: str = "",
    operation: str | None = None,
    mechanism: str | None = None,
    expected: object = None,
    actual: object = None,
    spec_ref: str | None = None,
    source: str | None = None,
    vector_id: str | None = None,
    summary: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Emit a classification: record it, then raise the matching pytest outcome.

    ``actual``/``expected`` may be ints (real CKR codes, resolved via ``ckr_name``)
    or strings (passed through unchanged).  A ``fail`` raises ``pytest.fail`` and an
    ``xfail`` raises ``pytest.xfail``; ``pass`` returns normally.
    """
    outcome, severity = derive_verdict(reason, kind)
    expected_names = _ckr_names(expected)
    actual_name = _ckr_name(actual)
    if summary is None:
        summary = _template_summary(label, expected_names, actual_name, reason)
    if spec_ref is None:
        from pkcs11_check.spec_refs import lookup

        spec_ref = lookup(operation, mechanism, expected)
    record(
        Classification(
            reason=reason,
            outcome=outcome,
            severity=severity,
            kind=kind,
            label=label,
            summary=summary,
            operation=operation,
            mechanism=mechanism,
            expected_ckr=expected_names,
            actual_ckr=actual_name,
            spec_ref=spec_ref or "",
            source=source,
            vector_id=vector_id,
            detail=detail,
        )
    )
    if outcome == "fail":
        pytest.fail(summary)
    if outcome == "xfail":
        pytest.xfail(summary)


def fail_as(reason: str, **kw: Any) -> NoReturn:
    """Emit a ``fail`` classification; raises ``ValueError`` if *reason* is not a fail reason."""
    if derive_verdict(reason, kw.get("kind"))[0] != "fail":
        raise ValueError(f"fail_as requires a fail reason, got {reason!r}")
    classify(reason, **kw)
    raise AssertionError("unreachable: classify() with a fail reason must raise")


def xfail_as(reason: str, **kw: Any) -> NoReturn:
    """Emit an ``xfail`` classification.

    Raises ``ValueError`` if *reason* does not map to an xfail outcome.
    """
    if derive_verdict(reason, kw.get("kind"))[0] != "xfail":
        raise ValueError(f"xfail_as requires an xfail reason, got {reason!r}")
    classify(reason, **kw)
    raise AssertionError("unreachable: classify() with an xfail reason must raise")
