"""Exact public-value search helper for QC6a (#58.1/.2).

One paging ``C_FindObjects`` loop shared by the DH, X9.42 DH, DSA and
derived-EC exact-value search nodes: pages until the terminating empty
page (so an absence verdict rests on an exhausted search, never on a
single full page), validates the reported count against the caller's
capacity, and always releases the search with ``C_FindObjectsFinal``.
Verdicts are *recorded* first (both the exact and the changed-value leg
are observed before any terminal outcome is raised), then the caller
raises the strongest record: a proved search contradiction (fail) is
never hidden behind the other leg's xfail.

Attribution: an Init refusal is recorded against ``C_FindObjectsInit``;
Find output defects and the expected-among / not-among verdicts against
``C_FindObjects``; termination defects against ``C_FindObjectsFinal``
without displacing a stronger Find verdict. A clean standard or
vendor-defined refusal of an advertised search is ``not_operational``
(original RV preserved); an undefined RV fails the metadata return-value
contract. Search templates carry stored readback bytes verbatim; records
carry only handle lists, counts and RV names -- never key material.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from ctypes import byref
from dataclasses import dataclass
from typing import Any

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.rv import is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE, CK_ULONG, CKR_OK

#: Handles requested per C_FindObjects call (label-scoped searches are tiny).
PAGE_SIZE = 16
#: Exhaustion bound: PAGE_SIZE * MAX_PAGES handles without an empty page is
#: a non-terminating search, not an absence proof.
MAX_PAGES = 128


@dataclass(frozen=True)
class ExactSearchObservation:
    """One leg's search outcome: handles on success, else a recorded verdict."""

    handles: tuple[int, ...] | None
    record: C.Classification | None


def flip_last_byte(value: bytes) -> bytes:
    """Return *value* with exactly its last byte changed (same length)."""
    if not value:
        raise ValueError("changed-value control needs a non-empty value")
    changed = value[:-1] + bytes([value[-1] ^ 1])
    assert changed != value and len(changed) == len(value)
    return changed


def _refusal_record(
    rv: int, *, label: str, operation: str, detail: dict[str, Any]
) -> C.Classification:
    """Record an Init/Find refusal: clean RV xfail, undefined RV metadata fail."""
    if is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
        return C.record_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            expected=int(CKR_OK),
            actual=rv,
            summary=(
                f"{label}: {operation} refused the exact-value search, "
                "so the result set was never observed"
            ),
            detail=detail,
        )
    return C.record_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        expected=int(CKR_OK),
        actual=rv,
        summary=(
            f"{label}: {operation} returned an undefined RV (return-value contract violation)"
        ),
        detail=detail,
    )


def _final_record(rv: int, *, label: str, detail: dict[str, Any]) -> C.Classification:
    """Record a Final defect: clean RV xfail, undefined RV metadata fail (P5)."""
    if is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
        return C.record_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_FindObjectsFinal",
            inherit_mechanism=False,
            expected=int(CKR_OK),
            actual=rv,
            summary=f"{label}: C_FindObjectsFinal refused to release the exact-value search",
            detail=detail,
        )
    return C.record_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation="C_FindObjectsFinal",
        inherit_mechanism=False,
        expected=int(CKR_OK),
        actual=rv,
        summary=(
            f"{label}: C_FindObjectsFinal returned an undefined RV "
            "(return-value contract violation)"
        ),
        detail=detail,
    )


def observe_exact_search(
    rs: Any,
    template_attrs: Mapping[Any, Any],
    *,
    label: str,
) -> ExactSearchObservation:
    """Run one template search to exhaustion and record any defect.

    Never raises for a provider outcome: failures come back on
    ``ExactSearchObservation.record`` so the sibling leg is still observed.
    """
    tmpl = template_from_dict({int(k): v for k, v in template_attrs.items()})
    rv_init = int(rs.raw.C_FindObjectsInit(rs.sh, tmpl.ptr, tmpl.count))
    if rv_init != int(CKR_OK):
        return ExactSearchObservation(
            handles=None,
            record=_refusal_record(
                rv_init,
                label=label,
                operation="C_FindObjectsInit",
                detail={"session": int(rs.sh)},
            ),
        )
    found: list[int] = []
    record: C.Classification | None = None
    final_rv = int(CKR_OK)
    try:
        for _page in range(MAX_PAGES):
            handles = (CK_OBJECT_HANDLE * PAGE_SIZE)()
            count = CK_ULONG(0)
            rv = int(rs.raw.C_FindObjects(rs.sh, handles, PAGE_SIZE, byref(count)))
            if rv != int(CKR_OK):
                record = _refusal_record(
                    rv,
                    label=label,
                    operation="C_FindObjects",
                    detail={"session": int(rs.sh), "handles_seen": found},
                )
                break
            raw_count = int(count.value)
            if raw_count > PAGE_SIZE:
                record = C.record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=label,
                    operation="C_FindObjects",
                    inherit_mechanism=False,
                    expected=f"find count <= {PAGE_SIZE}",
                    actual=f"find count {raw_count}",
                    summary=(
                        f"{label}: C_FindObjects claimed CKR_OK with count "
                        f"{raw_count} on a {PAGE_SIZE}-element buffer"
                    ),
                    detail={
                        "session": int(rs.sh),
                        "count": raw_count,
                        "capacity": PAGE_SIZE,
                    },
                )
                break
            if raw_count == 0:
                break
            found.extend(int(handles[i]) for i in range(raw_count))
        else:
            record = C.record_as(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation="C_FindObjects",
                inherit_mechanism=False,
                expected="terminating empty page",
                actual=f"{MAX_PAGES} non-empty pages",
                summary=(
                    f"{label}: C_FindObjects never reported an empty page within "
                    f"{MAX_PAGES * PAGE_SIZE} handles; absence is unproven"
                ),
                detail={"session": int(rs.sh), "pages": MAX_PAGES},
            )
    finally:
        try:
            final_rv = int(rs.raw.C_FindObjectsFinal(rs.sh))
        except AttributeError:
            pass
    if final_rv != int(CKR_OK):
        final_record = _final_record(
            final_rv,
            label=label,
            detail={"session": int(rs.sh), "handles_seen": found},
        )
        # Preserve the stronger verdict (P5): a Final FAIL outranks a
        # Find xfail; an existing FAIL -- or the first xfail -- stands.
        # Either way the sibling leg is still observed by the caller.
        if record is None or (final_record.outcome == "fail" and record.outcome != "fail"):
            record = final_record
    if record is not None:
        return ExactSearchObservation(handles=None, record=record)
    return ExactSearchObservation(handles=tuple(found), record=None)


def expected_among_record(
    observation: ExactSearchObservation,
    expected_handle: int,
    *,
    label: str,
) -> C.Classification | None:
    """Record a fail unless *expected_handle* is among the search results."""
    if observation.record is not None:
        return observation.record
    assert observation.handles is not None
    if expected_handle in observation.handles:
        return None
    return C.record_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation="C_FindObjects",
        inherit_mechanism=False,
        expected="expected object among exact-value search results",
        actual=f"{len(observation.handles)} other handle(s)",
        summary=(
            f"{label}: exact-value search claimed success but did not return "
            f"the staged object {expected_handle}"
        ),
        detail={
            "expected_handle": expected_handle,
            "found_handles": list(observation.handles),
        },
    )


def expected_not_among_record(
    observation: ExactSearchObservation,
    expected_handle: int,
    *,
    label: str,
) -> C.Classification | None:
    """Record a fail if *expected_handle* matches the changed-value template."""
    if observation.record is not None:
        return observation.record
    assert observation.handles is not None
    if expected_handle not in observation.handles:
        return None
    return C.record_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation="C_FindObjects",
        inherit_mechanism=False,
        expected="expected object absent from changed-value search results",
        actual=f"staged object {expected_handle} matched",
        summary=(
            f"{label}: changed-value search returned the staged object "
            f"{expected_handle}; the value attribute was ignored in matching"
        ),
        detail={
            "expected_handle": expected_handle,
            "found_handles": list(observation.handles),
        },
    )


def raise_for_exact_search_records(
    records: Iterable[C.Classification | None],
) -> None:
    """Raise the strongest recorded verdict (any fail beats any xfail)."""
    pending = [record for record in records if record is not None]
    for record in pending:
        if record.outcome == "fail":
            C.raise_for_record(record)
    if pending:
        C.raise_for_record(pending[0])


def check_exact_and_changed_search(
    rs: Any,
    *,
    exact_template: Mapping[Any, Any],
    changed_template: Mapping[Any, Any],
    expected_handle: int,
    label: str,
) -> None:
    """Observe both search legs, then raise the strongest verdict.

    The exact template must return *expected_handle* among its results;
    the changed-value control (identical except the tested value) must
    not. Both legs always run so neither can hide the other's defect.
    """
    exact = observe_exact_search(rs, exact_template, label=f"{label}:exact")
    changed = observe_exact_search(rs, changed_template, label=f"{label}:changed")
    raise_for_exact_search_records(
        [
            expected_among_record(exact, expected_handle, label=f"{label}:exact"),
            expected_not_among_record(changed, expected_handle, label=f"{label}:changed"),
        ]
    )
