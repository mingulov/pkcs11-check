"""Attempt-correlated adoption of novel success handles (R4-F1).

Novelty alone never proves ownership: a token object from another
application can become visible between a baseline inventory and a
success return, and adopting it would read -- and destroy -- a foreign
object. Adoption requires the handle's read-back identity to match the
attempt (label / token flag / class / type):

- every expected field matches: adopt (return);
- any READ field differs: fail loud (proved contradiction), no touch;
- any expected field unproved (and none differing): raise
  :class:`OwnershipUnprovedError` -- the caller voids in its own idiom
  (skip or unproved-effect xfail), no touch.

Validity findings fail loud here (undefined call RVs and
refusal-with-data are verdict-independent contradictions).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pkcs11_check.classification import fail_as
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import CKA_CLASS, CKA_KEY_TYPE, CKA_LABEL, CKA_TOKEN, CKR_OK
from pkcs11_check.testcases._attribute_values import (
    MISSING_ATTRIBUTE,
    attr_or_record,
    refusal_for,
)


@dataclass(frozen=True)
class CallRefused:
    """A call-level identity-read refusal (no per-attribute evidence)."""

    rv: int


class OwnershipUnprovedError(Exception):
    """A novel handle's attempt identity could not be proved (R4-F1).

    ``fields`` names each unproved expected field and why (call RV or
    channel shape); ``call_rv`` carries the call-level RV when the read
    itself refused (None when reads returned with absent attributes).
    Callers void in their own idiom WITHOUT touching the handle.
    """

    def __init__(self, handle: int, fields: dict[str, str], call_rv: int | None) -> None:
        self.handle = handle
        self.fields = fields
        self.call_rv = call_rv
        super().__init__(f"handle {handle}: ownership unproved ({fields})")


def read_identity_attr(rs: Any, handle: int, attr: int, *, label: str, operation: str) -> Any:
    """Read one identity attribute without adopting (R4-F1).

    Returns the decoded value, ``MISSING_ATTRIBUTE`` when the refusals
    channel (or a plain absence) carries no value, or :class:`CallRefused`
    when the call itself refused. Fails loud ONLY on undefined call RVs
    and refusal-with-data (validity findings). Reads are single-attribute
    so refusal-with-data stays attributable (multi-attribute reads cannot
    attribute a refusal CKR to one attribute's bytes).
    """
    try:
        read = read_attributes(rs.raw, rs.sh, handle, [attr])
    except CkrAssertionError as exc:
        if not is_standard_ckr(exc.rv) and not is_vendor_defined_ckr(exc.rv):
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=exc.rv,
                summary=(f"{label}: identity readback returned undefined CK_RV {ckr_name(exc.rv)}"),
            )
        return CallRefused(exc.rv)
    value = attr_or_record(
        read,
        attr,
        label=f"{label}: identity readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    if value is MISSING_ATTRIBUTE:
        refusal = refusal_for(read, attr)
        if refusal is not None and refusal.leaked_len is not None:
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=refusal.ckr,
                summary=(
                    f"{label}: identity readback answered {ckr_name(refusal.ckr)} "
                    f"but still wrote {refusal.leaked_len} bytes into the template"
                ),
                detail={"leaked_len": refusal.leaked_len},
            )
    return value


def _narrow_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _narrow_ulong(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    return int(value) if isinstance(value, int) else None


_FIELD_ATTRS: dict[str, int] = {
    "label": int(CKA_LABEL),
    "token": int(CKA_TOKEN),
    "class": int(CKA_CLASS),
    "key_type": int(CKA_KEY_TYPE),
}


def read_attempt_identity(
    rs: Any,
    handle: int,
    *,
    label: str,
    operation: str,
    fields: tuple[str, ...] = ("label", "token", "class", "key_type"),
) -> dict[str, Any]:
    """Read the named identity fields without adopting (R4-F1).

    Returns ``{field: value | MISSING_ATTRIBUTE | CallRefused}`` for
    exactly ``fields``. Validity findings (undefined call RVs,
    refusal-with-data) fail loud inside the single-attribute reads.
    """
    observed: dict[str, Any] = {}
    for name in fields:
        observed[name] = read_identity_attr(
            rs, handle, _FIELD_ATTRS[name], label=label, operation=operation
        )
    return observed


def read_source_expectations(rs: Any, source: int, *, label: str, operation: str) -> dict[str, Any]:
    """Read a copy source's inheritable identity, best-effort (R4-F1).

    Copies inherit label/token/class/type from the source, so the live
    source readback is the correlation expectation (self-consistent for
    every fixture). Unprovable fields degrade to None (unscored);
    session-ness degrading to None means adoption is impossible and the
    caller must void (it always does: token-None never adopts).
    """
    observed = read_attempt_identity(rs, source, label=label, operation=operation)
    token = observed["token"]
    expect: dict[str, Any] = {
        "token": _narrow_bool(token),
    }
    label_v = observed["label"]
    expect["label"] = label_v if isinstance(label_v, (bytes, str)) else None
    for name in ("class", "key_type"):
        expect[name] = _narrow_ulong(observed[name])
    return expect


def compare_attempt_identity(observed: dict[str, Any], expected: dict[str, Any]) -> str:
    """Grade read identity against the attempt: match/mismatch/unproved (R4-F1).

    Only fields present in ``expected`` (with non-None values) are
    compared. A read field that differs is "mismatch" (proved, even
    beside unproved fields); an expected field that is missing, refused,
    or shape-garbled is "unproved"; otherwise "match".
    """
    unproved = False
    for name, want in expected.items():
        if want is None:
            continue
        got = observed.get(name, MISSING_ATTRIBUTE)
        if isinstance(got, CallRefused) or got is MISSING_ATTRIBUTE:
            unproved = True
            continue
        if name == "token":
            narrowed: Any = _narrow_bool(got)
        elif name in ("class", "key_type"):
            narrowed = _narrow_ulong(got)
        elif isinstance(got, (bytes, str)):
            narrowed = got
        else:
            narrowed = None
        if narrowed is None:
            unproved = True
            continue
        if name == "label":
            match = (
                narrowed == want
                or (
                    isinstance(narrowed, bytes)
                    and isinstance(want, str)
                    and narrowed == want.encode()
                )
                or (
                    isinstance(narrowed, str)
                    and isinstance(want, bytes)
                    and narrowed.encode() == want
                )
            )
        else:
            match = narrowed == want
        if not match:
            return "mismatch"
    return "unproved" if unproved else "match"


def adopt_correlated_output(
    rs: Any,
    handle: int,
    *,
    label: str,
    operation: str,
    expect_label: str | bytes | None,
    expect_token: bool | None,
    expect_class: int | None,
    expect_key_type: int | None,
    spec_ref: str = "",
) -> None:
    """Adopt a novel success handle only with proved attempt correlation (R4-F1).

    A read field that differs from the attempt fails loud (proved
    contradiction) WITHOUT touching the handle; an expected field that
    cannot be proved (and no differing field) raises
    :class:`OwnershipUnprovedError` WITHOUT touching the handle. Fields
    passed as None are not read and not compared (unlabelled products,
    classless type checks).
    """
    expected: dict[str, Any] = {}
    if expect_label is not None:
        expected["label"] = expect_label
    if expect_token is not None:
        expected["token"] = expect_token
    if expect_class is not None:
        expected["class"] = expect_class
    if expect_key_type is not None:
        expected["key_type"] = expect_key_type
    observed = read_attempt_identity(
        rs, handle, label=label, operation=operation, fields=tuple(expected)
    )
    verdict = compare_attempt_identity(observed, expected)
    if verdict == "match":
        return
    per_field = {
        name: compare_attempt_identity({name: observed[name]}, {name: expected[name]})
        for name in expected
    }
    if verdict == "mismatch":
        mismatched = next(name for name in expected if per_field[name] == "mismatch")
        fail_as(
            "self_contradiction",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: success returned a handle whose {mismatched} is not the "
                "attempt's; refusing to use or destroy it"
            ),
            detail={"handle": handle, "field": mismatched},
        )
    unproved: dict[str, str] = {}
    call_rv: int | None = None
    for name in expected:
        if per_field[name] != "unproved":
            continue
        got = observed[name]
        if isinstance(got, CallRefused):
            call_rv = got.rv
            unproved[name] = f"call refused ({ckr_name(got.rv)})"
        elif got is MISSING_ATTRIBUTE:
            unproved[name] = "unreadable"
        else:
            unproved[name] = "unreadable (shape)"
    raise OwnershipUnprovedError(handle, unproved, call_rv)
