"""Scenario-aware mechanism selection primitives.

These helpers decide whether a mechanism entry is eligible for a semantic
scenario, and return structured reasons when it is rejected.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_ENCRYPT,
    CKF_SIGN,
    CKF_UNWRAP,
    CKF_VERIFY,
    CKF_WRAP,
)
from pkcs11_check.testcases.mechanism_registry import MechConfig

SelectionDetail = tuple[str, ...] | bool | str | None

_FLAG_VALUES: tuple[int, ...] = (
    int(CKF_ENCRYPT),
    int(CKF_DECRYPT),
    int(CKF_SIGN),
    int(CKF_VERIFY),
    int(CKF_WRAP),
    int(CKF_UNWRAP),
)

_FLAG_NAME_BY_VALUE: dict[int, str] = {
    0x00000001: "CKF_HW",
    0x00000002: "CKF_MESSAGE_ENCRYPT",
    0x00000004: "CKF_MESSAGE_DECRYPT",
    0x00000008: "CKF_MESSAGE_SIGN",
    0x00000010: "CKF_MESSAGE_VERIFY",
    0x00000020: "CKF_MULTI_MESSAGE",
    0x00000040: "CKF_FIND_OBJECTS",
    0x00000100: "CKF_ENCRYPT",
    0x00000200: "CKF_DECRYPT",
    0x00000400: "CKF_DIGEST",
    0x00000800: "CKF_SIGN",
    0x00001000: "CKF_SIGN_RECOVER",
    0x00002000: "CKF_VERIFY",
    0x00004000: "CKF_VERIFY_RECOVER",
    0x00008000: "CKF_GENERATE",
    0x00010000: "CKF_GENERATE_KEY_PAIR",
    0x00020000: "CKF_WRAP",
    0x00040000: "CKF_UNWRAP",
    0x00080000: "CKF_DERIVE",
    0x10000000: "CKF_ENCAPSULATE",
    0x20000000: "CKF_DECAPSULATE",
    0x80000000: "CKF_EXTENSION",
}


class _EntryLike(Protocol):
    mech_id: int
    mech_name: str
    flags: int
    config: MechConfig | None


@dataclass(frozen=True, slots=True)
class SelectionReason:
    """Structured explanation for a selection rejection."""

    code: str
    field: str
    expected: SelectionDetail = None
    actual: SelectionDetail = None
    missing: tuple[str, ...] = ()
    message: str = ""


@dataclass(frozen=True, slots=True)
class SelectionDecision:
    """Outcome of a scenario selection attempt."""

    scenario: str
    selected: bool
    reasons: tuple[SelectionReason, ...] = ()

    def __bool__(self) -> bool:
        return self.selected

    @property
    def rejected(self) -> bool:
        return not self.selected


def _flag_names(mask: int) -> tuple[str, ...]:
    names: list[str] = []
    for bit in _FLAG_VALUES:
        if mask & bit:
            name = _FLAG_NAME_BY_VALUE.get(bit, f"0x{bit:08x}")
            names.append(name)
    return tuple(names)


def _missing_flag_reason(
    *, field: str, required_mask: int, actual_mask: int
) -> SelectionReason | None:
    missing_mask = required_mask & ~actual_mask
    if missing_mask == 0:
        return None
    return SelectionReason(
        code="missing_flags",
        field=field,
        expected=_flag_names(required_mask),
        actual=_flag_names(actual_mask),
        missing=_flag_names(missing_mask),
    )


def _select_required_flags(
    entry: _EntryLike, scenario: str, required_mask: int
) -> SelectionDecision:
    reasons: list[SelectionReason] = []
    config = entry.config
    if config is None:
        reasons.append(
            SelectionReason(
                code="missing_registry_config",
                field="config",
                expected="registry config",
                actual=None,
            )
        )

    reason = _missing_flag_reason(
        field="flags",
        required_mask=required_mask,
        actual_mask=int(entry.flags),
    )
    if reason is not None:
        reasons.append(reason)

    return SelectionDecision(scenario=scenario, selected=not reasons, reasons=tuple(reasons))


def wrap_roundtrip(entry: _EntryLike) -> SelectionDecision:
    """Select mechanisms that support wrap and unwrap semantics."""

    return _select_required_flags(entry, "wrap_roundtrip", int(CKF_WRAP) | int(CKF_UNWRAP))


def encrypt_roundtrip(entry: _EntryLike) -> SelectionDecision:
    """Select mechanisms that support encrypt and decrypt semantics."""

    return _select_required_flags(entry, "encrypt_roundtrip", int(CKF_ENCRYPT) | int(CKF_DECRYPT))


def sign_verify_roundtrip(entry: _EntryLike) -> SelectionDecision:
    """Select mechanisms that support sign and verify semantics."""

    return _select_required_flags(entry, "sign_verify_roundtrip", int(CKF_SIGN) | int(CKF_VERIFY))


def multipart_encrypt_roundtrip(entry: _EntryLike) -> SelectionDecision:
    """Select mechanisms that can encrypt/decrypt in multi-part mode."""

    decision = _select_required_flags(
        entry, "multipart_encrypt_roundtrip", int(CKF_ENCRYPT) | int(CKF_DECRYPT)
    )
    config = entry.config
    if config is None or config.multi_part_supported:
        return decision

    reasons = list(decision.reasons)
    reasons.append(
        SelectionReason(
            code="unsupported_multi_part",
            field="multi_part_supported",
            expected=True,
            actual=False,
        )
    )
    return SelectionDecision(
        scenario=decision.scenario,
        selected=False,
        reasons=tuple(reasons),
    )


def select_for_scenario(entry: _EntryLike, scenario: str) -> SelectionDecision:
    """Dispatch to the scenario-specific selector."""

    if scenario == "wrap_roundtrip":
        return wrap_roundtrip(entry)
    if scenario == "encrypt_roundtrip":
        return encrypt_roundtrip(entry)
    if scenario == "sign_verify_roundtrip":
        return sign_verify_roundtrip(entry)
    if scenario == "multipart_encrypt_roundtrip":
        return multipart_encrypt_roundtrip(entry)
    raise ValueError(f"Unknown mechanism selection scenario: {scenario}")
