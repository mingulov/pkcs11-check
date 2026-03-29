"""Scenario-aware mechanism selection primitives.

These helpers decide whether a mechanism entry is eligible for a semantic
scenario, and return structured reasons when it is rejected.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_ENCRYPT,
    CKF_SIGN,
    CKF_UNWRAP,
    CKF_VERIFY,
    CKF_WRAP,
)
from pkcs11_check.testcases.mechanism_registry import MechConfig

ScenarioName = Literal[
    "wrap_roundtrip",
    "encrypt_roundtrip",
    "sign_verify_roundtrip",
    "multipart_encrypt_roundtrip",
    "multipart_sign_verify_roundtrip",
]

WRAP_ROUNDTRIP: ScenarioName = "wrap_roundtrip"
ENCRYPT_ROUNDTRIP: ScenarioName = "encrypt_roundtrip"
SIGN_VERIFY_ROUNDTRIP: ScenarioName = "sign_verify_roundtrip"
MULTIPART_ENCRYPT_ROUNDTRIP: ScenarioName = "multipart_encrypt_roundtrip"
MULTIPART_SIGN_VERIFY_ROUNDTRIP: ScenarioName = "multipart_sign_verify_roundtrip"

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
    0x00000100: "CKF_ENCRYPT",
    0x00000200: "CKF_DECRYPT",
    0x00000800: "CKF_SIGN",
    0x00002000: "CKF_VERIFY",
    0x00020000: "CKF_WRAP",
    0x00040000: "CKF_UNWRAP",
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

    return SelectionDecision(
        scenario=scenario,
        selected=not reasons,
        reasons=tuple(reasons),
    )


def _retag_decision(decision: SelectionDecision, scenario: str) -> SelectionDecision:
    """Return a copy of a decision with a different scenario label."""

    return SelectionDecision(
        scenario=scenario,
        selected=decision.selected,
        reasons=decision.reasons,
    )


def wrap_roundtrip(entry: _EntryLike) -> SelectionDecision:
    """Select mechanisms that support wrap and unwrap semantics."""

    return _select_required_flags(entry, WRAP_ROUNDTRIP, int(CKF_WRAP) | int(CKF_UNWRAP))


def encrypt_roundtrip(entry: _EntryLike) -> SelectionDecision:
    """Select mechanisms that support encrypt and decrypt semantics."""

    config = entry.config
    if config is not None and config.input_constraint == "none":
        return SelectionDecision(
            scenario=ENCRYPT_ROUNDTRIP,
            selected=False,
            reasons=(
                SelectionReason(
                    code="unsupported_input_constraint",
                    field="input_constraint",
                    expected="data-capable",
                    actual="none",
                ),
            ),
        )

    return _select_required_flags(
        entry, ENCRYPT_ROUNDTRIP, int(CKF_ENCRYPT) | int(CKF_DECRYPT)
    )


def sign_verify_roundtrip(entry: _EntryLike) -> SelectionDecision:
    """Select mechanisms that support sign and verify semantics."""

    return _select_required_flags(
        entry, SIGN_VERIFY_ROUNDTRIP, int(CKF_SIGN) | int(CKF_VERIFY)
    )


def multipart_encrypt_roundtrip(entry: _EntryLike) -> SelectionDecision:
    """Select mechanisms that can encrypt/decrypt in multi-part mode."""

    decision = _retag_decision(encrypt_roundtrip(entry), MULTIPART_ENCRYPT_ROUNDTRIP)
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


def multipart_sign_verify_roundtrip(entry: _EntryLike) -> SelectionDecision:
    """Select mechanisms that can sign/verify in multi-part mode."""

    decision = _retag_decision(sign_verify_roundtrip(entry), MULTIPART_SIGN_VERIFY_ROUNDTRIP)
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


def select_for_scenario(
    entry: _EntryLike,
    scenario: ScenarioName | str,
) -> SelectionDecision:
    """Dispatch to the scenario-specific selector."""

    if scenario == WRAP_ROUNDTRIP:
        return wrap_roundtrip(entry)
    if scenario == ENCRYPT_ROUNDTRIP:
        return encrypt_roundtrip(entry)
    if scenario == SIGN_VERIFY_ROUNDTRIP:
        return sign_verify_roundtrip(entry)
    if scenario == MULTIPART_ENCRYPT_ROUNDTRIP:
        return multipart_encrypt_roundtrip(entry)
    if scenario == MULTIPART_SIGN_VERIFY_ROUNDTRIP:
        return multipart_sign_verify_roundtrip(entry)
    raise ValueError(f"unknown scenario: {scenario}")
