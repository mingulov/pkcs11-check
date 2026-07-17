"""Shared CKR-spec primitives (CkrExpectation, full_compat, universal tuples).

Extracted so the data tables (_ckr_spec_tables.py) and the assertion logic (_ckr_spec.py)
both depend on this base without a circular import (Tier-4 god-module split).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_DEVICE_MEMORY,
    CKR_DEVICE_REMOVED,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_HOST_MEMORY,
    CKR_SESSION_CLOSED,
    CKR_SESSION_HANDLE_INVALID,
    CKR_TOKEN_NOT_PRESENT,
)

# ---------------------------------------------------------------------------
# Universal CKR codes (spec Sec.5.1.1 - Sec.5.1.3)
# ---------------------------------------------------------------------------

# Any function may return these (spec Sec.5.1.1)
_UNIVERSAL = (CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_FUNCTION_FAILED)

# Session-using functions additionally (spec Sec.5.1.2)
_SESSION_UNIVERSAL = (
    CKR_SESSION_HANDLE_INVALID,
    CKR_DEVICE_REMOVED,
    CKR_SESSION_CLOSED,
)

# Token-using functions additionally (spec Sec.5.1.3)
_TOKEN_UNIVERSAL = (CKR_DEVICE_MEMORY, CKR_DEVICE_ERROR, CKR_TOKEN_NOT_PRESENT)


def full_compat(base_tuple: tuple[int, ...], uses_session: bool = True) -> tuple[int, ...]:
    """Build full acceptable error set from base + universals.

    Duplicates with base_tuple (e.g. CKR_FUNCTION_FAILED already in most tuples)
    are harmless for `in` checks and kept for clarity - each layer adds
    what the spec says it may return.
    """
    result = base_tuple + _UNIVERSAL
    if uses_session:
        result += _SESSION_UNIVERSAL + _TOKEN_UNIVERSAL
    return result


# ---------------------------------------------------------------------------
# CkrExpectation dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CkrExpectation:
    """One error condition for one C_* function.

    Maps a (function, condition) pair to spec-mandated CKR code(s)
    and a broader acceptable set for compat mode.  All CKR codes are
    represented as plain ints (values of CKR_* constants).
    """

    function: str
    """C_* function name, e.g. 'C_EncryptInit'."""

    condition: str
    """Error condition description, e.g. 'mechanism_not_supported'."""

    spec_ckr: int | tuple[int, ...]
    """Spec-mandated CKR int(s). Tuple if multiple are valid (first = preferred)."""

    compat_tuple: tuple[int, ...]
    """Acceptable CKR codes in compat mode (before universal injection)."""

    spec_ref: str
    """OASIS spec reference, e.g. 'PKCS#11 v3.2'."""

    allow_success: bool = False
    """True if permissive modules may accept the operation."""

    kind: str = "policy"
    """'crypto' (correctness) | 'policy' (attribute/permission) | 'lifecycle' (state) |
    'metadata'."""

    testable: bool = True
    """False for conditions requiring NULL pointers or C-memory semantics."""

    mechanisms: list[str] = field(default_factory=list)
    """If mechanism-specific, which mechanisms this applies to."""

    priority_note: str = ""
    """Priority info, e.g. 'Higher priority than CKR_DATA_INVALID'."""

    spec_ckr_code: str = ""
    """Override CKR code name for coverage tracking.

    When the spec mandates a CKR code that has no distinct constant
    (e.g., CKR_TOKEN_RESOURCE_EXCEEDED), spec_ckr may be set to
    CKR_FUNCTION_FAILED but this field records the actual CKR code name
    so the coverage script can count it correctly.
    """
