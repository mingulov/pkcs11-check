"""Compliance note system for p11test.

Tracks whether a test exercises standard, recommended, allowed-but-not-recommended,
or deprecated behavior. This enables reports like:

  "Module supports AES-GCM with 16-byte IVs
   (allowed by PKCS#11, not recommended by NIST SP 800-38D)"
  "Module accepts HMAC keys shorter than hash output
   (allowed by spec, not recommended by FIPS 198-1)"
  "Module supports MD5 (deprecated, not approved for FIPS 140-3)"

Usage in tests:
    from p11test.compliance import note, ComplianceLevel

    def test_aes_gcm_16byte_iv(p11_session):
        note("GCM with 16-byte IV", ComplianceLevel.NOT_RECOMMENDED,
             reference="NIST SP 800-38D §8.2 recommends 96-bit IVs")
        # ... test body ...
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class ComplianceLevel(enum.Enum):
    """Classification of a test's compliance posture."""

    STANDARD = "standard"  # Fully conformant, recommended usage
    EXTENDED = "extended"  # Beyond base spec requirements (e.g., large keys)
    NOT_RECOMMENDED = "not_recommended"  # Allowed but explicitly not recommended
    DEPRECATED = "deprecated"  # Uses deprecated algorithms/modes
    VENDOR = "vendor"  # Vendor-specific extension
    FIPS_NON_APPROVED = "fips_non_approved"  # Not approved in FIPS 140-3 mode


@dataclass
class ComplianceNote:
    """A single compliance observation from a test."""

    description: str
    level: ComplianceLevel
    reference: str = ""  # e.g., "NIST SP 800-38D §8.2"
    test_id: str = ""  # filled in by the collector


# Global collector for the current test run
_notes: list[ComplianceNote] = []


def note(
    description: str,
    level: ComplianceLevel,
    reference: str = "",
) -> None:
    """Record a compliance observation for the current test.

    Call this inside a test function to annotate the result with
    compliance-relevant metadata.
    """
    import inspect

    # Get the calling test's name
    frame = inspect.currentframe()
    caller = frame.f_back if frame else None
    test_id = ""
    if caller:
        test_id = caller.f_code.co_qualname

    _notes.append(
        ComplianceNote(
            description=description,
            level=level,
            reference=reference,
            test_id=test_id,
        )
    )


def get_notes() -> list[ComplianceNote]:
    """Return all compliance notes collected so far."""
    return list(_notes)


def clear_notes() -> None:
    """Clear collected notes (call between test runs)."""
    _notes.clear()


def summary() -> dict[str, list[ComplianceNote]]:
    """Group notes by compliance level."""
    result: dict[str, list[ComplianceNote]] = {}
    for n in _notes:
        key = n.level.value
        if key not in result:
            result[key] = []
        result[key].append(n)
    return result
