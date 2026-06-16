"""Over-delivery probe (@security): does the module perform operations OUTSIDE
its advertised boundaries?

Provider-general; no provider identity. For each advertised RSA/EC/AES mechanism
this deliberately attempts work outside its CK_MECHANISM_INFO box and asserts a
refusal. Performing a below-min/weak op is a security downgrade (fail); performing
a stronger-than-advertised op is benign over-advertisement (xfail). A clean refusal
is the conformant pass; a crash is the finding.

Runs under the framework's per-file subprocess isolation, so a crash on an
out-of-range input is captured as the finding, not a run-killer.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

import pytest

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.recipes import destroy_quietly, gen_rsa_keypair, get_mechanism_info
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)

pytestmark = pytest.mark.security

# RSA moduli are multiples of 8 bits; 512 is the smallest gen_rsa_keypair can
# meaningfully attempt. Returns a size STRICTLY below the module's advertised
# minimum (and >= 512), or None when no valid smaller size exists (so the probe
# is inconclusive and must skip -- never a false pass or false fail).
_RSA_HARD_FLOOR = 512


def rsa_probe_size_below_min(advertised_min: int) -> int | None:
    """A valid RSA modulus size strictly below ``advertised_min``, or None."""
    if advertised_min == 0 or advertised_min <= _RSA_HARD_FLOOR:
        return None
    candidate = advertised_min - 8  # one RSA step (8 bits) below the floor
    if candidate < _RSA_HARD_FLOOR:
        candidate = _RSA_HARD_FLOOR
    return candidate


# Refusal codes that count as the module ENFORCING its advertised boundary.
_ENFORCED_REFUSAL_RVS: frozenset[int] = frozenset(
    {
        CKR_FUNCTION_NOT_SUPPORTED,
        CKR_KEY_SIZE_RANGE,
        CKR_MECHANISM_INVALID,
        CKR_KEY_FUNCTION_NOT_PERMITTED,
        CKR_ATTRIBUTE_VALUE_INVALID,
        CKR_TEMPLATE_INCONSISTENT,
    }
)


class BoundaryCase(Enum):
    BELOW_MIN = "below_min"
    ABOVE_MAX = "above_max"
    FLAG_UNSET = "flag_unset"
    UNADVERTISED_MECH = "unadvertised_mech"


def classify_boundary_outcome(
    case: BoundaryCase,
    *,
    performed: bool,
    refusal: CkrAssertionError | None,
    weak: bool,
) -> None:
    """Decide the verdict of one out-of-range attempt.

    ``performed`` True means the module carried out the out-of-range operation.
    ``refusal`` is the CkrAssertionError raised when it refused (else None).
    ``weak`` marks the security-relevant direction (below-min, or a known-weak
    unadvertised mechanism). Returns None (= pass) on an enforced refusal;
    otherwise raises the pytest verdict.

    ``performed`` and ``refusal`` are mutually exclusive: a real caller either
    got handles back (performed) or caught a CkrAssertionError (refusal).
    """
    if not performed:
        rv = getattr(refusal, "rv", None)
        if rv is not None and rv in _ENFORCED_REFUSAL_RVS:
            return None  # enforced its boundary -> conformant pass
        # Refused, but with a non-canonical clean code: recorded deviation.
        xfail_as(
            "nonspec_reject",
            label=f"capability_boundary:{case.value}",
            actual=rv if rv is not None else "unknown",
            summary=f"boundary {case.value}: refused with non-canonical code "
            f"({ckr_name(rv) if rv is not None else 'unknown'})",
        )
    # The module PERFORMED an out-of-range operation.
    if weak:
        fail_as(
            "self_contradiction",
            kind="policy",
            label=f"capability_boundary:{case.value}",
            summary=f"boundary {case.value}: performed a weaker-than-advertised "
            "operation it claims to reject (security downgrade)",
        )
    xfail_as(
        "undeclared_capability",
        kind="metadata",
        label=f"capability_boundary:{case.value}",
        summary=f"boundary {case.value}: performed an operation beyond its "
        "advertised boundary (benign over-advertisement)",
    )


class TestRSAKeySizeBoundary:
    """RSA: attempt key sizes outside the advertised [min,max] (bits)."""

    def test_rsa_below_min_is_refused(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not advertised")
        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)
        except CkrAssertionError:
            pytest.skip("C_GetMechanismInfo failed for RSA keygen -- cannot determine floor")
        probe_size = rsa_probe_size_below_min(int(info["min_key_size"]))
        if probe_size is None:
            pytest.skip(
                f"advertised RSA min={info['min_key_size']}: no valid size strictly below it"
            )
        # probe_size is genuinely below the module's OWN advertised minimum -> weak.
        performed = False
        refusal: CkrAssertionError | None = None
        pub = priv = 0
        try:
            pub, priv = gen_rsa_keypair(rs.raw, rs.sh, probe_size)
            performed = True
        except CkrAssertionError as exc:
            refusal = exc
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
        classify_boundary_outcome(
            BoundaryCase.BELOW_MIN, performed=performed, refusal=refusal, weak=True
        )
