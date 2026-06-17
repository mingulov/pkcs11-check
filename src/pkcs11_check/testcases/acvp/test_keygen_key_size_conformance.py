"""Conformance tests: advertised key-size range must be TRUTHFUL.

For each keygen mechanism whose C_GetMechanismInfo max is below a safe ceiling,
we attempt keygen ONE NOTCH ABOVE the advertised max and classify what the module
does.  This is deliberately NOT gated by require_keygen_key_size -- the whole
point is to probe out-of-range behavior.

Classification (classify_over_max_keygen):
- CKR_KEY_SIZE_RANGE             -> PASS  (correct, spec-preferred enforcement)
- other CkrAssertionError        -> xfail "nonspec_reject" (metadata)
- success (no exception)         -> xfail "honest_deviation" (metadata) -- module
                                   accepts above its advertised range; caller
                                   destroys the handle.

Caps:
- RSA: max >= 8192 -> skip (no 17408-bit keygen attempt)
- EC:  no standard NIST P-curve has field bits > max -> skip (no fabricated curve)
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import xfail_as
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_ec_keypair,
    gen_rsa_keypair,
    get_mechanism_info,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_VERIFY,
    CKM_EC_KEY_PAIR_GEN,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKR_KEY_SIZE_RANGE,
)

# Standard NIST P-curves ordered by field-bit size (ascending).
# Used to pick the smallest curve whose field bits exceed the advertised max.
_NIST_P_CURVES: list[tuple[int, str]] = [
    (192, "secp192r1"),
    (224, "secp224r1"),
    (256, "secp256r1"),
    (384, "secp384r1"),
    (521, "secp521r1"),
]

# RSA over-range probe: add this many bits above the advertised max.
_RSA_OVER_RANGE_STEP = 1024

# RSA safe ceiling: skip the probe when advertised max is at or above this.
_RSA_MAX_SAFE_CEILING = 8192


def classify_over_max_keygen(
    exc: CkrAssertionError | None,
    *,
    label: str,
) -> None:
    """Classify the outcome of an over-max keygen attempt.

    Parameters
    ----------
    exc:
        ``None`` if keygen SUCCEEDED (returned handles without exception);
        a ``CkrAssertionError`` if keygen raised (any CKR).
    label:
        Human-readable label for the finding (e.g. ``"RSA_PKCS_KEY_PAIR_GEN:4097-bit"``).

    Outcomes
    --------
    - ``exc is None`` (success)
        -> ``xfail_as("honest_deviation", kind="metadata", ...)``
    - ``exc.rv == CKR_KEY_SIZE_RANGE``
        -> returns ``None`` (PASS -- correct spec-preferred enforcement)
    - ``exc.rv`` is any other value
        -> ``xfail_as("nonspec_reject", kind="metadata", ...)``
    """
    if exc is None:
        xfail_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            summary=(
                f"{label}: generated a key ABOVE advertised max — "
                "advertised range under-states capability; "
                "re-run skipped over-range vectors"
            ),
        )
    if exc.rv == int(CKR_KEY_SIZE_RANGE):
        # Correct enforcement; PASS (just return).
        return
    xfail_as(
        "nonspec_reject",
        kind="metadata",
        label=label,
        summary=(
            f"{label}: enforced over-max with non-spec CKR (expected CKR_KEY_SIZE_RANGE): {exc}"
        ),
    )


class TestKeygenKeySizeConformance:
    """Advertised key-size range truthfulness conformance tests."""

    def test_rsa_keygen_enforces_advertised_max(self, p11_module_session: Any) -> None:
        """Over-max RSA keygen must be rejected with CKR_KEY_SIZE_RANGE (capped at 8192)."""
        rs = p11_module_session

        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA_PKCS_KEY_PAIR_GEN not supported by module")

        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)
        except CkrAssertionError as e:
            pytest.skip(f"C_GetMechanismInfo(RSA_PKCS_KEY_PAIR_GEN) failed: {e}")

        adv_max: int = info["max_key_size"]

        if adv_max >= _RSA_MAX_SAFE_CEILING:
            pytest.skip(
                f"advertised max {adv_max} already at/above sane ceiling "
                f"{_RSA_MAX_SAFE_CEILING}; over-range probe omitted"
            )

        probe_bits = adv_max + _RSA_OVER_RANGE_STEP
        label = f"RSA_PKCS_KEY_PAIR_GEN:{probe_bits}-bit"

        pub_key = priv_key = 0
        caught: CkrAssertionError | None = None
        try:
            try:
                pub_key, priv_key = gen_rsa_keypair(
                    rs.raw,
                    rs.sh,
                    bits=probe_bits,
                    public_attrs={CKA_VERIFY: True},
                    private_attrs={CKA_SIGN: True},
                )
            except CkrAssertionError as exc:
                caught = exc
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)

        classify_over_max_keygen(caught, label=label)

    def test_ec_keygen_enforces_advertised_max(self, p11_module_session: Any) -> None:
        """Over-max EC keygen must be rejected with CKR_KEY_SIZE_RANGE (standard curves only)."""
        rs = p11_module_session

        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC_KEY_PAIR_GEN not supported by module")

        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_EC_KEY_PAIR_GEN)
        except CkrAssertionError as e:
            pytest.skip(f"C_GetMechanismInfo(EC_KEY_PAIR_GEN) failed: {e}")

        adv_max: int = info["max_key_size"]

        # Pick the smallest standard curve whose field bits exceed the advertised max.
        probe_curve: tuple[int, str] | None = None
        for field_bits, curve_name in _NIST_P_CURVES:
            if field_bits > adv_max:
                probe_curve = (field_bits, curve_name)
                break

        if probe_curve is None:
            pytest.skip(
                f"no standard NIST P-curve has field bits > advertised max {adv_max}; "
                "over-range probe omitted"
            )

        field_bits, curve_name = probe_curve
        curve_oid = encode_named_curve_parameters(curve_name)
        label = f"EC_KEY_PAIR_GEN:{curve_name}({field_bits}-bit)"

        pub_key = priv_key = 0
        caught: CkrAssertionError | None = None
        try:
            try:
                pub_key, priv_key = gen_ec_keypair(
                    rs.raw,
                    rs.sh,
                    curve_oid=curve_oid,
                    public_attrs={CKA_VERIFY: True},
                    private_attrs={CKA_SIGN: True},
                )
            except CkrAssertionError as exc:
                caught = exc
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)

        classify_over_max_keygen(caught, label=label)
