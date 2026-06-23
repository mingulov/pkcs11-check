"""EC public key import with a short/ambiguous ``CKA_EC_PARAMS`` OID must be rejected.

A conformant module MUST reject an EC public key template whose ``CKA_EC_PARAMS``
value is a truncated or otherwise malformed DER OID.  Silently binding the key to a
*different* well-known curve is a curve-confusion self-contradiction (SEC1 §2.5,
RFC 5480 §2) that enables invalid-curve attacks: an attacker who can cause a module
to import a key on an unexpected curve can recover private-key material via DH with
a low-order point.

Test shape
----------
1. Generate a reference P-256 keypair to obtain a valid ``CKA_EC_POINT`` value.
   (The public point is orthogonal to the probe; it must be a valid DER-encoded
   uncompressed point so the module cannot reject on point grounds alone.)
2. Construct two malformed ``CKA_EC_PARAMS`` variants:
   - *Truncated OID*: the secp384r1 OID with its last byte removed (short read).
   - *Bad DER length*: a full secp384r1 OID with the DER length byte inflated by one
     (claims more octets than are present).
3. For each variant, attempt C_CreateObject(EC public key).  A conformant module
   rejects (pass); a module that accepts must be probed further:
   - If the created object round-trips the malformed ``CKA_EC_PARAMS`` faithfully,
     the module is lenient but not curve-confused (xfail honest_deviation).
   - If the object's stored ``CKA_EC_PARAMS`` differs from what was supplied, the
     module silently rebound the key to a different curve (fail self_contradiction).

Refer: SEC1:2009 §2.5 ("Elliptic Curve Domain Parameters"), RFC 5480 §2,
       invalid-curve attack class (Bernstein & Lange 2017; NIST SP 800-186 §6.2.1).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import destroy_quietly, read_attributes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EC_POINT,
    CKA_VERIFY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    ec_public_key_binding_defect,
    gen_ec_keypair_or_xfail,
    import_ec_public_key_negotiated,
    skip_unless_create_object_supported,
)

pytestmark = pytest.mark.security

# CKRs that constitute a correct rejection of a malformed EC_PARAMS OID.
_OID_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_ARGUMENTS_BAD,
)


def _make_malformed_params() -> list[tuple[str, bytes]]:
    """Return labelled malformed CKA_EC_PARAMS variants derived from secp384r1.

    secp384r1 DER OID: 06 05 2B 81 04 00 22
    - truncated: final byte removed -> 06 05 2B 81 04 00 (OID payload one byte short)
    - bad_length: DER length inflated by 1 -> 06 06 2B 81 04 00 22 (claims 6 bytes but
      only 5 are present, plus the trailing 0x22 becomes an extra phantom byte for the
      length claim -- structurally ambiguous)
    """
    # Full secp384r1 OID TLV: tag=0x06, length=0x05, content=2B 81 04 00 22
    full = encode_named_curve_parameters("secp384r1")
    assert full == bytes([0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22])

    # Variant 1: drop the last content byte -> OID payload is one byte shorter than
    # the DER length field declares.
    truncated = full[:-1]  # 06 05 2B 81 04 00

    # Variant 2: inflate the DER length byte by one (still the same payload bytes
    # present; the declared length now exceeds the actual payload).
    bad_length = bytes([full[0], full[1] + 1]) + full[2:]  # 06 06 2B 81 04 00 22

    return [
        ("truncated_secp384r1_oid", truncated),
        ("bad_der_length_secp384r1_oid", bad_length),
    ]


def _probe_malformed_ec_params(
    rs: Any,
    malformed_params: bytes,
    valid_point: bytes,
    label: str,
) -> None:
    """Import an EC public key with *malformed_params* and classify the outcome.

    See module docstring for the full three-way classification logic.
    """
    try:
        handle = import_ec_public_key_negotiated(
            rs,
            ec_params=malformed_params,
            ec_point=valid_point,
            attrs={CKA_VERIFY: True},
            purpose=f"EC OID confusion probe: {label}",
        )
    except CkrAssertionError as exc:
        # Clean rejection of the malformed OID — the expected conformant outcome.
        classify_negative_rv(
            exc.rv,
            _OID_REJECT_RVS,
            label=f"EC public-key import rejects a short/ambiguous EC_PARAMS OID ({label})",
            kind="crypto",
        )
        return

    # The module accepted. Inspect the stored object.
    try:
        defect = ec_public_key_binding_defect(rs, handle, malformed_params)
        if defect is not None:
            # Module accepted AND silently rebound to a different curve.
            fail_as(
                "self_contradiction",
                kind="crypto",
                label=(f"module accepted a short/ambiguous EC_PARAMS OID and {defect} ({label})"),
                operation="C_CreateObject",
            )
        else:
            # Module accepted AND stored the malformed OID faithfully — lenient,
            # but not curve-confused.  Record as honest deviation, not a hard fail.
            xfail_as(
                "honest_deviation",
                kind="crypto",
                label=(
                    "module accepted a malformed/short EC_PARAMS OID but stored it "
                    f"faithfully (no curve confusion) ({label})"
                ),
            )
    finally:
        destroy_quietly(rs.raw, rs.sh, handle)


class TestCurveOidConfusion:
    """EC public key import with a short/ambiguous CKA_EC_PARAMS OID must be rejected."""

    @pytest.mark.parametrize("label,malformed_params", _make_malformed_params())
    def test_short_ec_params_oid_rejected(
        self,
        p11_raw_session: Any,
        label: str,
        malformed_params: bytes,
    ) -> None:
        """Importing an EC public key with a malformed CKA_EC_PARAMS OID must not
        silently bind the key to a different curve (SEC1 §2.5, RFC 5480 §2).

        A conformant module rejects the malformed template.  A lenient module that
        stores the exact malformed bytes is classified as an honest deviation.
        A module that silently rebinds to a well-known curve is a self-contradiction.
        """
        rs = p11_raw_session

        # Gate: skip if C_CreateObject is not implemented.
        skip_unless_create_object_supported(rs)

        # Gate: skip if EC is not supported.
        if not (rs.has_mechanism("EC_KEY_PAIR_GEN") or rs.has_mechanism("ECDSA_KEY_PAIR_GEN")):
            pytest.skip("EC not supported by module")

        # Obtain a valid P-256 public point to pair with the malformed params.
        # The point is orthogonal — it is valid on P-256; the probe targets
        # EC_PARAMS handling, not point validation.
        ref_curve = encode_named_curve_parameters("secp256r1")
        pub_handle, priv_handle = gen_ec_keypair_or_xfail(rs, ref_curve)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub_handle, [int(CKA_EC_POINT)])
            valid_point: bytes = bytes(attrs[int(CKA_EC_POINT)])
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_handle)
            destroy_quietly(rs.raw, rs.sh, priv_handle)

        _probe_malformed_ec_params(rs, malformed_params, valid_point, label)
