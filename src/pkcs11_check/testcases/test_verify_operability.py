"""Dedicated verify-operability test: probe C_Verify per mechanism, once.

For each mechanism that advertises CKF_VERIFY, import a locally-generated public key
and call C_Verify with a known-valid signature built by the cryptography library.
Records a lifecycle finding when the module cannot perform C_Verify at all (not_operational),
and a crypto finding (self_contradiction) when it rejects a valid signature it should accept.

The honest non-advertisement case (CKF_VERIFY absent) is already owned by
test_mech_flags.py and is NOT re-flagged here.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.der import encode_ec_point
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import destroy_quietly, verify_single
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_VERIFY,
    CKF_VERIFY,
    CKK_EC,
    CKK_RSA,
    CKM_ECDSA_SHA256,
    CKM_SHA256_RSA_PKCS,
)
from pkcs11_check.testcases._provisioning import provision_public_key
from pkcs11_check.testcases._signature_policy import MODULE_VERIFY_UNUSABLE_RVS
from pkcs11_check.testcases.conftest import skip_unless_mechanism_flag

pytestmark = [pytest.mark.sign, pytest.mark.keymgmt]

# Fixed test message — same for both mechanisms.
_MESSAGE = b"pkcs11-check verify-operability probe"

# Coordinate byte length for P-256.
_P256_COORD_LEN = 32


# ---------------------------------------------------------------------------
# Part A — classifier helper (fully unit-testable)
# ---------------------------------------------------------------------------


def classify_module_verify(
    rs: Any,
    mechanism: Any,
    pub_handle: int,
    data: bytes,
    sig: bytes,
    *,
    label: str,
) -> None:
    """Probe module C_Verify with a known-valid (data, sig) pair.

    Outcomes:
    - C_Verify returns True  -> pass (capability confirmed).
    - C_Verify raises CkrAssertionError with rv in MODULE_VERIFY_UNUSABLE_RVS
      -> xfail ``not_operational`` (lifecycle): advertised CKF_VERIFY but C_Verify
      not operational.
    - C_Verify raises CkrAssertionError with any other rv -> re-raise (real finding).
    - C_Verify returns False -> fail ``self_contradiction`` (crypto): module rejected
      a known-valid signature.
    """
    try:
        ok = verify_single(rs.raw, rs.sh, pub_handle, mechanism, data, sig)
    except CkrAssertionError as exc:
        if getattr(exc, "rv", None) in MODULE_VERIFY_UNUSABLE_RVS:
            xfail_as(
                "not_operational",
                kind="lifecycle",
                label=label,
                summary=(f"{label}: advertises CKF_VERIFY but C_Verify not operational: {exc}"),
            )
        raise  # unexpected CKR -> real finding (don't swallow)
    if not ok:
        fail_as(
            "self_contradiction",
            kind="crypto",
            label=label,
            summary=f"{label}: module C_Verify rejected a known-valid signature",
        )
    # ok -> pass (capability confirmed)


# ---------------------------------------------------------------------------
# Helpers to build (public_key_bytes, message, signature) locally and import
# ---------------------------------------------------------------------------


def _build_rsa_pkcs1_probe(
    rs: Any,
    p11_config: Any,
) -> tuple[int, bytes, bytes]:
    """Generate RSA-2048 key locally, sign _MESSAGE with PKCS#1 v1.5 SHA-256.

    Returns (pub_handle, message, signature_bytes).
    pub_handle is a session object imported into the module with CKA_VERIFY=True.
    Caller is responsible for calling destroy_quietly on pub_handle.
    """
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sig = priv.sign(_MESSAGE, padding.PKCS1v15(), hashes.SHA256())
    pub_numbers = priv.public_key().public_numbers()
    n = pub_numbers.n.to_bytes(256, "big")
    e = pub_numbers.e.to_bytes(3, "big")
    pub_handle = provision_public_key(
        rs,
        p11_config,
        rsa_n=n,
        rsa_e=e,
        key_type=int(CKK_RSA),
        attrs={CKA_VERIFY: True},
        label="verify-operability RSA",
    )
    return pub_handle, _MESSAGE, sig


def _build_ecdsa_sha256_probe(
    rs: Any,
    p11_config: Any,
) -> tuple[int, bytes, bytes]:
    """Generate P-256 key locally, sign _MESSAGE with ECDSA-SHA256.

    Returns (pub_handle, message, raw_sig).
    raw_sig is the r||s raw format (fixed-width 32+32 bytes) expected by CKM_ECDSA_SHA256.
    pub_handle is a session object imported into the module with CKA_VERIFY=True.
    Caller is responsible for calling destroy_quietly on pub_handle.
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    der_sig = priv.sign(_MESSAGE, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(_P256_COORD_LEN, "big") + s.to_bytes(_P256_COORD_LEN, "big")

    pub_key = priv.public_key()
    pub_numbers = pub_key.public_numbers()
    ec_params = encode_named_curve_parameters("secp256r1")
    ec_point = encode_ec_point(pub_numbers.x, pub_numbers.y, _P256_COORD_LEN)
    pub_handle = provision_public_key(
        rs,
        p11_config,
        ec_params=ec_params,
        ec_point=ec_point,
        key_type=int(CKK_EC),
        attrs={CKA_VERIFY: True},
        label="verify-operability EC",
    )
    return pub_handle, _MESSAGE, raw_sig


# ---------------------------------------------------------------------------
# Part B — the test class
# ---------------------------------------------------------------------------

_VERIFY_PARAMS = [
    pytest.param(CKM_SHA256_RSA_PKCS, "CKM_SHA256_RSA_PKCS", id="RSA-PKCS1v15-SHA256"),
    pytest.param(CKM_ECDSA_SHA256, "CKM_ECDSA_SHA256", id="ECDSA-SHA256"),
]


class TestVerifyOperability:
    """Probe module C_Verify capability for each advertised mechanism.

    Exactly one test per mechanism: generates a known-valid signature locally,
    imports the public key, and checks whether the module's own C_Verify accepts it.
    This isolates the module verify path from the cross-verify oracle used by
    _local_verify.verify_roundtrip, ensuring verify-capability findings are always
    surfaced rather than silently bypassed.
    """

    @pytest.mark.parametrize("mechanism,mech_name", _VERIFY_PARAMS)
    def test_module_verify_operability(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        mechanism: Any,
        mech_name: str,
    ) -> None:
        """Import a locally-signed public key and probe module C_Verify.

        Skip if the module does not advertise CKF_VERIFY for this mechanism
        (honest non-advertisement is already owned by test_mech_flags.py).
        """
        rs = p11_raw_session
        skip_unless_mechanism_flag(rs, int(mechanism), int(CKF_VERIFY))

        label = f"{mech_name}:verify-operability"
        pub_handle = 0
        try:
            if mechanism == CKM_SHA256_RSA_PKCS:
                pub_handle, data, sig = _build_rsa_pkcs1_probe(rs, p11_config)
            else:
                pub_handle, data, sig = _build_ecdsa_sha256_probe(rs, p11_config)
            classify_module_verify(rs, mechanism, pub_handle, data, sig, label=label)
        finally:
            if pub_handle:
                destroy_quietly(rs.raw, rs.sh, pub_handle)
