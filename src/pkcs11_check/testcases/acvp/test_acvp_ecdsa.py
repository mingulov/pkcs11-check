"""NIST ACVP ECDSA signature test vectors (FIPS 186-5).

Tests ECDSA signature generation, verification, and key generation using official
NIST ACVP vectors for P-256, P-384, and P-521 with SHA2-256, SHA2-384, and SHA2-512.

Requires: scripts/fetch-optional-data.sh acvp
Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_ec_keypair,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_VERIFY,
    CKF_VERIFY,
    CKK_EC,
    CKM,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_HOST_MEMORY,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._ec_export import (
    coord_len_for_curve,
    read_ec_public_key_or_xfail,
)
from pkcs11_check.testcases._local_verify import ecdsa_local, verify_roundtrip
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases._provisioning import provision_public_key
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.acvp._duplicates import (
    mark_duplicate_pkcs11_inputs,
    skip_duplicate_pkcs11_input,
)
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors
from pkcs11_check.testcases.conftest import (
    is_known_error,
    require_keygen_key_size,
    skip_unless_mechanism_flag,
    xfail_if_known_ckr,
)

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

# ACVP hashAlg -> (CKM mechanism, mechanism name string for has_mechanism)
_HASH_TO_MECH: dict[str, tuple[Any, str]] = {
    "SHA2-256": (CKM_ECDSA_SHA256, "ECDSA_SHA256"),
    "SHA2-384": (CKM_ECDSA_SHA384, "ECDSA_SHA384"),
    "SHA2-512": (CKM_ECDSA_SHA512, "ECDSA_SHA512"),
}

# ACVP curve name -> (pkcs11 curve name, coordinate byte length)
_CURVE_MAP: dict[str, tuple[str, int]] = {
    "P-256": ("secp256r1", 32),
    "P-384": ("secp384r1", 48),
    "P-521": ("secp521r1", 66),
}

# ACVP curve name -> cryptography EllipticCurve class (for the local oracle).
_CURVE_TO_CRYPTO: dict[str, type[ec.EllipticCurve]] = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}

# ACVP curve name -> curve FIELD SIZE IN BITS, the unit EC_KEY_PAIR_GEN's
# advertised C_GetMechanismInfo min/max range is expressed in. This is
# cryptography's ``curve.key_size`` (P-521 -> 521), NOT coord_len*8 (66*8=528),
# which would wrongly skip P-521 on a module advertising max=521.
_CURVE_FIELD_BITS: dict[str, int] = {name: cls().key_size for name, cls in _CURVE_TO_CRYPTO.items()}

# ACVP hashAlg string -> cryptography HashAlgorithm class. The CKM_ECDSA_SHA*
# mechanism hashes the message internally, so the oracle hashes the same
# message internally and they match. ECDSA vectors only ever use SHA2 here.
_ACVP_HASH_TO_CRYPTO: dict[str, type[hashes.HashAlgorithm]] = {
    "SHA2-256": hashes.SHA256,
    "SHA2-384": hashes.SHA384,
    "SHA2-512": hashes.SHA512,
}

_EC_CAPABILITY_REJECT_RVS = (
    CKR_MECHANISM_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_KEY_SIZE_RANGE,
)

# Split of the merged _EC_CAPABILITY_REJECT_RVS for the public-key-import site
# (import-skip audit A14): genuine capability absence (the curve is not supported)
# stays a skip; the broad import-reject codes are "advertised but not operational"
# on an advertised ECDSA SigVer path and become xfail.
_EC_CURVE_ABSENT_RVS = (
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
)
_EC_PUBLIC_IMPORT_UNSUPPORTED_RVS = (
    CKR_MECHANISM_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_KEY_SIZE_RANGE,
    CKR_HOST_MEMORY,
)

_EC_RUNTIME_FAILURE_RVS = (
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
    CKR_HOST_MEMORY,
)

_DETERMINISTIC_ECDSA_SKIP = (
    "Deterministic ECDSA ACVP vectors require RFC6979 nonce generation; "
    "standard PKCS#11 ECDSA mechanisms do not expose deterministic nonce control"
)


def _der_octet_string(data: bytes) -> bytes:
    """Wrap bytes in a DER OCTET STRING (tag 0x04 + length + data)."""
    n = len(data)
    if n < 0x80:
        return bytes([0x04, n]) + data
    elif n < 0x100:
        return bytes([0x04, 0x81, n]) + data
    else:
        return bytes([0x04, 0x82, n >> 8, n & 0xFF]) + data


def _pad_coordinate(hex_str: str, coord_len: int) -> bytes:
    """Pad hex coordinate to specified byte length."""
    return bytes.fromhex(hex_str.zfill(coord_len * 2))


def _build_signature(r_hex: str, s_hex: str, coord_len: int) -> bytes:
    """Build raw signature from r and s components."""
    return _pad_coordinate(r_hex, coord_len) + _pad_coordinate(s_hex, coord_len)


def _build_ec_point(qx_hex: str, qy_hex: str, coord_len: int) -> bytes:
    """Build uncompressed EC point from coordinates."""
    return _der_octet_string(
        bytes([0x04]) + _pad_coordinate(qx_hex, coord_len) + _pad_coordinate(qy_hex, coord_len)
    )


def _handle_unsupported_curve(exc: AssertionError, curve: str) -> None:
    """Check if exception indicates unsupported curve and skip if so."""
    if is_known_error(exc, _EC_CAPABILITY_REJECT_RVS):
        pytest.skip(f"Curve {curve} not supported: {exc}")
    xfail_if_known_ckr(exc, _EC_RUNTIME_FAILURE_RVS, f"Curve {curve} rejected by runtime failure")
    raise


def _load_ecdsa_sigver_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load ECDSA SigVer ACVP vectors for P-256/384/521. Limits to 20 vectors for speed."""
    all_vecs = load_acvp_vectors("ECDSA-SigVer-FIPS186-5")
    result: list[tuple[str, dict[str, Any]]] = []
    for vec in all_vecs:
        group, inp, exp = vec["group"], vec["input"], vec["expected"]
        curve_name, hash_alg = group.get("curve", ""), group.get("hashAlg", "")
        if curve_name not in _CURVE_MAP or hash_alg not in _HASH_TO_MECH:
            continue
        msg_hex = inp.get("message", "")
        qx_hex, qy_hex = inp.get("qx", ""), inp.get("qy", "")
        r_hex, s_hex = inp.get("r", ""), inp.get("s", "")
        tc_id = inp.get("tcId", 0)
        if not (msg_hex and qx_hex and qy_hex and r_hex and s_hex):
            continue
        _, coord_len = _CURVE_MAP[curve_name]
        mech_int, mech_name = _HASH_TO_MECH[hash_alg]
        ec_curve_name, _ = _CURVE_MAP[curve_name]
        merged: dict[str, Any] = {
            "curve": curve_name,
            "hash_alg": hash_alg,
            "ec_curve_name": ec_curve_name,
            "mech_int": mech_int,
            "mech_name": mech_name,
            "msg": bytes.fromhex(msg_hex),
            "ec_params": encode_named_curve_parameters(ec_curve_name),
            "ec_point_der": _build_ec_point(qx_hex, qy_hex, coord_len),
            "sig": _build_signature(r_hex, s_hex, coord_len),
            "expected_pass": exp.get("testPassed", True),
            "tc_id": tc_id,
        }
        result.append((f"ECDSA-SigVer-{curve_name}-{hash_alg}-tc{tc_id}", merged))
        if len(result) >= 20:
            break
    return result


def _load_ecdsa_siggen_vectors(det: bool = False) -> list[tuple[str, dict[str, Any]]]:
    """Load ECDSA SigGen ACVP vectors (regular or deterministic). Limits to 30 vectors."""
    dirs = ["DetECDSA-SigGen-FIPS186-5"] if det else ["ECDSA-SigGen-FIPS186-5", "ECDSA-SigGen-1.0"]
    all_vecs: list[dict[str, Any]] = []
    for d in dirs:
        all_vecs.extend(load_acvp_vectors(d))
    result: list[tuple[str, dict[str, Any]]] = []
    prefix = "DetECDSA" if det else "ECDSA"
    for vec in all_vecs:
        group, inp, exp = vec["group"], vec["input"], vec["expected"]
        curve_name, hash_alg = group.get("curve", ""), group.get("hashAlg", "")
        if curve_name not in _CURVE_MAP or hash_alg not in _HASH_TO_MECH:
            continue
        msg_hex, tc_id = inp.get("message", ""), inp.get("tcId", 0)
        if not msg_hex:
            continue
        _, coord_len = _CURVE_MAP[curve_name]
        mech_int, mech_name = _HASH_TO_MECH[hash_alg]
        ec_curve_name, _ = _CURVE_MAP[curve_name]
        r_hex, s_hex = exp.get("r", ""), exp.get("s", "")
        qx_hex, qy_hex = exp.get("qx", ""), exp.get("qy", "")
        merged: dict[str, Any] = {
            "curve": curve_name,
            "hash_alg": hash_alg,
            "ec_curve_name": ec_curve_name,
            "mech_int": mech_int,
            "mech_name": mech_name,
            "msg": bytes.fromhex(msg_hex),
            "ec_params": encode_named_curve_parameters(ec_curve_name),
            "tc_id": tc_id,
            "expected_sig": _build_signature(r_hex, s_hex, coord_len)
            if (r_hex and s_hex)
            else None,
            "expected_pub": _build_ec_point(qx_hex, qy_hex, coord_len)
            if (qx_hex and qy_hex)
            else None,
        }
        result.append((f"{prefix}-SigGen-{curve_name}-{hash_alg}-tc{tc_id}", merged))
        if len(result) >= 30:
            break
    return result


def _load_ecdsa_keygen_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load ECDSA KeyGen ACVP vectors for P-256/384/521. Limits to 20 vectors for speed."""
    all_vecs: list[dict[str, Any]] = []
    for d in ["ECDSA-KeyGen-FIPS186-5", "ECDSA-KeyGen-1.0"]:
        all_vecs.extend(load_acvp_vectors(d))
    result: list[tuple[str, dict[str, Any]]] = []
    for vec in all_vecs:
        curve_name = vec["group"].get("curve", "")
        if curve_name not in _CURVE_MAP:
            continue
        ec_curve_name, coord_len = _CURVE_MAP[curve_name]
        tc_id = vec["input"].get("tcId", 0)
        merged: dict[str, Any] = {
            "curve": curve_name,
            "ec_curve_name": ec_curve_name,
            "ec_params": encode_named_curve_parameters(ec_curve_name),
            "coord_len": coord_len,
            "tc_id": tc_id,
        }
        result.append((f"ECDSA-KeyGen-{curve_name}-tc{tc_id}", merged))
        if len(result) >= 20:
            return mark_duplicate_pkcs11_inputs(result, lambda item: item["ec_params"])
    return mark_duplicate_pkcs11_inputs(result, lambda item: item["ec_params"])


_ECDSA_SIGVER_VECTORS = _load_ecdsa_sigver_vectors()
_ECDSA_SIGGEN_VECTORS = _load_ecdsa_siggen_vectors()
_ECDSA_KEYGEN_VECTORS = _load_ecdsa_keygen_vectors()
_DET_ECDSA_VECTORS = _load_ecdsa_siggen_vectors(det=True)


@pytest.mark.parametrize(
    "vec_id,vec", _ECDSA_SIGVER_VECTORS, ids=[v[0] for v in _ECDSA_SIGVER_VECTORS]
)
def test_acvp_ecdsa_sigver(
    p11_module_session: Any, p11_config: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """ECDSA signature verification from NIST ACVP FIPS 186-5 vectors."""
    rs = p11_module_session
    mech_int: CKM = cast(CKM, vec["mech_int"])
    mech_name: str = vec["mech_name"]
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"{mech_name} not supported by module")
    skip_unless_mechanism_flag(rs, mech_int, int(CKF_VERIFY))
    pub_key = 0
    try:
        try:
            pub_key = provision_public_key(
                rs,
                p11_config,
                ec_params=vec["ec_params"],
                ec_point=vec["ec_point_der"],
                key_type=int(CKK_EC),
                attrs={CKA_VERIFY: True},
                label="acvp ecdsa verify",
            )
        except AssertionError as exc:
            if is_known_error(exc, _EC_CURVE_ABSENT_RVS):
                # Genuine capability absence: this curve is not supported. Skip stays.
                pytest.skip(f"Cannot import EC public key for {vec['curve']}: {exc}")
            if isinstance(exc, CkrAssertionError) and is_known_error(
                exc, _EC_PUBLIC_IMPORT_UNSUPPORTED_RVS
            ):
                # The ECDSA SigVer mechanism is advertised (has_mechanism gate passed
                # above) and the import is exhausted -> "advertised but not operational"
                # -> xfail per the classification model (not skip).
                # May include curve-capability rejects expressed as generic CKRs --
                # recorded as xfail, not hidden.
                xfail_as(
                    "not_operational",
                    kind="crypto",
                    label=f"{mech_name}:key-import",
                    summary=not_operational_reason(
                        f"{mech_name}:key-import",
                        f"{vec['curve']}: {ckr_name(exc.rv)}",
                    ),
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
            raise
        try:
            verified = verify_single(rs.raw, rs.sh, pub_key, mech_int, vec["msg"], vec["sig"])
        except AssertionError as exc:
            verified = signature_rejected_or_xfail(exc, vec_id)
        if not vec["expected_pass"] and verified:
            fail_as(
                "accepted_invalid",
                kind="crypto",
                label=f"{mech_name}:verify",
                summary=f"{vec_id}: Module accepted invalid signature",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        if vec["expected_pass"] and not verified:
            fail_as(
                "wrong_result",
                kind="crypto",
                label=f"{mech_name}:verify",
                summary=f"{vec_id}: Module rejected valid signature",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
    finally:
        if pub_key:
            destroy_quietly(rs.raw, rs.sh, pub_key)


class TestEcdsaKeyGen:
    """ECDSA key generation tests using ACVP vectors."""

    @pytest.mark.parametrize(
        "vec_id,vec", _ECDSA_KEYGEN_VECTORS, ids=[v[0] for v in _ECDSA_KEYGEN_VECTORS]
    )
    def test_ecdsa_keygen(self, p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
        """Test ECDSA keypair generation and roundtrip sign/verify."""
        rs = p11_module_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC_KEY_PAIR_GEN not supported by module")
        require_keygen_key_size(
            rs, "EC_KEY_PAIR_GEN", _CURVE_FIELD_BITS[vec["curve"]], label=vec_id
        )
        skip_duplicate_pkcs11_input(vec, "ECDSA KeyGen")
        pub_key = priv_key = 0
        msg = b"ACVP keygen test"
        try:
            try:
                pub_key, priv_key = gen_ec_keypair(
                    rs.raw,
                    rs.sh,
                    curve_oid=vec["ec_params"],
                    public_attrs={CKA_VERIFY: True},
                    private_attrs={CKA_SIGN: True},
                )
                assert pub_key != 0, f"{vec_id}: Public key handle is zero"
                assert priv_key != 0, f"{vec_id}: Private key handle is zero"
                sig = sign_single(rs.raw, rs.sh, priv_key, CKM_ECDSA_SHA256, msg)
            except AssertionError as exc:
                _handle_unsupported_curve(exc, vec["curve"])
                return

            # CKM_ECDSA_SHA256 hashes the message internally -> oracle uses SHA256.
            curve = _CURVE_TO_CRYPTO[vec["curve"]]()
            verify_roundtrip(
                rs,
                mechanism=CKM_ECDSA_SHA256,
                data=msg,
                signature=sig,
                local=lambda: ecdsa_local(
                    read_ec_public_key_or_xfail(rs, pub_key, curve),
                    msg,
                    sig,
                    hashes.SHA256(),
                    coord_len_for_curve(curve),
                ),
                module_pub_handle=pub_key,
                label=vec_id,
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)


class TestEcdsaSigGen:
    """ECDSA signature generation tests using ACVP vectors."""

    @pytest.mark.parametrize(
        "vec_id,vec", _ECDSA_SIGGEN_VECTORS, ids=[v[0] for v in _ECDSA_SIGGEN_VECTORS]
    )
    def test_ecdsa_siggen(self, p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
        """Test ECDSA signature generation and roundtrip verification."""
        rs = p11_module_session
        mech_name: str = vec["mech_name"]
        mech_int: CKM = cast(CKM, vec["mech_int"])
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_name} not supported by module")
        require_keygen_key_size(
            rs, "EC_KEY_PAIR_GEN", _CURVE_FIELD_BITS[vec["curve"]], label=vec_id
        )
        pub_key = priv_key = 0
        try:
            try:
                pub_key, priv_key = gen_ec_keypair(
                    rs.raw,
                    rs.sh,
                    curve_oid=vec["ec_params"],
                    public_attrs={CKA_VERIFY: True},
                    private_attrs={CKA_SIGN: True},
                )
                sig = sign_single(rs.raw, rs.sh, priv_key, mech_int, vec["msg"])
            except AssertionError as exc:
                _handle_unsupported_curve(exc, vec["curve"])
                return

            # mech_int (CKM_ECDSA_SHA*) hashes the message internally -> oracle
            # hashes the same message with the matching SHA2 hash.
            curve = _CURVE_TO_CRYPTO[vec["curve"]]()
            hash_alg = _ACVP_HASH_TO_CRYPTO[vec["hash_alg"]]()
            verify_roundtrip(
                rs,
                mechanism=mech_int,
                data=vec["msg"],
                signature=sig,
                local=lambda: ecdsa_local(
                    read_ec_public_key_or_xfail(rs, pub_key, curve),
                    vec["msg"],
                    sig,
                    hash_alg,
                    coord_len_for_curve(curve),
                ),
                module_pub_handle=pub_key,
                label=vec_id,
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)


class TestDetEcdsa:
    """Deterministic ECDSA (RFC 6979) signature generation tests."""

    @pytest.mark.parametrize(
        "vec_id,vec", _DET_ECDSA_VECTORS, ids=[v[0] for v in _DET_ECDSA_VECTORS]
    )
    def test_det_ecdsa_siggen(
        self, p11_module_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test deterministic ECDSA signature generation."""
        rs = p11_module_session
        mech_name: str = vec["mech_name"]
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_name} not supported by module")
        pytest.skip(_DETERMINISTIC_ECDSA_SKIP)
