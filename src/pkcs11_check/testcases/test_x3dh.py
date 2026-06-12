"""Signal X3DH (Extended Triple Diffie-Hellman) mechanism tests.

CKM_X3DH_INITIALIZE - initiator side of X3DH key exchange.
CKM_X3DH_RESPOND   - responder side of X3DH key exchange.

Both mechanisms operate on EC Montgomery keys (CKK_EC_MONTGOMERY, i.e. X25519/X448).
Almost no HSM supports X3DH yet - tests skip cleanly when unavailable.  If a
module claims support, runtime probes attempt C_DeriveKey with the spec
parameter structs and xfail only on listed clean "not operational" CKRs.
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import PackedMechanism, _mech_struct, attr_bytes
from pkcs11_check.raw.recipes import derive_key, destroy_quietly, gen_keypair
from pkcs11_check.raw.types_std import (
    CK_VOID_PTR,
    CK_X3DH_INITIATE_PARAMS,
    CK_X3DH_RESPOND_PARAMS,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EC_PARAMS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKD_SHA256_KDF,
    CKK_GENERIC_SECRET,
    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    CKM_X3DH_INITIALIZE,
    CKM_X3DH_RESPOND,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases.conftest import is_known_error, reject_or_classify, xfail_if_known_ckr

pytestmark = pytest.mark.full

_X3DH_CURVES = (
    ("X25519", encode_named_curve_parameters("x25519")),
    ("X448", encode_named_curve_parameters("x448")),
)

_MONTGOMERY_CURVE_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
)

_MONTGOMERY_KEYGEN_REJECT_RVS = (
    *_MONTGOMERY_CURVE_REJECT_RVS,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_NOT_LOGGED_IN,
)

_X3DH_DERIVE_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_NOT_LOGGED_IN,
)

_X3DH_INVALID_KDF_REJECT_RVS = (CKR_MECHANISM_PARAM_INVALID,)
_X3DH_INVALID_KDF = 0xDEADBEEF


def _bytes_pointer(data: bytes | None, keepalive: list[Any]) -> Any:
    if data is None:
        return None
    if data:
        storage = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    else:
        storage = (ctypes.c_ubyte * 0)()
    keepalive.append(storage)
    return ctypes.cast(storage, CK_VOID_PTR)


def _mech_x3dh_initialize(
    *,
    peer_identity: int,
    peer_prekey: int,
    prekey_signature: bytes | None,
    onetime_key: bytes | None,
    own_identity: int,
    own_ephemeral: int,
    kdf: int = int(CKD_SHA256_KDF),
) -> PackedMechanism:
    keepalive: list[Any] = []
    params = CK_X3DH_INITIATE_PARAMS()
    params.kdf = kdf
    params.pPeer_identity = peer_identity
    params.pPeer_prekey = peer_prekey
    params.pPrekey_signature = _bytes_pointer(prekey_signature, keepalive)
    params.pOnetime_key = _bytes_pointer(onetime_key, keepalive)
    params.pOwn_identity = own_identity
    params.pOwn_ephemeral = own_ephemeral
    return _mech_struct(
        CKM_X3DH_INITIALIZE,
        params,
        "mech_x3dh_initialize",
        keepalive,
        sub_mechanisms={"kdf": int(kdf)},
    )


def _mech_x3dh_respond(
    *,
    identity_id: bytes | None,
    prekey_id: bytes | None,
    onetime_id: bytes | None,
    initiator_identity: int,
    initiator_ephemeral: bytes | None,
    kdf: int = int(CKD_SHA256_KDF),
) -> PackedMechanism:
    keepalive: list[Any] = []
    params = CK_X3DH_RESPOND_PARAMS()
    params.kdf = kdf
    params.pIdentity_id = _bytes_pointer(identity_id, keepalive)
    params.pPrekey_id = _bytes_pointer(prekey_id, keepalive)
    params.pOnetime_id = _bytes_pointer(onetime_id, keepalive)
    params.pInitiator_identity = initiator_identity
    params.pInitiator_ephemeral = _bytes_pointer(initiator_ephemeral, keepalive)
    return _mech_struct(
        CKM_X3DH_RESPOND,
        params,
        "mech_x3dh_respond",
        keepalive,
        sub_mechanisms={"kdf": int(kdf)},
    )


def _create_ec_keypair(rs: Any) -> tuple[int, int]:
    if not rs.has_mechanism("EC_MONTGOMERY_KEY_PAIR_GEN"):
        pytest.skip("CKM_EC_MONTGOMERY_KEY_PAIR_GEN not supported for X3DH setup")

    curve_rejects: list[BaseException] = []
    for curve_name, curve_oid in _X3DH_CURVES:
        try:
            return gen_keypair(
                rs.raw,
                rs.sh,
                int(CKM_EC_MONTGOMERY_KEY_PAIR_GEN),
                pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
                priv_base=[],
                public_attrs={CKA_TOKEN: False},
                private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
                pub_skip={CKA_EC_PARAMS},
            )
        except AssertionError as exc:
            if is_known_error(exc, _MONTGOMERY_CURVE_REJECT_RVS):
                curve_rejects.append(exc)
                continue
            xfail_if_known_ckr(
                exc,
                _MONTGOMERY_KEYGEN_REJECT_RVS,
                f"CKM_EC_MONTGOMERY_KEY_PAIR_GEN advertised but {curve_name} "
                "keypair generation for X3DH setup is not operational",
            )
            raise  # unreachable

    detail = "; ".join(str(exc) for exc in curve_rejects)
    pytest.xfail(
        "CKM_EC_MONTGOMERY_KEY_PAIR_GEN advertised but neither X25519 nor X448 "
        f"keypair generation is available for X3DH setup: {detail}"
    )


def _derive_attrs() -> dict[int, Any]:
    return {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_VALUE_LEN: 32,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
    }


def _destroy_all(rs: Any, *handles: int) -> None:
    for handle in handles:
        if handle:
            destroy_quietly(rs.raw, rs.sh, handle)


class TestX3DH:
    """X3DH mechanism availability and consistency tests."""

    def test_x3dh_initialize_mechanism_check(self, p11_raw_session: Any) -> None:
        """CKM_X3DH_INITIALIZE is listed as a supported mechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("X3DH_INITIALIZE"):
            pytest.skip("CKM_X3DH_INITIALIZE not supported")
        # Module claims support - mechanism is present in the slot's list.
        assert rs.has_mechanism("X3DH_INITIALIZE")

    def test_x3dh_respond_mechanism_check(self, p11_raw_session: Any) -> None:
        """CKM_X3DH_RESPOND is listed as a supported mechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("X3DH_RESPOND"):
            pytest.skip("CKM_X3DH_RESPOND not supported")
        assert rs.has_mechanism("X3DH_RESPOND")

    def test_x3dh_both_sides_available(self, p11_raw_session: Any) -> None:
        """If X3DH_INITIALIZE is available, X3DH_RESPOND must also be present.

        A module that exposes only one side of the X3DH exchange is incomplete
        per the PKCS#11 spec - both mechanisms are required together.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("X3DH_INITIALIZE"):
            pytest.skip("CKM_X3DH_INITIALIZE not supported")
        assert rs.has_mechanism("X3DH_RESPOND"), (
            "Module supports CKM_X3DH_INITIALIZE but not CKM_X3DH_RESPOND"
        )

    def test_x3dh_respond_implies_initialize(self, p11_raw_session: Any) -> None:
        """If X3DH_RESPOND is available, X3DH_INITIALIZE must also be present.

        Symmetric counterpart to test_x3dh_both_sides_available.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("X3DH_RESPOND"):
            pytest.skip("CKM_X3DH_RESPOND not supported")
        assert rs.has_mechanism("X3DH_INITIALIZE"), (
            "Module supports CKM_X3DH_RESPOND but not CKM_X3DH_INITIALIZE"
        )

    def test_x3dh_initialize_derive_generic_secret(self, p11_raw_session: Any) -> None:
        """Initiator side reaches C_DeriveKey with CK_X3DH_INITIATE_PARAMS."""
        rs = p11_raw_session
        if not rs.has_mechanism("X3DH_INITIALIZE"):
            pytest.skip("CKM_X3DH_INITIALIZE not supported")

        own_identity_pub, own_identity_priv = _create_ec_keypair(rs)
        own_ephemeral_pub, own_ephemeral_priv = _create_ec_keypair(rs)
        peer_identity_pub, peer_identity_priv = _create_ec_keypair(rs)
        peer_prekey_pub, peer_prekey_priv = _create_ec_keypair(rs)
        derived = 0
        try:
            mech_param = _mech_x3dh_initialize(
                peer_identity=peer_identity_pub,
                peer_prekey=peer_prekey_pub,
                prekey_signature=b"pkcs11-check-x3dh-prekey-signature",
                onetime_key=None,
                own_identity=own_identity_priv,
                own_ephemeral=own_ephemeral_priv,
            )
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    own_identity_priv,
                    CKM_X3DH_INITIALIZE,
                    attrs=_derive_attrs(),
                    mech_param=mech_param,
                )
                assert derived != 0
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _X3DH_DERIVE_REJECT_RVS,
                    "CKM_X3DH_INITIALIZE advertised but derive is not operational",
                )
        finally:
            _destroy_all(
                rs,
                derived,
                own_identity_pub,
                own_identity_priv,
                own_ephemeral_pub,
                own_ephemeral_priv,
                peer_identity_pub,
                peer_identity_priv,
                peer_prekey_pub,
                peer_prekey_priv,
            )

    def test_x3dh_initialize_rejects_invalid_kdf(self, p11_raw_session: Any) -> None:
        """CKM_X3DH_INITIALIZE rejects KDF selectors outside the OASIS table."""
        rs = p11_raw_session
        if not rs.has_mechanism("X3DH_INITIALIZE"):
            pytest.skip("CKM_X3DH_INITIALIZE not supported")

        own_identity_pub, own_identity_priv = _create_ec_keypair(rs)
        own_ephemeral_pub, own_ephemeral_priv = _create_ec_keypair(rs)
        peer_identity_pub, peer_identity_priv = _create_ec_keypair(rs)
        peer_prekey_pub, peer_prekey_priv = _create_ec_keypair(rs)
        derived = 0
        try:
            exc: AssertionError | None = None
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    own_identity_priv,
                    CKM_X3DH_INITIALIZE,
                    attrs=_derive_attrs(),
                    mech_param=_mech_x3dh_initialize(
                        peer_identity=peer_identity_pub,
                        peer_prekey=peer_prekey_pub,
                        prekey_signature=b"pkcs11-check-x3dh-prekey-signature",
                        onetime_key=None,
                        own_identity=own_identity_priv,
                        own_ephemeral=own_ephemeral_priv,
                        kdf=_X3DH_INVALID_KDF,
                    ),
                )
            except AssertionError as caught:
                exc = caught
            reject_or_classify(
                exc,
                _X3DH_INVALID_KDF_REJECT_RVS,
                label="X3DH_INITIALIZE invalid KDF",
            )
        finally:
            _destroy_all(
                rs,
                derived,
                own_identity_pub,
                own_identity_priv,
                own_ephemeral_pub,
                own_ephemeral_priv,
                peer_identity_pub,
                peer_identity_priv,
                peer_prekey_pub,
                peer_prekey_priv,
            )

    def test_x3dh_respond_derive_generic_secret(self, p11_raw_session: Any) -> None:
        """Responder side reaches C_DeriveKey with CK_X3DH_RESPOND_PARAMS."""
        rs = p11_raw_session
        if not rs.has_mechanism("X3DH_RESPOND"):
            pytest.skip("CKM_X3DH_RESPOND not supported")

        responder_identity_pub, responder_identity_priv = _create_ec_keypair(rs)
        initiator_identity_pub, initiator_identity_priv = _create_ec_keypair(rs)
        derived = 0
        try:
            mech_param = _mech_x3dh_respond(
                identity_id=b"pkcs11-check-responder-identity",
                prekey_id=b"pkcs11-check-responder-prekey",
                onetime_id=None,
                initiator_identity=initiator_identity_pub,
                initiator_ephemeral=b"pkcs11-check-initiator-ephemeral",
            )
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    responder_identity_priv,
                    CKM_X3DH_RESPOND,
                    attrs=_derive_attrs(),
                    mech_param=mech_param,
                )
                assert derived != 0
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _X3DH_DERIVE_REJECT_RVS,
                    "CKM_X3DH_RESPOND advertised but derive is not operational",
                )
        finally:
            _destroy_all(
                rs,
                derived,
                responder_identity_pub,
                responder_identity_priv,
                initiator_identity_pub,
                initiator_identity_priv,
            )

    def test_x3dh_respond_rejects_invalid_kdf(self, p11_raw_session: Any) -> None:
        """CKM_X3DH_RESPOND rejects KDF selectors outside the OASIS table."""
        rs = p11_raw_session
        if not rs.has_mechanism("X3DH_RESPOND"):
            pytest.skip("CKM_X3DH_RESPOND not supported")

        responder_identity_pub, responder_identity_priv = _create_ec_keypair(rs)
        initiator_identity_pub, initiator_identity_priv = _create_ec_keypair(rs)
        derived = 0
        try:
            exc: AssertionError | None = None
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    responder_identity_priv,
                    CKM_X3DH_RESPOND,
                    attrs=_derive_attrs(),
                    mech_param=_mech_x3dh_respond(
                        identity_id=b"pkcs11-check-responder-identity",
                        prekey_id=b"pkcs11-check-responder-prekey",
                        onetime_id=None,
                        initiator_identity=initiator_identity_pub,
                        initiator_ephemeral=b"pkcs11-check-initiator-ephemeral",
                        kdf=_X3DH_INVALID_KDF,
                    ),
                )
            except AssertionError as caught:
                exc = caught
            reject_or_classify(
                exc,
                _X3DH_INVALID_KDF_REJECT_RVS,
                label="X3DH_RESPOND invalid KDF",
            )
        finally:
            _destroy_all(
                rs,
                derived,
                responder_identity_pub,
                responder_identity_priv,
                initiator_identity_pub,
                initiator_identity_priv,
            )
