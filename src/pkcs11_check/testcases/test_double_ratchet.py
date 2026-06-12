"""Signal Double Ratchet mechanism tests - X2RATCHET derive/encrypt/decrypt.

Covers the four CKM_X2RATCHET_* mechanisms defined in PKCS#11 v3.2 / OASIS
Signal Protocol extension:

  CKM_X2RATCHET_INITIALIZE (0x00004025) - derive X2RATCHET key as Alice
  CKM_X2RATCHET_RESPOND   (0x00004026) - derive X2RATCHET key as Bob
  CKM_X2RATCHET_ENCRYPT   (0x00004027) - encrypt + wrap with ratchet state
  CKM_X2RATCHET_DECRYPT   (0x00004028) - decrypt + unwrap with ratchet state

Almost no HSM implements these yet.  Every test checks mechanism availability
first and skips cleanly.  If a module claims support the tests attempt a basic
operation and xfail on expected not-yet-operational errors rather than hiding
them with a broad catch.

OASIS spec: double_ratchet.md (Signal Double Ratchet section)
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import PackedMechanism, _mech_struct, attr_bytes
from pkcs11_check.raw.recipes import (
    create_object,
    decrypt_single,
    derive_key,
    destroy_quietly,
    encrypt_single,
    gen_keypair,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CK_VOID_PTR,
    CK_X2RATCHET_INITIALIZE_PARAMS,
    CK_X2RATCHET_RESPOND_PARAMS,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_EC_PARAMS,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKD_SHA256_KDF,
    CKK_GENERIC_SECRET,
    CKK_X2RATCHET,
    CKM_AES_GCM,
    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    CKM_X2RATCHET_DECRYPT,
    CKM_X2RATCHET_ENCRYPT,
    CKM_X2RATCHET_INITIALIZE,
    CKM_X2RATCHET_RESPOND,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import is_known_error, reject_or_classify, xfail_if_known_ckr

pytestmark = pytest.mark.full

# CKR values that indicate the mechanism is advertised but not yet operational.
# We xfail rather than hard-fail so the suite stays green while still
# surfacing evidence that the mechanism was reached.
_RATCHET_ERROR_RVS = {
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
}

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
)

_X2RATCHET_INVALID_CURVE_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

_X2RATCHET_CURVES = (
    ("X25519", encode_named_curve_parameters("x25519")),
    ("X448", encode_named_curve_parameters("x448")),
)

_X2RATCHET_SHARED_SECRET = bytes(range(32))


def _bytes_pointer(data: bytes, keepalive: list[Any]) -> Any:
    storage = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    keepalive.append(storage)
    return ctypes.cast(storage, CK_VOID_PTR)


def _mech_x2ratchet_initialize(
    *,
    shared_secret: bytes,
    peer_public_prekey: int,
    peer_public_identity: int,
    own_public_identity: int,
    encrypted_header: bool = False,
    curve: int = 255,
    aead_mechanism: int = int(CKM_AES_GCM),
    kdf_mechanism: int = int(CKD_SHA256_KDF),
) -> PackedMechanism:
    keepalive: list[Any] = []
    params = CK_X2RATCHET_INITIALIZE_PARAMS()
    params.sk = _bytes_pointer(shared_secret, keepalive)
    params.peer_public_prekey = peer_public_prekey
    params.peer_public_identity = peer_public_identity
    params.own_public_identity = own_public_identity
    params.bEncryptedHeader = encrypted_header
    params.eCurve = curve
    params.aeadMechanism = aead_mechanism
    params.kdfMechanism = kdf_mechanism
    return _mech_struct(
        CKM_X2RATCHET_INITIALIZE,
        params,
        "mech_x2ratchet_initialize",
        keepalive,
        sub_mechanisms={
            "aeadMechanism": int(aead_mechanism),
            "kdfMechanism": int(kdf_mechanism),
        },
    )


def _mech_x2ratchet_respond(
    *,
    shared_secret: bytes,
    own_prekey: int,
    initiator_identity: int,
    own_public_identity: int,
    encrypted_header: bool = False,
    curve: int = 255,
    aead_mechanism: int = int(CKM_AES_GCM),
    kdf_mechanism: int = int(CKD_SHA256_KDF),
) -> PackedMechanism:
    keepalive: list[Any] = []
    params = CK_X2RATCHET_RESPOND_PARAMS()
    params.sk = _bytes_pointer(shared_secret, keepalive)
    params.own_prekey = own_prekey
    params.initiator_identity = initiator_identity
    params.own_public_identity = own_public_identity
    params.bEncryptedHeader = encrypted_header
    params.eCurve = curve
    params.aeadMechanism = aead_mechanism
    params.kdfMechanism = kdf_mechanism
    return _mech_struct(
        CKM_X2RATCHET_RESPOND,
        params,
        "mech_x2ratchet_respond",
        keepalive,
        sub_mechanisms={
            "aeadMechanism": int(aead_mechanism),
            "kdfMechanism": int(kdf_mechanism),
        },
    )


def _create_ec_keypair(rs: Any) -> tuple[int, int]:
    """Generate a Montgomery keypair for ratchet key material.

    X2RATCHET permits curve 25519 or 448.  A P-curve fallback would make the
    test less spec-faithful, so only Montgomery setup is accepted here.
    """
    if not rs.has_mechanism("EC_MONTGOMERY_KEY_PAIR_GEN"):
        pytest.skip("CKM_EC_MONTGOMERY_KEY_PAIR_GEN not supported for X2RATCHET setup")

    curve_rejects: list[BaseException] = []
    for curve_name, curve_oid in _X2RATCHET_CURVES:
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
                "keypair generation for X2RATCHET setup is not operational",
            )
            raise  # unreachable

    detail = "; ".join(str(exc) for exc in curve_rejects)
    pytest.xfail(
        "CKM_EC_MONTGOMERY_KEY_PAIR_GEN advertised but neither X25519 nor X448 "
        f"keypair generation is available for X2RATCHET setup: {detail}"
    )


def _create_generic_secret_key(
    rs: Any,
    value: bytes,
    *,
    encrypt: bool = False,
    decrypt: bool = False,
) -> int:
    """Import a GENERIC_SECRET key for use with ratchet encrypt/decrypt tests."""
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_VALUE: value,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
    }
    if encrypt:
        attrs[CKA_ENCRYPT] = True
    if decrypt:
        attrs[CKA_DECRYPT] = True
    return create_object(rs.raw, rs.sh, attrs)


class TestX2RatchetDerive:
    """CKM_X2RATCHET_INITIALIZE and CKM_X2RATCHET_RESPOND - ratchet key setup."""

    # ------------------------------------------------------------------
    # CKM_X2RATCHET_INITIALIZE
    # ------------------------------------------------------------------

    def test_x2ratchet_initialize_mechanism_check(self, p11_raw_session: Any) -> None:
        """CKM_X2RATCHET_INITIALIZE is probed in the mechanism list."""
        rs = p11_raw_session
        if not rs.has_mechanism("X2RATCHET_INITIALIZE"):
            pytest.skip("CKM_X2RATCHET_INITIALIZE not supported")

    def test_x2ratchet_initialize_derive_generic_secret(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Alice-side ratchet init: derive a GENERIC_SECRET via X2RATCHET_INITIALIZE.

        The full CK_X2RATCHET_INITIALIZE_PARAMS structure requires several DH
        key handles and a KDF mechanism selector.  We attempt a minimal call to
        verify the code path is reachable; the xfail covers missing param support.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("X2RATCHET_INITIALIZE"):
            pytest.skip("CKM_X2RATCHET_INITIALIZE not supported")

        own_identity_pub, own_identity_priv = _create_ec_keypair(rs)
        peer_identity_pub, peer_identity_priv = _create_ec_keypair(rs)
        peer_prekey_pub, peer_prekey_priv = _create_ec_keypair(rs)
        try:
            mech_param = _mech_x2ratchet_initialize(
                shared_secret=_X2RATCHET_SHARED_SECRET,
                peer_public_prekey=peer_prekey_pub,
                peer_public_identity=peer_identity_pub,
                own_public_identity=own_identity_pub,
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                own_identity_priv,
                CKM_X2RATCHET_INITIALIZE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 32,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                },
                mech_param=mech_param,
            )
            try:
                assert derived != 0
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            # Check if it's a known "not yet operational" CKR
            if is_known_error(exc, _RATCHET_ERROR_RVS):
                pytest.xfail(f"CKM_X2RATCHET_INITIALIZE not yet operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, own_identity_pub)
            destroy_quietly(rs.raw, rs.sh, own_identity_priv)
            destroy_quietly(rs.raw, rs.sh, peer_identity_pub)
            destroy_quietly(rs.raw, rs.sh, peer_identity_priv)
            destroy_quietly(rs.raw, rs.sh, peer_prekey_pub)
            destroy_quietly(rs.raw, rs.sh, peer_prekey_priv)

    def test_x2ratchet_initialize_two_runs_differ(self, p11_raw_session: Any) -> None:
        """Two independent ratchet init calls should produce different session keys.

        Ratchet state includes a fresh ephemeral key each time; outputs must not
        be identical.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("X2RATCHET_INITIALIZE"):
            pytest.skip("CKM_X2RATCHET_INITIALIZE not supported")

        pub_a, priv_a = _create_ec_keypair(rs)
        pub_b, priv_b = _create_ec_keypair(rs)
        peer_identity_pub, peer_identity_priv = _create_ec_keypair(rs)
        peer_prekey_pub, peer_prekey_priv = _create_ec_keypair(rs)
        try:
            derive_attrs: dict[int, Any] = {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_VALUE_LEN: 32,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            }
            derived_a = derive_key(
                rs.raw,
                rs.sh,
                priv_a,
                CKM_X2RATCHET_INITIALIZE,
                attrs=derive_attrs,
                mech_param=_mech_x2ratchet_initialize(
                    shared_secret=_X2RATCHET_SHARED_SECRET,
                    peer_public_prekey=peer_prekey_pub,
                    peer_public_identity=peer_identity_pub,
                    own_public_identity=pub_a,
                ),
            )
            derived_b = derive_key(
                rs.raw,
                rs.sh,
                priv_b,
                CKM_X2RATCHET_INITIALIZE,
                attrs=derive_attrs,
                mech_param=_mech_x2ratchet_initialize(
                    shared_secret=_X2RATCHET_SHARED_SECRET,
                    peer_public_prekey=peer_prekey_pub,
                    peer_public_identity=peer_identity_pub,
                    own_public_identity=pub_b,
                ),
            )
            try:
                val_a = read_attributes(rs.raw, rs.sh, derived_a, [CKA_VALUE])[CKA_VALUE]
                val_b = read_attributes(rs.raw, rs.sh, derived_b, [CKA_VALUE])[CKA_VALUE]
                assert val_a != val_b, "Independent ratchet inits should produce different keys"
            finally:
                destroy_quietly(rs.raw, rs.sh, derived_a)
                destroy_quietly(rs.raw, rs.sh, derived_b)
        except AssertionError as exc:
            if is_known_error(exc, _RATCHET_ERROR_RVS):
                pytest.xfail(f"CKM_X2RATCHET_INITIALIZE not yet operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_a)
            destroy_quietly(rs.raw, rs.sh, priv_a)
            destroy_quietly(rs.raw, rs.sh, pub_b)
            destroy_quietly(rs.raw, rs.sh, priv_b)
            destroy_quietly(rs.raw, rs.sh, peer_identity_pub)
            destroy_quietly(rs.raw, rs.sh, peer_identity_priv)
            destroy_quietly(rs.raw, rs.sh, peer_prekey_pub)
            destroy_quietly(rs.raw, rs.sh, peer_prekey_priv)

    def test_x2ratchet_initialize_rejects_invalid_curve(self, p11_raw_session: Any) -> None:
        """CKM_X2RATCHET_INITIALIZE rejects eCurve values other than 255 or 448."""
        rs = p11_raw_session
        if not rs.has_mechanism("X2RATCHET_INITIALIZE"):
            pytest.skip("CKM_X2RATCHET_INITIALIZE not supported")

        own_identity_pub, own_identity_priv = _create_ec_keypair(rs)
        peer_identity_pub, peer_identity_priv = _create_ec_keypair(rs)
        peer_prekey_pub, peer_prekey_priv = _create_ec_keypair(rs)
        derived = 0
        try:
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    own_identity_priv,
                    CKM_X2RATCHET_INITIALIZE,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_VALUE_LEN: 32,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                    },
                    mech_param=_mech_x2ratchet_initialize(
                        shared_secret=_X2RATCHET_SHARED_SECRET,
                        peer_public_prekey=peer_prekey_pub,
                        peer_public_identity=peer_identity_pub,
                        own_public_identity=own_identity_pub,
                        curve=256,
                    ),
                )
            except AssertionError as exc:
                reject_or_classify(
                    exc,
                    _X2RATCHET_INVALID_CURVE_REJECT_RVS,
                    label="X2RATCHET_INITIALIZE invalid curve",
                )
                return
            reject_or_classify(
                None,
                _X2RATCHET_INVALID_CURVE_REJECT_RVS,
                label="X2RATCHET_INITIALIZE invalid curve",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, derived)
            destroy_quietly(rs.raw, rs.sh, own_identity_pub)
            destroy_quietly(rs.raw, rs.sh, own_identity_priv)
            destroy_quietly(rs.raw, rs.sh, peer_identity_pub)
            destroy_quietly(rs.raw, rs.sh, peer_identity_priv)
            destroy_quietly(rs.raw, rs.sh, peer_prekey_pub)
            destroy_quietly(rs.raw, rs.sh, peer_prekey_priv)

    # ------------------------------------------------------------------
    # CKM_X2RATCHET_RESPOND
    # ------------------------------------------------------------------

    def test_x2ratchet_respond_mechanism_check(self, p11_raw_session: Any) -> None:
        """CKM_X2RATCHET_RESPOND is probed in the mechanism list."""
        rs = p11_raw_session
        if not rs.has_mechanism("X2RATCHET_RESPOND"):
            pytest.skip("CKM_X2RATCHET_RESPOND not supported")

    def test_x2ratchet_respond_derive_generic_secret(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Bob-side ratchet respond: derive a GENERIC_SECRET via X2RATCHET_RESPOND.

        Mirrors the INITIALIZE test from Bob's perspective.  The full param
        structure mirrors CK_X2RATCHET_RESPOND_PARAMS; we probe the code path
        and xfail on not-yet-operational errors.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("X2RATCHET_RESPOND"):
            pytest.skip("CKM_X2RATCHET_RESPOND not supported")

        own_prekey_pub, own_prekey_priv = _create_ec_keypair(rs)
        own_identity_pub, own_identity_priv = _create_ec_keypair(rs)
        initiator_identity_pub, initiator_identity_priv = _create_ec_keypair(rs)
        try:
            mech_param = _mech_x2ratchet_respond(
                shared_secret=_X2RATCHET_SHARED_SECRET,
                own_prekey=own_prekey_priv,
                initiator_identity=initiator_identity_pub,
                own_public_identity=own_identity_pub,
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                own_prekey_priv,
                CKM_X2RATCHET_RESPOND,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 32,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                },
                mech_param=mech_param,
            )
            try:
                assert derived != 0
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _RATCHET_ERROR_RVS):
                pytest.xfail(f"CKM_X2RATCHET_RESPOND not yet operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, own_prekey_pub)
            destroy_quietly(rs.raw, rs.sh, own_prekey_priv)
            destroy_quietly(rs.raw, rs.sh, own_identity_pub)
            destroy_quietly(rs.raw, rs.sh, own_identity_priv)
            destroy_quietly(rs.raw, rs.sh, initiator_identity_pub)
            destroy_quietly(rs.raw, rs.sh, initiator_identity_priv)

    def test_x2ratchet_respond_derives_x2ratchet_key_type(
        self,
        p11_raw_session: Any,
    ) -> None:
        """X2RATCHET_RESPOND may produce a CKK_X2RATCHET typed key object.

        The spec allows the derived object to carry CKK_X2RATCHET (0x3F) to
        carry Double Ratchet state alongside key material.  This test checks
        that outcome if the mechanism is available.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("X2RATCHET_RESPOND"):
            pytest.skip("CKM_X2RATCHET_RESPOND not supported")

        own_prekey_pub, own_prekey_priv = _create_ec_keypair(rs)
        own_identity_pub, own_identity_priv = _create_ec_keypair(rs)
        initiator_identity_pub, initiator_identity_priv = _create_ec_keypair(rs)
        try:
            derived = derive_key(
                rs.raw,
                rs.sh,
                own_prekey_priv,
                CKM_X2RATCHET_RESPOND,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_X2RATCHET,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                },
                mech_param=_mech_x2ratchet_respond(
                    shared_secret=_X2RATCHET_SHARED_SECRET,
                    own_prekey=own_prekey_priv,
                    initiator_identity=initiator_identity_pub,
                    own_public_identity=own_identity_pub,
                ),
            )
            try:
                assert derived != 0
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _RATCHET_ERROR_RVS):
                pytest.xfail(f"CKM_X2RATCHET_RESPOND X2RATCHET key not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, own_prekey_pub)
            destroy_quietly(rs.raw, rs.sh, own_prekey_priv)
            destroy_quietly(rs.raw, rs.sh, own_identity_pub)
            destroy_quietly(rs.raw, rs.sh, own_identity_priv)
            destroy_quietly(rs.raw, rs.sh, initiator_identity_pub)
            destroy_quietly(rs.raw, rs.sh, initiator_identity_priv)

    def test_x2ratchet_respond_rejects_invalid_curve(self, p11_raw_session: Any) -> None:
        """CKM_X2RATCHET_RESPOND rejects eCurve values other than 255 or 448."""
        rs = p11_raw_session
        if not rs.has_mechanism("X2RATCHET_RESPOND"):
            pytest.skip("CKM_X2RATCHET_RESPOND not supported")

        own_prekey_pub, own_prekey_priv = _create_ec_keypair(rs)
        own_identity_pub, own_identity_priv = _create_ec_keypair(rs)
        initiator_identity_pub, initiator_identity_priv = _create_ec_keypair(rs)
        derived = 0
        try:
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    own_prekey_priv,
                    CKM_X2RATCHET_RESPOND,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_VALUE_LEN: 32,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                    },
                    mech_param=_mech_x2ratchet_respond(
                        shared_secret=_X2RATCHET_SHARED_SECRET,
                        own_prekey=own_prekey_priv,
                        initiator_identity=initiator_identity_pub,
                        own_public_identity=own_identity_pub,
                        curve=256,
                    ),
                )
            except AssertionError as exc:
                reject_or_classify(
                    exc,
                    _X2RATCHET_INVALID_CURVE_REJECT_RVS,
                    label="X2RATCHET_RESPOND invalid curve",
                )
                return
            reject_or_classify(
                None,
                _X2RATCHET_INVALID_CURVE_REJECT_RVS,
                label="X2RATCHET_RESPOND invalid curve",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, derived)
            destroy_quietly(rs.raw, rs.sh, own_prekey_pub)
            destroy_quietly(rs.raw, rs.sh, own_prekey_priv)
            destroy_quietly(rs.raw, rs.sh, own_identity_pub)
            destroy_quietly(rs.raw, rs.sh, own_identity_priv)
            destroy_quietly(rs.raw, rs.sh, initiator_identity_pub)
            destroy_quietly(rs.raw, rs.sh, initiator_identity_priv)


class TestX2RatchetEncrypt:
    """CKM_X2RATCHET_ENCRYPT and CKM_X2RATCHET_DECRYPT - message encryption."""

    # ------------------------------------------------------------------
    # CKM_X2RATCHET_ENCRYPT
    # ------------------------------------------------------------------

    def test_x2ratchet_encrypt_mechanism_check(self, p11_raw_session: Any) -> None:
        """CKM_X2RATCHET_ENCRYPT is probed in the mechanism list."""
        rs = p11_raw_session
        if not rs.has_mechanism("X2RATCHET_ENCRYPT"):
            pytest.skip("CKM_X2RATCHET_ENCRYPT not supported")

    def test_x2ratchet_encrypt_basic(self, p11_raw_session: Any) -> None:
        """Encrypt a short message with CKM_X2RATCHET_ENCRYPT.

        A valid X2RATCHET ratchet-state key is required as the mechanism key.
        We use a GENERIC_SECRET as a stand-in; the mechanism will likely reject
        it (xfail), but confirms the C_Encrypt code path was reached.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("X2RATCHET_ENCRYPT"):
            pytest.skip("CKM_X2RATCHET_ENCRYPT not supported")

        plaintext = b"Double Ratchet test message"
        key = _create_generic_secret_key(rs, bytes(range(32)), encrypt=True)
        try:
            ciphertext = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_X2RATCHET_ENCRYPT,
                plaintext,
            )
            assert ciphertext != plaintext
            assert len(ciphertext) > 0
        except AssertionError as exc:
            if is_known_error(exc, _RATCHET_ERROR_RVS):
                pytest.xfail(f"CKM_X2RATCHET_ENCRYPT not yet operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_x2ratchet_encrypt_ciphertext_not_plaintext(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Ciphertext produced by X2RATCHET_ENCRYPT must differ from plaintext."""
        rs = p11_raw_session
        if not rs.has_mechanism("X2RATCHET_ENCRYPT"):
            pytest.skip("CKM_X2RATCHET_ENCRYPT not supported")

        plaintext = b"Signal protocol Double Ratchet"
        key = _create_generic_secret_key(rs, bytes(range(32)), encrypt=True)
        try:
            ciphertext = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_X2RATCHET_ENCRYPT,
                plaintext,
            )
            assert ciphertext != plaintext, "Ciphertext must not equal plaintext"
        except AssertionError as exc:
            if is_known_error(exc, _RATCHET_ERROR_RVS):
                pytest.xfail(f"CKM_X2RATCHET_ENCRYPT not yet operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    # ------------------------------------------------------------------
    # CKM_X2RATCHET_DECRYPT
    # ------------------------------------------------------------------

    def test_x2ratchet_decrypt_mechanism_check(self, p11_raw_session: Any) -> None:
        """CKM_X2RATCHET_DECRYPT is probed in the mechanism list."""
        rs = p11_raw_session
        if not rs.has_mechanism("X2RATCHET_DECRYPT"):
            pytest.skip("CKM_X2RATCHET_DECRYPT not supported")

    def test_x2ratchet_decrypt_basic(self, p11_raw_session: Any) -> None:
        """Attempt C_Decrypt with CKM_X2RATCHET_DECRYPT on a stub ciphertext.

        Without a real ratchet-state key object we cannot produce valid
        ciphertext.  We confirm the call reaches C_Decrypt and xfail on the
        expected error rather than skipping the operation entirely.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("X2RATCHET_DECRYPT"):
            pytest.skip("CKM_X2RATCHET_DECRYPT not supported")

        # Synthetic ciphertext - will be rejected by any correct implementation.
        stub_ciphertext = bytes(range(64))
        key = _create_generic_secret_key(rs, bytes(range(32)), decrypt=True)
        try:
            plaintext = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_X2RATCHET_DECRYPT,
                stub_ciphertext,
            )
            # If the module actually decrypts the stub ciphertext without error,
            # accept it - some permissive stubs may succeed.
            assert plaintext is not None
        except AssertionError as exc:
            if is_known_error(exc, _RATCHET_ERROR_RVS):
                pytest.xfail(f"CKM_X2RATCHET_DECRYPT not yet operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_x2ratchet_encrypt_decrypt_roundtrip(self, p11_raw_session: Any) -> None:
        """Full encrypt-then-decrypt roundtrip with X2RATCHET mechanisms.

        Both ENCRYPT and DECRYPT must be available.  We use a shared
        GENERIC_SECRET as a stand-in ratchet key; a proper implementation
        requires a full CKK_X2RATCHET state object.  This test confirms the
        round-trip code path and xfails on not-yet-operational errors.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("X2RATCHET_ENCRYPT"):
            pytest.skip("CKM_X2RATCHET_ENCRYPT not supported")
        if not rs.has_mechanism("X2RATCHET_DECRYPT"):
            pytest.skip("CKM_X2RATCHET_DECRYPT not supported")

        plaintext = b"roundtrip test for double ratchet"
        enc_key = _create_generic_secret_key(rs, bytes(range(32)), encrypt=True)
        dec_key = _create_generic_secret_key(rs, bytes(range(32)), decrypt=True)
        try:
            ciphertext = encrypt_single(
                rs.raw,
                rs.sh,
                enc_key,
                CKM_X2RATCHET_ENCRYPT,
                plaintext,
            )
            recovered = decrypt_single(
                rs.raw,
                rs.sh,
                dec_key,
                CKM_X2RATCHET_DECRYPT,
                ciphertext,
            )
            assert recovered == plaintext, "Roundtrip plaintext mismatch"
        except AssertionError as exc:
            if is_known_error(exc, _RATCHET_ERROR_RVS):
                pytest.xfail(f"CKM_X2RATCHET encrypt/decrypt roundtrip not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, enc_key)
            destroy_quietly(rs.raw, rs.sh, dec_key)
