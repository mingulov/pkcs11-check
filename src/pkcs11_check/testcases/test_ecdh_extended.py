"""Tests for extended ECDH/EC mechanisms.

Covers CKM_ECDH1_COFACTOR_DERIVE, CKM_ECMQV_DERIVE, CKM_XEDDSA,
and CKM_EC_MONTGOMERY_KEY_PAIR_GEN.

Basic CKM_ECDH1_DERIVE is tested in test_kdf.py.

OASIS spec: elliptic_curves.md
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import (
    FunctionFailed,
    FunctionNotSupported,
    MechanismInvalid,
    MechanismParamInvalid,
)
from pkcs11.mechanisms import KDF

from pkcs11_check.testcases.conftest import extract_ec_point, has_mechanism

pytestmark = pytest.mark.keymgmt

# OIDs for Montgomery curves (DER-encoded OID)
_X25519_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x6E])  # 1.3.101.110
_X448_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x6F])  # 1.3.101.111


def _generate_ec_keypair(session: Any, curve: str = "secp256r1") -> tuple[Any, Any]:
    """Generate an EC keypair on the given curve."""
    ecparams = session.create_domain_parameters(
        KeyType.EC,
        {p11.Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters(curve)},
        local=True,
    )
    return ecparams.generate_keypair()  # type: ignore[no-any-return]


class TestECDH1CofactorDerive:
    """CKM_ECDH1_COFACTOR_DERIVE - ECDH with cofactor multiplication.

    For secp256r1 (cofactor=1), the result should match CKM_ECDH1_DERIVE.
    Uses the same CK_ECDH1_DERIVE_PARAMS structure as ECDH1_DERIVE.
    """

    def test_cofactor_derive_shared_secret(self, p11_session: Any, p11_module: Any) -> None:
        """Two parties derive the same shared secret via cofactor ECDH."""
        if not has_mechanism(p11_module, "ECDH1_COFACTOR_DERIVE"):
            pytest.skip("CKM_ECDH1_COFACTOR_DERIVE not supported")

        pub_a, priv_a = _generate_ec_keypair(p11_session)
        pub_b, priv_b = _generate_ec_keypair(p11_session)
        try:
            point_a = extract_ec_point(pub_a[Attribute.EC_POINT])
            point_b = extract_ec_point(pub_b[Attribute.EC_POINT])

            derive_tmpl = {
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            }

            shared_ab = priv_a.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.ECDH1_COFACTOR_DERIVE,
                mechanism_param=(KDF.NULL, None, point_b),
                template=derive_tmpl,
            )
            try:
                shared_ba = priv_b.derive_key(
                    KeyType.GENERIC_SECRET,
                    256,
                    mechanism=Mechanism.ECDH1_COFACTOR_DERIVE,
                    mechanism_param=(KDF.NULL, None, point_a),
                    template=derive_tmpl,
                )
                try:
                    assert shared_ab[Attribute.VALUE] == shared_ba[Attribute.VALUE]
                finally:
                    shared_ba.destroy()
            finally:
                shared_ab.destroy()
        finally:
            priv_a.destroy()
            pub_a.destroy()
            priv_b.destroy()
            pub_b.destroy()

    def test_cofactor_matches_standard_ecdh(self, p11_session: Any, p11_module: Any) -> None:
        """For secp256r1 (cofactor=1), cofactor derive == standard derive."""
        if not has_mechanism(p11_module, "ECDH1_COFACTOR_DERIVE"):
            pytest.skip("CKM_ECDH1_COFACTOR_DERIVE not supported")
        if not has_mechanism(p11_module, "ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        pub_a, priv_a = _generate_ec_keypair(p11_session)
        pub_b, priv_b = _generate_ec_keypair(p11_session)
        try:
            point_b = extract_ec_point(pub_b[Attribute.EC_POINT])

            derive_tmpl = {
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            }

            shared_standard = priv_a.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.ECDH1_DERIVE,
                mechanism_param=(KDF.NULL, None, point_b),
                template=derive_tmpl,
            )
            try:
                shared_cofactor = priv_a.derive_key(
                    KeyType.GENERIC_SECRET,
                    256,
                    mechanism=Mechanism.ECDH1_COFACTOR_DERIVE,
                    mechanism_param=(KDF.NULL, None, point_b),
                    template=derive_tmpl,
                )
                try:
                    # secp256r1 has cofactor=1 so results must match
                    assert shared_standard[Attribute.VALUE] == shared_cofactor[Attribute.VALUE]
                finally:
                    shared_cofactor.destroy()
            finally:
                shared_standard.destroy()
        finally:
            priv_a.destroy()
            pub_a.destroy()
            priv_b.destroy()
            pub_b.destroy()

    def test_cofactor_different_peers_different_secrets(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Cofactor ECDH with different peers yields different secrets."""
        if not has_mechanism(p11_module, "ECDH1_COFACTOR_DERIVE"):
            pytest.skip("CKM_ECDH1_COFACTOR_DERIVE not supported")

        _, priv_a = _generate_ec_keypair(p11_session)
        pub_b, _ = _generate_ec_keypair(p11_session)
        pub_c, _ = _generate_ec_keypair(p11_session)
        try:
            point_b = extract_ec_point(pub_b[Attribute.EC_POINT])
            point_c = extract_ec_point(pub_c[Attribute.EC_POINT])

            derive_tmpl = {
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            }

            shared_ab = priv_a.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.ECDH1_COFACTOR_DERIVE,
                mechanism_param=(KDF.NULL, None, point_b),
                template=derive_tmpl,
            )
            try:
                shared_ac = priv_a.derive_key(
                    KeyType.GENERIC_SECRET,
                    256,
                    mechanism=Mechanism.ECDH1_COFACTOR_DERIVE,
                    mechanism_param=(KDF.NULL, None, point_c),
                    template=derive_tmpl,
                )
                try:
                    assert shared_ab[Attribute.VALUE] != shared_ac[Attribute.VALUE]
                finally:
                    shared_ac.destroy()
            finally:
                shared_ab.destroy()
        finally:
            priv_a.destroy()
            pub_b.destroy()
            pub_c.destroy()

    def test_cofactor_derive_as_aes_key(self, p11_session: Any, p11_module: Any) -> None:
        """Cofactor ECDH can derive an AES key directly."""
        if not has_mechanism(p11_module, "ECDH1_COFACTOR_DERIVE"):
            pytest.skip("CKM_ECDH1_COFACTOR_DERIVE not supported")

        pub_a, priv_a = _generate_ec_keypair(p11_session)
        pub_b, _ = _generate_ec_keypair(p11_session)
        try:
            point_b = extract_ec_point(pub_b[Attribute.EC_POINT])

            aes_tmpl = {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE_LEN: 32,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            }

            try:
                derived = priv_a.derive_key(
                    KeyType.AES,
                    256,
                    mechanism=Mechanism.ECDH1_COFACTOR_DERIVE,
                    mechanism_param=(KDF.NULL, None, point_b),
                    template=aes_tmpl,
                )
            except (MechanismInvalid, FunctionFailed, MechanismParamInvalid) as exc:
                pytest.skip(f"Cofactor ECDH cannot derive AES key: {type(exc).__name__}: {exc}")
            else:
                try:
                    assert derived[Attribute.KEY_TYPE] is KeyType.AES
                    assert len(derived[Attribute.VALUE]) == 32
                finally:
                    derived.destroy()
        finally:
            priv_a.destroy()
            pub_a.destroy()
            pub_b.destroy()


class TestECMQVDerive:
    """CKM_ECMQV_DERIVE - EC Menter-Qu-Vanstone key agreement.

    Requires two keypairs per party (static + ephemeral).
    Very rarely supported by PKCS#11 modules.
    """

    def test_ecmqv_mechanism_listed(self, p11_module: Any) -> None:
        """Check if CKM_ECMQV_DERIVE is in the mechanism list."""
        if not has_mechanism(p11_module, "ECMQV_DERIVE"):
            pytest.skip("CKM_ECMQV_DERIVE not supported")
        # If we get here, mechanism is listed - that alone is noteworthy

    def test_ecmqv_derive(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt ECMQV key agreement with two keypairs per party.

        ECMQV requires CK_ECMQV_DERIVE_PARAMS which needs:
        - kdf, shared data, public data (from peer's ephemeral public key),
        - peer's static public key handle, and own ephemeral private key handle.

        This mechanism is extremely rare. The test verifies it at least
        accepts the call or returns a reasonable error.
        """
        if not has_mechanism(p11_module, "ECMQV_DERIVE"):
            pytest.skip("CKM_ECMQV_DERIVE not supported")

        # ECMQV requires complex params (CK_ECMQV_DERIVE_PARAMS) not easily
        # constructible through python-pkcs11's high-level API. We verify the
        # mechanism is listed but expect the derive call to fail with a
        # parameter error since python-pkcs11 does not have native ECMQV
        # parameter marshalling.
        pub_a_static, priv_a_static = _generate_ec_keypair(p11_session)
        pub_b_static, priv_b_static = _generate_ec_keypair(p11_session)
        try:
            point_b = extract_ec_point(pub_b_static[Attribute.EC_POINT])

            derive_tmpl = {
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            }

            # Attempt derive - expect failure due to missing ECMQV param support
            try:
                shared = priv_a_static.derive_key(
                    KeyType.GENERIC_SECRET,
                    256,
                    mechanism=Mechanism.ECMQV_DERIVE,
                    mechanism_param=(KDF.NULL, None, point_b),
                    template=derive_tmpl,
                )
            except (
                MechanismInvalid,
                MechanismParamInvalid,
                FunctionFailed,
                FunctionNotSupported,
            ) as exc:
                pytest.xfail(f"ECMQV derive not operational: {type(exc).__name__}: {exc}")
            else:
                # Unlikely to succeed, but if it does, verify and clean up
                try:
                    assert shared[Attribute.VALUE] is not None
                finally:
                    shared.destroy()
        finally:
            priv_a_static.destroy()
            pub_a_static.destroy()
            priv_b_static.destroy()
            pub_b_static.destroy()


class TestXEdDSA:
    """CKM_XEDDSA - XEdDSA sign/verify on Montgomery curve keys.

    Uses X25519 (Montgomery) keys for EdDSA-compatible signing.
    Very rarely supported.
    """

    def test_xeddsa_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """Sign and verify using XEdDSA on a Montgomery (X25519) key."""
        if not has_mechanism(p11_module, "XEDDSA"):
            pytest.skip("CKM_XEDDSA not supported")
        if not has_mechanism(p11_module, "EC_MONTGOMERY_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_MONTGOMERY_KEY_PAIR_GEN not supported for XEdDSA keygen")

        pub, priv = p11_session.generate_keypair(
            KeyType.EC_MONTGOMERY,
            mechanism=Mechanism.EC_MONTGOMERY_KEY_PAIR_GEN,
            mechanism_param=None,
            template={
                Attribute.EC_PARAMS: _X25519_OID,
                Attribute.TOKEN: False,
            },
            public_template={},
            private_template={
                Attribute.SIGN: True,
                Attribute.SENSITIVE: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            data = b"XEdDSA test message for signing"
            try:
                # XEdDSA param is the hash type; 0 = SHA-512 per spec
                sig = priv.sign(data, mechanism=Mechanism.XEDDSA, mechanism_param=0)
            except (
                MechanismInvalid,
                MechanismParamInvalid,
                FunctionFailed,
                FunctionNotSupported,
            ) as exc:
                pytest.xfail(f"XEdDSA sign not operational: {type(exc).__name__}: {exc}")
            else:
                assert len(sig) > 0
                # Verify the signature
                try:
                    pub.verify(data, sig, mechanism=Mechanism.XEDDSA, mechanism_param=0)
                except (
                    MechanismInvalid,
                    MechanismParamInvalid,
                    FunctionFailed,
                    FunctionNotSupported,
                ) as exc:
                    pytest.xfail(f"XEdDSA verify not operational: {type(exc).__name__}: {exc}")
        finally:
            priv.destroy()
            pub.destroy()

    def test_xeddsa_bad_signature_rejected(self, p11_session: Any, p11_module: Any) -> None:
        """XEdDSA verify rejects a corrupted signature."""
        if not has_mechanism(p11_module, "XEDDSA"):
            pytest.skip("CKM_XEDDSA not supported")
        if not has_mechanism(p11_module, "EC_MONTGOMERY_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_MONTGOMERY_KEY_PAIR_GEN not supported for XEdDSA keygen")

        pub, priv = p11_session.generate_keypair(
            KeyType.EC_MONTGOMERY,
            mechanism=Mechanism.EC_MONTGOMERY_KEY_PAIR_GEN,
            mechanism_param=None,
            template={
                Attribute.EC_PARAMS: _X25519_OID,
                Attribute.TOKEN: False,
            },
            public_template={},
            private_template={
                Attribute.SIGN: True,
                Attribute.SENSITIVE: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            data = b"XEdDSA bad signature test"
            try:
                sig = priv.sign(data, mechanism=Mechanism.XEDDSA, mechanism_param=0)
            except (
                MechanismInvalid,
                MechanismParamInvalid,
                FunctionFailed,
                FunctionNotSupported,
            ) as exc:
                pytest.xfail(f"XEdDSA sign not operational: {type(exc).__name__}: {exc}")
            else:
                # Corrupt the signature
                bad_sig_arr = bytearray(sig)
                bad_sig_arr[0] ^= 0xFF
                bad_sig = bytes(bad_sig_arr)

                from pkcs11.exceptions import SignatureInvalid

                try:
                    pub.verify(data, bad_sig, mechanism=Mechanism.XEDDSA, mechanism_param=0)
                    # Some modules don't raise on bad sig - that's a bug
                    pytest.fail("XEdDSA verify accepted a corrupted signature")
                except SignatureInvalid:
                    pass  # Expected: bad signature rejected
                except (
                    MechanismInvalid,
                    FunctionFailed,
                    FunctionNotSupported,
                ) as exc:
                    pytest.xfail(f"XEdDSA verify not operational: {type(exc).__name__}: {exc}")
        finally:
            priv.destroy()
            pub.destroy()


class TestECMontgomeryKeyPairGen:
    """CKM_EC_MONTGOMERY_KEY_PAIR_GEN - Generate Montgomery curve keypairs.

    Tests X25519 and X448 key generation and ECDH derivation.
    """

    def test_x25519_keygen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an X25519 keypair via EC_MONTGOMERY_KEY_PAIR_GEN."""
        if not has_mechanism(p11_module, "EC_MONTGOMERY_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_MONTGOMERY_KEY_PAIR_GEN not supported")

        try:
            pub, priv = p11_session.generate_keypair(
                KeyType.EC_MONTGOMERY,
                mechanism=Mechanism.EC_MONTGOMERY_KEY_PAIR_GEN,
                mechanism_param=None,
                template={
                    Attribute.EC_PARAMS: _X25519_OID,
                    Attribute.TOKEN: False,
                },
                public_template={},
                private_template={
                    Attribute.DERIVE: True,
                    Attribute.SENSITIVE: True,
                    Attribute.TOKEN: False,
                },
            )
        except (MechanismInvalid, FunctionFailed, FunctionNotSupported) as exc:
            pytest.skip(f"EC_MONTGOMERY_KEY_PAIR_GEN not operational: {type(exc).__name__}: {exc}")
        else:
            try:
                assert pub[Attribute.KEY_TYPE] is KeyType.EC_MONTGOMERY
                ec_point = pub[Attribute.EC_POINT]
                assert ec_point is not None
                assert len(ec_point) > 0
            finally:
                priv.destroy()
                pub.destroy()

    def test_x448_keygen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an X448 keypair via EC_MONTGOMERY_KEY_PAIR_GEN."""
        if not has_mechanism(p11_module, "EC_MONTGOMERY_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_MONTGOMERY_KEY_PAIR_GEN not supported")

        try:
            pub, priv = p11_session.generate_keypair(
                KeyType.EC_MONTGOMERY,
                mechanism=Mechanism.EC_MONTGOMERY_KEY_PAIR_GEN,
                mechanism_param=None,
                template={
                    Attribute.EC_PARAMS: _X448_OID,
                    Attribute.TOKEN: False,
                },
                public_template={},
                private_template={
                    Attribute.DERIVE: True,
                    Attribute.SENSITIVE: True,
                    Attribute.TOKEN: False,
                },
            )
        except (MechanismInvalid, FunctionFailed, FunctionNotSupported) as exc:
            pytest.skip(f"X448 keygen not supported: {type(exc).__name__}: {exc}")
        else:
            try:
                assert pub[Attribute.KEY_TYPE] is KeyType.EC_MONTGOMERY
                ec_point = pub[Attribute.EC_POINT]
                assert ec_point is not None
                assert len(ec_point) > 0
            finally:
                priv.destroy()
                pub.destroy()

    def test_x25519_two_keypairs_differ(self, p11_session: Any, p11_module: Any) -> None:
        """Two independently generated X25519 keypairs have different public keys."""
        if not has_mechanism(p11_module, "EC_MONTGOMERY_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_MONTGOMERY_KEY_PAIR_GEN not supported")

        try:
            pub_a, priv_a = p11_session.generate_keypair(
                KeyType.EC_MONTGOMERY,
                mechanism=Mechanism.EC_MONTGOMERY_KEY_PAIR_GEN,
                mechanism_param=None,
                template={Attribute.EC_PARAMS: _X25519_OID, Attribute.TOKEN: False},
                public_template={},
                private_template={
                    Attribute.DERIVE: True,
                    Attribute.SENSITIVE: True,
                    Attribute.TOKEN: False,
                },
            )
            pub_b, priv_b = p11_session.generate_keypair(
                KeyType.EC_MONTGOMERY,
                mechanism=Mechanism.EC_MONTGOMERY_KEY_PAIR_GEN,
                mechanism_param=None,
                template={Attribute.EC_PARAMS: _X25519_OID, Attribute.TOKEN: False},
                public_template={},
                private_template={
                    Attribute.DERIVE: True,
                    Attribute.SENSITIVE: True,
                    Attribute.TOKEN: False,
                },
            )
        except (MechanismInvalid, FunctionFailed, FunctionNotSupported) as exc:
            pytest.skip(f"EC_MONTGOMERY_KEY_PAIR_GEN not operational: {type(exc).__name__}: {exc}")
        else:
            try:
                assert pub_a[Attribute.EC_POINT] != pub_b[Attribute.EC_POINT]
            finally:
                priv_a.destroy()
                pub_a.destroy()
                priv_b.destroy()
                pub_b.destroy()

    def test_x25519_ecdh_derive(self, p11_session: Any, p11_module: Any) -> None:
        """X25519 keys can perform ECDH key agreement."""
        if not has_mechanism(p11_module, "EC_MONTGOMERY_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_MONTGOMERY_KEY_PAIR_GEN not supported")
        if not has_mechanism(p11_module, "ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        try:
            pub_a, priv_a = p11_session.generate_keypair(
                KeyType.EC_MONTGOMERY,
                mechanism=Mechanism.EC_MONTGOMERY_KEY_PAIR_GEN,
                mechanism_param=None,
                template={Attribute.EC_PARAMS: _X25519_OID, Attribute.TOKEN: False},
                public_template={},
                private_template={
                    Attribute.DERIVE: True,
                    Attribute.SENSITIVE: True,
                    Attribute.TOKEN: False,
                },
            )
            pub_b, priv_b = p11_session.generate_keypair(
                KeyType.EC_MONTGOMERY,
                mechanism=Mechanism.EC_MONTGOMERY_KEY_PAIR_GEN,
                mechanism_param=None,
                template={Attribute.EC_PARAMS: _X25519_OID, Attribute.TOKEN: False},
                public_template={},
                private_template={
                    Attribute.DERIVE: True,
                    Attribute.SENSITIVE: True,
                    Attribute.TOKEN: False,
                },
            )
        except (MechanismInvalid, FunctionFailed, FunctionNotSupported) as exc:
            pytest.skip(f"EC_MONTGOMERY_KEY_PAIR_GEN not operational: {type(exc).__name__}: {exc}")
        else:
            try:
                point_a = extract_ec_point(pub_a[Attribute.EC_POINT])
                point_b = extract_ec_point(pub_b[Attribute.EC_POINT])

                derive_tmpl = {
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.TOKEN: False,
                }

                shared_ab = priv_a.derive_key(
                    KeyType.GENERIC_SECRET,
                    256,
                    mechanism=Mechanism.ECDH1_DERIVE,
                    mechanism_param=(KDF.NULL, None, point_b),
                    template=derive_tmpl,
                )
                try:
                    shared_ba = priv_b.derive_key(
                        KeyType.GENERIC_SECRET,
                        256,
                        mechanism=Mechanism.ECDH1_DERIVE,
                        mechanism_param=(KDF.NULL, None, point_a),
                        template=derive_tmpl,
                    )
                    try:
                        assert shared_ab[Attribute.VALUE] == shared_ba[Attribute.VALUE]
                        assert len(shared_ab[Attribute.VALUE]) == 32
                    finally:
                        shared_ba.destroy()
                finally:
                    shared_ab.destroy()
            finally:
                priv_a.destroy()
                pub_a.destroy()
                priv_b.destroy()
                pub_b.destroy()
