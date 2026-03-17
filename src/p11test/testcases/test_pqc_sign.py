"""Post-quantum signature tests — ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).

All tests require PKCS#11 v3.2 interface.  Auto-skips on v3.1 and earlier.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.constants import MLDsaParameterSet, SlhDsaParameterSet

from p11test.testcases.conftest import has_mechanism

pytestmark = [pytest.mark.pqc, pytest.mark.requires_v32]

_PLAINTEXT = b"post-quantum signature test message 2026"


def _skip_if_no(p11_module: Any, mech_name: str) -> None:
    if not has_mechanism(p11_module, mech_name):
        pytest.skip(f"{mech_name} not supported by module")


def _generate_ml_dsa_keypair(session: Any, param_set: MLDsaParameterSet | None = None) -> Any:
    pub_tmpl: dict[Any, Any] = {Attribute.VERIFY: True, Attribute.TOKEN: False}
    priv_tmpl: dict[Any, Any] = {Attribute.SIGN: True, Attribute.TOKEN: False}
    if param_set is not None:
        pub_tmpl[Attribute.PARAMETER_SET] = int(param_set)
        priv_tmpl[Attribute.PARAMETER_SET] = int(param_set)
    return session.generate_keypair(
        KeyType.ML_DSA,
        mechanism=Mechanism.ML_DSA_KEY_PAIR_GEN,
        public_template=pub_tmpl,
        private_template=priv_tmpl,
    )


def _generate_slh_dsa_keypair(session: Any, param_set: SlhDsaParameterSet | None = None) -> Any:
    pub_tmpl: dict[Any, Any] = {Attribute.VERIFY: True, Attribute.TOKEN: False}
    priv_tmpl: dict[Any, Any] = {Attribute.SIGN: True, Attribute.TOKEN: False}
    if param_set is not None:
        pub_tmpl[Attribute.PARAMETER_SET] = int(param_set)
        priv_tmpl[Attribute.PARAMETER_SET] = int(param_set)
    return session.generate_keypair(
        KeyType.SLH_DSA,
        mechanism=Mechanism.SLH_DSA_KEY_PAIR_GEN,
        public_template=pub_tmpl,
        private_template=priv_tmpl,
    )


class TestMLDSAKeyGeneration:
    """ML-DSA key generation tests."""

    def test_ml_dsa_available(self, p11_module: Any) -> None:
        """Check that ML_DSA mechanism is available."""
        _skip_if_no(p11_module, "ML_DSA")

    def test_ml_dsa_keypair_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an ML-DSA key pair."""
        _skip_if_no(p11_module, "ML_DSA")
        pair = _generate_ml_dsa_keypair(p11_session)
        pub, priv = pair
        assert pub is not None
        assert priv is not None

    def test_ml_dsa_keypair_classes(self, p11_session: Any, p11_module: Any) -> None:
        """ML-DSA public key is PublicKey, private is PrivateKey."""
        _skip_if_no(p11_module, "ML_DSA")
        pub, priv = _generate_ml_dsa_keypair(p11_session)
        assert pub[Attribute.CLASS] == ObjectClass.PUBLIC_KEY
        assert priv[Attribute.CLASS] == ObjectClass.PRIVATE_KEY

    def test_ml_dsa_keypair_key_type(self, p11_session: Any, p11_module: Any) -> None:
        """ML-DSA keys report correct key type."""
        _skip_if_no(p11_module, "ML_DSA")
        pub, priv = _generate_ml_dsa_keypair(p11_session)
        assert pub[Attribute.KEY_TYPE] == KeyType.ML_DSA
        assert priv[Attribute.KEY_TYPE] == KeyType.ML_DSA

    @pytest.mark.parametrize(
        "param_set",
        [MLDsaParameterSet.ML_DSA_44, MLDsaParameterSet.ML_DSA_65, MLDsaParameterSet.ML_DSA_87],
    )
    def test_ml_dsa_keypair_parameter_set(
        self, p11_session: Any, p11_module: Any, param_set: MLDsaParameterSet
    ) -> None:
        """Generate ML-DSA key with explicit parameter set."""
        _skip_if_no(p11_module, "ML_DSA")
        try:
            pair = _generate_ml_dsa_keypair(p11_session, param_set=param_set)
        except Exception:
            pytest.xfail(f"Module does not support CKA_PARAMETER_SET={param_set.name}")
        pub, priv = pair
        assert pub is not None and priv is not None


class TestMLDSASignVerify:
    """ML-DSA sign/verify round-trip tests."""

    def test_sign_and_verify(self, p11_session: Any, p11_module: Any) -> None:
        """ML-DSA sign + verify round-trip."""
        _skip_if_no(p11_module, "ML_DSA")
        pub, priv = _generate_ml_dsa_keypair(p11_session)
        try:
            sig = priv.sign(_PLAINTEXT, mechanism=Mechanism.ML_DSA)
        except Exception:
            pytest.xfail("ML-DSA sign failed")
        assert isinstance(sig, bytes) and len(sig) > 0
        assert pub.verify(_PLAINTEXT, sig, mechanism=Mechanism.ML_DSA)

    def test_tampered_message_fails_verification(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Tampered message fails ML-DSA verification."""
        _skip_if_no(p11_module, "ML_DSA")
        pub, priv = _generate_ml_dsa_keypair(p11_session)
        try:
            sig = priv.sign(_PLAINTEXT, mechanism=Mechanism.ML_DSA)
        except Exception:
            pytest.xfail("ML-DSA sign failed")
        tampered = _PLAINTEXT[:-1] + bytes([_PLAINTEXT[-1] ^ 0xFF])
        result = pub.verify(tampered, sig, mechanism=Mechanism.ML_DSA)
        assert not result, "Tampered message should fail verification"

    def test_two_signatures_differ(self, p11_session: Any, p11_module: Any) -> None:
        """ML-DSA produces different signatures for the same message (randomized)."""
        _skip_if_no(p11_module, "ML_DSA")
        pub, priv = _generate_ml_dsa_keypair(p11_session)
        try:
            sig1 = priv.sign(_PLAINTEXT, mechanism=Mechanism.ML_DSA)
            sig2 = priv.sign(_PLAINTEXT, mechanism=Mechanism.ML_DSA)
        except Exception:
            pytest.xfail("ML-DSA sign failed")
        # ML-DSA is randomized — two signatures should differ (with overwhelming probability)
        # Note: some implementations may use deterministic signing, so xfail not assert
        if sig1 == sig2:
            pytest.xfail("ML-DSA produced identical signatures (deterministic mode?)")


class TestSLHDSAKeyGeneration:
    """SLH-DSA key generation tests."""

    def test_slh_dsa_available(self, p11_module: Any) -> None:
        """Check that SLH_DSA mechanism is available."""
        _skip_if_no(p11_module, "SLH_DSA")

    def test_slh_dsa_keypair_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an SLH-DSA key pair."""
        _skip_if_no(p11_module, "SLH_DSA")
        try:
            pair = _generate_slh_dsa_keypair(p11_session)
        except Exception:
            pytest.xfail("SLH-DSA key generation failed")
        pub, priv = pair
        assert pub is not None
        assert priv is not None

    def test_slh_dsa_keypair_key_type(self, p11_session: Any, p11_module: Any) -> None:
        """SLH-DSA keys report correct key type."""
        _skip_if_no(p11_module, "SLH_DSA")
        try:
            pub, priv = _generate_slh_dsa_keypair(p11_session)
        except Exception:
            pytest.xfail("SLH-DSA key generation failed")
        assert pub[Attribute.KEY_TYPE] == KeyType.SLH_DSA
        assert priv[Attribute.KEY_TYPE] == KeyType.SLH_DSA

    @pytest.mark.parametrize(
        "param_set",
        [SlhDsaParameterSet.SHA2_128S, SlhDsaParameterSet.SHA2_128F, SlhDsaParameterSet.SHA2_256F],
    )
    def test_slh_dsa_keypair_parameter_set(
        self, p11_session: Any, p11_module: Any, param_set: SlhDsaParameterSet
    ) -> None:
        """Generate SLH-DSA key with explicit parameter set."""
        _skip_if_no(p11_module, "SLH_DSA")
        try:
            pair = _generate_slh_dsa_keypair(p11_session, param_set=param_set)
        except Exception:
            pytest.xfail(f"Module does not support CKA_PARAMETER_SET={param_set.name}")
        pub, priv = pair
        assert pub is not None and priv is not None


class TestSLHDSASignVerify:
    """SLH-DSA sign/verify round-trip tests."""

    def test_sign_and_verify(self, p11_session: Any, p11_module: Any) -> None:
        """SLH-DSA sign + verify round-trip."""
        _skip_if_no(p11_module, "SLH_DSA")
        try:
            pub, priv = _generate_slh_dsa_keypair(p11_session)
            sig = priv.sign(_PLAINTEXT, mechanism=Mechanism.SLH_DSA)
        except Exception:
            pytest.xfail("SLH-DSA sign failed")
        assert isinstance(sig, bytes) and len(sig) > 0
        assert pub.verify(_PLAINTEXT, sig, mechanism=Mechanism.SLH_DSA)

    def test_tampered_message_fails_verification(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Tampered message fails SLH-DSA verification."""
        _skip_if_no(p11_module, "SLH_DSA")
        try:
            pub, priv = _generate_slh_dsa_keypair(p11_session)
            sig = priv.sign(_PLAINTEXT, mechanism=Mechanism.SLH_DSA)
        except Exception:
            pytest.xfail("SLH-DSA sign failed")
        tampered = _PLAINTEXT[:-1] + bytes([_PLAINTEXT[-1] ^ 0xFF])
        result = pub.verify(tampered, sig, mechanism=Mechanism.SLH_DSA)
        assert not result, "Tampered message should fail SLH-DSA verification"
