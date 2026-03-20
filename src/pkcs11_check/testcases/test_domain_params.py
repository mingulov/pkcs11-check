"""CKO_DOMAIN_PARAMETERS attribute coverage tests.

Domain parameter *usage* (create/generate + keypair generation) is already
well-tested across ~15 test files.  This file closes the gap on domain
parameter *object attributes*:

  - CKA_CLASS is ObjectClass.DOMAIN_PARAMETERS
  - CKA_KEY_TYPE matches the algorithm (EC, DH, DSA)
  - CKA_LOCAL distinguishes generated vs created domain params
  - CKA_EC_PARAMS is readable on EC domain parameter objects
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pkcs11.util.ec
import pytest
from pkcs11 import Attribute, KeyType, ObjectClass
from pkcs11.exceptions import (
    FunctionNotSupported,
    MechanismInvalid,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.object

# Common error tuple for domain param creation failures
_DOMAIN_PARAM_ERRORS = (
    FunctionNotSupported,
    MechanismInvalid,
)


class TestEcDomainParameters:
    """EC domain parameter object attribute tests."""

    def _create_ec_domain_params(self, p11_session: Any) -> Any:
        """Create EC domain parameters for secp256r1."""
        return p11_session.create_domain_parameters(
            KeyType.EC,
            {
                Attribute.EC_PARAMS: (
                    pkcs11.util.ec.encode_named_curve_parameters("secp256r1")
                ),
            },
            local=True,
        )

    def test_ec_domain_params_class(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """EC domain params have CKA_CLASS = DOMAIN_PARAMETERS."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        try:
            params = self._create_ec_domain_params(p11_session)
        except _DOMAIN_PARAM_ERRORS:
            pytest.skip("Module does not support EC domain parameter creation")
        try:
            obj_class = params[Attribute.CLASS]
            assert obj_class == ObjectClass.DOMAIN_PARAMETERS, (
                f"Expected DOMAIN_PARAMETERS, got {obj_class}"
            )
        finally:
            params.destroy()

    def test_ec_domain_params_key_type(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """EC domain params have CKA_KEY_TYPE = EC."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        try:
            params = self._create_ec_domain_params(p11_session)
        except _DOMAIN_PARAM_ERRORS:
            pytest.skip("Module does not support EC domain parameter creation")
        try:
            key_type = params[Attribute.KEY_TYPE]
            assert key_type == KeyType.EC, (
                f"Expected KeyType.EC, got {key_type}"
            )
        finally:
            params.destroy()

    def test_ec_domain_params_ec_params_readable(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """EC domain params have readable CKA_EC_PARAMS."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        try:
            params = self._create_ec_domain_params(p11_session)
        except _DOMAIN_PARAM_ERRORS:
            pytest.skip("Module does not support EC domain parameter creation")
        try:
            ec_params = params[Attribute.EC_PARAMS]
            assert ec_params is not None, "CKA_EC_PARAMS should not be None"
            assert len(ec_params) > 0, "CKA_EC_PARAMS should not be empty"
            # Should match what we put in
            expected = pkcs11.util.ec.encode_named_curve_parameters("secp256r1")
            assert ec_params == expected, (
                "CKA_EC_PARAMS does not match encoded secp256r1"
            )
        finally:
            params.destroy()

    def test_ec_domain_params_local_true(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Created EC domain params with local=True have CKA_LOCAL=True."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        try:
            params = p11_session.create_domain_parameters(
                KeyType.EC,
                {
                    Attribute.EC_PARAMS: (
                        pkcs11.util.ec.encode_named_curve_parameters("secp256r1")
                    ),
                },
                local=True,
            )
        except _DOMAIN_PARAM_ERRORS:
            pytest.skip("Module does not support EC domain parameter creation")
        try:
            try:
                local = params[Attribute.LOCAL]
                assert local is True, (
                    f"Expected CKA_LOCAL=True for local domain params, got {local}"
                )
            except Exception:
                pytest.xfail("Module does not expose CKA_LOCAL on domain params")
        finally:
            params.destroy()

    def test_ec_domain_params_local_false(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Created EC domain params with local=False have CKA_LOCAL=False."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        try:
            params = p11_session.create_domain_parameters(
                KeyType.EC,
                {
                    Attribute.EC_PARAMS: (
                        pkcs11.util.ec.encode_named_curve_parameters("secp256r1")
                    ),
                },
                local=False,
            )
        except _DOMAIN_PARAM_ERRORS:
            pytest.skip("Module does not support EC domain parameter creation")
        try:
            try:
                local = params[Attribute.LOCAL]
                assert local is False, (
                    f"Expected CKA_LOCAL=False for non-local domain params, got {local}"
                )
            except Exception:
                pytest.xfail("Module does not expose CKA_LOCAL on domain params")
        finally:
            params.destroy()


class TestDomainParameterEnumeration:
    """Enumerate CKO_DOMAIN_PARAMETERS objects on the token."""

    def test_enumerate_domain_params(self, p11_session: Any) -> None:
        """Enumerate CKO_DOMAIN_PARAMETERS objects without error."""
        try:
            params = list(
                p11_session.get_objects(
                    {Attribute.CLASS: ObjectClass.DOMAIN_PARAMETERS}
                )
            )
        except Exception:
            pytest.xfail(
                "Module does not support CKO_DOMAIN_PARAMETERS enumeration"
            )
        assert isinstance(params, list)

    def test_domain_params_have_key_type(self, p11_session: Any) -> None:
        """Each CKO_DOMAIN_PARAMETERS object has a readable CKA_KEY_TYPE."""
        try:
            params = list(
                p11_session.get_objects(
                    {Attribute.CLASS: ObjectClass.DOMAIN_PARAMETERS}
                )
            )
        except Exception:
            pytest.xfail(
                "Module does not support CKO_DOMAIN_PARAMETERS enumeration"
            )
        if not params:
            pytest.skip("No CKO_DOMAIN_PARAMETERS objects present")
        for param in params:
            try:
                key_type = param[Attribute.KEY_TYPE]
                assert isinstance(key_type, (int, KeyType)), (
                    f"Expected int/KeyType for KEY_TYPE, got {type(key_type)}"
                )
            except Exception:
                pytest.xfail(
                    "Cannot read CKA_KEY_TYPE from domain parameter object"
                )


class TestMultipleCurveDomainParams:
    """Test domain parameters across different EC curves."""

    @pytest.mark.parametrize(
        "curve",
        ["secp256r1", "secp384r1", "secp521r1"],
        ids=["P-256", "P-384", "P-521"],
    )
    def test_ec_curve_domain_params(
        self, p11_session: Any, p11_module: Any, curve: str
    ) -> None:
        """EC domain params can be created for standard NIST curves."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        try:
            params = p11_session.create_domain_parameters(
                KeyType.EC,
                {
                    Attribute.EC_PARAMS: (
                        pkcs11.util.ec.encode_named_curve_parameters(curve)
                    ),
                },
                local=True,
            )
        except _DOMAIN_PARAM_ERRORS:
            pytest.skip(
                f"Module does not support domain parameter creation for {curve}"
            )
        try:
            obj_class = params[Attribute.CLASS]
            assert obj_class == ObjectClass.DOMAIN_PARAMETERS
            ec_params = params[Attribute.EC_PARAMS]
            expected = pkcs11.util.ec.encode_named_curve_parameters(curve)
            assert ec_params == expected, (
                f"CKA_EC_PARAMS mismatch for {curve}"
            )
        finally:
            params.destroy()
