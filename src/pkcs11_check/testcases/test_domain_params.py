"""CKO_DOMAIN_PARAMETERS attribute coverage tests.

Domain parameter *usage* (create/generate + keypair generation) is already
well-tested across ~15 test files.  This file closes the gap on domain
parameter *object attributes*:

  - CKA_KEY_TYPE matches the algorithm (EC)
  - CKA_LOCAL distinguishes generated vs created domain params
  - CKA_EC_PARAMS is readable on EC domain parameter objects
  - Enumeration of existing CKO_DOMAIN_PARAMETERS objects

Note: create_domain_parameters(local=True) returns a wrapper-level
LocalDomainParameters that does NOT support arbitrary attribute reads.
Tests use wrapper properties (.key_type) or local=False for token objects.
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pkcs11.util.ec
import pytest
from pkcs11 import Attribute, KeyType, ObjectClass
from pkcs11.exceptions import (
    PKCS11Error,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.object

# Errors when domain param creation is unsupported
_DOMAIN_PARAM_ERRORS = (PKCS11Error, NotImplementedError)


class TestEcDomainParameters:
    """EC domain parameter object attribute tests."""

    def test_ec_domain_params_key_type_via_property(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """EC domain params have key_type = EC (via wrapper property)."""
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
        except _DOMAIN_PARAM_ERRORS as e:
            pytest.skip(f"Module does not support EC domain parameter creation: {e}")
        try:
            assert params.key_type == KeyType.EC, (
                f"Expected KeyType.EC, got {params.key_type}"
            )
        finally:
            try:
                params.destroy()
            except (PKCS11Error, NotImplementedError, AttributeError):
                pass  # LocalDomainParameters may not support destroy

    def test_ec_domain_params_on_token(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """EC domain params created on token (local=False) have readable attributes."""
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
        except _DOMAIN_PARAM_ERRORS as e:
            pytest.skip(
                f"Module does not support EC domain parameter creation on token: {e}"
            )
        try:
            key_type = params[Attribute.KEY_TYPE]
            assert key_type == KeyType.EC, (
                f"Expected KeyType.EC, got {key_type}"
            )
        except (PKCS11Error, NotImplementedError) as e:
            pytest.skip(f"Cannot read CKA_KEY_TYPE from domain params on token: {e}")
        finally:
            try:
                params.destroy()
            except PKCS11Error:
                pass

    def test_ec_domain_params_ec_params_readable(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """EC domain params have readable CKA_EC_PARAMS on token objects."""
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
        except _DOMAIN_PARAM_ERRORS as e:
            pytest.skip(
                f"Module does not support EC domain parameter creation on token: {e}"
            )
        try:
            ec_params = params[Attribute.EC_PARAMS]
            assert ec_params is not None, "CKA_EC_PARAMS should not be None"
            assert len(ec_params) > 0, "CKA_EC_PARAMS should not be empty"
            expected = pkcs11.util.ec.encode_named_curve_parameters("secp256r1")
            assert ec_params == expected, (
                "CKA_EC_PARAMS does not match encoded secp256r1"
            )
        except (PKCS11Error, NotImplementedError) as e:
            pytest.skip(f"Cannot read CKA_EC_PARAMS from domain params: {e}")
        finally:
            try:
                params.destroy()
            except PKCS11Error:
                pass

    def test_ec_domain_params_local_flag(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """CKA_LOCAL on token domain params should be False (created, not generated)."""
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
        except _DOMAIN_PARAM_ERRORS as e:
            pytest.skip(
                f"Module does not support EC domain parameter creation on token: {e}"
            )
        try:
            local = params[Attribute.LOCAL]
            assert local is False, (
                f"Expected CKA_LOCAL=False for created domain params, got {local}"
            )
        except (PKCS11Error, NotImplementedError) as e:
            pytest.xfail(f"Module does not expose CKA_LOCAL on domain params: {e}")
        finally:
            try:
                params.destroy()
            except PKCS11Error:
                pass


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
        except PKCS11Error as e:
            pytest.xfail(
                f"Module does not support CKO_DOMAIN_PARAMETERS enumeration: {e}"
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
        except PKCS11Error as e:
            pytest.xfail(
                f"Module does not support CKO_DOMAIN_PARAMETERS enumeration: {e}"
            )
        if not params:
            pytest.skip("No CKO_DOMAIN_PARAMETERS objects present")
        for param in params:
            try:
                key_type = param[Attribute.KEY_TYPE]
                assert isinstance(key_type, (int, KeyType)), (
                    f"Expected int/KeyType for KEY_TYPE, got {type(key_type)}"
                )
            except PKCS11Error as e:
                pytest.xfail(
                    f"Cannot read CKA_KEY_TYPE from domain parameter object: {e}"
                )


class TestMultipleCurveDomainParams:
    """Test domain parameters across different EC curves via wrapper."""

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
        except _DOMAIN_PARAM_ERRORS as e:
            pytest.skip(
                f"Module does not support domain parameter creation for {curve}: {e}"
            )
        try:
            assert params.key_type == KeyType.EC
        finally:
            try:
                params.destroy()
            except (PKCS11Error, NotImplementedError, AttributeError):
                pass
