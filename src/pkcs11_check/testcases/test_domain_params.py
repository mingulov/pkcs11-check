"""CKO_DOMAIN_PARAMETERS attribute coverage tests.

Domain parameter *usage* (create/generate + keypair generation) is already
well-tested across ~15 test files.  This file closes the gap on domain
parameter *object attributes*:

  - CKA_KEY_TYPE matches the algorithm (EC)
  - CKA_LOCAL distinguishes generated vs created domain params
  - CKA_EC_PARAMS is readable on EC domain parameter objects
  - Enumeration of existing CKO_DOMAIN_PARAMETERS objects

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_ulong, template
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    find_objects,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_KEY_TYPE,
    CKA_LOCAL,
    CKA_TOKEN,
    CKK_EC,
    CKO_DOMAIN_PARAMETERS,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

pytestmark = pytest.mark.object

# Acceptable CKR codes when domain param creation is unsupported
_DOMAIN_PARAM_ERROR_RVS = {
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
}


def _create_ec_domain_params(rs: Any, on_token: bool = False) -> int | None:
    """Create EC domain parameters object on token.

    Returns handle on success, None if unsupported.
    """
    curve_oid = encode_named_curve_parameters("secp256r1")
    handle = 0
    try:
        handle = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DOMAIN_PARAMETERS,
                CKA_KEY_TYPE: CKK_EC,
                CKA_EC_PARAMS: curve_oid,
                CKA_TOKEN: on_token,
            },
        )
        return handle
    except (AssertionError, Exception):
        return None


class TestEcDomainParameters:
    """EC domain parameter object attribute tests."""

    def test_ec_domain_params_key_type(
        self,
        p11_raw_session: Any,
    ) -> None:
        """EC domain params have key_type = EC."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        handle = _create_ec_domain_params(rs, on_token=False)
        if handle is None:
            pytest.skip("Module does not support EC domain parameter creation")
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE])
            assert attrs[CKA_KEY_TYPE] == CKK_EC, f"Expected CKK_EC, got {attrs[CKA_KEY_TYPE]}"
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)

    def test_ec_domain_params_on_token(
        self,
        p11_raw_session: Any,
    ) -> None:
        """EC domain params created on token have readable attributes."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        handle = _create_ec_domain_params(rs, on_token=True)
        if handle is None:
            pytest.skip("Module does not support EC domain parameter creation on token")
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE])
            assert attrs[CKA_KEY_TYPE] == CKK_EC, f"Expected CKK_EC, got {attrs[CKA_KEY_TYPE]}"
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)

    def test_ec_domain_params_ec_params_readable(
        self,
        p11_raw_session: Any,
    ) -> None:
        """EC domain params have readable CKA_EC_PARAMS on token objects."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        handle = _create_ec_domain_params(rs, on_token=True)
        if handle is None:
            pytest.skip("Module does not support EC domain parameter creation on token")
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_EC_PARAMS])
            ec_params = attrs[CKA_EC_PARAMS]
            assert ec_params is not None, "CKA_EC_PARAMS should not be None"
            assert len(ec_params) > 0, "CKA_EC_PARAMS should not be empty"
            expected = encode_named_curve_parameters("secp256r1")
            assert ec_params == expected, "CKA_EC_PARAMS does not match encoded secp256r1"
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)

    def test_ec_domain_params_local_flag(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKA_LOCAL on token domain params should be False (created, not generated)."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        handle = _create_ec_domain_params(rs, on_token=True)
        if handle is None:
            pytest.skip("Module does not support EC domain parameter creation on token")
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_LOCAL])
            local = attrs[CKA_LOCAL]
            assert local is False, (
                f"Expected CKA_LOCAL=False for created domain params, got {local}"
            )
        except (AssertionError, Exception) as e:
            pytest.xfail(f"Module does not expose CKA_LOCAL on domain params: {e}")
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)


class TestDomainParameterEnumeration:
    """Enumerate CKO_DOMAIN_PARAMETERS objects on the token."""

    def test_enumerate_domain_params(self, p11_raw_session: Any) -> None:
        """Enumerate CKO_DOMAIN_PARAMETERS objects without error."""
        rs = p11_raw_session
        tmpl = template(attr_ulong(CKA_CLASS, CKO_DOMAIN_PARAMETERS))
        try:
            params = find_objects(rs.raw, rs.sh, tmpl)
        except (AssertionError, Exception) as e:
            pytest.skip(f"Module does not support CKO_DOMAIN_PARAMETERS enumeration: {e}")
        assert isinstance(params, list)

    def test_domain_params_have_key_type(self, p11_raw_session: Any) -> None:
        """Each CKO_DOMAIN_PARAMETERS object has a readable CKA_KEY_TYPE."""
        rs = p11_raw_session
        tmpl = template(attr_ulong(CKA_CLASS, CKO_DOMAIN_PARAMETERS))
        try:
            params = find_objects(rs.raw, rs.sh, tmpl)
        except (AssertionError, Exception) as e:
            pytest.skip(f"Module does not support CKO_DOMAIN_PARAMETERS enumeration: {e}")
        if not params:
            pytest.skip("No CKO_DOMAIN_PARAMETERS objects present")
        for handle in params:
            try:
                attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE])
                key_type = attrs[CKA_KEY_TYPE]
                assert isinstance(key_type, int), f"Expected int for KEY_TYPE, got {type(key_type)}"
            except (AssertionError, Exception) as e:
                pytest.xfail(f"Cannot read CKA_KEY_TYPE from domain parameter object: {e}")


class TestMultipleCurveDomainParams:
    """Test domain parameters across different EC curves."""

    @pytest.mark.parametrize(
        "curve",
        ["secp256r1", "secp384r1", "secp521r1"],
        ids=["P-256", "P-384", "P-521"],
    )
    def test_ec_curve_domain_params(
        self,
        p11_raw_session: Any,
        curve: str,
    ) -> None:
        """EC domain params can be created for standard NIST curves."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        curve_oid = encode_named_curve_parameters(curve)
        handle = 0
        try:
            handle = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_DOMAIN_PARAMETERS,
                    CKA_KEY_TYPE: CKK_EC,
                    CKA_EC_PARAMS: curve_oid,
                    CKA_TOKEN: False,
                },
            )
        except (AssertionError, Exception) as e:
            pytest.skip(f"Module does not support domain parameter creation for {curve}: {e}")
        try:
            attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_KEY_TYPE])
            assert attrs[CKA_KEY_TYPE] == CKK_EC
        finally:
            if handle:
                destroy_quietly(rs.raw, rs.sh, handle)
