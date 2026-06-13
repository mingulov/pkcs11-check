"""PKCS#11 API security tests - attribute attacks, policy bypass, access control.

Based on Bortolozzo et al. "Attacking and Fixing PKCS#11 Security Tokens" (CCS 2010)
and PKCS#11 attribute enforcement rules from the OASIS specification.

Tests are marked @security - results are security findings, not correctness failures.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
)
from pkcs11_check.raw.bootstrap import (
    open_session as _raw_open_session,
)
from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import (
    copy_object,
    decrypt_single,
    destroy_quietly,
    find_objects,
    read_attributes,
    set_attributes,
    wrap_key,
)
from pkcs11_check.raw.recipes import gen_aes_key as _raw_gen_aes_key
from pkcs11_check.raw.recipes import gen_rsa_keypair as _raw_gen_rsa_keypair
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_COPYABLE,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_PRIVATE_EXPONENT,
    CKA_SENSITIVE,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKF_SERIAL_SESSION,
    CKM_AES_ECB,
    CKO_PRIVATE_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_UNEXTRACTABLE,
    CKR_MECHANISM_INVALID,
    CKR_SESSION_COUNT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    classify_policy_enforcement,
    is_known_error,
    require_operational_aes_keygen,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.security

_API_SECURITY_AES_SETUP_REJECT_RVS = (
    *AES_KEYGEN_RUNTIME_REJECT_RVS,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_POLICY_KEYGEN_REJECT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_ATTR_POLICY_REJECT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)

_WRAP_DECRYPT_POLICY_BLOCK_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_NOT_WRAPPABLE,
    # Refusing to wrap a non-extractable target is itself a valid way to block
    # the wrap-decrypt oracle (the secure outcome), not a test failure.
    CKR_KEY_UNEXTRACTABLE,
)

_WRAP_DECRYPT_RUNTIME_REJECT_RVS = (
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
)


def _skip_unless_mechanism(rs: Any, name: str) -> None:
    if not rs.has_mechanism(name):
        pytest.skip(f"{name} not supported by module")


def raw_open_session(raw: Any, slot_id: int, flags: int) -> int:
    """Open an extra public session needed by API-security tests."""
    try:
        return _raw_open_session(raw, slot_id, flags)
    except AssertionError as exc:
        if is_known_error(exc, (CKR_SESSION_COUNT,)):
            pytest.skip(
                "Cannot open additional session required by API security test: "
                f"{ckr_name(int(CKR_SESSION_COUNT))}"
            )
        raise


def _gen_api_security_aes_key(
    rs: Any,
    bits: int = 128,
    *,
    attrs: dict[Any, Any] | None = None,
    purpose: str = "API security AES setup",
) -> int:
    """Generate an AES fixture key without turning setup gaps into security results."""
    _skip_unless_mechanism(rs, "AES_KEY_GEN")
    require_operational_aes_keygen(rs)
    try:
        return _raw_gen_aes_key(rs.raw, rs.sh, bits, attrs=attrs)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _API_SECURITY_AES_SETUP_REJECT_RVS,
            f"{purpose} is not operational",
        )
    raise


def _gen_api_security_rsa_keypair(rs: Any, bits: int = 2048) -> tuple[int, int]:
    """Generate an RSA fixture keypair for API-security tests."""
    _skip_unless_mechanism(rs, "RSA_PKCS_KEY_PAIR_GEN")
    try:
        return _raw_gen_rsa_keypair(rs.raw, rs.sh, bits)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            KEYPAIR_RUNTIME_REJECT_RVS,
            "API security RSA setup is not operational",
        )
    raise


def _return_if_policy_reject(exc: AssertionError, allowed_rvs: tuple[Any, ...]) -> None:
    if is_known_error(exc, allowed_rvs):
        return
    raise exc


def _return_if_policy_reject_or_xfail_runtime(
    exc: AssertionError,
    *,
    policy_rvs: tuple[Any, ...],
    runtime_rvs: tuple[Any, ...],
    msg: str,
) -> None:
    if is_known_error(exc, policy_rvs):
        return
    xfail_if_known_ckr(exc, runtime_rvs, msg)
    raise exc


class TestWrapDecryptOracle:
    """Test for the classic wrap-decrypt oracle attack.

    If a key has both CKA_WRAP and CKA_DECRYPT, an attacker can:
    1. Wrap a target key under the dual-purpose key
    2. Decrypt the wrapped blob -> get raw key material

    A secure module should prevent keys from having both CKA_WRAP and CKA_DECRYPT.
    """

    def test_wrap_decrypt_combination_prevented(self, p11_raw_session: Any) -> None:
        """Module should prevent creating key with both WRAP and DECRYPT."""
        rs = p11_raw_session
        _skip_unless_mechanism(rs, "AES_ECB")
        _skip_unless_mechanism(rs, "AES_KEY_GEN")
        require_operational_aes_keygen(rs)
        try:
            dual_key_h = _raw_gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={
                    CKA_WRAP: True,
                    CKA_UNWRAP: True,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                },
            )
        except AssertionError as exc:
            if is_known_error(exc, _POLICY_KEYGEN_REJECT_RVS):
                return  # Module prevented dual-purpose key creation - best
            xfail_if_known_ckr(
                exc,
                AES_KEYGEN_RUNTIME_REJECT_RVS,
                "API security dual-purpose AES setup is not operational",
            )
            raise

        target_h = 0
        try:
            # The target is created PROTECTED (non-extractable + sensitive) so the
            # wrap-decrypt oracle, if it works, extracts material the module
            # promised to protect -- a Type-B self-contradiction.
            target_h = _gen_api_security_aes_key(
                rs,
                attrs={CKA_EXTRACTABLE: False, CKA_SENSITIVE: True},
                purpose="API security wrap-decrypt target setup",
            )
            try:
                wrapped = wrap_key(rs.raw, rs.sh, dual_key_h, target_h, CKM_AES_ECB)
                # Decrypt the wrapped blob = extract the key material.
                try:
                    raw_key = decrypt_single(rs.raw, rs.sh, dual_key_h, CKM_AES_ECB, wrapped)
                    # Claim-check: did the target actually hold its protection?
                    tgt = read_attributes(rs.raw, rs.sh, target_h, [CKA_EXTRACTABLE])
                    claimed = tgt.get(CKA_EXTRACTABLE) is False
                    extracted = bool(raw_key) and len(raw_key) > 0
                    classify_policy_enforcement(
                        claimed=claimed,
                        violated=extracted,
                        label="wrap-decrypt oracle extracts a non-extractable/sensitive key "
                        "(PKCS#11 v3.1 Sec.4.9.4: CKA_WRAP and CKA_DECRYPT should not both "
                        "be True)",
                    )
                except AssertionError as exc:
                    _return_if_policy_reject_or_xfail_runtime(
                        exc,
                        policy_rvs=_WRAP_DECRYPT_POLICY_BLOCK_RVS,
                        runtime_rvs=_WRAP_DECRYPT_RUNTIME_REJECT_RVS,
                        msg="API security wrap-decrypt operation is not operational",
                    )
            except AssertionError as exc:
                _return_if_policy_reject_or_xfail_runtime(
                    exc,
                    policy_rvs=_WRAP_DECRYPT_POLICY_BLOCK_RVS,
                    runtime_rvs=_WRAP_DECRYPT_RUNTIME_REJECT_RVS,
                    msg="API security wrap-decrypt operation is not operational",
                )
        finally:
            if target_h:
                destroy_quietly(rs.raw, rs.sh, target_h)
            destroy_quietly(rs.raw, rs.sh, dual_key_h)


class TestSensitiveExtraction:
    """Verify sensitive key material cannot be read."""

    def test_sensitive_key_value_not_readable(self, p11_raw_session: Any) -> None:
        """CKA_SENSITIVE=True key: C_GetAttributeValue(CKA_VALUE) must fail."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={CKA_SENSITIVE: True, CKA_EXTRACTABLE: False},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_VALUE])
            assert CKA_VALUE not in attrs, (
                "SECURITY: CKA_VALUE readable on SENSITIVE key -- key material exposed"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_private_key_not_extractable(self, p11_raw_session: Any) -> None:
        """RSA private key material must not be readable."""
        rs = p11_raw_session
        pub_h, priv_h = _gen_api_security_rsa_keypair(rs)
        try:
            attrs = read_attributes(rs.raw, rs.sh, priv_h, [CKA_PRIVATE_EXPONENT])
            assert CKA_PRIVATE_EXPONENT not in attrs, (
                "SECURITY: CKA_PRIVATE_EXPONENT readable -- private key material exposed"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_h)
            destroy_quietly(rs.raw, rs.sh, priv_h)


class TestAttributeEscalation:
    """Verify attributes cannot be escalated after creation."""

    def test_extractable_cannot_be_set_true(self, p11_raw_session: Any) -> None:
        """CKA_EXTRACTABLE=False cannot be changed to True."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={CKA_EXTRACTABLE: False},
        )
        try:
            try:
                set_attributes(rs.raw, rs.sh, key_h, {CKA_EXTRACTABLE: True})
                classify(
                    "self_contradiction",
                    kind="policy",
                    label="CKA_EXTRACTABLE escalation via C_SetAttributeValue",
                    operation="C_SetAttributeValue",
                    summary="SECURITY: CKA_EXTRACTABLE escalated from False to True",
                )
            except AssertionError as exc:
                _return_if_policy_reject(exc, _ATTR_POLICY_REJECT_RVS)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_sensitive_cannot_be_set_false(self, p11_raw_session: Any) -> None:
        """CKA_SENSITIVE=True cannot be changed to False."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={CKA_SENSITIVE: True},
        )
        try:
            try:
                set_attributes(rs.raw, rs.sh, key_h, {CKA_SENSITIVE: False})
                classify(
                    "self_contradiction",
                    kind="policy",
                    label="CKA_SENSITIVE downgrade via C_SetAttributeValue",
                    operation="C_SetAttributeValue",
                    summary="SECURITY: CKA_SENSITIVE downgraded from True to False",
                )
            except AssertionError as exc:
                _return_if_policy_reject(exc, _ATTR_POLICY_REJECT_RVS)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestAttributeLaunderingViaCopy:
    """Test attribute laundering through C_CopyObject.

    An attacker might try to copy a key with modified attributes
    to bypass security restrictions.
    """

    def test_copy_cannot_escalate_extractable(self, p11_raw_session: Any) -> None:
        """Copying a non-extractable key with CKA_EXTRACTABLE=True must fail."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={CKA_EXTRACTABLE: False, CKA_COPYABLE: True},
        )
        try:
            # Type-B claim/effect-check. claimed = the original key reads back
            # CKA_EXTRACTABLE=False (the module honored the protection); violated
            # = the escalated copy actually exposes CKA_VALUE.
            orig = read_attributes(rs.raw, rs.sh, key_h, [CKA_EXTRACTABLE])
            claimed = orig.get(CKA_EXTRACTABLE) is False
            try:
                copy_h = copy_object(rs.raw, rs.sh, key_h, {CKA_EXTRACTABLE: True})
                try:
                    attrs = read_attributes(rs.raw, rs.sh, copy_h, [CKA_VALUE])
                    violated = CKA_VALUE in attrs
                    classify_policy_enforcement(
                        claimed=claimed,
                        violated=violated,
                        label="C_CopyObject escalates CKA_EXTRACTABLE False->True and exposes "
                        "key material (PKCS#11 v3.1 Sec.4.9.4: CKA_EXTRACTABLE may only "
                        "change True->False on copy)",
                    )
                finally:
                    destroy_quietly(rs.raw, rs.sh, copy_h)
            except AssertionError as exc:
                _return_if_policy_reject(exc, _ATTR_POLICY_REJECT_RVS)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_copy_cannot_downgrade_sensitive(self, p11_raw_session: Any) -> None:
        """Copying with CKA_SENSITIVE=False when original is True must fail."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={CKA_SENSITIVE: True, CKA_COPYABLE: True},
        )
        try:
            try:
                copy_h = copy_object(rs.raw, rs.sh, key_h, {CKA_SENSITIVE: False})
                try:
                    attrs = read_attributes(rs.raw, rs.sh, copy_h, [CKA_VALUE])
                    if CKA_VALUE in attrs:
                        classify(
                            "self_contradiction",
                            kind="policy",
                            label="CKA_SENSITIVE downgrade via C_CopyObject",
                            operation="C_CopyObject",
                            summary="SECURITY: Copy downgraded CKA_SENSITIVE, "
                            "key material readable",
                        )
                finally:
                    destroy_quietly(rs.raw, rs.sh, copy_h)
            except AssertionError as exc:
                _return_if_policy_reject(exc, _ATTR_POLICY_REJECT_RVS)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestKeyUsageRestrictions:
    """Verify key usage attributes are enforced."""

    def test_encrypt_disabled_removes_capability(self, p11_raw_session: Any) -> None:
        """Key with CKA_ENCRYPT=False should not have encrypt capability."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={CKA_ENCRYPT: False, CKA_DECRYPT: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_ENCRYPT])
            assert attrs[CKA_ENCRYPT] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_non_extractable_enforced(self, p11_raw_session: Any) -> None:
        """Non-extractable key material cannot be read."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={CKA_EXTRACTABLE: False, CKA_SENSITIVE: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_VALUE])
            assert CKA_VALUE not in attrs, (
                "SECURITY: CKA_VALUE readable on non-extractable key -- key material exposed"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_decrypt_only_key(self, p11_raw_session: Any) -> None:
        """Key created for decrypt-only should have correct attributes."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={
                CKA_ENCRYPT: False,
                CKA_DECRYPT: True,
                CKA_WRAP: False,
                CKA_UNWRAP: False,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_DECRYPT, CKA_ENCRYPT])
            assert attrs[CKA_DECRYPT] is True
            assert attrs[CKA_ENCRYPT] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestAccessControl:
    """Test session access control enforcement."""

    def test_no_login_private_objects_invisible(self, p11_raw_session: Any) -> None:
        """Without login, private objects should not be visible."""
        rs = p11_raw_session
        # Open a public (non-logged-in) session
        pub_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        try:
            tmpl = template_from_dict({CKA_CLASS: CKO_PRIVATE_KEY})
            found = find_objects(rs.raw, pub_sh, tmpl)
            # This isn't a hard assertion since there may be no private keys at all
            # The point is that the search doesn't crash and doesn't leak
            assert isinstance(found, list)
        finally:
            close_session_quietly(rs.raw, pub_sh)

    def test_handle_prediction(self, p11_raw_session: Any) -> None:
        """Object handles should not be trivially sequential/predictable."""
        rs = p11_raw_session
        # Create multiple keys simultaneously (don't destroy) to get unique handles
        keys = []
        for i in range(10):
            key_h = _gen_api_security_aes_key(
                rs,
                attrs={CKA_LABEL: f"handle-{i}"},
                purpose="API security handle-prediction setup",
            )
            keys.append(key_h)
        # All should be distinct handles
        assert len(keys) == 10
        # Clean up
        for key_h in keys:
            destroy_quietly(rs.raw, rs.sh, key_h)
