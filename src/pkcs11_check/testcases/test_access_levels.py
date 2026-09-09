"""SO vs USER vs public access level tests.

Verifies visibility, operational capabilities, and mutual exclusion for
the three PKCS#11 access levels: public (no login), USER, and SO.
Also covers CKA_TRUSTED, CKA_WRAP_WITH_TRUSTED, and CKA_ALWAYS_AUTHENTICATE
enforcement at the access-level boundary.
"""

from __future__ import annotations

from ctypes import byref, c_ubyte
from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    login_user,
)
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.metadata_std import ATTR_NAMES
from pkcs11_check.raw.pack import mech_bytes, mech_simple, template_from_dict
from pkcs11_check.raw.recipes import (
    create_object,
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    find_objects,
    gen_aes_key,
    gen_rsa_keypair,
    generate_random,
    read_attributes,
    set_attributes,
    sign_single,
)
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    expect_rv,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CK_UTF8CHAR,
    CKA_ALWAYS_AUTHENTICATE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_PRIVATE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_TRUSTED,
    CKA_VALUE,
    CKA_WRAP,
    CKA_WRAP_WITH_TRUSTED,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_AES_CBC_PAD,
    CKM_AES_KEY_WRAP,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_PIN_INVALID,
    CKR_PIN_LEN_RANGE,
    CKR_PIN_TOO_WEAK,
    CKR_SESSION_COUNT,
    CKR_SESSION_READ_ONLY,
    CKR_SESSION_READ_ONLY_EXISTS,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TOKEN_NOT_INITIALIZED,
    CKR_TOKEN_WRITE_PROTECTED,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
    CKU_CONTEXT_SPECIFIC,
    CKU_SO,
    CKU_USER,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases._so_login import (
    guard_so_lockout,
    resolve_so_pin,
    skip_if_so_pin_rejected,
    so_session,
)
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    get_pin_bytes,
    is_known_error,
    require_operational_aes_keygen,
    skip_unless_create_object_supported,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.access

_TEMPLATE_ERROR_RVS = (
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_TRUSTED_SETATTR_REJECT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_USER_NOT_LOGGED_IN,
)

_WRAP_WITH_TRUSTED_SETATTR_REJECT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
)

_TRUSTED_CREATE_REJECT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_NOT_LOGGED_IN,
)

_ALWAYS_AUTH_TEMPLATE_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_INIT_PIN_POLICY_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_PIN_INVALID,
    CKR_PIN_LEN_RANGE,
    CKR_PIN_TOO_WEAK,
    CKR_SESSION_READ_ONLY,
    CKR_TOKEN_NOT_INITIALIZED,
    CKR_TOKEN_WRITE_PROTECTED,
)

_INIT_PIN_RUNTIME_REJECT_RVS = (
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_USER_NOT_LOGGED_IN,
)

_ALWAYS_AUTH_EXPECTED_SIGN_REJECT_RVS = (CKR_USER_NOT_LOGGED_IN,)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_bool_attribute(value: Any, *, attr: Any, label: str, mechanism: str | None) -> bool:
    """Validate a present CK_BBOOL readback after the caller handled omission."""
    if value is MISSING_ATTRIBUTE:
        classification.raise_for_record(
            classification.record_as(
                "wrong_result",
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                mechanism=mechanism,
                detail={
                    "attribute": int(attr),
                    "expected_shape": "CK_BBOOL",
                    "actual": "missing",
                },
                summary=f"{label}: missing value reached the boolean validator",
            )
        )
        return False
    if type(value) is bool:
        return value
    classification.raise_for_record(
        classification.record_as(
            "wrong_result",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=mechanism,
            detail={
                "attribute": int(attr),
                "expected_shape": "CK_BBOOL",
                "actual_type": type(value).__name__,
                "actual_repr": repr(value),
            },
            summary=f"{label}: present value has invalid CK_BBOOL shape: {value!r}",
        )
    )
    return False


def _classify_post_success_attribute_error(
    exc: CkrAssertionError,
    *,
    attr: Any,
    label: str,
    producer_operation: str,
    producer_mechanism: str | None,
    terminate: bool = True,
) -> None:
    """Retain a clean readback CKR after the producer already succeeded."""
    attr_id = int(attr)
    handle_invalid = exc.rv == CKR_OBJECT_HANDLE_INVALID
    record = classification.record_as(
        "self_contradiction" if handle_invalid else "not_operational",
        kind="lifecycle" if handle_invalid else "metadata",
        label=label,
        operation="C_GetAttributeValue",
        mechanism=producer_mechanism,
        expected=CKR_OK,
        actual=exc.rv,
        detail={
            "attribute": {
                "name": ATTR_NAMES.get(attr_id, str(attr)),
                "id": attr_id,
            },
            "producer_operation": producer_operation,
            "producer_mechanism": producer_mechanism,
        },
        summary=(
            f"{label}: provider invalidated the produced object handle"
            if handle_invalid
            else f"{label}: post-success attribute read was rejected"
        ),
    )
    if terminate:
        classification.raise_for_record(record)


def _raise_for_undefined_ckr(
    rv: int,
    *,
    label: str,
    operation: str,
    mechanism: str | None,
    expected: object,
    detail: dict[str, Any] | None = None,
) -> None:
    """Fail loudly when a provider returns a value outside the CK_RV space."""
    if is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
        return
    undefined_detail = {"ckr_validity": "undefined"}
    if detail is not None:
        undefined_detail.update(detail)
    classification.classify(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        mechanism=mechanism,
        expected=expected,
        actual=rv,
        detail=undefined_detail,
        summary=f"{label}: provider returned an undefined CK_RV",
    )


def _classify_setter_rejection(
    exc: BaseException,
    *,
    expected_rvs: tuple[Any, ...],
    attr: Any,
    label: str,
) -> None:
    """Retain an unexpected clean setter CKR with exact operation context."""
    if not isinstance(exc, CkrAssertionError):
        raise exc
    if exc.rv in expected_rvs:
        return
    _raise_for_undefined_ckr(
        exc.rv,
        label=label,
        operation="C_SetAttributeValue",
        mechanism=None,
        expected=expected_rvs,
        detail={"attribute": int(attr)},
    )
    classification.classify(
        "nonspec_reject",
        kind="policy",
        label=label,
        operation="C_SetAttributeValue",
        mechanism=None,
        expected=expected_rvs,
        actual=exc.rv,
        detail={
            "attribute": int(attr),
            "producer_operation": "C_SetAttributeValue",
            "producer_mechanism": None,
        },
        summary=f"{label}: provider rejected with a non-spec CKR",
    )


def _classify_operation_rejection(
    exc: BaseException,
    *,
    expected_rvs: tuple[Any, ...],
    label: str,
    operation: str,
    mechanism: str | None,
) -> None:
    """Retain an unexpected clean rejection for an operation with its mechanism."""
    if not isinstance(exc, CkrAssertionError):
        raise exc
    if exc.rv in expected_rvs:
        return
    _raise_for_undefined_ckr(
        exc.rv,
        label=label,
        operation=operation,
        mechanism=mechanism,
        expected=expected_rvs,
    )
    classification.classify(
        "nonspec_reject",
        kind="policy",
        label=label,
        operation=operation,
        mechanism=mechanism,
        expected=expected_rvs,
        actual=exc.rv,
        summary=f"{label}: provider rejected with a non-spec CKR",
    )


def _classify_operation_unavailable(
    exc: BaseException,
    *,
    label: str,
    operation: str,
    mechanism: str | None,
    producer_operation: str | None = None,
    producer_mechanism: str | None = None,
) -> None:
    """Retain a clean CKR from an operation that was expected to succeed."""
    if not isinstance(exc, CkrAssertionError):
        raise exc
    detail: dict[str, Any] = {}
    if producer_operation is not None:
        detail["producer_operation"] = producer_operation
    if producer_mechanism is not None:
        detail["producer_mechanism"] = producer_mechanism
    _raise_for_undefined_ckr(
        exc.rv,
        label=label,
        operation=operation,
        mechanism=mechanism,
        expected=CKR_OK,
        detail=detail,
    )
    classification.classify(
        "not_operational",
        kind="crypto",
        label=label,
        operation=operation,
        mechanism=mechanism,
        expected=CKR_OK,
        actual=exc.rv,
        detail=detail or None,
        summary=f"{label}: provider rejected an operation expected to succeed",
    )


def _classify_negative_operation_rv(
    rv: int,
    *,
    expected_rvs: tuple[Any, ...],
    label: str,
    operation: str,
    mechanism: str | None,
    kind: str | None = None,
    allow_ok: bool = False,
) -> None:
    """Classify a raw negative-operation return with exact call context."""
    if rv == CKR_OK:
        if allow_ok:
            return
        classification.classify(
            "accepted_invalid",
            kind=kind,
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=expected_rvs,
            actual=rv,
            summary=f"{label}: accepted invalid (CKR_OK) -- must reject",
        )
        return
    if rv in expected_rvs:
        return
    _raise_for_undefined_ckr(
        rv,
        label=label,
        operation=operation,
        mechanism=mechanism,
        expected=expected_rvs,
    )
    if is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
        classification.classify(
            "nonspec_reject",
            kind=kind,
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=expected_rvs,
            actual=rv,
            summary=f"{label}: provider rejected with a non-spec CKR",
        )
        return
    classification.classify(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        mechanism=mechanism,
        expected=expected_rvs,
        actual=rv,
        summary=f"{label}: provider returned an undefined CK_RV",
    )


def _login_user_raw(raw: Any, sh: int, pin_bytes: bytes | None) -> None:
    """Login as USER, tolerating already-logged-in at token level."""
    if pin_bytes is None:
        return
    pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
    rv = raw.C_Login(sh, CKU_USER, pin_buf, len(pin_bytes))
    if rv not in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN, CKR_USER_TYPE_INVALID):
        expect_rv(rv, CKR_OK)


def _logout_safe(raw: Any, sh: int) -> None:
    """Logout ignoring not-logged-in or closed-session errors."""
    raw.C_Logout(sh)


def _gen_access_aes_key(rs: Any, sh: int, *, attrs: dict[Any, Any] | None = None) -> int:
    """Generate a setup AES key for access-level tests, preserving provider findings."""
    require_operational_aes_keygen(rs)
    try:
        return gen_aes_key(rs.raw, sh, 128, attrs=attrs)
    except CkrAssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            "AES_KEY_GEN advertised but access-level setup key generation is not operational",
        )
    raise


def _create_access_data_object(rs: Any, sh: int, attrs: dict[Any, Any]) -> int:
    """Create a setup data object for access-level visibility tests."""
    skip_unless_create_object_supported(rs)
    try:
        return create_object(rs.raw, sh, attrs)
    except CkrAssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _TEMPLATE_ERROR_RVS,
            "access-level data object setup rejected by the provider",
        )
    raise


def _open_access_session_or_skip(rs: Any, flags: int) -> int:
    """Open an extra session for access-level scenarios."""
    try:
        return raw_open_session(rs.raw, rs.slot_id, flags)
    except CkrAssertionError as exc:
        if is_known_error(exc, (CKR_SESSION_COUNT,)):
            pytest.skip(
                "Cannot open additional session required by access-level test: "
                f"{ckr_name(int(CKR_SESSION_COUNT))}"
            )
        raise


def _skip_or_xfail_always_auth_keygen_reject(exc: CkrAssertionError) -> None:
    if is_known_error(exc, _ALWAYS_AUTH_TEMPLATE_REJECT_RVS):
        pytest.skip(f"Module does not support CKA_ALWAYS_AUTHENTICATE=True: {exc}")
    xfail_if_known_ckr(
        exc,
        KEYPAIR_RUNTIME_REJECT_RVS,
        "CKA_ALWAYS_AUTHENTICATE RSA keypair setup rejected at runtime",
    )
    raise


# ---------------------------------------------------------------------------
# Public session (no login) visibility
# ---------------------------------------------------------------------------


class TestPublicSessionVisibility:
    """Verify what a public (no-login) session can and cannot see/do."""

    def test_public_sees_non_private_objects(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Public session can see CKA_PRIVATE=False objects."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"pub-vis-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Create a non-private object while logged in
        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            _create_access_data_object(
                rs,
                s1,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                    CKA_VALUE: b"public-data",
                    CKA_TOKEN: True,
                    CKA_PRIVATE: False,
                },
            )
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

        # Open public session (no login) and check visibility
        pub_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        try:
            tmpl = template_from_dict(
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                }
            )
            found = find_objects(rs.raw, pub_sh, tmpl)
            if len(found) == 0:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "CKA_PRIVATE=False object not visible in public session",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec: public objects visible without login",
                )
        finally:
            close_session_quietly(rs.raw, pub_sh)

        # Cleanup
        cleanup_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, cleanup_sh, pin_bytes)
            tmpl2 = template_from_dict(
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                }
            )
            for h in find_objects(rs.raw, cleanup_sh, tmpl2):
                destroy_quietly(rs.raw, cleanup_sh, h)
        finally:
            _logout_safe(rs.raw, cleanup_sh)
            close_session_quietly(rs.raw, cleanup_sh)

    def test_public_cannot_see_private_objects(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Public session cannot see CKA_PRIVATE=True objects."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"priv-invis-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Create a private token object while logged in
        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            _gen_access_aes_key(
                rs,
                s1,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
            )
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

        # Open public session - private objects must not be visible
        pub_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        try:
            tmpl = template_from_dict(
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_LABEL: label,
                }
            )
            found = find_objects(rs.raw, pub_sh, tmpl)
            assert len(found) == 0, "CKA_PRIVATE=True object visible in public session"
        finally:
            close_session_quietly(rs.raw, pub_sh)

        # Cleanup
        cleanup_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, cleanup_sh, pin_bytes)
            for h in find_objects(rs.raw, cleanup_sh, template_from_dict({CKA_LABEL: label})):
                destroy_quietly(rs.raw, cleanup_sh, h)
        finally:
            _logout_safe(rs.raw, cleanup_sh)
            close_session_quietly(rs.raw, cleanup_sh)

    def test_public_session_can_digest(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Public session can perform digest operations (no login needed)."""
        rs = p11_raw_session
        pub_sh = _open_access_session_or_skip(rs, CKF_SERIAL_SESSION)
        try:
            digest = digest_single(rs.raw, pub_sh, CKM_SHA256, b"public digest")
            assert len(digest) == 32
        finally:
            close_session_quietly(rs.raw, pub_sh)

    def test_public_session_can_generate_random(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Public session can generate random (no login needed)."""
        rs = p11_raw_session
        pub_sh = _open_access_session_or_skip(rs, CKF_SERIAL_SESSION)
        try:
            rand = generate_random(rs.raw, pub_sh, 16)
            assert len(rand) == 16  # 128 bits = 16 bytes
        finally:
            close_session_quietly(rs.raw, pub_sh)


# ---------------------------------------------------------------------------
# USER session visibility and capabilities
# ---------------------------------------------------------------------------


class TestUserSessionCapabilities:
    """Verify USER session access level."""

    def test_user_sees_private_objects(self, p11_raw_session: Any, p11_config: Any) -> None:
        """USER session sees CKA_PRIVATE=True objects."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"user-priv-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            key_h = _gen_access_aes_key(
                rs,
                s1,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
            )
            assert key_h != 0

            # Verify visible in same session
            tmpl = template_from_dict({CKA_LABEL: label})
            found = find_objects(rs.raw, s1, tmpl)
            assert len(found) >= 1, "Private object not visible in USER session"

            # Cleanup
            for h in found:
                destroy_quietly(rs.raw, s1, h)
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

    def test_user_sees_non_private_objects(self, p11_raw_session: Any, p11_config: Any) -> None:
        """USER session also sees CKA_PRIVATE=False objects."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"user-pub-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            _create_access_data_object(
                rs,
                s1,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                    CKA_VALUE: b"pub-data",
                    CKA_TOKEN: True,
                    CKA_PRIVATE: False,
                },
            )
            tmpl = template_from_dict(
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                }
            )
            found = find_objects(rs.raw, s1, tmpl)
            assert len(found) >= 1, "Public object not visible in USER session"
            for h in find_objects(rs.raw, s1, tmpl):
                destroy_quietly(rs.raw, s1, h)
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

    def test_user_can_create_and_destroy_objects(self, p11_raw_session: Any) -> None:
        """USER session can create and destroy objects."""
        rs = p11_raw_session
        key_h = _gen_access_aes_key(
            rs,
            rs.sh,
            attrs={CKA_TOKEN: False, CKA_LABEL: "user-create-test"},
        )
        assert key_h != 0
        destroy_quietly(rs.raw, rs.sh, key_h)

    def test_user_can_encrypt_decrypt(self, p11_raw_session: Any) -> None:
        """USER session can perform crypto operations on private keys."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_PAD"):
            pytest.skip("CKM_AES_CBC_PAD not supported")

        key_h = _gen_access_aes_key(
            rs,
            rs.sh,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_PRIVATE: True,
            },
        )
        try:
            iv = b"\x00" * 16
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key_h,
                CKM_AES_CBC_PAD,
                b"sixteen byte msg",
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key_h,
                CKM_AES_CBC_PAD,
                ct,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            assert pt == b"sixteen byte msg"
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_user_cannot_login_as_so(self, p11_raw_session: Any, p11_config: Any) -> None:
        """USER session cannot switch to SO login."""
        so_pin, explicit = resolve_so_pin(p11_config)
        if so_pin is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        guard_so_lockout(rs.raw, rs.slot_id, explicit=explicit)
        pin_buf = (CK_UTF8CHAR * len(so_pin))(*so_pin)
        rv = rs.raw.C_Login(rs.sh, CKU_SO, pin_buf, len(so_pin))
        skip_if_so_pin_rejected(rv, explicit=explicit)
        _classify_negative_operation_rv(
            rv,
            expected_rvs=(CKR_USER_ANOTHER_ALREADY_LOGGED_IN,),
            label="C_Login(SO) while a USER session is logged in",
            operation="C_Login",
            mechanism=None,
        )


# ---------------------------------------------------------------------------
# SO session capabilities
# ---------------------------------------------------------------------------


class TestSOSessionCapabilities:
    """Verify SO access level capabilities.

    All tests marked @destructive because SO login may affect token state.
    """

    @pytest.mark.destructive
    def test_so_login_succeeds_on_rw_session(self, p11_raw_session: Any, p11_config: Any) -> None:
        """SO login succeeds on RW session when no USER is logged in."""
        user_pin = get_pin_bytes(p11_config)
        if user_pin is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        with so_session(rs, p11_config) as s1:
            # Verify SO is logged in by attempting USER login (should fail)
            pin_buf = (CK_UTF8CHAR * len(user_pin))(*user_pin)
            rv2 = rs.raw.C_Login(s1, CKU_USER, pin_buf, len(user_pin))
            _classify_negative_operation_rv(
                rv2,
                expected_rvs=(
                    CKR_USER_ALREADY_LOGGED_IN,
                    CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
                    CKR_USER_TYPE_INVALID,
                ),
                label="C_Login(USER) while SO is logged in",
                operation="C_Login",
                mechanism=None,
                kind="policy",
            )

    @pytest.mark.destructive
    def test_so_can_init_pin(self, p11_raw_session: Any, p11_config: Any) -> None:
        """SO session can set USER PIN via C_InitPIN (or skip if unsupported)."""
        from pkcs11_check.raw.recipes import init_pin, set_pin

        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION
        new_pin = pin_bytes + b"X"

        entered = False
        try:
            with so_session(rs, p11_config) as s1:
                entered = True
                try:
                    init_pin(rs.raw, s1, new_pin)
                except CkrAssertionError as exc:
                    if is_known_error(exc, _INIT_PIN_POLICY_REJECT_RVS):
                        pytest.skip(f"C_InitPIN not usable with configured token policy: {exc}")
                    xfail_if_known_ckr(
                        exc,
                        _INIT_PIN_RUNTIME_REJECT_RVS,
                        "C_InitPIN rejected valid SO PIN setup",
                    )
                    raise  # unreachable
        finally:
            if entered:
                # Restore original PIN: login USER with new PIN, set back
                restore_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
                try:
                    login_user(rs.raw, restore_sh, CKU_USER, new_pin)
                    set_pin(rs.raw, restore_sh, new_pin, pin_bytes)
                finally:
                    _logout_safe(rs.raw, restore_sh)
                    close_session_quietly(rs.raw, restore_sh)

    @pytest.mark.destructive
    def test_so_cannot_use_private_crypto_keys(self, p11_raw_session: Any, p11_config: Any) -> None:
        """SO session should not be able to use private crypto keys."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_PAD"):
            pytest.skip("CKM_AES_CBC_PAD not supported")
        label = f"so-no-crypto-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Create a private key while logged in as USER
        user_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, user_sh, pin_bytes)
            _gen_access_aes_key(
                rs,
                user_sh,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: True,
                    CKA_ENCRYPT: True,
                    CKA_LABEL: label,
                },
            )
        finally:
            _logout_safe(rs.raw, user_sh)
            close_session_quietly(rs.raw, user_sh)

        try:
            with so_session(rs, p11_config) as so_sh:
                tmpl = template_from_dict({CKA_LABEL: label})
                found = find_objects(rs.raw, so_sh, tmpl)
                if len(found) == 0:
                    # SO cannot see private keys - expected per spec
                    pass
                else:
                    # SO can see the key; some modules allow this
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "SO session can see CKA_PRIVATE=True USER objects",
                        ComplianceLevel.VENDOR,
                        reference="PKCS#11 spec: SO should not access user private objects",
                    )
        finally:
            # Cleanup the key (also on the so_session skip paths)
            cleanup_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
            try:
                _login_user_raw(rs.raw, cleanup_sh, pin_bytes)
                for h in find_objects(rs.raw, cleanup_sh, template_from_dict({CKA_LABEL: label})):
                    destroy_quietly(rs.raw, cleanup_sh, h)
            finally:
                _logout_safe(rs.raw, cleanup_sh)
                close_session_quietly(rs.raw, cleanup_sh)

    @pytest.mark.destructive
    def test_so_user_mutual_exclusion(self, p11_raw_session: Any, p11_config: Any) -> None:
        """SO and USER cannot be logged in simultaneously on the same token."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        with so_session(rs, p11_config):
            # Try USER login on a second session - should fail (login is token-wide)
            s2 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
            try:
                pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
                rv2 = rs.raw.C_Login(s2, CKU_USER, pin_buf, len(pin_bytes))
                _classify_negative_operation_rv(
                    rv2,
                    expected_rvs=(
                        CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
                        CKR_USER_ALREADY_LOGGED_IN,
                        CKR_USER_TYPE_INVALID,
                    ),
                    label="C_Login(USER) while SO is logged in",
                    operation="C_Login",
                    mechanism=None,
                    kind="policy",
                )
            finally:
                close_session_quietly(rs.raw, s2)


# ---------------------------------------------------------------------------
# CKA_TRUSTED enforcement
# ---------------------------------------------------------------------------


class TestTrustedAttribute:
    """CKA_TRUSTED enforcement at the access-level boundary."""

    @pytest.mark.destructive
    def test_so_can_set_trusted(self, p11_raw_session: Any, p11_config: Any) -> None:
        """SO session can set CKA_TRUSTED=True on a key (or skip)."""
        rs = p11_raw_session
        with so_session(rs, p11_config) as s1:
            try:
                key_h = _gen_access_aes_key(
                    rs,
                    s1,
                    attrs={
                        CKA_TOKEN: False,
                        CKA_WRAP: True,
                        CKA_TRUSTED: True,
                    },
                )
            except CkrAssertionError as e:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"Module does not support CKA_TRUSTED: {e}",
                    ComplianceLevel.VENDOR,
                    reference="PKCS#11 spec: CKA_TRUSTED set by SO",
                )
                if is_known_error(e, {CKR_ATTRIBUTE_TYPE_INVALID}):
                    pytest.skip(f"CKA_TRUSTED not supported: {e}")
                raise

            try:
                try:
                    attrs = read_attributes(rs.raw, s1, key_h, [CKA_TRUSTED])
                    val = attr_or_record(
                        attrs,
                        CKA_TRUSTED,
                        label="SO:create-CKA_TRUSTED readback",
                        mechanism="CKM_AES_KEY_GEN",
                    )
                except CkrAssertionError as e:
                    _classify_post_success_attribute_error(
                        e,
                        attr=CKA_TRUSTED,
                        label="SO:create-CKA_TRUSTED readback",
                        producer_operation="C_GenerateKey",
                        producer_mechanism="CKM_AES_KEY_GEN",
                    )
                    return
                if val is MISSING_ATTRIBUTE:
                    return
                _require_bool_attribute(
                    val,
                    attr=CKA_TRUSTED,
                    label="SO:create-CKA_TRUSTED readback",
                    mechanism="CKM_AES_KEY_GEN",
                )
                if val is not True:
                    fail_as(
                        "wrong_result",
                        kind="policy",
                        label="SO:create-CKA_TRUSTED",
                        operation="C_GenerateKey",
                        mechanism="CKM_AES_KEY_GEN",
                        expected=CKR_OK,
                        actual=CKR_OK,
                        detail={
                            "attribute": int(CKA_TRUSTED),
                            "expected": True,
                            "actual": val,
                            "producer_operation": "C_GenerateKey",
                            "producer_mechanism": "CKM_AES_KEY_GEN",
                        },
                        summary=(
                            "SO C_GenerateKey returned CKR_OK but did not preserve CKA_TRUSTED=True"
                        ),
                    )
            finally:
                destroy_quietly(rs.raw, s1, key_h)

    def test_user_cannot_set_trusted(self, p11_raw_session: Any) -> None:
        """USER session must not be able to gen a key with CKA_TRUSTED=True.

        Per PKCS#11 v3.2, only the SO can mark a key as TRUSTED.
        A USER session creating a TRUSTED=True key bypasses the SO trust
        boundary used by CKA_WRAP_WITH_TRUSTED to gate sensitive wraps.
        """
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        try:
            key_h = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={
                    CKA_TOKEN: False,
                    CKA_WRAP: True,
                    CKA_TRUSTED: True,
                },
            )
        except CkrAssertionError as exc:
            _classify_operation_rejection(
                exc,
                expected_rvs=_TRUSTED_CREATE_REJECT_RVS,
                label="C_GenerateKey CKA_TRUSTED=True from a USER session",
                operation="C_GenerateKey",
                mechanism="CKM_AES_KEY_GEN",
            )
            return

        # If we get here, module allowed creating a CKA_TRUSTED key from a
        # USER session — confirm the security boundary violation from the
        # provider's readback before emitting the terminal finding.
        try:
            # Read back to confirm the violation rather than just trust the
            # gen success — some modules silently drop the attribute.
            try:
                attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_TRUSTED])
            except CkrAssertionError as e:
                _classify_post_success_attribute_error(
                    e,
                    attr=CKA_TRUSTED,
                    label="USER:create-CKA_TRUSTED readback",
                    producer_operation="C_GenerateKey",
                    producer_mechanism="CKM_AES_KEY_GEN",
                )
                return
            val = attr_or_record(
                attrs,
                CKA_TRUSTED,
                label="USER:create-CKA_TRUSTED readback",
                mechanism="CKM_AES_KEY_GEN",
            )
            if val is MISSING_ATTRIBUTE:
                return
            _require_bool_attribute(
                val,
                attr=CKA_TRUSTED,
                label="USER:create-CKA_TRUSTED readback",
                mechanism="CKM_AES_KEY_GEN",
            )
            if val is True:
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label="USER:create-CKA_TRUSTED",
                    operation="C_GenerateKey",
                    mechanism="CKM_AES_KEY_GEN",
                    expected=_TRUSTED_CREATE_REJECT_RVS,
                    actual=CKR_OK,
                    detail={
                        "attribute": int(CKA_TRUSTED),
                        "expected": True,
                        "actual": val,
                        "producer_operation": "C_GenerateKey",
                        "producer_mechanism": "CKM_AES_KEY_GEN",
                    },
                    summary=(
                        "SECURITY: USER session created and was granted "
                        "CKA_TRUSTED=True on a freshly-generated key — "
                        "trust boundary breached"
                    ),
                )
            xfail_as(
                "honest_deviation",
                kind="policy",
                label="USER:create-CKA_TRUSTED-dropped",
                operation="C_GenerateKey",
                mechanism="CKM_AES_KEY_GEN",
                expected=CKR_OK,
                actual=CKR_OK,
                detail={
                    "attribute": int(CKA_TRUSTED),
                    "expected": True,
                    "actual": val,
                    "producer_operation": "C_GenerateKey",
                    "producer_mechanism": "CKM_AES_KEY_GEN",
                },
                summary=(
                    "USER C_GenerateKey accepted CKA_TRUSTED=True but the provider "
                    "did not grant the requested trust attribute"
                ),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_user_cannot_setattr_trusted(self, p11_raw_session: Any) -> None:
        """USER session must not be able to set CKA_TRUSTED=True on an
        existing TRUSTED=False key via C_SetAttributeValue.

        Closes Phase 4.5 GAP-T5 (HIGH-side coverage — the create-time
        case is covered by test_user_cannot_set_trusted; the
        SetAttributeValue path was missing).
        """
        rs = p11_raw_session
        # First generate a key without CKA_TRUSTED to avoid colliding with
        # modules that reject TRUSTED in templates entirely.
        key_h = _gen_access_aes_key(
            rs,
            rs.sh,
            attrs={CKA_TOKEN: False, CKA_WRAP: True},
        )

        try:
            # Pre-check: the key must exist and be readable.
            initial_read_available = True
            try:
                attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_TRUSTED])
            except CkrAssertionError as e:
                _classify_post_success_attribute_error(
                    e,
                    attr=CKA_TRUSTED,
                    label="USER:setattr-CKA_TRUSTED initial readback",
                    producer_operation="C_GenerateKey",
                    producer_mechanism="CKM_AES_KEY_GEN",
                    terminate=e.rv == CKR_OBJECT_HANDLE_INVALID,
                )
                initial_read_available = False
            if initial_read_available:
                val = attr_or_record(
                    attrs,
                    CKA_TRUSTED,
                    label="USER:setattr-CKA_TRUSTED initial readback",
                    mechanism="CKM_AES_KEY_GEN",
                )
                if val is not MISSING_ATTRIBUTE:
                    _require_bool_attribute(
                        val,
                        attr=CKA_TRUSTED,
                        label="USER:setattr-CKA_TRUSTED initial readback",
                        mechanism="CKM_AES_KEY_GEN",
                    )
                    if val is True:
                        fail_as(
                            "self_contradiction",
                            kind="policy",
                            label="USER:create-CKA_TRUSTED-default",
                            operation="C_GenerateKey",
                            mechanism="CKM_AES_KEY_GEN",
                            expected=_TRUSTED_CREATE_REJECT_RVS,
                            actual=CKR_OK,
                            detail={
                                "attribute": int(CKA_TRUSTED),
                                "expected": False,
                                "actual": True,
                                "producer_operation": "C_GenerateKey",
                                "producer_mechanism": "CKM_AES_KEY_GEN",
                            },
                            summary=(
                                "USER C_GenerateKey returned a key with CKA_TRUSTED=True "
                                "by default; only the SO may grant trust"
                            ),
                        )

            # Attempt the escalation.
            try:
                set_attributes(rs.raw, rs.sh, key_h, {CKA_TRUSTED: True})
            except CkrAssertionError as e:
                _classify_setter_rejection(
                    e,
                    expected_rvs=_TRUSTED_SETATTR_REJECT_RVS,
                    attr=CKA_TRUSTED,
                    label="C_SetAttributeValue CKA_TRUSTED=True from a USER session",
                )
                return

            # SetAttribute returned CKR_OK — confirm whether the change
            # actually took effect (some modules silently no-op).
            try:
                attrs2 = read_attributes(rs.raw, rs.sh, key_h, [CKA_TRUSTED])
            except CkrAssertionError as exc:
                _classify_post_success_attribute_error(
                    exc,
                    attr=CKA_TRUSTED,
                    label="USER:setattr-CKA_TRUSTED final readback",
                    producer_operation="C_SetAttributeValue",
                    producer_mechanism=None,
                )
                return
            val2 = attr_or_record(
                attrs2,
                CKA_TRUSTED,
                label="USER:setattr-CKA_TRUSTED final readback",
                mechanism=None,
            )
            if val2 is MISSING_ATTRIBUTE:
                return
            _require_bool_attribute(
                val2,
                attr=CKA_TRUSTED,
                label="USER:setattr-CKA_TRUSTED final readback",
                mechanism=None,
            )
            if val2 is True:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "USER session escalated CKA_TRUSTED=False → True via "
                    "C_SetAttributeValue (should require SO)",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.2: CKA_TRUSTED set by SO only",
                )
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label="USER:setattr-CKA_TRUSTED",
                    operation="C_SetAttributeValue",
                    mechanism=None,
                    expected=_TRUSTED_SETATTR_REJECT_RVS,
                    actual=CKR_OK,
                    detail={
                        "attribute": int(CKA_TRUSTED),
                        "expected": False,
                        "actual": True,
                        "producer_operation": "C_SetAttributeValue",
                        "producer_mechanism": None,
                    },
                    summary=(
                        "SECURITY: USER session escalated a key's CKA_TRUSTED "
                        "from False to True via C_SetAttributeValue — trust "
                        "boundary breached, opens CKA_WRAP_WITH_TRUSTED bypass"
                    ),
                )
            xfail_as(
                "honest_deviation",
                kind="lifecycle",
                label="USER:setattr-CKA_TRUSTED-noop",
                operation="C_SetAttributeValue",
                mechanism=None,
                expected=CKR_OK,
                actual=CKR_OK,
                detail={
                    "attribute": int(CKA_TRUSTED),
                    "expected": False,
                    "actual": val2,
                    "producer_operation": "C_SetAttributeValue",
                    "producer_mechanism": None,
                },
                summary=(
                    "C_SetAttributeValue returned CKR_OK for CKA_TRUSTED=True "
                    "but the provider left the attribute unchanged"
                ),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_wrap_with_trusted_cannot_be_cleared_once_true(self, p11_raw_session: Any) -> None:
        """CKA_WRAP_WITH_TRUSTED can only move toward stricter wrapping policy."""
        rs = p11_raw_session
        try:
            target_h = _gen_access_aes_key(
                rs,
                rs.sh,
                attrs={
                    CKA_WRAP_WITH_TRUSTED: True,
                    CKA_TOKEN: False,
                },
            )
        except CkrAssertionError as exc:
            if is_known_error(exc, {CKR_ATTRIBUTE_TYPE_INVALID}):
                pytest.skip(f"CKA_WRAP_WITH_TRUSTED not supported: {exc}")
            xfail_if_known_ckr(
                exc,
                AES_KEYGEN_RUNTIME_REJECT_RVS,
                "CKA_WRAP_WITH_TRUSTED setup key generation is not operational",
            )
            raise

        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, target_h, [CKA_WRAP_WITH_TRUSTED])
            except CkrAssertionError as exc:
                _classify_post_success_attribute_error(
                    exc,
                    attr=CKA_WRAP_WITH_TRUSTED,
                    label="CKA_WRAP_WITH_TRUSTED setup readback",
                    producer_operation="C_GenerateKey",
                    producer_mechanism="CKM_AES_KEY_GEN",
                )
                return
            val = attr_or_record(
                attrs,
                CKA_WRAP_WITH_TRUSTED,
                label="CKA_WRAP_WITH_TRUSTED setup readback",
                mechanism="CKM_AES_KEY_GEN",
            )
            if val is MISSING_ATTRIBUTE:
                return
            _require_bool_attribute(
                val,
                attr=CKA_WRAP_WITH_TRUSTED,
                label="CKA_WRAP_WITH_TRUSTED setup readback",
                mechanism="CKM_AES_KEY_GEN",
            )
            if val is not True:
                fail_as(
                    "wrong_result",
                    kind="policy",
                    label="CKA_WRAP_WITH_TRUSTED setup",
                    operation="C_GenerateKey",
                    mechanism="CKM_AES_KEY_GEN",
                    expected=CKR_OK,
                    actual=CKR_OK,
                    detail={
                        "attribute": int(CKA_WRAP_WITH_TRUSTED),
                        "expected": True,
                        "actual": val,
                        "producer_operation": "C_GenerateKey",
                        "producer_mechanism": "CKM_AES_KEY_GEN",
                    },
                    summary=(
                        "C_GenerateKey returned CKR_OK but did not preserve "
                        "CKA_WRAP_WITH_TRUSTED=True"
                    ),
                )

            try:
                set_attributes(rs.raw, rs.sh, target_h, {CKA_WRAP_WITH_TRUSTED: False})
            except CkrAssertionError as exc:
                _classify_setter_rejection(
                    exc,
                    expected_rvs=_WRAP_WITH_TRUSTED_SETATTR_REJECT_RVS,
                    attr=CKA_WRAP_WITH_TRUSTED,
                    label="C_SetAttributeValue CKA_WRAP_WITH_TRUSTED=True->False",
                )
                return

            try:
                after = read_attributes(rs.raw, rs.sh, target_h, [CKA_WRAP_WITH_TRUSTED])
            except CkrAssertionError as exc:
                _classify_post_success_attribute_error(
                    exc,
                    attr=CKA_WRAP_WITH_TRUSTED,
                    label="CKA_WRAP_WITH_TRUSTED downgrade readback",
                    producer_operation="C_SetAttributeValue",
                    producer_mechanism=None,
                )
                return
            after_val = attr_or_record(
                after,
                CKA_WRAP_WITH_TRUSTED,
                label="CKA_WRAP_WITH_TRUSTED downgrade readback",
                mechanism=None,
            )
            if after_val is MISSING_ATTRIBUTE:
                return
            _require_bool_attribute(
                after_val,
                attr=CKA_WRAP_WITH_TRUSTED,
                label="CKA_WRAP_WITH_TRUSTED downgrade readback",
                mechanism=None,
            )
            if after_val is False:
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label="CKA_WRAP_WITH_TRUSTED:downgrade",
                    operation="C_SetAttributeValue",
                    mechanism=None,
                    expected=_WRAP_WITH_TRUSTED_SETATTR_REJECT_RVS,
                    actual=CKR_OK,
                    detail={
                        "attribute": int(CKA_WRAP_WITH_TRUSTED),
                        "expected": True,
                        "actual": False,
                        "producer_operation": "C_SetAttributeValue",
                        "producer_mechanism": None,
                    },
                    summary=(
                        "SECURITY: CKA_WRAP_WITH_TRUSTED downgraded from True to False "
                        "via C_SetAttributeValue"
                    ),
                )
            xfail_as(
                "honest_deviation",
                kind="lifecycle",
                label="CKA_WRAP_WITH_TRUSTED:setattr-noop",
                operation="C_SetAttributeValue",
                mechanism=None,
                expected=CKR_OK,
                actual=CKR_OK,
                detail={
                    "attribute": int(CKA_WRAP_WITH_TRUSTED),
                    "expected": True,
                    "actual": after_val,
                    "producer_operation": "C_SetAttributeValue",
                    "producer_mechanism": None,
                },
                summary=(
                    "C_SetAttributeValue returned CKR_OK for CKA_WRAP_WITH_TRUSTED "
                    "True->False but left the stricter value unchanged"
                ),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, target_h)

    def test_wrap_with_trusted_rejects_untrusted(self, p11_raw_session: Any) -> None:
        """Without CKA_TRUSTED, wrapping a CKA_WRAP_WITH_TRUSTED key fails."""
        rs = p11_raw_session

        try:
            target_h = _gen_access_aes_key(
                rs,
                rs.sh,
                attrs={
                    CKA_EXTRACTABLE: True,
                    CKA_WRAP_WITH_TRUSTED: True,
                    CKA_TOKEN: False,
                },
            )
        except CkrAssertionError as e:
            if is_known_error(e, {CKR_ATTRIBUTE_TYPE_INVALID}):
                pytest.skip(f"CKA_WRAP_WITH_TRUSTED not supported: {e}")
            xfail_if_known_ckr(
                e,
                AES_KEYGEN_RUNTIME_REJECT_RVS,
                "CKA_WRAP_WITH_TRUSTED setup key generation is not operational",
            )
            raise

        wrapper_h: int | None = None
        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, target_h, [CKA_WRAP_WITH_TRUSTED])
                val = attr_or_record(
                    attrs,
                    CKA_WRAP_WITH_TRUSTED,
                    label="CKA_WRAP_WITH_TRUSTED enforcement setup readback",
                    mechanism="CKM_AES_KEY_GEN",
                )
            except CkrAssertionError as exc:
                _classify_post_success_attribute_error(
                    exc,
                    attr=CKA_WRAP_WITH_TRUSTED,
                    label="CKA_WRAP_WITH_TRUSTED enforcement setup readback",
                    producer_operation="C_GenerateKey",
                    producer_mechanism="CKM_AES_KEY_GEN",
                )
                return

            if val is MISSING_ATTRIBUTE:
                return
            _require_bool_attribute(
                val,
                attr=CKA_WRAP_WITH_TRUSTED,
                label="CKA_WRAP_WITH_TRUSTED enforcement setup readback",
                mechanism="CKM_AES_KEY_GEN",
            )
            if val is not True:
                fail_as(
                    "wrong_result",
                    kind="policy",
                    label="CKA_WRAP_WITH_TRUSTED setup",
                    operation="C_GenerateKey",
                    mechanism="CKM_AES_KEY_GEN",
                    expected=CKR_OK,
                    actual=CKR_OK,
                    detail={
                        "attribute": int(CKA_WRAP_WITH_TRUSTED),
                        "expected": True,
                        "actual": val,
                        "producer_operation": "C_GenerateKey",
                        "producer_mechanism": "CKM_AES_KEY_GEN",
                    },
                    summary=(
                        "C_GenerateKey returned CKR_OK but did not preserve "
                        "CKA_WRAP_WITH_TRUSTED=True"
                    ),
                )

            # Create a normal (non-TRUSTED) wrapping key.
            wrapper_h = _gen_access_aes_key(
                rs,
                rs.sh,
                attrs={CKA_WRAP: True, CKA_TOKEN: False},
            )
            if rs.has_mechanism("AES_KEY_WRAP"):
                mech_name = "CKM_AES_KEY_WRAP"
                mech = mech_simple(CKM_AES_KEY_WRAP)
            elif rs.has_mechanism("AES_CBC_PAD"):
                mech_name = "CKM_AES_CBC_PAD"
                mech = mech_bytes(CKM_AES_CBC_PAD, b"\x00" * 16)
            else:
                pytest.skip("No AES wrap mechanism available")
            # Drive the full wrap (size query, then a real output buffer) so a
            # module that enforces the WRAP_WITH_TRUSTED policy only on the actual
            # wrap is exercised, not just the size query.  A successful size query
            # alone is not a policy bypass: only a successful final call with
            # non-empty output exports the target.
            out_len = CK_ULONG(0)
            label = "C_WrapKey of a CKA_WRAP_WITH_TRUSTED key with an untrusted wrapping key"
            expected_wrap_reject_rvs = (CKR_ACTION_PROHIBITED, CKR_KEY_NOT_WRAPPABLE)
            size_rv = rs.raw.C_WrapKey(
                rs.sh, mech.byref(), wrapper_h, target_h, None, byref(out_len)
            )
            if size_rv not in (CKR_OK, CKR_BUFFER_TOO_SMALL):
                _classify_negative_operation_rv(
                    size_rv,
                    expected_rvs=expected_wrap_reject_rvs,
                    label=f"{label}: size query",
                    operation="C_WrapKey",
                    mechanism=mech_name,
                    kind="policy",
                )
            elif out_len.value == 0:
                classification.classify(
                    "wrong_result",
                    kind="metadata",
                    label=f"{label}: size query returned zero output length",
                    operation="C_WrapKey",
                    mechanism=mech_name,
                    detail={
                        "attribute": int(CKA_WRAP_WITH_TRUSTED),
                        "phase": "size_query",
                        "expected": "positive output length",
                        "actual": 0,
                        "producer_operation": "C_GenerateKey",
                        "producer_mechanism": "CKM_AES_KEY_GEN",
                    },
                    summary=(
                        f"{label}: CKR_OK/CKR_BUFFER_TOO_SMALL did not provide "
                        "a wrapped-output length"
                    ),
                )
            else:
                buf = (c_ubyte * out_len.value)()
                final_rv = rs.raw.C_WrapKey(
                    rs.sh, mech.byref(), wrapper_h, target_h, buf, byref(out_len)
                )
                if final_rv == CKR_OK and out_len.value == 0:
                    classification.classify(
                        "wrong_result",
                        kind="crypto",
                        label=f"{label}: final call returned empty output",
                        operation="C_WrapKey",
                        mechanism=mech_name,
                        detail={
                            "attribute": int(CKA_WRAP_WITH_TRUSTED),
                            "phase": "final",
                            "expected": "non-empty wrapped output",
                            "actual_length": 0,
                            "producer_operation": "C_GenerateKey",
                            "producer_mechanism": "CKM_AES_KEY_GEN",
                        },
                        summary=(
                            f"{label}: final C_WrapKey returned CKR_OK but "
                            "produced no wrapped bytes"
                        ),
                    )
                if final_rv == CKR_OK:
                    classification.classify(
                        "self_contradiction",
                        kind="policy",
                        label=label,
                        operation="C_WrapKey",
                        mechanism=mech_name,
                        expected=expected_wrap_reject_rvs,
                        actual=final_rv,
                        detail={
                            "attribute": int(CKA_WRAP_WITH_TRUSTED),
                            "expected": True,
                            "actual": False,
                            "output_length": out_len.value,
                            "producer_operation": "C_GenerateKey",
                            "producer_mechanism": "CKM_AES_KEY_GEN",
                        },
                        summary=(
                            f"{label}: accepted an untrusted wrapper despite "
                            "CKA_WRAP_WITH_TRUSTED=True"
                        ),
                    )
                _classify_negative_operation_rv(
                    final_rv,
                    expected_rvs=expected_wrap_reject_rvs,
                    label=f"{label}: final call",
                    operation="C_WrapKey",
                    mechanism=mech_name,
                    kind="policy",
                )
        finally:
            if wrapper_h is not None:
                destroy_quietly(rs.raw, rs.sh, wrapper_h)
            destroy_quietly(rs.raw, rs.sh, target_h)


# ---------------------------------------------------------------------------
# CKA_ALWAYS_AUTHENTICATE
# ---------------------------------------------------------------------------


class TestAlwaysAuthenticate:
    """CKA_ALWAYS_AUTHENTICATE - context-specific re-authentication."""

    def test_always_authenticate_key_requires_reauth(self, p11_raw_session: Any) -> None:
        """Key with CKA_ALWAYS_AUTHENTICATE=True requires context-specific login."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        try:
            pub_h, priv_h = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                private_attrs={
                    CKA_SIGN: True,
                    CKA_ALWAYS_AUTHENTICATE: True,
                    CKA_TOKEN: False,
                },
            )
        except CkrAssertionError as e:
            _skip_or_xfail_always_auth_keygen_reject(e)

        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, priv_h, [CKA_ALWAYS_AUTHENTICATE])
                val = attr_or_record(
                    attrs,
                    CKA_ALWAYS_AUTHENTICATE,
                    label="CKA_ALWAYS_AUTHENTICATE setup readback",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                )
            except CkrAssertionError as e:
                _classify_post_success_attribute_error(
                    e,
                    attr=CKA_ALWAYS_AUTHENTICATE,
                    label="CKA_ALWAYS_AUTHENTICATE setup readback",
                    producer_operation="C_GenerateKeyPair",
                    producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                )
                return
            if val is MISSING_ATTRIBUTE:
                return
            _require_bool_attribute(
                val,
                attr=CKA_ALWAYS_AUTHENTICATE,
                label="CKA_ALWAYS_AUTHENTICATE setup readback",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            if val is not True:
                fail_as(
                    "wrong_result",
                    kind="policy",
                    label="CKA_ALWAYS_AUTHENTICATE setup",
                    operation="C_GenerateKeyPair",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    expected=CKR_OK,
                    actual=CKR_OK,
                    detail={
                        "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                        "expected": True,
                        "actual": val,
                        "producer_operation": "C_GenerateKeyPair",
                        "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                    },
                    summary=(
                        "C_GenerateKeyPair returned CKR_OK but did not preserve "
                        "CKA_ALWAYS_AUTHENTICATE=True"
                    ),
                )

            # Attempt to sign - should require context-specific login
            data = b"test data for always-auth"
            try:
                sig = sign_single(rs.raw, rs.sh, priv_h, CKM_SHA256_RSA_PKCS, data)
                if len(sig) == 0:
                    fail_as(
                        "wrong_result",
                        kind="crypto",
                        label="CKA_ALWAYS_AUTHENTICATE:first-sign-empty-output",
                        operation="C_Sign",
                        mechanism="CKM_SHA256_RSA_PKCS",
                        detail={
                            "expected": "non-empty signature",
                            "actual_length": 0,
                            "producer_operation": "C_GenerateKeyPair",
                            "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                        },
                        summary=(
                            "C_Sign returned CKR_OK without context-specific login "
                            "but produced an empty signature"
                        ),
                    )
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label="CKA_ALWAYS_AUTHENTICATE:first-sign-without-reauth",
                    operation="C_Sign",
                    mechanism="CKM_SHA256_RSA_PKCS",
                    expected=CKR_USER_NOT_LOGGED_IN,
                    actual=CKR_OK,
                    detail={
                        "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                        "expected": CKR_USER_NOT_LOGGED_IN,
                        "actual": CKR_OK,
                        "signature_length": len(sig),
                        "producer_operation": "C_GenerateKeyPair",
                        "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                    },
                    summary=(
                        "C_Sign succeeded without context-specific re-authentication "
                        "on a CKA_ALWAYS_AUTHENTICATE=True key"
                    ),
                )
            except CkrAssertionError as exc:
                _classify_operation_rejection(
                    exc,
                    expected_rvs=_ALWAYS_AUTH_EXPECTED_SIGN_REJECT_RVS,
                    label=(
                        "C_Sign on a CKA_ALWAYS_AUTHENTICATE key before "
                        "context-specific re-authentication"
                    ),
                    operation="C_Sign",
                    mechanism="CKM_SHA256_RSA_PKCS",
                )
                pass
        finally:
            destroy_quietly(rs.raw, rs.sh, priv_h)
            destroy_quietly(rs.raw, rs.sh, pub_h)

    def test_always_authenticate_with_context_login(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Context-specific login enables crypto on CKA_ALWAYS_AUTHENTICATE key."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")

        try:
            pub_h, priv_h = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                private_attrs={
                    CKA_SIGN: True,
                    CKA_ALWAYS_AUTHENTICATE: True,
                    CKA_TOKEN: False,
                },
            )
        except CkrAssertionError as e:
            _skip_or_xfail_always_auth_keygen_reject(e)

        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, priv_h, [CKA_ALWAYS_AUTHENTICATE])
                val = attr_or_record(
                    attrs,
                    CKA_ALWAYS_AUTHENTICATE,
                    label="CKA_ALWAYS_AUTHENTICATE context-login setup readback",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                )
            except CkrAssertionError as e:
                _classify_post_success_attribute_error(
                    e,
                    attr=CKA_ALWAYS_AUTHENTICATE,
                    label="CKA_ALWAYS_AUTHENTICATE context-login setup readback",
                    producer_operation="C_GenerateKeyPair",
                    producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                )
                return
            if val is MISSING_ATTRIBUTE:
                return
            _require_bool_attribute(
                val,
                attr=CKA_ALWAYS_AUTHENTICATE,
                label="CKA_ALWAYS_AUTHENTICATE context-login setup readback",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            if val is not True:
                fail_as(
                    "wrong_result",
                    kind="policy",
                    label="CKA_ALWAYS_AUTHENTICATE setup",
                    operation="C_GenerateKeyPair",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    expected=CKR_OK,
                    actual=CKR_OK,
                    detail={
                        "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                        "expected": True,
                        "actual": val,
                        "producer_operation": "C_GenerateKeyPair",
                        "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                    },
                    summary=(
                        "C_GenerateKeyPair returned CKR_OK but did not preserve "
                        "CKA_ALWAYS_AUTHENTICATE=True"
                    ),
                )

            # Do context-specific login, then sign
            pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
            rv = rs.raw.C_Login(rs.sh, CKU_CONTEXT_SPECIFIC, pin_buf, len(pin_bytes))
            if rv not in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN):
                _classify_negative_operation_rv(
                    rv,
                    expected_rvs=(CKR_USER_ALREADY_LOGGED_IN,),
                    label="Context-specific C_Login for CKA_ALWAYS_AUTHENTICATE",
                    operation="C_Login",
                    mechanism=None,
                    allow_ok=True,
                )
                return

            data = b"context auth test data"
            try:
                sig = sign_single(rs.raw, rs.sh, priv_h, CKM_SHA256_RSA_PKCS, data)
                if len(sig) == 0:
                    fail_as(
                        "wrong_result",
                        kind="crypto",
                        label="CKA_ALWAYS_AUTHENTICATE:context-auth-sign",
                        operation="C_Sign",
                        mechanism="CKM_SHA256_RSA_PKCS",
                        detail={
                            "expected": "non-empty signature",
                            "actual_length": 0,
                            "producer_operation": "C_GenerateKeyPair",
                            "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                        },
                        summary=(
                            "C_Sign returned CKR_OK after context-specific login "
                            "but produced an empty signature"
                        ),
                    )
            except CkrAssertionError as e:
                if e.rv == CKR_USER_NOT_LOGGED_IN:
                    classification.classify(
                        "self_contradiction",
                        kind="lifecycle",
                        label="CKA_ALWAYS_AUTHENTICATE:context-login-not-honored",
                        operation="C_Sign",
                        mechanism="CKM_SHA256_RSA_PKCS",
                        expected=CKR_OK,
                        actual=e.rv,
                        detail={
                            "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                            "producer_operation": "C_GenerateKeyPair",
                            "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                        },
                        summary=(
                            "C_Sign returned CKR_USER_NOT_LOGGED_IN after accepted "
                            "context-specific login"
                        ),
                    )
                _classify_operation_unavailable(
                    e,
                    label="C_Sign after context-specific login is not operational",
                    operation="C_Sign",
                    mechanism="CKM_SHA256_RSA_PKCS",
                    producer_operation="C_GenerateKeyPair",
                    producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, priv_h)
            destroy_quietly(rs.raw, rs.sh, pub_h)


# ---------------------------------------------------------------------------
# Access level matrix: PRIVATE x TOKEN combinations
# ---------------------------------------------------------------------------


class TestAccessLevelMatrix:
    """Create objects with various PRIVATE/TOKEN combos, verify visibility."""

    def test_session_public_object_visible_in_public(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Session object with PRIVATE=False visible without login."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"sess-pub-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Create session object (PRIVATE=False, TOKEN=False) while logged in
        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            _create_access_data_object(
                rs,
                s1,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                    CKA_VALUE: b"session-public",
                    CKA_TOKEN: False,
                    CKA_PRIVATE: False,
                },
            )

            # Open another session without login on same token
            s2 = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
            try:
                tmpl = template_from_dict(
                    {
                        CKA_CLASS: CKO_DATA,
                        CKA_LABEL: label,
                    }
                )
                found = find_objects(rs.raw, s2, tmpl)
                if len(found) == 0:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "Session-public object not visible in another session "
                        "(implementation-defined)",
                        ComplianceLevel.VENDOR,
                        reference="PKCS#11 spec: session object visibility",
                    )
            finally:
                close_session_quietly(rs.raw, s2)
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

    def test_token_public_object_visible_in_public(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Token object with PRIVATE=False visible in public session."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"tok-pub-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Create token object
        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            _create_access_data_object(
                rs,
                s1,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                    CKA_VALUE: b"token-public",
                    CKA_TOKEN: True,
                    CKA_PRIVATE: False,
                },
            )
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

        # Check visibility without login
        s2 = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        try:
            tmpl = template_from_dict(
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                }
            )
            found = find_objects(rs.raw, s2, tmpl)
            if len(found) == 0:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "Token-public object not visible without login",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec: CKA_PRIVATE=False visible in public",
                )
        finally:
            close_session_quietly(rs.raw, s2)

        # Cleanup
        cleanup_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, cleanup_sh, pin_bytes)
            for h in find_objects(
                rs.raw,
                cleanup_sh,
                template_from_dict({CKA_CLASS: CKO_DATA, CKA_LABEL: label}),
            ):
                destroy_quietly(rs.raw, cleanup_sh, h)
        finally:
            _logout_safe(rs.raw, cleanup_sh)
            close_session_quietly(rs.raw, cleanup_sh)

    def test_token_private_object_invisible_in_public(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Token object with PRIVATE=True not visible without login."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"tok-priv-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            _gen_access_aes_key(
                rs,
                s1,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
            )
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

        # Check NOT visible without login
        s2 = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        try:
            tmpl = template_from_dict(
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_LABEL: label,
                }
            )
            found = find_objects(rs.raw, s2, tmpl)
            assert len(found) == 0, "Token-private object visible in public session"
        finally:
            close_session_quietly(rs.raw, s2)

        # Cleanup
        cleanup_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, cleanup_sh, pin_bytes)
            for h in find_objects(rs.raw, cleanup_sh, template_from_dict({CKA_LABEL: label})):
                destroy_quietly(rs.raw, cleanup_sh, h)
        finally:
            _logout_safe(rs.raw, cleanup_sh)
            close_session_quietly(rs.raw, cleanup_sh)

    def test_session_private_object_invisible_after_logout(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Session object with PRIVATE=True invisible after logout."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"sess-priv-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            _gen_access_aes_key(
                rs,
                s1,
                attrs={
                    CKA_TOKEN: False,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
            )

            # Verify visible while logged in
            tmpl = template_from_dict({CKA_LABEL: label})
            found = find_objects(rs.raw, s1, tmpl)
            assert len(found) >= 1

            # Logout
            rs.raw.C_Logout(s1)

            # Should be invisible
            found = find_objects(rs.raw, s1, tmpl)
            assert len(found) == 0, "Session-private object visible after logout"
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

    def test_user_session_visibility_matrix(self, p11_raw_session: Any, p11_config: Any) -> None:
        """USER session sees all four PRIVATE x TOKEN combinations."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        combos: list[tuple[bool, bool, str]] = [
            (False, False, f"matrix-sf-{id(self)}"),  # session, public
            (False, True, f"matrix-sp-{id(self)}"),  # session, private
            (True, False, f"matrix-tf-{id(self)}"),  # token, public
            (True, True, f"matrix-tp-{id(self)}"),  # token, private
        ]

        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        created_labels: list[str] = []
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            for is_token, is_private, label in combos:
                _create_access_data_object(
                    rs,
                    s1,
                    {
                        CKA_CLASS: CKO_DATA,
                        CKA_LABEL: label,
                        CKA_VALUE: b"matrix-data",
                        CKA_TOKEN: is_token,
                        CKA_PRIVATE: is_private,
                    },
                )
                created_labels.append(label)

            # USER should see all four
            for label in created_labels:
                tmpl = template_from_dict(
                    {
                        CKA_CLASS: CKO_DATA,
                        CKA_LABEL: label,
                    }
                )
                found = find_objects(rs.raw, s1, tmpl)
                assert len(found) >= 1, f"USER session cannot see object with label {label}"
        finally:
            # Cleanup token objects
            for label in created_labels:
                tmpl = template_from_dict(
                    {
                        CKA_CLASS: CKO_DATA,
                        CKA_LABEL: label,
                    }
                )
                for h in find_objects(rs.raw, s1, tmpl):
                    destroy_quietly(rs.raw, s1, h)
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)


# ---------------------------------------------------------------------------
# SO login on RO session (negative test)
# ---------------------------------------------------------------------------


class TestSOOnROSession:
    """SO login requirements."""

    @pytest.mark.destructive
    def test_so_login_rejected_on_ro_session(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_Login(SO) on R/O session must fail per spec."""
        so_pin, explicit = resolve_so_pin(p11_config)
        if so_pin is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        guard_so_lockout(rs.raw, rs.slot_id, explicit=explicit)
        flags_ro = CKF_SERIAL_SESSION
        s1 = raw_open_session(rs.raw, rs.slot_id, flags_ro)
        try:
            pin_buf = (CK_UTF8CHAR * len(so_pin))(*so_pin)
            rv = rs.raw.C_Login(s1, CKU_SO, pin_buf, len(so_pin))
            skip_if_so_pin_rejected(rv, explicit=explicit)
            _classify_negative_operation_rv(
                rv,
                expected_rvs=(CKR_SESSION_READ_ONLY_EXISTS,),
                label="C_Login(SO) on a read-only session (SO requires a R/W session)",
                operation="C_Login",
                mechanism=None,
            )
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)


# ---------------------------------------------------------------------------
# Public session cannot create private objects
# ---------------------------------------------------------------------------


class TestPublicSessionRestrictions:
    """Public session operational restrictions."""

    def test_public_cannot_create_private_token_object(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Public session (no login) must not create CKA_PRIVATE=True token objects.

        PKCS#11: private objects require an authenticated (logged-in) session, so
        C_GenerateKey for a private object from a public session must return
        CKR_USER_NOT_LOGGED_IN. A module that creates a usable private object
        without authentication has claimed the protection (CKA_PRIVATE=True reads
        back) then violated it -- a policy self-contradiction, not a soft note.
        """
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured; cannot establish an unauthenticated session")
        require_operational_aes_keygen(rs)
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION
        label = f"pub-no-create-priv-{id(self)}"

        # Clear application-wide (token-wide) login so the probe session is public.
        pre_sh = _open_access_session_or_skip(rs, flags_rw)
        rs.raw.C_Logout(pre_sh)
        close_session_quietly(rs.raw, pre_sh)

        s1 = _open_access_session_or_skip(rs, flags_rw)
        created = None
        try:
            try:
                created = gen_aes_key(
                    rs.raw,
                    s1,
                    128,
                    attrs={
                        CKA_TOKEN: True,
                        CKA_PRIVATE: True,
                        CKA_LABEL: label,
                    },
                )
            except CkrAssertionError as exc:
                _classify_operation_rejection(
                    exc,
                    expected_rvs=(CKR_USER_NOT_LOGGED_IN,),
                    label="C_GenerateKey CKA_PRIVATE=True token object in a public "
                    "(unauthenticated) session",
                    operation="C_GenerateKey",
                    mechanism="CKM_AES_KEY_GEN",
                )
                return
            # Created without login -- policy claim/effect check: claimed is that
            # the object reads back CKA_PRIVATE=True; violated is that it exists at
            # all (created by an unauthenticated session).
            try:
                private_attrs = read_attributes(rs.raw, s1, created, [CKA_PRIVATE])
            except CkrAssertionError as exc:
                _classify_post_success_attribute_error(
                    exc,
                    attr=CKA_PRIVATE,
                    label="public CKA_PRIVATE=True token object readback",
                    producer_operation="C_GenerateKey",
                    producer_mechanism="CKM_AES_KEY_GEN",
                )
                return
            priv = attr_or_record(
                private_attrs,
                CKA_PRIVATE,
                label="public CKA_PRIVATE=True token object readback",
                mechanism="CKM_AES_KEY_GEN",
            )
            if priv is MISSING_ATTRIBUTE:
                return
            _require_bool_attribute(
                priv,
                attr=CKA_PRIVATE,
                label="public CKA_PRIVATE=True token object readback",
                mechanism="CKM_AES_KEY_GEN",
            )
            label = (
                "public (unauthenticated) session created a CKA_PRIVATE=True "
                "token object (PKCS#11 requires CKR_USER_NOT_LOGGED_IN)"
            )
            if priv is True:
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label=label,
                    operation="C_GenerateKey",
                    mechanism="CKM_AES_KEY_GEN",
                    expected=CKR_USER_NOT_LOGGED_IN,
                    actual=CKR_OK,
                    detail={
                        "attribute": int(CKA_PRIVATE),
                        "expected": True,
                        "actual": priv,
                        "read_operation": "C_GetAttributeValue",
                        "read_mechanism": "CKM_AES_KEY_GEN",
                        "producer_operation": "C_GenerateKey",
                        "producer_mechanism": "CKM_AES_KEY_GEN",
                    },
                    summary=f"{label}: claimed the protection then violated it",
                )
            xfail_as(
                "honest_deviation",
                kind="policy",
                label=label,
                operation="C_GenerateKey",
                mechanism="CKM_AES_KEY_GEN",
                expected=CKR_OK,
                actual=CKR_OK,
                detail={
                    "attribute": int(CKA_PRIVATE),
                    "expected": True,
                    "actual": priv,
                    "producer_operation": "C_GenerateKey",
                    "producer_mechanism": "CKM_AES_KEY_GEN",
                },
                summary=f"{label}: module did not claim the protection",
            )
        finally:
            # Restore login so the created object can be cleaned up and later tests
            # in this file see authenticated state again.
            _login_user_raw(rs.raw, s1, pin_bytes)
            if created is not None:
                destroy_quietly(rs.raw, s1, created)
            else:
                for h in find_objects(rs.raw, s1, template_from_dict({CKA_LABEL: label})):
                    destroy_quietly(rs.raw, s1, h)
            close_session_quietly(rs.raw, s1)

    def test_public_can_create_non_private_data(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Public session may create CKA_PRIVATE=False data objects."""
        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Clear login
        pre_sh = _open_access_session_or_skip(rs, flags_rw)
        rs.raw.C_Logout(pre_sh)
        close_session_quietly(rs.raw, pre_sh)

        s1 = _open_access_session_or_skip(rs, flags_rw)
        label = f"pub-create-{id(self)}"
        try:
            try:
                create_object(
                    rs.raw,
                    s1,
                    {
                        CKA_CLASS: CKO_DATA,
                        CKA_LABEL: label,
                        CKA_VALUE: b"pub-created",
                        CKA_TOKEN: True,
                        CKA_PRIVATE: False,
                    },
                )
            except CkrAssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    (
                        CKR_SESSION_READ_ONLY,
                        CKR_TEMPLATE_INCOMPLETE,
                        CKR_TEMPLATE_INCONSISTENT,
                        CKR_USER_NOT_LOGGED_IN,
                        CKR_USER_TYPE_INVALID,
                    ),
                    "Public C_CreateObject for a non-private data object is not operational",
                )
                raise

            # Cleanup
            tmpl = template_from_dict(
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                }
            )
            for h in find_objects(rs.raw, s1, tmpl):
                destroy_quietly(rs.raw, s1, h)
        finally:
            close_session_quietly(rs.raw, s1)

    def test_public_create_private_session_object_rejected(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Public session must not C_CreateObject a CKA_PRIVATE=True object.

        Complements the C_GenerateKey path: the private-object login rule applies
        to direct object creation and to session (not only token) objects.
        Expected CKR_USER_NOT_LOGGED_IN; creating a usable private object without
        authentication is a policy self-contradiction, not a soft note.
        """
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured; cannot establish an unauthenticated session")
        skip_unless_create_object_supported(rs)
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION
        label = f"pub-create-priv-{id(self)}"

        # Clear application-wide (token-wide) login so the probe session is public.
        pre_sh = _open_access_session_or_skip(rs, flags_rw)
        rs.raw.C_Logout(pre_sh)
        close_session_quietly(rs.raw, pre_sh)

        s1 = _open_access_session_or_skip(rs, flags_rw)
        created = None
        try:
            try:
                created = create_object(
                    rs.raw,
                    s1,
                    {
                        CKA_CLASS: CKO_DATA,
                        CKA_LABEL: label,
                        CKA_VALUE: b"private-no-login",
                        CKA_TOKEN: False,
                        CKA_PRIVATE: True,
                    },
                )
            except CkrAssertionError as exc:
                _classify_operation_rejection(
                    exc,
                    expected_rvs=(CKR_USER_NOT_LOGGED_IN,),
                    label="C_CreateObject CKA_PRIVATE=True session object in a public "
                    "(unauthenticated) session",
                    operation="C_CreateObject",
                    mechanism=None,
                )
                return
            # Created without login -- policy claim/effect check.
            try:
                private_attrs = read_attributes(rs.raw, s1, created, [CKA_PRIVATE])
            except CkrAssertionError as exc:
                _classify_post_success_attribute_error(
                    exc,
                    attr=CKA_PRIVATE,
                    label="public CKA_PRIVATE=True session object readback",
                    producer_operation="C_CreateObject",
                    producer_mechanism=None,
                )
                return
            priv = attr_or_record(
                private_attrs,
                CKA_PRIVATE,
                label="public CKA_PRIVATE=True session object readback",
                mechanism=None,
            )
            if priv is MISSING_ATTRIBUTE:
                return
            _require_bool_attribute(
                priv,
                attr=CKA_PRIVATE,
                label="public CKA_PRIVATE=True session object readback",
                mechanism=None,
            )
            label = (
                "public (unauthenticated) session created a CKA_PRIVATE=True "
                "session object (PKCS#11 requires CKR_USER_NOT_LOGGED_IN)"
            )
            if priv is True:
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label=label,
                    operation="C_CreateObject",
                    mechanism=None,
                    expected=CKR_USER_NOT_LOGGED_IN,
                    actual=CKR_OK,
                    detail={
                        "attribute": int(CKA_PRIVATE),
                        "expected": True,
                        "actual": priv,
                        "read_operation": "C_GetAttributeValue",
                        "read_mechanism": None,
                        "producer_operation": "C_CreateObject",
                        "producer_mechanism": None,
                    },
                    summary=f"{label}: claimed the protection then violated it",
                )
            xfail_as(
                "honest_deviation",
                kind="policy",
                label=label,
                operation="C_CreateObject",
                mechanism=None,
                expected=CKR_OK,
                actual=CKR_OK,
                detail={
                    "attribute": int(CKA_PRIVATE),
                    "expected": True,
                    "actual": priv,
                    "read_operation": "C_GetAttributeValue",
                    "read_mechanism": None,
                    "producer_operation": "C_CreateObject",
                    "producer_mechanism": None,
                },
                summary=f"{label}: module did not claim the protection",
            )
        finally:
            # Session objects are discarded on close; destroy first if it exists.
            if created is not None:
                destroy_quietly(rs.raw, s1, created)
            close_session_quietly(rs.raw, s1)
