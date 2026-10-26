"""Public-session private-object creation rejection probes (Wave 2).

PKCS#11 requires an authenticated (CKU_USER) session to create private
(``CKA_PRIVATE=True``) objects. ``test_access_levels.py`` covers
``C_CreateObject`` and ``C_GenerateKey`` in the context of private-object
*visibility* access-level tests; this file focuses on the creation-rejection
rule for the remaining creation paths -- ``C_UnwrapKey``, ``C_DeriveKey``
(ECDH + HKDF), and ``C_CopyObject`` -- to confirm the rule holds uniformly.

Each probe clears the token-wide login (login is per-token, not per-session),
then attempts the creation on a public session. A module that creates a usable
private object without authentication has claimed the protection then violated
it -- a policy self-contradiction, not a soft note.
"""

from __future__ import annotations

import sys
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from ctypes import byref
from typing import Any, NoReturn

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.bootstrap import close_session_quietly
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_simple, template_from_dict
from pkcs11_check.raw.pack_mechanisms import mech_ecdh, mech_hkdf
from pkcs11_check.raw.recipes import (
    copy_object,
    create_object,
    derive_key,
    destroy_quietly,
    find_objects,
    find_objects_exhaustive,
    gen_aes_key,
    gen_ec_keypair,
    partition_proved_new,
    read_attributes,
    to_ubyte_buf,
    unwrap_key,
    wrap_key,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_SESSION_INFO,
    CK_UTF8CHAR,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_PRIVATE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_WRAP,
    CKD_NULL,
    CKF_EC_COMPRESS,
    CKF_EC_UNCOMPRESS,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_KEY_GEN,
    CKM_AES_KEY_WRAP,
    CKM_ECDH1_DERIVE,
    CKM_HKDF_DERIVE,
    CKM_SHA256,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKR_OK,
    CKR_SESSION_COUNT,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
    CKS_RW_SO_FUNCTIONS,
    CKS_RW_USER_FUNCTIONS,
    CKU_SO,
    CKU_USER,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases._ec_export import (
    read_conventional_ec_point_or_xfail,
    select_ecdh_point_form,
)
from pkcs11_check.testcases._so_login import (
    guard_so_lockout,
    resolve_so_pin,
    skip_if_so_pin_rejected,
)
from pkcs11_check.testcases.conftest import (
    KEYPAIR_RUNTIME_REJECT_RVS,
    classify_policy_enforcement,
    gen_aes_key_or_xfail,
    get_pin_bytes,
    is_known_error,
    reject_or_classify,
    skip_unless_create_object_supported,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# Local session helpers (mirrored from test_access_levels.py:164-222 -- login
# is per-token so we cannot rely on the p11_raw_session fixture's auth state)
# ---------------------------------------------------------------------------


def _login_user_raw(raw: Any, sh: int, pin_bytes: bytes | None) -> None:
    """Login as USER, tolerating already-logged-in at token level."""
    if pin_bytes is None:
        return
    pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
    rv = raw.C_Login(sh, CKU_USER, pin_buf, len(pin_bytes))
    if rv not in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN, CKR_USER_TYPE_INVALID):
        from pkcs11_check.raw.rv import expect_rv

        expect_rv(rv, CKR_OK)


def _logout_safe(raw: Any, sh: int) -> None:
    """Logout ignoring not-logged-in or closed-session errors."""
    raw.C_Logout(sh)


def _open_access_session_or_skip(rs: Any, flags: int) -> int:
    """Open an extra session for public-session scenarios."""
    try:
        return raw_open_session(rs.raw, rs.slot_id, flags)
    except AssertionError as exc:
        if is_known_error(exc, (CKR_SESSION_COUNT,)):
            pytest.skip(
                "Cannot open additional session required by public-session test: "
                f"{ckr_name(int(CKR_SESSION_COUNT))}"
            )
        raise


def _establish_public_session(
    rs: Any, p11_config: Any, *, flags: int = CKF_SERIAL_SESSION | CKF_RW_SESSION
) -> tuple[int, bytes]:
    """Clear token-wide login and return (public_session_handle, pin_bytes).

    Mirrors the canonical pattern from test_access_levels.py:1519-1524: open a
    transient session, C_Logout to clear the application-wide (token-wide)
    login state, close it, then open a fresh session that is genuinely public.
    """
    pin_bytes = get_pin_bytes(p11_config)
    if pin_bytes is None:
        pytest.skip("No PIN configured; cannot establish an unauthenticated session")
    pre_sh = _open_access_session_or_skip(rs, flags)
    _logout_safe(rs.raw, pre_sh)
    close_session_quietly(rs.raw, pre_sh)
    public_sh = _open_access_session_or_skip(rs, flags)
    return public_sh, pin_bytes


def _label_template(label: str) -> Any:
    """Build a find_objects template matching CKA_LABEL == label."""
    return template_from_dict({CKA_LABEL: label})


def _cleanup_label(rs: Any, sh: int, label: str) -> None:
    """Destroy all objects matching ``label`` on the given session."""
    for h in find_objects(rs.raw, sh, _label_template(label)):
        destroy_quietly(rs.raw, sh, h)


def _read_private_claim(
    rs: Any,
    session: int,
    handle: int,
    *,
    label: str,
    producer_operation: str,
    producer_mechanism: str | None = None,
) -> tuple[bool, C.Classification | None]:
    """Read CKA_PRIVATE strictly, retaining missing/malformed metadata evidence.

    Every call site creates `handle` via an operation that explicitly requests
    CKA_PRIVATE=True and raises/returns on any non-CKR_OK result, so reaching
    this call already proves the module ACCEPTED that protective template at
    creation -- independent claim evidence.  A missing or unreadable readback
    must not downgrade that claim (it would let one unreadable attribute mask
    a proven public-session private-object self-contradiction); only an
    explicit `False` readback is real evidence the claim does not hold.
    """
    detail: dict[str, Any] = {
        "attribute": {"name": "CKA_PRIVATE", "id": int(CKA_PRIVATE)},
        "producer_operation": producer_operation,
    }
    if producer_mechanism is not None:
        detail["producer_mechanism"] = producer_mechanism

    try:
        attrs = read_attributes(rs.raw, session, handle, [CKA_PRIVATE])
    except CkrAssertionError as exc:
        reason = (
            "not_operational"
            if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv)
            else "self_contradiction"
        )
        record = C.record_as(
            reason,
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            expected=CKR_OK,
            actual=exc.rv,
            detail=detail,
            summary=(
                f"{label}: attribute read was rejected with {ckr_name(exc.rv)}"
                if reason == "not_operational"
                else f"{label}: attribute read returned undefined CK_RV {exc.rv:#x}"
            ),
        )
        return True, record

    before = len(C.get_records())
    value = attr_or_record(
        attrs,
        CKA_PRIVATE,
        label=label,
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )
    if value is MISSING_ATTRIBUTE:
        records = C.get_records()
        if len(records) <= before:
            raise AssertionError(f"{label}: missing attribute did not produce evidence")
        record = records[-1]
        record.detail = {**(record.detail or {}), **detail}
        return True, record
    if type(value) is bool:
        return value, None

    record = C.record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        inherit_mechanism=False,
        detail={
            **detail,
            "expected": "strict CK_BBOOL (bool)",
            "actual_type": type(value).__name__,
            "actual_length": len(value) if isinstance(value, bytes) else None,
        },
        summary=(
            f"{label}: present CKA_PRIVATE has malformed CK_BBOOL value: {type(value).__name__}"
        ),
    )
    return False, record


_POLICY_KIND_PRIORITY = {"metadata": 1, "lifecycle": 2, "policy": 2, "crypto": 3}
_POLICY_SEVERITY_PRIORITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _raise_strongest_policy_observation(records: list[C.Classification]) -> None:
    """Raise a deferred policy result after the public-session cleanup ran."""
    if not records:
        return
    strongest = max(
        records,
        key=lambda record: (
            1 if record.outcome == "fail" else 0,
            _POLICY_SEVERITY_PRIORITY.get(record.severity, 0),
            _POLICY_KIND_PRIORITY.get(record.kind or "", 0),
        ),
    )
    C.raise_for_record(strongest)


def _classify_private_policy(
    *,
    claimed: bool,
    read_record: C.Classification | None,
    label: str,
) -> None:
    """Run the independent policy oracle and preserve stronger readback evidence."""
    records: list[C.Classification] = []
    if read_record is not None:
        records.append(read_record)
    try:
        classify_policy_enforcement(claimed=claimed, violated=True, label=label)
    except BaseException as exc:
        policy_record = getattr(exc, "_pkcs11_check_classification", None)
        if policy_record is None:
            raise
        records.append(policy_record)
    _raise_strongest_policy_observation(records)


class TestPublicSessionPrivateCreation:
    """Private-object creation must be rejected on a public (no-login) session.

    Covers the 4 creation paths NOT already in test_access_levels.py:
    C_UnwrapKey, C_DeriveKey (ECDH), C_DeriveKey (HKDF), C_CopyObject.
    """

    def test_public_cannot_unwrap_private_object(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """C_UnwrapKey with CKA_PRIVATE=True on a public session must reject.

        PKCS#11: private objects require an authenticated session. The KEK is
        a public token object (CKA_PRIVATE=False) so it is visible without
        login; the unwrap template claims CKA_PRIVATE=True. Spec-correct reject
        is CKR_USER_NOT_LOGGED_IN; a successful unwrap of a usable private
        object is a policy self-contradiction.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not advertised")
        label = f"pub-unwrap-priv-{id(self)}"

        try:
            # Setup on the logged-in fixture session: public KEK + extractable target.
            kek = gen_aes_key_or_xfail(
                rs,
                256,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: False,
                    CKA_WRAP: True,
                    CKA_UNWRAP: True,
                    CKA_LABEL: label,
                    CKA_EXTRACTABLE: True,
                },
                purpose="public-session unwrap KEK setup",
            )
            target = gen_aes_key_or_xfail(
                rs,
                128,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_LABEL: label,
                },
                purpose="public-session unwrap target setup",
            )
            wrapped = wrap_key(rs.raw, rs.sh, kek, target, CKM_AES_KEY_WRAP)

            # Establish a genuinely public session (login is per-token).
            public_sh, pin_bytes = _establish_public_session(rs, p11_config)
            created = None
            try:
                try:
                    created = unwrap_key(
                        rs.raw,
                        public_sh,
                        kek,
                        wrapped,
                        CKM_AES_KEY_WRAP,
                        attrs={
                            CKA_CLASS: CKO_SECRET_KEY,
                            CKA_KEY_TYPE: CKK_AES,
                            CKA_TOKEN: False,
                            CKA_PRIVATE: True,
                            CKA_VALUE_LEN: 16,
                            CKA_LABEL: label,
                        },
                    )
                except AssertionError as exc:
                    reject_or_classify(
                        exc,
                        (CKR_USER_NOT_LOGGED_IN,),
                        label="C_UnwrapKey CKA_PRIVATE=True session object in a public "
                        "(unauthenticated) session",
                    )
                    return
                # Created without login -- policy claim/effect check.
                claimed, read_record = _read_private_claim(
                    rs,
                    public_sh,
                    created,
                    label="public-session unwrap CKA_PRIVATE readback",
                    producer_operation="C_UnwrapKey",
                    producer_mechanism="CKM_AES_KEY_WRAP",
                )
                _classify_private_policy(
                    claimed=claimed,
                    read_record=read_record,
                    label="public (unauthenticated) session unwrapped a CKA_PRIVATE=True "
                    "session object (PKCS#11 requires CKR_USER_NOT_LOGGED_IN)",
                )
            finally:
                # Restore login for cleanup of token objects created during setup.
                _login_user_raw(rs.raw, public_sh, pin_bytes)
                if created is not None:
                    destroy_quietly(rs.raw, public_sh, created)
                _cleanup_label(rs, public_sh, label)
                close_session_quietly(rs.raw, public_sh)
        finally:
            _cleanup_label(
                rs, rs.sh, label
            )  # catches early pytest.skip in _establish_public_session

    def test_public_cannot_derive_private_ecdh_key(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """C_DeriveKey (ECDH1) with CKA_PRIVATE=True on a public session must reject.

        The base EC private key is a public token object (CKA_PRIVATE=False) so
        it is visible without login; the derive template claims CKA_PRIVATE=True.
        Spec-correct reject is CKR_USER_NOT_LOGGED_IN.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not advertised")
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not advertised")
        label = f"pub-derive-ecdh-{id(self)}"
        curve_oid = encode_named_curve_parameters("secp256r1")

        try:
            # Setup on the logged-in fixture session: derive-capable public EC key.
            try:
                pub, priv = gen_ec_keypair(
                    rs.raw,
                    rs.sh,
                    curve_oid,
                    public_attrs={CKA_TOKEN: True, CKA_PRIVATE: False, CKA_LABEL: label},
                    private_attrs={
                        CKA_TOKEN: True,
                        CKA_PRIVATE: False,
                        CKA_DERIVE: True,
                        CKA_LABEL: label,
                    },
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    KEYPAIR_RUNTIME_REJECT_RVS,
                    "EC keypair staging for public-session ECDH setup is not operational",
                )
            peer = read_conventional_ec_point_or_xfail(
                rs,
                pub,
                ec.SECP256R1(),
                label="CKM_ECDH1_DERIVE: public-session peer public key",
            )
            peer_point = select_ecdh_point_form(
                peer,
                supports_compressed=rs.has_mechanism_flag(CKM_ECDH1_DERIVE, int(CKF_EC_COMPRESS)),
                supports_uncompressed=rs.has_mechanism_flag(
                    CKM_ECDH1_DERIVE, int(CKF_EC_UNCOMPRESS)
                ),
            )

            # Establish a genuinely public session.
            public_sh, pin_bytes = _establish_public_session(rs, p11_config)
            created = None
            try:
                try:
                    created = derive_key(
                        rs.raw,
                        public_sh,
                        priv,
                        CKM_ECDH1_DERIVE,
                        attrs={
                            CKA_CLASS: CKO_SECRET_KEY,
                            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                            CKA_TOKEN: False,
                            CKA_PRIVATE: True,
                            CKA_LABEL: label,
                        },
                        mech_param=mech_ecdh(
                            CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=peer_point
                        ),
                    )
                except AssertionError as exc:
                    reject_or_classify(
                        exc,
                        (CKR_USER_NOT_LOGGED_IN,),
                        label="C_DeriveKey(ECDH) CKA_PRIVATE=True session object in a public "
                        "(unauthenticated) session",
                    )
                    return
                claimed, read_record = _read_private_claim(
                    rs,
                    public_sh,
                    created,
                    label="public-session ECDH CKA_PRIVATE readback",
                    producer_operation="C_DeriveKey",
                    producer_mechanism="CKM_ECDH1_DERIVE",
                )
                _classify_private_policy(
                    claimed=claimed,
                    read_record=read_record,
                    label="public (unauthenticated) session ECDH-derived a CKA_PRIVATE=True "
                    "session object (PKCS#11 requires CKR_USER_NOT_LOGGED_IN)",
                )
            finally:
                _login_user_raw(rs.raw, public_sh, pin_bytes)
                if created is not None:
                    destroy_quietly(rs.raw, public_sh, created)
                _cleanup_label(rs, public_sh, label)
                close_session_quietly(rs.raw, public_sh)
        finally:
            _cleanup_label(
                rs, rs.sh, label
            )  # catches early pytest.skip in _establish_public_session

    def test_public_cannot_derive_private_hkdf_key(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """C_DeriveKey (HKDF) with CKA_PRIVATE=True on a public session must reject.

        The base secret key is a public token object (CKA_PRIVATE=False) so it
        is visible without login; the derive template claims CKA_PRIVATE=True.
        Spec-correct reject is CKR_USER_NOT_LOGGED_IN.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not advertised")
        label = f"pub-derive-hkdf-{id(self)}"

        try:
            # Setup on the logged-in fixture session: derive-capable public secret key.
            gen_aes_key_or_xfail(
                rs,
                256,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: False,
                    CKA_DERIVE: True,
                    CKA_LABEL: label,
                    CKA_EXTRACTABLE: True,
                },
                purpose="public-session HKDF base setup",
            )
            # Re-fetch the handle so cleanup in finally matches what we use.
            setup_tmpl = template_from_dict({CKA_LABEL: label, CKA_KEY_TYPE: CKK_AES})
            setup_handles = find_objects(rs.raw, rs.sh, setup_tmpl)
            if not setup_handles:
                pytest.skip("Module refused to create the derive base key for HKDF setup")
            base_key = setup_handles[0]

            # Establish a genuinely public session.
            public_sh, pin_bytes = _establish_public_session(rs, p11_config)
            created = None
            try:
                try:
                    created = derive_key(
                        rs.raw,
                        public_sh,
                        base_key,
                        CKM_HKDF_DERIVE,
                        attrs={
                            CKA_CLASS: CKO_SECRET_KEY,
                            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                            CKA_TOKEN: False,
                            CKA_PRIVATE: True,
                            CKA_VALUE_LEN: 32,
                            CKA_LABEL: label,
                        },
                        mech_param=mech_hkdf(CKM_HKDF_DERIVE, hash_mech=CKM_SHA256),
                    )
                except AssertionError as exc:
                    reject_or_classify(
                        exc,
                        (CKR_USER_NOT_LOGGED_IN,),
                        label="C_DeriveKey(HKDF) CKA_PRIVATE=True session object in a public "
                        "(unauthenticated) session",
                    )
                    return
                claimed, read_record = _read_private_claim(
                    rs,
                    public_sh,
                    created,
                    label="public-session HKDF CKA_PRIVATE readback",
                    producer_operation="C_DeriveKey",
                    producer_mechanism="CKM_HKDF_DERIVE",
                )
                _classify_private_policy(
                    claimed=claimed,
                    read_record=read_record,
                    label="public (unauthenticated) session HKDF-derived a CKA_PRIVATE=True "
                    "session object (PKCS#11 requires CKR_USER_NOT_LOGGED_IN)",
                )
            finally:
                _login_user_raw(rs.raw, public_sh, pin_bytes)
                if created is not None:
                    destroy_quietly(rs.raw, public_sh, created)
                _cleanup_label(rs, public_sh, label)
                close_session_quietly(rs.raw, public_sh)
        finally:
            _cleanup_label(
                rs, rs.sh, label
            )  # catches early pytest.skip in _establish_public_session

    def test_public_cannot_copy_to_private_object(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """C_CopyObject flipping CKA_PRIVATE=True on a public session must reject.

        The source object is a public token data object (CKA_PRIVATE=False) so
        it is visible without login; the copy template claims CKA_PRIVATE=True.
        Spec-correct reject is CKR_USER_NOT_LOGGED_IN.
        """
        rs = p11_raw_session
        label = f"pub-copy-priv-{id(self)}"

        try:
            # Setup on the logged-in fixture session: public data object.
            create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                    CKA_VALUE: b"public-copy-source",
                    CKA_TOKEN: True,
                    CKA_PRIVATE: False,
                },
            )
            setup_tmpl = template_from_dict({CKA_LABEL: label, CKA_CLASS: CKO_DATA})
            setup_handles = find_objects(rs.raw, rs.sh, setup_tmpl)
            if not setup_handles:
                pytest.skip("Module refused to create the source data object for copy setup")
            source = setup_handles[0]

            # Establish a genuinely public session.
            public_sh, pin_bytes = _establish_public_session(rs, p11_config)
            created = None
            try:
                try:
                    created = copy_object(
                        rs.raw,
                        public_sh,
                        source,
                        attrs={
                            CKA_PRIVATE: True,
                            CKA_LABEL: label,
                        },
                    )
                except AssertionError as exc:
                    reject_or_classify(
                        exc,
                        (CKR_USER_NOT_LOGGED_IN,),
                        label="C_CopyObject CKA_PRIVATE=True copy in a public "
                        "(unauthenticated) session",
                    )
                    return
                claimed, read_record = _read_private_claim(
                    rs,
                    public_sh,
                    created,
                    label="public-session copy CKA_PRIVATE readback",
                    producer_operation="C_CopyObject",
                )
                _classify_private_policy(
                    claimed=claimed,
                    read_record=read_record,
                    label="public (unauthenticated) session C_CopyObject'd to a "
                    "CKA_PRIVATE=True copy (PKCS#11 requires CKR_USER_NOT_LOGGED_IN)",
                )
            finally:
                _login_user_raw(rs.raw, public_sh, pin_bytes)
                if created is not None:
                    destroy_quietly(rs.raw, public_sh, created)
                _cleanup_label(rs, public_sh, label)
                close_session_quietly(rs.raw, public_sh)
        finally:
            _cleanup_label(
                rs, rs.sh, label
            )  # catches early pytest.skip in _establish_public_session


# ---------------------------------------------------------------------------
# QC10a: SO-session private-object creation matrix (#52.4)
#
# PKCS#11 v3.2: "Only public objects can be created unless the normal user is
# logged in" (C_CreateObject, C_CopyObject); an SO session is not the normal
# user, so a private-object Create/Copy/Generate/Derive/Unwrap there must
# refuse with CKR_USER_NOT_LOGGED_IN -- the only code in each creation
# function's return list expressing that rule -- and create no object.
# Each SO node runs its SO public-object control first (the function must
# work under SO before a refusal leg means anything), then the private
# refusal leg. USER private-creation controls prove the role contrast.
# ---------------------------------------------------------------------------

_QC10A_CANONICAL_REFUSAL: dict[str, dict[str, Any]] = {
    "C_CreateObject": {
        "rvs": (int(CKR_USER_NOT_LOGGED_IN),),
        "spec": "v3.2 §5.7.1: only public objects can be created unless the normal user "
        "is logged in",
    },
    "C_CopyObject": {
        "rvs": (int(CKR_USER_NOT_LOGGED_IN),),
        "spec": "v3.2 §5.7.2: only public objects can be created unless the normal user "
        "is logged in",
    },
    "C_GenerateKey": {
        "rvs": (int(CKR_USER_NOT_LOGGED_IN),),
        "spec": "v3.2 §5.18.1 return list: the §5.7 login rule governs all object "
        "creation; an SO session is not the normal user",
    },
    "C_DeriveKey": {
        "rvs": (int(CKR_USER_NOT_LOGGED_IN),),
        "spec": "v3.2 §5.18.5 return list: the §5.7 login rule governs all object "
        "creation; an SO session is not the normal user",
    },
    "C_UnwrapKey": {
        "rvs": (int(CKR_USER_NOT_LOGGED_IN),),
        "spec": "v3.2 §5.18.4 return list: the §5.7 login rule governs all object "
        "creation; an SO session is not the normal user",
    },
}

_QC10A_LOGGED_OUT_RVS = (int(CKR_OK), int(CKR_USER_NOT_LOGGED_IN))


def _qc10a_unique_label(prefix: str) -> str:
    return f"qc10a-{prefix}-{uuid.uuid4().hex[:8]}"


def _qc10a_is_clean(rv: int) -> bool:
    return bool(is_standard_ckr(rv) or is_vendor_defined_ckr(rv))


def _qc10a_create_raw(raw: Any, sh: int, attempt: Mapping[Any, Any]) -> tuple[int, int]:
    """Raw C_CreateObject returning (rv, output handle) so refusals keep evidence."""
    tmpl = template_from_dict(dict(attempt))
    out = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(sh, tmpl.ptr, tmpl.count, byref(out))
    return int(rv), int(out.value)


def _qc10a_copy_raw(raw: Any, sh: int, source: int, attempt: Mapping[Any, Any]) -> tuple[int, int]:
    """Raw C_CopyObject returning (rv, output handle) so refusals keep evidence."""
    tmpl = template_from_dict(dict(attempt))
    out = CK_OBJECT_HANDLE(0)
    rv = raw.C_CopyObject(sh, source, tmpl.ptr, tmpl.count, byref(out))
    return int(rv), int(out.value)


def _qc10a_generate_raw(raw: Any, sh: int, attempt: Mapping[Any, Any]) -> tuple[int, int]:
    """Raw C_GenerateKey (AES) returning (rv, output handle)."""
    mech = mech_simple(CKM_AES_KEY_GEN)
    tmpl = template_from_dict(dict(attempt))
    out = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(out))
    return int(rv), int(out.value)


def _qc10a_derive_raw(
    raw: Any, sh: int, base: int, packed_mech: Any, attempt: Mapping[Any, Any]
) -> tuple[int, int]:
    """Raw C_DeriveKey returning (rv, output handle) so refusals keep evidence."""
    tmpl = template_from_dict(dict(attempt))
    out = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(sh, packed_mech.byref(), base, tmpl.ptr, tmpl.count, byref(out))
    return int(rv), int(out.value)


def _qc10a_unwrap_raw(
    raw: Any, sh: int, kek: int, wrapped: bytes, attempt: Mapping[Any, Any]
) -> tuple[int, int]:
    """Raw C_UnwrapKey (AES_KEY_WRAP) returning (rv, output handle)."""
    mech = mech_simple(CKM_AES_KEY_WRAP)
    tmpl = template_from_dict(dict(attempt))
    in_buf = to_ubyte_buf(wrapped)
    out = CK_OBJECT_HANDLE(0)
    rv = raw.C_UnwrapKey(
        sh, mech.byref(), kek, in_buf, len(wrapped), tmpl.ptr, tmpl.count, byref(out)
    )
    return int(rv), int(out.value)


def _qc10a_setup_failed(
    exc: CkrAssertionError,
    *,
    operation: str,
    purpose: str,
    rs: Any,
    sh: int,
    before: list[int],
    attempt: Mapping[Any, Any],
    identities: tuple[tuple[int, int], ...] = (),
) -> NoReturn:
    """Judge a setup refusal with after-inventory ownership tiers.

    A refused setup call may still have created our object, so the refusal
    runs the established refusal-ownership tiers: a proved-new leftover is
    destroyed and fails, an unproved delta stays alive as honest-deviation
    xfail, and only a clean zero delta keeps the not_operational setup
    xfail. Undefined CK_RV fails after proved leftovers are cleaned.
    """
    rv = int(exc.rv)
    after = _qc10a_after_inventory_or_judge(
        rs, sh, rv=rv, handle=0, label=purpose, operation=operation, leg="setup"
    )
    _qc10a_judge_refusal_ownership(
        rs,
        sh,
        rv=rv,
        handle=0,
        before=before,
        after=after,
        attempt=attempt,
        identities=identities,
        label=purpose,
        operation=operation,
    )
    C.xfail_as(
        "not_operational",
        label=purpose,
        operation=operation,
        inherit_mechanism=False,
        expected=CKR_OK,
        actual=rv,
        detail={"phase": "setup"},
        summary=f"{purpose}: USER-phase setup refused with {ckr_name(rv)}",
    )


def _qc10a_judge_setup_success(
    rs: Any,
    sh: int,
    candidate: int,
    *,
    before: list[int],
    after: list[int],
    attempt: Mapping[Any, Any],
    identities: tuple[tuple[int, int], ...] = (),
    label: str,
    operation: str,
) -> None:
    """Judge setup success: returned handle must be proved, extras fail, companions xfail.

    Mirrors the positive-leg created-extra doctrine (R16-02): proved extras
    beside the returned handle are destroyed and fail; an unproved returned
    handle xfails without being touched; proved handle plus unproved
    companions cleans the owned handle and xfails. Returns on clean (candidate
    proved, zero unexpected delta).
    """
    proved, unproved = partition_proved_new(
        rs.raw,
        sh,
        before,
        after,
        attempt_templates=(dict(attempt),),
        identities=identities,
        error_handles=(candidate,),
    )
    new_handles = sorted({int(handle) for handle in after} - {int(handle) for handle in before})
    extras = sorted(handle for handle in proved if handle != int(candidate))
    if extras:
        for sibling in extras:
            destroy_quietly(rs.raw, sh, sibling)
        if int(candidate) in proved:
            destroy_quietly(rs.raw, sh, int(candidate))
            C.fail_as(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=CKR_OK,
                detail={
                    "phase": "setup",
                    "disposition": "created-extra",
                    "returned_handle": int(candidate),
                    "new_handles": new_handles,
                    "proved_new_handles": sorted(proved),
                    "extra_handles": extras,
                },
                summary=(
                    f"{label}: {operation} returned CKR_OK but created extra proved "
                    f"objects {extras} beside the returned handle"
                ),
            )
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=CKR_OK,
            detail={
                "phase": "setup",
                "disposition": "created-extra",
                "returned_handle": int(candidate),
                "new_handles": new_handles,
                "proved_new_handles": sorted(proved),
                "extra_handles": extras,
                "returned_handle_proved": False,
            },
            summary=(
                f"{label}: {operation} returned CKR_OK with an unproved handle "
                f"but created proved objects {extras}; the returned handle is "
                "foreign, left alive"
            ),
        )
    if int(candidate) not in proved:
        C.xfail_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=CKR_OK,
            detail={
                "phase": "setup",
                "disposition": "unproved-handle",
                "returned_handle": int(candidate),
                "new_handles": new_handles,
            },
            summary=(
                f"{label}: {operation} returned CKR_OK but handle {int(candidate)} "
                "is not proved in the setup inventory delta; it is foreign, left alive"
            ),
        )
    if unproved:
        destroy_quietly(rs.raw, sh, int(candidate))
        C.xfail_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=CKR_OK,
            detail={
                "phase": "setup",
                "disposition": "unproved-effect",
                "returned_handle": int(candidate),
                "new_handles": sorted(unproved),
                "proved_new_handles": [int(candidate)],
            },
            summary=(
                f"{label}: {operation} returned CKR_OK with unexpected delta "
                f"companions {sorted(unproved)}"
            ),
        )


def _qc10a_judge_wrap_setup_success(
    *,
    before: list[int],
    after: list[int],
    label: str,
) -> None:
    """Judge wrap-setup success: any inventory delta is an unproved effect.

    C_WrapKey returns bytes, not a handle, so no delta handle can be proved
    owned -- visibility, not ownership (R17-02). A non-empty delta stays
    alive as an honest-deviation xfail citing the new handles; a zero delta
    proceeds silently.
    """
    new_handles = sorted({int(handle) for handle in after} - {int(handle) for handle in before})
    if new_handles:
        C.xfail_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation="C_WrapKey",
            inherit_mechanism=False,
            actual=CKR_OK,
            detail={
                "phase": "setup",
                "disposition": "unproved-effect",
                "new_handles": new_handles,
                "proved_new_handles": [],
            },
            summary=(
                f"{label}: C_WrapKey returned CKR_OK with an inventory delta "
                f"{new_handles}; no output handle exists to prove ownership, "
                "left alive"
            ),
        )


def _qc10a_premise_refusal(rv: int, *, operation: str, label: str) -> NoReturn:
    """Judge a login/state premise refusal: clean CK_RV xfails, undefined fails."""
    if _qc10a_is_clean(rv):
        C.xfail_as(
            "not_operational",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            expected=CKR_OK,
            actual=rv,
            summary=f"{label}: {operation} refused with {ckr_name(rv)}; premise unmet",
        )
    C.fail_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        expected=CKR_OK,
        actual=rv,
        detail={"ckr_validity": "undefined"},
        summary=f"{label}: {operation} returned undefined {ckr_name(rv)}",
    )


def _qc10a_session_state(raw: Any, sh: int) -> tuple[int, int]:
    """Read C_GetSessionInfo state; returns (rv, state) with state -1 on error."""
    info = CK_SESSION_INFO()
    rv = int(raw.C_GetSessionInfo(sh, byref(info)))
    if rv != int(CKR_OK):
        return rv, -1
    return rv, int(info.state)


class _Qc10aRestorationError(Exception):
    """Internal signal: SO-scope restoration did not reach verified USER state."""

    def __init__(self, operation: str, rv: int, detail: str) -> None:
        super().__init__(operation, rv, detail)
        self.operation = operation
        self.rv = rv
        self.detail = detail


def _qc10a_sweep_find(rs: Any, sh: int, tmpl: Any, *, label: str, what: str) -> list[int]:
    """One sweep inventory: a failed find upgrades the pass, never passes silently."""
    try:
        return find_objects_exhaustive(rs.raw, sh, tmpl)
    except CkrAssertionError as exc:
        inv_rv = int(exc.rv)
        if not _qc10a_is_clean(inv_rv):
            C.fail_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: post-restoration sweep",
                operation="C_FindObjects",
                inherit_mechanism=False,
                actual=inv_rv,
                detail={"sweep": what},
                summary=(f"{label}: post-restoration sweep returned undefined {ckr_name(inv_rv)}"),
            )
        C.xfail_as(
            "honest_deviation",
            kind="metadata",
            label=f"{label}: post-restoration sweep",
            operation="C_FindObjects",
            inherit_mechanism=False,
            actual=inv_rv,
            detail={
                "disposition": "unproved-effect",
                "sweep": what,
                "inventory_rv": ckr_name(inv_rv),
            },
            summary=(
                f"{label}: post-restoration sweep refused with {ckr_name(inv_rv)}; "
                "SO-invisible creation unproved"
            ),
        )
    except AssertionError as exc:
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=f"{label}: post-restoration sweep",
            operation="C_FindObjects",
            inherit_mechanism=False,
            detail={"sweep": what, "error": str(exc)},
            summary=f"{label}: post-restoration sweep violated the Find protocol",
        )
    raise AssertionError("unreachable: every sweep-find branch terminates")


def _qc10a_sweep_restored_user(
    rs: Any,
    sh: int,
    sweeps: list[dict[str, str]],
    *,
    before: list[int],
    label: str,
) -> None:
    """USER-side sweep for SO-invisible window creations.

    Runs after verified USER restoration, before the session closes. Armed
    attempt labels are unique, so a label hit is attributable to its leg:
    found objects are destroyed and fail. Anything else the USER session sees
    that the SO-side baseline never contained is an unattributable remainder
    and stays alive as an unproved-effect xfail.
    """
    for sweep in sweeps:
        attempt_label = sweep["label"]
        operation = sweep["operation"]
        found = _qc10a_sweep_find(
            rs, sh, _label_template(attempt_label), label=label, what="armed-label"
        )
        if found:
            for leaked in found:
                destroy_quietly(rs.raw, sh, leaked)
            C.fail_as(
                "self_contradiction",
                kind="policy",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                detail={
                    "disposition": "refused-but-created",
                    "attempt_label": attempt_label,
                    "new_handles": sorted(int(handle) for handle in found),
                    "proved_new_handles": sorted(int(handle) for handle in found),
                },
                summary=(
                    f"{label}: canonically refused {operation} created "
                    f"{sorted(int(handle) for handle in found)} invisible to the "
                    "SO session (found by the post-restoration sweep)"
                ),
            )
    full = _qc10a_sweep_find(rs, sh, None, label=label, what="full-remainder")
    remainder = sorted(set(full) - {int(handle) for handle in before})
    if remainder:
        C.xfail_as(
            "honest_deviation",
            kind="metadata",
            label=f"{label}: post-restoration sweep",
            operation="C_FindObjects",
            inherit_mechanism=False,
            detail={
                "disposition": "unproved-effect",
                "new_handles": remainder,
                "proved_new_handles": [],
            },
            summary=(
                f"{label}: USER-side sweep found {remainder} never visible to "
                "the SO session; unattributable, left alive"
            ),
        )


@contextmanager
def _qc10a_so_login_scope(
    rs: Any,
    user_pin: bytes,
    so_pin: bytes,
    *,
    explicit_so: bool,
    label: str,
) -> Iterator[tuple[int, dict[str, Any]]]:
    """Establish a verified SO login; restore verified USER login on exit.

    Entry (premise failures xfail, contradictions fail): clear the token-wide
    login, C_Login(CKU_SO), then verify CKS_RW_SO_FUNCTIONS via
    C_GetSessionInfo -- never assumed. Exit (only when SO state was reached):
    C_Logout, C_Login(CKU_USER), then verify CKS_RW_USER_FUNCTIONS. A
    restoration failure fails loudly: on the pass path it is the verdict; on
    a failing primary the restoration RV is attached to that record; on an
    xfail/skip primary the leg is upgraded to fail with both outcomes in
    evidence.
    """
    scope: dict[str, Any] = {
        "transitioned": False,
        "primary": "leg-did-not-run",
        "primary_rv": None,
    }
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
    so_sh = _open_access_session_or_skip(rs, flags)
    cleared = False
    so_reached = False
    try:
        rv = int(rs.raw.C_Logout(so_sh))
        if rv not in _QC10A_LOGGED_OUT_RVS:
            _qc10a_premise_refusal(rv, operation="C_Logout", label=f"{label}: clear login")
        cleared = True
        pin_buf = (CK_UTF8CHAR * len(so_pin))(*so_pin)
        rv = int(rs.raw.C_Login(so_sh, CKU_SO, pin_buf, len(so_pin)))
        skip_if_so_pin_rejected(rv, explicit=explicit_so)
        if rv in (CKR_USER_ALREADY_LOGGED_IN, CKR_USER_ANOTHER_ALREADY_LOGGED_IN):
            pytest.skip("Another user already logged in on this token")
        if rv != int(CKR_OK):
            _qc10a_premise_refusal(rv, operation="C_Login", label=f"{label}: SO login")
        so_reached = True
        srv, state = _qc10a_session_state(rs.raw, so_sh)
        if srv != int(CKR_OK):
            _qc10a_premise_refusal(
                srv, operation="C_GetSessionInfo", label=f"{label}: verify SO state"
            )
        if state != int(CKS_RW_SO_FUNCTIONS):
            C.fail_as(
                "self_contradiction",
                kind="lifecycle",
                label=f"{label}: verify SO state",
                operation="C_GetSessionInfo",
                inherit_mechanism=False,
                expected=int(CKS_RW_SO_FUNCTIONS),
                actual=state,
                summary=(
                    f"{label}: C_Login(CKU_SO) returned CKR_OK but the session state "
                    f"reads {state}, not CKS_RW_SO_FUNCTIONS"
                ),
            )
        scope["transitioned"] = True
        yield so_sh, scope
    finally:
        # Every exit path closes the scope session; every path that cleared
        # the entry login also restores verified USER state (early exits
        # included: a refused SO login must not strand the token logged out,
        # an unverified SO login must not strand it SO-logged-in).
        # Capture before the try: inside the handler below, sys.exc_info()
        # reports the restoration signal, not the propagating primary.
        in_flight = sys.exc_info()[1]
        try:
            if scope["transitioned"]:
                try:
                    _qc10a_restore_user(rs, so_sh, user_pin)
                except _Qc10aRestorationError as rest:
                    _qc10a_report_restoration_failure(scope, rest, label, in_flight)
                else:
                    sweeps = scope.get("sweep_labels")
                    if in_flight is None and sweeps:
                        _qc10a_sweep_restored_user(
                            rs,
                            so_sh,
                            sweeps,
                            before=scope.get("sweep_before", []),
                            label=label,
                        )
            elif so_reached or cleared:
                try:
                    _qc10a_restore_user(rs, so_sh, user_pin)
                except _Qc10aRestorationError as rest:
                    _qc10a_report_restoration_failure(scope, rest, label, in_flight)
        finally:
            # The session closes even when restoration reporting or the
            # sweep raises: a sweep verdict must not leak the session.
            close_session_quietly(rs.raw, so_sh)


def _qc10a_restore_user(rs: Any, so_sh: int, user_pin: bytes) -> None:
    """Return the token to verified USER login; raises _Qc10aRestorationError."""
    rv = int(rs.raw.C_Logout(so_sh))
    if rv not in _QC10A_LOGGED_OUT_RVS:
        raise _Qc10aRestorationError("C_Logout", rv, f"SO logout refused with {ckr_name(rv)}")
    pin_buf = (CK_UTF8CHAR * len(user_pin))(*user_pin)
    rv = int(rs.raw.C_Login(so_sh, CKU_USER, pin_buf, len(user_pin)))
    if rv != int(CKR_OK):
        raise _Qc10aRestorationError("C_Login", rv, f"USER re-login refused with {ckr_name(rv)}")
    srv, state = _qc10a_session_state(rs.raw, so_sh)
    if srv != int(CKR_OK):
        raise _Qc10aRestorationError(
            "C_GetSessionInfo", srv, f"restoration state unreadable: {ckr_name(srv)}"
        )
    if state != int(CKS_RW_USER_FUNCTIONS):
        raise _Qc10aRestorationError(
            "C_GetSessionInfo",
            srv,
            f"session state reads {state}, not CKS_RW_USER_FUNCTIONS",
        )


def _qc10a_report_restoration_failure(
    scope: dict[str, Any],
    rest: _Qc10aRestorationError,
    label: str,
    in_flight: BaseException | None,
) -> None:
    """Fail loudly on restoration failure, preserving the primary outcome."""
    from _pytest.outcomes import Failed, Skipped, XFailed

    primary = str(scope.get("primary", "leg-did-not-run"))
    primary_rv = scope.get("primary_rv")
    records = C.get_records()
    restoration_detail: dict[str, Any] = {
        "primary": primary,
        "restoration_operation": rest.operation,
        "restoration_rv": ckr_name(rest.rv),
        "restoration_detail": rest.detail,
    }
    if primary_rv is not None:
        restoration_detail["primary_rv"] = ckr_name(int(primary_rv))
    if in_flight is None and not records:
        C.fail_as(
            "self_contradiction",
            kind="lifecycle",
            label=f"{label}: restore USER login",
            operation=rest.operation,
            inherit_mechanism=False,
            actual=rest.rv,
            detail=restoration_detail,
            summary=f"{label}: restoration failed ({rest.detail}) after {primary}",
        )
    if records and isinstance(in_flight, XFailed):
        # XFailed subclasses Failed: check it first, then upgrade to fail.
        # The upgrade drops the xfail reason and re-derives FAIL severity so
        # the rewritten record stays consistent with the verdict model.
        last = records[-1]
        last.detail = {**(last.detail or {}), **restoration_detail}
        last.reason = "self_contradiction"
        last.outcome = "fail"
        last.severity = C.derive_verdict(last.reason, last.kind)[1]
        last.summary = f"{last.summary} (restoration also failed: {rest.detail})"
        C.raise_for_record(last)
    if records and isinstance(in_flight, Failed):
        last = records[-1]
        last.detail = {**(last.detail or {}), **restoration_detail}
        return
    C.fail_as(
        "self_contradiction",
        kind="lifecycle",
        label=f"{label}: restore USER login",
        operation=rest.operation,
        inherit_mechanism=False,
        actual=rest.rv,
        detail={
            **restoration_detail,
            "in_flight": (
                f"{type(in_flight).__name__}: {in_flight}"
                if in_flight is not None and not isinstance(in_flight, Skipped)
                else ("skipped" if isinstance(in_flight, Skipped) else "none")
            ),
        },
        summary=f"{label}: restoration failed ({rest.detail}) after {primary}",
    )


def _qc10a_inventory_or_classify(rs: Any, sh: int, *, phase: str, label: str) -> list[int]:
    """Exhaustive inventory judging inventory RVs (clean xfail, undefined fail)."""
    try:
        return find_objects_exhaustive(rs.raw, sh)
    except CkrAssertionError as exc:
        rv = int(exc.rv)
        if not _qc10a_is_clean(rv):
            C.fail_as(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation="C_FindObjects",
                inherit_mechanism=False,
                actual=rv,
                detail={"phase": phase, "rv": ckr_name(rv)},
                summary=f"{label}: {phase} inventory returned undefined {ckr_name(rv)}",
            )
        C.xfail_as(
            "not_operational",
            label=f"{label}: object inventory not operational",
            operation="C_FindObjects",
            inherit_mechanism=False,
            actual=rv,
            detail={"phase": phase, "rv": ckr_name(rv)},
            summary=f"{label}: {phase} inventory refused with {ckr_name(rv)}",
        )
    except AssertionError as exc:
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_FindObjects",
            inherit_mechanism=False,
            detail={"phase": phase, "error": str(exc)},
            summary=f"{label}: {phase} inventory violated the Find protocol",
        )


def _qc10a_after_inventory_or_judge(
    rs: Any,
    sh: int,
    *,
    rv: int,
    handle: int,
    label: str,
    operation: str,
    leg: str,
) -> list[int]:
    """After-inventory preserving known failures (acceptance, undefined RV).

    Mirrors the QC9a doctrine: an undefined operation RV and an acceptance on
    a must-reject leg are known failures that a failed after-inventory must
    not downgrade (the handle stays alive, the verdict stays FAIL with both
    RVs in evidence). A defined refusal with a failed inventory is an
    unproved-effect xfail; CKR_OK on a positive leg with a failed inventory
    is an unproved-creation xfail, never a pass.
    """
    try:
        return find_objects_exhaustive(rs.raw, sh)
    except CkrAssertionError as exc:
        inv_rv = int(exc.rv)
        detail: dict[str, Any] = {
            "phase": "after",
            "leg": leg,
            "handle_after": handle,
            "operation_rv": ckr_name(rv),
            "inventory_rv": ckr_name(inv_rv),
        }
        if rv != int(CKR_OK) and not _qc10a_is_clean(rv):
            C.fail_as(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=rv,
                detail=detail,
                summary=(
                    f"{label}: refused with undefined {ckr_name(rv)}; "
                    f"after-inventory failed with {ckr_name(inv_rv)}"
                ),
            )
        if not _qc10a_is_clean(inv_rv):
            C.fail_as(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation="C_FindObjects",
                inherit_mechanism=False,
                actual=inv_rv,
                detail=detail,
                summary=f"{label}: after inventory returned undefined {ckr_name(inv_rv)}",
            )
        if rv == int(CKR_OK) and leg == "negative":
            C.classify(
                "accepted_invalid",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=rv,
                expected=(CKR_USER_NOT_LOGGED_IN,),
                detail={**detail, "disposition": "unproved-handle-alive"},
                summary=(
                    f"{label}: accepted invalid (CKR_OK) -- must reject; "
                    f"after-inventory failed with {ckr_name(inv_rv)}, handle left alive"
                ),
            )
        if rv == int(CKR_OK):
            C.xfail_as(
                "not_operational",
                label=f"{label}: object inventory not operational",
                operation="C_FindObjects",
                inherit_mechanism=False,
                actual=inv_rv,
                detail={"phase": "after", "rv": ckr_name(inv_rv)},
                summary=f"{label}: after inventory refused with {ckr_name(inv_rv)}",
            )
        C.xfail_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=rv,
            detail={**detail, "disposition": "unproved-effect"},
            summary=(
                f"{label}: refusal {ckr_name(rv)} with a failed after-inventory "
                f"({ckr_name(inv_rv)}); zero-delta unproved"
            ),
        )
    except AssertionError as exc:
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_FindObjects",
            inherit_mechanism=False,
            detail={
                "phase": "after",
                "leg": leg,
                "handle_after": handle,
                "operation_rv": ckr_name(rv),
                "error": str(exc),
            },
            summary=f"{label}: after inventory violated the Find protocol",
        )


def _qc10a_judge_refusal_ownership(
    rs: Any,
    sh: int,
    *,
    rv: int,
    handle: int,
    before: list[int],
    after: list[int],
    attempt: Mapping[Any, Any],
    identities: tuple[tuple[int, int], ...],
    label: str,
    operation: str,
) -> None:
    """Ownership-first refusal judge; returns only on a clean zero delta.

    A proved-new leftover is destroyed and fails; an unproved delta stays
    alive as honest-deviation xfail. Undefined operation RVs fail after
    proved leftovers are cleaned, so an undefined RV never hides a leak.
    Never touches unproved handles.
    """
    proved, unproved = partition_proved_new(
        rs.raw,
        sh,
        before,
        after,
        attempt_templates=(dict(attempt),),
        identities=identities,
        error_handles=(handle,),
    )
    before_set = {int(h) for h in before}
    after_set = {int(h) for h in after}
    detail: dict[str, Any] = {
        "handle_after": handle,
        "new_handles": sorted(after_set - before_set),
        "proved_new_handles": proved,
        "unproved_new_handles": unproved,
    }
    if proved:
        for leaked in proved:
            destroy_quietly(rs.raw, sh, leaked)
    if not _qc10a_is_clean(rv):
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=rv,
            detail=detail,
            summary=f"{label}: refused with undefined {ckr_name(rv)}",
        )
    if proved:
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=rv,
            detail={**detail, "disposition": "refused-but-created"},
            summary=f"{label}: refusal {ckr_name(rv)} left an object behind",
        )
    if unproved:
        C.xfail_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=rv,
            detail={**detail, "disposition": "unproved-effect"},
            summary=(
                f"{label}: refusal {ckr_name(rv)} with an unproved inventory delta; left alive"
            ),
        )


def _qc10a_read_private_bool(rs: Any, sh: int, handle: int, *, label: str) -> tuple[str, Any]:
    """Read CKA_PRIVATE via the sanctioned accessor; returns (status, evidence).

    Statuses: "value" (bool), "missing" (the recorded absence observation,
    for single-record enrich-and-re-raise), "refused" (clean read RV),
    "undefined" (undefined read RV), "malformed" (non-bool value). Callers
    emit exactly one verdict from the status.
    """
    try:
        attrs = read_attributes(rs.raw, sh, handle, [CKA_PRIVATE])
    except CkrAssertionError as exc:
        rv = int(exc.rv)
        if _qc10a_is_clean(rv):
            return "refused", rv
        return "undefined", rv
    value = attr_or_record(
        attrs,
        CKA_PRIVATE,
        label=label,
        reason="honest_deviation",
        kind="metadata",
        inherit_mechanism=False,
    )
    if value is MISSING_ATTRIBUTE:
        return "missing", C.get_records()[-1]
    if type(value) is bool:
        return "value", value
    return "malformed", value


def _qc10a_login_user_verified(rs: Any, sh: int, pin: bytes, *, label: str) -> None:
    """Explicit USER login (never ambient): OK/ALREADY/NSS-quirk pass, else judge."""
    pin_buf = (CK_UTF8CHAR * len(pin))(*pin)
    rv = int(rs.raw.C_Login(sh, CKU_USER, pin_buf, len(pin)))
    if rv in (int(CKR_OK), int(CKR_USER_ALREADY_LOGGED_IN), int(CKR_USER_TYPE_INVALID)):
        return
    _qc10a_premise_refusal(rv, operation="C_Login", label=f"{label}: USER login")


def _qc10a_prove_source_visible(
    rs: Any, so_sh: int, source: int, source_label: str, *, label: str
) -> None:
    """Prove the setup source is visible to the SO session.

    A USER-private source hidden from SO would mask the output-creation rule
    (the attempt would fail on the invisible input, not the private output),
    so invisibility xfails the leg before any attempt runs.
    """
    try:
        found = find_objects(rs.raw, so_sh, _label_template(source_label))
    except CkrAssertionError as exc:
        _qc10a_premise_refusal(
            int(exc.rv), operation="C_FindObjects", label=f"{label}: source visibility"
        )
    except AssertionError as exc:
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=f"{label}: source visibility",
            operation="C_FindObjects",
            inherit_mechanism=False,
            detail={"error": str(exc)},
            summary=f"{label}: source-visibility find violated the Find protocol",
        )
    if int(source) not in {int(handle) for handle in found}:
        C.xfail_as(
            "not_operational",
            label=label,
            operation="C_FindObjects",
            inherit_mechanism=False,
            summary=(
                f"{label}: setup source not visible to the SO session; "
                "output-creation rule untestable"
            ),
        )


def _qc10a_note_primary(scope: dict[str, Any] | None, primary: str, rv: int | None) -> None:
    if scope is not None:
        scope["primary"] = primary
        scope["primary_rv"] = rv


def _qc10a_run_positive_leg(
    rs: Any,
    sh: int,
    scope: dict[str, Any] | None,
    *,
    operation: str,
    attempt: Mapping[Any, Any],
    identities: tuple[tuple[int, int], ...],
    attempt_fn: Any,
    expected_private: bool,
    label: str,
) -> None:
    """Positive creation leg (SO-public or USER-private control).

    CKR_OK with a proved-new object reading back the expected CKA_PRIVATE
    passes. Clean refusal xfails, never passes; undefined RVs fail; CKR_OK
    with the wrong effect fails; CKR_OK with an unproved handle, an
    unreadable readback, or unexpected delta companions xfails unproved.
    Owned objects are always destroyed.
    """
    before = _qc10a_inventory_or_classify(rs, sh, phase="before", label=label)
    rv, handle = attempt_fn()
    if rv == int(CKR_OK):
        _qc10a_note_primary(scope, f"{operation} created", rv)
    else:
        _qc10a_note_primary(scope, f"{operation} refused with {ckr_name(rv)}", rv)
    after = _qc10a_after_inventory_or_judge(
        rs, sh, rv=rv, handle=handle, label=label, operation=operation, leg="positive"
    )
    if rv != int(CKR_OK):
        _qc10a_judge_refusal_ownership(
            rs,
            sh,
            rv=rv,
            handle=handle,
            before=before,
            after=after,
            attempt=attempt,
            identities=identities,
            label=label,
            operation=operation,
        )
        C.xfail_as(
            "not_operational",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            expected=CKR_OK,
            actual=rv,
            summary=f"{label}: {operation} refused a valid control template with {ckr_name(rv)}",
        )
    proved, unproved = partition_proved_new(
        rs.raw,
        sh,
        before,
        after,
        attempt_templates=(dict(attempt),),
        identities=identities,
        error_handles=(handle,),
    )
    extras = sorted(h for h in proved if h != handle)
    if extras:
        # Proved side-creations are judged FIRST, even when the returned
        # handle itself is foreign: a provider that demonstrably created
        # our objects while handing back a foreign handle is contradictory,
        # not a premise gap. Proved handles are destroyed; a foreign
        # returned handle is never touched and stays alive.
        for sibling in extras:
            destroy_quietly(rs.raw, sh, sibling)
        if handle in proved:
            # The call created more than it returned, and the siblings are
            # proved-new (ours): destroy them all, then fail loud -- a CKR_OK
            # creation must create exactly the returned object.
            destroy_quietly(rs.raw, sh, handle)
            C.fail_as(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=rv,
                detail={
                    "disposition": "created-extra",
                    "handle_after": handle,
                    "new_handles": sorted({int(h) for h in after} - {int(h) for h in before}),
                    "proved_new_handles": sorted(proved),
                    "extra_handles": extras,
                },
                summary=(
                    f"{label}: {operation} returned CKR_OK but created extra proved "
                    f"objects {extras} beside the returned handle"
                ),
            )
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=rv,
            detail={
                "disposition": "created-extra",
                "handle_after": handle,
                "new_handles": sorted({int(h) for h in after} - {int(h) for h in before}),
                "proved_new_handles": sorted(proved),
                "extra_handles": extras,
                "returned_handle_proved": False,
            },
            summary=(
                f"{label}: {operation} returned CKR_OK with an unproved handle "
                f"but created proved objects {extras}; the returned handle is "
                "foreign, left alive"
            ),
        )
    if handle not in proved:
        C.xfail_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=rv,
            detail={"disposition": "unproved-handle", "handle_after": handle},
            summary=f"{label}: {operation} returned CKR_OK but the handle is unproved",
        )
    if unproved:
        # The handle is proved, but the delta gained unexpected companions:
        # not a clean pass. The owned handle is cleaned; the companions are
        # unprovable and stay alive.
        destroy_quietly(rs.raw, sh, handle)
        C.xfail_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=rv,
            detail={
                "disposition": "unproved-effect",
                "handle_after": handle,
                "new_handles": sorted(unproved),
                "proved_new_handles": [handle],
            },
            summary=(
                f"{label}: {operation} returned CKR_OK with unexpected delta "
                f"companions {sorted(unproved)}"
            ),
        )
    status, evidence = _qc10a_read_private_bool(
        rs, sh, handle, label=f"{label} CKA_PRIVATE readback"
    )
    destroy_quietly(rs.raw, sh, handle)
    if status == "value" and evidence is expected_private:
        _qc10a_note_primary(scope, f"{operation} created and verified", rv)
        # Arm the post-restoration sweep for the control label too: an
        # SO-hidden creation during the control window must not pass
        # silently. USER legs (scope None) need no sweep: their inventories
        # already see everything.
        if scope is not None:
            sweep_label = attempt.get(CKA_LABEL)
            if isinstance(sweep_label, str):
                scope.setdefault("sweep_labels", []).append(
                    {"label": sweep_label, "operation": operation}
                )
        return
    if status == "value":
        if expected_private:
            C.fail_as(
                "wrong_result",
                kind="policy",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                detail={"expected_private": True, "actual_private": False},
                summary=f"{label}: asked CKA_PRIVATE=True, the object reads back False",
            )
        C.fail_as(
            "self_contradiction",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            detail={"expected_private": False, "actual_private": True},
            summary=(
                f"{label}: SO session created a CKA_PRIVATE=True object "
                "(PKCS#11 requires CKR_USER_NOT_LOGGED_IN)"
            ),
        )
    if status == "missing":
        evidence.detail = {**(evidence.detail or {}), "disposition": "unreadable-value"}
        C.raise_for_record(evidence)
    if status == "refused":
        C.xfail_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            actual=evidence,
            detail={"disposition": "unreadable-value", "readback": "refused"},
            summary=f"{label}: created object CKA_PRIVATE unreadable (refused)",
        )
    if status == "undefined":
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            actual=evidence,
            detail={"ckr_validity": "undefined"},
            summary=f"{label}: CKA_PRIVATE readback returned undefined {ckr_name(evidence)}",
        )
    C.fail_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        inherit_mechanism=False,
        detail={"expected": "strict CK_BBOOL (bool)", "actual_type": type(evidence).__name__},
        summary=f"{label}: present CKA_PRIVATE has malformed value: {type(evidence).__name__}",
    )


def _qc10a_run_negative_leg(
    rs: Any,
    sh: int,
    scope: dict[str, Any] | None,
    *,
    operation: str,
    attempt: Mapping[Any, Any],
    identities: tuple[tuple[int, int], ...],
    attempt_fn: Any,
    label: str,
) -> None:
    """SO private-creation refusal leg.

    Canonical CKR_USER_NOT_LOGGED_IN with zero inventory delta passes; other
    clean refusals xfail preserving the original RV; acceptance always fails
    (the refusal assertion is independent of the readback); undefined RVs
    fail; known failures survive inventory gaps.
    """
    before = _qc10a_inventory_or_classify(rs, sh, phase="before", label=label)
    rv, handle = attempt_fn()
    if rv == int(CKR_OK):
        _qc10a_note_primary(scope, f"{operation} accepted (CKR_OK)", rv)
    else:
        _qc10a_note_primary(scope, f"{operation} refused with {ckr_name(rv)}", rv)
    after = _qc10a_after_inventory_or_judge(
        rs, sh, rv=rv, handle=handle, label=label, operation=operation, leg="negative"
    )
    if rv == int(CKR_OK):
        _qc10a_judge_negative_acceptance(
            rs,
            sh,
            handle=handle,
            before=before,
            after=after,
            attempt=attempt,
            identities=identities,
            label=label,
            operation=operation,
        )
    _qc10a_judge_refusal_ownership(
        rs,
        sh,
        rv=rv,
        handle=handle,
        before=before,
        after=after,
        attempt=attempt,
        identities=identities,
        label=label,
        operation=operation,
    )
    canonical = _QC10A_CANONICAL_REFUSAL[operation]["rvs"]
    if rv in canonical:
        _qc10a_note_primary(scope, f"{operation} canonically refused", rv)
        # The SO-side delta is zero, but a refused-but-created private object
        # would be invisible to the SO session: arm a post-restoration
        # USER-side sweep by attempt label (runs only on the pass path).
        if scope is not None:
            sweep_label = attempt.get(CKA_LABEL)
            if isinstance(sweep_label, str):
                scope.setdefault("sweep_labels", []).append(
                    {"label": sweep_label, "operation": operation}
                )
                scope["sweep_before"] = before
        return
    C.classify(
        "nonspec_reject",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        actual=rv,
        expected=(CKR_USER_NOT_LOGGED_IN,),
        summary=(
            f"{label}: rejected with {ckr_name(rv)}; "
            f"spec requires {ckr_name(int(CKR_USER_NOT_LOGGED_IN))}"
        ),
    )


def _qc10a_judge_negative_acceptance(
    rs: Any,
    sh: int,
    *,
    handle: int,
    before: list[int],
    after: list[int],
    attempt: Mapping[Any, Any],
    identities: tuple[tuple[int, int], ...],
    label: str,
    operation: str,
) -> NoReturn:
    """Judge CKR_OK on a must-reject leg: proved claims fail, unproved stays FAIL-alive."""
    proved, _unproved = partition_proved_new(
        rs.raw,
        sh,
        before,
        after,
        attempt_templates=(dict(attempt),),
        identities=identities,
        error_handles=(handle,),
    )
    extras = sorted(h for h in proved if h != handle)
    if extras:
        # Proved side-creations are judged FIRST, even when the returned
        # handle itself is foreign: a provider that demonstrably created
        # our objects while handing back a foreign handle is contradictory,
        # not a premise gap. Proved handles are destroyed; a foreign
        # returned handle is never touched and stays alive.
        for sibling in extras:
            destroy_quietly(rs.raw, sh, sibling)
        if handle in proved:
            # The acceptance created more than it returned, and the siblings are
            # proved-new (ours): destroy them all, then fail loud -- the same
            # created-extra shape as the positive leg.
            destroy_quietly(rs.raw, sh, handle)
            C.fail_as(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=CKR_OK,
                detail={
                    "disposition": "created-extra",
                    "handle_after": handle,
                    "new_handles": sorted({int(h) for h in after} - {int(h) for h in before}),
                    "proved_new_handles": sorted(proved),
                    "extra_handles": extras,
                },
                summary=(
                    f"{label}: {operation} accepted (CKR_OK) on a must-reject leg but "
                    f"created extra proved objects {extras} beside the returned handle"
                ),
            )
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=CKR_OK,
            detail={
                "disposition": "created-extra",
                "handle_after": handle,
                "new_handles": sorted({int(h) for h in after} - {int(h) for h in before}),
                "proved_new_handles": sorted(proved),
                "extra_handles": extras,
                "returned_handle_proved": False,
            },
            summary=(
                f"{label}: {operation} accepted (CKR_OK) on a must-reject leg "
                f"with an unproved handle but created proved objects {extras}; "
                "the returned handle is foreign, left alive"
            ),
        )
    if handle not in proved:
        C.classify(
            "accepted_invalid",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=CKR_OK,
            expected=(CKR_USER_NOT_LOGGED_IN,),
            detail={"disposition": "unproved-handle-alive", "handle_after": handle},
            summary=(
                f"{label}: accepted invalid (CKR_OK) -- must reject; handle unproved, left alive"
            ),
        )
    status, evidence = _qc10a_read_private_bool(
        rs, sh, handle, label=f"{label} CKA_PRIVATE readback"
    )
    destroy_quietly(rs.raw, sh, handle)
    if status == "value" and evidence is True:
        C.fail_as(
            "self_contradiction",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            expected=CKR_USER_NOT_LOGGED_IN,
            actual=CKR_OK,
            detail={"attribute": int(CKA_PRIVATE), "expected": True, "actual": True},
            summary=(
                f"{label}: SO session created a CKA_PRIVATE=True object "
                "(PKCS#11 requires CKR_USER_NOT_LOGGED_IN)"
            ),
        )
    if status == "value":
        # CKR_OK on a must-reject leg fails however the object reads back:
        # the refusal assertion does not depend on the protection claim, and
        # a False readback is a second violation (attribute flip), not an
        # excuse. The proved handle was already destroyed above.
        C.classify(
            "accepted_invalid",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=CKR_OK,
            expected=(CKR_USER_NOT_LOGGED_IN,),
            detail={
                "attribute": int(CKA_PRIVATE),
                "expected": True,
                "actual": evidence,
                "readback_private": evidence,
            },
            summary=(
                f"{label}: accepted invalid (CKR_OK) -- must reject; "
                f"object reads CKA_PRIVATE={evidence}"
            ),
        )
    if status == "missing":
        # The accepted CKA_PRIVATE=True template is independent claim evidence
        # a missing readback must not downgrade: rewrite the absence
        # observation into the policy failure it supports (single record).
        evidence.reason = "self_contradiction"
        evidence.kind = "policy"
        evidence.outcome = "fail"
        evidence.severity = C.derive_verdict(evidence.reason, evidence.kind)[1]
        evidence.operation = operation
        evidence.label = label
        evidence.expected_ckr = [ckr_name(int(CKR_USER_NOT_LOGGED_IN))]
        evidence.actual_ckr = ckr_name(int(CKR_OK))
        evidence.detail = {
            **(evidence.detail or {}),
            "attribute": int(CKA_PRIVATE),
            "readback": "missing",
        }
        evidence.summary = (
            f"{label}: SO session accepted CKA_PRIVATE=True but the readback is "
            "missing; claim preserved"
        )
        C.raise_for_record(evidence)
    if status == "refused":
        # Same claim-preservation as missing, with no prior record to rewrite.
        C.fail_as(
            "self_contradiction",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            expected=CKR_USER_NOT_LOGGED_IN,
            actual=CKR_OK,
            detail={
                "attribute": int(CKA_PRIVATE),
                "readback": "refused",
                "read_rv": ckr_name(int(evidence)),
            },
            summary=(
                f"{label}: SO session accepted CKA_PRIVATE=True but the readback is "
                "refused; claim preserved"
            ),
        )
    if status == "undefined":
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            actual=evidence,
            detail={"ckr_validity": "undefined"},
            summary=f"{label}: CKA_PRIVATE readback returned undefined {ckr_name(evidence)}",
        )
    C.fail_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        inherit_mechanism=False,
        detail={"expected": "strict CK_BBOOL (bool)", "actual_type": type(evidence).__name__},
        summary=f"{label}: present CKA_PRIVATE has malformed value: {type(evidence).__name__}",
    )


def _qc10a_so_pins(p11_config: Any, rs: Any) -> tuple[bytes, bytes, bool]:
    """Resolve USER + SO PINs with the SO lockout guard; skips when unusable."""
    user_pin = get_pin_bytes(p11_config)
    if user_pin is None:
        pytest.skip("No PIN configured")
    so_pin, explicit = resolve_so_pin(p11_config)
    if so_pin is None:
        pytest.skip("No PIN configured")
    guard_so_lockout(rs.raw, rs.slot_id, explicit=explicit)
    return user_pin, so_pin, explicit


class TestSOPrivateCreation:
    """SO sessions must refuse private-object creation (v3.2 §5.7 login rule).

    Each node runs its SO public-object control first, then the private
    refusal leg; credentials are scoped per leg and the USER login state is
    restored explicitly with verification.
    """

    @pytest.mark.destructive
    def test_so_cannot_create_private_object(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_CreateObject with CKA_PRIVATE=True on an SO session must refuse."""
        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
        user_pin, so_pin, explicit = _qc10a_so_pins(p11_config, rs)
        label = "SO C_CreateObject CKA_PRIVATE=True"
        control_label = _qc10a_unique_label("create-pub")
        negative_label = _qc10a_unique_label("create-priv")
        with _qc10a_so_login_scope(rs, user_pin, so_pin, explicit_so=explicit, label=label) as (
            so_sh,
            scope,
        ):
            control: dict[Any, Any] = {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: control_label,
                CKA_VALUE: b"qc10a-so-public-create",
                CKA_TOKEN: False,
                CKA_PRIVATE: False,
            }
            _qc10a_run_positive_leg(
                rs,
                so_sh,
                scope,
                operation="C_CreateObject",
                attempt=control,
                identities=(),
                attempt_fn=lambda: _qc10a_create_raw(rs.raw, so_sh, control),
                expected_private=False,
                label=f"{label} control",
            )
            negative: dict[Any, Any] = {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: negative_label,
                CKA_VALUE: b"qc10a-so-private-create",
                CKA_TOKEN: False,
                CKA_PRIVATE: True,
            }
            _qc10a_run_negative_leg(
                rs,
                so_sh,
                scope,
                operation="C_CreateObject",
                attempt=negative,
                identities=(),
                attempt_fn=lambda: _qc10a_create_raw(rs.raw, so_sh, negative),
                label=label,
            )

    @pytest.mark.destructive
    def test_so_cannot_copy_to_private_object(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_CopyObject flipping CKA_PRIVATE=True on an SO session must refuse.

        The source is a PUBLIC session data object, and its visibility to the
        SO session is proven first so a hidden source cannot mask the
        output-creation rule.
        """
        rs = p11_raw_session
        user_pin, so_pin, explicit = _qc10a_so_pins(p11_config, rs)
        label = "SO C_CopyObject CKA_PRIVATE=True"
        source_label = _qc10a_unique_label("copy-src")
        source = 0
        try:
            setup_before = _qc10a_inventory_or_classify(
                rs, rs.sh, phase="setup-before", label=f"{label} source setup"
            )
            source_attempt: dict[Any, Any] = {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: source_label,
                CKA_VALUE: b"qc10a-copy-source",
                CKA_TOKEN: False,
                CKA_PRIVATE: False,
            }
            try:
                candidate = create_object(rs.raw, rs.sh, source_attempt)
            except CkrAssertionError as exc:
                _qc10a_setup_failed(
                    exc,
                    operation="C_CreateObject",
                    purpose=f"{label} source setup",
                    rs=rs,
                    sh=rs.sh,
                    before=setup_before,
                    attempt=source_attempt,
                )
            setup_after = _qc10a_after_inventory_or_judge(
                rs,
                rs.sh,
                rv=int(CKR_OK),
                handle=candidate,
                label=f"{label} source setup",
                operation="C_CreateObject",
                leg="positive",
            )
            _qc10a_judge_setup_success(
                rs,
                rs.sh,
                candidate,
                before=setup_before,
                after=setup_after,
                attempt=source_attempt,
                label=f"{label} source setup",
                operation="C_CreateObject",
            )
            source = candidate
            control_label = _qc10a_unique_label("copy-pub")
            negative_label = _qc10a_unique_label("copy-priv")
            with _qc10a_so_login_scope(rs, user_pin, so_pin, explicit_so=explicit, label=label) as (
                so_sh,
                scope,
            ):
                _qc10a_prove_source_visible(rs, so_sh, source, source_label, label=label)
                control: dict[Any, Any] = {CKA_PRIVATE: False, CKA_LABEL: control_label}
                _qc10a_run_positive_leg(
                    rs,
                    so_sh,
                    scope,
                    operation="C_CopyObject",
                    attempt=control,
                    identities=(),
                    attempt_fn=lambda: _qc10a_copy_raw(rs.raw, so_sh, source, control),
                    expected_private=False,
                    label=f"{label} control",
                )
                negative: dict[Any, Any] = {CKA_PRIVATE: True, CKA_LABEL: negative_label}
                _qc10a_run_negative_leg(
                    rs,
                    so_sh,
                    scope,
                    operation="C_CopyObject",
                    attempt=negative,
                    identities=(),
                    attempt_fn=lambda: _qc10a_copy_raw(rs.raw, so_sh, source, negative),
                    label=label,
                )
        finally:
            if source:
                destroy_quietly(rs.raw, rs.sh, source)

    @pytest.mark.destructive
    def test_so_cannot_generate_private_key(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_GenerateKey with CKA_PRIVATE=True on an SO session must refuse."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not advertised")
        user_pin, so_pin, explicit = _qc10a_so_pins(p11_config, rs)
        label = "SO C_GenerateKey CKA_PRIVATE=True"
        identity = (int(CKO_SECRET_KEY), int(CKK_AES))
        control_label = _qc10a_unique_label("gen-pub")
        negative_label = _qc10a_unique_label("gen-priv")
        with _qc10a_so_login_scope(rs, user_pin, so_pin, explicit_so=explicit, label=label) as (
            so_sh,
            scope,
        ):
            control: dict[Any, Any] = {
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_KEY_TYPE: CKK_AES,
                CKA_VALUE_LEN: 16,
                CKA_TOKEN: False,
                CKA_PRIVATE: False,
                CKA_LABEL: control_label,
            }
            _qc10a_run_positive_leg(
                rs,
                so_sh,
                scope,
                operation="C_GenerateKey",
                attempt=control,
                identities=(identity,),
                attempt_fn=lambda: _qc10a_generate_raw(rs.raw, so_sh, control),
                expected_private=False,
                label=f"{label} control",
            )
            negative: dict[Any, Any] = {
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_KEY_TYPE: CKK_AES,
                CKA_VALUE_LEN: 16,
                CKA_TOKEN: False,
                CKA_PRIVATE: True,
                CKA_LABEL: negative_label,
            }
            _qc10a_run_negative_leg(
                rs,
                so_sh,
                scope,
                operation="C_GenerateKey",
                attempt=negative,
                identities=(identity,),
                attempt_fn=lambda: _qc10a_generate_raw(rs.raw, so_sh, negative),
                label=label,
            )

    @pytest.mark.destructive
    def test_so_cannot_derive_private_key(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_DeriveKey (HKDF) with CKA_PRIVATE=True on an SO session must refuse.

        The base key is a PUBLIC session AES key, and its visibility to the
        SO session is proven first.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not advertised")
        user_pin, so_pin, explicit = _qc10a_so_pins(p11_config, rs)
        label = "SO C_DeriveKey(HKDF) CKA_PRIVATE=True"
        source_label = _qc10a_unique_label("derive-base")
        base = 0
        try:
            setup_before = _qc10a_inventory_or_classify(
                rs, rs.sh, phase="setup-before", label=f"{label} base setup"
            )
            base_attempt: dict[Any, Any] = {
                CKA_TOKEN: False,
                CKA_PRIVATE: False,
                CKA_DERIVE: True,
                CKA_LABEL: source_label,
                CKA_EXTRACTABLE: True,
            }
            try:
                candidate = gen_aes_key(rs.raw, rs.sh, 256, attrs=base_attempt)
            except CkrAssertionError as exc:
                _qc10a_setup_failed(
                    exc,
                    operation="C_GenerateKey",
                    purpose=f"{label} base setup",
                    rs=rs,
                    sh=rs.sh,
                    before=setup_before,
                    attempt=base_attempt,
                )
            setup_after = _qc10a_after_inventory_or_judge(
                rs,
                rs.sh,
                rv=int(CKR_OK),
                handle=candidate,
                label=f"{label} base setup",
                operation="C_GenerateKey",
                leg="positive",
            )
            _qc10a_judge_setup_success(
                rs,
                rs.sh,
                candidate,
                before=setup_before,
                after=setup_after,
                attempt=base_attempt,
                label=f"{label} base setup",
                operation="C_GenerateKey",
            )
            base = candidate
            identity = (int(CKO_SECRET_KEY), int(CKK_GENERIC_SECRET))
            hkdf = mech_hkdf(CKM_HKDF_DERIVE, hash_mech=CKM_SHA256)
            control_label = _qc10a_unique_label("derive-pub")
            negative_label = _qc10a_unique_label("derive-priv")
            with _qc10a_so_login_scope(rs, user_pin, so_pin, explicit_so=explicit, label=label) as (
                so_sh,
                scope,
            ):
                _qc10a_prove_source_visible(rs, so_sh, base, source_label, label=label)
                control: dict[Any, Any] = {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_TOKEN: False,
                    CKA_PRIVATE: False,
                    CKA_VALUE_LEN: 32,
                    CKA_LABEL: control_label,
                }
                _qc10a_run_positive_leg(
                    rs,
                    so_sh,
                    scope,
                    operation="C_DeriveKey",
                    attempt=control,
                    identities=(identity,),
                    attempt_fn=lambda: _qc10a_derive_raw(rs.raw, so_sh, base, hkdf, control),
                    expected_private=False,
                    label=f"{label} control",
                )
                negative: dict[Any, Any] = {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_TOKEN: False,
                    CKA_PRIVATE: True,
                    CKA_VALUE_LEN: 32,
                    CKA_LABEL: negative_label,
                }
                _qc10a_run_negative_leg(
                    rs,
                    so_sh,
                    scope,
                    operation="C_DeriveKey",
                    attempt=negative,
                    identities=(identity,),
                    attempt_fn=lambda: _qc10a_derive_raw(rs.raw, so_sh, base, hkdf, negative),
                    label=label,
                )
        finally:
            if base:
                destroy_quietly(rs.raw, rs.sh, base)

    @pytest.mark.destructive
    def test_so_cannot_unwrap_private_key(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_UnwrapKey with CKA_PRIVATE=True on an SO session must refuse.

        The KEK is a PUBLIC session AES key (wrap leg proves it operational),
        and its visibility to the SO session is proven first.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not advertised")
        user_pin, so_pin, explicit = _qc10a_so_pins(p11_config, rs)
        label = "SO C_UnwrapKey CKA_PRIVATE=True"
        source_label = _qc10a_unique_label("unwrap-kek")
        kek = 0
        target = 0
        wrapped = b""
        try:
            setup_before = _qc10a_inventory_or_classify(
                rs, rs.sh, phase="setup-before", label=f"{label} KEK setup"
            )
            kek_attempt: dict[Any, Any] = {
                CKA_TOKEN: False,
                CKA_PRIVATE: False,
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_LABEL: source_label,
                CKA_EXTRACTABLE: True,
            }
            try:
                candidate = gen_aes_key(rs.raw, rs.sh, 256, attrs=kek_attempt)
            except CkrAssertionError as exc:
                _qc10a_setup_failed(
                    exc,
                    operation="C_GenerateKey",
                    purpose=f"{label} KEK setup",
                    rs=rs,
                    sh=rs.sh,
                    before=setup_before,
                    attempt=kek_attempt,
                )
            setup_after = _qc10a_after_inventory_or_judge(
                rs,
                rs.sh,
                rv=int(CKR_OK),
                handle=candidate,
                label=f"{label} KEK setup",
                operation="C_GenerateKey",
                leg="positive",
            )
            _qc10a_judge_setup_success(
                rs,
                rs.sh,
                candidate,
                before=setup_before,
                after=setup_after,
                attempt=kek_attempt,
                label=f"{label} KEK setup",
                operation="C_GenerateKey",
            )
            kek = candidate
            setup_before = _qc10a_inventory_or_classify(
                rs, rs.sh, phase="setup-before", label=f"{label} target setup"
            )
            target_attempt: dict[Any, Any] = {
                CKA_TOKEN: False,
                CKA_PRIVATE: False,
                CKA_EXTRACTABLE: True,
                CKA_LABEL: _qc10a_unique_label("unwrap-tgt"),
            }
            try:
                candidate = gen_aes_key(rs.raw, rs.sh, 128, attrs=target_attempt)
            except CkrAssertionError as exc:
                _qc10a_setup_failed(
                    exc,
                    operation="C_GenerateKey",
                    purpose=f"{label} target setup",
                    rs=rs,
                    sh=rs.sh,
                    before=setup_before,
                    attempt=target_attempt,
                )
            setup_after = _qc10a_after_inventory_or_judge(
                rs,
                rs.sh,
                rv=int(CKR_OK),
                handle=candidate,
                label=f"{label} target setup",
                operation="C_GenerateKey",
                leg="positive",
            )
            _qc10a_judge_setup_success(
                rs,
                rs.sh,
                candidate,
                before=setup_before,
                after=setup_after,
                attempt=target_attempt,
                label=f"{label} target setup",
                operation="C_GenerateKey",
            )
            target = candidate
            setup_before = _qc10a_inventory_or_classify(
                rs, rs.sh, phase="setup-before", label=f"{label} wrap setup"
            )
            try:
                wrapped = wrap_key(rs.raw, rs.sh, kek, target, CKM_AES_KEY_WRAP)
            except CkrAssertionError as exc:
                _qc10a_setup_failed(
                    exc,
                    operation="C_WrapKey",
                    purpose=f"{label} wrap setup",
                    rs=rs,
                    sh=rs.sh,
                    before=setup_before,
                    attempt={},
                )
            setup_after = _qc10a_after_inventory_or_judge(
                rs,
                rs.sh,
                rv=int(CKR_OK),
                handle=0,
                label=f"{label} wrap setup",
                operation="C_WrapKey",
                leg="positive",
            )
            _qc10a_judge_wrap_setup_success(
                before=setup_before,
                after=setup_after,
                label=f"{label} wrap setup",
            )
            identity = (int(CKO_SECRET_KEY), int(CKK_AES))
            control_label = _qc10a_unique_label("unwrap-pub")
            negative_label = _qc10a_unique_label("unwrap-priv")
            with _qc10a_so_login_scope(rs, user_pin, so_pin, explicit_so=explicit, label=label) as (
                so_sh,
                scope,
            ):
                _qc10a_prove_source_visible(rs, so_sh, kek, source_label, label=label)
                control: dict[Any, Any] = {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_TOKEN: False,
                    CKA_PRIVATE: False,
                    CKA_VALUE_LEN: 16,
                    CKA_LABEL: control_label,
                }
                _qc10a_run_positive_leg(
                    rs,
                    so_sh,
                    scope,
                    operation="C_UnwrapKey",
                    attempt=control,
                    identities=(identity,),
                    attempt_fn=lambda: _qc10a_unwrap_raw(rs.raw, so_sh, kek, wrapped, control),
                    expected_private=False,
                    label=f"{label} control",
                )
                negative: dict[Any, Any] = {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_TOKEN: False,
                    CKA_PRIVATE: True,
                    CKA_VALUE_LEN: 16,
                    CKA_LABEL: negative_label,
                }
                _qc10a_run_negative_leg(
                    rs,
                    so_sh,
                    scope,
                    operation="C_UnwrapKey",
                    attempt=negative,
                    identities=(identity,),
                    attempt_fn=lambda: _qc10a_unwrap_raw(rs.raw, so_sh, kek, wrapped, negative),
                    label=label,
                )
        finally:
            if target:
                destroy_quietly(rs.raw, rs.sh, target)
            if kek:
                destroy_quietly(rs.raw, rs.sh, kek)


class TestUserPrivateCreationControls:
    """USER sessions can create private objects: the SO-matrix role contrast.

    No login transitions here (USER is the entry state); each node logs in
    explicitly, creates one private object with the same shape the SO legs
    refuse, verifies the readback, and destroys it. Clean refusal xfails,
    never passes.
    """

    def test_user_can_create_private_object(self, p11_raw_session: Any, p11_config: Any) -> None:
        """USER C_CreateObject with CKA_PRIVATE=True succeeds."""
        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
        pin = get_pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        label = "USER C_CreateObject CKA_PRIVATE=True"
        _qc10a_login_user_verified(rs, rs.sh, pin, label=label)
        attempt: dict[Any, Any] = {
            CKA_CLASS: CKO_DATA,
            CKA_LABEL: _qc10a_unique_label("ucreate-priv"),
            CKA_VALUE: b"qc10a-user-private-create",
            CKA_TOKEN: False,
            CKA_PRIVATE: True,
        }
        _qc10a_run_positive_leg(
            rs,
            rs.sh,
            None,
            operation="C_CreateObject",
            attempt=attempt,
            identities=(),
            attempt_fn=lambda: _qc10a_create_raw(rs.raw, rs.sh, attempt),
            expected_private=True,
            label=label,
        )

    def test_user_can_copy_to_private_object(self, p11_raw_session: Any, p11_config: Any) -> None:
        """USER C_CopyObject to CKA_PRIVATE=True succeeds (public source)."""
        rs = p11_raw_session
        pin = get_pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        label = "USER C_CopyObject CKA_PRIVATE=True"
        _qc10a_login_user_verified(rs, rs.sh, pin, label=label)
        source = 0
        try:
            setup_before = _qc10a_inventory_or_classify(
                rs, rs.sh, phase="setup-before", label=f"{label} source setup"
            )
            source_attempt: dict[Any, Any] = {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: _qc10a_unique_label("ucopy-src"),
                CKA_VALUE: b"qc10a-user-copy-source",
                CKA_TOKEN: False,
                CKA_PRIVATE: False,
            }
            try:
                candidate = create_object(rs.raw, rs.sh, source_attempt)
            except CkrAssertionError as exc:
                _qc10a_setup_failed(
                    exc,
                    operation="C_CreateObject",
                    purpose=f"{label} source setup",
                    rs=rs,
                    sh=rs.sh,
                    before=setup_before,
                    attempt=source_attempt,
                )
            setup_after = _qc10a_after_inventory_or_judge(
                rs,
                rs.sh,
                rv=int(CKR_OK),
                handle=candidate,
                label=f"{label} source setup",
                operation="C_CreateObject",
                leg="positive",
            )
            _qc10a_judge_setup_success(
                rs,
                rs.sh,
                candidate,
                before=setup_before,
                after=setup_after,
                attempt=source_attempt,
                label=f"{label} source setup",
                operation="C_CreateObject",
            )
            source = candidate
            attempt: dict[Any, Any] = {
                CKA_PRIVATE: True,
                CKA_LABEL: _qc10a_unique_label("ucopy-priv"),
            }
            _qc10a_run_positive_leg(
                rs,
                rs.sh,
                None,
                operation="C_CopyObject",
                attempt=attempt,
                identities=(),
                attempt_fn=lambda: _qc10a_copy_raw(rs.raw, rs.sh, source, attempt),
                expected_private=True,
                label=label,
            )
        finally:
            if source:
                destroy_quietly(rs.raw, rs.sh, source)

    def test_user_can_generate_private_key(self, p11_raw_session: Any, p11_config: Any) -> None:
        """USER C_GenerateKey with CKA_PRIVATE=True succeeds."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not advertised")
        pin = get_pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        label = "USER C_GenerateKey CKA_PRIVATE=True"
        _qc10a_login_user_verified(rs, rs.sh, pin, label=label)
        attempt: dict[Any, Any] = {
            CKA_ENCRYPT: True,
            CKA_DECRYPT: True,
            CKA_KEY_TYPE: CKK_AES,
            CKA_VALUE_LEN: 16,
            CKA_TOKEN: False,
            CKA_PRIVATE: True,
            CKA_LABEL: _qc10a_unique_label("ugen-priv"),
        }
        _qc10a_run_positive_leg(
            rs,
            rs.sh,
            None,
            operation="C_GenerateKey",
            attempt=attempt,
            identities=((int(CKO_SECRET_KEY), int(CKK_AES)),),
            attempt_fn=lambda: _qc10a_generate_raw(rs.raw, rs.sh, attempt),
            expected_private=True,
            label=label,
        )

    def test_user_can_derive_private_key(self, p11_raw_session: Any, p11_config: Any) -> None:
        """USER C_DeriveKey (HKDF) with CKA_PRIVATE=True succeeds."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not advertised")
        pin = get_pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        label = "USER C_DeriveKey(HKDF) CKA_PRIVATE=True"
        _qc10a_login_user_verified(rs, rs.sh, pin, label=label)
        base = 0
        try:
            setup_before = _qc10a_inventory_or_classify(
                rs, rs.sh, phase="setup-before", label=f"{label} base setup"
            )
            base_attempt: dict[Any, Any] = {
                CKA_TOKEN: False,
                CKA_PRIVATE: False,
                CKA_DERIVE: True,
                CKA_LABEL: _qc10a_unique_label("uderive-base"),
                CKA_EXTRACTABLE: True,
            }
            try:
                candidate = gen_aes_key(rs.raw, rs.sh, 256, attrs=base_attempt)
            except CkrAssertionError as exc:
                _qc10a_setup_failed(
                    exc,
                    operation="C_GenerateKey",
                    purpose=f"{label} base setup",
                    rs=rs,
                    sh=rs.sh,
                    before=setup_before,
                    attempt=base_attempt,
                )
            setup_after = _qc10a_after_inventory_or_judge(
                rs,
                rs.sh,
                rv=int(CKR_OK),
                handle=candidate,
                label=f"{label} base setup",
                operation="C_GenerateKey",
                leg="positive",
            )
            _qc10a_judge_setup_success(
                rs,
                rs.sh,
                candidate,
                before=setup_before,
                after=setup_after,
                attempt=base_attempt,
                label=f"{label} base setup",
                operation="C_GenerateKey",
            )
            base = candidate
            hkdf = mech_hkdf(CKM_HKDF_DERIVE, hash_mech=CKM_SHA256)
            attempt: dict[Any, Any] = {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_TOKEN: False,
                CKA_PRIVATE: True,
                CKA_VALUE_LEN: 32,
                CKA_LABEL: _qc10a_unique_label("uderive-priv"),
            }
            _qc10a_run_positive_leg(
                rs,
                rs.sh,
                None,
                operation="C_DeriveKey",
                attempt=attempt,
                identities=((int(CKO_SECRET_KEY), int(CKK_GENERIC_SECRET)),),
                attempt_fn=lambda: _qc10a_derive_raw(rs.raw, rs.sh, base, hkdf, attempt),
                expected_private=True,
                label=label,
            )
        finally:
            if base:
                destroy_quietly(rs.raw, rs.sh, base)

    def test_user_can_unwrap_private_key(self, p11_raw_session: Any, p11_config: Any) -> None:
        """USER C_UnwrapKey with CKA_PRIVATE=True succeeds."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not advertised")
        pin = get_pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        label = "USER C_UnwrapKey CKA_PRIVATE=True"
        _qc10a_login_user_verified(rs, rs.sh, pin, label=label)
        kek = 0
        target = 0
        try:
            setup_before = _qc10a_inventory_or_classify(
                rs, rs.sh, phase="setup-before", label=f"{label} KEK setup"
            )
            kek_attempt: dict[Any, Any] = {
                CKA_TOKEN: False,
                CKA_PRIVATE: False,
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_LABEL: _qc10a_unique_label("uunwrap-kek"),
                CKA_EXTRACTABLE: True,
            }
            try:
                candidate = gen_aes_key(rs.raw, rs.sh, 256, attrs=kek_attempt)
            except CkrAssertionError as exc:
                _qc10a_setup_failed(
                    exc,
                    operation="C_GenerateKey",
                    purpose=f"{label} KEK setup",
                    rs=rs,
                    sh=rs.sh,
                    before=setup_before,
                    attempt=kek_attempt,
                )
            setup_after = _qc10a_after_inventory_or_judge(
                rs,
                rs.sh,
                rv=int(CKR_OK),
                handle=candidate,
                label=f"{label} KEK setup",
                operation="C_GenerateKey",
                leg="positive",
            )
            _qc10a_judge_setup_success(
                rs,
                rs.sh,
                candidate,
                before=setup_before,
                after=setup_after,
                attempt=kek_attempt,
                label=f"{label} KEK setup",
                operation="C_GenerateKey",
            )
            kek = candidate
            setup_before = _qc10a_inventory_or_classify(
                rs, rs.sh, phase="setup-before", label=f"{label} target setup"
            )
            target_attempt: dict[Any, Any] = {
                CKA_TOKEN: False,
                CKA_PRIVATE: False,
                CKA_EXTRACTABLE: True,
                CKA_LABEL: _qc10a_unique_label("uunwrap-tgt"),
            }
            try:
                candidate = gen_aes_key(rs.raw, rs.sh, 128, attrs=target_attempt)
            except CkrAssertionError as exc:
                _qc10a_setup_failed(
                    exc,
                    operation="C_GenerateKey",
                    purpose=f"{label} target setup",
                    rs=rs,
                    sh=rs.sh,
                    before=setup_before,
                    attempt=target_attempt,
                )
            setup_after = _qc10a_after_inventory_or_judge(
                rs,
                rs.sh,
                rv=int(CKR_OK),
                handle=candidate,
                label=f"{label} target setup",
                operation="C_GenerateKey",
                leg="positive",
            )
            _qc10a_judge_setup_success(
                rs,
                rs.sh,
                candidate,
                before=setup_before,
                after=setup_after,
                attempt=target_attempt,
                label=f"{label} target setup",
                operation="C_GenerateKey",
            )
            target = candidate
            setup_before = _qc10a_inventory_or_classify(
                rs, rs.sh, phase="setup-before", label=f"{label} wrap setup"
            )
            try:
                wrapped = wrap_key(rs.raw, rs.sh, kek, target, CKM_AES_KEY_WRAP)
            except CkrAssertionError as exc:
                _qc10a_setup_failed(
                    exc,
                    operation="C_WrapKey",
                    purpose=f"{label} wrap setup",
                    rs=rs,
                    sh=rs.sh,
                    before=setup_before,
                    attempt={},
                )
            setup_after = _qc10a_after_inventory_or_judge(
                rs,
                rs.sh,
                rv=int(CKR_OK),
                handle=0,
                label=f"{label} wrap setup",
                operation="C_WrapKey",
                leg="positive",
            )
            _qc10a_judge_wrap_setup_success(
                before=setup_before,
                after=setup_after,
                label=f"{label} wrap setup",
            )
            attempt: dict[Any, Any] = {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_AES,
                CKA_TOKEN: False,
                CKA_PRIVATE: True,
                CKA_VALUE_LEN: 16,
                CKA_LABEL: _qc10a_unique_label("uunwrap-priv"),
            }
            _qc10a_run_positive_leg(
                rs,
                rs.sh,
                None,
                operation="C_UnwrapKey",
                attempt=attempt,
                identities=((int(CKO_SECRET_KEY), int(CKK_AES)),),
                attempt_fn=lambda: _qc10a_unwrap_raw(rs.raw, rs.sh, kek, wrapped, attempt),
                expected_private=True,
                label=label,
            )
        finally:
            if target:
                destroy_quietly(rs.raw, rs.sh, target)
            if kek:
                destroy_quietly(rs.raw, rs.sh, kek)
