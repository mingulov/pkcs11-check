"""Public-session private-object creation rejection probes (Wave 2).

PKCS#11 requires an authenticated (CKU_USER) session to create private
(``CKA_PRIVATE=True``) objects. The ``C_CreateObject`` and ``C_GenerateKey``
paths are covered by ``test_access_levels.py``; this file covers the remaining
creation paths -- ``C_UnwrapKey``, ``C_DeriveKey`` (ECDH + HKDF), and
``C_CopyObject`` -- to confirm the rule holds uniformly.

Each probe clears the token-wide login (login is per-token, not per-session),
then attempts the creation on a public session. A module that creates a usable
private object without authentication has claimed the protection then violated
it -- a policy self-contradiction, not a soft note.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import close_session_quietly
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.pack_mechanisms import mech_ecdh, mech_hkdf
from pkcs11_check.raw.recipes import (
    copy_object,
    create_object,
    derive_key,
    destroy_quietly,
    find_objects,
    gen_aes_key,
    gen_ec_keypair,
    read_attributes,
    unwrap_key,
    wrap_key,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_UTF8CHAR,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EC_POINT,
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
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_KEY_WRAP,
    CKM_ECDH1_DERIVE,
    CKM_HKDF_DERIVE,
    CKM_SHA256,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKR_OK,
    CKR_SESSION_COUNT,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import (
    classify_policy_enforcement,
    get_pin_bytes,
    is_known_error,
    reject_or_classify,
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

        # Setup on the logged-in fixture session: public KEK + extractable target.
        kek = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_TOKEN: True,
                CKA_PRIVATE: False,
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_LABEL: label,
                CKA_EXTRACTABLE: True,
            },
        )
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={
                CKA_TOKEN: True,
                CKA_PRIVATE: False,
                CKA_EXTRACTABLE: True,
                CKA_LABEL: label,
            },
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
            priv = read_attributes(rs.raw, public_sh, created, [CKA_PRIVATE]).get(CKA_PRIVATE)
            classify_policy_enforcement(
                claimed=priv is True,
                violated=True,
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
            pytest.skip(f"Module cannot stage a non-private EC keypair for ECDH setup: {exc}")
        peer_point = read_attributes(rs.raw, rs.sh, pub, [CKA_EC_POINT]).get(CKA_EC_POINT)
        if peer_point is None:
            pytest.skip("Module did not return CKA_EC_POINT for the staged EC public key")

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
                        CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=bytes(peer_point)
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
            priv_attr = read_attributes(rs.raw, public_sh, created, [CKA_PRIVATE]).get(CKA_PRIVATE)
            classify_policy_enforcement(
                claimed=priv_attr is True,
                violated=True,
                label="public (unauthenticated) session ECDH-derived a CKA_PRIVATE=True "
                "session object (PKCS#11 requires CKR_USER_NOT_LOGGED_IN)",
            )
        finally:
            _login_user_raw(rs.raw, public_sh, pin_bytes)
            if created is not None:
                destroy_quietly(rs.raw, public_sh, created)
            _cleanup_label(rs, public_sh, label)
            close_session_quietly(rs.raw, public_sh)

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

        # Setup on the logged-in fixture session: derive-capable public secret key.
        gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_TOKEN: True,
                CKA_PRIVATE: False,
                CKA_DERIVE: True,
                CKA_LABEL: label,
                CKA_EXTRACTABLE: True,
            },
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
            priv_attr = read_attributes(rs.raw, public_sh, created, [CKA_PRIVATE]).get(CKA_PRIVATE)
            classify_policy_enforcement(
                claimed=priv_attr is True,
                violated=True,
                label="public (unauthenticated) session HKDF-derived a CKA_PRIVATE=True "
                "session object (PKCS#11 requires CKR_USER_NOT_LOGGED_IN)",
            )
        finally:
            _login_user_raw(rs.raw, public_sh, pin_bytes)
            if created is not None:
                destroy_quietly(rs.raw, public_sh, created)
            _cleanup_label(rs, public_sh, label)
            close_session_quietly(rs.raw, public_sh)

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
            priv_attr = read_attributes(rs.raw, public_sh, created, [CKA_PRIVATE]).get(CKA_PRIVATE)
            classify_policy_enforcement(
                claimed=priv_attr is True,
                violated=True,
                label="public (unauthenticated) session C_CopyObject'd to a "
                "CKA_PRIVATE=True copy (PKCS#11 requires CKR_USER_NOT_LOGGED_IN)",
            )
        finally:
            _login_user_raw(rs.raw, public_sh, pin_bytes)
            if created is not None:
                destroy_quietly(rs.raw, public_sh, created)
            _cleanup_label(rs, public_sh, label)
            close_session_quietly(rs.raw, public_sh)
