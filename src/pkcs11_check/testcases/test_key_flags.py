"""Key attribute flag tests.

Verifies CKA_NEVER_EXTRACTABLE, CKA_LOCAL, CKA_ALWAYS_SENSITIVE,
and other security-critical attribute flags that catch real bugs
in module implementations.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    gen_rsa_keypair,
    generate_random,
    import_secret_key,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_ALWAYS_SENSITIVE,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_LOCAL,
    CKA_NEVER_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKK_AES,
    CKM_AES_CBC_PAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import AES_KEYGEN_RUNTIME_REJECT_RVS, xfail_if_known_ckr

pytestmark = pytest.mark.security


def _gen_aes_key_or_xfail(
    rs: Any,
    bits: int = 256,
    *,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Generate an AES setup key, xfail-ing explicit advertised-runtime rejects."""
    has_mechanism = getattr(rs, "has_mechanism", None)
    if callable(has_mechanism) and not has_mechanism("AES_KEY_GEN"):
        pytest.skip("AES_KEY_GEN not supported by module")
    try:
        return gen_aes_key(rs.raw, rs.sh, bits, attrs=attrs)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            "AES_KEY_GEN advertised but key generation is not operational",
        )
    raise


def _read_bool_attr_safe(
    rs: Any,
    handle: int,
    attr: int,
) -> bool | None:
    """Read a bool attribute, returning None if CKR_ATTRIBUTE_TYPE_INVALID."""
    import ctypes

    from pkcs11_check.raw.types_std import CK_ATTRIBUTE, CK_BBOOL, CK_VOID_PTR

    val = CK_BBOOL(0)
    tmpl = (CK_ATTRIBUTE * 1)()
    tmpl[0].type = attr
    tmpl[0].pValue = ctypes.cast(ctypes.pointer(val), CK_VOID_PTR)
    tmpl[0].ulValueLen = ctypes.sizeof(val)
    rv = rs.raw.C_GetAttributeValue(rs.sh, handle, tmpl, 1)
    if rv == CKR_ATTRIBUTE_TYPE_INVALID:
        return None
    if rv != CKR_OK:
        return None
    return val.value != 0


class TestNeverExtractable:
    """Verify CKA_NEVER_EXTRACTABLE flag semantics."""

    def test_generated_non_extractable_is_never_extractable(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Key generated with EXTRACTABLE=False has NEVER_EXTRACTABLE=True."""
        rs = p11_raw_session
        key = _gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_EXTRACTABLE: False},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_NEVER_EXTRACTABLE])
            assert attrs[CKA_NEVER_EXTRACTABLE] is True
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_generated_extractable_is_not_never_extractable(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Key generated with EXTRACTABLE=True has NEVER_EXTRACTABLE=False."""
        rs = p11_raw_session
        key = _gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_NEVER_EXTRACTABLE])
            assert attrs[CKA_NEVER_EXTRACTABLE] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_extractable_and_never_extractable_consistent(
        self,
        p11_raw_session: Any,
    ) -> None:
        """EXTRACTABLE=True implies NEVER_EXTRACTABLE=False (and vice versa for default)."""
        rs = p11_raw_session
        # Default key: non-extractable
        key_default = _gen_aes_key_or_xfail(rs, 256)
        try:
            attrs_d = read_attributes(rs.raw, rs.sh, key_default, [CKA_EXTRACTABLE])
            if attrs_d[CKA_EXTRACTABLE] is not False:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "Module generated AES key with CKA_EXTRACTABLE=True by default "
                    "(PKCS#11 spec Table 18 requires CKA_EXTRACTABLE default to be False "
                    "for keys generated without an explicit CKA_EXTRACTABLE attribute).",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec Table 18",
                )
                pytest.xfail(
                    "Module generates AES keys with CKA_EXTRACTABLE=True by default "
                    "(spec Table 18 requires CKA_EXTRACTABLE to default to False)"
                )
            assert attrs_d[CKA_EXTRACTABLE] is False
            never_ext_default = _read_bool_attr_safe(rs, key_default, CKA_NEVER_EXTRACTABLE)
            if never_ext_default is None:
                pytest.xfail(
                    "Module does not implement CKA_NEVER_EXTRACTABLE tracking "
                    "(PKCS#11 spec Table 18 requires this attribute)"
                )
            if never_ext_default is not True:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "CKA_NEVER_EXTRACTABLE=False on non-extractable generated key "
                    "(spec requires True when key was created with EXTRACTABLE=False)",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec Table 18",
                )
                pytest.xfail(
                    "Module does not set CKA_NEVER_EXTRACTABLE=True on non-extractable "
                    "generated keys (PKCS#11 spec Table 18 invariant violation)"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_default)

        # Extractable key
        key_ext = _gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            attrs_e = read_attributes(rs.raw, rs.sh, key_ext, [CKA_EXTRACTABLE])
            assert attrs_e[CKA_EXTRACTABLE] is True
            never_ext = _read_bool_attr_safe(rs, key_ext, CKA_NEVER_EXTRACTABLE)
            if never_ext is None:
                pytest.xfail(
                    "Module does not implement CKA_NEVER_EXTRACTABLE tracking "
                    "(PKCS#11 spec Table 18 requires this attribute)"
                )
            if never_ext is not False:
                pytest.xfail(
                    "Module sets CKA_NEVER_EXTRACTABLE=True on extractable keys -- "
                    "violates PKCS#11 spec Table 18 invariant"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_ext)


class TestLocalFlag:
    """Verify CKA_LOCAL flag distinguishes generated vs imported keys."""

    def test_generated_key_is_local(self, p11_raw_session: Any) -> None:
        """Keys generated on the token have LOCAL=True.

        PKCS#11 spec Table 18: CKA_LOCAL is True for keys generated on the token
        (C_GenerateKey / C_GenerateKeyPair), False for keys imported via C_CreateObject.

        NSS deviation: NSS does not set CKA_LOCAL on generated keys.
        Tracked in docs/module-issues.md under NSS.
        """
        rs = p11_raw_session
        key = _gen_aes_key_or_xfail(rs, 256)
        try:
            local_val = _read_bool_attr_safe(rs, key, CKA_LOCAL)
            if local_val is None:
                pytest.xfail(
                    "Module does not implement CKA_LOCAL attribute "
                    "(PKCS#11 spec Table 18 requires it for generated keys)"
                )
            if local_val is not True:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "CKA_LOCAL=False on generated key (spec requires True for C_GenerateKey)",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec Table 18",
                )
                pytest.xfail(
                    "Module does not set CKA_LOCAL=True on generated keys "
                    "(PKCS#11 spec Table 18 requires CKA_LOCAL=True for C_GenerateKey)"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_imported_key_is_not_local(self, p11_raw_session: Any) -> None:
        """Imported keys have LOCAL=False."""
        rs = p11_raw_session
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            b"\x00" * 32,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
        )
        try:
            local_val = _read_bool_attr_safe(rs, key, CKA_LOCAL)
            if local_val is None:
                pytest.xfail(
                    "Module does not implement CKA_LOCAL attribute "
                    "(PKCS#11 spec Table 18 requires it for imported keys)"
                )
            if local_val is not False:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "CKA_LOCAL=True on imported key (spec requires False for C_CreateObject)",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec Table 18",
                )
                pytest.xfail(
                    "Module sets CKA_LOCAL=True on imported keys "
                    "(PKCS#11 spec Table 18 requires CKA_LOCAL=False for C_CreateObject)"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_generated_rsa_keypair_is_local(self, p11_raw_session: Any) -> None:
        """Generated RSA keypair has LOCAL=True on both keys.

        PKCS#11 spec Table 18: CKA_LOCAL is True for keys generated via
        C_GenerateKeyPair.

        NSS deviation: NSS does not set CKA_LOCAL=True on the generated public key.
        Tracked in docs/module-issues.md under NSS.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA key generation not supported")

        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            pub_local = _read_bool_attr_safe(rs, pub, CKA_LOCAL)
            priv_local = _read_bool_attr_safe(rs, priv, CKA_LOCAL)

            if pub_local is None or priv_local is None:
                pytest.xfail(
                    "Module does not implement CKA_LOCAL attribute "
                    "(PKCS#11 spec requires it for generated keys)"
                )
                return

            if pub_local is not True or priv_local is not True:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"CKA_LOCAL not True on generated RSA keypair: "
                    f"pub={pub_local}, priv={priv_local} "
                    f"(spec requires LOCAL=True for C_GenerateKeyPair)",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec Table 18",
                )
                pytest.xfail(
                    f"Module does not set CKA_LOCAL=True on generated RSA keypair: "
                    f"pub={pub_local}, priv={priv_local} "
                    f"(PKCS#11 spec Table 18 requires CKA_LOCAL=True for C_GenerateKeyPair)"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestAlwaysSensitive:
    """Verify CKA_ALWAYS_SENSITIVE flag semantics."""

    def test_sensitive_key_always_sensitive(self, p11_raw_session: Any) -> None:
        """Key generated sensitive has ALWAYS_SENSITIVE=True."""
        rs = p11_raw_session
        key = _gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_SENSITIVE: True},
        )
        try:
            attrs = read_attributes(
                rs.raw,
                rs.sh,
                key,
                [CKA_SENSITIVE, CKA_ALWAYS_SENSITIVE],
            )
            assert attrs[CKA_SENSITIVE] is True
            assert attrs[CKA_ALWAYS_SENSITIVE] is True
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_non_sensitive_key_not_always_sensitive(self, p11_raw_session: Any) -> None:
        """Key generated non-sensitive has ALWAYS_SENSITIVE=False."""
        rs = p11_raw_session
        key = _gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_SENSITIVE: False},
        )
        try:
            attrs = read_attributes(
                rs.raw,
                rs.sh,
                key,
                [CKA_SENSITIVE, CKA_ALWAYS_SENSITIVE],
            )
            assert attrs[CKA_SENSITIVE] is False
            assert attrs[CKA_ALWAYS_SENSITIVE] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestAutopadding:
    """Verify AES-CBC-PAD handles automatic PKCS#7 padding correctly."""

    @pytest.mark.parametrize("plaintext_len", [1, 7, 15, 16, 17, 31, 32, 100])
    def test_aes_cbc_pad_variable_length(
        self,
        p11_raw_session: Any,
        plaintext_len: int,
    ) -> None:
        """AES-CBC-PAD roundtrip works for non-block-aligned plaintext lengths."""
        rs = p11_raw_session
        key = _gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        iv = generate_random(rs.raw, rs.sh, 16)
        plaintext = bytes(range(256))[:plaintext_len]
        try:
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            # Ciphertext should be padded to next block boundary
            assert len(ct) % 16 == 0
            assert len(ct) >= plaintext_len

            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC_PAD,
                ct,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
