"""Key usage policy enforcement tests.

Verifies that PKCS#11 modules enforce CKA_ENCRYPT, CKA_DECRYPT,
CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP, CKA_ENCAPSULATE, and
CKA_DECAPSULATE capability flags.

These tests verify at the raw API level that C_EncryptInit / C_SignInit /
C_EncapsulateKey / C_DecapsulateKey etc. fail with appropriate CKR when the
key lacks the corresponding capability flag.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import attr_ulong, mech_simple, template, template_ptr_count
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    gen_keypair,
    read_attributes,
    to_ubyte_buf,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECAPSULATE,
    CKA_DECRYPT,
    CKA_ENCAPSULATE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_PARAMETER_SET,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKK_AES,
    CKM_AES_ECB,
    CKM_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKO_SECRET_KEY,
    CKP_ML_KEM_768,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    classify_policy_enforcement,
    gen_rsa_keypair_or_xfail,
    require_operational_aes_keygen,
)

# Key-usage-policy guards classify 3-way via classify_negative_rv: running the
# forbidden function (CKR_OK) -> fail, the spec code
# CKR_KEY_FUNCTION_NOT_PERMITTED -> pass, any other clean reject (e.g.
# CKR_FUNCTION_NOT_SUPPORTED, CKR_ARGUMENTS_BAD, CKR_KEY_TYPE_INCONSISTENT) ->
# xfail.

pytestmark = pytest.mark.security


class TestAESKeyUsagePolicy:
    """Test AES key capability enforcement."""

    def test_encrypt_only_key_cannot_decrypt(self, p11_raw_session: Any) -> None:
        """AES key with ENCRYPT=True, DECRYPT=False cannot be used for decrypt."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: False,
                CKA_SIGN: False,
                CKA_VERIFY: False,
            },
        )
        try:
            # Encrypt should succeed
            data = b"\x00" * 16
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
            assert len(ct) == 16

            # DecryptInit should fail with KEY_FUNCTION_NOT_PERMITTED
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
            classify_negative_rv(
                rv,
                (CKR_KEY_FUNCTION_NOT_PERMITTED,),
                label="C_DecryptInit on an AES key created CKA_DECRYPT=False",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_decrypt_only_key_cannot_encrypt(self, p11_raw_session: Any) -> None:
        """AES key with DECRYPT=True, ENCRYPT=False cannot be used for encrypt."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: False,
                CKA_DECRYPT: True,
                CKA_SIGN: False,
                CKA_VERIFY: False,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_DECRYPT])
            assert attrs[CKA_DECRYPT] is True

            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            classify_negative_rv(
                rv,
                (CKR_KEY_FUNCTION_NOT_PERMITTED,),
                label="C_EncryptInit on an AES key created CKA_ENCRYPT=False",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sign_only_key_cannot_encrypt(self, p11_raw_session: Any) -> None:
        """Key with SIGN=True but ENCRYPT=False cannot encrypt."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_ENCRYPT: False,
                CKA_DECRYPT: False,
            },
        )
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            classify_negative_rv(
                rv,
                (CKR_KEY_FUNCTION_NOT_PERMITTED,),
                label="C_EncryptInit on a SIGN-only AES key created CKA_ENCRYPT=False",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_full_capabilities_key(self, p11_raw_session: Any) -> None:
        """Key with all capabilities can encrypt."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_WRAP: True,
                CKA_UNWRAP: True,
            },
        )
        try:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, b"\x00" * 16)
            assert len(ct) == 16
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestRSAKeyUsagePolicy:
    """Test RSA key capability enforcement."""

    def test_sign_only_rsa_cannot_encrypt(self, p11_raw_session: Any) -> None:
        """RSA key pair generated for signing only cannot encrypt."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={
                CKA_ENCRYPT: False,
                CKA_VERIFY: True,
                CKA_WRAP: False,
            },
            private_attrs={
                CKA_DECRYPT: False,
                CKA_SIGN: True,
                CKA_UNWRAP: False,
            },
        )
        try:
            # Verify SIGN is True on private
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_SIGN])
            assert priv_attrs[CKA_SIGN] is True

            # Verify VERIFY is True on public
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_VERIFY])
            assert pub_attrs[CKA_VERIFY] is True

            # Encrypt should fail on public key
            from pkcs11_check.raw.types_std import CKM_RSA_PKCS

            mech = mech_simple(CKM_RSA_PKCS)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), pub)
            classify_negative_rv(
                rv,
                (CKR_KEY_FUNCTION_NOT_PERMITTED,),
                label="C_EncryptInit on an RSA public key created CKA_ENCRYPT=False",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_encrypt_only_rsa_cannot_sign(self, p11_raw_session: Any) -> None:
        """RSA key pair generated for encryption only cannot sign."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={
                CKA_ENCRYPT: True,
                CKA_VERIFY: False,
                CKA_WRAP: False,
            },
            private_attrs={
                CKA_DECRYPT: True,
                CKA_SIGN: False,
                CKA_UNWRAP: False,
            },
        )
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_ENCRYPT])
            assert pub_attrs[CKA_ENCRYPT] is True

            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_DECRYPT])
            assert priv_attrs[CKA_DECRYPT] is True

            # Sign should fail on private key
            from pkcs11_check.raw.types_std import CKM_SHA256_RSA_PKCS

            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), priv)
            classify_negative_rv(
                rv,
                (CKR_KEY_FUNCTION_NOT_PERMITTED,),
                label="C_SignInit on an RSA private key created CKA_SIGN=False",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestCapabilityReadback:
    """Verify capability flags are readable and consistent."""

    def test_aes_capabilities_match_template(self, p11_raw_session: Any) -> None:
        """Generated key's capability flags match what was requested."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: False,
                CKA_SIGN: False,
                CKA_VERIFY: False,
                CKA_WRAP: False,
                CKA_UNWRAP: False,
            },
        )
        try:
            attrs = read_attributes(
                rs.raw,
                rs.sh,
                key,
                [CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN],
            )
            assert attrs[CKA_ENCRYPT] is True
            assert attrs[CKA_DECRYPT] is False
            assert attrs[CKA_SIGN] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rsa_capabilities_match_template(self, p11_raw_session: Any) -> None:
        """RSA keypair flags match what was requested."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_VERIFY: False},
            private_attrs={CKA_DECRYPT: True, CKA_SIGN: False},
        )
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_ENCRYPT, CKA_VERIFY])
            assert pub_attrs[CKA_ENCRYPT] is True
            assert pub_attrs[CKA_VERIFY] is False

            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_DECRYPT, CKA_SIGN])
            assert priv_attrs[CKA_DECRYPT] is True
            assert priv_attrs[CKA_SIGN] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


# ---------------------------------------------------------------------------
# ML-KEM shared-secret size used in encapsulation templates (FIPS 203)
# ---------------------------------------------------------------------------
_ML_KEM_SHARED_SECRET_BYTES = 32


def _gen_ml_kem_keypair(
    rs: Any,
    *,
    encapsulate: bool = True,
    decapsulate: bool = True,
) -> tuple[int, int]:
    """Generate an ML-KEM-768 keypair with the given usage flags.

    Returns ``(pub_handle, priv_handle)``.  The caller owns both objects and
    must destroy them in a ``finally`` block.

    If the module does not support ``CKM_ML_KEM_KEY_PAIR_GEN`` the caller
    should guard with ``rs.has_mechanism("ML_KEM")`` before calling this.
    """
    pub, priv = gen_keypair(
        rs.raw,
        rs.sh,
        CKM_ML_KEM_KEY_PAIR_GEN,
        pub_base=[attr_ulong(CKA_PARAMETER_SET, CKP_ML_KEM_768)],
        priv_base=[],
        public_attrs={
            CKA_TOKEN: False,
            CKA_ENCAPSULATE: encapsulate,
        },
        private_attrs={
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: False,
            CKA_DECAPSULATE: decapsulate,
        },
        pub_skip={CKA_PARAMETER_SET},
    )
    return pub, priv


def _ml_kem_secret_template() -> dict[int, Any]:
    """Minimal encapsulation/decapsulation output template (GENERIC_SECRET, 32 B)."""
    return {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_AES,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_VALUE_LEN: _ML_KEM_SHARED_SECRET_BYTES,
    }


@pytest.mark.v32
@pytest.mark.needs_function("C_EncapsulateKey")
class TestKEMKeyUsagePolicy:
    """Verify CKA_ENCAPSULATE and CKA_DECAPSULATE flag enforcement.

    PKCS#11 v3.2 Sec.5.14.7 requires ``CKR_KEY_FUNCTION_NOT_PERMITTED`` when
    ``CKA_ENCAPSULATE`` is ``False`` on the public key supplied to
    ``C_EncapsulateKey``.  Sec.5.14.8 imposes the same requirement for
    ``CKA_DECAPSULATE`` on the private key supplied to ``C_DecapsulateKey``.

    Classification (3-way via ``classify_negative_rv`` / ``classify_policy_enforcement``):
    - ``CKR_OK`` from the forbidden operation → ``fail`` (policy bypass).
    - ``CKR_KEY_FUNCTION_NOT_PERMITTED`` → ``pass`` (spec-correct enforcement).
    - any other clean rejection → ``xfail`` (noted deviation).

    Setup failures (keypair creation refused, keygen not operational) route
    to ``pytest.skip`` so they never false-accuse a conformant module.
    """

    def test_encapsulate_flag_false_rejected(self, p11_raw_session: Any) -> None:
        """C_EncapsulateKey is rejected when public key has CKA_ENCAPSULATE=False.

        Spec: PKCS#11 v3.2 Sec.5.14.7 — ``CKR_KEY_FUNCTION_NOT_PERMITTED``
        when ``CKA_ENCAPSULATE`` is ``False``.

        This probe drives the *full* encapsulation, not just the size-query
        call, because some modules validate output-buffer availability before
        checking key permissions and return ``CKR_BUFFER_TOO_SMALL`` on a
        size-query-only call.  We use the reported ciphertext length when the
        module supplies it, and fall back to a buffer larger than the largest
        standard ML-KEM ciphertext (1568 B for ML-KEM-1024) otherwise.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("CKM_ML_KEM not supported")

        try:
            pub, priv = _gen_ml_kem_keypair(rs, encapsulate=False)
        except (AssertionError, OSError):
            pytest.skip("Module refused ML-KEM keypair with CKA_ENCAPSULATE=False")

        from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE, CK_ULONG

        handle = CK_OBJECT_HANDLE(0)
        try:
            mech = mech_simple(CKM_ML_KEM)
            tmpl_attrs = _ml_kem_secret_template()
            from pkcs11_check.raw.pack import attr_bool

            packed = [
                attr_ulong(CKA_CLASS, tmpl_attrs[CKA_CLASS]),
                attr_ulong(CKA_KEY_TYPE, tmpl_attrs[CKA_KEY_TYPE]),
                attr_ulong(CKA_VALUE_LEN, tmpl_attrs[CKA_VALUE_LEN]),
                attr_bool(CKA_SENSITIVE, tmpl_attrs[CKA_SENSITIVE]),
                attr_bool(CKA_EXTRACTABLE, tmpl_attrs[CKA_EXTRACTABLE]),
            ]
            tmpl = template(*packed)

            # First call: query the ciphertext length.
            ct_len = CK_ULONG(0)
            size_rv = rs.raw.C_EncapsulateKey(
                rs.sh,
                mech.byref(),
                pub,
                *template_ptr_count(tmpl),
                None,
                byref(ct_len),
                byref(handle),
            )
            # If the module enforces the flag at the size-query stage, classify
            # immediately and return — no further call needed.
            if size_rv not in (CKR_OK,):
                classify_negative_rv(
                    size_rv,
                    (CKR_KEY_FUNCTION_NOT_PERMITTED,),
                    label="C_EncapsulateKey with CKA_ENCAPSULATE=False on public key "
                    "(PKCS#11 v3.2 Sec.5.14.7)",
                    kind="policy",
                )
                return

            # Second call: full encapsulation with a real buffer.
            buf_len = ct_len.value if ct_len.value else 4096
            ct_buf = (ctypes.c_ubyte * buf_len)()
            ct_len = CK_ULONG(buf_len)
            rv = rs.raw.C_EncapsulateKey(
                rs.sh,
                mech.byref(),
                pub,
                *template_ptr_count(tmpl),
                ct_buf,
                byref(ct_len),
                byref(handle),
            )
            if rv == CKR_OK and handle.value:
                destroy_quietly(rs.raw, rs.sh, handle.value)
                handle = CK_OBJECT_HANDLE(0)

            if rv != CKR_OK:
                classify_negative_rv(
                    rv,
                    (CKR_KEY_FUNCTION_NOT_PERMITTED,),
                    label="C_EncapsulateKey with CKA_ENCAPSULATE=False on public key "
                    "(PKCS#11 v3.2 Sec.5.14.7)",
                    kind="policy",
                )
                return

            # rv == CKR_OK — check whether the module actually claims the flag.
            # If CKA_ENCAPSULATE reads back False, the module contradicted itself.
            # If it reads back True (flag silently overridden at create), that is
            # honest non-enforcement of the restriction → xfail.
            encap_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_ENCAPSULATE])
            claimed = encap_attrs.get(CKA_ENCAPSULATE) is False
            classify_policy_enforcement(
                claimed=claimed,
                violated=True,
                label="C_EncapsulateKey with CKA_ENCAPSULATE=False on public key "
                "(PKCS#11 v3.2 Sec.5.14.7 requires CKR_KEY_FUNCTION_NOT_PERMITTED)",
            )
        finally:
            if handle.value:
                destroy_quietly(rs.raw, rs.sh, handle.value)
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_decapsulate_flag_false_rejected(self, p11_raw_session: Any) -> None:
        """C_DecapsulateKey is rejected when private key has CKA_DECAPSULATE=False.

        Spec: PKCS#11 v3.2 Sec.5.14.8 — ``CKR_KEY_FUNCTION_NOT_PERMITTED``
        when ``CKA_DECAPSULATE`` is ``False``.

        A valid ciphertext is obtained by encapsulating with a normal keypair
        (``CKA_ENCAPSULATE=True``) so the decapsulation attempt is well-formed;
        only the private key's permission flag is restricted.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("CKM_ML_KEM not supported")

        # Generate a normal keypair to produce a valid ciphertext for decapsulation.
        try:
            norm_pub, norm_priv = _gen_ml_kem_keypair(rs, encapsulate=True, decapsulate=True)
        except (AssertionError, OSError):
            pytest.skip("Module refused ML-KEM keypair generation (setup)")

        # Generate the restricted private key to probe.
        try:
            restr_pub, restr_priv = _gen_ml_kem_keypair(rs, encapsulate=True, decapsulate=False)
        except (AssertionError, OSError):
            destroy_quietly(rs.raw, rs.sh, norm_pub)
            destroy_quietly(rs.raw, rs.sh, norm_priv)
            pytest.skip("Module refused ML-KEM keypair with CKA_DECAPSULATE=False")

        from pkcs11_check.raw.recipes import encapsulate_key

        encap_handle = 0
        dec_handle = 0
        try:
            # Encapsulate with the normal public key to get a valid ciphertext.
            try:
                encap_handle, ct = encapsulate_key(
                    rs.raw, rs.sh, norm_pub, CKM_ML_KEM, attrs=_ml_kem_secret_template()
                )
            except (NotImplementedError, AttributeError):
                pytest.skip("encapsulate_key not available")
            except AssertionError:
                pytest.skip("ML-KEM encapsulate not operational (setup)")

            # Attempt to decapsulate using the restricted private key.
            from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE

            handle = CK_OBJECT_HANDLE(0)
            mech = mech_simple(CKM_ML_KEM)

            packed = [
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_AES),
            ]
            tmpl = template(*packed)
            ct_buf = to_ubyte_buf(ct)
            rv = rs.raw.C_DecapsulateKey(
                rs.sh,
                mech.byref(),
                restr_priv,
                *template_ptr_count(tmpl),
                ct_buf,
                len(ct),
                byref(handle),
            )
            dec_handle = handle.value

            if rv != CKR_OK:
                classify_negative_rv(
                    rv,
                    (CKR_KEY_FUNCTION_NOT_PERMITTED,),
                    label="C_DecapsulateKey with CKA_DECAPSULATE=False on private key "
                    "(PKCS#11 v3.2 Sec.5.14.8)",
                    kind="policy",
                )
                return

            # rv == CKR_OK — check whether the flag was actually claimed.
            decap_attrs = read_attributes(rs.raw, rs.sh, restr_priv, [CKA_DECAPSULATE])
            claimed = decap_attrs.get(CKA_DECAPSULATE) is False
            classify_policy_enforcement(
                claimed=claimed,
                violated=True,
                label="C_DecapsulateKey with CKA_DECAPSULATE=False on private key "
                "(PKCS#11 v3.2 Sec.5.14.8 requires CKR_KEY_FUNCTION_NOT_PERMITTED)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, norm_pub)
            destroy_quietly(rs.raw, rs.sh, norm_priv)
            destroy_quietly(rs.raw, rs.sh, restr_pub)
            destroy_quietly(rs.raw, rs.sh, restr_priv)
            if encap_handle:
                destroy_quietly(rs.raw, rs.sh, encap_handle)
            if dec_handle:
                destroy_quietly(rs.raw, rs.sh, dec_handle)
