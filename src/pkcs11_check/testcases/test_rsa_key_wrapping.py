"""RSA key wrapping tests.

Tests C_WrapKey / C_UnwrapKey with RSA-PKCS, RSA-OAEP, and AES-family mechanisms.
Wraps an AES key with a wrapping key, unwraps, and verifies key material matches.
Includes policy tests: non-extractable key must be refused by all wrap mechanisms,
and sensitive-but-extractable key is conformant to wrap.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, xfail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.pack import mech_cbc_pad, mech_oaep
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    read_attributes,
)
from pkcs11_check.raw.recipes import (
    wrap_key as wrap_key_recipe,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKG_MGF1_SHA1,
    CKK_AES,
    CKM_AES_CBC_PAD,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP,
    CKM_AES_KEY_WRAP_KWP,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA_1,
    CKO_SECRET_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_UNEXTRACTABLE,
)
from pkcs11_check.testcases._signature_policy import xfail_if_op_not_operational
from pkcs11_check.testcases.conftest import (
    assert_correct,
    classify_policy_enforcement,
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
    reject_or_classify,
    require_operational_aes_keygen,
    unwrap_key_for_mechanism_roundtrip,
)

pytestmark = pytest.mark.keymgmt

# Return codes that indicate the module refused to wrap a non-extractable key
# (any of these is conformant and results in a pass verdict).
_NON_EXTRACTABLE_WRAP_REFUSE_RVS = (
    CKR_KEY_NOT_WRAPPABLE,
    CKR_ACTION_PROHIBITED,
    CKR_KEY_UNEXTRACTABLE,
)


def _make_rsa_pair(rs: Any) -> tuple[int, int]:
    """Generate RSA-2048 keypair with default capabilities (includes WRAP/UNWRAP)."""
    return gen_rsa_keypair_or_xfail(
        rs,
        2048,
        public_attrs={
            CKA_WRAP: True,
            CKA_ENCRYPT: True,
            CKA_TOKEN: False,
        },
        private_attrs={
            CKA_UNWRAP: True,
            CKA_DECRYPT: True,
            CKA_TOKEN: False,
        },
    )


def _make_extractable_aes(rs: Any, bits: int = 128) -> int:
    """Generate an extractable AES key suitable for wrapping."""
    require_operational_aes_keygen(rs)
    return gen_aes_key(
        rs.raw,
        rs.sh,
        bits,
        attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
    )


class TestRSAPKCSWrap:
    """Test RSA-PKCS (v1.5) key wrapping."""

    def test_wrap_unwrap_aes128(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Wrap AES-128 key with RSA, unwrap, verify key material matches."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = _make_rsa_pair(rs)
        aes_key = _make_extractable_aes(rs, 128)
        try:
            original_value = read_attributes(rs.raw, rs.sh, aes_key, [CKA_VALUE])[CKA_VALUE]

            wrapped = wrap_key_recipe(
                rs.raw,
                rs.sh,
                pub,
                aes_key,
                CKM_RSA_PKCS,
            )
            if wrapped == original_value:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_RSA_PKCS:wrap AES-128 confidentiality",
                    operation="C_WrapKey",
                    mechanism="CKM_RSA_PKCS",
                    summary="wrapped blob equals the raw key value -- key transport "
                    "leaked the key in cleartext",
                )
            assert len(wrapped) == 256  # 2048-bit RSA -> 256 bytes

            try:
                unwrapped = unwrap_key_for_mechanism_roundtrip(
                    rs,
                    p11_config,
                    unwrapping_key=priv,
                    wrapped_key=wrapped,
                    mechanism=CKM_RSA_PKCS,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_EXTRACTABLE: True,
                        CKA_SENSITIVE: False,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_TOKEN: False,
                    },
                    purpose="RSA-PKCS AES-128 wrap/unwrap roundtrip",
                )
            except AssertionError as exc:
                # FIPS restricts RSA PKCS#1 v1.5 key transport -> CKR_DEVICE_ERROR on
                # C_UnwrapKey: advertised but not operational, not a break.
                xfail_if_op_not_operational(exc, "CKM_RSA_PKCS unwrap (key transport)")
            try:
                unwrapped_value = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
                assert_correct(
                    actual=unwrapped_value,
                    expected=original_value,
                    label="CKM_RSA_PKCS:unwrap AES-128 roundtrip",
                    operation="C_UnwrapKey",
                    mechanism="CKM_RSA_PKCS",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, aes_key)

    def test_wrap_unwrap_aes256(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Wrap AES-256 key - larger key material still fits in RSA-2048."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = _make_rsa_pair(rs)
        aes_key = _make_extractable_aes(rs, 256)
        try:
            original_value = read_attributes(rs.raw, rs.sh, aes_key, [CKA_VALUE])[CKA_VALUE]

            wrapped = wrap_key_recipe(
                rs.raw,
                rs.sh,
                pub,
                aes_key,
                CKM_RSA_PKCS,
            )
            try:
                unwrapped = unwrap_key_for_mechanism_roundtrip(
                    rs,
                    p11_config,
                    unwrapping_key=priv,
                    wrapped_key=wrapped,
                    mechanism=CKM_RSA_PKCS,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_EXTRACTABLE: True,
                        CKA_SENSITIVE: False,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_TOKEN: False,
                    },
                    purpose="RSA-PKCS AES-256 wrap/unwrap roundtrip",
                )
            except AssertionError as exc:
                # FIPS restricts RSA PKCS#1 v1.5 key transport -> CKR_DEVICE_ERROR on
                # C_UnwrapKey: advertised but not operational, not a break.
                xfail_if_op_not_operational(exc, "CKM_RSA_PKCS unwrap (key transport)")
            try:
                unwrapped_value = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
                assert_correct(
                    actual=unwrapped_value,
                    expected=original_value,
                    label="CKM_RSA_PKCS:unwrap AES-256 roundtrip",
                    operation="C_UnwrapKey",
                    mechanism="CKM_RSA_PKCS",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, aes_key)

    def test_wrapped_key_is_different_each_time(self, p11_raw_session: Any) -> None:
        """RSA-PKCS wrapping is randomized - same key wraps differently each time."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = _make_rsa_pair(rs)
        aes_key = _make_extractable_aes(rs)
        try:
            wrapped1 = wrap_key_recipe(
                rs.raw,
                rs.sh,
                pub,
                aes_key,
                CKM_RSA_PKCS,
            )
            wrapped2 = wrap_key_recipe(
                rs.raw,
                rs.sh,
                pub,
                aes_key,
                CKM_RSA_PKCS,
            )
            if wrapped1 == wrapped2:  # Randomized padding
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_RSA_PKCS:wrap randomization",
                    operation="C_WrapKey",
                    mechanism="CKM_RSA_PKCS",
                    summary="two RSA-PKCS#1v1.5 wraps of the same key are identical -- "
                    "padding is not randomized",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, aes_key)


class TestRSAOAEPWrap:
    """Test RSA-OAEP key wrapping (more secure than PKCS v1.5)."""

    def test_wrap_unwrap_oaep(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Wrap/unwrap AES key with RSA-OAEP."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")

        pub, priv = _make_rsa_pair(rs)
        aes_key = _make_extractable_aes(rs, 128)
        try:
            original_value = read_attributes(rs.raw, rs.sh, aes_key, [CKA_VALUE])[CKA_VALUE]

            oaep = mech_oaep(
                CKM_RSA_PKCS_OAEP,
                hash_mech=CKM_SHA_1,
                mgf=CKG_MGF1_SHA1,
            )
            wrapped = wrap_key_recipe(
                rs.raw,
                rs.sh,
                pub,
                aes_key,
                CKM_RSA_PKCS_OAEP,
                mech_param=oaep,
            )
            oaep2 = mech_oaep(
                CKM_RSA_PKCS_OAEP,
                hash_mech=CKM_SHA_1,
                mgf=CKG_MGF1_SHA1,
            )
            unwrapped = unwrap_key_for_mechanism_roundtrip(
                rs,
                p11_config,
                unwrapping_key=priv,
                wrapped_key=wrapped,
                mechanism=CKM_RSA_PKCS_OAEP,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_TOKEN: False,
                },
                mech_param=oaep2,
                purpose="RSA-OAEP AES wrap/unwrap roundtrip",
            )
            try:
                unwrapped_value = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
                assert_correct(
                    actual=unwrapped_value,
                    expected=original_value,
                    label="CKM_RSA_PKCS_OAEP:unwrap AES roundtrip",
                    operation="C_UnwrapKey",
                    mechanism="CKM_RSA_PKCS_OAEP",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, aes_key)


class TestWrappedKeyUsability:
    """Verify unwrapped keys are fully functional."""

    def test_unwrapped_key_encrypts(self, p11_raw_session: Any, p11_config: Any) -> None:
        """An unwrapped AES key can be used for encryption."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = _make_rsa_pair(rs)
        aes_key = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={
                CKA_EXTRACTABLE: True,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
            },
        )
        try:
            # Encrypt with original key
            plaintext = b"wrap-test-data!!" * 2  # 32 bytes
            ct = encrypt_single(rs.raw, rs.sh, aes_key, CKM_AES_ECB, plaintext)

            # Wrap -> unwrap -> decrypt with unwrapped key
            wrapped = wrap_key_recipe(
                rs.raw,
                rs.sh,
                pub,
                aes_key,
                CKM_RSA_PKCS,
            )
            try:
                unwrapped = unwrap_key_for_mechanism_roundtrip(
                    rs,
                    p11_config,
                    unwrapping_key=priv,
                    wrapped_key=wrapped,
                    mechanism=CKM_RSA_PKCS,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_EXTRACTABLE: True,
                        CKA_SENSITIVE: False,
                        CKA_ENCRYPT: True,
                        CKA_DECRYPT: True,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_TOKEN: False,
                    },
                    purpose="RSA-PKCS unwrapped-key usability roundtrip",
                )
            except AssertionError as exc:
                # FIPS restricts RSA PKCS#1 v1.5 key transport -> CKR_DEVICE_ERROR on
                # C_UnwrapKey: advertised but not operational, not a break.
                xfail_if_op_not_operational(exc, "CKM_RSA_PKCS unwrap (key transport)")
            try:
                pt = decrypt_single(rs.raw, rs.sh, unwrapped, CKM_AES_ECB, ct)
                assert_correct(
                    actual=pt,
                    expected=plaintext,
                    label="CKM_RSA_PKCS:unwrapped AES key usability roundtrip",
                    operation="C_Decrypt",
                    mechanism="CKM_AES_ECB",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, aes_key)

    def test_non_extractable_key_cannot_be_wrapped(self, p11_raw_session: Any) -> None:
        """EXTRACTABLE=False key must not be wrappable via CKM_RSA_PKCS.

        PKCS#11 spec: C_WrapKey must return CKR_KEY_NOT_WRAPPABLE,
        CKR_KEY_UNEXTRACTABLE, or CKR_ACTION_PROHIBITED if the key has
        CKA_EXTRACTABLE=False.

        SECURITY: A module that wraps a non-extractable key allows key material
        exfiltration in violation of the PKCS#11 security model. This is a policy
        self-contradiction (the key reads back CKA_EXTRACTABLE=False, then its
        material leaves the token) and must FAIL, not xfail -- consistent with
        the sensitive-value and Tookan extractable-escalation security tests.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = _make_rsa_pair(rs)
        non_extractable = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: False},
        )

        try:
            # Establish the claim: the key must actually read back
            # CKA_EXTRACTABLE=False. If the module did not honour the flag at
            # creation, it never claimed the protection -> honest non-support.
            extractable = read_attributes(rs.raw, rs.sh, non_extractable, [CKA_EXTRACTABLE]).get(
                CKA_EXTRACTABLE
            )
            if extractable is not False:
                xfail_as(
                    "honest_deviation",
                    kind="metadata",
                    label="C_GenerateKey:CKA_EXTRACTABLE",
                    summary="Module did not honour CKA_EXTRACTABLE=False at key creation",
                )

            try:
                wrap_key_recipe(
                    rs.raw,
                    rs.sh,
                    pub,
                    non_extractable,
                    CKM_RSA_PKCS,
                )
            except AssertionError as exc:
                reject_or_classify(
                    exc,
                    _NON_EXTRACTABLE_WRAP_REFUSE_RVS,
                    label="C_WrapKey of a CKA_EXTRACTABLE=False key via CKM_RSA_PKCS",
                )
                return

            # Wrap succeeded on a verified non-extractable key -- policy: claimed
            # the protection (CKA_EXTRACTABLE=False) then violated it (material
            # left the token).
            classify_policy_enforcement(
                claimed=True,
                violated=True,
                label="C_WrapKey succeeded on a CKA_EXTRACTABLE=False key via "
                "CKM_RSA_PKCS -- key material exfiltration "
                "(PKCS#11 requires CKR_KEY_NOT_WRAPPABLE/CKR_KEY_UNEXTRACTABLE)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, non_extractable)


class TestNonExtractableWrapRefusal:
    """CKA_EXTRACTABLE=False key must be refused across all wrap mechanisms.

    PKCS#11 v3.2 §4 attribute model: CKA_EXTRACTABLE=False is a binding
    commitment -- key material must not leave the token boundary via any
    mechanism. A module that honours the flag for one mechanism but not
    another exports key material inconsistently with the declared attribute.
    Each test is gated on the mechanism being advertised; absent mechanisms
    skip cleanly.
    """

    @staticmethod
    def _check_non_extractable(
        rs: Any,
        wrapping_key: int,
        target: int,
        mechanism: Any,
        mech_label: str,
        *,
        mech_param: Any = None,
    ) -> None:
        """Core: try to wrap a verified non-extractable key, classify the outcome.

        Readback guard: if the module did not honour CKA_EXTRACTABLE=False at
        creation it never made the claim -> honest_deviation/xfail, not fail.
        Wrap refused -> pass. Wrap accepted on a claimed key -> self_contradiction
        policy fail (key material exfiltration).
        """
        # Verify the claim before probing the enforcement.
        extractable = read_attributes(rs.raw, rs.sh, target, [CKA_EXTRACTABLE]).get(CKA_EXTRACTABLE)
        claimed = extractable is False
        if not claimed:
            xfail_as(
                "honest_deviation",
                kind="metadata",
                label=f"C_GenerateKey:CKA_EXTRACTABLE ({mech_label})",
                summary="Module did not honour CKA_EXTRACTABLE=False at key creation",
            )

        # Probe enforcement for this mechanism.
        try:
            wrap_key_recipe(
                rs.raw,
                rs.sh,
                wrapping_key,
                target,
                mechanism,
                mech_param=mech_param,
            )
        except AssertionError as exc:
            reject_or_classify(
                exc,
                _NON_EXTRACTABLE_WRAP_REFUSE_RVS,
                label=f"C_WrapKey of CKA_EXTRACTABLE=False key via {mech_label}",
            )
            return

        # Wrap returned CKR_OK on a verified non-extractable key.
        classify_policy_enforcement(
            claimed=True,
            violated=True,
            label=f"C_WrapKey accepted CKA_EXTRACTABLE=False key via {mech_label} -- "
            "key material exfiltration (PKCS#11 CKA_EXTRACTABLE=False must prevent export)",
        )

    def test_aes_key_wrap(self, p11_raw_session: Any) -> None:
        """CKM_AES_KEY_WRAP must refuse to wrap a CKA_EXTRACTABLE=False key.

        CKM_AES_KEY_WRAP (RFC 3394 / NIST SP 800-38F) exports raw key material
        in an authenticated envelope; accepting a non-extractable key violates
        the CKA_EXTRACTABLE binding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported")

        wrapping_key = gen_aes_key_or_xfail(rs, 256, attrs={CKA_WRAP: True}, purpose="AES-KW wrap")
        target = gen_aes_key(rs.raw, rs.sh, 128, attrs={CKA_EXTRACTABLE: False})
        try:
            self._check_non_extractable(
                rs, wrapping_key, target, CKM_AES_KEY_WRAP, "CKM_AES_KEY_WRAP"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_aes_key_wrap_kwp(self, p11_raw_session: Any) -> None:
        """CKM_AES_KEY_WRAP_KWP must refuse to wrap a CKA_EXTRACTABLE=False key.

        CKM_AES_KEY_WRAP_KWP (NIST SP 800-38F §6.3) is the padded AES key-wrap
        variant; it also exports raw key material and must honour CKA_EXTRACTABLE.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP_KWP"):
            pytest.skip("CKM_AES_KEY_WRAP_KWP not supported")

        wrapping_key = gen_aes_key_or_xfail(rs, 256, attrs={CKA_WRAP: True}, purpose="AES-KWP wrap")
        target = gen_aes_key(rs.raw, rs.sh, 128, attrs={CKA_EXTRACTABLE: False})
        try:
            self._check_non_extractable(
                rs, wrapping_key, target, CKM_AES_KEY_WRAP_KWP, "CKM_AES_KEY_WRAP_KWP"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_aes_cbc_pad(self, p11_raw_session: Any) -> None:
        """CKM_AES_CBC_PAD must refuse to wrap a CKA_EXTRACTABLE=False key.

        AES-CBC-PAD (PKCS#7 padding) applied as a wrap mechanism still exports
        the underlying key material; a non-extractable key must not be exported.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_PAD"):
            pytest.skip("CKM_AES_CBC_PAD not supported")

        wrapping_key = gen_aes_key_or_xfail(
            rs, 128, attrs={CKA_WRAP: True, CKA_ENCRYPT: True}, purpose="AES-CBC-PAD wrap"
        )
        target = gen_aes_key(rs.raw, rs.sh, 128, attrs={CKA_EXTRACTABLE: False})
        iv = bytes(16)  # zero IV -- this is a policy test, not a crypto roundtrip
        mech_param = mech_cbc_pad(CKM_AES_CBC_PAD, iv)
        try:
            self._check_non_extractable(
                rs, wrapping_key, target, CKM_AES_CBC_PAD, "CKM_AES_CBC_PAD", mech_param=mech_param
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_rsa_oaep(self, p11_raw_session: Any) -> None:
        """CKM_RSA_PKCS_OAEP must refuse to wrap a CKA_EXTRACTABLE=False key.

        RSA-OAEP (PKCS#11 §2.1.8) encrypts the raw key bytes under an RSA public
        key; exporting a non-extractable key via OAEP violates CKA_EXTRACTABLE.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA_PKCS_KEY_PAIR_GEN not supported")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_WRAP: True, CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_UNWRAP: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        target = gen_aes_key(rs.raw, rs.sh, 128, attrs={CKA_EXTRACTABLE: False})
        oaep = mech_oaep(CKM_RSA_PKCS_OAEP, hash_mech=CKM_SHA_1, mgf=CKG_MGF1_SHA1)
        try:
            self._check_non_extractable(
                rs,
                pub,
                target,
                CKM_RSA_PKCS_OAEP,
                "CKM_RSA_PKCS_OAEP",
                mech_param=oaep,
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, target)


class TestSensitiveExtractableWrap:
    """CKA_SENSITIVE=True, CKA_EXTRACTABLE=True: wrap is conformant.

    CKA_SENSITIVE governs plaintext readback via C_GetAttributeValue (the module
    must refuse to return the raw value). CKA_EXTRACTABLE controls whether key
    material may leave the token via C_WrapKey. A key that is sensitive-but-
    extractable is fully permitted to be wrapped -- the two attributes are
    orthogonal. A module that refuses to wrap such a key is overly restrictive
    (not a security violation); a module that wraps it is correct. Both outcomes
    are noted, never failed.
    """

    def test_sensitive_extractable_key_may_be_wrapped(self, p11_raw_session: Any) -> None:
        """Sensitive-but-extractable key: wrap success is conformant; refusal is noted.

        PKCS#11 v3.2 attribute model: CKA_SENSITIVE=True prevents the key value
        from being read directly (C_GetAttributeValue returns CKR_ATTRIBUTE_SENSITIVE
        or an empty value). CKA_EXTRACTABLE=True permits the key to be wrapped by
        C_WrapKey. These attributes are orthogonal; a module may honour both.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported")

        wrapping_key = gen_aes_key_or_xfail(
            rs, 256, attrs={CKA_WRAP: True}, purpose="sensitive-extractable wrap probe"
        )
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_SENSITIVE: True, CKA_EXTRACTABLE: True},
        )
        try:
            try:
                wrap_key_recipe(rs.raw, rs.sh, wrapping_key, target, CKM_AES_KEY_WRAP)
            except AssertionError:
                # Module refused to wrap a sensitive-but-extractable key.
                # This is overly restrictive but not a security violation --
                # note only, never fail.
                note(
                    "C_WrapKey refused to wrap a CKA_SENSITIVE=True, CKA_EXTRACTABLE=True key "
                    "via CKM_AES_KEY_WRAP -- overly restrictive but not a spec violation; "
                    "CKA_SENSITIVE and CKA_EXTRACTABLE are orthogonal (PKCS#11 v3.2 §4)",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 v3.2 §4",
                )
                return
            # Wrap succeeded -- conformant. Note it for visibility.
            note(
                "C_WrapKey accepted CKA_SENSITIVE=True, CKA_EXTRACTABLE=True key "
                "via CKM_AES_KEY_WRAP -- correct per PKCS#11 v3.2 §4 "
                "(CKA_EXTRACTABLE=True permits wrapping regardless of CKA_SENSITIVE)",
                ComplianceLevel.STANDARD,
                reference="PKCS#11 v3.2 §4",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
            destroy_quietly(rs.raw, rs.sh, target)
