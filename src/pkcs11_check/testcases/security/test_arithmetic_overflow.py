"""Integer overflow/underflow probes for user-controlled size fields.

All tests run in subprocess for crash safety. Each test constructs ctypes
structures with near-SIZE_MAX values in length/count fields, then calls C_*
functions to check whether the module wraps around or crashes.

Covers:
- Data length overflow in C_Encrypt / C_Decrypt (ulDataLen near SIZE_MAX)
- Mechanism parameter length overflow (ulParameterLen = ULONG_MAX)
- GCM tag bits overflow ((ulTagBits + 7) / 8 wraps to 0)
- PSS salt length overflow (hash_len + sLen + 2 wraps)
- Template count overflow (count * sizeof(CK_ATTRIBUTE) wraps)
- KEM output-template count overflow in C_EncapsulateKey / C_DecapsulateKey
- Key value length overflow (CKA_VALUE_LEN = ULONG_MAX)
- Attribute value length overflow (ulValueLen = ULONG_MAX)
- GenerateKeyPair template count overflow
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    _CK_ULONG_MAX,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    destroy_returned_handles,
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
)
from pkcs11_check.testcases.security._boundary_values import requires_64bit_ck_ulong
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

# Literal values for embedding in subprocess script strings.
# Subprocess scripts cannot import _CK_ULONG_MAX so we use plain ints.
_ULONG_MAX = int(_CK_ULONG_MAX)
_ULONG_MAX_MINUS_15 = _ULONG_MAX - 15
_ULONG_HALF = _ULONG_MAX // 2
_ULONG_32BIT_SIGN = 0x80000000
_ULONG_32BIT_MAX = 0xFFFFFFFF
_ULONG_64BIT_SIGN = 0x8000000000000000
_SIZEOF_ATTR_OVERFLOW = _ULONG_MAX // 24 + 1
_ULONG_33BIT = 0x100000000


# ---------------------------------------------------------------------------
# TestDataLengthOverflow -- 4 lengths x 2 ops = 8 cases
# ---------------------------------------------------------------------------

_DATA_LENGTHS = [
    pytest.param(_ULONG_MAX, id="ulong_max"),
    pytest.param(_ULONG_MAX_MINUS_15, id="ulong_max_minus_15"),
    pytest.param(_ULONG_HALF, id="ulong_half"),
    pytest.param(_ULONG_32BIT_SIGN, id="0x80000000"),
]

_DATA_OPS = [
    pytest.param("C_Encrypt", "C_EncryptInit", id="encrypt"),
    pytest.param("C_Decrypt", "C_DecryptInit", id="decrypt"),
]


class TestDataLengthOverflow:
    """Probe C_Encrypt/C_Decrypt with near-SIZE_MAX ulDataLen.

    After C_EncryptInit / C_DecryptInit with AES-ECB, call the data function
    with a huge ulDataLen.  Modules that compute padded_len =
    block_size * (len / block_size + 1) will wrap near SIZE_MAX.
    """

    @pytest.mark.parametrize("data_len", _DATA_LENGTHS)
    @pytest.mark.parametrize("func,init_func", _DATA_OPS)
    def test_data_length_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        func: str,
        init_func: str,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose=f"{func} data-length overflow crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        result = run_probe(
            "arithmetic_overflow",
            {
                "module_path": str(p11_config.module),
                "which": "data_length_overflow",
                "func": func,
                "init_func": init_func,
                "data_len": data_len,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"{func}(ulDataLen={data_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestGcmDecryptUpdateAccumulation -- 1 case
# ---------------------------------------------------------------------------

# Reject codes a conformant module may return when ulEncryptedPartLen is
# out of range for the streaming decryption phase.
_DATA_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
)


class TestGcmDecryptUpdateAccumulation:
    """AES-GCM C_DecryptUpdate must reject huge length before accumulating.

    A plain 32-bit add for the internal byte accumulator means that feeding
    0xFFFFFFFF first then 2 wraps the accumulator to 1, bypassing the length
    guard and driving an OOB copy.  A conformant module rejects the oversized
    first-update length with ``CKR_DATA_LEN_RANGE`` / ``CKR_ARGUMENTS_BAD`` /
    ``CKR_ENCRYPTED_DATA_LEN_RANGE`` (or another clean code) BEFORE any
    accumulation.
    """

    def test_gcm_decrypt_update_accumulation_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Two-call ``C_DecryptUpdate`` accumulation wrap must be rejected.

        Two ``C_DecryptUpdate`` calls whose lengths sum past the 32-bit boundary
        must not wrap the internal byte accumulator into a small allocation.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        if "C_DecryptUpdate" not in rs.raw.available_function_names():
            pytest.skip("C_DecryptUpdate not available")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-GCM DecryptUpdate accumulation crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        result = run_probe(
            "arithmetic_overflow",
            {
                "module_path": str(p11_config.module),
                "which": "gcm_decrypt_update_accumulation",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_DecryptUpdate(AES_GCM, ulEncryptedPartLen={_ULONG_32BIT_MAX:#x})",
        )
        # Classify the first-update return value: the module must reject the
        # oversized length before any accumulation.
        rv1_line = next(
            (ln for ln in result.stdout.splitlines() if ln.startswith("CKR_UPDATE1:")),
            None,
        )
        if rv1_line is not None:
            rv1 = int(rv1_line.removeprefix("CKR_UPDATE1:"), 0)
            classify_negative_rv(
                rv1,
                _DATA_REJECT_CKRS,
                label=(
                    f"C_DecryptUpdate(AES_GCM, ulEncryptedPartLen={_ULONG_32BIT_MAX:#x}) "
                    "-- must reject before accumulating"
                ),
                allow_ok=True,  # CKR_OK + no crash is tolerable; the two-call crash is the finding
            )


# ---------------------------------------------------------------------------
# TestMechanismParamLengthOverflow -- 2 cases
# ---------------------------------------------------------------------------

_MECH_PARAM_CASES = [
    pytest.param("AES_CBC", "CKM_AES_CBC", 16, id="aes_cbc"),
    pytest.param("AES_GCM", "CKM_AES_GCM", 64, id="aes_gcm"),
]


class TestMechanismParamLengthOverflow:
    """Probe C_EncryptInit with pParameter pointing to a small buffer
    but ulParameterLen = ULONG_MAX.

    Modules that memcpy(ulParameterLen) from the small buffer will read
    past the allocation boundary.
    """

    @pytest.mark.parametrize("mech_check,mech_name,real_size", _MECH_PARAM_CASES)
    def test_mechanism_param_length_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        mech_check: str,
        mech_name: str,
        real_size: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(mech_check):
            pytest.skip(f"CKM_{mech_check} not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose=f"{mech_name} parameter-length overflow crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        result = run_probe(
            "arithmetic_overflow",
            {
                "module_path": str(p11_config.module),
                "which": "mechanism_param_length_overflow",
                "mech_name": mech_name,
                "real_size": real_size,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=(
                f"C_EncryptInit({mech_name}, "
                f"pParameter={real_size}B, ulParameterLen={_ULONG_MAX:#x})"
            ),
        )


# ---------------------------------------------------------------------------
# TestGcmTagBitsOverflow -- 4 cases
# ---------------------------------------------------------------------------

_GCM_TAG_BITS = [
    pytest.param(_ULONG_MAX, id="ulong_max"),
    pytest.param(_ULONG_MAX - 6, id="ulong_max_minus_6"),
    pytest.param(_ULONG_32BIT_MAX, id="0xFFFFFFFF"),
    pytest.param(_ULONG_64BIT_SIGN, id="0x8000000000000000"),
]


@requires_64bit_ck_ulong
class TestGcmTagBitsOverflow:
    """Probe AES-GCM with extreme ulTagBits values.

    Modules compute tag_len = (ulTagBits + 7) / 8 which wraps to 0 near
    SIZE_MAX, causing a buffer underflow when writing the tag.
    """

    @pytest.mark.parametrize("tag_bits", _GCM_TAG_BITS)
    def test_gcm_tag_bits_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        tag_bits: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-GCM tag-bits overflow crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        result = run_probe(
            "arithmetic_overflow",
            {
                "module_path": str(p11_config.module),
                "which": "gcm_tag_bits_overflow",
                "tag_bits": tag_bits,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_EncryptInit(AES_GCM, ulTagBits={tag_bits:#x})",
        )


# ---------------------------------------------------------------------------
# TestPssSaltLengthOverflow -- 3 cases
# ---------------------------------------------------------------------------

_PSS_SALT_LENGTHS = [
    pytest.param(_ULONG_MAX, id="ulong_max"),
    pytest.param(_ULONG_32BIT_SIGN, id="0x80000000"),
    pytest.param(_ULONG_32BIT_MAX, id="0xFFFFFFFF"),
]


class TestPssSaltLengthOverflow:
    """Probe RSA-PSS with extreme sLen values.

    Modules compute emLen >= hash_len + sLen + 2 which overflows when
    sLen is near SIZE_MAX, bypassing length validation.
    """

    @pytest.mark.parametrize("salt_len", _PSS_SALT_LENGTHS)
    def test_pss_salt_length_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        salt_len: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_RSA_PKCS_PSS"):
            pytest.skip("CKM_SHA256_RSA_PKCS_PSS not supported")
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)
        result = run_probe(
            "arithmetic_overflow",
            {
                "module_path": str(p11_config.module),
                "which": "pss_salt_length_overflow",
                "salt_len": salt_len,
            },
            pin=pin_from_config(p11_config),
            timeout=15,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_SignInit(SHA256_RSA_PKCS_PSS, sLen={salt_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestTemplateCountOverflow -- 3 counts x 5 ops = 15 cases
# ---------------------------------------------------------------------------

_TEMPLATE_COUNTS = [
    pytest.param(_ULONG_MAX, id="ulong_max"),
    pytest.param(_SIZEOF_ATTR_OVERFLOW, id="sizeof_attr_overflow"),
    pytest.param(_ULONG_33BIT, id="0x100000000"),
]

_TEMPLATE_OPS = [
    pytest.param("C_CreateObject", id="create_object"),
    pytest.param("C_GenerateKey", id="generate_key"),
    pytest.param("C_FindObjectsInit", id="find_objects_init"),
    pytest.param("C_SetAttributeValue", id="set_attribute_value"),
    pytest.param("C_UnwrapKey", id="unwrap_key"),
]


@requires_64bit_ck_ulong
class TestTemplateCountOverflow:
    """Probe template-accepting functions with huge template counts.

    Pass a template with 1 real CK_ATTRIBUTE but claim a count that would
    overflow count * sizeof(CK_ATTRIBUTE), causing the module to iterate
    past the allocation boundary.
    """

    @pytest.mark.parametrize("count", _TEMPLATE_COUNTS)
    @pytest.mark.parametrize("op", _TEMPLATE_OPS)
    def test_template_count_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        count: int,
        op: str,
    ) -> None:
        rs = p11_raw_session
        if op == "C_GenerateKey" and not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if op == "C_UnwrapKey" and not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        if op == "C_UnwrapKey":
            setup_key = gen_aes_key_or_xfail(
                rs,
                256,
                purpose="C_UnwrapKey template-count overflow crash probe setup",
            )
            destroy_returned_handles(rs, setup_key)
        result = run_probe(
            "arithmetic_overflow",
            {
                "module_path": str(p11_config.module),
                "which": "template_count_overflow",
                "op": op,
                "count": count,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"{op}(template_count={count:#x})",
        )


# ---------------------------------------------------------------------------
# TestTemplateCountOverflowValidHandles -- 3 counts x 3 ops = 9 cases
# ---------------------------------------------------------------------------

_VALID_HANDLE_TEMPLATE_OPS = [
    pytest.param("C_GetAttributeValue", id="get_attribute_value"),
    pytest.param("C_SetAttributeValue", id="set_attribute_value"),
    pytest.param("C_CopyObject", id="copy_object"),
]


@requires_64bit_ck_ulong
class TestTemplateCountOverflowValidHandles:
    """Template-count overflow probes that reach real object-handle paths."""

    @pytest.mark.parametrize("count", _TEMPLATE_COUNTS)
    @pytest.mark.parametrize("op", _VALID_HANDLE_TEMPLATE_OPS)
    def test_template_count_overflow_with_valid_object_handle(
        self,
        p11_config: Any,
        count: int,
        op: str,
    ) -> None:
        """A huge template count must not walk beyond a one-attribute template."""
        result = run_probe(
            "arithmetic_overflow",
            {
                "module_path": str(p11_config.module),
                "which": "template_count_overflow_valid_handles",
                "op": op,
                "count": count,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"{op}(valid object, template_count={count:#x})",
        )


# ---------------------------------------------------------------------------
# TestDeriveTemplateCountOverflowValidBase -- 3 cases
# ---------------------------------------------------------------------------


@requires_64bit_ck_ulong
class TestDeriveTemplateCountOverflowValidBase:
    """Template-count overflow probes that reach a valid C_DeriveKey base key path."""

    @pytest.mark.parametrize("count", _TEMPLATE_COUNTS)
    def test_derive_key_template_count_overflow_with_valid_base_key(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        count: int,
    ) -> None:
        """A huge derived-key template count must not walk beyond one attribute."""
        rs = p11_raw_session
        if not rs.has_mechanism("CONCATENATE_BASE_AND_DATA"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_DATA not supported")

        result = run_probe(
            "arithmetic_overflow",
            {
                "module_path": str(p11_config.module),
                "which": "derive_key_template_count_overflow",
                "count": count,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_DeriveKey(valid base, template_count={count:#x})",
        )


# ---------------------------------------------------------------------------
# TestKemTemplateCountOverflow -- 3 counts x 2 ops = 6 cases
# ---------------------------------------------------------------------------

_KEM_TEMPLATE_COUNT_OPS = [
    pytest.param("C_EncapsulateKey", id="encapsulate_key"),
    pytest.param("C_DecapsulateKey", id="decapsulate_key"),
]


@requires_64bit_ck_ulong
class TestKemTemplateCountOverflow:
    """Template-count overflow probes for v3.2 KEM output templates."""

    @pytest.mark.needs_function("C_EncapsulateKey")
    @pytest.mark.parametrize("count", _TEMPLATE_COUNTS)
    @pytest.mark.parametrize("op", _KEM_TEMPLATE_COUNT_OPS)
    def test_kem_output_template_count_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        count: int,
        op: str,
    ) -> None:
        """A huge KEM output-template count must not walk beyond one attribute."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("CKM_ML_KEM not supported")
        if "C_EncapsulateKey" not in rs.raw.available_function_names():
            pytest.skip("C_EncapsulateKey not available")
        if op == "C_DecapsulateKey" and "C_DecapsulateKey" not in rs.raw.available_function_names():
            pytest.skip("C_DecapsulateKey not available")

        result = run_probe(
            "arithmetic_overflow",
            {
                "module_path": str(p11_config.module),
                "which": "kem_template_count_overflow",
                "op": op,
                "count": count,
            },
            pin=pin_from_config(p11_config),
            timeout=15,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"{op}(ML-KEM output template_count={count:#x})",
        )


# ---------------------------------------------------------------------------
# TestKeyValueLenOverflow -- 2 cases
# ---------------------------------------------------------------------------

_KEYGEN_MECHS = [
    pytest.param("AES_KEY_GEN", "CKM_AES_KEY_GEN", id="aes"),
    pytest.param("DES3_KEY_GEN", "CKM_DES3_KEY_GEN", id="des3"),
]


class TestKeyValueLenOverflow:
    """Probe C_GenerateKey with CKA_VALUE_LEN = ULONG_MAX.

    Modules that allocate CKA_VALUE_LEN bytes without validation will
    attempt a near-SIZE_MAX allocation, crashing or hanging.
    """

    @pytest.mark.parametrize("mech_check,mech_name", _KEYGEN_MECHS)
    def test_key_value_len_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        mech_check: str,
        mech_name: str,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(mech_check):
            pytest.skip(f"CKM_{mech_check} not supported")
        result = run_probe(
            "arithmetic_overflow",
            {
                "module_path": str(p11_config.module),
                "which": "key_value_len_overflow",
                "mech_name": mech_name,
            },
            pin=pin_from_config(p11_config),
            timeout=5,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_GenerateKey({mech_name}, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )


# ---------------------------------------------------------------------------
# TestAttributeValueLenOverflow -- 3 cases
# ---------------------------------------------------------------------------

_ATTR_VALUE_OPS = [
    pytest.param("C_GetAttributeValue", id="get_attribute_value"),
    pytest.param("C_SetAttributeValue", id="set_attribute_value"),
    pytest.param("C_CreateObject", id="create_object"),
]


class TestAttributeValueLenOverflow:
    """Probe attribute functions with CK_ATTRIBUTE.ulValueLen = ULONG_MAX.

    Pass a CK_ATTRIBUTE whose pValue points to a small buffer but whose
    ulValueLen claims ULONG_MAX bytes.  Modules that memcpy(ulValueLen)
    from pValue will read or write far past the allocation.
    """

    @pytest.mark.parametrize("op", _ATTR_VALUE_OPS)
    def test_attribute_value_len_overflow(
        self,
        p11_config: Any,
        op: str,
    ) -> None:
        result = run_probe(
            "arithmetic_overflow",
            {
                "module_path": str(p11_config.module),
                "which": "attribute_value_len_overflow",
                "op": op,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"{op}(ulValueLen={_ULONG_MAX:#x})",
        )


# ---------------------------------------------------------------------------
# TestGenerateKeyPairCountOverflow -- 2 cases
# ---------------------------------------------------------------------------

_KEYPAIR_COUNT_CASES = [
    pytest.param("pub", id="pub_template_overflow"),
    pytest.param("priv", id="priv_template_overflow"),
]


class TestGenerateKeyPairCountOverflow:
    """Probe C_GenerateKeyPair with ULONG_MAX template count.

    Pass one real attribute in the pub/priv template but claim ULONG_MAX
    as the count for one of them.  Modules that iterate
    count * sizeof(CK_ATTRIBUTE) bytes will overflow.
    """

    @pytest.mark.parametrize("which", _KEYPAIR_COUNT_CASES)
    def test_generate_key_pair_count_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        which: str,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        if which == "pub":
            pub_count = _ULONG_MAX
            priv_count = 1
        else:
            pub_count = 1
            priv_count = _ULONG_MAX

        result = run_probe(
            "arithmetic_overflow",
            {
                "module_path": str(p11_config.module),
                "which": "generate_key_pair_count_overflow",
                "pub_count": pub_count,
                "priv_count": priv_count,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=(f"C_GenerateKeyPair(pub_count={pub_count:#x}, priv_count={priv_count:#x})"),
        )
