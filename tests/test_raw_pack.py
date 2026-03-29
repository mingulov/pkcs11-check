from __future__ import annotations

import ctypes
import datetime
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from pkcs11_check.raw.pack import attr_auto
from pkcs11_check.raw.types_std import (
    CKA_ALLOWED_MECHANISMS,
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_ENCRYPT,
    CKA_LABEL,
    CKA_MODULUS_BITS,
    CKA_START_DATE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_WRAP_TEMPLATE,
)


def test_pack_template_keeps_pointer_and_length_separate() -> None:
    from pkcs11_check.raw.pack import LengthArg, attr_ulong

    attr = attr_ulong(0x00000161, 32, length=LengthArg.explicit_value(1))
    assert attr.attribute.ulValueLen == 1


def test_pack_nested_templates_are_supported() -> None:
    from pkcs11_check.raw.pack import attr_bool, attr_template, template

    inner = template(attr_bool(0x00000104, True))
    outer = template(attr_template(0x40000211, inner))
    assert outer.count == 1


def test_pack_retains_pointer_and_length_provenance_metadata() -> None:
    from pkcs11_check.raw.pack import LengthArg, attr_bytes

    attr = attr_bytes(0x00000011, b"abcd", length=LengthArg.explicit_value(2))

    assert attr.pointer_arg.kind == "bytes"
    assert attr.pointer_arg.origin == "attr_bytes"
    assert attr.pointer_arg.native_length == 4
    assert len(attr.storage) == 4
    assert attr.length_arg.explicit is True
    assert attr.length_arg.value == 2


def test_template_retains_packed_attributes_for_inspection() -> None:
    from pkcs11_check.raw.pack import attr_bool, attr_ulong, template

    value = template(attr_bool(0x00000104, True), attr_ulong(0x00000161, 32))

    assert len(value.attributes) == 2
    assert value.attributes[0].pointer_arg.kind == "scalar"


def test_pack_mech_bytes_native_length_matches_payload_length() -> None:
    from pkcs11_check.raw.pack import mech_bytes

    value = mech_bytes(0x80010099, b"abc")
    assert value.pointer_arg.native_length == 3
    assert len(value.storage) == 3


def test_mech_gcm_packs_iv_and_aad_len_and_tag_bits() -> None:
    from pkcs11_check.raw.pack import mech_gcm
    from pkcs11_check.raw.types_std import CK_AES_GCM_PARAMS, CKM_AES_GCM

    iv = b"\x00" * 12
    mech = mech_gcm(CKM_AES_GCM, iv, aad_len=0, tag_bits=128)

    assert mech.ck.mechanism == CKM_AES_GCM
    params = mech.params
    assert isinstance(params, CK_AES_GCM_PARAMS)
    assert params.ulIvLen == 12
    assert params.ulIvBits == 96
    assert params.ulAADLen == 0
    assert params.ulTagBits == 128


def test_mech_pss_packs_hash_mgf_salt() -> None:
    from pkcs11_check.raw.pack import mech_pss
    from pkcs11_check.raw.types_std import (
        CK_RSA_PKCS_PSS_PARAMS,
        CKG_MGF1_SHA256,
        CKM_SHA256,
        CKM_SHA256_RSA_PKCS_PSS,
    )

    mech = mech_pss(CKM_SHA256_RSA_PKCS_PSS, hash_mech=CKM_SHA256, mgf=CKG_MGF1_SHA256, salt_len=32)

    assert mech.ck.mechanism == CKM_SHA256_RSA_PKCS_PSS
    params = mech.params
    assert isinstance(params, CK_RSA_PKCS_PSS_PARAMS)
    assert params.hashAlg == CKM_SHA256
    assert params.mgf == CKG_MGF1_SHA256
    assert params.sLen == 32


def test_mech_oaep_packs_hash_mgf_source() -> None:
    from pkcs11_check.raw.pack import mech_oaep
    from pkcs11_check.raw.types_std import (
        CK_RSA_PKCS_OAEP_PARAMS,
        CKG_MGF1_SHA256,
        CKM_RSA_PKCS_OAEP,
        CKM_SHA256,
        CKZ_DATA_SPECIFIED,
    )

    mech = mech_oaep(CKM_RSA_PKCS_OAEP, hash_mech=CKM_SHA256, mgf=CKG_MGF1_SHA256)

    assert mech.ck.mechanism == CKM_RSA_PKCS_OAEP
    params = mech.params
    assert isinstance(params, CK_RSA_PKCS_OAEP_PARAMS)
    assert params.hashAlg == CKM_SHA256
    assert params.mgf == CKG_MGF1_SHA256
    assert params.source == CKZ_DATA_SPECIFIED
    assert params.pSourceData is None
    assert params.ulSourceDataLen == 0


def test_mech_oaep_with_source_data() -> None:
    from pkcs11_check.raw.pack import mech_oaep
    from pkcs11_check.raw.types_std import CKG_MGF1_SHA1, CKM_RSA_PKCS_OAEP, CKM_SHA_1

    label = b"test-label"
    mech = mech_oaep(CKM_RSA_PKCS_OAEP, hash_mech=CKM_SHA_1, mgf=CKG_MGF1_SHA1, source_data=label)

    params = mech.params
    assert params.ulSourceDataLen == 10
    assert params.pSourceData is not None


def test_mech_ecdh_packs_kdf_and_public_data() -> None:
    from pkcs11_check.raw.pack import mech_ecdh
    from pkcs11_check.raw.types_std import CK_ECDH1_DERIVE_PARAMS, CKD_NULL, CKM_ECDH1_DERIVE

    pub = b"\x04" + b"\x01" * 64
    mech = mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=pub)

    assert mech.ck.mechanism == CKM_ECDH1_DERIVE
    params = mech.params
    assert isinstance(params, CK_ECDH1_DERIVE_PARAMS)
    assert params.kdf == CKD_NULL
    assert params.ulPublicDataLen == 65
    assert params.ulSharedDataLen == 0
    assert params.pSharedData is None


def test_mech_hkdf_packs_extract_expand_and_hash() -> None:
    from pkcs11_check.raw.pack import mech_hkdf
    from pkcs11_check.raw.types_std import (
        CK_HKDF_PARAMS,
        CKF_HKDF_SALT_NULL,
        CKM_HKDF_DERIVE,
        CKM_SHA256,
    )

    info = b"context-info"
    mech = mech_hkdf(
        CKM_HKDF_DERIVE,
        hash_mech=CKM_SHA256,
        extract=True,
        expand=True,
        salt_type=CKF_HKDF_SALT_NULL,
        info=info,
    )

    assert mech.ck.mechanism == CKM_HKDF_DERIVE
    params = mech.params
    assert isinstance(params, CK_HKDF_PARAMS)
    assert params.bExtract == 1
    assert params.bExpand == 1
    assert params.prfHashMechanism == CKM_SHA256
    assert params.ulSaltType == CKF_HKDF_SALT_NULL
    assert params.ulInfoLen == 12


def test_mech_cbc_pad_sets_mechanism_and_iv_length() -> None:
    from pkcs11_check.raw.pack import mech_cbc_pad
    from pkcs11_check.raw.types_std import CKM_AES_CBC_PAD

    iv = b"\x01" * 16
    m = mech_cbc_pad(CKM_AES_CBC_PAD, iv)

    assert m.ck.mechanism == CKM_AES_CBC_PAD
    assert m.length_arg.value == 16
    assert m.params is None  # mech_bytes path, no struct


def test_mech_cbc_pad_aes_cbc_variant() -> None:
    from pkcs11_check.raw.pack import mech_cbc_pad
    from pkcs11_check.raw.types_std import CKM_AES_CBC

    m = mech_cbc_pad(CKM_AES_CBC, b"\x00" * 16)
    assert m.ck.mechanism == CKM_AES_CBC
    assert m.length_arg.value == 16


def test_mech_ctr_sets_counter_bits_and_zeroed_block() -> None:
    from pkcs11_check.raw.pack import mech_ctr
    from pkcs11_check.raw.types_std import CK_AES_CTR_PARAMS, CKM_AES_CTR

    m = mech_ctr(CKM_AES_CTR, bits=64)

    assert m.ck.mechanism == CKM_AES_CTR
    params = m.params
    assert isinstance(params, CK_AES_CTR_PARAMS)
    assert params.ulCounterBits == 64
    assert all(params.cb[i] == 0 for i in range(16))


def test_mech_ctr_default_bits() -> None:
    from pkcs11_check.raw.pack import mech_ctr
    from pkcs11_check.raw.types_std import CK_AES_CTR_PARAMS, CKM_AES_CTR

    m = mech_ctr(CKM_AES_CTR)
    assert isinstance(m.params, CK_AES_CTR_PARAMS)
    assert m.params.ulCounterBits == 128


def test_mech_chacha20_sets_nonce_bits_and_counter() -> None:
    from pkcs11_check.raw.pack import mech_chacha20
    from pkcs11_check.raw.types_std import CK_CHACHA20_PARAMS, CKM_CHACHA20

    nonce = b"\xab" * 12
    m = mech_chacha20(CKM_CHACHA20, nonce, counter=1)

    assert m.ck.mechanism == CKM_CHACHA20
    params = m.params
    assert isinstance(params, CK_CHACHA20_PARAMS)
    assert params.ulNonceBits == 96
    assert params.blockCounterBits == 32
    assert params.pNonce is not None
    assert params.pBlockCounter is not None


def test_mech_chacha20_default_counter() -> None:
    from pkcs11_check.raw.pack import mech_chacha20
    from pkcs11_check.raw.types_std import CKM_CHACHA20

    m = mech_chacha20(CKM_CHACHA20, b"\x00" * 12)
    assert m.params.blockCounterBits == 32
    assert m.params.pBlockCounter is not None


def test_mech_chacha20_poly1305_sets_nonce_and_no_aad() -> None:
    from pkcs11_check.raw.pack import mech_chacha20_poly1305
    from pkcs11_check.raw.types_std import (
        CK_SALSA20_CHACHA20_POLY1305_PARAMS,
        CKM_CHACHA20_POLY1305,
    )

    nonce = b"\x11" * 12
    m = mech_chacha20_poly1305(CKM_CHACHA20_POLY1305, nonce)

    assert m.ck.mechanism == CKM_CHACHA20_POLY1305
    params = m.params
    assert isinstance(params, CK_SALSA20_CHACHA20_POLY1305_PARAMS)
    assert params.ulNonceLen == 12
    assert params.pNonce is not None
    assert params.ulAADLen == 0
    assert params.pAAD is None


def test_mech_chacha20_poly1305_with_aad() -> None:
    from pkcs11_check.raw.pack import mech_chacha20_poly1305
    from pkcs11_check.raw.types_std import CKM_CHACHA20_POLY1305

    aad = b"additional"
    m = mech_chacha20_poly1305(CKM_CHACHA20_POLY1305, b"\x00" * 12, aad=aad)
    assert m.params.ulAADLen == 10
    assert m.params.pAAD is not None


def test_mech_eddsa_no_context_data() -> None:
    from pkcs11_check.raw.pack import mech_eddsa
    from pkcs11_check.raw.types_std import CK_EDDSA_PARAMS, CKM_EDDSA

    m = mech_eddsa(CKM_EDDSA)

    assert m.ck.mechanism == CKM_EDDSA
    params = m.params
    assert isinstance(params, CK_EDDSA_PARAMS)
    assert params.phFlag == 0
    assert params.ulContextDataLen == 0
    assert params.pContextData is None


def test_mech_eddsa_with_context_data() -> None:
    from pkcs11_check.raw.pack import mech_eddsa
    from pkcs11_check.raw.types_std import CK_EDDSA_PARAMS, CKM_EDDSA

    ctx = b"test-context"
    m = mech_eddsa(CKM_EDDSA, context_data=ctx)

    params = m.params
    assert isinstance(params, CK_EDDSA_PARAMS)
    assert params.phFlag == 1
    assert params.ulContextDataLen == 12
    assert params.pContextData is not None


def test_mech_pbkdf2_sets_salt_iterations_prf() -> None:
    from pkcs11_check.raw.pack import mech_pbkdf2
    from pkcs11_check.raw.types_std import CK_PKCS5_PBKD2_PARAMS2, CKM_PKCS5_PBKD2

    salt = b"saltsalt"
    m = mech_pbkdf2(CKM_PKCS5_PBKD2, salt=salt, iterations=1000, prf=0x00000002)

    assert m.ck.mechanism == CKM_PKCS5_PBKD2
    params = m.params
    assert isinstance(params, CK_PKCS5_PBKD2_PARAMS2)
    assert params.saltSource == 1  # CKZ_SALT_SPECIFIED
    assert params.ulSaltSourceDataLen == 8
    assert params.pSaltSourceData is not None
    assert params.iterations == 1000
    assert params.prf == 0x00000002
    assert params.ulPasswordLen == 0
    assert params.pPassword is None


def test_mech_pbkdf2_with_password() -> None:
    from pkcs11_check.raw.pack import mech_pbkdf2
    from pkcs11_check.raw.types_std import CKM_PKCS5_PBKD2

    m = mech_pbkdf2(CKM_PKCS5_PBKD2, salt=b"s", iterations=1, prf=1, password=b"secret")
    assert m.params.ulPasswordLen == 6
    assert m.params.pPassword is not None


def test_mech_string_data_sets_pointer_and_length() -> None:
    from pkcs11_check.raw.pack import mech_string_data
    from pkcs11_check.raw.types_std import (
        CK_KEY_DERIVATION_STRING_DATA,
        CKM_CONCATENATE_BASE_AND_KEY,
    )

    data = b"derivation-label"
    m = mech_string_data(CKM_CONCATENATE_BASE_AND_KEY, data)

    assert m.ck.mechanism == CKM_CONCATENATE_BASE_AND_KEY
    params = m.params
    assert isinstance(params, CK_KEY_DERIVATION_STRING_DATA)
    assert params.ulLen == 16
    assert params.pData is not None


class TestAttrAutoBool:
    """attr_auto with 'bool' type attributes."""

    def test_bool_true(self) -> None:
        pa = attr_auto(int(CKA_TOKEN), True)
        assert pa.storage.value == 1

    def test_bool_false(self) -> None:
        pa = attr_auto(int(CKA_TOKEN), False)
        assert pa.storage.value == 0

    def test_bool_from_int_1(self) -> None:
        """int 1 coerced to True for bool attrs."""
        pa = attr_auto(int(CKA_ENCRYPT), 1)
        assert pa.storage.value == 1

    def test_bool_from_int_0(self) -> None:
        """int 0 coerced to False for bool attrs."""
        pa = attr_auto(int(CKA_ENCRYPT), 0)
        assert pa.storage.value == 0


class TestAttrAutoUlong:
    """attr_auto with 'ulong' type attributes."""

    TEST_CLASS_VALUE = 3

    def test_ulong_int(self) -> None:
        pa = attr_auto(int(CKA_CLASS), self.TEST_CLASS_VALUE)
        # CK_ULONG is platform-sized, just verify it roundtrips
        assert pa.storage.value == self.TEST_CLASS_VALUE

    def test_ulong_from_bool(self) -> None:
        """bool True coerced to int 1 for ulong attrs."""
        pa = attr_auto(int(CKA_MODULUS_BITS), True)
        assert pa.storage.value == 1


class TestAttrAutoStr:
    """attr_auto with 'str' type attributes."""

    TEST_STR_HELLO = "hello"
    TEST_STR_LABEL = b"raw-label"
    TEST_STR_CAFE = "café"

    def test_str_from_str(self) -> None:
        pa = attr_auto(int(CKA_LABEL), self.TEST_STR_HELLO)
        assert bytes(pa.storage[: len(self.TEST_STR_HELLO)]) == self.TEST_STR_HELLO.encode()

    def test_str_from_bytes(self) -> None:
        """bytes passed to str attr stay as bytes (no double-encoding)."""
        pa = attr_auto(int(CKA_LABEL), self.TEST_STR_LABEL)
        assert bytes(pa.storage[: len(self.TEST_STR_LABEL)]) == self.TEST_STR_LABEL

    def test_str_utf8(self) -> None:
        pa = attr_auto(int(CKA_LABEL), self.TEST_STR_CAFE)
        expected = self.TEST_STR_CAFE.encode("utf-8")
        assert bytes(pa.storage[: len(expected)]) == expected


class TestAttrAutoBytes:
    """attr_auto with 'bytes' type attributes."""

    TEST_BYTES_DATA = b"\x01\x02\x03"
    TEST_BYTES_EC_PARAMS = b"\x06\x05"
    TEST_BYTES_INT = 42
    TEST_BYTES_STR = "hello"

    def test_bytes_from_bytes(self) -> None:
        pa = attr_auto(int(CKA_VALUE), self.TEST_BYTES_DATA)
        assert bytes(pa.storage[: len(self.TEST_BYTES_DATA)]) == self.TEST_BYTES_DATA

    def test_bytes_from_bytearray(self) -> None:
        pa = attr_auto(int(CKA_EC_PARAMS), bytearray(self.TEST_BYTES_EC_PARAMS))
        assert bytes(pa.storage[: len(self.TEST_BYTES_EC_PARAMS)]) == self.TEST_BYTES_EC_PARAMS

    def test_bytes_rejects_int(self) -> None:
        with pytest.raises(TypeError, match="bytes.*expects bytes"):
            attr_auto(int(CKA_VALUE), self.TEST_BYTES_INT)

    def test_bytes_from_str_encodes_utf8(self) -> None:
        """str is accepted for 'bytes' attrs via UTF-8 encoding."""
        pa = attr_auto(int(CKA_VALUE), self.TEST_BYTES_STR)
        expected = self.TEST_BYTES_STR.encode()
        assert bytes(pa.storage[: len(expected)]) == expected


class TestAttrAutoDate:
    """attr_auto with 'date' type attributes."""

    TEST_DATE_STR = "20260325"
    TEST_DATE_BYTES = TEST_DATE_STR.encode()
    TEST_DATE_INT = 20260325

    def test_date_from_datetime(self) -> None:
        d = datetime.date(2026, 3, 25)
        pa = attr_auto(int(CKA_START_DATE), d)
        assert bytes(pa.storage[: len(self.TEST_DATE_BYTES)]) == self.TEST_DATE_BYTES

    def test_date_from_str(self) -> None:
        pa = attr_auto(int(CKA_START_DATE), self.TEST_DATE_STR)
        assert bytes(pa.storage[: len(self.TEST_DATE_BYTES)]) == self.TEST_DATE_BYTES

    def test_date_from_bytes(self) -> None:
        pa = attr_auto(int(CKA_START_DATE), self.TEST_DATE_BYTES)
        assert bytes(pa.storage[: len(self.TEST_DATE_BYTES)]) == self.TEST_DATE_BYTES

    def test_date_rejects_bad_str(self) -> None:
        with pytest.raises(ValueError, match="YYYYMMDD"):
            attr_auto(int(CKA_START_DATE), "not-a-date")

    def test_date_rejects_int(self) -> None:
        with pytest.raises(TypeError, match="date"):
            attr_auto(int(CKA_START_DATE), self.TEST_DATE_INT)


class TestAttrAutoUlongArray:
    """attr_auto with 'ulong_array' type attributes."""

    CKM_SHA256_HMAC = 0x00000250
    CKM_AES_CBC = 0x00001082
    TEST_ULONG_INT = 42

    def test_ulong_array_list(self) -> None:
        mechs = [self.CKM_SHA256_HMAC, self.CKM_AES_CBC]
        pa = attr_auto(int(CKA_ALLOWED_MECHANISMS), mechs)
        ulong_size = ctypes.sizeof(ctypes.c_ulong)
        assert len(bytes(pa.storage)) == len(mechs) * ulong_size
        v0 = int.from_bytes(bytes(pa.storage[:ulong_size]), byteorder=sys.byteorder)
        v1 = int.from_bytes(bytes(pa.storage[ulong_size : 2 * ulong_size]), byteorder=sys.byteorder)
        assert v0 == self.CKM_SHA256_HMAC
        assert v1 == self.CKM_AES_CBC

    def test_ulong_array_empty(self) -> None:
        pa = attr_auto(int(CKA_ALLOWED_MECHANISMS), [])
        assert len(bytes(pa.storage)) == 0

    def test_ulong_array_rejects_int(self) -> None:
        with pytest.raises(TypeError, match="ulong_array.*list"):
            attr_auto(int(CKA_ALLOWED_MECHANISMS), self.TEST_ULONG_INT)


class TestAttrAutoTemplate:
    """attr_auto with 'template' type attributes."""

    TEST_TEMPLATE_BYTES = b"\x00"

    def test_template_raises(self) -> None:
        with pytest.raises(TypeError, match="template.*cannot be auto-packed"):
            attr_auto(int(CKA_WRAP_TEMPLATE), self.TEST_TEMPLATE_BYTES)


class TestAttrAutoUnknown:
    """attr_auto with unknown (vendor) attributes."""

    VENDOR_ATTR = 0x80000001
    TEST_BOOL_TRUE = 1
    TEST_INT = 42
    TEST_BYTES = b"\xab\xcd"
    TEST_LIST = [1, 2, 3]

    def test_unknown_bool(self) -> None:
        """Unknown attr with bool value uses Python type inference."""
        pa = attr_auto(self.VENDOR_ATTR, True)
        assert pa.storage.value == self.TEST_BOOL_TRUE

    def test_unknown_int(self) -> None:
        pa = attr_auto(self.VENDOR_ATTR, self.TEST_INT)
        assert pa.storage.value == self.TEST_INT

    def test_unknown_bytes(self) -> None:
        pa = attr_auto(self.VENDOR_ATTR, self.TEST_BYTES)
        assert bytes(pa.storage[: len(self.TEST_BYTES)]) == self.TEST_BYTES

    def test_unknown_rejects_unsupported_type(self) -> None:
        with pytest.raises(TypeError, match="cannot infer"):
            attr_auto(self.VENDOR_ATTR, self.TEST_LIST)


_STANDARD_RAW_MODULES = (
    "raw/types_std.py",
    "raw/metadata_std.py",
)

_REQUIRED_HEADERS = ("pkcs11.h",)  # Always required — single-file or multi-file
_OPTIONAL_HEADERS = ("pkcs11f.h", "pkcs11t.h")  # Only in OASIS 3-file format

_HEADERS_SOURCE_DIR = Path(__file__).resolve().parents[1] / "third_party/pkcs11-headers/3.2"


def _assert_standard_raw_pack_contents(
    archive_names: set[str], *, module_prefix: str, header_prefix: str
) -> None:
    for module in _STANDARD_RAW_MODULES:
        assert f"{module_prefix}/{module}" in archive_names
    for header in _REQUIRED_HEADERS:
        assert f"{header_prefix}/{header}" in archive_names
    for header in _OPTIONAL_HEADERS:
        if (_HEADERS_SOURCE_DIR / header).exists():
            assert f"{header_prefix}/{header}" in archive_names


@pytest.mark.timeout(300)
def test_sdist_and_wheel_include_vendored_standard_headers_and_generated_raw_modules(
    tmp_path: Path,
) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    dist_dir = tmp_path / "dist"

    result = subprocess.run(
        ["uv", "build", "--sdist", "--wheel", "--out-dir", str(dist_dir)],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr

    wheel_path = next(dist_dir.glob("*.whl"))
    with zipfile.ZipFile(wheel_path) as wheel:
        wheel_names = set(wheel.namelist())

    sdist_path = next(dist_dir.glob("*.tar.gz"))
    with tarfile.open(sdist_path, mode="r:gz") as sdist:
        sdist_names = {
            member.name.split("/", 1)[1]
            for member in sdist.getmembers()
            if member.isfile() and "/" in member.name
        }

    _assert_standard_raw_pack_contents(
        wheel_names,
        module_prefix="pkcs11_check",
        header_prefix="pkcs11_check/_vendor/pkcs11-headers/3.2",
    )
    _assert_standard_raw_pack_contents(
        sdist_names,
        module_prefix="src/pkcs11_check",
        header_prefix="third_party/pkcs11-headers/3.2",
    )
