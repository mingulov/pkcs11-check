from __future__ import annotations

import subprocess
import tarfile
import zipfile
from pathlib import Path


def test_pack_template_keeps_pointer_and_length_separate() -> None:
    from pkcs11_check.raw.pack import attr_ulong, explicit_length

    attr = attr_ulong(0x00000161, 32, length=explicit_length(1))
    assert attr.attribute.ulValueLen == 1


def test_pack_nested_templates_are_supported() -> None:
    from pkcs11_check.raw.pack import attr_bool, attr_template, template

    inner = template(attr_bool(0x00000104, True))
    outer = template(attr_template(0x40000211, inner))
    assert outer.count == 1


def test_pack_retains_pointer_and_length_provenance_metadata() -> None:
    from pkcs11_check.raw.pack import attr_bytes, explicit_length

    attr = attr_bytes(0x00000011, b"abcd", length=explicit_length(2))

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


_STANDARD_RAW_MODULES = (
    "raw/types_std.py",
    "raw/metadata_std.py",
)

_STANDARD_HEADERS = (
    "pkcs11.h",
    "pkcs11f.h",
    "pkcs11t.h",
)


def _assert_standard_raw_pack_contents(
    archive_names: set[str], *, module_prefix: str, header_prefix: str
) -> None:
    for module in _STANDARD_RAW_MODULES:
        assert f"{module_prefix}/{module}" in archive_names
    for header in _STANDARD_HEADERS:
        assert f"{header_prefix}/{header}" in archive_names


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
