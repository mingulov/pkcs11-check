"""Tests for mechanisms that lack dedicated roundtrip coverage.

Phase 4.1: High-priority mechanism roundtrip tests for:
- CKM_SHAKE_128 / CKM_SHAKE_256 -- XOF digest (requires C_DigestXof* functions)
- CKM_SHA512_224 / CKM_SHA512_256 -- Truncated SHA-512 variants
- CKM_AES_KEY_WRAP_KWP -- AES Key Wrap with Padding
- CKM_KMAC_128 / CKM_KMAC_256 -- Keccak MAC (v3.2)
- CKM_ML_DSA_EXTERNAL_MU -- External message update PQC sign
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from pkcs11_check.raw.pack import attr_ulong, mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    digest_single,
    gen_aes_key,
    gen_keypair,
    sign_single,
    to_ubyte_buf,
    verify_single,
    wrap_key,
)
from pkcs11_check.raw.rv import CkrAssertionError, expect_rv
from pkcs11_check.raw.types_std import (
    CK_BYTE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_PARAMETER_SET,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VERIFY,
    CKA_WRAP,
    CKK_AES,
    CKM,
    CKM_AES_KEY_WRAP_KWP,
    CKM_ML_DSA_EXTERNAL_MU,
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKM_SHA512_224,
    CKM_SHA512_256,
    CKO_SECRET_KEY,
    CKP_ML_DSA_65,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_DEVICE_MEMORY,
    CKR_DEVICE_REMOVED,
    CKR_FUNCTION_CANCELED,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_HOST_MEMORY,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_PENDING,
    CKR_SESSION_CLOSED,
    CKR_SESSION_HANDLE_INVALID,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases.conftest import (
    CIPHER_OP_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    unwrap_key_for_mechanism_roundtrip,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.full

_CKM_SHAKE_128 = CKM(0x00000418, "CKM_SHAKE_128")
_CKM_SHAKE_256 = CKM(0x00000419, "CKM_SHAKE_256")


@dataclass(frozen=True)
class _ShakeXofCase:
    name: str
    mechanism: CKM
    reference_factory: Callable[[bytes], Any]
    single_output_len: int
    extract_len: int
    final_len: int

    @property
    def mechanism_label(self) -> str:
        return f"CKM_{self.name}"

    def reference(self, data: bytes, output_len: int) -> bytes:
        return bytes(self.reference_factory(data).digest(output_len))


_SHAKE_XOF_CASES = (
    _ShakeXofCase("SHAKE_128", _CKM_SHAKE_128, hashlib.shake_128, 32, 13, 19),
    _ShakeXofCase("SHAKE_256", _CKM_SHAKE_256, hashlib.shake_256, 64, 23, 41),
)
_SHAKE_XOF_CASE_BY_NAME = {case.name: case for case in _SHAKE_XOF_CASES}

_XOF_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_DEVICE_MEMORY,
    CKR_DEVICE_REMOVED,
    CKR_FUNCTION_CANCELED,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_HOST_MEMORY,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_PENDING,
    CKR_SESSION_CLOSED,
    CKR_SESSION_HANDLE_INVALID,
    CKR_USER_NOT_LOGGED_IN,
)


def _require_xof_support(rs: Any, case: _ShakeXofCase, function_names: tuple[str, ...]) -> None:
    if not rs.has_mechanism(case.name):
        pytest.skip(f"{case.mechanism_label} not supported")
    for function_name in function_names:
        if not hasattr(rs.raw, function_name):
            pytest.skip(f"{function_name} not available in this raw binding")


def _expect_xof_ok(rv: int, case: _ShakeXofCase, operation: str) -> None:
    try:
        expect_rv(rv, CKR_OK, context=f"{case.mechanism_label} {operation}")
    except CkrAssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _XOF_RUNTIME_REJECT_RVS,
            f"{case.mechanism_label} {operation} not operational",
        )


def _shake_xof_single_shot_matches_reference(
    rs: Any,
    case: _ShakeXofCase,
    data: bytes,
    output_len: int,
) -> None:
    mech = mech_simple(case.mechanism)
    _expect_xof_ok(
        rs.raw.C_DigestXofInit(rs.sh, mech.byref()),
        case,
        "XOF init",
    )

    data_buf = to_ubyte_buf(data)
    output = (CK_BYTE * output_len)()
    _expect_xof_ok(
        rs.raw.C_DigestXof(rs.sh, data_buf, len(data), output, output_len),
        case,
        "XOF single-shot",
    )

    actual = bytes(output)
    expected = case.reference(data, output_len)
    assert actual == expected, f"{case.mechanism_label} XOF single-shot mismatch"


def _shake_xof_multipart_matches_reference(
    rs: Any,
    case: _ShakeXofCase,
    data_parts: tuple[bytes, ...],
    *,
    extract_len: int,
    final_len: int,
) -> None:
    mech = mech_simple(case.mechanism)
    _expect_xof_ok(
        rs.raw.C_DigestXofInit(rs.sh, mech.byref()),
        case,
        "XOF init",
    )

    for part in data_parts:
        part_buf = to_ubyte_buf(part)
        _expect_xof_ok(
            rs.raw.C_DigestXofUpdate(rs.sh, part_buf, len(part)),
            case,
            "XOF update",
        )

    extract_output = (CK_BYTE * extract_len)()
    _expect_xof_ok(
        rs.raw.C_DigestXofExtract(rs.sh, extract_output, extract_len),
        case,
        "XOF extract",
    )

    final_output = (CK_BYTE * final_len)()
    _expect_xof_ok(
        rs.raw.C_DigestXofFinal(rs.sh, final_output, final_len),
        case,
        "XOF final",
    )

    actual = bytes(extract_output) + bytes(final_output)
    expected = case.reference(b"".join(data_parts), extract_len + final_len)
    assert actual == expected, f"{case.mechanism_label} XOF multipart mismatch"


class TestSHAKEDigest:
    """CKM_SHAKE_128 and CKM_SHAKE_256 XOF digest via C_DigestXof functions.

    SHAKE is an extendable-output function. The tests verify both the
    single-shot path (C_DigestXof) and multipart absorb/squeeze path
    (C_DigestXofUpdate/C_DigestXofExtract/C_DigestXofFinal) against Python's
    hashlib SHAKE implementations.
    """

    @pytest.mark.needs_function("C_DigestXofInit")
    @pytest.mark.needs_function("C_DigestXof")
    @pytest.mark.parametrize("case", _SHAKE_XOF_CASES, ids=lambda case: case.name)
    def test_single_shot_matches_hashlib(
        self,
        p11_raw_session: Any,
        case: _ShakeXofCase,
    ) -> None:
        rs = p11_raw_session
        _require_xof_support(rs, case, ("C_DigestXofInit", "C_DigestXof"))

        _shake_xof_single_shot_matches_reference(
            rs,
            case,
            b"pkcs11-check SHAKE XOF single-shot KAT",
            case.single_output_len,
        )

    @pytest.mark.needs_function("C_DigestXofInit")
    @pytest.mark.needs_function("C_DigestXofUpdate")
    @pytest.mark.needs_function("C_DigestXofExtract")
    @pytest.mark.needs_function("C_DigestXofFinal")
    @pytest.mark.parametrize("case", _SHAKE_XOF_CASES, ids=lambda case: case.name)
    def test_multipart_matches_hashlib(
        self,
        p11_raw_session: Any,
        case: _ShakeXofCase,
    ) -> None:
        rs = p11_raw_session
        _require_xof_support(
            rs,
            case,
            (
                "C_DigestXofInit",
                "C_DigestXofUpdate",
                "C_DigestXofExtract",
                "C_DigestXofFinal",
            ),
        )

        _shake_xof_multipart_matches_reference(
            rs,
            case,
            (b"pkcs11-check ", b"SHAKE XOF ", b"multipart KAT"),
            extract_len=case.extract_len,
            final_len=case.final_len,
        )


class TestSHA512Truncated:
    """CKM_SHA512_224 and CKM_SHA512_256 truncated SHA-512 digests."""

    def test_sha512_224_cross_verify(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA512_224"):
            pytest.skip("CKM_SHA512_224 not supported")
        data = b"SHA-512/224 cross-verification test data"
        p11_digest = digest_single(rs.raw, rs.sh, CKM_SHA512_224, data)
        expected = hashlib.new("sha512_224", data).digest()
        assert p11_digest == expected

    def test_sha512_224_empty_data(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA512_224"):
            pytest.skip("CKM_SHA512_224 not supported")
        p11_digest = digest_single(rs.raw, rs.sh, CKM_SHA512_224, b"")
        expected = hashlib.new("sha512_224", b"").digest()
        assert p11_digest == expected
        assert len(p11_digest) == 28

    def test_sha512_256_cross_verify(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA512_256"):
            pytest.skip("CKM_SHA512_256 not supported")
        data = b"SHA-512/256 cross-verification test data"
        p11_digest = digest_single(rs.raw, rs.sh, CKM_SHA512_256, data)
        expected = hashlib.new("sha512_256", data).digest()
        assert p11_digest == expected

    def test_sha512_256_empty_data(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA512_256"):
            pytest.skip("CKM_SHA512_256 not supported")
        p11_digest = digest_single(rs.raw, rs.sh, CKM_SHA512_256, b"")
        expected = hashlib.new("sha512_256", b"").digest()
        assert p11_digest == expected
        assert len(p11_digest) == 32

    def test_sha512_224_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA512_224"):
            pytest.skip("CKM_SHA512_224 not supported")
        data = b"deterministic SHA-512/224 test"
        d1 = digest_single(rs.raw, rs.sh, CKM_SHA512_224, data)
        d2 = digest_single(rs.raw, rs.sh, CKM_SHA512_224, data)
        assert d1 == d2

    def test_sha512_256_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA512_256"):
            pytest.skip("CKM_SHA512_256 not supported")
        data = b"deterministic SHA-512/256 test"
        d1 = digest_single(rs.raw, rs.sh, CKM_SHA512_256, data)
        d2 = digest_single(rs.raw, rs.sh, CKM_SHA512_256, data)
        assert d1 == d2


class TestAESKeyWrapKWP:
    """CKM_AES_KEY_WRAP_KWP -- AES Key Wrap with Padding (NIST SP 800-38F)."""

    def test_wrap_unwrap_roundtrip(self, p11_raw_session: Any, p11_config: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP_KWP"):
            pytest.skip("CKM_AES_KEY_WRAP_KWP not supported")

        wrapping_key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
            },
        )

        target_key = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False},
        )
        unwrapped_h = 0
        try:
            wrapped = wrap_key(
                rs.raw,
                rs.sh,
                wrapping_key,
                target_key,
                CKM_AES_KEY_WRAP_KWP,
                output_size_hint=64,  # KWP overhead: 8-byte ICV + up to 15 bytes padding
            )
            assert len(wrapped) > 0, "wrap_key returned empty output"

            unwrapped_h = unwrap_key_for_mechanism_roundtrip(
                rs,
                p11_config,
                unwrapping_key=wrapping_key,
                wrapped_key=wrapped,
                mechanism=CKM_AES_KEY_WRAP_KWP,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                    CKA_TOKEN: False,
                    CKA_ENCRYPT: True,
                },
                purpose="AES-KWP wrap/unwrap roundtrip",
            )
        finally:
            if unwrapped_h:
                destroy_quietly(rs.raw, rs.sh, unwrapped_h)
            destroy_quietly(rs.raw, rs.sh, target_key)
            destroy_quietly(rs.raw, rs.sh, wrapping_key)

    def test_wrap_unwrap_256bit_key(self, p11_raw_session: Any, p11_config: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP_KWP"):
            pytest.skip("CKM_AES_KEY_WRAP_KWP not supported")

        wrapping_key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_TOKEN: False,
            },
        )

        target_key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False},
        )
        unwrapped_h = 0
        try:
            wrapped = wrap_key(
                rs.raw,
                rs.sh,
                wrapping_key,
                target_key,
                CKM_AES_KEY_WRAP_KWP,
                output_size_hint=64,  # KWP overhead: 8-byte ICV + up to 15 bytes padding
            )
            assert len(wrapped) > 0

            unwrapped_h = unwrap_key_for_mechanism_roundtrip(
                rs,
                p11_config,
                unwrapping_key=wrapping_key,
                wrapped_key=wrapped,
                mechanism=CKM_AES_KEY_WRAP_KWP,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                    CKA_TOKEN: False,
                },
                purpose="AES-KWP 256-bit wrap/unwrap roundtrip",
            )
        finally:
            if unwrapped_h:
                destroy_quietly(rs.raw, rs.sh, unwrapped_h)
            destroy_quietly(rs.raw, rs.sh, target_key)
            destroy_quietly(rs.raw, rs.sh, wrapping_key)


class TestKMAC:
    """CKM_KMAC_128 / CKM_KMAC_256 -- Keccak MAC (v3.2, NIST SP 800-185).

    KMAC mechanisms require CK_KMAC_PARAMS with a key handle, output length,
    and optional customization string. These are XOF-capable: output can be
    any length when ulMacLength is 0.

    Most current modules do not yet support KMAC. Tests skip cleanly.
    """

    def test_kmac_128_availability(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KMAC_128"):
            pytest.skip("CKM_KMAC_128 not supported")

    def test_kmac_256_availability(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KMAC_256"):
            pytest.skip("CKM_KMAC_256 not supported")

    def test_kmac_128_sign_roundtrip(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KMAC_128"):
            pytest.skip("CKM_KMAC_128 not supported")
        pytest.skip(
            "CKM_KMAC_128 requires CK_KMAC_PARAMS mechanism parameter "
            "not yet available in pkcs11_check.raw bindings"
        )

    def test_kmac_256_sign_roundtrip(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KMAC_256"):
            pytest.skip("CKM_KMAC_256 not supported")
        pytest.skip(
            "CKM_KMAC_256 requires CK_KMAC_PARAMS mechanism parameter "
            "not yet available in pkcs11_check.raw bindings"
        )


_EXTERNAL_MU_SAMPLE = bytes(range(64))


def _generate_external_mu_mldsa_keypair(rs: Any) -> tuple[int, int]:
    return gen_keypair(
        rs.raw,
        rs.sh,
        mechanism=int(CKM_ML_DSA_KEY_PAIR_GEN),
        pub_base=[attr_ulong(CKA_PARAMETER_SET, CKP_ML_DSA_65)],
        priv_base=[],
        public_attrs={
            CKA_VERIFY: True,
            CKA_TOKEN: False,
        },
        private_attrs={
            CKA_SIGN: True,
            CKA_TOKEN: False,
        },
        pub_skip={CKA_PARAMETER_SET},
    )


def _external_mu_sign_verify_roundtrip(rs: Any) -> None:
    pub_key = 0
    priv_key = 0
    try:
        try:
            pub_key, priv_key = _generate_external_mu_mldsa_keypair(rs)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                KEYPAIR_RUNTIME_REJECT_RVS,
                "CKM_ML_DSA_KEY_PAIR_GEN for ExternalMu not operational",
            )

        try:
            signature = sign_single(
                rs.raw,
                rs.sh,
                priv_key,
                int(CKM_ML_DSA_EXTERNAL_MU),
                _EXTERNAL_MU_SAMPLE,
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                CIPHER_OP_RUNTIME_REJECT_RVS,
                "CKM_ML_DSA_EXTERNAL_MU sign not operational",
            )

        assert len(signature) > 0, "CKM_ML_DSA_EXTERNAL_MU returned an empty signature"
        verified = verify_single(
            rs.raw,
            rs.sh,
            pub_key,
            int(CKM_ML_DSA_EXTERNAL_MU),
            _EXTERNAL_MU_SAMPLE,
            signature,
        )
        assert verified is True, "CKM_ML_DSA_EXTERNAL_MU verify rejected a fresh signature"

        tampered_mu = _EXTERNAL_MU_SAMPLE[:-1] + bytes([_EXTERNAL_MU_SAMPLE[-1] ^ 0x01])
        try:
            tampered_verified = verify_single(
                rs.raw,
                rs.sh,
                pub_key,
                int(CKM_ML_DSA_EXTERNAL_MU),
                tampered_mu,
                signature,
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                CIPHER_OP_RUNTIME_REJECT_RVS,
                "tampered CKM_ML_DSA_EXTERNAL_MU rejected with non-spec CKR",
            )
        else:
            assert not tampered_verified, "CKM_ML_DSA_EXTERNAL_MU verified a tampered mu"
    finally:
        if pub_key:
            destroy_quietly(rs.raw, rs.sh, pub_key)
        if priv_key:
            destroy_quietly(rs.raw, rs.sh, priv_key)


class TestMLDSAExternalMU:
    """CKM_ML_DSA_EXTERNAL_MU -- ExternalMu PQC sign/verify (v3.2 draft).

    ExternalMu-ML-DSA accepts a precomputed 64-byte message representative mu
    instead of hashing the message on-token. The mu value is normally computed
    by FIPS 204 algorithms 7/8 and supplied directly to single-part sign/verify.
    """

    def test_external_mu_availability(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("ML_DSA_EXTERNAL_MU"):
            pytest.skip("CKM_ML_DSA_EXTERNAL_MU not supported")

    def test_external_mu_sign_verify_with_dummy_mu(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("ML_DSA_EXTERNAL_MU"):
            pytest.skip("CKM_ML_DSA_EXTERNAL_MU not supported")
        if not rs.has_mechanism("ML_DSA_KEY_PAIR_GEN"):
            pytest.skip("CKM_ML_DSA_KEY_PAIR_GEN not supported for EXTERNAL_MU test")

        _external_mu_sign_verify_roundtrip(rs)
