"""BLAKE2B digest tests - BLAKE2B-160/256/384/512.

Tests PKCS#11 v3.0 BLAKE2B digest mechanisms (unkeyed variant).
Cross-verifies against Python hashlib.blake2b with matching digest_size.

PKCS#11 reference: v3.0 Sec.2.42 (BLAKE2b Message Digesting).
"""

from __future__ import annotations

import hashlib
import hmac
from ctypes import byref, sizeof, string_at
from typing import Any, NamedTuple, NoReturn

import pytest

from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_bytes, mech_simple, template
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    digest_single,
    import_secret_key,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKK_AES,
    CKK_BLAKE2B_160_HMAC,
    CKK_BLAKE2B_256_HMAC,
    CKK_BLAKE2B_384_HMAC,
    CKK_BLAKE2B_512_HMAC,
    CKK_GENERIC_SECRET,
    CKM_BLAKE2B_160,
    CKM_BLAKE2B_160_HMAC,
    CKM_BLAKE2B_160_HMAC_GENERAL,
    CKM_BLAKE2B_160_KEY_DERIVE,
    CKM_BLAKE2B_160_KEY_GEN,
    CKM_BLAKE2B_256,
    CKM_BLAKE2B_256_HMAC,
    CKM_BLAKE2B_256_HMAC_GENERAL,
    CKM_BLAKE2B_256_KEY_DERIVE,
    CKM_BLAKE2B_256_KEY_GEN,
    CKM_BLAKE2B_384,
    CKM_BLAKE2B_384_HMAC,
    CKM_BLAKE2B_384_HMAC_GENERAL,
    CKM_BLAKE2B_384_KEY_DERIVE,
    CKM_BLAKE2B_384_KEY_GEN,
    CKM_BLAKE2B_512,
    CKM_BLAKE2B_512_HMAC,
    CKM_BLAKE2B_512_HMAC_GENERAL,
    CKM_BLAKE2B_512_KEY_DERIVE,
    CKM_BLAKE2B_512_KEY_GEN,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import reject_or_classify, xfail_if_known_ckr

pytestmark = pytest.mark.full

_BLAKE2_MECHS = {
    "BLAKE2B_160": (CKM_BLAKE2B_160, 20),
    "BLAKE2B_256": (CKM_BLAKE2B_256, 32),
    "BLAKE2B_384": (CKM_BLAKE2B_384, 48),
    "BLAKE2B_512": (CKM_BLAKE2B_512, 64),
}

_EMPTY_DIGEST_REJECT_RVS = (CKR_ARGUMENTS_BAD,)

_BLAKE2B_TEST_KEY = b"pkcs11-check blake2b hmac key"
_BLAKE2B_TEST_DATA = b"pkcs11-check blake2b keyed data"

_BLAKE2B_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)


class _Blake2bKeyedCase(NamedTuple):
    bits: int
    digest_len: int
    hmac_name: str
    hmac_mech: Any
    hmac_general_name: str
    hmac_general_mech: Any
    key_gen_name: str
    key_gen_mech: Any
    key_derive_name: str
    key_derive_mech: Any
    key_type: Any
    id: str


_BLAKE2B_KEYED_CASES: tuple[_Blake2bKeyedCase, ...] = (
    _Blake2bKeyedCase(
        bits=160,
        digest_len=20,
        hmac_name="BLAKE2B_160_HMAC",
        hmac_mech=CKM_BLAKE2B_160_HMAC,
        hmac_general_name="BLAKE2B_160_HMAC_GENERAL",
        hmac_general_mech=CKM_BLAKE2B_160_HMAC_GENERAL,
        key_gen_name="BLAKE2B_160_KEY_GEN",
        key_gen_mech=CKM_BLAKE2B_160_KEY_GEN,
        key_derive_name="BLAKE2B_160_KEY_DERIVE",
        key_derive_mech=CKM_BLAKE2B_160_KEY_DERIVE,
        key_type=CKK_BLAKE2B_160_HMAC,
        id="BLAKE2B-160",
    ),
    _Blake2bKeyedCase(
        bits=256,
        digest_len=32,
        hmac_name="BLAKE2B_256_HMAC",
        hmac_mech=CKM_BLAKE2B_256_HMAC,
        hmac_general_name="BLAKE2B_256_HMAC_GENERAL",
        hmac_general_mech=CKM_BLAKE2B_256_HMAC_GENERAL,
        key_gen_name="BLAKE2B_256_KEY_GEN",
        key_gen_mech=CKM_BLAKE2B_256_KEY_GEN,
        key_derive_name="BLAKE2B_256_KEY_DERIVE",
        key_derive_mech=CKM_BLAKE2B_256_KEY_DERIVE,
        key_type=CKK_BLAKE2B_256_HMAC,
        id="BLAKE2B-256",
    ),
    _Blake2bKeyedCase(
        bits=384,
        digest_len=48,
        hmac_name="BLAKE2B_384_HMAC",
        hmac_mech=CKM_BLAKE2B_384_HMAC,
        hmac_general_name="BLAKE2B_384_HMAC_GENERAL",
        hmac_general_mech=CKM_BLAKE2B_384_HMAC_GENERAL,
        key_gen_name="BLAKE2B_384_KEY_GEN",
        key_gen_mech=CKM_BLAKE2B_384_KEY_GEN,
        key_derive_name="BLAKE2B_384_KEY_DERIVE",
        key_derive_mech=CKM_BLAKE2B_384_KEY_DERIVE,
        key_type=CKK_BLAKE2B_384_HMAC,
        id="BLAKE2B-384",
    ),
    _Blake2bKeyedCase(
        bits=512,
        digest_len=64,
        hmac_name="BLAKE2B_512_HMAC",
        hmac_mech=CKM_BLAKE2B_512_HMAC,
        hmac_general_name="BLAKE2B_512_HMAC_GENERAL",
        hmac_general_mech=CKM_BLAKE2B_512_HMAC_GENERAL,
        key_gen_name="BLAKE2B_512_KEY_GEN",
        key_gen_mech=CKM_BLAKE2B_512_KEY_GEN,
        key_derive_name="BLAKE2B_512_KEY_DERIVE",
        key_derive_mech=CKM_BLAKE2B_512_KEY_DERIVE,
        key_type=CKK_BLAKE2B_512_HMAC,
        id="BLAKE2B-512",
    ),
)

_BLAKE2B_KEYED_CASE_BY_BITS = {case.bits: case for case in _BLAKE2B_KEYED_CASES}


def _digest_empty_or_xfail(raw: Any, sh: int, mechanism: Any, mech_name: str) -> bytes:
    try:
        return digest_single(raw, sh, mechanism, b"")
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _EMPTY_DIGEST_REJECT_RVS, f"CKM_{mech_name} empty digest")
        raise


def _blake2b_hmac_reference(key: bytes, data: bytes, digest_size: int) -> bytes:
    def _digest(payload: bytes = b"") -> Any:
        return hashlib.blake2b(payload, digest_size=digest_size)

    return hmac.new(key, data, _digest).digest()


def _xfail_blake2b_reject(exc: AssertionError, label: str) -> NoReturn:
    xfail_if_known_ckr(exc, _BLAKE2B_RUNTIME_REJECT_RVS, label)
    raise


def _ck_ulong_param(value: int) -> bytes:
    storage = CK_ULONG(value)
    return string_at(byref(storage), sizeof(storage))


def _import_blake2b_setup_key(
    rs: Any,
    key_value: bytes = _BLAKE2B_TEST_KEY,
    *,
    sign: bool = False,
    verify: bool = False,
    derive: bool = False,
) -> int:
    attrs = {
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_SIGN: sign,
        CKA_VERIFY: verify,
        CKA_DERIVE: derive,
    }
    try:
        return import_secret_key(rs.raw, rs.sh, CKK_GENERIC_SECRET, key_value, attrs)
    except AssertionError as e:
        _xfail_blake2b_reject(e, "BLAKE2B setup generic-secret import rejected")


def _generate_blake2b_hmac_key(rs: Any, case: _Blake2bKeyedCase) -> int:
    tmpl = template(
        attr_ulong(CKA_VALUE_LEN, case.digest_len),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_SENSITIVE, False),
        attr_bool(CKA_EXTRACTABLE, True),
        attr_bool(CKA_SIGN, True),
        attr_bool(CKA_VERIFY, True),
    )
    handle = CK_OBJECT_HANDLE(0)
    mech = mech_simple(case.key_gen_mech)
    rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
    try:
        expect_rv(rv, CKR_OK)
    except AssertionError as e:
        _xfail_blake2b_reject(e, f"{case.key_gen_name} advertised but keygen failed")
    return handle.value


class TestBlake2bDigestLength:
    """Verify correct output lengths for all BLAKE2B digest mechanisms."""

    @pytest.mark.parametrize(
        "mech_name_str,mechanism,expected_len",
        [
            ("BLAKE2B_160", CKM_BLAKE2B_160, 20),
            ("BLAKE2B_256", CKM_BLAKE2B_256, 32),
            ("BLAKE2B_384", CKM_BLAKE2B_384, 48),
            ("BLAKE2B_512", CKM_BLAKE2B_512, 64),
        ],
        ids=["BLAKE2B-160", "BLAKE2B-256", "BLAKE2B-384", "BLAKE2B-512"],
    )
    def test_digest_length(
        self,
        p11_raw_session: Any,
        mech_name_str: str,
        mechanism: Any,
        expected_len: int,
    ) -> None:
        """Each BLAKE2B mechanism produces the correct output length."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")
        digest = digest_single(rs.raw, rs.sh, mechanism, b"test data")
        assert len(digest) == expected_len


class TestBlake2bCrossVerify:
    """Cross-verify PKCS#11 BLAKE2B digests against Python hashlib.

    PKCS#11 BLAKE2B mechanisms use the unkeyed variant - no key material.
    hashlib.blake2b(data, digest_size=N) with no key matches this exactly.
    """

    @pytest.mark.parametrize(
        "mech_name_str,mechanism,digest_size",
        [
            ("BLAKE2B_160", CKM_BLAKE2B_160, 20),
            ("BLAKE2B_256", CKM_BLAKE2B_256, 32),
            ("BLAKE2B_384", CKM_BLAKE2B_384, 48),
            ("BLAKE2B_512", CKM_BLAKE2B_512, 64),
        ],
        ids=["BLAKE2B-160", "BLAKE2B-256", "BLAKE2B-384", "BLAKE2B-512"],
    )
    def test_cross_verify(
        self,
        p11_raw_session: Any,
        mech_name_str: str,
        mechanism: Any,
        digest_size: int,
    ) -> None:
        """PKCS#11 BLAKE2B digest matches hashlib for each output size."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")
        data = b"BLAKE2B cross-verification test data"
        p11_digest = digest_single(rs.raw, rs.sh, mechanism, data)
        py_digest = hashlib.blake2b(data, digest_size=digest_size).digest()
        assert p11_digest == py_digest

    @pytest.mark.parametrize(
        "mech_name_str,mechanism,digest_size",
        [
            ("BLAKE2B_256", CKM_BLAKE2B_256, 32),
            ("BLAKE2B_512", CKM_BLAKE2B_512, 64),
        ],
        ids=["BLAKE2B-256", "BLAKE2B-512"],
    )
    def test_cross_verify_binary_data(
        self,
        p11_raw_session: Any,
        mech_name_str: str,
        mechanism: Any,
        digest_size: int,
    ) -> None:
        """Digest of all 256 byte values matches hashlib."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")
        data = bytes(range(256))
        p11_digest = digest_single(rs.raw, rs.sh, mechanism, data)
        py_digest = hashlib.blake2b(data, digest_size=digest_size).digest()
        assert p11_digest == py_digest


class TestBlake2bProperties:
    """Test fundamental hash function properties using BLAKE2B-256 as representative."""

    def test_deterministic(self, p11_raw_session: Any) -> None:
        """Same input produces the same BLAKE2B-256 digest."""
        rs = p11_raw_session
        if not rs.has_mechanism("BLAKE2B_256"):
            pytest.skip("CKM_BLAKE2B_256 not supported")
        data = b"deterministic test"
        d1 = digest_single(rs.raw, rs.sh, CKM_BLAKE2B_256, data)
        d2 = digest_single(rs.raw, rs.sh, CKM_BLAKE2B_256, data)
        assert d1 == d2

    def test_different_input_different_digest(self, p11_raw_session: Any) -> None:
        """Different inputs produce different BLAKE2B-256 digests."""
        rs = p11_raw_session
        if not rs.has_mechanism("BLAKE2B_256"):
            pytest.skip("CKM_BLAKE2B_256 not supported")
        d1 = digest_single(rs.raw, rs.sh, CKM_BLAKE2B_256, b"input one")
        d2 = digest_single(rs.raw, rs.sh, CKM_BLAKE2B_256, b"input two")
        assert d1 != d2

    def test_empty_data(self, p11_raw_session: Any) -> None:
        """BLAKE2B-256 digest of empty data matches hashlib."""
        rs = p11_raw_session
        if not rs.has_mechanism("BLAKE2B_256"):
            pytest.skip("CKM_BLAKE2B_256 not supported")
        digest = _digest_empty_or_xfail(rs.raw, rs.sh, CKM_BLAKE2B_256, "BLAKE2B_256")
        expected = hashlib.blake2b(b"", digest_size=32).digest()
        assert digest == expected

    def test_empty_data_blake2b_512(self, p11_raw_session: Any) -> None:
        """BLAKE2B-512 digest of empty data matches hashlib."""
        rs = p11_raw_session
        if not rs.has_mechanism("BLAKE2B_512"):
            pytest.skip("CKM_BLAKE2B_512 not supported")
        digest = _digest_empty_or_xfail(rs.raw, rs.sh, CKM_BLAKE2B_512, "BLAKE2B_512")
        expected = hashlib.blake2b(b"", digest_size=64).digest()
        assert digest == expected

    def test_large_data(self, p11_raw_session: Any) -> None:
        """BLAKE2B-256 digest of 1 MiB data matches hashlib."""
        rs = p11_raw_session
        if not rs.has_mechanism("BLAKE2B_256"):
            pytest.skip("CKM_BLAKE2B_256 not supported")
        data = b"\xab" * (1024 * 1024)
        p11_digest = digest_single(rs.raw, rs.sh, CKM_BLAKE2B_256, data)
        expected = hashlib.blake2b(data, digest_size=32).digest()
        assert p11_digest == expected


class TestBlake2bKeyed:
    """Keyed BLAKE2b HMAC, key generation, and key derivation tests."""

    def _hmac_matches_reference(self, p11_raw_session: Any, case: _Blake2bKeyedCase) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(case.hmac_name):
            pytest.skip(f"CKM_{case.hmac_name} not supported")

        key = _import_blake2b_setup_key(rs, sign=True, verify=True)
        try:
            try:
                mac = sign_single(
                    rs.raw,
                    rs.sh,
                    key,
                    case.hmac_mech,
                    _BLAKE2B_TEST_DATA,
                )
            except AssertionError as e:
                _xfail_blake2b_reject(
                    e,
                    f"{case.hmac_name} advertised but sign failed",
                )

            expected = _blake2b_hmac_reference(
                _BLAKE2B_TEST_KEY,
                _BLAKE2B_TEST_DATA,
                case.digest_len,
            )
            assert mac == expected

            try:
                assert verify_single(
                    rs.raw,
                    rs.sh,
                    key,
                    case.hmac_mech,
                    _BLAKE2B_TEST_DATA,
                    mac,
                )
            except AssertionError as e:
                _xfail_blake2b_reject(
                    e,
                    f"{case.hmac_name} advertised but verify failed",
                )

            tampered = bytes([mac[0] ^ 0x01]) + mac[1:]
            try:
                assert not verify_single(
                    rs.raw,
                    rs.sh,
                    key,
                    case.hmac_mech,
                    _BLAKE2B_TEST_DATA,
                    tampered,
                )
            except AssertionError as e:
                _xfail_blake2b_reject(
                    e,
                    f"{case.hmac_name} tampered verify rejected with unexpected CKR",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @pytest.mark.parametrize(
        "case",
        _BLAKE2B_KEYED_CASES,
        ids=[case.id for case in _BLAKE2B_KEYED_CASES],
    )
    def test_blake2b_hmac_matches_reference(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
    ) -> None:
        self._hmac_matches_reference(p11_raw_session, case)

    def _hmac_general_matches_reference(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
        *,
        mac_len: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(case.hmac_general_name):
            pytest.skip(f"CKM_{case.hmac_general_name} not supported")

        key = _import_blake2b_setup_key(rs, sign=True, verify=True)
        mech_param = mech_bytes(
            case.hmac_general_mech,
            _ck_ulong_param(mac_len),
        )
        try:
            try:
                mac = sign_single(
                    rs.raw,
                    rs.sh,
                    key,
                    case.hmac_general_mech,
                    _BLAKE2B_TEST_DATA,
                    mech_param=mech_param,
                )
            except AssertionError as e:
                _xfail_blake2b_reject(
                    e,
                    f"{case.hmac_general_name} advertised but sign failed",
                )

            expected_full = _blake2b_hmac_reference(
                _BLAKE2B_TEST_KEY,
                _BLAKE2B_TEST_DATA,
                case.digest_len,
            )
            assert mac == expected_full[:mac_len]

            try:
                assert verify_single(
                    rs.raw,
                    rs.sh,
                    key,
                    case.hmac_general_mech,
                    _BLAKE2B_TEST_DATA,
                    mac,
                    mech_param=mech_param,
                )
            except AssertionError as e:
                _xfail_blake2b_reject(
                    e,
                    f"{case.hmac_general_name} advertised but verify failed",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def _hmac_general_truncates(self, p11_raw_session: Any, case: _Blake2bKeyedCase) -> None:
        self._hmac_general_matches_reference(p11_raw_session, case, mac_len=12)

    @pytest.mark.parametrize(
        "case",
        _BLAKE2B_KEYED_CASES,
        ids=[case.id for case in _BLAKE2B_KEYED_CASES],
    )
    def test_blake2b_hmac_general_truncates(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
    ) -> None:
        self._hmac_general_truncates(p11_raw_session, case)

    def _hmac_general_rejects_tampered_mac(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
        *,
        mac_len: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(case.hmac_general_name):
            pytest.skip(f"CKM_{case.hmac_general_name} not supported")

        key = _import_blake2b_setup_key(rs, sign=True, verify=True)
        mech_param = mech_bytes(case.hmac_general_mech, _ck_ulong_param(mac_len))
        try:
            try:
                mac = sign_single(
                    rs.raw,
                    rs.sh,
                    key,
                    case.hmac_general_mech,
                    _BLAKE2B_TEST_DATA,
                    mech_param=mech_param,
                )
            except AssertionError as e:
                _xfail_blake2b_reject(
                    e,
                    f"{case.hmac_general_name} advertised but sign failed",
                )

            tampered = bytes([mac[0] ^ 0x01]) + mac[1:]
            try:
                assert not verify_single(
                    rs.raw,
                    rs.sh,
                    key,
                    case.hmac_general_mech,
                    _BLAKE2B_TEST_DATA,
                    tampered,
                    mech_param=mech_param,
                )
            except AssertionError as e:
                _xfail_blake2b_reject(
                    e,
                    f"{case.hmac_general_name} tampered BLAKE2B HMAC_GENERAL verify "
                    "rejected with unexpected CKR",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @pytest.mark.parametrize(
        "case",
        _BLAKE2B_KEYED_CASES,
        ids=[case.id for case in _BLAKE2B_KEYED_CASES],
    )
    def test_blake2b_hmac_general_rejects_tampered_mac(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
    ) -> None:
        self._hmac_general_rejects_tampered_mac(p11_raw_session, case, mac_len=12)

    def _hmac_general_rejects_wrong_length_mac(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
        *,
        mac_len: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(case.hmac_general_name):
            pytest.skip(f"CKM_{case.hmac_general_name} not supported")

        key = _import_blake2b_setup_key(rs, sign=True, verify=True)
        mech_param = mech_bytes(case.hmac_general_mech, _ck_ulong_param(mac_len))
        try:
            try:
                mac = sign_single(
                    rs.raw,
                    rs.sh,
                    key,
                    case.hmac_general_mech,
                    _BLAKE2B_TEST_DATA,
                    mech_param=mech_param,
                )
            except AssertionError as e:
                _xfail_blake2b_reject(
                    e,
                    f"{case.hmac_general_name} advertised but sign failed",
                )

            wrong_macs = (
                ("extended", mac + b"\x00"),
                ("truncated", mac[:-1]),
            )
            for variant, wrong_mac in wrong_macs:
                try:
                    accepted = verify_single(
                        rs.raw,
                        rs.sh,
                        key,
                        case.hmac_general_mech,
                        _BLAKE2B_TEST_DATA,
                        wrong_mac,
                        mech_param=mech_param,
                    )
                except AssertionError as e:
                    _xfail_blake2b_reject(
                        e,
                        f"{case.hmac_general_name} {variant} wrong-length verify "
                        "rejected with unexpected CKR",
                    )
                if accepted:
                    raise AssertionError(
                        f"accepted wrong-length {case.hmac_general_name} {variant} MAC; "
                        f"expected {len(mac)} bytes, got {len(wrong_mac)} bytes"
                    )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @pytest.mark.parametrize(
        "case",
        _BLAKE2B_KEYED_CASES,
        ids=[case.id for case in _BLAKE2B_KEYED_CASES],
    )
    def test_blake2b_hmac_general_rejects_wrong_length_mac(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
    ) -> None:
        self._hmac_general_rejects_wrong_length_mac(p11_raw_session, case, mac_len=12)

    @pytest.mark.parametrize(
        "case",
        _BLAKE2B_KEYED_CASES,
        ids=[case.id for case in _BLAKE2B_KEYED_CASES],
    )
    @pytest.mark.parametrize("mac_len_kind", ("minimum", "maximum"))
    def test_blake2b_hmac_general_boundary_lengths(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
        mac_len_kind: str,
    ) -> None:
        mac_len = 1 if mac_len_kind == "minimum" else case.digest_len
        self._hmac_general_matches_reference(p11_raw_session, case, mac_len=mac_len)

    def _hmac_general_invalid_length_rejected(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
        *,
        bad_len: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(case.hmac_general_name):
            pytest.skip(f"CKM_{case.hmac_general_name} not supported")

        key = _import_blake2b_setup_key(rs, sign=True, verify=True)
        mech_param = mech_bytes(case.hmac_general_mech, _ck_ulong_param(bad_len))
        try:
            try:
                mac = sign_single(
                    rs.raw,
                    rs.sh,
                    key,
                    case.hmac_general_mech,
                    _BLAKE2B_TEST_DATA,
                    mech_param=mech_param,
                )
            except AssertionError as e:
                reject_or_classify(
                    e,
                    (CKR_MECHANISM_PARAM_INVALID,),
                    label=f"{case.hmac_general_name} invalid output length {bad_len}",
                )
                return

            raise AssertionError(
                f"accepted invalid {case.hmac_general_name} output length {bad_len}; "
                f"returned {len(mac)} bytes"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @pytest.mark.parametrize(
        "case",
        _BLAKE2B_KEYED_CASES,
        ids=[case.id for case in _BLAKE2B_KEYED_CASES],
    )
    @pytest.mark.parametrize("bad_kind", ("zero", "too-long"))
    def test_blake2b_hmac_general_rejects_invalid_lengths(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
        bad_kind: str,
    ) -> None:
        bad_len = 0 if bad_kind == "zero" else case.digest_len + 1
        self._hmac_general_invalid_length_rejected(
            p11_raw_session,
            case,
            bad_len=bad_len,
        )

    def _key_gen_signs_reference(self, p11_raw_session: Any, case: _Blake2bKeyedCase) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(case.key_gen_name):
            pytest.skip(f"CKM_{case.key_gen_name} not supported")
        if not rs.has_mechanism(case.hmac_name):
            pytest.skip(f"CKM_{case.hmac_name} not supported")

        key = _generate_blake2b_hmac_key(rs, case)
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_KEY_TYPE, CKA_VALUE])
            assert attrs[CKA_KEY_TYPE] == case.key_type
            key_value = attrs[CKA_VALUE]
            assert isinstance(key_value, bytes)
            assert len(key_value) == case.digest_len

            try:
                mac = sign_single(
                    rs.raw,
                    rs.sh,
                    key,
                    case.hmac_mech,
                    _BLAKE2B_TEST_DATA,
                )
            except AssertionError as e:
                _xfail_blake2b_reject(
                    e,
                    f"{case.key_gen_name} produced key but {case.hmac_name} sign failed",
                )

            expected = _blake2b_hmac_reference(
                key_value,
                _BLAKE2B_TEST_DATA,
                case.digest_len,
            )
            assert mac == expected
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @pytest.mark.parametrize(
        "case",
        _BLAKE2B_KEYED_CASES,
        ids=[case.id for case in _BLAKE2B_KEYED_CASES],
    )
    def test_blake2b_key_gen_signs_reference(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
    ) -> None:
        self._key_gen_signs_reference(p11_raw_session, case)

    def _key_derive_value(self, p11_raw_session: Any, case: _Blake2bKeyedCase) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(case.key_derive_name):
            pytest.skip(f"CKM_{case.key_derive_name} not supported")

        base = _import_blake2b_setup_key(rs, derive=True)
        derived = 0
        try:
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    base,
                    case.key_derive_mech,
                    attrs={
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_VALUE_LEN: case.digest_len,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                    },
                )
            except AssertionError as e:
                _xfail_blake2b_reject(
                    e,
                    f"{case.key_derive_name} advertised but derive failed",
                )

            value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
            expected = hashlib.blake2b(_BLAKE2B_TEST_KEY, digest_size=case.digest_len).digest()
            assert value == expected
        finally:
            destroy_quietly(rs.raw, rs.sh, base)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)

    def _key_derive_default_template_value(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(case.key_derive_name):
            pytest.skip(f"CKM_{case.key_derive_name} not supported")

        base = _import_blake2b_setup_key(rs, derive=True)
        derived = 0
        try:
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    base,
                    case.key_derive_mech,
                    attrs={
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                    },
                )
            except AssertionError as e:
                _xfail_blake2b_reject(
                    e,
                    f"{case.key_derive_name} advertised but default-template derive failed",
                )

            attrs = read_attributes(rs.raw, rs.sh, derived, [CKA_KEY_TYPE, CKA_VALUE])
            assert attrs[CKA_KEY_TYPE] == CKK_GENERIC_SECRET
            value = attrs[CKA_VALUE]
            expected = hashlib.blake2b(_BLAKE2B_TEST_KEY, digest_size=case.digest_len).digest()
            assert value == expected
        finally:
            destroy_quietly(rs.raw, rs.sh, base)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)

    def _key_derive_length_only_template_value(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(case.key_derive_name):
            pytest.skip(f"CKM_{case.key_derive_name} not supported")

        requested_len = 12
        base = _import_blake2b_setup_key(rs, derive=True)
        derived = 0
        try:
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    base,
                    case.key_derive_mech,
                    attrs={
                        CKA_VALUE_LEN: requested_len,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                    },
                )
            except AssertionError as e:
                _xfail_blake2b_reject(
                    e,
                    f"{case.key_derive_name} advertised but length-only derive failed",
                )

            attrs = read_attributes(rs.raw, rs.sh, derived, [CKA_KEY_TYPE, CKA_VALUE])
            assert attrs[CKA_KEY_TYPE] == CKK_GENERIC_SECRET
            value = attrs[CKA_VALUE]
            assert isinstance(value, bytes)
            assert len(value) == requested_len
        finally:
            destroy_quietly(rs.raw, rs.sh, base)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)

    def _key_derive_rejects_overlong_requested_key(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(case.key_derive_name):
            pytest.skip(f"CKM_{case.key_derive_name} not supported")

        base = _import_blake2b_setup_key(rs, derive=True)
        derived = 0
        try:
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    base,
                    case.key_derive_mech,
                    attrs={
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_VALUE_LEN: 32,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                    },
                )
            except AssertionError as e:
                reject_or_classify(
                    e,
                    (CKR_KEY_SIZE_RANGE,),
                    label=f"{case.key_derive_name} overlong AES-256 output",
                )
                return

            raise AssertionError(
                f"accepted {case.key_derive_name} overlong AES-256 output; "
                f"digest length is {case.digest_len} bytes"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, base)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)

    def _key_derive_rejects_variable_key_type_without_len(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(case.key_derive_name):
            pytest.skip(f"CKM_{case.key_derive_name} not supported")

        base = _import_blake2b_setup_key(rs, derive=True)
        derived = 0
        try:
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    base,
                    case.key_derive_mech,
                    attrs={
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                    },
                )
            except AssertionError as e:
                reject_or_classify(
                    e,
                    (CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT, CKR_KEY_SIZE_RANGE),
                    label=f"{case.key_derive_name} AES without CKA_VALUE_LEN",
                )
                return

            raise AssertionError(
                f"accepted {case.key_derive_name} AES without CKA_VALUE_LEN; "
                "AES is a variable-length key type"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, base)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)

    @pytest.mark.parametrize(
        "case",
        _BLAKE2B_KEYED_CASES,
        ids=[case.id for case in _BLAKE2B_KEYED_CASES],
    )
    def test_blake2b_key_derive_value(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
    ) -> None:
        self._key_derive_value(p11_raw_session, case)

    @pytest.mark.parametrize(
        "case",
        _BLAKE2B_KEYED_CASES,
        ids=[case.id for case in _BLAKE2B_KEYED_CASES],
    )
    def test_blake2b_key_derive_default_template_value(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
    ) -> None:
        self._key_derive_default_template_value(p11_raw_session, case)

    @pytest.mark.parametrize(
        "case",
        _BLAKE2B_KEYED_CASES,
        ids=[case.id for case in _BLAKE2B_KEYED_CASES],
    )
    def test_blake2b_key_derive_length_only_template_value(
        self,
        p11_raw_session: Any,
        case: _Blake2bKeyedCase,
    ) -> None:
        self._key_derive_length_only_template_value(p11_raw_session, case)

    def test_blake2b_key_derive_rejects_overlong_requested_key(
        self,
        p11_raw_session: Any,
    ) -> None:
        """BLAKE2B_160_KEY_DERIVE overlong AES-256 output is rejected."""
        self._key_derive_rejects_overlong_requested_key(
            p11_raw_session,
            _BLAKE2B_KEYED_CASE_BY_BITS[160],
        )

    def test_blake2b_key_derive_rejects_aes_without_value_len(
        self,
        p11_raw_session: Any,
    ) -> None:
        """BLAKE2B_256_KEY_DERIVE AES without CKA_VALUE_LEN is rejected."""
        self._key_derive_rejects_variable_key_type_without_len(
            p11_raw_session,
            _BLAKE2B_KEYED_CASE_BY_BITS[256],
        )
