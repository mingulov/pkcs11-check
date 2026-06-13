"""Regression tests for keyed BLAKE2b coverage and classification."""

from __future__ import annotations

import hashlib
import hmac
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import test_blake2


def test_blake2b_keyed_cases_cover_all_output_sizes() -> None:
    assert {case.bits for case in test_blake2._BLAKE2B_KEYED_CASES} == {160, 256, 384, 512}


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def test_blake2b_hmac_reference_matches_python_hmac() -> None:
    key = b"blake2 hmac key"
    data = b"blake2 hmac data"
    digest_size = 32

    def _digest(payload: bytes = b"") -> Any:
        return hashlib.blake2b(payload, digest_size=digest_size)

    expected = hmac.new(key, data, _digest).digest()

    assert test_blake2._blake2b_hmac_reference(key, data, digest_size) == expected


def test_blake2b_hmac_general_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _sign_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms("BLAKE2B_256_HMAC_GENERAL")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "sign_single", _sign_reject)

    with pytest.raises(pytest.xfail.Exception, match="BLAKE2B_256_HMAC_GENERAL advertised"):
        test_blake2.TestBlake2bKeyed()._hmac_general_truncates(
            rs,
            test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256],
        )


@pytest.mark.parametrize("mac_len", (1, 32))
def test_blake2b_hmac_general_boundary_lengths_match_reference(
    monkeypatch: pytest.MonkeyPatch,
    mac_len: int,
) -> None:
    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    expected = test_blake2._blake2b_hmac_reference(
        test_blake2._BLAKE2B_TEST_KEY,
        test_blake2._BLAKE2B_TEST_DATA,
        case.digest_len,
    )[:mac_len]
    signed: list[bytes] = []

    def _sign_reference(*_args: Any, **_kwargs: Any) -> bytes:
        signed.append(expected)
        return expected

    def _verify_reference(*_args: Any, **_kwargs: Any) -> bool:
        return True

    rs = _session_with_mechanisms("BLAKE2B_256_HMAC_GENERAL")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_blake2, "sign_single", _sign_reference)
    monkeypatch.setattr(test_blake2, "verify_single", _verify_reference)

    test_blake2.TestBlake2bKeyed()._hmac_general_matches_reference(
        rs,
        case,
        mac_len=mac_len,
    )

    assert signed == [expected]


def test_blake2b_hmac_general_invalid_length_acceptance_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _sign_accepts_invalid_length(*_args: Any, **_kwargs: Any) -> bytes:
        return b"invalid"

    rs = _session_with_mechanisms("BLAKE2B_256_HMAC_GENERAL")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_blake2, "sign_single", _sign_accepts_invalid_length)

    with pytest.raises(AssertionError, match="accepted invalid BLAKE2B_256_HMAC_GENERAL"):
        test_blake2.TestBlake2bKeyed()._hmac_general_invalid_length_rejected(
            rs,
            test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256],
            bad_len=0,
        )


def test_blake2b_hmac_general_wrong_length_mac_variants_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    mac = b"\x5a" * 12
    verified: list[bytes] = []

    def _sign_reference(*_args: Any, **_kwargs: Any) -> bytes:
        return mac

    def _verify_rejects(
        _raw: Any,
        _sh: int,
        _key: int,
        _mech: Any,
        _data: bytes,
        sig: bytes,
        **_kwargs: Any,
    ) -> bool:
        verified.append(sig)
        return False

    rs = _session_with_mechanisms("BLAKE2B_256_HMAC_GENERAL")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_blake2, "sign_single", _sign_reference)
    monkeypatch.setattr(test_blake2, "verify_single", _verify_rejects)

    test_blake2.TestBlake2bKeyed()._hmac_general_rejects_wrong_length_mac(
        rs,
        case,
        mac_len=12,
    )

    assert verified == [mac + b"\x00", mac[:-1]]


def test_blake2b_hmac_general_wrong_length_mac_acceptance_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]

    def _sign_reference(*_args: Any, **_kwargs: Any) -> bytes:
        return b"\xa5" * 12

    def _verify_accepts(*_args: Any, **_kwargs: Any) -> bool:
        return True

    rs = _session_with_mechanisms("BLAKE2B_256_HMAC_GENERAL")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_blake2, "sign_single", _sign_reference)
    monkeypatch.setattr(test_blake2, "verify_single", _verify_accepts)

    with pytest.raises(AssertionError, match="accepted wrong-length BLAKE2B_256_HMAC_GENERAL"):
        test_blake2.TestBlake2bKeyed()._hmac_general_rejects_wrong_length_mac(
            rs,
            case,
            mac_len=12,
        )


def test_blake2b_hmac_wrong_length_mac_variants_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert hasattr(test_blake2.TestBlake2bKeyed, "_hmac_rejects_wrong_length_mac")

    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    mac = b"\x6b" * case.digest_len
    verified: list[bytes] = []

    def _sign_reference(*_args: Any, **_kwargs: Any) -> bytes:
        return mac

    def _verify_rejects(
        _raw: Any,
        _sh: int,
        _key: int,
        _mech: Any,
        _data: bytes,
        sig: bytes,
        **_kwargs: Any,
    ) -> bool:
        verified.append(sig)
        return False

    rs = _session_with_mechanisms("BLAKE2B_256_HMAC")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_blake2, "sign_single", _sign_reference)
    monkeypatch.setattr(test_blake2, "verify_single", _verify_rejects)

    test_blake2.TestBlake2bKeyed()._hmac_rejects_wrong_length_mac(rs, case)

    assert verified == [mac + b"\x00", mac[:-1]]


def test_blake2b_hmac_wrong_length_mac_acceptance_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert hasattr(test_blake2.TestBlake2bKeyed, "_hmac_rejects_wrong_length_mac")

    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]

    def _sign_reference(*_args: Any, **_kwargs: Any) -> bytes:
        return b"\xa6" * case.digest_len

    def _verify_accepts(*_args: Any, **_kwargs: Any) -> bool:
        return True

    rs = _session_with_mechanisms("BLAKE2B_256_HMAC")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_blake2, "sign_single", _sign_reference)
    monkeypatch.setattr(test_blake2, "verify_single", _verify_accepts)

    with pytest.raises(AssertionError, match="accepted wrong-length BLAKE2B_256_HMAC"):
        test_blake2.TestBlake2bKeyed()._hmac_rejects_wrong_length_mac(rs, case)


def test_blake2b_key_derive_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _derive_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms("BLAKE2B_256_KEY_DERIVE")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "derive_key", _derive_reject)

    with pytest.raises(pytest.xfail.Exception, match="BLAKE2B_256_KEY_DERIVE advertised"):
        test_blake2.TestBlake2bKeyed()._key_derive_value(
            rs,
            test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256],
        )


def test_blake2b_key_derive_default_template_omits_type_and_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    expected = hashlib.blake2b(
        test_blake2._BLAKE2B_TEST_KEY,
        digest_size=case.digest_len,
    ).digest()
    derive_attrs: list[dict[int, Any]] = []

    def _derive_key(
        _raw: object,
        _sh: int,
        _base_key: int,
        _mechanism: int,
        attrs: dict[int, Any],
    ) -> int:
        derive_attrs.append(attrs)
        return 77

    def _read_attributes(
        _raw: object,
        _sh: int,
        handle: int,
        attrs: list[int],
    ) -> dict[int, Any]:
        assert handle == 77
        assert attrs == [CKA_KEY_TYPE, CKA_VALUE]
        return {CKA_KEY_TYPE: CKK_GENERIC_SECRET, CKA_VALUE: expected}

    rs = _session_with_mechanisms("BLAKE2B_256_KEY_DERIVE")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "derive_key", _derive_key)
    monkeypatch.setattr(test_blake2, "read_attributes", _read_attributes)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)

    test_blake2.TestBlake2bKeyed()._key_derive_default_template_value(rs, case)

    assert len(derive_attrs) == 1
    assert CKA_KEY_TYPE not in derive_attrs[0]
    assert CKA_VALUE_LEN not in derive_attrs[0]


def test_blake2b_key_derive_length_only_template_omits_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    expected = hashlib.blake2b(
        test_blake2._BLAKE2B_TEST_KEY,
        digest_size=case.digest_len,
    ).digest()[:12]
    derive_attrs: list[dict[int, Any]] = []

    def _derive_key(
        _raw: object,
        _sh: int,
        _base_key: int,
        _mechanism: int,
        attrs: dict[int, Any],
    ) -> int:
        derive_attrs.append(attrs)
        return 78

    def _read_attributes(
        _raw: object,
        _sh: int,
        handle: int,
        attrs: list[int],
    ) -> dict[int, Any]:
        assert handle == 78
        assert attrs == [CKA_KEY_TYPE, CKA_VALUE]
        return {CKA_KEY_TYPE: CKK_GENERIC_SECRET, CKA_VALUE: expected}

    rs = _session_with_mechanisms("BLAKE2B_256_KEY_DERIVE")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "derive_key", _derive_key)
    monkeypatch.setattr(test_blake2, "read_attributes", _read_attributes)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)

    test_blake2.TestBlake2bKeyed()._key_derive_length_only_template_value(rs, case)

    assert len(derive_attrs) == 1
    assert derive_attrs[0][CKA_VALUE_LEN] == 12
    assert CKA_KEY_TYPE not in derive_attrs[0]


def test_blake2b_key_derive_overlong_aes256_request_is_expected_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[160]
    derive_attrs: list[dict[int, Any]] = []

    def _derive_reject(
        _raw: object,
        _sh: int,
        _base_key: int,
        _mechanism: int,
        attrs: dict[int, Any],
    ) -> int:
        derive_attrs.append(attrs)
        raise CkrAssertionError("Unexpected CK_RV CKR_KEY_SIZE_RANGE", int(CKR_KEY_SIZE_RANGE))

    rs = _session_with_mechanisms("BLAKE2B_160_KEY_DERIVE")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "derive_key", _derive_reject)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)

    test_blake2.TestBlake2bKeyed()._key_derive_rejects_overlong_requested_key(rs, case)

    assert derive_attrs == [
        {
            CKA_KEY_TYPE: CKK_AES,
            CKA_VALUE_LEN: 32,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
        }
    ]


def test_blake2b_key_derive_aes_without_length_is_expected_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    derive_attrs: list[dict[int, Any]] = []

    def _derive_reject(
        _raw: object,
        _sh: int,
        _base_key: int,
        _mechanism: int,
        attrs: dict[int, Any],
    ) -> int:
        derive_attrs.append(attrs)
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_TEMPLATE_INCOMPLETE",
            int(CKR_TEMPLATE_INCOMPLETE),
        )

    rs = _session_with_mechanisms("BLAKE2B_256_KEY_DERIVE")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "derive_key", _derive_reject)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)

    test_blake2.TestBlake2bKeyed()._key_derive_rejects_variable_key_type_without_len(
        rs,
        case,
    )

    assert derive_attrs == [
        {
            CKA_KEY_TYPE: CKK_AES,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
        }
    ]
    assert CKA_VALUE_LEN not in derive_attrs[0]


def test_blake2b_key_derive_length_only_overlong_is_expected_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[160]
    derive_attrs: list[dict[int, Any]] = []

    def _derive_reject(
        _raw: object,
        _sh: int,
        _base_key: int,
        _mechanism: int,
        attrs: dict[int, Any],
    ) -> int:
        derive_attrs.append(attrs)
        raise CkrAssertionError("Unexpected CK_RV CKR_KEY_SIZE_RANGE", int(CKR_KEY_SIZE_RANGE))

    rs = _session_with_mechanisms("BLAKE2B_160_KEY_DERIVE")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "derive_key", _derive_reject)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)

    test_blake2.TestBlake2bKeyed()._key_derive_rejects_length_only_overlong(
        rs,
        case,
    )

    assert derive_attrs == [
        {
            CKA_VALUE_LEN: case.digest_len + 1,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
        }
    ]
    assert CKA_KEY_TYPE not in derive_attrs[0]


def test_blake2b_key_derive_length_only_zero_is_expected_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    derive_attrs: list[dict[int, Any]] = []

    def _derive_reject(
        _raw: object,
        _sh: int,
        _base_key: int,
        _mechanism: int,
        attrs: dict[int, Any],
    ) -> int:
        derive_attrs.append(attrs)
        raise CkrAssertionError("Unexpected CK_RV CKR_KEY_SIZE_RANGE", int(CKR_KEY_SIZE_RANGE))

    rs = _session_with_mechanisms("BLAKE2B_256_KEY_DERIVE")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "derive_key", _derive_reject)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)

    test_blake2.TestBlake2bKeyed()._key_derive_rejects_length_only_zero(
        rs,
        case,
    )

    assert derive_attrs == [
        {
            CKA_VALUE_LEN: 0,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
        }
    ]
    assert CKA_KEY_TYPE not in derive_attrs[0]


def test_blake2b_key_derive_value_injection_is_expected_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    derive_attrs: list[dict[int, Any]] = []

    def _derive_reject(
        _raw: object,
        _sh: int,
        _base_key: int,
        _mechanism: int,
        attrs: dict[int, Any],
    ) -> int:
        derive_attrs.append(attrs)
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT",
            int(CKR_TEMPLATE_INCONSISTENT),
        )

    rs = _session_with_mechanisms("BLAKE2B_256_KEY_DERIVE")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "derive_key", _derive_reject)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)

    test_blake2.TestBlake2bKeyed()._key_derive_rejects_value_injection(
        rs,
        case,
    )

    assert derive_attrs == [
        {
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_VALUE_LEN: case.digest_len,
            CKA_VALUE: b"\xa5" * case.digest_len,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
        }
    ]


def test_blake2b_key_derive_value_injection_accepts_injected_value_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    injected = b"\xa5" * case.digest_len

    def _derive_key(
        _raw: object,
        _sh: int,
        _base_key: int,
        _mechanism: int,
        attrs: dict[int, Any],
    ) -> int:
        assert CKA_VALUE in attrs
        return 79

    def _read_attributes(
        _raw: object,
        _sh: int,
        handle: int,
        attrs: list[int],
    ) -> dict[int, Any]:
        assert handle == 79
        assert attrs == [CKA_VALUE]
        return {CKA_VALUE: injected}

    rs = _session_with_mechanisms("BLAKE2B_256_KEY_DERIVE")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "derive_key", _derive_key)
    monkeypatch.setattr(test_blake2, "read_attributes", _read_attributes)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)

    with pytest.raises(AssertionError, match="accepted caller-supplied CKA_VALUE"):
        test_blake2.TestBlake2bKeyed()._key_derive_rejects_value_injection(
            rs,
            case,
        )


def test_blake2b_key_derive_value_injection_accepts_but_ignores_value_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    expected = hashlib.blake2b(
        test_blake2._BLAKE2B_TEST_KEY,
        digest_size=case.digest_len,
    ).digest()

    def _derive_key(
        _raw: object,
        _sh: int,
        _base_key: int,
        _mechanism: int,
        attrs: dict[int, Any],
    ) -> int:
        assert CKA_VALUE in attrs
        return 80

    def _read_attributes(
        _raw: object,
        _sh: int,
        handle: int,
        attrs: list[int],
    ) -> dict[int, Any]:
        assert handle == 80
        assert attrs == [CKA_VALUE]
        return {CKA_VALUE: expected}

    rs = _session_with_mechanisms("BLAKE2B_256_KEY_DERIVE")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "derive_key", _derive_key)
    monkeypatch.setattr(test_blake2, "read_attributes", _read_attributes)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)

    with pytest.raises(pytest.xfail.Exception, match="ignored caller-supplied CKA_VALUE"):
        test_blake2.TestBlake2bKeyed()._key_derive_rejects_value_injection(
            rs,
            case,
        )
