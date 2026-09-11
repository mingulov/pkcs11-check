"""Runtime regressions for authenticated-wrap provider output readbacks."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKA_VALUE
from pkcs11_check.testcases import test_authenticated_wrap as authenticated_wrap
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "AES_GCM")


def test_missing_original_value_is_structured_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([10, 11])
    monkeypatch.setattr(authenticated_wrap, "gen_aes_key", lambda *_args, **_kwargs: next(handles))
    monkeypatch.setattr(authenticated_wrap, "read_attributes", lambda *_args: {})
    monkeypatch.setattr(authenticated_wrap, "generate_random", lambda *_args: b"i" * 12)
    monkeypatch.setattr(
        authenticated_wrap,
        "mech_gcm_message",
        lambda *_args, **_kwargs: SimpleNamespace(buffer_bytes=lambda _name: b"tag"),
    )
    monkeypatch.setattr(
        authenticated_wrap,
        "mech_gcm_message_inherit_tag",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        authenticated_wrap, "wrap_key_authenticated", lambda *_args, **_kwargs: b"wrapped"
    )
    monkeypatch.setattr(
        authenticated_wrap, "unwrap_key_authenticated", lambda *_args, **_kwargs: 12
    )
    destroyed: list[int] = []
    monkeypatch.setattr(
        authenticated_wrap,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    authenticated_wrap.TestAuthenticatedWrap().test_aes_gcm_wrap_unwrap(_rs(), "3.2")

    assert destroyed == [12, 10, 11]
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "not_operational"]
    assert all(record.operation == "C_GetAttributeValue" for record in records)
    # F6: a plain readback is never stamped with the mechanism that produced the
    # object being read; the producer survives in the label instead.
    assert all(record.mechanism is None for record in records)
    assert all("producer_mechanism=CKM_AES_GCM" in record.label for record in records)
    assert all(
        record.detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}
        for record in records
    )


@pytest.mark.parametrize("value", [False, 0, b"", None], ids=["false", "zero", "empty", "none"])
def test_false_like_original_value_is_structured_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    handles = iter([10, 11, 12])
    monkeypatch.setattr(authenticated_wrap, "gen_aes_key", lambda *_args, **_kwargs: next(handles))
    monkeypatch.setattr(
        authenticated_wrap,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {CKA_VALUE: value if handle in (11, 12) else b"unused"},
    )
    monkeypatch.setattr(authenticated_wrap, "generate_random", lambda *_args: b"i" * 12)
    monkeypatch.setattr(
        authenticated_wrap,
        "mech_gcm_message",
        lambda *_args, **_kwargs: SimpleNamespace(buffer_bytes=lambda _name: b"tag"),
    )
    monkeypatch.setattr(
        authenticated_wrap,
        "mech_gcm_message_inherit_tag",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        authenticated_wrap, "wrap_key_authenticated", lambda *_args, **_kwargs: b"wrapped"
    )
    monkeypatch.setattr(
        authenticated_wrap, "unwrap_key_authenticated", lambda *_args, **_kwargs: 12
    )
    destroyed: list[int] = []
    monkeypatch.setattr(
        authenticated_wrap,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        authenticated_wrap.TestAuthenticatedWrap().test_aes_gcm_wrap_unwrap(_rs(), "3.2")

    assert destroyed == [12, 10, 11]
    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "wrong_result"]
    assert all(record.kind == "crypto" for record in records)
    assert all(record.operation == "C_GetAttributeValue" for record in records)


def test_zero_authentication_tag_is_structured_and_cleanup_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([10, 11])
    monkeypatch.setattr(authenticated_wrap, "gen_aes_key", lambda *_args, **_kwargs: next(handles))
    monkeypatch.setattr(
        authenticated_wrap,
        "read_attributes",
        lambda *_args: {CKA_VALUE: b"k" * 16},
    )
    monkeypatch.setattr(authenticated_wrap, "generate_random", lambda *_args: b"i" * 12)
    monkeypatch.setattr(
        authenticated_wrap,
        "mech_gcm_message",
        lambda *_args, **_kwargs: SimpleNamespace(buffer_bytes=lambda _name: b"\0" * 16),
    )
    monkeypatch.setattr(
        authenticated_wrap, "wrap_key_authenticated", lambda *_args, **_kwargs: b"wrapped"
    )
    destroyed: list[int] = []
    monkeypatch.setattr(
        authenticated_wrap,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        authenticated_wrap.TestAuthenticatedWrap().test_aes_gcm_wrap_unwrap(_rs(), "3.2")

    assert destroyed == [10, 11]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].operation == "C_WrapKeyAuthenticated"
    assert records[0].mechanism == "CKM_AES_GCM"
    assert records[0].detail == {
        "output": {"expected": "non-zero tag bytes", "actual": repr(b"\0" * 16)},
    }


def test_short_wrap_output_is_structured_and_skips_dependent_unwrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "AES_KEY_WRAP")
    handles = iter([10, 11])
    monkeypatch.setattr(authenticated_wrap, "gen_aes_key", lambda *_args, **_kwargs: next(handles))
    monkeypatch.setattr(
        authenticated_wrap,
        "read_attributes",
        lambda *_args: {CKA_VALUE: b"k" * 16},
    )
    monkeypatch.setattr(authenticated_wrap, "wrap_key", lambda *_args, **_kwargs: b"")
    monkeypatch.setattr(
        authenticated_wrap,
        "unwrap_key_for_mechanism_roundtrip",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not unwrap")),
    )
    destroyed: list[int] = []
    monkeypatch.setattr(
        authenticated_wrap,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        authenticated_wrap.TestWrapIntegrity().test_aes_key_wrap_bit_flip_detected(rs, object())

    assert destroyed == [10, 11]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.operation == "C_WrapKey"
    assert record.mechanism == "CKM_AES_KEY_WRAP"
    assert record.detail == {
        "output": {"expected": "at least 16 ciphertext bytes", "actual": "b''"},
    }


def test_empty_authenticated_wrap_output_is_structured_and_cleanup_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([10, 11])
    monkeypatch.setattr(authenticated_wrap, "gen_aes_key", lambda *_args, **_kwargs: next(handles))
    monkeypatch.setattr(
        authenticated_wrap,
        "read_attributes",
        lambda *_args: {CKA_VALUE: b"k" * 16},
    )
    monkeypatch.setattr(authenticated_wrap, "generate_random", lambda *_args: b"i" * 12)
    monkeypatch.setattr(
        authenticated_wrap,
        "mech_gcm_message",
        lambda *_args, **_kwargs: SimpleNamespace(buffer_bytes=lambda _name: b"t"),
    )
    monkeypatch.setattr(authenticated_wrap, "wrap_key_authenticated", lambda *_args, **_kwargs: b"")
    monkeypatch.setattr(
        authenticated_wrap,
        "unwrap_key_authenticated",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not unwrap")),
    )
    destroyed: list[int] = []
    monkeypatch.setattr(
        authenticated_wrap,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        authenticated_wrap.TestWrapIntegrity().test_aes_gcm_wrap_bit_flip_detected(
            _rs(), "3.2", object()
        )

    assert destroyed == [10, 11]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.operation == "C_WrapKeyAuthenticated"
    assert record.mechanism == "CKM_AES_GCM"
    assert record.detail == {
        "output": {"expected": "non-empty ciphertext", "actual": "b''"},
    }


def test_aad_leg_clean_wrap_rejection_of_advertised_mechanism_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation: the wrap leg cleanly rejects CKM_AES_GCM (advertised) with a known CKR.

    Before the fix this was ``pytest.skip(...)`` -- discarding the observation entirely and
    silently voiding the CWE-354 discrimination this test exists to make. A clean refusal of
    an *advertised* mechanism is a deviation, not an absent capability, so it must now be
    retained as an xfail (matching the sibling ``test_aes_gcm_wrap_unwrap`` at the wrap leg),
    never a skip.
    """
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_MECHANISM_INVALID

    handles = iter([10, 11])
    monkeypatch.setattr(authenticated_wrap, "gen_aes_key", lambda *_args, **_kwargs: next(handles))
    monkeypatch.setattr(
        authenticated_wrap,
        "read_attributes",
        lambda *_args: {CKA_VALUE: b"k" * 16},
    )
    monkeypatch.setattr(authenticated_wrap, "generate_random", lambda *_args: b"i" * 12)
    monkeypatch.setattr(
        authenticated_wrap,
        "mech_gcm_message",
        lambda *_args, **_kwargs: SimpleNamespace(buffer_bytes=lambda _name: b"t"),
    )

    def _raise_mechanism_invalid(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_INVALID", int(CKR_MECHANISM_INVALID)
        )

    monkeypatch.setattr(authenticated_wrap, "wrap_key_authenticated", _raise_mechanism_invalid)

    # rs.has_mechanism must report AES_GCM as advertised for this to be a genuine deviation
    # rather than a capability-absence skip.
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "AES_GCM")

    with pytest.raises(pytest.xfail.Exception):
        authenticated_wrap.TestAuthenticatedWrapAAD().test_aes_gcm_unwrap_with_different_aad_rejected(
            rs, "3.2", object()
        )

    records = C.get_records()
    assert records[-1].reason == "not_operational"
    assert records[-1].outcome == "xfail"


def test_valid_leg_wrong_result_uses_unwrap_operation() -> None:
    hard_results: list[C.Classification] = []
    authenticated_wrap._record_discrimination(
        valid_accepted=False,
        valid_value=b"x" * 16,
        invalid_outcome=object(),
        label="tamper",
        operation="C_UnwrapKeyAuthenticated",
        mechanism="CKM_AES_GCM",
        hard_results=hard_results,
    )
    assert [record.reason for record in C.get_records()] == ["wrong_result", "accepted_invalid"]
    assert C.get_records()[0].operation == "C_UnwrapKeyAuthenticated"
    assert C.get_records()[0].mechanism == "CKM_AES_GCM"


def test_missing_valid_leg_does_not_hide_tamper_acceptance() -> None:
    hard_results: list[C.Classification] = []
    authenticated_wrap._record_discrimination(
        valid_accepted=False,
        valid_value=MISSING_ATTRIBUTE,
        invalid_outcome=object(),
        label="tamper",
        operation="C_UnwrapKeyAuthenticated",
        mechanism="CKM_AES_GCM",
        hard_results=hard_results,
    )
    assert [record.reason for record in C.get_records()] == ["accepted_invalid"]
    assert hard_results[0].operation == "C_UnwrapKeyAuthenticated"


def test_missing_valid_leg_readback_keeps_tamper_acceptance_independent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([10, 11, 12, 13])
    monkeypatch.setattr(authenticated_wrap, "gen_aes_key", lambda *_args, **_kwargs: next(handles))
    monkeypatch.setattr(
        authenticated_wrap,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {CKA_VALUE: b"k" * 16} if handle == 11 else {},
    )
    monkeypatch.setattr(authenticated_wrap, "generate_random", lambda *_args: b"i" * 12)
    monkeypatch.setattr(
        authenticated_wrap,
        "mech_gcm_message",
        lambda *_args, **_kwargs: SimpleNamespace(buffer_bytes=lambda _name: b"t" * 16),
    )
    monkeypatch.setattr(
        authenticated_wrap,
        "mech_gcm_message_inherit_tag",
        lambda *_args, **_kwargs: SimpleNamespace(
            buffer_storage=lambda _name: (bytearray(b"t" * 16), 16)
        ),
    )
    monkeypatch.setattr(
        authenticated_wrap, "wrap_key_authenticated", lambda *_args, **_kwargs: b"wrapped"
    )
    monkeypatch.setattr(
        authenticated_wrap,
        "unwrap_key_authenticated",
        lambda *_args, **_kwargs: next(handles),
    )
    destroyed: list[int] = []
    monkeypatch.setattr(
        authenticated_wrap,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        authenticated_wrap.TestAuthenticatedWrap().test_tampered_tag_rejected(
            _rs(), "3.2", object()
        )

    assert destroyed == [12, 13, 10, 11]
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "accepted_invalid"]
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert "producer_mechanism=CKM_AES_GCM" in records[0].label
    assert records[1].operation == "C_UnwrapKeyAuthenticated"
    assert records[1].mechanism == "CKM_AES_GCM"


def test_wrap_target_acquisition_failure_cleans_wrapping_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = iter([10])

    def _gen(*_args: Any, **_kwargs: Any) -> int:
        try:
            return next(calls)
        except StopIteration:
            raise RuntimeError("target acquisition failed")

    monkeypatch.setattr(authenticated_wrap, "gen_aes_key", _gen)
    destroyed: list[int] = []
    monkeypatch.setattr(
        authenticated_wrap,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(RuntimeError, match="target acquisition failed"):
        authenticated_wrap.TestAuthenticatedWrap().test_aes_gcm_wrap_unwrap(_rs(), "3.2")

    assert destroyed == [10]


def test_ecdh_target_acquisition_failure_cleans_recipient_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        authenticated_wrap,
        "_ecdh_aes_kw_recipient_keypair",
        lambda *_args: (10, 11),
    )

    def _gen(*_args: Any, **_kwargs: Any) -> int:
        raise RuntimeError("ECDH target acquisition failed")

    monkeypatch.setattr(authenticated_wrap, "gen_aes_key", _gen)
    destroyed: list[int] = []
    monkeypatch.setattr(
        authenticated_wrap,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "ECDH_AES_KEY_WRAP",
    )

    with pytest.raises(RuntimeError, match="ECDH target acquisition failed"):
        authenticated_wrap.TestEcdhAesKeyWrap().test_ecdh_aes_kw_roundtrip(
            rs,
            object(),
            authenticated_wrap._ECDH_AES_KW_CASES[0],
        )

    assert destroyed == [10, 11]
