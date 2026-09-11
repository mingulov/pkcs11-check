"""Runtime regressions for TLS-family provider output readback classification."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.pack import mech_ssl3_key_mat
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_KEY_TYPE,
    CKA_VALUE,
    CKR_MECHANISM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases import test_ssl3 as ssl3
from pkcs11_check.testcases import test_tls12 as tls12
from pkcs11_check.testcases import test_wtls as wtls
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _rs(*mechanisms: str, raw: Any = None) -> SimpleNamespace:
    advertised = set(mechanisms)
    return SimpleNamespace(
        raw=object() if raw is None else raw,
        sh=1,
        has_mechanism=lambda name: name in advertised,
    )


def test_tls12_missing_derived_value_is_structured_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tls12, "_create_tls_pms", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(tls12, "derive_key", lambda *_args, **_kwargs: 12)
    monkeypatch.setattr(tls12, "read_attributes", lambda *_args, **_kwargs: {})
    destroyed: list[int] = []
    monkeypatch.setattr(
        tls12,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    tls12.TestTLS12MasterKeyDerive().test_master_key_derive(_rs("TLS12_MASTER_KEY_DERIVE"))

    assert destroyed == [12, 11]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    # F6: a plain readback is never stamped with the mechanism that produced the
    # object being read; the producer survives in the label instead.
    assert records[0].mechanism is None
    assert "producer_mechanism=CKM_TLS12_MASTER_KEY_DERIVE" in records[0].label
    assert records[0].detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}
    assert MISSING_ATTRIBUTE is not False


def test_tls12_false_like_derived_value_is_hard_crypto_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tls12, "_create_tls_pms", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(tls12, "derive_key", lambda *_args, **_kwargs: 12)
    monkeypatch.setattr(tls12, "read_attributes", lambda *_args, **_kwargs: {CKA_VALUE: False})
    destroyed: list[int] = []
    monkeypatch.setattr(
        tls12,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        tls12.TestTLS12MasterKeyDerive().test_master_key_derive(_rs("TLS12_MASTER_KEY_DERIVE"))

    assert destroyed == [12, 11]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_TLS12_MASTER_KEY_DERIVE"
    assert record.expected_ckr is None
    assert record.actual_ckr is None
    assert record.detail is not None
    assert record.detail["attribute"]["actual"] == repr(False)


def test_tls12_generated_version_mismatch_uses_generate_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _generate_key(*args: Any) -> int:
        args[-1]._obj.value = 7
        return CKR_OK

    raw = SimpleNamespace(C_GenerateKey=_generate_key)
    monkeypatch.setattr(
        tls12,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_VALUE: b"\x02\x01" + bytes(46)},
    )
    monkeypatch.setattr(tls12, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception):
        tls12.TestTLS10PreMasterKeyGen().test_pre_master_key_gen(
            _rs("TLS_PRE_MASTER_KEY_GEN", raw=raw)
        )

    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_GenerateKey"
    assert record.mechanism == "CKM_TLS_PRE_MASTER_KEY_GEN"


def test_tls12_extended_hash_rejection_preserves_first_leg_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tls12, "_create_tls_pms", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(
        tls12,
        "mech_tls12_extended_master_key_derive",
        lambda *_args, **_kwargs: SimpleNamespace(),
    )
    derives = 0

    def _derive(*_args: Any, **_kwargs: Any) -> int:
        nonlocal derives
        derives += 1
        if derives == 2:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_MECHANISM_INVALID", int(CKR_MECHANISM_INVALID)
            )
        return 12

    monkeypatch.setattr(tls12, "derive_key", _derive)
    reads: list[int] = []

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        return {CKA_VALUE: False}

    monkeypatch.setattr(tls12, "read_attributes", _read)
    destroyed: list[int] = []
    monkeypatch.setattr(
        tls12,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.xfail.Exception):
        tls12.TestTLS12Extended().test_different_session_hashes_produce_different_secrets(
            _rs("TLS12_EXTENDED_MASTER_KEY_DERIVE")
        )

    assert reads == [12]
    assert destroyed == [12, 11]
    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "not_operational"]
    assert records[0].operation == "C_DeriveKey"
    assert records[0].mechanism == "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE"
    assert records[1].operation == "C_DeriveKey"
    assert records[1].mechanism == "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE"
    assert records[1].actual_ckr == "CKR_MECHANISM_INVALID"


def test_tls12_equal_extended_hash_outputs_use_two_leg_relation_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tls12, "_create_tls_pms", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(
        tls12,
        "mech_tls12_extended_master_key_derive",
        lambda *_args, **_kwargs: SimpleNamespace(),
    )
    derived = iter([12, 13])
    monkeypatch.setattr(tls12, "derive_key", lambda *_args, **_kwargs: next(derived))
    monkeypatch.setattr(
        tls12,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_VALUE: b"same-output" + bytes(37)},
    )
    destroyed: list[int] = []
    monkeypatch.setattr(
        tls12,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        tls12.TestTLS12Extended().test_different_session_hashes_produce_different_secrets(
            _rs("TLS12_EXTENDED_MASTER_KEY_DERIVE")
        )

    assert destroyed == [13, 12, 11]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism is None
    assert record.detail is not None
    relation = record.detail["relation"]
    assert relation["operator"] == "must_differ"
    assert relation["left"] == {
        "label": "hash-A",
        "mechanism": "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE",
        "actual": repr(b"same-output" + bytes(37)),
    }
    assert relation["right"] == {
        "label": "hash-B",
        "mechanism": "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE",
        "actual": repr(b"same-output" + bytes(37)),
    }


@pytest.mark.parametrize(
    ("family", "probe", "mechanism"),
    [
        (
            "tls",
            "TLS12_EXTENDED_MASTER_KEY_DERIVE",
            "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE",
        ),
        ("ssl3", "SSL3_PRE_MASTER_KEY_GEN", "CKM_SSL3_PRE_MASTER_KEY_GEN"),
        (
            "wtls",
            "WTLS_SERVER_KEY_AND_MAC_DERIVE",
            "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",
        ),
    ],
)
def test_readback_ckr_is_attribute_failure_for_tls_families(
    monkeypatch: pytest.MonkeyPatch,
    family: str,
    probe: str,
    mechanism: str,
) -> None:
    module: Any
    test_case: Any
    raw: Any = None
    reads: list[int] = []
    if family == "tls":
        module = tls12
        test_case = (
            tls12.TestTLS12Extended().test_different_session_hashes_produce_different_secrets
        )
        monkeypatch.setattr(tls12, "_create_tls_pms", lambda *_args, **_kwargs: 11)
        monkeypatch.setattr(
            tls12,
            "mech_tls12_extended_master_key_derive",
            lambda *_args, **_kwargs: SimpleNamespace(),
        )
        derived = iter([12, 13])
        monkeypatch.setattr(tls12, "derive_key", lambda *_args, **_kwargs: next(derived))
    elif family == "ssl3":
        module = ssl3
        test_case = ssl3.TestSSL3PreMasterKeyGen().test_generate_produces_random_output
        monkeypatch.setattr(ssl3, "_create_generic_secret", lambda *_args, **_kwargs: 11)
        calls = 0

        def _generate_key(*args: Any) -> int:
            nonlocal calls
            calls += 1
            args[-1]._obj.value = 7 if calls == 1 else 8
            return CKR_OK

        raw = SimpleNamespace(C_GenerateKey=_generate_key)
    else:
        module = wtls
        test_case = wtls.TestWTLSKeyAndMacDerive().test_server_and_client_differ
        monkeypatch.setattr(wtls, "_create_generic_secret", lambda *_args, **_kwargs: 11)
        outputs = iter(
            [
                SimpleNamespace(hMacSecret=201, hKey=202),
                SimpleNamespace(hMacSecret=203, hKey=204),
            ]
        )
        monkeypatch.setattr(
            wtls,
            "mech_wtls_key_mat",
            lambda *_args, **_kwargs: SimpleNamespace(key_mat_out=next(outputs)),
        )
        monkeypatch.setattr(wtls, "_derive_key_material_to_params", lambda *_args, **_kwargs: None)

    def _read_error(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        first_handle = 12 if family == "tls" else 7 if family == "ssl3" else 202
        if handle == first_handle:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_MECHANISM_INVALID", int(CKR_MECHANISM_INVALID)
            )
        return {CKA_VALUE: b"client" + bytes(42) if family in {"tls", "ssl3"} else b"client"}

    monkeypatch.setattr(module, "read_attributes", _read_error)
    destroyed: list[int] = []
    monkeypatch.setattr(
        module,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    destroyed_returned: list[int] = []
    monkeypatch.setattr(
        module,
        "destroy_returned_handles",
        lambda _rs, *handles: destroyed_returned.extend(handles),
    )

    test_case(
        _rs(
            probe,
            *("WTLS_CLIENT_KEY_AND_MAC_DERIVE",) if family == "wtls" else (),
            raw=raw,
        )
    )

    if family == "tls":
        assert destroyed == [13, 12, 11]
        assert destroyed_returned == []
        assert reads == [12, 13]
    elif family == "ssl3":
        assert destroyed == [8, 7]
        assert destroyed_returned == []
        assert reads == [7, 8]
    else:
        assert destroyed == [11]
        assert destroyed_returned == [203, 204, 201, 202]
        assert reads == [202, 204]
    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "not_operational"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == mechanism
    assert record.actual_ckr == "CKR_MECHANISM_INVALID"


@pytest.mark.parametrize("module", [tls12, ssl3, wtls])
def test_unlisted_readback_ckr_propagates_without_classification(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
) -> None:
    error = CkrAssertionError("Unexpected CK_RV CKR_MECHANISM_INVALID", int(CKR_MECHANISM_INVALID))
    monkeypatch.setattr(
        module, "read_attributes", lambda *_args, **_kwargs: (_ for _ in ()).throw(error)
    )

    with pytest.raises(CkrAssertionError) as raised:
        module._read_provider_attribute(
            object(),
            1,
            2,
            CKA_VALUE,
            label="readback unexpected CKR",
            mechanism="CKM_TEST",
            error_rvs=(),
        )

    assert raised.value is error
    assert C.get_records() == []


@pytest.mark.parametrize("module", [tls12, ssl3, wtls])
def test_plain_readback_exception_propagates_without_classification(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
) -> None:
    error = ValueError("readback harness failure")
    monkeypatch.setattr(
        module, "read_attributes", lambda *_args, **_kwargs: (_ for _ in ()).throw(error)
    )

    with pytest.raises(ValueError) as raised:
        module._read_provider_attribute(
            object(),
            1,
            2,
            CKA_VALUE,
            label="readback plain exception",
            mechanism="CKM_TEST",
            error_rvs=(),
        )

    assert raised.value is error
    assert C.get_records() == []


def test_ssl3_key_material_reads_independent_outputs_before_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = SimpleNamespace(
        hClientMacSecret=101,
        hServerMacSecret=102,
        hClientKey=103,
        hServerKey=104,
    )
    mechanism = SimpleNamespace(
        key_mat_out=output,
        buffer_bytes=lambda _name: b"\x01" * 16,
    )
    monkeypatch.setattr(ssl3, "_create_generic_secret", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(ssl3, "mech_ssl3_key_mat", lambda *_args, **_kwargs: mechanism)
    monkeypatch.setattr(ssl3, "_ssl3_key_block_reference", lambda *_args, **_kwargs: b"\x01" * 96)
    monkeypatch.setattr(ssl3, "_derive_key_material_to_params", lambda *_args, **_kwargs: None)
    reads: list[int] = []

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        return {} if handle == 101 else {CKA_VALUE: False}

    monkeypatch.setattr(ssl3, "read_attributes", _read)
    monkeypatch.setattr(ssl3, "destroy_returned_handles", lambda *_args: None)
    monkeypatch.setattr(ssl3, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception):
        ssl3.TestSSL3KeyAndMacDerive().test_derive_key_material_exact_vector(
            _rs("SSL3_KEY_AND_MAC_DERIVE")
        )

    assert reads == [101, 102, 103, 104]
    records = C.get_records()
    assert [record.reason for record in records] == [
        "not_operational",
        "wrong_result",
        "wrong_result",
        "wrong_result",
    ]
    # F6: records[0] (missing value) is a plain readback and is never stamped with
    # the mechanism that produced the object being read -- the producer survives in
    # the label instead. records[1:] (malformed present values) are unrelated and
    # keep their mechanism.
    assert [record.mechanism for record in records] == [
        None,
        "CKM_SSL3_KEY_AND_MAC_DERIVE",
        "CKM_SSL3_KEY_AND_MAC_DERIVE",
        "CKM_SSL3_KEY_AND_MAC_DERIVE",
    ]
    assert "producer_mechanism=CKM_SSL3_KEY_AND_MAC_DERIVE" in records[0].label
    assert [record.operation for record in records] == [
        "C_GetAttributeValue",
        "C_DeriveKey",
        "C_DeriveKey",
        "C_DeriveKey",
    ]
    assert all(record.kind == "crypto" for record in records[1:])
    assert all(record.expected_ckr is None and record.actual_ckr is None for record in records)


def test_ssl3_generated_version_mismatch_uses_generate_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _generate_key(*args: Any) -> int:
        args[-1]._obj.value = 7
        return CKR_OK

    raw = SimpleNamespace(C_GenerateKey=_generate_key)
    monkeypatch.setattr(
        ssl3,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_VALUE: b"\x02\x00" + bytes(46)},
    )
    monkeypatch.setattr(ssl3, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception):
        ssl3.TestSSL3PreMasterKeyGen().test_generate_pre_master_key(
            _rs("SSL3_PRE_MASTER_KEY_GEN", raw=raw)
        )

    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_GenerateKey"
    assert record.mechanism == "CKM_SSL3_PRE_MASTER_KEY_GEN"


def test_ssl3_second_generation_rejection_preserves_first_evidence_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def _generate_key(*args: Any) -> int:
        nonlocal calls
        calls += 1
        args[-1]._obj.value = 7 if calls == 1 else 8
        return CKR_OK if calls == 1 else CKR_MECHANISM_INVALID

    raw = SimpleNamespace(C_GenerateKey=_generate_key)
    reads: list[int] = []

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        return {CKA_VALUE: False}

    monkeypatch.setattr(ssl3, "read_attributes", _read)
    destroyed: list[int] = []
    monkeypatch.setattr(
        ssl3,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.xfail.Exception):
        ssl3.TestSSL3PreMasterKeyGen().test_generate_produces_random_output(
            _rs("SSL3_PRE_MASTER_KEY_GEN", raw=raw)
        )

    assert reads == [7]
    assert destroyed == [8, 7]
    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "not_operational"]
    assert records[0].operation == "C_GenerateKey"
    assert records[0].mechanism == "CKM_SSL3_PRE_MASTER_KEY_GEN"
    assert records[1].operation == "C_GenerateKey"
    assert records[1].mechanism == "CKM_SSL3_PRE_MASTER_KEY_GEN"
    assert records[1].actual_ckr == "CKR_MECHANISM_INVALID"


def test_ssl3_iv_output_uses_derive_operation_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = SimpleNamespace(
        hClientMacSecret=101,
        hServerMacSecret=102,
        hClientKey=103,
        hServerKey=104,
    )
    mechanism = SimpleNamespace(
        key_mat_out=output,
        buffer_bytes=lambda _name: b"\x00" * 16,
    )
    expected_block = bytes(range(96))
    monkeypatch.setattr(ssl3, "_create_generic_secret", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(ssl3, "mech_ssl3_key_mat", lambda *_args, **_kwargs: mechanism)
    monkeypatch.setattr(
        ssl3,
        "_ssl3_key_block_reference",
        lambda *_args, **_kwargs: expected_block,
    )
    monkeypatch.setattr(ssl3, "_derive_key_material_to_params", lambda *_args, **_kwargs: None)

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        slices = {101: expected_block[:16], 102: expected_block[16:32]}
        slices.update({103: expected_block[32:48], 104: expected_block[48:64]})
        return {CKA_VALUE: slices[handle]}

    monkeypatch.setattr(ssl3, "read_attributes", _read)
    destroyed: list[int] = []
    monkeypatch.setattr(
        ssl3,
        "destroy_returned_handles",
        lambda _rs, *handles: destroyed.extend(handles),
    )
    monkeypatch.setattr(ssl3, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception):
        ssl3.TestSSL3KeyAndMacDerive().test_derive_key_material_exact_vector(
            _rs("SSL3_KEY_AND_MAC_DERIVE")
        )

    assert destroyed == [101, 102, 103, 104]
    records = C.get_records()
    assert [record.operation for record in records] == ["C_DeriveKey", "C_DeriveKey"]
    assert [record.detail["parameter"]["name"] for record in records if record.detail] == [
        "pIVClient",
        "pIVServer",
    ]
    assert all(record.expected_ckr is None and record.actual_ckr is None for record in records)


@pytest.mark.parametrize(
    "method_name",
    ["test_derive_key_material", "test_derive_key_material_exact_vector"],
)
def test_ssl3_derive_rejection_identifies_derive_operation(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
) -> None:
    output = SimpleNamespace(
        hClientMacSecret=101,
        hServerMacSecret=102,
        hClientKey=103,
        hServerKey=104,
    )
    mechanism = SimpleNamespace(
        key_mat_out=output,
        buffer_bytes=lambda _name: b"\x01" * 16,
    )

    def _reject(*_args: Any, **_kwargs: Any) -> None:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_INVALID", int(CKR_MECHANISM_INVALID)
        )

    monkeypatch.setattr(ssl3, "_create_generic_secret", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(ssl3, "mech_ssl3_key_mat", lambda *_args, **_kwargs: mechanism)
    monkeypatch.setattr(ssl3, "_derive_key_material_to_params", _reject)
    destroyed_returned: list[int] = []
    monkeypatch.setattr(
        ssl3,
        "destroy_returned_handles",
        lambda _rs, *handles: destroyed_returned.extend(handles),
    )
    destroyed_master: list[int] = []
    monkeypatch.setattr(
        ssl3,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed_master.append(handle),
    )

    with pytest.raises(pytest.xfail.Exception):
        getattr(ssl3.TestSSL3KeyAndMacDerive(), method_name)(_rs("SSL3_KEY_AND_MAC_DERIVE"))

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_DeriveKey"
    assert records[0].mechanism == "CKM_SSL3_KEY_AND_MAC_DERIVE"
    assert records[0].actual_ckr == "CKR_MECHANISM_INVALID"
    assert destroyed_returned == [101, 102, 103, 104]
    assert destroyed_master == [11]


def test_ssl3_derive_zero_key_handle_is_structured_lifecycle_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = SimpleNamespace(
        hClientMacSecret=101,
        hServerMacSecret=102,
        hClientKey=0,
        hServerKey=104,
    )
    mechanism = SimpleNamespace(
        key_mat_out=output,
        buffer_bytes=lambda _name: b"\x01" * 16,
    )
    monkeypatch.setattr(ssl3, "_create_generic_secret", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(ssl3, "mech_ssl3_key_mat", lambda *_args, **_kwargs: mechanism)
    monkeypatch.setattr(ssl3, "_derive_key_material_to_params", lambda *_args, **_kwargs: None)
    destroyed_returned: list[int] = []
    monkeypatch.setattr(
        ssl3,
        "destroy_returned_handles",
        lambda _rs, *handles: destroyed_returned.extend(handles),
    )
    destroyed_master: list[int] = []
    monkeypatch.setattr(
        ssl3,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed_master.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        ssl3.TestSSL3KeyAndMacDerive().test_derive_key_material(_rs("SSL3_KEY_AND_MAC_DERIVE"))

    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_SSL3_KEY_AND_MAC_DERIVE"
    assert record.expected_ckr is None and record.actual_ckr == "CKR_OK"
    assert destroyed_returned == [101, 102, 0, 104]
    assert destroyed_master == [11]


def test_tls12_derive_zero_handle_skips_readback_and_cleans_master(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tls12, "_create_tls_pms", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(tls12, "derive_key", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(
        tls12,
        "read_attributes",
        lambda *_args, **_kwargs: pytest.fail("must not read a null derived handle"),
    )
    destroyed: list[int] = []
    monkeypatch.setattr(
        tls12,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        tls12.TestTLS12MasterKeyDerive().test_master_key_derive(_rs("TLS12_MASTER_KEY_DERIVE"))

    assert destroyed == [11]
    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_TLS12_MASTER_KEY_DERIVE"
    assert record.actual_ckr == "CKR_OK"
    assert record.detail == {"handle": {"actual": 0, "expected": "non-zero"}}


def test_ssl3_derive_zero_handle_skips_readback_and_cleans_master(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ssl3, "_create_generic_secret", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(ssl3, "derive_key", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(
        ssl3,
        "read_attributes",
        lambda *_args, **_kwargs: pytest.fail("must not read a null derived handle"),
    )
    destroyed: list[int] = []
    monkeypatch.setattr(
        ssl3,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        ssl3.TestSSL3MasterKeyDerive().test_derive_master_secret(_rs("SSL3_MASTER_KEY_DERIVE"))

    assert destroyed == [11]
    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_SSL3_MASTER_KEY_DERIVE"
    assert record.actual_ckr == "CKR_OK"
    assert record.detail == {"handle": {"actual": 0, "expected": "non-zero"}}


def test_wtls_key_material_zero_handle_is_lifecycle_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mechanism = SimpleNamespace(
        key_mat_out=SimpleNamespace(hMacSecret=0, hKey=202),
        buffer_bytes=lambda _name: b"\x01" * 8,
    )
    monkeypatch.setattr(wtls, "_create_generic_secret", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(wtls, "mech_wtls_key_mat", lambda *_args, **_kwargs: mechanism)
    monkeypatch.setattr(wtls, "_derive_key_material_to_params", lambda *_args, **_kwargs: None)
    destroyed_returned: list[int] = []
    monkeypatch.setattr(
        wtls,
        "destroy_returned_handles",
        lambda _rs, *handles: destroyed_returned.extend(handles),
    )
    destroyed_master: list[int] = []
    monkeypatch.setattr(
        wtls,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed_master.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        wtls.TestWTLSKeyAndMacDerive().test_server_key_and_mac_derive(
            _rs("WTLS_SERVER_KEY_AND_MAC_DERIVE")
        )

    assert destroyed_returned == [0, 202]
    assert destroyed_master == [11]
    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE"
    assert record.actual_ckr == "CKR_OK"
    assert record.detail == {"handle": {"actual": 0, "expected": "non-zero"}}


def test_tls_key_material_zero_handle_is_lifecycle_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mechanism = SimpleNamespace(
        key_mat_out=SimpleNamespace(
            hClientMacSecret=0,
            hServerMacSecret=0,
            hClientKey=0,
            hServerKey=202,
        ),
        buffer_bytes=lambda _name: b"\x01" * 16,
    )
    monkeypatch.setattr(tls12, "_create_tls_pms", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(tls12, "mech_ssl3_key_mat", lambda *_args, **_kwargs: mechanism)
    monkeypatch.setattr(tls12, "_derive_key_material_to_params", lambda *_args, **_kwargs: None)
    destroyed_returned: list[int] = []
    monkeypatch.setattr(
        tls12,
        "destroy_returned_handles",
        lambda _rs, *handles: destroyed_returned.extend(handles),
    )
    destroyed_master: list[int] = []
    monkeypatch.setattr(
        tls12,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed_master.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        tls12.TestTLS10PreMasterKeyGen().test_tls_key_and_mac_derive(_rs("TLS_KEY_AND_MAC_DERIVE"))

    assert destroyed_returned == [0, 0, 0, 202]
    assert destroyed_master == [11]
    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_TLS_KEY_AND_MAC_DERIVE"
    assert record.actual_ckr == "CKR_OK"
    assert record.detail == {"handle": {"actual": 0, "expected": "non-zero"}}


def test_ssl3_exact_vector_requests_two_128_bit_mac_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}
    real_packer = mech_ssl3_key_mat

    def _pack(*args: Any, **kwargs: Any) -> Any:
        mechanism = real_packer(*args, **kwargs)
        observed["mechanism"] = mechanism
        return mechanism

    monkeypatch.setattr(ssl3, "mech_ssl3_key_mat", _pack)
    monkeypatch.setattr(ssl3, "_create_generic_secret", lambda *_args, **_kwargs: 11)

    def _reject(*_args: Any, **_kwargs: Any) -> None:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_INVALID", int(CKR_MECHANISM_INVALID)
        )

    monkeypatch.setattr(
        ssl3,
        "_derive_key_material_to_params",
        _reject,
    )
    monkeypatch.setattr(ssl3, "destroy_returned_handles", lambda *_args: None)
    monkeypatch.setattr(ssl3, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception):
        ssl3.TestSSL3KeyAndMacDerive().test_derive_key_material_exact_vector(
            _rs("SSL3_KEY_AND_MAC_DERIVE")
        )

    mechanism = observed["mechanism"]
    assert mechanism.params.ulMacSizeInBits == 128


def test_tls_family_attribute_access_analyzer_is_clean() -> None:
    """The three migrated modules must preserve explicit missing sentinels."""
    source_root = Path(__file__).resolve().parents[1] / "src" / "pkcs11_check" / "testcases"
    from tests._attribute_access_guard import analyze_paths

    paths = [source_root / name for name in ("test_tls12.py", "test_ssl3.py", "test_wtls.py")]
    assert analyze_paths(paths) == []


def test_wtls_missing_key_type_is_structured_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _generate_key(*args: Any) -> int:
        key_pointer = args[-1]
        key_pointer._obj.value = 7
        return CKR_OK

    raw = SimpleNamespace(C_GenerateKey=_generate_key)
    monkeypatch.setattr(wtls, "read_attributes", lambda *_args, **_kwargs: {})
    destroyed: list[int] = []
    monkeypatch.setattr(
        wtls,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    wtls.TestWTLSPreMasterKeyGen().test_generate_pre_master_key(
        _rs("WTLS_PRE_MASTER_KEY_GEN", raw=raw)
    )

    assert destroyed == [7]
    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_GetAttributeValue"
    # F6: a plain readback is never stamped with the mechanism that produced the
    # object being read; the producer survives in the label instead.
    assert record.mechanism is None
    assert "producer_mechanism=CKM_WTLS_PRE_MASTER_KEY_GEN" in record.label
    assert record.detail == {"attribute": {"name": "CKA_KEY_TYPE", "id": int(CKA_KEY_TYPE)}}


def test_wtls_false_like_key_type_is_present_structured_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _generate_key(*args: Any) -> int:
        key_pointer = args[-1]
        key_pointer._obj.value = 7
        return CKR_OK

    raw = SimpleNamespace(C_GenerateKey=_generate_key)
    monkeypatch.setattr(
        wtls,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_KEY_TYPE: False},
    )
    destroyed: list[int] = []
    monkeypatch.setattr(
        wtls,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        wtls.TestWTLSPreMasterKeyGen().test_generate_pre_master_key(
            _rs("WTLS_PRE_MASTER_KEY_GEN", raw=raw)
        )

    assert destroyed == [7]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.mechanism == "CKM_WTLS_PRE_MASTER_KEY_GEN"
    assert record.operation == "C_GenerateKey"
    assert record.expected_ckr is None
    assert record.actual_ckr is None
    assert record.detail is not None
    assert record.detail["attribute"]["actual"] == repr(False)


def test_wtls_second_generation_rejection_preserves_first_evidence_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def _generate_key(*args: Any) -> int:
        nonlocal calls
        calls += 1
        args[-1]._obj.value = 7 if calls == 1 else 8
        return CKR_OK if calls == 1 else CKR_MECHANISM_INVALID

    raw = SimpleNamespace(C_GenerateKey=_generate_key)
    reads: list[int] = []

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        return {CKA_VALUE: False}

    monkeypatch.setattr(wtls, "read_attributes", _read)
    destroyed: list[int] = []
    monkeypatch.setattr(
        wtls,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.xfail.Exception):
        wtls.TestWTLSPreMasterKeyGen().test_two_generated_keys_differ(
            _rs("WTLS_PRE_MASTER_KEY_GEN", raw=raw)
        )

    assert reads == [7]
    assert destroyed == [8, 7]
    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "not_operational"]
    assert records[0].operation == "C_GenerateKey"
    assert records[0].mechanism == "CKM_WTLS_PRE_MASTER_KEY_GEN"
    assert records[1].operation == "C_GenerateKey"
    assert records[1].mechanism == "CKM_WTLS_PRE_MASTER_KEY_GEN"
    assert records[1].actual_ckr == "CKR_MECHANISM_INVALID"


def test_wtls_generate_ok_without_handle_is_lifecycle_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _generate_key(*_args: Any) -> int:
        return CKR_OK

    raw = SimpleNamespace(C_GenerateKey=_generate_key)
    monkeypatch.setattr(
        wtls,
        "read_attributes",
        lambda *_args, **_kwargs: pytest.fail("must not read an absent generated handle"),
    )
    destroyed: list[int] = []
    monkeypatch.setattr(
        wtls,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        wtls.TestWTLSPreMasterKeyGen().test_generate_pre_master_key(
            _rs("WTLS_PRE_MASTER_KEY_GEN", raw=raw)
        )

    assert destroyed == []
    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_GenerateKey"
    assert record.mechanism == "CKM_WTLS_PRE_MASTER_KEY_GEN"
    assert record.actual_ckr == "CKR_OK"
    assert record.expected_ckr is None
    assert record.detail == {"handle": {"actual": 0, "expected": "non-zero"}}


def test_wtls_key_material_reads_independent_outputs_before_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = iter(
        [
            SimpleNamespace(hMacSecret=201, hKey=202),
            SimpleNamespace(hMacSecret=203, hKey=204),
        ]
    )
    monkeypatch.setattr(wtls, "_create_generic_secret", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(
        wtls,
        "mech_wtls_key_mat",
        lambda *_args, **_kwargs: SimpleNamespace(key_mat_out=next(outputs)),
    )
    monkeypatch.setattr(wtls, "_derive_key_material_to_params", lambda *_args, **_kwargs: None)
    reads: list[int] = []

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        return {} if handle == 202 else {CKA_VALUE: False}

    monkeypatch.setattr(wtls, "read_attributes", _read)
    destroyed_returned: list[int] = []
    monkeypatch.setattr(
        wtls,
        "destroy_returned_handles",
        lambda _rs, *handles: destroyed_returned.extend(handles),
    )
    destroyed_master: list[int] = []
    monkeypatch.setattr(
        wtls,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed_master.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        wtls.TestWTLSKeyAndMacDerive().test_server_and_client_differ(
            _rs("WTLS_SERVER_KEY_AND_MAC_DERIVE", "WTLS_CLIENT_KEY_AND_MAC_DERIVE")
        )

    assert reads == [202, 204]
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "wrong_result"]
    # F6: records[0] (missing value) is a plain readback and is never stamped with
    # the mechanism that produced the object being read; records[1] is an unrelated
    # C_DeriveKey outcome and keeps its mechanism.
    assert [record.mechanism for record in records] == [
        None,
        "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE",
    ]
    assert "producer_mechanism=CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE" in records[0].label
    assert [record.operation for record in records] == [
        "C_GetAttributeValue",
        "C_DeriveKey",
    ]
    assert records[-1].kind == "crypto"
    assert destroyed_returned == [203, 204, 201, 202]
    assert destroyed_master == [11]


def test_wtls_client_derive_rejection_keeps_client_identity_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = iter(
        [
            SimpleNamespace(hMacSecret=201, hKey=202),
            SimpleNamespace(hMacSecret=203, hKey=204),
        ]
    )
    calls = 0

    def _derive(*_args: Any, **_kwargs: Any) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_MECHANISM_INVALID", int(CKR_MECHANISM_INVALID)
            )

    monkeypatch.setattr(wtls, "_create_generic_secret", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(
        wtls,
        "mech_wtls_key_mat",
        lambda *_args, **_kwargs: SimpleNamespace(key_mat_out=next(outputs)),
    )
    monkeypatch.setattr(wtls, "_derive_key_material_to_params", _derive)

    reads: list[int] = []

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        if handle == 202:
            return {CKA_VALUE: False}
        return pytest.fail("client derive rejection must stop client readback")

    monkeypatch.setattr(
        wtls,
        "read_attributes",
        _read,
    )
    destroyed_returned: list[int] = []
    monkeypatch.setattr(
        wtls,
        "destroy_returned_handles",
        lambda _rs, *handles: destroyed_returned.extend(handles),
    )
    destroyed_master: list[int] = []
    monkeypatch.setattr(
        wtls,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed_master.append(handle),
    )

    with pytest.raises(pytest.xfail.Exception):
        wtls.TestWTLSKeyAndMacDerive().test_server_and_client_differ(
            _rs("WTLS_SERVER_KEY_AND_MAC_DERIVE", "WTLS_CLIENT_KEY_AND_MAC_DERIVE")
        )

    assert reads == [202]
    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "not_operational"]
    assert records[0].kind == "crypto"
    assert records[0].operation == "C_DeriveKey"
    assert records[0].mechanism == "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE"
    assert records[0].detail is not None
    assert records[0].detail["attribute"]["actual"] == repr(False)
    assert records[1].operation == "C_DeriveKey"
    assert records[1].mechanism == "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE"
    assert records[1].actual_ckr == "CKR_MECHANISM_INVALID"
    assert destroyed_returned == [203, 204, 201, 202]
    assert destroyed_master == [11]


def test_wtls_equal_server_client_outputs_use_relation_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = iter(
        [
            SimpleNamespace(hMacSecret=201, hKey=202),
            SimpleNamespace(hMacSecret=203, hKey=204),
        ]
    )
    monkeypatch.setattr(wtls, "_create_generic_secret", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(
        wtls,
        "mech_wtls_key_mat",
        lambda *_args, **_kwargs: SimpleNamespace(key_mat_out=next(outputs)),
    )
    monkeypatch.setattr(wtls, "_derive_key_material_to_params", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        wtls,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_VALUE: b"same-output"},
    )
    destroyed_returned: list[int] = []
    monkeypatch.setattr(
        wtls,
        "destroy_returned_handles",
        lambda _rs, *handles: destroyed_returned.extend(handles),
    )
    destroyed_master: list[int] = []
    monkeypatch.setattr(
        wtls,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed_master.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        wtls.TestWTLSKeyAndMacDerive().test_server_and_client_differ(
            _rs("WTLS_SERVER_KEY_AND_MAC_DERIVE", "WTLS_CLIENT_KEY_AND_MAC_DERIVE")
        )

    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism is None
    assert record.detail is not None
    relation = record.detail["relation"]
    assert relation["left"]["mechanism"] == "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE"
    assert relation["right"]["mechanism"] == "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE"
    assert relation["left"]["actual"] == repr(b"same-output")
    assert relation["right"]["actual"] == repr(b"same-output")
    assert destroyed_returned == [203, 204, 201, 202]
    assert destroyed_master == [11]


def test_wtls_strongest_hard_output_kind_wins() -> None:
    metadata = wtls._record_wrong_attribute(
        attr=CKA_KEY_TYPE,
        label="CKM_WTLS_PRE_MASTER_KEY_GEN:CKA_KEY_TYPE readback",
        expected=1,
        actual=2,
        kind="metadata",
        mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
        operation="C_GenerateKey",
    )
    crypto = wtls._record_wrong_attribute(
        attr=CKA_VALUE,
        label="CKM_WTLS_PRE_MASTER_KEY_GEN:CKA_VALUE readback",
        expected=b"expected",
        actual=b"actual",
        kind="crypto",
        mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
        operation="C_GenerateKey",
    )

    with pytest.raises(pytest.fail.Exception, match="CKA_VALUE readback"):
        wtls._raise_strongest([metadata, crypto])

    records = C.get_records()
    assert [record.kind for record in records] == ["metadata", "crypto"]
    assert records[-1].expected_ckr is None and records[-1].actual_ckr is None
