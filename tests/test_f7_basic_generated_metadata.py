"""Runtime regressions for F7 slice 05: basic generated metadata.

Covers the attribute-presence migration in test_buffers.py, test_encrypt.py,
test_errors.py, test_mechanism_fuzz.py, test_sign.py, test_stateful.py, and
test_token_objects.py -- proving each migrated site class produces a structured,
mechanism-free readback record on omission (never a KeyError or a silent None),
that the omission never blocks an *independent* check in the same test, that
handles are still destroyed, and that a present-but-malformed value stays hard.
"""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKA_ENCRYPT, CKA_KEY_TYPE, CKA_TOKEN, CKA_VALUE, CKK_AES
from pkcs11_check.testcases import (
    test_buffers,
    test_encrypt,
    test_errors,
    test_mechanism_fuzz,
    test_sign,
    test_stateful,
    test_token_objects,
)

_SPEC_REF = "PKCS#11 v3.2 · C_GetAttributeValue"


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _assert_readback_record(rec: C.Classification, *, reason: str) -> None:
    assert rec.reason == reason
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == _SPEC_REF


# --------------------------------------------------------------------------
# test_buffers.py -- CKA_VALUE readback verifying an import roundtrip
# --------------------------------------------------------------------------


def test_buffers_missing_value_is_not_operational_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    monkeypatch.setattr(test_buffers, "import_secret_key", lambda *_a, **_k: 42)
    monkeypatch.setattr(test_buffers, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(test_buffers, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    session = SimpleNamespace(raw=object(), sh=1)
    test_buffers.TestKeyImportBufferSizes().test_aes_128(session)

    assert destroyed == [42]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")


def test_buffers_present_value_still_asserted(monkeypatch: pytest.MonkeyPatch) -> None:
    """A present CKA_VALUE that mismatches the import stays a hard assertion failure."""
    destroyed: list[int] = []
    monkeypatch.setattr(test_buffers, "import_secret_key", lambda *_a, **_k: 42)
    monkeypatch.setattr(
        test_buffers, "read_attributes", lambda *_a, **_k: {CKA_VALUE: b"\x99" * 16}
    )
    monkeypatch.setattr(test_buffers, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    session = SimpleNamespace(raw=object(), sh=1)
    with pytest.raises(AssertionError):
        test_buffers.TestKeyImportBufferSizes().test_aes_128(session)

    # cleanup still ran even though the assertion failed inside the try block
    assert destroyed == [42]
    assert C.get_records() == []


# --------------------------------------------------------------------------
# test_encrypt.py -- CKA_KEY_TYPE readback verifying generated key identity
# --------------------------------------------------------------------------


def test_encrypt_missing_key_type_is_not_operational_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    monkeypatch.setattr(test_encrypt, "_require_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_encrypt, "_gen_aes_key_or_xfail", lambda *_a, **_k: 55)
    monkeypatch.setattr(test_encrypt, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(test_encrypt, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    session = SimpleNamespace(raw=object(), sh=1)
    test_encrypt.TestAESEncryption().test_aes_key_sizes(session, key_bits=128)

    assert destroyed == [55]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")


# --------------------------------------------------------------------------
# test_errors.py -- CKA_KEY_TYPE (not_operational) and CKA_ENCRYPT
# (honest_deviation) are independent checks in the same test
# --------------------------------------------------------------------------


def test_errors_missing_key_type_does_not_block_independent_encrypt_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_errors, "_gen_aes_key_or_xfail", lambda *_a, **_k: 77)
    monkeypatch.setattr(test_errors, "read_attributes", lambda *_a, **_k: {CKA_ENCRYPT: True})
    monkeypatch.setattr(test_errors, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    session = SimpleNamespace(raw=object(), sh=1)
    # No exception: the CKA_ENCRYPT check ran and passed despite CKA_KEY_TYPE missing.
    test_errors.TestKeyLifecycle().test_key_attribute_access(session)

    assert destroyed == [77]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")


def test_errors_missing_encrypt_flag_is_honest_deviation_and_independent_of_key_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_errors, "_gen_aes_key_or_xfail", lambda *_a, **_k: 78)
    monkeypatch.setattr(test_errors, "read_attributes", lambda *_a, **_k: {CKA_KEY_TYPE: CKK_AES})
    monkeypatch.setattr(test_errors, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    session = SimpleNamespace(raw=object(), sh=1)
    test_errors.TestKeyLifecycle().test_key_attribute_access(session)

    assert destroyed == [78]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="honest_deviation")


# --------------------------------------------------------------------------
# test_mechanism_fuzz.py -- hostile-input probe: destroy_quietly runs even
# without a try/finally wrapper, and the CKA_KEY_TYPE sanity check stays hard
# when the attribute is present but malformed.
# --------------------------------------------------------------------------


class _RawGenerateKeyOk:
    def C_GenerateKey(  # noqa: N802
        self, _sh: int, _mech: Any, _tmpl: Any, _count: int, out: Any
    ) -> int:
        out._obj.value = 88
        return 0


def test_mechanism_fuzz_missing_key_type_is_not_operational_and_still_destroys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_mechanism_fuzz, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_mechanism_fuzz, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )

    session = SimpleNamespace(raw=_RawGenerateKeyOk(), sh=1)
    test_mechanism_fuzz.TestKeyGenParameterFuzz().test_aes_keygen_with_random_param(
        session, b"\x00"
    )

    # destroy_quietly is called unconditionally after the check (no try/finally
    # around this site) -- proving the migration did not introduce a leak.
    assert destroyed == [88]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")


def test_mechanism_fuzz_present_but_none_key_type_stays_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(
        test_mechanism_fuzz, "read_attributes", lambda *_a, **_k: {CKA_KEY_TYPE: None}
    )
    monkeypatch.setattr(
        test_mechanism_fuzz, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )

    session = SimpleNamespace(raw=_RawGenerateKeyOk(), sh=1)
    with pytest.raises(AssertionError):
        test_mechanism_fuzz.TestKeyGenParameterFuzz().test_aes_keygen_with_random_param(
            session, b"\x00"
        )

    # present-but-malformed never gets recorded as an omission
    assert C.get_records() == []


# --------------------------------------------------------------------------
# test_sign.py -- CKA_PRIME/CKA_SUBPRIME/CKA_BASE block the downstream DSA
# keypair generation (taint_escape avoidance) and cleanup still runs.
# --------------------------------------------------------------------------


class _RawDSAParamGen:
    def __init__(self) -> None:
        self.keypair_calls = 0

    def C_GenerateKey(  # noqa: N802
        self, _sh: int, _mech: Any, _tmpl: Any, _count: int, out: Any
    ) -> int:
        out._obj.value = 501
        return 0

    def C_GenerateKeyPair(self, *_args: Any, **_kwargs: Any) -> int:  # noqa: N802
        self.keypair_calls += 1
        return 0


def test_sign_missing_dsa_domain_params_blocks_keypair_gen_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    monkeypatch.setattr(test_sign, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(test_sign, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    raw = _RawDSAParamGen()
    session = SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)
    test_sign.TestDSASignature().test_dsa_generate_and_sign(session)

    # all three domain-parameter attributes were resolved independently before the
    # blocking check -- each omission is its own record
    records = C.get_records()
    assert len(records) == 3
    for rec in records:
        _assert_readback_record(rec, reason="not_operational")

    # the dependent keypair generation never ran with missing domain parameters
    assert raw.keypair_calls == 0
    # only the domain-parameter object was allocated/destroyed; pub/priv stayed 0
    assert destroyed == [501]


# --------------------------------------------------------------------------
# test_stateful.py -- a missing CKA_KEY_TYPE on one key in a loop does not
# block the same check on sibling keys, nor the independent encrypt/decrypt,
# random, and digest work later in the same test; final cleanup still runs.
# --------------------------------------------------------------------------


def test_stateful_missing_key_type_on_one_key_continues_independent_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter(range(1, 6))
    destroyed: list[int] = []

    monkeypatch.setattr(test_stateful, "require_operational_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_stateful, "_gen_stateful_aes_key", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(test_stateful, "encrypt_single", lambda _raw, _sh, _key, _mech, pt: pt)
    monkeypatch.setattr(test_stateful, "decrypt_single", lambda _raw, _sh, _key, _mech, ct: ct)
    monkeypatch.setattr(test_stateful, "generate_random", lambda _raw, _sh, n: bytes(n))
    monkeypatch.setattr(test_stateful, "digest_single", lambda _raw, _sh, _mech, _data: bytes(32))

    def _fake_read_attributes(_raw: Any, _sh: Any, handle: int, _attrs: Any) -> dict[Any, Any]:
        # only the first key omits CKA_KEY_TYPE; the rest report it normally
        if handle == 1:
            return {}
        return {CKA_KEY_TYPE: CKK_AES}

    monkeypatch.setattr(test_stateful, "read_attributes", _fake_read_attributes)
    monkeypatch.setattr(test_stateful, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    session = SimpleNamespace(raw=object(), sh=1)
    # No exception: the CKA_KEY_TYPE loop, the encrypt/decrypt continuation, the
    # random check, and the digest check all ran to completion.
    test_stateful.test_generate_use_destroy_cycle(session)

    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")
    # all 5 keys were destroyed exactly once (3 mid-test, 2 in the finally block)
    assert sorted(destroyed) == [1, 2, 3, 4, 5]


# --------------------------------------------------------------------------
# test_token_objects.py -- CKA_TOKEN readback (honest_deviation) does not
# block the independent find-by-label check in the same test.
# --------------------------------------------------------------------------


def test_token_objects_missing_token_flag_does_not_block_find_by_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_token_objects, "gen_aes_key", lambda *_a, **_k: 99)
    monkeypatch.setattr(test_token_objects, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(test_token_objects, "find_objects", lambda *_a, **_k: [1])
    monkeypatch.setattr(
        test_token_objects, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )

    session = SimpleNamespace(raw=object(), sh=1)
    # No exception: find_objects ran and "found" the object despite CKA_TOKEN missing.
    test_token_objects.TestTokenObjectLifecycle().test_create_token_aes_key(session)

    assert destroyed == [99]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="honest_deviation")


def test_token_objects_missing_token_flag_on_one_object_leaves_the_other_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([201, 202])
    destroyed: list[int] = []

    monkeypatch.setattr(test_token_objects, "gen_aes_key", lambda *_a, **_k: next(handles))

    def _fake_read_attributes(_raw: Any, _sh: Any, handle: int, _attrs: Any) -> dict[Any, Any]:
        if handle == 201:
            return {}
        return {CKA_TOKEN: False}

    monkeypatch.setattr(test_token_objects, "read_attributes", _fake_read_attributes)
    monkeypatch.setattr(
        test_token_objects, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )

    session = SimpleNamespace(raw=object(), sh=1)
    # No exception: the session-object CKA_TOKEN check (False) still ran and passed.
    test_token_objects.TestTokenObjectAttributes().test_token_flag_readable(session)

    assert sorted(destroyed) == [201, 202]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="honest_deviation")
