"""Runtime regression tests for the F7 RSA/key-lifecycle attribute-presence migration.

Covers `test_key_lifecycle.py`, `test_key_sizes.py`, `test_rsa_extended.py`,
`test_rsa_key_import.py`, and `test_rsa_key_wrapping.py`: every call site now routes
provider-backed `read_attributes()` results through `attr_or_record()` instead of a bare
subscript/`.get()`. These tests prove, per migrated site *class*:

- an omitted attribute produces a structured record (reason, `operation ==
  "C_GetAttributeValue"`, `mechanism is None`, exact spec_ref) instead of a KeyError/None crash;
- the omission disables only the dependent oracle -- independent work in the same test
  (an already-completed step, or a sibling wrap/unwrap operation) still runs, and handles are
  still destroyed;
- a present-but-wrong value is unaffected by the migration and still fails hard.
"""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_KEY_TYPE,
    CKK_EC,
    CKM_AES_KEY_WRAP,
    CKR_ENCRYPTED_DATA_INVALID,
)
from pkcs11_check.testcases import test_key_lifecycle as lifecycle_case
from pkcs11_check.testcases import test_key_sizes as key_sizes_case
from pkcs11_check.testcases import test_rsa_extended as rsa_extended_case
from pkcs11_check.testcases import test_rsa_key_import as rsa_import_case
from pkcs11_check.testcases import test_rsa_key_wrapping as rsa_wrap_case

_SPEC_REF = "PKCS#11 v3.2 · C_GetAttributeValue"


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session(*, mechanisms: set[str] | None = None) -> Any:
    mechs = mechanisms or set()
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name in mechs)


def _assert_readback_record(record: C.Classification, *, reason: str) -> None:
    assert record.reason == reason
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == _SPEC_REF


def _record_call(calls: list[str], tag: str, value: Any) -> Any:
    """Append `tag` to `calls` and return `value` -- a typed stand-in for the
    `calls.append(tag) or value` idiom (`list.append` returns `None`, which
    `mypy --strict` flags as `func-returns-value` when used as an expression)."""
    calls.append(tag)
    return value


# ---------------------------------------------------------------------------
# test_key_lifecycle.py -- return-early class (export required for a dependent
# import/verify oracle; the independent step before the export already ran).
# ---------------------------------------------------------------------------


def test_rsa_export_import_missing_modulus_stops_before_import_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing CKA_MODULUS/CKA_PUBLIC_EXPONENT records evidence, skips import/verify,
    but the independent sign step still ran and both handles are still destroyed."""
    rs = _session(mechanisms={"RSA_PKCS_KEY_PAIR_GEN"})
    destroyed: list[int] = []
    signed: list[str] = []
    create_object_calls: list[str] = []
    verify_calls: list[str] = []

    monkeypatch.setattr(lifecycle_case, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(
        lifecycle_case,
        "sign_single",
        lambda *_a, **_k: _record_call(signed, "signed", b"\x00" * 256),
    )
    monkeypatch.setattr(lifecycle_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        lifecycle_case,
        "create_object",
        lambda *_a, **_k: _record_call(create_object_calls, "create", 99),
    )
    monkeypatch.setattr(
        lifecycle_case,
        "verify_single",
        lambda *_a, **_k: _record_call(verify_calls, "verify", True),
    )
    monkeypatch.setattr(
        lifecycle_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    lifecycle_case.TestRSAKeyLifecycle().test_rsa_export_import_verify(rs)

    # Independent work (sign) already ran before the export read.
    assert signed == ["signed"]
    # Dependent work (import + verify) never ran -- no evidence to drive it.
    assert create_object_calls == []
    assert verify_calls == []
    # Cleanup still happened for both real handles (imported stayed 0).
    assert destroyed == [11, 12]

    records = C.get_records()
    assert len(records) == 2
    for record in records:
        _assert_readback_record(record, reason="not_operational")


# ---------------------------------------------------------------------------
# test_key_lifecycle.py -- continue-independent-work class (wrap/unwrap still
# execute on a missing readback; only the dependent comparisons are skipped).
# ---------------------------------------------------------------------------


def test_aes_wrap_lifecycle_missing_value_continues_wrap_unwrap_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing CKA_VALUE on either leg records evidence but wrap/unwrap still run,
    only the value-equality assertions are skipped, and every handle is destroyed."""
    rs = _session(mechanisms={"AES_KEY_WRAP"})
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    wrap_calls: list[str] = []
    unwrap_calls: list[str] = []

    handles = iter([21, 22])
    monkeypatch.setattr(lifecycle_case, "require_operational_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(lifecycle_case, "gen_aes_key", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(lifecycle_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        lifecycle_case,
        "wrap_key_recipe",
        lambda *_a, **_k: _record_call(wrap_calls, "wrap", b"wrapped-bytes"),
    )
    monkeypatch.setattr(
        lifecycle_case,
        "unwrap_key_for_mechanism_roundtrip",
        lambda *_a, **_k: _record_call(unwrap_calls, "unwrap", 23),
    )
    monkeypatch.setattr(
        lifecycle_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    lifecycle_case.TestAESKeyWrapLifecycle().test_aes_wrap_unwrap_roundtrip(rs, p11_config=None)

    # Independent wrap/unwrap operations still ran despite the missing readback.
    assert wrap_calls == ["wrap"]
    assert unwrap_calls == ["unwrap"]
    # All three handles (wrap key, target, unwrapped) were destroyed.
    assert destroyed == [21, 22, 23]

    records = C.get_records()
    assert len(records) == 2
    for record in records:
        _assert_readback_record(record, reason="not_operational")


# ---------------------------------------------------------------------------
# test_key_sizes.py -- simple single-guard class (the readback is the test's
# sole assertion; a miss just skips that assertion, no crash).
# ---------------------------------------------------------------------------


def test_aes_generate_missing_key_type_skips_only_the_assertion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session()
    destroyed: list[int] = []
    monkeypatch.setattr(key_sizes_case, "gen_aes_key_or_xfail", lambda *_a, **_k: 31)
    monkeypatch.setattr(key_sizes_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        key_sizes_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    key_sizes_case.TestAESKeySizes().test_aes_generate(rs, key_bits=128)

    assert destroyed == [31]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")


def test_rsa_generate_missing_modulus_skips_only_the_length_assertion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session()
    destroyed: list[int] = []
    monkeypatch.setattr(key_sizes_case, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (41, 42))
    monkeypatch.setattr(key_sizes_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        key_sizes_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    key_sizes_case.TestRSAKeySizes().test_rsa_generate(rs, key_bits=2048)

    assert destroyed == [41, 42]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")


# ---------------------------------------------------------------------------
# test_rsa_extended.py -- X9.31 keypair-gen guard class (isinstance/length
# checks skip cleanly on a missing readback).
# ---------------------------------------------------------------------------


def test_x931_keypair_missing_modulus_skips_isinstance_and_length_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session(mechanisms={"RSA_X9_31_KEY_PAIR_GEN"})
    destroyed: list[int] = []
    monkeypatch.setattr(rsa_extended_case, "_rsa_keypair", lambda *_a, **_k: (51, 52))
    monkeypatch.setattr(rsa_extended_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        rsa_extended_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    rsa_extended_case.TestRSAX931KeyPairGen().test_generate_keypair(rs)

    assert destroyed == [51, 52]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")


# ---------------------------------------------------------------------------
# test_rsa_extended.py -- continue-independent-work class for CKM_RSA_AES_KEY_WRAP
# (wrap/unwrap still execute; only the material-equality compare is skipped).
# ---------------------------------------------------------------------------


def test_rsa_aes_wrap_missing_value_continues_wrap_unwrap_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session(mechanisms={"RSA_AES_KEY_WRAP"})
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    wrap_calls: list[str] = []
    unwrap_calls: list[str] = []

    monkeypatch.setattr(rsa_extended_case, "_rsa_keypair", lambda *_a, **_k: (61, 62))
    monkeypatch.setattr(rsa_extended_case, "_make_extractable_aes", lambda *_a, **_k: 63)
    monkeypatch.setattr(rsa_extended_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        rsa_extended_case,
        "wrap_key",
        lambda *_a, **_k: _record_call(wrap_calls, "wrap", b"wrapped-blob"),
    )
    monkeypatch.setattr(
        rsa_extended_case,
        "unwrap_key_for_mechanism_roundtrip",
        lambda *_a, **_k: _record_call(unwrap_calls, "unwrap", 64),
    )
    monkeypatch.setattr(
        rsa_extended_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    rsa_extended_case.TestRSAAESKeyWrap().test_wrap_unwrap_aes128(rs, p11_config=None)

    assert wrap_calls == ["wrap"]
    assert unwrap_calls == ["unwrap"]
    assert destroyed == [64, 61, 62, 63]

    records = C.get_records()
    assert len(records) == 2
    for record in records:
        _assert_readback_record(record, reason="not_operational")


# ---------------------------------------------------------------------------
# test_rsa_extended.py -- aggregate-oracle class (fix-round-1): a missing
# roundtrip readback must neither fabricate a crypto break for a conformant
# provider, nor suppress a real, independently observable forgery-acceptance.
# ---------------------------------------------------------------------------


def test_tampered_blob_missing_value_and_clean_rejection_is_not_a_crypto_break(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Omitted CKA_VALUE plus a clean tamper rejection must NOT fabricate a
    crypto/CRITICAL `accepted_invalid` verdict against a conformant provider."""
    rs = _session(mechanisms={"RSA_AES_KEY_WRAP"})
    destroyed: list[int] = []
    monkeypatch.setattr(rsa_extended_case, "_rsa_keypair", lambda *_a, **_k: (111, 112))
    monkeypatch.setattr(rsa_extended_case, "_make_extractable_aes", lambda *_a, **_k: 113)
    monkeypatch.setattr(rsa_extended_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(rsa_extended_case, "wrap_key", lambda *_a, **_k: b"\x00" * 10)

    def _unwrap(*_args: Any, **kwargs: Any) -> int:
        if kwargs.get("purpose") == "RSA-AES-KEY-WRAP unwrap (valid leg)":
            return 114
        raise CkrAssertionError("tampered blob cleanly rejected", int(CKR_ENCRYPTED_DATA_INVALID))

    monkeypatch.setattr(rsa_extended_case, "unwrap_key_for_mechanism_roundtrip", _unwrap)
    monkeypatch.setattr(
        rsa_extended_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    rsa_extended_case.TestRSAAESKeyWrap().test_tampered_blob_rejected(rs, p11_config=None)

    # Only the two not_operational readback records exist -- no fabricated
    # crypto/CRITICAL verdict from the omission alone.
    records = C.get_records()
    assert len(records) == 2
    for record in records:
        _assert_readback_record(record, reason="not_operational")
        assert record.kind == "metadata"
    assert destroyed == [114, 111, 112, 113]


def test_tampered_blob_missing_value_and_forgery_acceptance_still_fails_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Omitted CKA_VALUE must NOT suppress a real, independently observable
    forgery-acceptance: the tamper-acceptance finding must still fire, with its
    own summary, even though the roundtrip-material oracle is unverifiable."""
    rs = _session(mechanisms={"RSA_AES_KEY_WRAP"})
    destroyed: list[int] = []
    monkeypatch.setattr(rsa_extended_case, "_rsa_keypair", lambda *_a, **_k: (121, 122))
    monkeypatch.setattr(rsa_extended_case, "_make_extractable_aes", lambda *_a, **_k: 123)
    monkeypatch.setattr(rsa_extended_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(rsa_extended_case, "wrap_key", lambda *_a, **_k: b"\x00" * 10)

    def _unwrap(*_args: Any, **kwargs: Any) -> int:
        if kwargs.get("purpose") == "RSA-AES-KEY-WRAP unwrap (valid leg)":
            return 124
        return 125  # tampered blob ACCEPTED -- forged/confused input, no readback needed

    monkeypatch.setattr(rsa_extended_case, "unwrap_key_for_mechanism_roundtrip", _unwrap)
    monkeypatch.setattr(
        rsa_extended_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(pytest.fail.Exception, match="accepted the tampered/forged/confused input"):
        rsa_extended_case.TestRSAAESKeyWrap().test_tampered_blob_rejected(rs, p11_config=None)

    records = C.get_records()
    assert len(records) == 3
    assert records[0].reason == "not_operational"
    assert records[1].reason == "not_operational"
    assert records[2].reason == "accepted_invalid"
    assert records[2].kind == "crypto"
    assert destroyed == [124, 125, 121, 122, 123]


# ---------------------------------------------------------------------------
# test_rsa_key_import.py -- assert_correct guard class, and its
# present-but-wrong-value counterpart (must stay hard, unaffected by F7).
# ---------------------------------------------------------------------------


def test_rsa_public_import_missing_key_type_skips_assert_correct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session()
    destroyed: list[int] = []
    monkeypatch.setattr(rsa_import_case, "import_rsa_public_key_negotiated", lambda *_a, **_k: 71)
    monkeypatch.setattr(rsa_import_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        rsa_import_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    rsa_import_case.TestRSAPublicKeyImport().test_import_rsa_public_key(rs)

    assert destroyed == [71]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")


def test_rsa_public_import_wrong_key_type_still_fails_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-wrong CKA_KEY_TYPE is unaffected by the F7 migration: it must
    still raise a hard `wrong_result` failure via `assert_correct`, not be swallowed."""
    rs = _session()
    monkeypatch.setattr(rsa_import_case, "import_rsa_public_key_negotiated", lambda *_a, **_k: 72)
    monkeypatch.setattr(
        rsa_import_case, "read_attributes", lambda *_a, **_k: {CKA_KEY_TYPE: CKK_EC}
    )
    monkeypatch.setattr(rsa_import_case, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.fail.Exception, match="output does not match known answer"):
        rsa_import_case.TestRSAPublicKeyImport().test_import_rsa_public_key(rs)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"


def test_rsa_import_local_flag_missing_is_honest_deviation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_LOCAL is optional/informational metadata: the migration must preserve the
    file's existing `honest_deviation` reason for its omission."""
    rs = _session()
    destroyed: list[int] = []
    monkeypatch.setattr(rsa_import_case, "import_rsa_public_key_negotiated", lambda *_a, **_k: 73)
    monkeypatch.setattr(rsa_import_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        rsa_import_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    rsa_import_case.TestRSAPrivateKeyImport().test_imported_key_local_flag_false(rs)

    assert destroyed == [73]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="honest_deviation")
    # The pre-migration classify() call's spec citation is preserved as bounded
    # detail on the generic attr_or_record() omission record.
    assert records[0].detail is not None
    assert records[0].detail["spec"] == "PKCS#11 §4.x requires CKA_LOCAL=False on import"


# ---------------------------------------------------------------------------
# test_rsa_key_wrapping.py -- continue-independent-work class (mirrors the
# rsa_extended.py wrap/unwrap pattern for CKM_RSA_PKCS).
# ---------------------------------------------------------------------------


def test_rsa_pkcs_wrap_missing_value_continues_wrap_unwrap_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session(mechanisms={"RSA_PKCS"})
    destroyed: list[int] = []
    wrap_calls: list[str] = []
    unwrap_calls: list[str] = []

    monkeypatch.setattr(rsa_wrap_case, "_make_rsa_pair", lambda *_a, **_k: (81, 82))
    monkeypatch.setattr(rsa_wrap_case, "_make_extractable_aes", lambda *_a, **_k: 83)
    monkeypatch.setattr(rsa_wrap_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        rsa_wrap_case,
        "wrap_key_recipe",
        lambda *_a, **_k: _record_call(wrap_calls, "wrap", b"\x00" * 256),
    )
    monkeypatch.setattr(
        rsa_wrap_case,
        "unwrap_key_for_mechanism_roundtrip",
        lambda *_a, **_k: _record_call(unwrap_calls, "unwrap", 84),
    )
    monkeypatch.setattr(
        rsa_wrap_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    rsa_wrap_case.TestRSAPKCSWrap().test_wrap_unwrap_aes128(rs, p11_config=None)

    assert wrap_calls == ["wrap"]
    assert unwrap_calls == ["unwrap"]
    assert destroyed == [84, 81, 82, 83]

    # Only the two CKA_VALUE readbacks are recorded -- the `wrapped ==
    # original_value` confidentiality check must not fire from a sentinel compare.
    records = C.get_records()
    assert len(records) == 2
    for record in records:
        _assert_readback_record(record, reason="not_operational")


# ---------------------------------------------------------------------------
# test_rsa_key_wrapping.py -- policy-gate class (the `.get()` -> attr_or_record
# substitution feeding a `claimed` boolean gate), with stale-mechanism
# scaffolding proving the readback record stays mechanism-free.
# ---------------------------------------------------------------------------


def test_non_extractable_wrap_missing_extractable_drops_stale_mechanism_and_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session()
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    monkeypatch.setattr(rsa_wrap_case, "read_attributes", lambda *_a, **_k: {})

    with pytest.raises(pytest.xfail.Exception, match="did not honour CKA_EXTRACTABLE=False"):
        rsa_wrap_case.TestNonExtractableWrapRefusal._check_non_extractable(
            rs, 91, 92, CKM_AES_KEY_WRAP, "CKM_AES_KEY_WRAP"
        )

    records = C.get_records()
    assert len(records) == 2
    _assert_readback_record(records[0], reason="honest_deviation")
