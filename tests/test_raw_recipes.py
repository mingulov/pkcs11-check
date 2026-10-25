"""Tests for raw recipe helpers."""

from __future__ import annotations

import ctypes
import sys
from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    copy_object,
    decapsulate_key,
    decrypt_multipart,
    decrypt_single,
    derive_key,
    destroy_quietly,
    digest_multipart,
    digest_single,
    encapsulate_key,
    encrypt_multipart,
    encrypt_single,
    find_objects,
    gen_aes_key,
    gen_ec_keypair,
    gen_rsa_keypair,
    generate_random,
    get_object_size,
    import_secret_key,
    init_pin,
    init_token,
    message_decrypt,
    message_encrypt,
    quick_session,
    read_attributes,
    restore_operation_state,
    save_operation_state,
    seed_random,
    set_attributes,
    set_pin,
    sign_multipart,
    sign_single,
    unwrap_key,
    unwrap_key_authenticated,
    verify_multipart,
    verify_recover_single,
    verify_single,
    wrap_key,
    wrap_key_authenticated,
)


class TestEcCurveEncoding:
    def test_p256_returns_der_oid(self) -> None:
        result = encode_named_curve_parameters("secp256r1")
        assert isinstance(result, bytes)
        assert len(result) == 10  # OID 1.2.840.10045.3.1.7 DER-encoded
        assert result[0] == 0x06  # ASN.1 OID tag

    def test_p384_returns_der_oid(self) -> None:
        result = encode_named_curve_parameters("secp384r1")
        assert isinstance(result, bytes)
        assert result[0] == 0x06

    def test_p521_returns_der_oid(self) -> None:
        result = encode_named_curve_parameters("secp521r1")
        assert isinstance(result, bytes)
        assert result[0] == 0x06

    def test_ed25519_returns_der_oid(self) -> None:
        result = encode_named_curve_parameters("ed25519")
        assert result == bytes([0x06, 0x03, 0x2B, 0x65, 0x70])

    def test_ed448_returns_der_oid(self) -> None:
        result = encode_named_curve_parameters("ed448")
        assert result == bytes([0x06, 0x03, 0x2B, 0x65, 0x71])

    def test_x25519_returns_der_oid(self) -> None:
        result = encode_named_curve_parameters("x25519")
        assert result == bytes([0x06, 0x03, 0x2B, 0x65, 0x6E])

    def test_x448_returns_der_oid(self) -> None:
        result = encode_named_curve_parameters("x448")
        assert result == bytes([0x06, 0x03, 0x2B, 0x65, 0x6F])

    def test_alias_prime256v1(self) -> None:
        p256 = encode_named_curve_parameters("secp256r1")
        assert encode_named_curve_parameters("prime256v1") == p256

    def test_alias_p256(self) -> None:
        assert encode_named_curve_parameters("P-256") == encode_named_curve_parameters("secp256r1")

    def test_unknown_curve_raises(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="Unknown curve"):
            encode_named_curve_parameters("not-a-real-curve")


class TestRawFixtureSignatures:
    def test_raw_has_mechanism_callable(self) -> None:
        from pkcs11_check.raw_fixtures import raw_has_mechanism

        assert callable(raw_has_mechanism)

    def test_raw_session_fixture_exists(self) -> None:
        from pkcs11_check.raw_fixtures import raw_session

        assert callable(raw_session)

    def test_raw_pkcs11_fixture_exists(self) -> None:
        from pkcs11_check.raw_fixtures import raw_pkcs11

        assert callable(raw_pkcs11)


class TestRecipeSignatures:
    def test_quick_session_callable(self) -> None:
        assert callable(quick_session)

    def test_gen_aes_key_callable(self) -> None:
        assert callable(gen_aes_key)

    def test_gen_rsa_keypair_callable(self) -> None:
        assert callable(gen_rsa_keypair)

    def test_gen_ec_keypair_callable(self) -> None:
        assert callable(gen_ec_keypair)

    def test_import_secret_key_callable(self) -> None:
        assert callable(import_secret_key)

    def test_destroy_quietly_callable(self) -> None:
        assert callable(destroy_quietly)

    def test_encrypt_single_callable(self) -> None:
        assert callable(encrypt_single)

    def test_sign_single_callable(self) -> None:
        assert callable(sign_single)

    def test_decrypt_single_callable(self) -> None:
        assert callable(decrypt_single)

    def test_verify_single_callable(self) -> None:
        assert callable(verify_single)

    def test_digest_single_callable(self) -> None:
        assert callable(digest_single)

    def test_read_attributes_callable(self) -> None:
        assert callable(read_attributes)

    def test_get_object_size_callable(self) -> None:
        assert callable(get_object_size)

    def test_find_objects_callable(self) -> None:
        assert callable(find_objects)

    def test_wrap_key_callable(self) -> None:
        assert callable(wrap_key)

    def test_unwrap_key_callable(self) -> None:
        assert callable(unwrap_key)

    def test_derive_key_callable(self) -> None:
        assert callable(derive_key)

    def test_generate_random_callable(self) -> None:
        assert callable(generate_random)

    def test_copy_object_callable(self) -> None:
        assert callable(copy_object)

    def test_set_attributes_callable(self) -> None:
        assert callable(set_attributes)

    def test_encrypt_multipart_callable(self) -> None:
        assert callable(encrypt_multipart)

    def test_decrypt_multipart_callable(self) -> None:
        assert callable(decrypt_multipart)

    def test_sign_multipart_callable(self) -> None:
        assert callable(sign_multipart)

    def test_verify_multipart_callable(self) -> None:
        assert callable(verify_multipart)

    def test_digest_multipart_callable(self) -> None:
        assert callable(digest_multipart)

    def test_save_operation_state_callable(self) -> None:
        assert callable(save_operation_state)

    def test_restore_operation_state_callable(self) -> None:
        assert callable(restore_operation_state)

    def test_init_token_callable(self) -> None:
        assert callable(init_token)

    def test_init_pin_callable(self) -> None:
        assert callable(init_pin)

    def test_set_pin_callable(self) -> None:
        assert callable(set_pin)

    def test_seed_random_callable(self) -> None:
        assert callable(seed_random)

    def test_message_encrypt_callable(self) -> None:
        assert callable(message_encrypt)

    def test_message_decrypt_callable(self) -> None:
        assert callable(message_decrypt)

    def test_encapsulate_key_callable(self) -> None:
        assert callable(encapsulate_key)

    def test_decapsulate_key_callable(self) -> None:
        assert callable(decapsulate_key)

    def test_wrap_key_authenticated_callable(self) -> None:
        assert callable(wrap_key_authenticated)

    def test_unwrap_key_authenticated_callable(self) -> None:
        assert callable(unwrap_key_authenticated)


def test_get_session_info_returns_struct_fields() -> None:
    from pkcs11_check.raw.recipes import get_session_info
    from pkcs11_check.raw.types_std import CKR_OK

    class FakeRaw:
        def C_GetSessionInfo(self, session: int, info) -> int:  # noqa: N802
            info._obj.slotID = 42
            info._obj.state = 1
            info._obj.flags = 0x04
            info._obj.ulDeviceError = 0
            return CKR_OK

    result = get_session_info(FakeRaw(), 1)
    assert result == {"slot_id": 42, "state": 1, "flags": 0x04, "device_error": 0}


def test_get_mechanism_info_returns_struct_fields() -> None:
    from pkcs11_check.raw.recipes import get_mechanism_info
    from pkcs11_check.raw.types_std import CKR_OK

    class FakeRaw:
        def C_GetMechanismInfo(self, slot_id: int, mech: int, info) -> int:  # noqa: N802
            info._obj.ulMinKeySize = 128
            info._obj.ulMaxKeySize = 256
            info._obj.flags = 0x01
            return CKR_OK

    result = get_mechanism_info(FakeRaw(), 0, 0x01)
    assert result == {"min_key_size": 128, "max_key_size": 256, "flags": 0x01}


def test_get_slot_info_returns_struct_fields() -> None:
    from pkcs11_check.raw.recipes import get_slot_info
    from pkcs11_check.raw.types_std import CK_VERSION, CKR_OK

    class FakeRaw:
        def C_GetSlotInfo(self, slot_id: int, info) -> int:  # noqa: N802
            info._obj.flags = 0x03
            info._obj.hardwareVersion = CK_VERSION(2, 1)
            info._obj.firmwareVersion = CK_VERSION(1, 0)
            return CKR_OK

    result = get_slot_info(FakeRaw(), 0)
    assert result["flags"] == 0x03
    assert result["hardware_version"] == (2, 1)
    assert result["firmware_version"] == (1, 0)


def test_digest_single_with_key_calls_init_key_final() -> None:
    from pkcs11_check.raw.recipes import digest_single_with_key
    from pkcs11_check.raw.types_std import CKM_SHA224, CKR_OK

    calls: list[str] = []

    class FakeRaw:
        def C_DigestInit(self, session, mech) -> int:  # noqa: N802
            calls.append("init")
            return CKR_OK

        def C_DigestKey(self, session, key) -> int:  # noqa: N802
            calls.append("key")
            return CKR_OK

        def C_DigestFinal(self, session, out, out_len):  # noqa: N802
            calls.append("final")
            if out is None:
                out_len._obj.value = 4
                return CKR_OK
            out[0] = 0x01
            out[1] = 0x02
            out[2] = 0x03
            out[3] = 0x04
            out_len._obj.value = 4
            return CKR_OK

    result = digest_single_with_key(FakeRaw(), 1, CKM_SHA224, 99)
    assert calls == ["init", "key", "final", "final"]
    assert result == b"\x01\x02\x03\x04"


def test_verify_recover_single_returns_false_on_invalid_sig() -> None:
    from pkcs11_check.raw.types_std import CKM_RSA_PKCS, CKR_OK, CKR_SIGNATURE_INVALID

    class FakeRaw:
        def C_VerifyRecoverInit(self, session, mech, key) -> int:  # noqa: N802
            return CKR_OK

        def C_VerifyRecover(self, session, sig, sig_len, out, out_len) -> int:  # noqa: N802
            return CKR_SIGNATURE_INVALID

    valid, data = verify_recover_single(FakeRaw(), 1, 1, CKM_RSA_PKCS, b"x" * 8)
    assert valid is False
    assert data == b""


def test_expect_rv_context_in_error_message() -> None:
    from pkcs11_check.raw.rv import expect_rv
    from pkcs11_check.raw.types_std import CKR_OK

    try:
        expect_rv(999, CKR_OK, context="C_EncryptInit")
        assert False, "Should have raised"
    except AssertionError as e:
        assert "C_EncryptInit" in str(e)


def test_to_ubyte_buf_round_trips_bytes() -> None:
    from pkcs11_check.raw.recipes import to_ubyte_buf

    data = b"\x00\xff\x42\xa5" + bytes(range(32))
    buf = to_ubyte_buf(data)
    assert len(buf) == len(data)
    assert bytes(buf) == data


def test_to_ubyte_buf_empty_input_returns_empty_array() -> None:
    from pkcs11_check.raw.recipes import to_ubyte_buf

    buf = to_ubyte_buf(b"")
    assert len(buf) == 0
    assert bytes(buf) == b""


def test_init_token_passes_pin_and_label_as_utf8char_buffers() -> None:
    from pkcs11_check.raw.types_std import CKR_OK

    class FakeRaw:
        def C_InitToken(self, slot_id: int, pin_buf: Any, pin_len: int, label_buf: Any) -> int:  # noqa: N802
            assert slot_id == 7
            assert pin_len == 6
            assert isinstance(pin_buf, ctypes.Array)
            assert pin_buf._type_ is ctypes.c_ubyte
            assert bytes(pin_buf) == b"so-pin"
            assert isinstance(label_buf, ctypes.Array)
            assert label_buf._type_ is ctypes.c_ubyte
            assert bytes(label_buf) == b"pkcs11-check".ljust(32)
            return CKR_OK

    init_token(FakeRaw(), 7, b"so-pin", "pkcs11-check")


@pytest.mark.parametrize("size", [64, 4096, 1_048_576])
def test_benchmark_to_ubyte_buf(benchmark: Any, size: int) -> None:
    """Confirms ``to_ubyte_buf`` does memcpy-speed copies, not per-byte conversion.

    Run with ``pytest --benchmark-only`` for numbers; on a 1 MiB payload the
    ``from_buffer_copy`` path is ~100× faster than the legacy
    ``(c_ubyte * N)(*data)`` varargs construction.
    """
    from pkcs11_check.raw.recipes import to_ubyte_buf

    data = bytes(size)
    result = benchmark(to_ubyte_buf, data)
    assert len(result) == size


class _CountingRaw:
    """Minimal raw stub that records each output call's buffer-query mode.

    Each recorded entry is ``True`` when called with a NULL output buffer (the
    size-query pass) and ``False`` for a real call with an allocated buffer.
    """

    def __init__(self, output: bytes, *, too_small_once: bool = False) -> None:
        self.output = output
        self.too_small_once = too_small_once
        self.calls: list[bool] = []

    def _run(self, out_buf: Any, out_len_ref: Any) -> int:
        from pkcs11_check.raw.types_std import CKR_BUFFER_TOO_SMALL, CKR_OK

        is_query = out_buf is None
        self.calls.append(is_query)
        out_len = out_len_ref._obj  # the CK_ULONG behind byref()
        full = len(self.output)
        if is_query:
            out_len.value = full
            return CKR_OK
        if self.too_small_once and out_len.value < full:
            self.too_small_once = False
            out_len.value = full  # report the true required size on failure
            return CKR_BUFFER_TOO_SMALL
        for i in range(full):
            out_buf[i] = self.output[i]
        out_len.value = full
        return CKR_OK

    def C_Encrypt(  # noqa: N802
        self,
        _session: int,
        _in_buf: Any,
        _in_len: int,
        out_buf: Any,
        out_len_ref: Any,
    ) -> int:
        return self._run(out_buf, out_len_ref)


class TestTwoCallOutputSizing:
    """Regression tests for the size-query optimization in _two_call_output.

    Stream/feedback modes (AES CFB/OFB) have ciphertext length == plaintext
    length, so the CFB/OFB runners pass ``output_size_hint`` to skip the
    NULL-buffer size-query round-trip — roughly halving per-op round-trips on
    transport-bound modules (e.g. bouncyhsm, one TCP RPC per call). The
    single-call path MUST still recover from CKR_BUFFER_TOO_SMALL when
    ``retry_on_buffer_too_small`` is set, so a wrong size guess is corrected
    rather than silently dropped.
    """

    def test_hint_skips_size_query(self) -> None:
        from pkcs11_check.raw.recipes import _two_call_output

        raw = _CountingRaw(b"\xaa" * 16)
        out = _two_call_output(raw, "C_Encrypt", 1, None, 16, output_size_hint=16)
        assert out == b"\xaa" * 16
        assert raw.calls == [False]  # single real call, no NULL size query

    def test_no_hint_does_size_query(self) -> None:
        from pkcs11_check.raw.recipes import _two_call_output

        raw = _CountingRaw(b"\xaa" * 16)
        out = _two_call_output(raw, "C_Encrypt", 1, None, 16)
        assert out == b"\xaa" * 16
        assert raw.calls == [True, False]  # NULL query, then real call

    def test_hint_retries_on_buffer_too_small(self) -> None:
        from pkcs11_check.raw.recipes import _two_call_output

        raw = _CountingRaw(b"\xbb" * 20, too_small_once=True)
        out = _two_call_output(
            raw,
            "C_Encrypt",
            1,
            None,
            16,
            output_size_hint=16,
            retry_on_buffer_too_small=True,
        )
        assert out == b"\xbb" * 20
        assert raw.calls == [False, False]  # too-small real call, then retry — no NULL query

    def test_hint_without_retry_raises_on_buffer_too_small(self) -> None:
        from pkcs11_check.raw.recipes import _two_call_output

        raw = _CountingRaw(b"\xbb" * 20, too_small_once=True)
        with pytest.raises(AssertionError):
            _two_call_output(raw, "C_Encrypt", 1, None, 16, output_size_hint=16)


class _FailingRaw:
    """Stub whose size query and output call fail independently."""

    def __init__(self, *, query_rv: int, output_rv: int) -> None:
        self._query_rv = query_rv
        self._output_rv = output_rv

    def C_Encrypt(  # noqa: N802
        self,
        _session: int,
        _in_buf: Any,
        _in_len: int,
        out_buf: Any,
        out_len_ref: Any,
    ) -> int:
        if out_buf is None:
            out_len_ref._obj.value = 16
            return self._query_rv
        out_len_ref._obj.value = 16
        return self._output_rv

    def C_EncryptInit(self, *_args: Any) -> int:  # noqa: N802
        return self._output_rv


class TestTwoCallStageAttribution:
    """Single-shot failures name the failing stage (Init vs size query vs call)."""

    def test_size_query_failure_names_size_query(self) -> None:
        from pkcs11_check.raw.recipes import _two_call_output
        from pkcs11_check.raw.rv import CkrAssertionError
        from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR, CKR_OK

        raw = _FailingRaw(query_rv=CKR_GENERAL_ERROR, output_rv=CKR_OK)
        with pytest.raises(CkrAssertionError, match=r"^C_Encrypt size query:"):
            _two_call_output(raw, "C_Encrypt", 1, None, 16)

    def test_output_call_failure_names_call(self) -> None:
        from pkcs11_check.raw.recipes import _two_call_output
        from pkcs11_check.raw.rv import CkrAssertionError
        from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR, CKR_OK

        raw = _FailingRaw(query_rv=CKR_OK, output_rv=CKR_GENERAL_ERROR)
        with pytest.raises(CkrAssertionError, match=r"^C_Encrypt:"):
            _two_call_output(raw, "C_Encrypt", 1, None, 16)

    def test_init_failure_names_init(self) -> None:
        from pkcs11_check.raw.rv import CkrAssertionError
        from pkcs11_check.raw.types_std import CKM_AES_CTR, CKR_GENERAL_ERROR

        raw = _FailingRaw(query_rv=CKR_GENERAL_ERROR, output_rv=CKR_GENERAL_ERROR)
        with pytest.raises(CkrAssertionError, match=r"^C_EncryptInit:"):
            encrypt_single(raw, 1, 1, CKM_AES_CTR, b"\x00" * 16)


class _InventoryRaw:
    """Cursor-correct Find/attribute fake for exhaustive inventory proofs."""

    def __init__(self, objects: dict[int, dict[int, bytes]]) -> None:
        self.objects = objects
        self._search: list[int] = []
        self.final_calls = 0
        self.count_override: int | None = None
        self.page_script: list[int] = []
        self.attr_rv: int | None = None

    def C_FindObjectsInit(self, _sh: int, _tmpl: Any, _count: int) -> int:  # noqa: N802
        self._search = list(self.objects)
        return 0

    def C_FindObjects(self, _sh: int, handles: Any, max_count: int, found_ptr: Any) -> int:  # noqa: N802
        from pkcs11_check.raw.types_std import CK_ULONG

        found = ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents
        if self.count_override is not None:
            found.value = self.count_override
            return 0
        limit = int(max_count)
        if self.page_script:
            limit = min(limit, self.page_script.pop(0))
        take = self._search[:limit]
        for i, handle in enumerate(take):
            handles[i] = handle
        found.value = len(take)
        self._search = self._search[len(take) :]
        return 0

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        self.final_calls += 1
        return 0

    def C_GetAttributeValue(self, _sh: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        from pkcs11_check.raw.types_std import (
            CK_UNAVAILABLE_INFORMATION,
            CKR_ATTRIBUTE_TYPE_INVALID,
        )

        if self.attr_rv is not None:
            return self.attr_rv
        stored = self.objects.get(int(handle), {})
        row_rvs: list[int] = []
        for i in range(count):
            attr = int(tmpl[i].type)
            cap = int(tmpl[i].ulValueLen)
            addr = tmpl[i].pValue
            blob = stored.get(attr)
            if blob is None:
                tmpl[i].ulValueLen = int(CK_UNAVAILABLE_INFORMATION)
                row_rvs.append(int(CKR_ATTRIBUTE_TYPE_INVALID))
                continue
            if addr:
                ctypes.memmove(addr, blob, min(len(blob), cap))
            tmpl[i].ulValueLen = len(blob)
            row_rvs.append(0)
        return int(CKR_ATTRIBUTE_TYPE_INVALID) if row_rvs and any(row_rvs) else 0


def _ulong_blob(value: int) -> bytes:
    from pkcs11_check.raw.types_std import CK_ULONG

    return int(value).to_bytes(ctypes.sizeof(CK_ULONG), sys.byteorder)


class TestExhaustiveInventoryPartition:
    """R1/R4: inventories exhaust; only correlated delta handles are proved."""

    def test_exhaustive_pages_past_256_to_empty_page(self) -> None:
        from pkcs11_check.raw.recipes import find_objects_exhaustive

        raw: Any = _InventoryRaw({handle: {} for handle in range(1, 302)})
        assert find_objects_exhaustive(raw, 7, page_size=256) == list(range(1, 302))
        assert raw.final_calls == 1

    def test_exhaustive_short_page_is_not_exhaustion(self) -> None:
        from pkcs11_check.raw.recipes import find_objects_exhaustive

        raw: Any = _InventoryRaw({11: {}, 12: {}, 13: {}, 14: {}, 15: {}})
        raw.page_script = [1, 3, 1]
        assert find_objects_exhaustive(raw, 7, page_size=3) == [11, 12, 13, 14, 15]
        assert raw.final_calls == 1

    def test_exhaustive_count_above_capacity_fails_and_finalizes(self) -> None:
        from pkcs11_check.raw.recipes import find_objects_exhaustive

        raw: Any = _InventoryRaw({11: {}})
        raw.count_override = 3
        with pytest.raises(AssertionError, match="above capacity"):
            find_objects_exhaustive(raw, 7, page_size=2)
        assert raw.final_calls == 1

    def test_partition_proves_only_correlated_delta(self) -> None:
        from pkcs11_check.raw.recipes import partition_proved_new
        from pkcs11_check.raw.types_std import (
            CKA_CLASS,
            CKA_KEY_TYPE,
            CKA_LABEL,
            CKA_MODULUS,
            CKA_TOKEN,
            CKK_AES,
            CKK_RSA,
            CKO_DATA,
            CKO_PUBLIC_KEY,
        )

        modulus = b"\x80known-modulus"
        raw: Any = _InventoryRaw(
            {
                1: {},
                2: {
                    int(CKA_LABEL): b"attempt",
                    int(CKA_TOKEN): b"\x01",
                    int(CKA_CLASS): _ulong_blob(int(CKO_DATA)),
                },
                3: {
                    int(CKA_TOKEN): b"\x00",
                    int(CKA_CLASS): _ulong_blob(int(CKO_PUBLIC_KEY)),
                    int(CKA_KEY_TYPE): _ulong_blob(int(CKK_RSA)),
                    int(CKA_MODULUS): modulus,
                },
                4: {
                    int(CKA_LABEL): b"foreign",
                    int(CKA_TOKEN): b"\x01",
                    int(CKA_CLASS): _ulong_blob(int(CKO_DATA)),
                    int(CKA_KEY_TYPE): _ulong_blob(int(CKK_AES)),
                },
                5: {
                    int(CKA_TOKEN): b"\x00",
                    int(CKA_CLASS): _ulong_blob(int(CKO_PUBLIC_KEY)),
                    int(CKA_KEY_TYPE): _ulong_blob(int(CKK_RSA)),
                },
                6: {
                    int(CKA_LABEL): b"attempt",
                    int(CKA_TOKEN): b"\x00",
                    int(CKA_CLASS): _ulong_blob(int(CKO_PUBLIC_KEY)),
                    int(CKA_KEY_TYPE): _ulong_blob(int(CKK_RSA)),
                    int(CKA_MODULUS): b"\x80foreign-modulus",
                },
            }
        )
        proved, unproved = partition_proved_new(
            raw,
            7,
            [1],
            [1, 2, 3, 4, 5, 6],
            attempt_templates=(
                {
                    CKA_LABEL: "attempt",
                    CKA_TOKEN: False,
                    CKA_CLASS: CKO_PUBLIC_KEY,
                    CKA_KEY_TYPE: CKK_RSA,
                    CKA_MODULUS: modulus,
                },
            ),
            error_handles=(5,),
        )
        # 2: attempt label on a token object (attempt is session) and 6:
        # attempt label with contradicted modulus stay unproved.
        assert proved == [3, 5]
        assert unproved == [2, 4, 6]

    def test_partition_identity_and_common_exponent_alone_unproved(self) -> None:
        from pkcs11_check.raw.recipes import partition_proved_new
        from pkcs11_check.raw.types_std import (
            CKA_CLASS,
            CKA_KEY_TYPE,
            CKA_PUBLIC_EXPONENT,
            CKA_TOKEN,
            CKK_RSA,
            CKO_PUBLIC_KEY,
        )

        exponent = (65537).to_bytes(3, "big")
        raw: Any = _InventoryRaw(
            {
                1: {},
                2: {
                    int(CKA_TOKEN): b"\x00",
                    int(CKA_CLASS): _ulong_blob(int(CKO_PUBLIC_KEY)),
                    int(CKA_KEY_TYPE): _ulong_blob(int(CKK_RSA)),
                    int(CKA_PUBLIC_EXPONENT): exponent,
                },
            }
        )
        proved, unproved = partition_proved_new(
            raw,
            7,
            [1],
            [1, 2],
            attempt_templates=(
                {
                    CKA_TOKEN: False,
                    CKA_CLASS: CKO_PUBLIC_KEY,
                    CKA_KEY_TYPE: CKK_RSA,
                    CKA_PUBLIC_EXPONENT: exponent,
                },
            ),
        )
        assert proved == []
        assert unproved == [2]

    def test_partition_parameter_set_is_not_strong_material(self) -> None:
        from pkcs11_check.raw.recipes import partition_proved_new
        from pkcs11_check.raw.types_std import CKA_PARAMETER_SET, CKA_TOKEN

        raw: Any = _InventoryRaw(
            {1: {}, 2: {int(CKA_TOKEN): b"\x00", int(CKA_PARAMETER_SET): _ulong_blob(2)}}
        )
        proved, unproved = partition_proved_new(
            raw,
            7,
            [1],
            [1, 2],
            attempt_templates=({CKA_TOKEN: False, CKA_PARAMETER_SET: 2},),
        )
        assert proved == []
        assert unproved == [2]

    def test_partition_pair_completion_extends_proved_anchor(self) -> None:
        from pkcs11_check.raw.recipes import partition_proved_new
        from pkcs11_check.raw.types_std import (
            CKA_CLASS,
            CKA_ID,
            CKA_KEY_TYPE,
            CKA_LABEL,
            CKA_MODULUS,
            CKA_PUBLIC_EXPONENT,
            CKA_TOKEN,
            CKA_VALUE,
            CKK_RSA,
            CKO_PRIVATE_KEY,
            CKO_PUBLIC_KEY,
        )

        exponent = (65537).to_bytes(3, "big")
        modulus = b"\x80shared-pair-modulus"
        objects: dict[int, dict[int, bytes]] = {
            1: {},
            2: {
                int(CKA_LABEL): b"attempt-pub",
                int(CKA_TOKEN): b"\x00",
                int(CKA_CLASS): _ulong_blob(int(CKO_PUBLIC_KEY)),
                int(CKA_KEY_TYPE): _ulong_blob(int(CKK_RSA)),
                int(CKA_PUBLIC_EXPONENT): exponent,
                int(CKA_MODULUS): modulus,
            },
            3: {
                int(CKA_TOKEN): b"\x00",
                int(CKA_CLASS): _ulong_blob(int(CKO_PRIVATE_KEY)),
                int(CKA_KEY_TYPE): _ulong_blob(int(CKK_RSA)),
                int(CKA_MODULUS): modulus,
            },
        }
        templates = (
            {
                CKA_LABEL: "attempt-pub",
                CKA_TOKEN: False,
                CKA_CLASS: CKO_PUBLIC_KEY,
                CKA_KEY_TYPE: CKK_RSA,
                CKA_PUBLIC_EXPONENT: exponent,
            },
            {CKA_TOKEN: False},
        )
        raw: Any = _InventoryRaw(objects)
        proved, unproved = partition_proved_new(
            raw,
            7,
            [1],
            [1, 2, 3],
            attempt_templates=templates,
            identities=((int(CKO_PRIVATE_KEY), int(CKK_RSA)),),
        )
        assert proved == [2, 3]
        assert unproved == []

        # A foreign private mate beside the proved anchor stays unproved:
        # a shared CKA_ID does not override contradictory moduli.
        objects[2] = {**objects[2], int(CKA_ID): b"shared-id"}
        objects[3] = {
            **objects[3],
            int(CKA_MODULUS): b"\x80foreign-modulus",
            int(CKA_ID): b"shared-id",
        }
        raw = _InventoryRaw(objects)
        proved, unproved = partition_proved_new(
            raw,
            7,
            [1],
            [1, 2, 3],
            attempt_templates=templates,
            identities=((int(CKO_PRIVATE_KEY), int(CKK_RSA)),),
        )
        assert proved == [2]
        assert unproved == [3]
        objects[2] = {k: v for k, v in objects[2].items() if k != int(CKA_ID)}
        objects[3] = {k: v for k, v in objects[3].items() if k != int(CKA_ID)}

        # Empty shared CKA_VALUE and a shared CKA_ID are not pairing
        # evidence (ID association/uniqueness is not enforced).
        objects[2] = {
            **{k: v for k, v in objects[2].items() if k != int(CKA_MODULUS)},
            int(CKA_VALUE): b"",
            int(CKA_ID): b"shared-id",
        }
        objects[3] = {
            **{k: v for k, v in objects[3].items() if k != int(CKA_MODULUS)},
            int(CKA_VALUE): b"",
            int(CKA_ID): b"shared-id",
        }
        raw = _InventoryRaw(objects)
        proved, unproved = partition_proved_new(
            raw,
            7,
            [1],
            [1, 2, 3],
            attempt_templates=templates,
            identities=((int(CKO_PRIVATE_KEY), int(CKK_RSA)),),
        )
        assert proved == [2]
        assert unproved == [3]

        # A mate whose CKA_TOKEN readback is hidden does not satisfy the
        # explicit attempt token requirement, shared modulus or not.
        objects[2] = {**objects[2], int(CKA_MODULUS): modulus}
        objects[3] = {
            k: v
            for k, v in {**objects[3], int(CKA_MODULUS): modulus}.items()
            if k != int(CKA_TOKEN)
        }
        raw = _InventoryRaw(objects)
        proved, unproved = partition_proved_new(
            raw,
            7,
            [1],
            [1, 2, 3],
            attempt_templates=templates,
            identities=((int(CKO_PRIVATE_KEY), int(CKK_RSA)),),
        )
        assert proved == [2]
        assert unproved == [3]
        objects[3] = {**objects[3], int(CKA_TOKEN): b"\x00"}

        # The same pair with no independently proved anchor (labels
        # dropped, no error output) stays wholly unproved.
        objects[2] = {k: v for k, v in objects[2].items() if k != int(CKA_LABEL)}
        raw = _InventoryRaw(objects)
        proved, unproved = partition_proved_new(
            raw,
            7,
            [1],
            [1, 2, 3],
            attempt_templates=templates,
            identities=((int(CKO_PRIVATE_KEY), int(CKK_RSA)),),
        )
        assert proved == []
        assert unproved == [2, 3]

    def test_partition_clean_read_refusal_in_pair_delta_unproved(self) -> None:
        from pkcs11_check.raw.recipes import partition_proved_new
        from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR

        raw: Any = _InventoryRaw({1: {}, 2: {}, 3: {}})
        raw.attr_rv = int(CKR_GENERAL_ERROR)
        proved, unproved = partition_proved_new(raw, 7, [1], [1, 2, 3], attempt_templates=({}, {}))
        assert proved == []
        assert unproved == [2, 3]

    def test_partition_undefined_read_rv_propagates(self) -> None:
        from pkcs11_check.raw.recipes import partition_proved_new
        from pkcs11_check.raw.rv import CkrAssertionError

        raw: Any = _InventoryRaw({1: {}, 2: {}})
        raw.attr_rv = 0x7FFFFFFF
        with pytest.raises(CkrAssertionError):
            partition_proved_new(raw, 7, [1], [1, 2], attempt_templates=({},))
