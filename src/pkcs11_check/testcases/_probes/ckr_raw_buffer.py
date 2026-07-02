"""Probe: CKR_BUFFER_TOO_SMALL / output-guard error conditions via a raw session.

Fifteen child bodies ported verbatim from the legacy ``ckr/test_ckr_raw_buffer.py`` scripts
(Batches A + B of the file's migration), dispatched on ``extra["probe"]``.  Each drives an output
call with a deliberately undersized buffer through ``RawPKCS11`` and prints the resulting
``CKR:0x...`` line (plus ``LEN:`` / ``OVERWRITTEN:`` / ``RETRY_*`` guard-preservation markers)
for the parent-side classifier / guard assertions in ``test_ckr_raw_buffer.py``.

Probes covered (dispatch keys):
  ``digest_buffer_too_small``          -- C_Digest, 1-byte declared output over a 64-byte guarded
                                          buffer; counts bytes written past the declared boundary,
                                          then a size-query retry (parent classifies the outcome).
  ``encrypt_buffer_too_small``         -- C_Encrypt (AES-ECB), 1-byte output -> BUFFER_TOO_SMALL.
  ``sign_buffer_too_small``            -- C_Sign (SHA256-RSA-PKCS), 1-byte output + 256-byte retry.
  ``get_slot_list_guard``              -- C_GetSlotList must not write past a one-entry buffer.
  ``get_mechanism_list_guard``         -- C_GetMechanismList must not write past a one-entry buffer.
  ``get_interface_list_guard``         -- C_GetInterfaceList must not write past a one-entry buffer.
  ``find_objects_max_count_one_guard`` -- C_FindObjects must honor ulMaxObjectCount=1.
  ``get_attribute_value_guard``        -- C_GetAttributeValue must not write past a one-byte buffer
                                          and must be retryable at the size-query length.
  ``aes_cbc_pad_decrypt_buffer_too_small``        -- C_Decrypt (AES-CBC-PAD) 1-byte output
                                                     guard + size-query retry.
  ``aes_cbc_pad_decrypt_update_buffer_too_small`` -- C_DecryptUpdate (AES-CBC-PAD) undersized
                                                     output, state preservation + retry.
  ``aes_cbc_pad_encrypt_final_buffer_too_small``  -- C_EncryptFinal (AES-CBC-PAD) undersized
                                                     output, state preservation + retry.
  ``aes_cbc_pad_decrypt_final_buffer_too_small``  -- C_DecryptFinal (AES-CBC-PAD) undersized
                                                     output, state preservation + retry.
  ``wrap_key_buffer_too_small``                   -- C_WrapKey (AES-KEY-WRAP) 1-byte output
                                                     guard + size-query retry.
  ``ecdh_aes_wrap_compressed_public_key_buffer_too_small``
                                                  -- ECDH-AES C_WrapKey with a compressed EC public
                                                     key must size safely (guard + retry).
  ``get_operation_state_buffer_too_small``        -- C_GetOperationState 1-byte output guard +
                                                     size-query retry.

Runs through ``probe_main`` at ``Level.LOGIN``: the infra does C_Initialize + slot discovery +
``C_OpenSession`` + (only when ``_P11CHECK_PIN`` is set) ``C_Login`` before handing the probe
``ctx.raw`` / ``ctx.sh`` / ``ctx.slot_id`` -- mirroring the legacy ``_run_raw`` child, which opened
a session and logged in *only* when a PIN was configured.  The PIN travels ONLY via the
``_P11CHECK_PIN`` env var; it is never read, printed, or embedded here or in the probe params.
This CLOSES the legacy leak that formatted the PIN literal into the generated child-script source
(Invariant I3).  Session teardown + rv-trace are handled by ``probe_main`` atexit, matching the
legacy ``cleanup()`` / rv-trace setup.

Output protocol (byte-identical to the legacy child, for the parent classifier / guard asserts):
  ``CKR:0x{rv:08x}``       -- return value of the tested output call
  ``LEN:`` / ``FOUND:`` / ``NEEDED:`` / ``OVERWRITTEN:`` / ``RETRY_*``  -- guard-preservation state
  ``SETUP_XFAIL:...``      -- a setup step (Init/keygen/size-query) cleanly failed before the probe
  ``OK``                   -- probe reached its expected point

The uppercase legacy locals (``GUARD`` / ``BUF_SIZE`` / ``DECLARED`` / ``GUARD_SIZE``) are
lowercased here to satisfy ruff N806; they are internal-only and never appear in a printed line,
so the output protocol is unchanged (I5).

Required ``extra`` keys:
  ``"probe"`` -- one of the dispatch keys above.

Launch with ``coverage="session"`` and ``pin=pin_from_config(p11_config)``.
"""

from __future__ import annotations

import ctypes
import hashlib
from collections.abc import Callable
from ctypes import byref, cast
from typing import Any

from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import (
    TemplateArg,
    attr_bool,
    attr_bytes,
    attr_ulong,
    mech_bytes,
    mech_ecdh_aes_kw,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_ATTRIBUTE_PTR,
    CK_INTERFACE,
    CK_INTERFACE_PTR,
    CK_MECHANISM_TYPE,
    CK_MECHANISM_TYPE_PTR,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE_PTR,
    CK_SLOT_ID,
    CK_SLOT_ID_PTR,
    CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
    CKA_APPLICATION,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS_BITS,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKD_SHA256_KDF,
    CKK_EC,
    CKM_AES_CBC_PAD,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_AES_KEY_WRAP,
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDH_AES_KEY_WRAP,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKO_DATA,
    CKO_PUBLIC_KEY,
    CKR_BUFFER_TOO_SMALL,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_STATE_UNSAVEABLE,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _template_ptr(attrs: TemplateArg) -> Any:
    return cast(attrs.array, CK_ATTRIBUTE_PTR)


def _der_octet_string(value: bytes) -> bytes:
    if len(value) < 128:
        return bytes([0x04, len(value)]) + value
    length = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([0x04, 0x80 | len(length)]) + length + value


def _compress_p256_ec_point(ec_point_der: bytes) -> bytes:
    raw_point = decode_ec_point(bytes(ec_point_der))
    if len(raw_point) != 65 or raw_point[0] != 0x04:
        raise ValueError(f"expected uncompressed P-256 point, got {len(raw_point)} bytes")
    x = raw_point[1:33]
    y = raw_point[33:65]
    compressed = bytes([0x02 | (y[-1] & 1)]) + x
    return _der_octet_string(compressed)


def _digest_buffer_too_small(ctx: ProbeContext) -> None:
    """C_Digest with a 1-byte declared output over a 64-byte guarded buffer."""
    raw = ctx.raw
    sh = ctx.sh
    mech = mech_simple(CKM_SHA256)
    rv = raw.C_DigestInit(sh, mech.byref())
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_DigestInit(CKM_SHA256) failed: {ckr_name(rv)}")
    else:
        guard = 0xAA
        buf_size = 64
        declared = 1  # Tell C_Digest the buffer is only 1 byte

        data = (ctypes.c_ubyte * 16)(*([0x42] * 16))
        buf = (ctypes.c_ubyte * buf_size)(*([guard] * buf_size))
        out_len = ctypes.c_ulong(declared)
        rv = raw.C_Digest(sh, data, 16, buf, ctypes.byref(out_len))
        print(f"CKR:0x{rv:08x}")
        print(f"LEN:{out_len.value}")

        # Count how many bytes were overwritten past the declared boundary
        overwritten = 0
        for i in range(declared, buf_size):
            if buf[i] != guard:
                overwritten += 1
        print(f"OVERWRITTEN:{overwritten}")
        if rv == CKR_BUFFER_TOO_SMALL:
            retry_len = CK_ULONG(32)
            retry_buf = (ctypes.c_ubyte * retry_len.value)()
            retry_rv = raw.C_Digest(sh, data, 16, retry_buf, ctypes.byref(retry_len))
            retry_value = bytes(retry_buf[: retry_len.value])
            expected = hashlib.sha256(bytes([0x42] * 16)).digest()
            print(f"RETRY_CKR:0x{retry_rv:08x}")
            print(f"RETRY_LEN:{retry_len.value}")
            print(f"RETRY_MATCH:{int(retry_value == expected)}")
            assert retry_rv == CKR_OK, (
                f"C_Digest retry after CKR_BUFFER_TOO_SMALL failed: {ckr_name(retry_rv)}"
            )
            assert retry_len.value == len(expected), (
                f"C_Digest retry reported length {retry_len.value}, expected {len(expected)}"
            )
            assert retry_value == expected, "C_Digest retry returned wrong digest"
        print("OK")


def _encrypt_buffer_too_small(ctx: ProbeContext) -> None:
    """C_Encrypt AES-ECB with 1-byte output -> CKR_BUFFER_TOO_SMALL."""
    raw = ctx.raw
    sh = ctx.sh
    attrs = template(
        attr_ulong(CKA_VALUE_LEN, 32),
        attr_bool(CKA_ENCRYPT, True),
        attr_bool(CKA_TOKEN, False),
    )

    mech_kg = mech_simple(CKM_AES_KEY_GEN)
    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(sh, mech_kg.byref(), _template_ptr(attrs), attrs.count, byref(key))
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_GenerateKey for AES encrypt failed: {ckr_name(rv)}")
    else:
        # EncryptInit
        mech = mech_simple(CKM_AES_ECB)
        rv = raw.C_EncryptInit(sh, mech.byref(), key.value)
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_EncryptInit(CKM_AES_ECB) failed: {ckr_name(rv)}")
        else:
            # Encrypt with 1-byte output buffer
            data = (ctypes.c_ubyte * 16)(*([0] * 16))
            out = (ctypes.c_ubyte * 1)()
            out_len = ctypes.c_ulong(1)
            rv = raw.C_Encrypt(sh, data, 16, out, ctypes.byref(out_len))
            print(f"CKR:0x{rv:08x}")
            assert rv == CKR_BUFFER_TOO_SMALL, f"Expected BUFFER_TOO_SMALL, got 0x{rv:08x}"
            print("OK")


def _sign_buffer_too_small(ctx: ProbeContext) -> None:
    """C_Sign with 1-byte output -> CKR_BUFFER_TOO_SMALL, then a 256-byte retry."""
    raw = ctx.raw
    sh = ctx.sh
    # Generate RSA keypair for sign
    mech_rsa = mech_simple(CKM_RSA_PKCS_KEY_PAIR_GEN)
    pub_tmpl = template(
        attr_ulong(CKA_MODULUS_BITS, 2048),
        attr_bool(CKA_TOKEN, False),
    )
    priv_tmpl = template(
        attr_bool(CKA_SIGN, True),
        attr_bool(CKA_TOKEN, False),
    )
    pub = CK_OBJECT_HANDLE(0)
    priv = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        sh,
        mech_rsa.byref(),
        _template_ptr(pub_tmpl),
        pub_tmpl.count,
        _template_ptr(priv_tmpl),
        priv_tmpl.count,
        byref(pub),
        byref(priv),
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_GenerateKeyPair for RSA sign failed: {ckr_name(rv)}")
    else:
        # SignInit with SHA256_RSA_PKCS
        sign_mech = mech_simple(CKM_SHA256_RSA_PKCS)
        rv = raw.C_SignInit(sh, sign_mech.byref(), priv.value)
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_SignInit(CKM_SHA256_RSA_PKCS) failed: {ckr_name(rv)}")
        else:
            data = (ctypes.c_ubyte * 32)(*([0x42] * 32))
            out = (ctypes.c_ubyte * 1)()  # Too small for RSA-2048 sig (256 bytes)
            out_len = ctypes.c_ulong(1)
            rv = raw.C_Sign(sh, data, 32, out, ctypes.byref(out_len))
            print(f"CKR:0x{rv:08x}")
            assert rv == CKR_BUFFER_TOO_SMALL, f"Expected BUFFER_TOO_SMALL, got 0x{rv:08x}"
            retry_len = CK_ULONG(256)
            retry_buf = (ctypes.c_ubyte * retry_len.value)()
            retry_rv = raw.C_Sign(sh, data, 32, retry_buf, ctypes.byref(retry_len))
            print(f"RETRY_CKR:0x{retry_rv:08x}")
            print(f"RETRY_LEN:{retry_len.value}")
            assert retry_rv == CKR_OK, (
                f"C_Sign retry after CKR_BUFFER_TOO_SMALL failed: {ckr_name(retry_rv)}"
            )
            assert retry_len.value == 256, (
                f"C_Sign retry reported length {retry_len.value}, expected 256"
            )
            print("OK")


def _get_slot_list_guard(ctx: ProbeContext) -> None:
    """C_GetSlotList with one declared slot must preserve adjacent guard bytes."""
    raw = ctx.raw
    needed = CK_ULONG(0)
    rv = raw.C_GetSlotList(0, None, byref(needed))
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_GetSlotList size query failed: {ckr_name(rv)}")
    elif needed.value <= 1:
        print(f"SETUP_XFAIL:C_GetSlotList returned only {needed.value} slot(s)")
    else:
        guard = 0xE1
        guard_size = 32

        class SlotProbe(ctypes.Structure):
            _fields_ = [
                ("items", CK_SLOT_ID * 1),
                ("guard", ctypes.c_ubyte * guard_size),
            ]

        probe = SlotProbe()
        for idx in range(guard_size):
            probe.guard[idx] = guard

        out_count = CK_ULONG(1)
        rv = raw.C_GetSlotList(
            0,
            cast(probe.items, CK_SLOT_ID_PTR),
            byref(out_count),
        )
        print(f"CKR:0x{rv:08x}")
        print(f"LEN:{out_count.value}")
        overwritten = sum(1 for byte in probe.guard if byte != guard)
        print(f"OVERWRITTEN:{overwritten}")
        assert overwritten == 0, (
            "C_GetSlotList wrote past the declared one-entry output buffer: "
            f"{overwritten} guard byte(s) changed"
        )
        assert rv == CKR_BUFFER_TOO_SMALL, (
            f"Expected CKR_BUFFER_TOO_SMALL for one-entry slot buffer, got {ckr_name(rv)}"
        )
        assert out_count.value == needed.value, (
            f"C_GetSlotList reported required count {out_count.value}, expected {needed.value}"
        )
        print("OK")


def _get_mechanism_list_guard(ctx: ProbeContext) -> None:
    """C_GetMechanismList with one declared slot must preserve adjacent guard bytes."""
    raw = ctx.raw
    slot_id = ctx.slot_id
    needed = CK_ULONG(0)
    rv = raw.C_GetMechanismList(slot_id, None, byref(needed))
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_GetMechanismList size query failed: {ckr_name(rv)}")
    elif needed.value <= 1:
        print(f"SETUP_XFAIL:C_GetMechanismList returned only {needed.value} mechanism(s)")
    else:
        guard = 0xA5
        guard_size = 32

        class MechanismProbe(ctypes.Structure):
            _fields_ = [
                ("items", CK_MECHANISM_TYPE * 1),
                ("guard", ctypes.c_ubyte * guard_size),
            ]

        probe = MechanismProbe()
        for idx in range(guard_size):
            probe.guard[idx] = guard

        out_count = CK_ULONG(1)
        rv = raw.C_GetMechanismList(
            slot_id,
            cast(probe.items, CK_MECHANISM_TYPE_PTR),
            byref(out_count),
        )
        print(f"CKR:0x{rv:08x}")
        print(f"LEN:{out_count.value}")
        overwritten = sum(1 for byte in probe.guard if byte != guard)
        print(f"OVERWRITTEN:{overwritten}")
        assert overwritten == 0, (
            "C_GetMechanismList wrote past the declared one-entry output buffer: "
            f"{overwritten} guard byte(s) changed"
        )
        assert rv == CKR_BUFFER_TOO_SMALL, (
            f"Expected CKR_BUFFER_TOO_SMALL for one-entry mechanism buffer, got {ckr_name(rv)}"
        )
        assert out_count.value == needed.value, (
            f"C_GetMechanismList reported required count {out_count.value}, expected {needed.value}"
        )
        print("OK")


def _get_interface_list_guard(ctx: ProbeContext) -> None:
    """C_GetInterfaceList with one declared slot must preserve adjacent guard bytes."""
    raw = ctx.raw
    if "C_GetInterfaceList" not in raw.available_function_names():
        print("SETUP_XFAIL:C_GetInterfaceList is not exposed by this interface")
    else:
        needed = CK_ULONG(0)
        rv = raw.C_GetInterfaceList(None, byref(needed))
        if rv == CKR_FUNCTION_NOT_SUPPORTED:
            print("SETUP_XFAIL:C_GetInterfaceList returned CKR_FUNCTION_NOT_SUPPORTED")
        elif rv != CKR_OK:
            print(f"SETUP_XFAIL:C_GetInterfaceList size query failed: {ckr_name(rv)}")
        elif needed.value <= 1:
            print(f"SETUP_XFAIL:C_GetInterfaceList returned only {needed.value} interface(s)")
        else:
            guard = 0x5A
            guard_size = 32

            class InterfaceProbe(ctypes.Structure):
                _fields_ = [
                    ("items", CK_INTERFACE * 1),
                    ("guard", ctypes.c_ubyte * guard_size),
                ]

            probe = InterfaceProbe()
            for idx in range(guard_size):
                probe.guard[idx] = guard

            out_count = CK_ULONG(1)
            rv = raw.C_GetInterfaceList(cast(probe.items, CK_INTERFACE_PTR), byref(out_count))
            print(f"CKR:0x{rv:08x}")
            print(f"LEN:{out_count.value}")
            overwritten = sum(1 for byte in probe.guard if byte != guard)
            print(f"OVERWRITTEN:{overwritten}")
            assert overwritten == 0, (
                "C_GetInterfaceList wrote past the declared one-entry output buffer: "
                f"{overwritten} guard byte(s) changed"
            )
            assert rv == CKR_BUFFER_TOO_SMALL, (
                f"Expected CKR_BUFFER_TOO_SMALL for one-entry interface buffer, got {ckr_name(rv)}"
            )
            assert out_count.value == needed.value, (
                f"C_GetInterfaceList reported required count {out_count.value}, "
                f"expected {needed.value}"
            )
            print("OK")


def _find_objects_max_count_one_guard(ctx: ProbeContext) -> None:
    """C_FindObjects must return at most ulMaxObjectCount handles."""
    raw = ctx.raw
    sh = ctx.sh
    label = b"p11chk-find-guard"
    application = b"pkcs11-check"
    created: list[Any] = []
    search_active = False

    create_tmpl = template(
        attr_ulong(CKA_CLASS, CKO_DATA),
        attr_bool(CKA_TOKEN, False),
        attr_bytes(CKA_LABEL, label),
        attr_bytes(CKA_APPLICATION, application),
        attr_bytes(CKA_VALUE, b"find-object-guard"),
    )
    search_tmpl = template(
        attr_ulong(CKA_CLASS, CKO_DATA),
        attr_bytes(CKA_LABEL, label),
    )

    try:
        for _idx in range(2):
            handle = CK_OBJECT_HANDLE(0)
            rv = raw.C_CreateObject(
                sh,
                _template_ptr(create_tmpl),
                create_tmpl.count,
                byref(handle),
            )
            if rv != CKR_OK:
                print(f"SETUP_XFAIL:C_CreateObject(CKO_DATA) failed: {ckr_name(rv)}")
                break
            created.append(handle.value)
        else:
            rv = raw.C_FindObjectsInit(sh, _template_ptr(search_tmpl), search_tmpl.count)
            if rv != CKR_OK:
                print(f"SETUP_XFAIL:C_FindObjectsInit failed: {ckr_name(rv)}")
            else:
                search_active = True
                guard = 0xD4
                guard_size = 32

                class FindProbe(ctypes.Structure):
                    _fields_ = [
                        ("items", CK_OBJECT_HANDLE * 1),
                        ("guard", ctypes.c_ubyte * guard_size),
                    ]

                probe = FindProbe()
                for idx in range(guard_size):
                    probe.guard[idx] = guard

                found = CK_ULONG(0)
                rv = raw.C_FindObjects(
                    sh,
                    cast(probe.items, CK_OBJECT_HANDLE_PTR),
                    1,
                    byref(found),
                )
                print(f"CKR:0x{rv:08x}")
                print(f"FOUND:{found.value}")
                overwritten = sum(1 for byte in probe.guard if byte != guard)
                print(f"OVERWRITTEN:{overwritten}")
                assert rv == CKR_OK, f"Expected CKR_OK from C_FindObjects, got {ckr_name(rv)}"
                assert found.value <= 1, (
                    f"C_FindObjects reported {found.value} handles for ulMaxObjectCount=1"
                )
                assert overwritten == 0, (
                    "C_FindObjects wrote past the declared one-handle output buffer: "
                    f"{overwritten} guard byte(s) changed"
                )
                print("OK")
    finally:
        if search_active:
            raw.C_FindObjectsFinal(sh)
        for handle_value in created:
            raw.C_DestroyObject(sh, handle_value)


def _get_attribute_value_guard(ctx: ProbeContext) -> None:
    """C_GetAttributeValue must not write past an undersized attribute buffer."""
    raw = ctx.raw
    sh = ctx.sh
    label = b"p11chk-attribute-required-size"
    application = b"pkcs11-check"
    obj = CK_OBJECT_HANDLE(0)
    create_tmpl = template(
        attr_ulong(CKA_CLASS, CKO_DATA),
        attr_bool(CKA_TOKEN, False),
        attr_bytes(CKA_LABEL, label),
        attr_bytes(CKA_APPLICATION, application),
        attr_bytes(CKA_VALUE, b"attribute-size-guard"),
    )

    try:
        rv = raw.C_CreateObject(
            sh,
            _template_ptr(create_tmpl),
            create_tmpl.count,
            byref(obj),
        )
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_CreateObject(CKO_DATA) failed: {ckr_name(rv)}")
        else:
            query_attr = CK_ATTRIBUTE()
            query_attr.type = CKA_LABEL
            query_attr.pValue = None
            query_attr.ulValueLen = 0
            rv = raw.C_GetAttributeValue(sh, obj.value, byref(query_attr), 1)
            if rv != CKR_OK:
                print(f"SETUP_XFAIL:C_GetAttributeValue size query failed: {ckr_name(rv)}")
            elif query_attr.ulValueLen != len(label):
                print(
                    "SETUP_XFAIL:C_GetAttributeValue size query reported "
                    f"{query_attr.ulValueLen} byte(s), expected {len(label)}"
                )
            else:
                guard = 0xB6
                guard_size = 32

                class AttributeProbe(ctypes.Structure):
                    _fields_ = [
                        ("data", ctypes.c_ubyte * 1),
                        ("guard", ctypes.c_ubyte * guard_size),
                    ]

                probe = AttributeProbe()
                for idx in range(guard_size):
                    probe.guard[idx] = guard

                attr = CK_ATTRIBUTE()
                attr.type = CKA_LABEL
                attr.pValue = ctypes.cast(probe.data, ctypes.c_void_p)
                attr.ulValueLen = 1
                print(f"NEEDED:{query_attr.ulValueLen}")
                rv = raw.C_GetAttributeValue(sh, obj.value, byref(attr), 1)
                print(f"CKR:0x{rv:08x}")
                print(f"LEN:{attr.ulValueLen}")
                overwritten = sum(1 for byte in probe.guard if byte != guard)
                print(f"OVERWRITTEN:{overwritten}")
                assert rv == CKR_BUFFER_TOO_SMALL, (
                    "Expected CKR_BUFFER_TOO_SMALL for one-byte CKA_LABEL buffer, "
                    f"got {ckr_name(rv)}"
                )
                assert attr.ulValueLen == CK_UNAVAILABLE_INFORMATION, (
                    "C_GetAttributeValue must set an undersized attribute ulValueLen "
                    f"to CK_UNAVAILABLE_INFORMATION, got {attr.ulValueLen}"
                )
                assert overwritten == 0, (
                    "C_GetAttributeValue wrote past the declared one-byte attribute buffer: "
                    f"{overwritten} guard byte(s) changed"
                )

                retry_len = query_attr.ulValueLen
                retry_buf = (ctypes.c_ubyte * retry_len)()
                retry_attr = CK_ATTRIBUTE()
                retry_attr.type = CKA_LABEL
                retry_attr.pValue = ctypes.cast(retry_buf, ctypes.c_void_p)
                retry_attr.ulValueLen = retry_len
                retry_rv = raw.C_GetAttributeValue(sh, obj.value, byref(retry_attr), 1)
                print(f"RETRY_CKR:0x{retry_rv:08x}")
                print(f"RETRY_LEN:{retry_attr.ulValueLen}")
                retry_value = bytes(retry_buf[: retry_attr.ulValueLen])
                print(f"RETRY_MATCH:{int(retry_value == label)}")
                assert retry_rv == CKR_OK, (
                    "C_GetAttributeValue retry with the size-query length failed: "
                    f"{ckr_name(retry_rv)}"
                )
                assert retry_attr.ulValueLen == len(label), (
                    f"C_GetAttributeValue retry reported length {retry_attr.ulValueLen}, "
                    f"expected {len(label)}"
                )
                assert retry_value == label, "C_GetAttributeValue retry returned wrong CKA_LABEL"
                print("OK")
    finally:
        if obj.value:
            raw.C_DestroyObject(sh, obj.value)


def _aes_cbc_pad_decrypt_buffer_too_small(ctx: ProbeContext) -> None:
    """C_Decrypt(CKM_AES_CBC_PAD) must be retryable after an undersized output."""
    raw = ctx.raw
    sh = ctx.sh
    key_attrs = template(
        attr_ulong(CKA_VALUE_LEN, 16),
        attr_bool(CKA_ENCRYPT, True),
        attr_bool(CKA_DECRYPT, True),
        attr_bool(CKA_TOKEN, False),
    )
    key = CK_OBJECT_HANDLE(0)
    try:
        mech_kg = mech_simple(CKM_AES_KEY_GEN)
        rv = raw.C_GenerateKey(
            sh,
            mech_kg.byref(),
            _template_ptr(key_attrs),
            key_attrs.count,
            byref(key),
        )
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_GenerateKey for AES-CBC-PAD decrypt failed: {ckr_name(rv)}")
        else:
            iv = bytes(range(16))
            plaintext = b"cbc-pad-output"
            enc_mech = mech_bytes(CKM_AES_CBC_PAD, iv)
            rv = raw.C_EncryptInit(sh, enc_mech.byref(), key.value)
            if rv != CKR_OK:
                print(f"SETUP_XFAIL:C_EncryptInit(CKM_AES_CBC_PAD) failed: {ckr_name(rv)}")
            else:
                plain_buf = (ctypes.c_ubyte * len(plaintext))(*plaintext)
                enc_buf = (ctypes.c_ubyte * 64)()
                enc_len = CK_ULONG(64)
                rv = raw.C_Encrypt(
                    sh,
                    plain_buf,
                    len(plaintext),
                    cast(enc_buf, ctypes.POINTER(ctypes.c_ubyte)),
                    byref(enc_len),
                )
                if rv != CKR_OK:
                    print(f"SETUP_XFAIL:C_Encrypt(CKM_AES_CBC_PAD) failed: {ckr_name(rv)}")
                else:
                    decrypt_mech = mech_bytes(CKM_AES_CBC_PAD, iv)
                    rv = raw.C_DecryptInit(sh, decrypt_mech.byref(), key.value)
                    if rv != CKR_OK:
                        print(f"SETUP_XFAIL:C_DecryptInit(CKM_AES_CBC_PAD) failed: {ckr_name(rv)}")
                    else:
                        guard = 0x73
                        guard_size = 32

                        class DecryptProbe(ctypes.Structure):
                            _fields_ = [
                                ("data", ctypes.c_ubyte * 1),
                                ("guard", ctypes.c_ubyte * guard_size),
                            ]

                        probe = DecryptProbe()
                        for idx in range(guard_size):
                            probe.guard[idx] = guard

                        ct_buf = (ctypes.c_ubyte * enc_len.value)(*enc_buf[: enc_len.value])
                        out_len = CK_ULONG(1)
                        rv = raw.C_Decrypt(
                            sh,
                            ct_buf,
                            enc_len.value,
                            cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
                            byref(out_len),
                        )
                        print(f"CKR:0x{rv:08x}")
                        print(f"LEN:{out_len.value}")
                        overwritten = sum(1 for byte in probe.guard if byte != guard)
                        print(f"OVERWRITTEN:{overwritten}")
                        assert overwritten == 0, (
                            "C_Decrypt wrote past the declared one-byte output buffer: "
                            f"{overwritten} guard byte(s) changed"
                        )
                        assert rv == CKR_BUFFER_TOO_SMALL, (
                            "Expected CKR_BUFFER_TOO_SMALL for one-byte AES-CBC-PAD "
                            f"decrypt buffer, got {ckr_name(rv)}"
                        )
                        assert len(plaintext) <= out_len.value <= enc_len.value, (
                            f"C_Decrypt reported retry length {out_len.value}; expected "
                            f"between plaintext length {len(plaintext)} and ciphertext "
                            f"length {enc_len.value}"
                        )

                        retry_buf = (ctypes.c_ubyte * out_len.value)()
                        retry_len = CK_ULONG(out_len.value)
                        retry_rv = raw.C_Decrypt(
                            sh,
                            ct_buf,
                            enc_len.value,
                            cast(retry_buf, ctypes.POINTER(ctypes.c_ubyte)),
                            byref(retry_len),
                        )
                        print(f"RETRY_CKR:0x{retry_rv:08x}")
                        print(f"RETRY_LEN:{retry_len.value}")
                        retry_value = bytes(retry_buf[: retry_len.value])
                        print(f"RETRY_MATCH:{int(retry_value == plaintext)}")
                        assert retry_rv == CKR_OK, (
                            "C_Decrypt retry after CKR_BUFFER_TOO_SMALL failed: "
                            f"{ckr_name(retry_rv)}"
                        )
                        assert retry_len.value == len(plaintext), (
                            f"C_Decrypt retry reported length {retry_len.value}, "
                            f"expected {len(plaintext)}"
                        )
                        assert retry_value == plaintext, "C_Decrypt retry returned wrong plaintext"
                        print("OK")
    finally:
        if key.value:
            raw.C_DestroyObject(sh, key.value)


def _aes_cbc_pad_decrypt_update_buffer_too_small(ctx: ProbeContext) -> None:
    """C_DecryptUpdate(CKM_AES_CBC_PAD) must preserve state after undersized output."""
    raw = ctx.raw
    sh = ctx.sh
    key_attrs = template(
        attr_ulong(CKA_VALUE_LEN, 16),
        attr_bool(CKA_ENCRYPT, True),
        attr_bool(CKA_DECRYPT, True),
        attr_bool(CKA_TOKEN, False),
    )
    key = CK_OBJECT_HANDLE(0)
    try:
        mech_kg = mech_simple(CKM_AES_KEY_GEN)
        rv = raw.C_GenerateKey(
            sh,
            mech_kg.byref(),
            _template_ptr(key_attrs),
            key_attrs.count,
            byref(key),
        )
        if rv != CKR_OK:
            print(
                f"SETUP_XFAIL:C_GenerateKey for AES-CBC-PAD decrypt update failed: {ckr_name(rv)}"
            )
        else:
            iv = bytes(range(16))
            plaintext = b"B" * 48
            enc_mech = mech_bytes(CKM_AES_CBC_PAD, iv)
            rv = raw.C_EncryptInit(sh, enc_mech.byref(), key.value)
            if rv != CKR_OK:
                print(f"SETUP_XFAIL:C_EncryptInit(CKM_AES_CBC_PAD) failed: {ckr_name(rv)}")
            else:
                plain_buf = (ctypes.c_ubyte * len(plaintext))(*plaintext)
                enc_buf = (ctypes.c_ubyte * 96)()
                enc_len = CK_ULONG(96)
                rv = raw.C_Encrypt(
                    sh,
                    plain_buf,
                    len(plaintext),
                    cast(enc_buf, ctypes.POINTER(ctypes.c_ubyte)),
                    byref(enc_len),
                )
                if rv != CKR_OK:
                    print(f"SETUP_XFAIL:C_Encrypt(CKM_AES_CBC_PAD) failed: {ckr_name(rv)}")
                else:
                    decrypt_mech = mech_bytes(CKM_AES_CBC_PAD, iv)
                    rv = raw.C_DecryptInit(sh, decrypt_mech.byref(), key.value)
                    if rv != CKR_OK:
                        print(f"SETUP_XFAIL:C_DecryptInit(CKM_AES_CBC_PAD) failed: {ckr_name(rv)}")
                    else:
                        guard = 0x8D
                        guard_size = 32

                        class UpdateProbe(ctypes.Structure):
                            _fields_ = [
                                ("data", ctypes.c_ubyte * 1),
                                ("guard", ctypes.c_ubyte * guard_size),
                            ]

                        probe = UpdateProbe()
                        for idx in range(guard_size):
                            probe.guard[idx] = guard

                        ct_buf = (ctypes.c_ubyte * enc_len.value)(*enc_buf[: enc_len.value])
                        update_len = CK_ULONG(1)
                        rv = raw.C_DecryptUpdate(
                            sh,
                            ct_buf,
                            enc_len.value,
                            cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
                            byref(update_len),
                        )
                        print(f"CKR:0x{rv:08x}")
                        print(f"LEN:{update_len.value}")
                        overwritten = sum(1 for byte in probe.guard if byte != guard)
                        print(f"OVERWRITTEN:{overwritten}")
                        assert overwritten == 0, (
                            "C_DecryptUpdate wrote past the declared one-byte output buffer: "
                            f"{overwritten} guard byte(s) changed"
                        )
                        if rv == CKR_OK:
                            assert update_len.value <= 1, (
                                "C_DecryptUpdate returned CKR_OK but reported more bytes than "
                                f"the declared one-byte output buffer: {update_len.value}"
                            )
                            update_value = bytes(probe.data[: update_len.value])
                            final_buf = (ctypes.c_ubyte * 96)()
                            final_len = CK_ULONG(96)
                            final_rv = raw.C_DecryptFinal(
                                sh,
                                cast(final_buf, ctypes.POINTER(ctypes.c_ubyte)),
                                byref(final_len),
                            )
                            combined = update_value + bytes(final_buf[: final_len.value])
                            print(f"FINAL_CKR:0x{final_rv:08x}")
                            print(f"FINAL_LEN:{final_len.value}")
                            print(f"MATCH:{int(combined == plaintext)}")
                            assert final_rv == CKR_OK, (
                                "C_DecryptFinal after CKR_OK C_DecryptUpdate failed: "
                                f"{ckr_name(final_rv)}"
                            )
                            assert combined == plaintext, (
                                "C_DecryptUpdate accepted a one-byte output buffer but "
                                "combined plaintext was wrong"
                            )
                        elif rv == CKR_BUFFER_TOO_SMALL:
                            retry_usable = 1 < update_len.value <= enc_len.value
                            print(f"RETRY_USABLE:{int(retry_usable)}")
                            if retry_usable:
                                retry_buf = (ctypes.c_ubyte * update_len.value)()
                                retry_len = CK_ULONG(update_len.value)
                                retry_rv = raw.C_DecryptUpdate(
                                    sh,
                                    ct_buf,
                                    enc_len.value,
                                    cast(retry_buf, ctypes.POINTER(ctypes.c_ubyte)),
                                    byref(retry_len),
                                )
                                final_buf = (ctypes.c_ubyte * 96)()
                                final_len = CK_ULONG(96)
                                final_rv = raw.C_DecryptFinal(
                                    sh,
                                    cast(final_buf, ctypes.POINTER(ctypes.c_ubyte)),
                                    byref(final_len),
                                )
                                combined = bytes(retry_buf[: retry_len.value]) + bytes(
                                    final_buf[: final_len.value]
                                )
                                print(f"RETRY_CKR:0x{retry_rv:08x}")
                                print(f"RETRY_LEN:{retry_len.value}")
                                print(f"FINAL_CKR:0x{final_rv:08x}")
                                print(f"FINAL_LEN:{final_len.value}")
                                print(f"RETRY_MATCH:{int(combined == plaintext)}")
                                assert retry_rv == CKR_OK, (
                                    "C_DecryptUpdate retry after CKR_BUFFER_TOO_SMALL failed: "
                                    f"{ckr_name(retry_rv)}"
                                )
                                assert final_rv == CKR_OK, (
                                    "C_DecryptFinal after C_DecryptUpdate retry failed: "
                                    f"{ckr_name(final_rv)}"
                                )
                                assert combined == plaintext, (
                                    "C_DecryptUpdate retry returned wrong plaintext"
                                )
                        print("OK")
    finally:
        if key.value:
            raw.C_DestroyObject(sh, key.value)


def _aes_cbc_pad_encrypt_final_buffer_too_small(ctx: ProbeContext) -> None:
    """C_EncryptFinal(CKM_AES_CBC_PAD) must preserve state after undersized output."""
    raw = ctx.raw
    sh = ctx.sh
    key_attrs = template(
        attr_ulong(CKA_VALUE_LEN, 16),
        attr_bool(CKA_ENCRYPT, True),
        attr_bool(CKA_DECRYPT, True),
        attr_bool(CKA_TOKEN, False),
    )
    key = CK_OBJECT_HANDLE(0)
    try:
        mech_kg = mech_simple(CKM_AES_KEY_GEN)
        rv = raw.C_GenerateKey(
            sh,
            mech_kg.byref(),
            _template_ptr(key_attrs),
            key_attrs.count,
            byref(key),
        )
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_GenerateKey for AES-CBC-PAD encrypt final failed: {ckr_name(rv)}")
        else:
            iv = bytes(range(16))
            plaintext = b"A" * 31

            def decrypt_ciphertext(ciphertext: bytes) -> bytes:
                dec_mech = mech_bytes(CKM_AES_CBC_PAD, iv)
                dec_rv = raw.C_DecryptInit(sh, dec_mech.byref(), key.value)
                assert dec_rv == CKR_OK, (
                    f"C_DecryptInit(CKM_AES_CBC_PAD) failed: {ckr_name(dec_rv)}"
                )
                ct_buf = (ctypes.c_ubyte * len(ciphertext))(*ciphertext)
                plain_buf = (ctypes.c_ubyte * 64)()
                plain_len = CK_ULONG(64)
                dec_rv = raw.C_Decrypt(
                    sh,
                    ct_buf,
                    len(ciphertext),
                    cast(plain_buf, ctypes.POINTER(ctypes.c_ubyte)),
                    byref(plain_len),
                )
                assert dec_rv == CKR_OK, (
                    f"C_Decrypt(CKM_AES_CBC_PAD) failed for produced ciphertext: {ckr_name(dec_rv)}"
                )
                return bytes(plain_buf[: plain_len.value])

            enc_mech = mech_bytes(CKM_AES_CBC_PAD, iv)
            rv = raw.C_EncryptInit(sh, enc_mech.byref(), key.value)
            if rv != CKR_OK:
                print(f"SETUP_XFAIL:C_EncryptInit(CKM_AES_CBC_PAD) failed: {ckr_name(rv)}")
            else:
                plain_buf = (ctypes.c_ubyte * len(plaintext))(*plaintext)
                update_buf = (ctypes.c_ubyte * 64)()
                update_len = CK_ULONG(64)
                rv = raw.C_EncryptUpdate(
                    sh,
                    plain_buf,
                    len(plaintext),
                    cast(update_buf, ctypes.POINTER(ctypes.c_ubyte)),
                    byref(update_len),
                )
                if rv != CKR_OK:
                    print(f"SETUP_XFAIL:C_EncryptUpdate failed: {ckr_name(rv)}")
                else:
                    guard = 0x92
                    guard_size = 32

                    class FinalProbe(ctypes.Structure):
                        _fields_ = [
                            ("data", ctypes.c_ubyte * 1),
                            ("guard", ctypes.c_ubyte * guard_size),
                        ]

                    probe = FinalProbe()
                    for idx in range(guard_size):
                        probe.guard[idx] = guard

                    final_len = CK_ULONG(1)
                    rv = raw.C_EncryptFinal(
                        sh,
                        cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
                        byref(final_len),
                    )
                    print(f"CKR:0x{rv:08x}")
                    print(f"LEN:{final_len.value}")
                    overwritten = sum(1 for byte in probe.guard if byte != guard)
                    print(f"OVERWRITTEN:{overwritten}")
                    assert overwritten == 0, (
                        "C_EncryptFinal wrote past the declared one-byte output buffer: "
                        f"{overwritten} guard byte(s) changed"
                    )

                    update_value = bytes(update_buf[: update_len.value])
                    if rv == CKR_OK:
                        assert final_len.value <= 1, (
                            "C_EncryptFinal returned CKR_OK but reported more bytes than the "
                            f"declared one-byte output buffer: {final_len.value}"
                        )
                        final_value = bytes(probe.data[: final_len.value])
                        combined = update_value + final_value
                        decrypted = decrypt_ciphertext(combined)
                        print(f"MATCH:{int(decrypted == plaintext)}")
                        assert decrypted == plaintext, (
                            "C_EncryptFinal accepted a one-byte output buffer but "
                            "produced ciphertext that does not decrypt to the original plaintext"
                        )
                    elif rv == CKR_BUFFER_TOO_SMALL:
                        retry_usable = 1 < final_len.value <= 64
                        print(f"RETRY_USABLE:{int(retry_usable)}")
                        if retry_usable:
                            retry_buf = (ctypes.c_ubyte * final_len.value)()
                            retry_len = CK_ULONG(final_len.value)
                            retry_rv = raw.C_EncryptFinal(
                                sh,
                                cast(retry_buf, ctypes.POINTER(ctypes.c_ubyte)),
                                byref(retry_len),
                            )
                            retry_value = bytes(retry_buf[: retry_len.value])
                            combined = update_value + retry_value
                            decrypted = decrypt_ciphertext(combined)
                            print(f"RETRY_CKR:0x{retry_rv:08x}")
                            print(f"RETRY_LEN:{retry_len.value}")
                            print(f"RETRY_MATCH:{int(decrypted == plaintext)}")
                            assert retry_rv == CKR_OK, (
                                "C_EncryptFinal retry after CKR_BUFFER_TOO_SMALL failed: "
                                f"{ckr_name(retry_rv)}"
                            )
                            assert decrypted == plaintext, (
                                "C_EncryptFinal retry produced ciphertext that does not decrypt "
                                "to the original plaintext"
                            )
                    print("OK")
    finally:
        if key.value:
            raw.C_DestroyObject(sh, key.value)


def _aes_cbc_pad_decrypt_final_buffer_too_small(ctx: ProbeContext) -> None:
    """C_DecryptFinal(CKM_AES_CBC_PAD) must preserve state after undersized output."""
    raw = ctx.raw
    sh = ctx.sh
    key_attrs = template(
        attr_ulong(CKA_VALUE_LEN, 16),
        attr_bool(CKA_ENCRYPT, True),
        attr_bool(CKA_DECRYPT, True),
        attr_bool(CKA_TOKEN, False),
    )
    key = CK_OBJECT_HANDLE(0)
    try:
        mech_kg = mech_simple(CKM_AES_KEY_GEN)
        rv = raw.C_GenerateKey(
            sh,
            mech_kg.byref(),
            _template_ptr(key_attrs),
            key_attrs.count,
            byref(key),
        )
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_GenerateKey for AES-CBC-PAD decrypt final failed: {ckr_name(rv)}")
        else:
            iv = bytes(range(16))
            plaintext = b"A" * 31
            enc_mech = mech_bytes(CKM_AES_CBC_PAD, iv)
            rv = raw.C_EncryptInit(sh, enc_mech.byref(), key.value)
            if rv != CKR_OK:
                print(f"SETUP_XFAIL:C_EncryptInit(CKM_AES_CBC_PAD) failed: {ckr_name(rv)}")
            else:
                plain_buf = (ctypes.c_ubyte * len(plaintext))(*plaintext)
                enc_buf = (ctypes.c_ubyte * 64)()
                enc_len = CK_ULONG(64)
                rv = raw.C_Encrypt(
                    sh,
                    plain_buf,
                    len(plaintext),
                    cast(enc_buf, ctypes.POINTER(ctypes.c_ubyte)),
                    byref(enc_len),
                )
                if rv != CKR_OK:
                    print(f"SETUP_XFAIL:C_Encrypt(CKM_AES_CBC_PAD) failed: {ckr_name(rv)}")
                else:
                    decrypt_mech = mech_bytes(CKM_AES_CBC_PAD, iv)
                    rv = raw.C_DecryptInit(sh, decrypt_mech.byref(), key.value)
                    if rv != CKR_OK:
                        print(f"SETUP_XFAIL:C_DecryptInit(CKM_AES_CBC_PAD) failed: {ckr_name(rv)}")
                    else:
                        ct_buf = (ctypes.c_ubyte * enc_len.value)(*enc_buf[: enc_len.value])
                        update_buf = (ctypes.c_ubyte * len(plaintext))()
                        update_len = CK_ULONG(len(plaintext))
                        rv = raw.C_DecryptUpdate(
                            sh,
                            ct_buf,
                            enc_len.value,
                            cast(update_buf, ctypes.POINTER(ctypes.c_ubyte)),
                            byref(update_len),
                        )
                        if rv != CKR_OK:
                            print(f"SETUP_XFAIL:C_DecryptUpdate failed: {ckr_name(rv)}")
                        else:
                            guard = 0x91
                            guard_size = 32

                            class FinalProbe(ctypes.Structure):
                                _fields_ = [
                                    ("data", ctypes.c_ubyte * 1),
                                    ("guard", ctypes.c_ubyte * guard_size),
                                ]

                            probe = FinalProbe()
                            for idx in range(guard_size):
                                probe.guard[idx] = guard

                            final_len = CK_ULONG(1)
                            rv = raw.C_DecryptFinal(
                                sh,
                                cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
                                byref(final_len),
                            )
                            print(f"CKR:0x{rv:08x}")
                            print(f"LEN:{final_len.value}")
                            overwritten = sum(1 for byte in probe.guard if byte != guard)
                            print(f"OVERWRITTEN:{overwritten}")
                            assert overwritten == 0, (
                                "C_DecryptFinal wrote past the declared one-byte output buffer: "
                                f"{overwritten} guard byte(s) changed"
                            )

                            update_value = bytes(update_buf[: update_len.value])
                            if rv == CKR_OK:
                                final_value = bytes(probe.data[: final_len.value])
                                combined = update_value + final_value
                                print(f"MATCH:{int(combined == plaintext)}")
                                assert combined == plaintext, (
                                    "C_DecryptFinal accepted a one-byte output buffer but "
                                    "combined plaintext was wrong"
                                )
                            elif rv == CKR_BUFFER_TOO_SMALL:
                                retry_len = CK_ULONG(len(plaintext))
                                retry_buf = (ctypes.c_ubyte * retry_len.value)()
                                retry_rv = raw.C_DecryptFinal(
                                    sh,
                                    cast(retry_buf, ctypes.POINTER(ctypes.c_ubyte)),
                                    byref(retry_len),
                                )
                                retry_value = bytes(retry_buf[: retry_len.value])
                                combined = update_value + retry_value
                                print(f"RETRY_CKR:0x{retry_rv:08x}")
                                print(f"RETRY_LEN:{retry_len.value}")
                                print(f"RETRY_MATCH:{int(combined == plaintext)}")
                                assert retry_rv == CKR_OK, (
                                    "C_DecryptFinal retry after CKR_BUFFER_TOO_SMALL failed: "
                                    f"{ckr_name(retry_rv)}"
                                )
                                assert combined == plaintext, (
                                    "C_DecryptFinal retry returned wrong plaintext"
                                )
                            print("OK")
    finally:
        if key.value:
            raw.C_DestroyObject(sh, key.value)


def _wrap_key_buffer_too_small(ctx: ProbeContext) -> None:
    """C_WrapKey with one declared byte must preserve adjacent guard bytes."""
    raw = ctx.raw
    sh = ctx.sh
    wrap_attrs = template(
        attr_ulong(CKA_VALUE_LEN, 32),
        attr_bool(CKA_WRAP, True),
        attr_bool(CKA_TOKEN, False),
    )
    target_attrs = template(
        attr_ulong(CKA_VALUE_LEN, 16),
        attr_bool(CKA_EXTRACTABLE, True),
        attr_bool(CKA_TOKEN, False),
    )

    mech_kg = mech_simple(CKM_AES_KEY_GEN)
    wrap_key = CK_OBJECT_HANDLE(0)
    target_key = CK_OBJECT_HANDLE(0)
    try:
        rv = raw.C_GenerateKey(
            sh,
            mech_kg.byref(),
            _template_ptr(wrap_attrs),
            wrap_attrs.count,
            byref(wrap_key),
        )
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_GenerateKey for AES wrap key failed: {ckr_name(rv)}")
        else:
            rv = raw.C_GenerateKey(
                sh,
                mech_kg.byref(),
                _template_ptr(target_attrs),
                target_attrs.count,
                byref(target_key),
            )
            if rv != CKR_OK:
                print(f"SETUP_XFAIL:C_GenerateKey for AES target key failed: {ckr_name(rv)}")
            else:
                mech = mech_simple(CKM_AES_KEY_WRAP)
                needed = CK_ULONG(0)
                rv = raw.C_WrapKey(
                    sh,
                    mech.byref(),
                    wrap_key.value,
                    target_key.value,
                    None,
                    byref(needed),
                )
                if rv != CKR_OK:
                    print(f"SETUP_XFAIL:C_WrapKey size query failed: {ckr_name(rv)}")
                elif needed.value <= 1:
                    print(f"SETUP_XFAIL:C_WrapKey reported only {needed.value} output byte(s)")
                else:
                    guard = 0xC3
                    guard_size = 32

                    class WrapProbe(ctypes.Structure):
                        _fields_ = [
                            ("data", ctypes.c_ubyte * 1),
                            ("guard", ctypes.c_ubyte * guard_size),
                        ]

                    probe = WrapProbe()
                    for idx in range(guard_size):
                        probe.guard[idx] = guard

                    out_len = CK_ULONG(1)
                    print(f"NEEDED:{needed.value}")
                    rv = raw.C_WrapKey(
                        sh,
                        mech.byref(),
                        wrap_key.value,
                        target_key.value,
                        cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
                        byref(out_len),
                    )
                    print(f"CKR:0x{rv:08x}")
                    print(f"LEN:{out_len.value}")
                    overwritten = sum(1 for byte in probe.guard if byte != guard)
                    print(f"OVERWRITTEN:{overwritten}")
                    assert overwritten == 0, (
                        "C_WrapKey wrote past the declared one-byte output buffer: "
                        f"{overwritten} guard byte(s) changed"
                    )
                    if rv == CKR_BUFFER_TOO_SMALL:
                        retry_len = CK_ULONG(needed.value)
                        retry_buf = (ctypes.c_ubyte * needed.value)()
                        retry_rv = raw.C_WrapKey(
                            sh,
                            mech.byref(),
                            wrap_key.value,
                            target_key.value,
                            cast(retry_buf, ctypes.POINTER(ctypes.c_ubyte)),
                            byref(retry_len),
                        )
                        print(f"RETRY_CKR:0x{retry_rv:08x}")
                        print(f"RETRY_LEN:{retry_len.value}")
                    print("OK")
    finally:
        if target_key.value:
            raw.C_DestroyObject(sh, target_key.value)
        if wrap_key.value:
            raw.C_DestroyObject(sh, wrap_key.value)


def _ecdh_aes_wrap_compressed_public_key_buffer_too_small(ctx: ProbeContext) -> None:
    """ECDH-AES C_WrapKey with compressed EC public key must size safely."""
    raw = ctx.raw
    sh = ctx.sh
    curve_oid = encode_named_curve_parameters("secp256r1")
    pub_attrs = template(
        attr_bytes(CKA_EC_PARAMS, curve_oid),
        attr_bool(CKA_VERIFY, True),
        attr_bool(CKA_WRAP, True),
        attr_bool(CKA_DERIVE, True),
        attr_bool(CKA_TOKEN, False),
    )
    priv_attrs = template(
        attr_bool(CKA_UNWRAP, True),
        attr_bool(CKA_DERIVE, True),
        attr_bool(CKA_TOKEN, False),
    )
    keypair_mech = mech_simple(CKM_EC_KEY_PAIR_GEN)
    pub = CK_OBJECT_HANDLE(0)
    priv = CK_OBJECT_HANDLE(0)
    compressed_pub = CK_OBJECT_HANDLE(0)
    target_key = CK_OBJECT_HANDLE(0)
    try:
        rv = raw.C_GenerateKeyPair(
            sh,
            keypair_mech.byref(),
            _template_ptr(pub_attrs),
            pub_attrs.count,
            _template_ptr(priv_attrs),
            priv_attrs.count,
            byref(pub),
            byref(priv),
        )
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_GenerateKeyPair for ECDH-AES wrap failed: {ckr_name(rv)}")
        else:
            assert sh is not None  # Level.LOGIN always opens a session
            attrs = read_attributes(raw, sh, pub.value, [CKA_EC_POINT, CKA_EC_PARAMS])
            try:
                compressed_point = _compress_p256_ec_point(attrs[CKA_EC_POINT])
            except ValueError as exc:
                print(f"SETUP_XFAIL:cannot build compressed EC point: {exc}")
            else:
                imported_pub_attrs = template(
                    attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY),
                    attr_ulong(CKA_KEY_TYPE, CKK_EC),
                    attr_bytes(CKA_EC_PARAMS, attrs[CKA_EC_PARAMS]),
                    attr_bytes(CKA_EC_POINT, compressed_point),
                    attr_bool(CKA_WRAP, True),
                    attr_bool(CKA_DERIVE, True),
                    attr_bool(CKA_TOKEN, False),
                )
                rv = raw.C_CreateObject(
                    sh,
                    _template_ptr(imported_pub_attrs),
                    imported_pub_attrs.count,
                    byref(compressed_pub),
                )
                if rv != CKR_OK:
                    print(f"SETUP_XFAIL:compressed EC public-key import rejected: {ckr_name(rv)}")
                else:
                    target_attrs = template(
                        attr_ulong(CKA_VALUE_LEN, 16),
                        attr_bool(CKA_EXTRACTABLE, True),
                        attr_bool(CKA_TOKEN, False),
                    )
                    aes_mech = mech_simple(CKM_AES_KEY_GEN)
                    rv = raw.C_GenerateKey(
                        sh,
                        aes_mech.byref(),
                        _template_ptr(target_attrs),
                        target_attrs.count,
                        byref(target_key),
                    )
                    if rv != CKR_OK:
                        print(
                            "SETUP_XFAIL:C_GenerateKey for ECDH-AES target key failed: "
                            f"{ckr_name(rv)}"
                        )
                    else:
                        mech = mech_ecdh_aes_kw(
                            CKM_ECDH_AES_KEY_WRAP,
                            aes_key_bits=256,
                            kdf=CKD_SHA256_KDF,
                        )
                        needed = CK_ULONG(0)
                        rv = raw.C_WrapKey(
                            sh,
                            mech.byref(),
                            compressed_pub.value,
                            target_key.value,
                            None,
                            byref(needed),
                        )
                        if rv != CKR_OK:
                            print(
                                f"SETUP_XFAIL:ECDH-AES C_WrapKey size query failed: {ckr_name(rv)}"
                            )
                        elif needed.value <= 1:
                            print(
                                "SETUP_XFAIL:ECDH-AES C_WrapKey reported only "
                                f"{needed.value} output byte(s)"
                            )
                        else:
                            guard = 0xA7
                            guard_size = 32

                            class WrapProbe(ctypes.Structure):
                                _fields_ = [
                                    ("data", ctypes.c_ubyte * 1),
                                    ("guard", ctypes.c_ubyte * guard_size),
                                ]

                            probe = WrapProbe()
                            for idx in range(guard_size):
                                probe.guard[idx] = guard

                            out_len = CK_ULONG(1)
                            print(f"NEEDED:{needed.value}")
                            rv = raw.C_WrapKey(
                                sh,
                                mech.byref(),
                                compressed_pub.value,
                                target_key.value,
                                cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
                                byref(out_len),
                            )
                            print(f"CKR:0x{rv:08x}")
                            print(f"LEN:{out_len.value}")
                            overwritten = sum(1 for byte in probe.guard if byte != guard)
                            print(f"OVERWRITTEN:{overwritten}")
                            assert overwritten == 0, (
                                "ECDH-AES C_WrapKey wrote past the declared one-byte output "
                                f"buffer: {overwritten} guard byte(s) changed"
                            )
                            if rv == CKR_BUFFER_TOO_SMALL:
                                retry_len = CK_ULONG(needed.value)
                                retry_buf = (ctypes.c_ubyte * needed.value)()
                                retry_rv = raw.C_WrapKey(
                                    sh,
                                    mech.byref(),
                                    compressed_pub.value,
                                    target_key.value,
                                    cast(retry_buf, ctypes.POINTER(ctypes.c_ubyte)),
                                    byref(retry_len),
                                )
                                print(f"RETRY_CKR:0x{retry_rv:08x}")
                                print(f"RETRY_LEN:{retry_len.value}")
                            print("OK")
    finally:
        if target_key.value:
            raw.C_DestroyObject(sh, target_key.value)
        if compressed_pub.value:
            raw.C_DestroyObject(sh, compressed_pub.value)
        if priv.value:
            raw.C_DestroyObject(sh, priv.value)
        if pub.value:
            raw.C_DestroyObject(sh, pub.value)


def _get_operation_state_buffer_too_small(ctx: ProbeContext) -> None:
    """C_GetOperationState with one declared byte must preserve adjacent guard bytes."""
    raw = ctx.raw
    sh = ctx.sh
    mech = mech_simple(CKM_SHA256)
    rv = raw.C_DigestInit(sh, mech.byref())
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_DigestInit(CKM_SHA256) failed: {ckr_name(rv)}")
    else:
        data = (ctypes.c_ubyte * 16)(*([0x42] * 16))
        rv = raw.C_DigestUpdate(sh, data, 16)
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_DigestUpdate(CKM_SHA256) failed: {ckr_name(rv)}")
        else:
            needed = CK_ULONG(0)
            rv = raw.C_GetOperationState(sh, None, byref(needed))
            if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_STATE_UNSAVEABLE):
                print(f"SETUP_XFAIL:C_GetOperationState is not saveable: {ckr_name(rv)}")
            elif rv == CKR_OPERATION_NOT_INITIALIZED:
                print("SETUP_XFAIL:C_GetOperationState reported no active digest operation")
            elif rv != CKR_OK:
                print(f"SETUP_XFAIL:C_GetOperationState size query failed: {ckr_name(rv)}")
            elif needed.value <= 1:
                print(f"SETUP_XFAIL:C_GetOperationState returned only {needed.value} state byte(s)")
            else:
                guard = 0x3C
                guard_size = 32

                class StateProbe(ctypes.Structure):
                    _fields_ = [
                        ("data", ctypes.c_ubyte * 1),
                        ("guard", ctypes.c_ubyte * guard_size),
                    ]

                probe = StateProbe()
                for idx in range(guard_size):
                    probe.guard[idx] = guard

                out_len = CK_ULONG(1)
                print(f"NEEDED:{needed.value}")
                rv = raw.C_GetOperationState(
                    sh,
                    cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
                    byref(out_len),
                )
                print(f"CKR:0x{rv:08x}")
                print(f"LEN:{out_len.value}")
                overwritten = sum(1 for byte in probe.guard if byte != guard)
                print(f"OVERWRITTEN:{overwritten}")
                assert overwritten == 0, (
                    "C_GetOperationState wrote past the declared one-byte output buffer: "
                    f"{overwritten} guard byte(s) changed"
                )
                if rv == CKR_BUFFER_TOO_SMALL:
                    retry_len = CK_ULONG(needed.value)
                    retry_buf = (ctypes.c_ubyte * needed.value)()
                    retry_rv = raw.C_GetOperationState(
                        sh,
                        cast(retry_buf, ctypes.POINTER(ctypes.c_ubyte)),
                        byref(retry_len),
                    )
                    print(f"RETRY_CKR:0x{retry_rv:08x}")
                    print(f"RETRY_LEN:{retry_len.value}")
                print("OK")


_PROBES: dict[str, Callable[[ProbeContext], None]] = {
    "digest_buffer_too_small": _digest_buffer_too_small,
    "encrypt_buffer_too_small": _encrypt_buffer_too_small,
    "sign_buffer_too_small": _sign_buffer_too_small,
    "get_slot_list_guard": _get_slot_list_guard,
    "get_mechanism_list_guard": _get_mechanism_list_guard,
    "get_interface_list_guard": _get_interface_list_guard,
    "find_objects_max_count_one_guard": _find_objects_max_count_one_guard,
    "get_attribute_value_guard": _get_attribute_value_guard,
    "aes_cbc_pad_decrypt_buffer_too_small": _aes_cbc_pad_decrypt_buffer_too_small,
    "aes_cbc_pad_decrypt_update_buffer_too_small": _aes_cbc_pad_decrypt_update_buffer_too_small,
    "aes_cbc_pad_encrypt_final_buffer_too_small": _aes_cbc_pad_encrypt_final_buffer_too_small,
    "aes_cbc_pad_decrypt_final_buffer_too_small": _aes_cbc_pad_decrypt_final_buffer_too_small,
    "wrap_key_buffer_too_small": _wrap_key_buffer_too_small,
    "ecdh_aes_wrap_compressed_public_key_buffer_too_small": (
        _ecdh_aes_wrap_compressed_public_key_buffer_too_small
    ),
    "get_operation_state_buffer_too_small": _get_operation_state_buffer_too_small,
}


def _run(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe = extra["probe"]
    try:
        handler = _PROBES[probe]
    except KeyError:
        raise ValueError(f"unknown probe {probe!r}") from None
    handler(ctx)


if __name__ == "__main__":
    probe_main(_run, level=Level.LOGIN)
