"""Probe: CKR_BUFFER_TOO_SMALL / output-guard error conditions via a raw session.

Eight child bodies ported verbatim from the legacy ``ckr/test_ckr_raw_buffer.py`` scripts
(Batch A of the file's migration), dispatched on ``extra["probe"]``.  Each drives an output
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

from pkcs11_check.raw.pack import (
    TemplateArg,
    attr_bool,
    attr_bytes,
    attr_ulong,
    mech_simple,
    template,
)
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
    CKA_ENCRYPT,
    CKA_LABEL,
    CKA_MODULUS_BITS,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKO_DATA,
    CKR_BUFFER_TOO_SMALL,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _template_ptr(attrs: TemplateArg) -> Any:
    return cast(attrs.array, CK_ATTRIBUTE_PTR)


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


_PROBES: dict[str, Callable[[ProbeContext], None]] = {
    "digest_buffer_too_small": _digest_buffer_too_small,
    "encrypt_buffer_too_small": _encrypt_buffer_too_small,
    "sign_buffer_too_small": _sign_buffer_too_small,
    "get_slot_list_guard": _get_slot_list_guard,
    "get_mechanism_list_guard": _get_mechanism_list_guard,
    "get_interface_list_guard": _get_interface_list_guard,
    "find_objects_max_count_one_guard": _find_objects_max_count_one_guard,
    "get_attribute_value_guard": _get_attribute_value_guard,
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
