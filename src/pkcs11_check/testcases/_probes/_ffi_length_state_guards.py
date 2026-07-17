"""ffi_length arm group: update/final/single-shot output-guard + continuation probes.

Moved verbatim from ffi_length.py (god-module split, 2026-07-17); dispatched via
ffi_length._DISPATCH.  Output protocol unchanged (TARGET_RV/GUARD_OVERWRITE lines).
"""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
)
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_ULONG,
    CKM_AES_ECB,
    CKR_OK,
)
from pkcs11_check.testcases._probes._ffi_length_base import (
    _setup_reject_or_raise,
    _SetupRejected,
)
from pkcs11_check.testcases._probes.honeypot import (
    SETUP_XFAIL_PREFIX,
)
from pkcs11_check.testcases._probes.session import ProbeContext
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
)


def _run_encrypt_update_guard(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_EncryptUpdate with one declared output byte must preserve guard bytes."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"INIT_RV:0x{rv:08x}", flush=True)
        if rv == CKR_OK:
            buf = (ctypes.c_ubyte * 16)(*range(16))
            needed = CK_ULONG(0)
            rv_q = raw.C_EncryptUpdate(sh, buf, 16, None, ctypes.byref(needed))
            print(f"QUERY_RV:0x{rv_q:08x}", flush=True)
            print(f"NEEDED:{needed.value}", flush=True)
            if rv_q == CKR_OK:
                guard_byte = 0xE1
                guard_size = 32

                class UpdateProbe(ctypes.Structure):
                    _fields_ = [
                        ("data", ctypes.c_ubyte * 1),
                        ("guard", ctypes.c_ubyte * guard_size),
                    ]

                probe = UpdateProbe()
                for idx in range(guard_size):
                    probe.guard[idx] = guard_byte
                out_len = CK_ULONG(1)
                rv2 = raw.C_EncryptUpdate(
                    sh,
                    buf,
                    16,
                    ctypes.cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
                    ctypes.byref(out_len),
                )
                print(f"FINAL_RV:0x{rv2:08x}", flush=True)
                print(f"LEN:{out_len.value}", flush=True)
                overwritten = sum(1 for byte in probe.guard if byte != guard_byte)
                print(f"OVERWRITTEN:{overwritten}", flush=True)
                if overwritten != 0:
                    print(f"GUARD_OVERWRITE:{overwritten}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_decrypt_update_guard(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_DecryptUpdate with one declared output byte must preserve guard bytes."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0

        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}encrypt setup (C_EncryptInit) rejected: rv=0x{rv:08x}")
            raise _SetupRejected
        pt_buf = (ctypes.c_ubyte * 16)(*range(16))
        ct_buf = (ctypes.c_ubyte * 16)()
        ct_len = CK_ULONG(16)
        rv = raw.C_Encrypt(sh, pt_buf, 16, ct_buf, ctypes.byref(ct_len))
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}encrypt setup (C_Encrypt) rejected: rv=0x{rv:08x}")
            raise _SetupRejected

        dec_rv = raw.C_DecryptInit(sh, ctypes.byref(mech), key)
        print(f"INIT_RV:0x{dec_rv:08x}", flush=True)
        if dec_rv == CKR_OK:
            needed = CK_ULONG(0)
            rv_q = raw.C_DecryptUpdate(sh, ct_buf, 16, None, ctypes.byref(needed))
            print(f"QUERY_RV:0x{rv_q:08x}", flush=True)
            print(f"NEEDED:{needed.value}", flush=True)
            if rv_q == CKR_OK:
                guard_byte = 0xD2
                guard_size = 32

                class UpdateProbe(ctypes.Structure):
                    _fields_ = [
                        ("data", ctypes.c_ubyte * 1),
                        ("guard", ctypes.c_ubyte * guard_size),
                    ]

                probe = UpdateProbe()
                for idx in range(guard_size):
                    probe.guard[idx] = guard_byte
                out_len = CK_ULONG(1)
                rv2 = raw.C_DecryptUpdate(
                    sh,
                    ct_buf,
                    16,
                    ctypes.cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
                    ctypes.byref(out_len),
                )
                print(f"FINAL_RV:0x{rv2:08x}", flush=True)
                print(f"LEN:{out_len.value}", flush=True)
                overwritten = sum(1 for byte in probe.guard if byte != guard_byte)
                print(f"OVERWRITTEN:{overwritten}", flush=True)
                if overwritten != 0:
                    print(f"GUARD_OVERWRITE:{overwritten}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_encrypt_update_continuation(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_EncryptUpdate real call after a NULL-output size query must continue."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"INIT_RV:0x{rv:08x}", flush=True)
        if rv == CKR_OK:
            buf = (ctypes.c_ubyte * 16)(*range(16))
            needed = CK_ULONG(0)
            rv_q = raw.C_EncryptUpdate(sh, buf, 16, None, ctypes.byref(needed))
            print(f"QUERY_RV:0x{rv_q:08x}", flush=True)
            if rv_q == CKR_OK:
                real_buf = (ctypes.c_ubyte * 64)()
                real_len = CK_ULONG(64)
                rv2 = raw.C_EncryptUpdate(sh, buf, 16, real_buf, ctypes.byref(real_len))
                print(f"CONTINUATION_RV:0x{rv2:08x}", flush=True)
    finally:
        destroy_quietly(raw, sh, key)


def _run_decrypt_update_continuation(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_DecryptUpdate real call after a NULL-output size query must continue."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0

        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}encrypt setup (C_EncryptInit) rejected: rv=0x{rv:08x}")
            raise _SetupRejected
        pt_buf = (ctypes.c_ubyte * 16)(*range(16))
        ct_buf = (ctypes.c_ubyte * 16)()
        ct_len = CK_ULONG(16)
        rv = raw.C_Encrypt(sh, pt_buf, 16, ct_buf, ctypes.byref(ct_len))
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}encrypt setup (C_Encrypt) rejected: rv=0x{rv:08x}")
            raise _SetupRejected

        dec_rv = raw.C_DecryptInit(sh, ctypes.byref(mech), key)
        print(f"INIT_RV:0x{dec_rv:08x}", flush=True)
        if dec_rv == CKR_OK:
            needed = CK_ULONG(0)
            rv_q = raw.C_DecryptUpdate(sh, ct_buf, 16, None, ctypes.byref(needed))
            print(f"QUERY_RV:0x{rv_q:08x}", flush=True)
            if rv_q == CKR_OK:
                real_buf = (ctypes.c_ubyte * 64)()
                real_len = CK_ULONG(64)
                rv2 = raw.C_DecryptUpdate(sh, ct_buf, 16, real_buf, ctypes.byref(real_len))
                print(f"CONTINUATION_RV:0x{rv2:08x}", flush=True)
    finally:
        destroy_quietly(raw, sh, key)


def _run_encrypt_final_continuation(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_EncryptFinal real call after a NULL-output size query must continue."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"INIT_RV:0x{rv:08x}", flush=True)
        if rv == CKR_OK:
            buf = (ctypes.c_ubyte * 16)(*range(16))
            upd_buf = (ctypes.c_ubyte * 16)()
            upd_len = CK_ULONG(16)
            rv_u = raw.C_EncryptUpdate(sh, buf, 16, upd_buf, ctypes.byref(upd_len))
            print(f"UPDATE_RV:0x{rv_u:08x}", flush=True)
            if rv_u == CKR_OK:
                needed = CK_ULONG(0)
                rv_q = raw.C_EncryptFinal(sh, None, ctypes.byref(needed))
                print(f"QUERY_RV:0x{rv_q:08x}", flush=True)
                if rv_q == CKR_OK:
                    real_buf = (ctypes.c_ubyte * 64)()
                    real_len = CK_ULONG(64)
                    rv2 = raw.C_EncryptFinal(sh, real_buf, ctypes.byref(real_len))
                    print(f"CONTINUATION_RV:0x{rv2:08x}", flush=True)
    finally:
        destroy_quietly(raw, sh, key)


def _run_decrypt_final_continuation(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_DecryptFinal real call after a NULL-output size query must continue."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0

        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}encrypt setup (C_EncryptInit) rejected: rv=0x{rv:08x}")
            raise _SetupRejected
        pt_buf = (ctypes.c_ubyte * 16)(*range(16))
        ct_buf = (ctypes.c_ubyte * 16)()
        ct_len = CK_ULONG(16)
        rv = raw.C_Encrypt(sh, pt_buf, 16, ct_buf, ctypes.byref(ct_len))
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}encrypt setup (C_Encrypt) rejected: rv=0x{rv:08x}")
            raise _SetupRejected

        dec_rv = raw.C_DecryptInit(sh, ctypes.byref(mech), key)
        print(f"INIT_RV:0x{dec_rv:08x}", flush=True)
        if dec_rv == CKR_OK:
            upd_buf = (ctypes.c_ubyte * 16)()
            upd_len = CK_ULONG(16)
            rv_u = raw.C_DecryptUpdate(sh, ct_buf, 16, upd_buf, ctypes.byref(upd_len))
            print(f"UPDATE_RV:0x{rv_u:08x}", flush=True)
            if rv_u == CKR_OK:
                needed = CK_ULONG(0)
                rv_q = raw.C_DecryptFinal(sh, None, ctypes.byref(needed))
                print(f"QUERY_RV:0x{rv_q:08x}", flush=True)
                if rv_q == CKR_OK:
                    real_buf = (ctypes.c_ubyte * 64)()
                    real_len = CK_ULONG(64)
                    rv2 = raw.C_DecryptFinal(sh, real_buf, ctypes.byref(real_len))
                    print(f"CONTINUATION_RV:0x{rv2:08x}", flush=True)
    finally:
        destroy_quietly(raw, sh, key)


def _run_encrypt_single_shot_guard(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_Encrypt single-shot with one declared output byte must preserve guard bytes."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_ECB
        mech.pParameter = None
        mech.ulParameterLen = 0
        rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
        print(f"INIT_RV:0x{rv:08x}", flush=True)
        if rv == CKR_OK:
            guard_byte = 0xC3
            guard_size = 32

            class SingleShotProbe(ctypes.Structure):
                _fields_ = [
                    ("data", ctypes.c_ubyte * 1),
                    ("guard", ctypes.c_ubyte * guard_size),
                ]

            probe = SingleShotProbe()
            for idx in range(guard_size):
                probe.guard[idx] = guard_byte
            pt_buf = (ctypes.c_ubyte * 16)(*range(16))
            out_len = CK_ULONG(1)
            rv2 = raw.C_Encrypt(
                sh,
                pt_buf,
                16,
                ctypes.cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
                ctypes.byref(out_len),
            )
            print(f"TARGET_RV:0x{rv2:08x}", flush=True)
            overwritten = sum(1 for byte in probe.guard if byte != guard_byte)
            if overwritten != 0:
                print(f"GUARD_OVERWRITE:{overwritten}")
    finally:
        destroy_quietly(raw, sh, key)


def _run_decrypt_single_shot_guard(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """C_Decrypt single-shot with one declared output byte must preserve guard bytes."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    raw = ctx.raw

    try:
        key = gen_aes_key(raw, sh, 256)
    except AssertionError as exc:
        _setup_reject_or_raise(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected")

    try:
        # Produce a valid AES-ECB ciphertext block to use as decrypt input.
        enc_mech = CK_MECHANISM()
        enc_mech.mechanism = CKM_AES_ECB
        enc_mech.pParameter = None
        enc_mech.ulParameterLen = 0
        rv = raw.C_EncryptInit(sh, ctypes.byref(enc_mech), key)
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}encrypt setup (C_EncryptInit) rejected: rv=0x{rv:08x}")
            raise _SetupRejected
        pt_buf = (ctypes.c_ubyte * 16)(*range(16))
        ct_buf = (ctypes.c_ubyte * 16)()
        ct_len = CK_ULONG(16)
        rv = raw.C_Encrypt(sh, pt_buf, 16, ct_buf, ctypes.byref(ct_len))
        if rv != CKR_OK:
            print(f"{SETUP_XFAIL_PREFIX}encrypt setup (C_Encrypt) rejected: rv=0x{rv:08x}")
            raise _SetupRejected

        dec_mech = CK_MECHANISM()
        dec_mech.mechanism = CKM_AES_ECB
        dec_mech.pParameter = None
        dec_mech.ulParameterLen = 0
        dec_rv = raw.C_DecryptInit(sh, ctypes.byref(dec_mech), key)
        print(f"INIT_RV:0x{dec_rv:08x}", flush=True)
        if dec_rv == CKR_OK:
            guard_byte = 0xD4
            guard_size = 32

            class SingleShotProbe(ctypes.Structure):
                _fields_ = [
                    ("data", ctypes.c_ubyte * 1),
                    ("guard", ctypes.c_ubyte * guard_size),
                ]

            probe = SingleShotProbe()
            for idx in range(guard_size):
                probe.guard[idx] = guard_byte
            out_len = CK_ULONG(1)
            rv2 = raw.C_Decrypt(
                sh,
                ct_buf,
                16,
                ctypes.cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
                ctypes.byref(out_len),
            )
            print(f"TARGET_RV:0x{rv2:08x}", flush=True)
            overwritten = sum(1 for byte in probe.guard if byte != guard_byte)
            if overwritten != 0:
                print(f"GUARD_OVERWRITE:{overwritten}")
    finally:
        destroy_quietly(raw, sh, key)
