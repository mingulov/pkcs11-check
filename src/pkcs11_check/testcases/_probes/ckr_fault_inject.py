"""Probe: fault-injection + delegation checks driven through a fault-proxy module.

Five child bodies ported verbatim from the legacy ``ckr/test_ckr_fault_inject.py`` scripts,
dispatched on ``extra["probe"]``.  Each loads the *fault-proxy* module (``params.module_path``
is the proxy, NOT the real provider) which delegates to the real module and -- for the three
injection probes -- forces a specific CK_RV on one function:

  ``"inject_device_removed_on_encrypt"`` -- generate an AES key, C_EncryptInit, then C_Encrypt
      must surface the injected CKR_DEVICE_REMOVED.  Emits ``OK:DEVICE_REMOVED`` / ``FAIL:no_error``
      / ``OTHER:0x{rv:08x}`` (setup failures -> ``SETUP_XFAIL:...``).
  ``"inject_device_error_on_sign"`` -- generate an RSA keypair, C_SignInit, then C_Sign must
      surface the injected CKR_DEVICE_ERROR.  Emits ``OK:DEVICE_ERROR`` / ``FAIL:no_error`` /
      ``OTHER:0x{rv:08x}`` (setup failures -> ``SETUP_XFAIL:...``).
  ``"inject_device_memory_on_generate_key"`` -- C_GenerateKey must surface the injected
      CKR_DEVICE_MEMORY.  Emits ``OK:DEVICE_MEMORY`` / ``FAIL:no_error`` / ``OTHER:0x{rv:08x}``.
  ``"proxy_loads_real_module"`` -- the proxy loads the real module and lists slots.  Emits
      ``OK:{n}_slots``.  Runs at ``Level.INIT`` (C_Initialize + slot list only, no session/login --
      the legacy child never opened a session).
  ``"proxy_encrypt_decrypt"`` -- full AES-ECB encrypt/decrypt roundtrip through the proxy.  Emits
      ``OK:encrypt_decrypt_roundtrip`` (setup failure -> ``SETUP_XFAIL:...``).

The fault-proxy reads its delegation + injection config from the environment as it loads, which
happens inside ``probe_main``'s ``from_lib`` -- *before* ``_run``.  So ``PKCS11_REAL_MODULE`` (and,
for the injection probes, ``PKCS11_INJECT_FUNCTION`` / ``PKCS11_INJECT_ERROR``) are set from
``params.extra`` in ``_main`` before ``probe_main`` runs -- plain data threaded through params,
never a PIN -- reproducing the legacy child's pre-load ``os.environ`` writes.

The four session probes run at ``Level.LOGIN``: the infra opens a session and -- only when a PIN
is configured -- logs in, with the PIN travelling solely through the ``_P11CHECK_PIN`` env var
(never embedded in source or params -- Invariant I3).  This CLOSES the legacy leak that formatted
the PIN literal into the generated child-script source.  Session teardown + rv-trace are handled
by ``probe_main`` atexit, matching the legacy ``_p11check_cleanup_session`` / rv-trace setup.

Output protocol (byte-identical to the legacy child, for ``assert_ckr_subprocess_ok`` and the
parent-side ``in stdout`` checks):
  ``OK:DEVICE_REMOVED`` / ``OK:DEVICE_ERROR`` / ``OK:DEVICE_MEMORY``  -- injection fired
  ``FAIL:no_error``                 -- injection did not fire (the call returned CKR_OK)
  ``OTHER:0x{rv:08x}``              -- some other CK_RV
  ``OK:{n}_slots``                  -- proxy slot delegation
  ``OK:encrypt_decrypt_roundtrip``  -- proxy AES roundtrip
  ``SETUP_XFAIL:...``               -- a setup step cleanly failed

Required ``extra`` keys:
  ``"probe"``       -- one of the dispatch keys above.
  ``"real_module"`` -- path the fault-proxy delegates to (``PKCS11_REAL_MODULE``; plain data).
For the injection probes additionally (plain data, never a PIN):
  ``"inject_function"`` -- function to inject on (``PKCS11_INJECT_FUNCTION``).
  ``"inject_error"``    -- CK_RV hex string to inject (``PKCS11_INJECT_ERROR``).

Launch with ``coverage="session"``; ``pin=pin_from_config(p11_config)`` for the session probes,
no PIN for ``"proxy_loads_real_module"`` (it never logs in).
"""

from __future__ import annotations

import ctypes
import os
import sys
from collections.abc import Callable
from typing import Any

from pkcs11_check.raw.bootstrap import get_slot_ids
from pkcs11_check.raw.pack import attr_ulong, mech_simple, template
from pkcs11_check.raw.recipes import decrypt_single, encrypt_single, gen_aes_key, gen_rsa_keypair
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_VALUE_LEN,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_SHA256_RSA_PKCS,
    CKR_DEVICE_ERROR,
    CKR_DEVICE_MEMORY,
    CKR_DEVICE_REMOVED,
    CKR_OK,
)
from pkcs11_check.testcases._probes.params import ProbeParams
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _inject_device_removed_on_encrypt(ctx: ProbeContext) -> None:
    """C_Encrypt must surface the fault-proxy's injected CKR_DEVICE_REMOVED."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    try:
        key = gen_aes_key(ctx.raw, sh, 256)
    except AssertionError as exc:
        print(f"SETUP_XFAIL:C_GenerateKey for fault-injected encrypt failed: {exc}")
    else:
        mech = mech_simple(CKM_AES_ECB)
        rv = ctx.raw.C_EncryptInit(sh, mech.byref(), key)
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_EncryptInit for fault injection failed: {ckr_name(rv)}")
        else:
            data = (ctypes.c_ubyte * 16)(*([0] * 16))
            out_len = CK_ULONG(32)
            out_buf = (ctypes.c_ubyte * 32)()
            rv = ctx.raw.C_Encrypt(sh, data, 16, out_buf, ctypes.byref(out_len))
            if rv == CKR_DEVICE_REMOVED:
                print("OK:DEVICE_REMOVED")
            elif rv == CKR_OK:
                print("FAIL:no_error")
            else:
                print(f"OTHER:0x{rv:08x}")


def _inject_device_error_on_sign(ctx: ProbeContext) -> None:
    """C_Sign must surface the fault-proxy's injected CKR_DEVICE_ERROR."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    try:
        _pub, priv = gen_rsa_keypair(ctx.raw, sh, 2048)
    except AssertionError as exc:
        print(f"SETUP_XFAIL:C_GenerateKeyPair for fault-injected sign failed: {exc}")
    else:
        mech = mech_simple(CKM_SHA256_RSA_PKCS)
        rv = ctx.raw.C_SignInit(sh, mech.byref(), priv)
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_SignInit for fault injection failed: {ckr_name(rv)}")
        else:
            data = (ctypes.c_ubyte * 4)(*b"test")
            sig_len = CK_ULONG(256)
            sig_buf = (ctypes.c_ubyte * 256)()
            rv = ctx.raw.C_Sign(sh, data, 4, sig_buf, ctypes.byref(sig_len))
            if rv == CKR_DEVICE_ERROR:
                print("OK:DEVICE_ERROR")
            elif rv == CKR_OK:
                print("FAIL:no_error")
            else:
                print(f"OTHER:0x{rv:08x}")


def _inject_device_memory_on_generate_key(ctx: ProbeContext) -> None:
    """C_GenerateKey must surface the fault-proxy's injected CKR_DEVICE_MEMORY."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    mech = mech_simple(CKM_AES_KEY_GEN)
    tmpl = template(attr_ulong(CKA_VALUE_LEN, 32))
    key = CK_OBJECT_HANDLE(0)
    rv = ctx.raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, ctypes.byref(key))
    if rv == CKR_DEVICE_MEMORY:
        print("OK:DEVICE_MEMORY")
    elif rv == CKR_OK:
        print("FAIL:no_error")
    else:
        print(f"OTHER:0x{rv:08x}")


def _proxy_loads_real_module(ctx: ProbeContext) -> None:
    """Proxy loads the real module and lists slots (Level.INIT: no session/login)."""
    slots = get_slot_ids(ctx.raw)
    print(f"OK:{len(slots)}_slots")


def _proxy_encrypt_decrypt(ctx: ProbeContext) -> None:
    """Full AES-ECB encrypt/decrypt roundtrip delegated through the proxy."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    try:
        key = gen_aes_key(ctx.raw, sh, 256)
    except AssertionError as exc:
        print(f"SETUP_XFAIL:C_GenerateKey for proxy roundtrip failed: {exc}")
    else:
        ct = encrypt_single(ctx.raw, sh, key, CKM_AES_ECB, b"\x00" * 16)
        pt = decrypt_single(ctx.raw, sh, key, CKM_AES_ECB, ct)
        assert pt == b"\x00" * 16
        print("OK:encrypt_decrypt_roundtrip")


_PROBES: dict[str, Callable[[ProbeContext], None]] = {
    "inject_device_removed_on_encrypt": _inject_device_removed_on_encrypt,
    "inject_device_error_on_sign": _inject_device_error_on_sign,
    "inject_device_memory_on_generate_key": _inject_device_memory_on_generate_key,
    "proxy_loads_real_module": _proxy_loads_real_module,
    "proxy_encrypt_decrypt": _proxy_encrypt_decrypt,
}


def _run(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe = extra["probe"]
    try:
        handler = _PROBES[probe]
    except KeyError:
        raise ValueError(f"unknown probe {probe!r}") from None
    handler(ctx)


def _main() -> None:
    params = ProbeParams.load(sys.argv[1])
    extra = params.extra
    # The fault-proxy reads its delegation + injection config from the environment as it
    # loads, which happens inside probe_main's from_lib() before _run -- so set them here,
    # ahead of probe_main, from the params (plain data; never a PIN).
    os.environ["PKCS11_REAL_MODULE"] = extra["real_module"]
    inject_function = extra.get("inject_function")
    if inject_function is not None:
        os.environ["PKCS11_INJECT_FUNCTION"] = inject_function
        os.environ["PKCS11_INJECT_ERROR"] = extra["inject_error"]
    level = Level.INIT if extra.get("probe") == "proxy_loads_real_module" else Level.LOGIN
    probe_main(_run, level=level)


if __name__ == "__main__":
    _main()
