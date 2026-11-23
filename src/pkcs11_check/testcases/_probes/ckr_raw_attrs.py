"""Probe: CKA_*=False permission flags tested via raw C_*Init calls.

Ported verbatim from the legacy ``ckr/test_ckr_raw_attrs.py`` child scripts, which
drove the module through a logged-in ``RawPKCS11`` session built by
``subprocess_session_preamble``.  Each probe generates a key with one usage
attribute (``CKA_ENCRYPT`` / ``CKA_SIGN`` / ``CKA_DECRYPT``) set to False (AES for
encrypt/decrypt; generic-secret-first with an AES fallback for sign), reads the
flag back (claim check), then issues the matching raw ``C_*Init`` -- bypassing the
python-pkcs11 wrapper's attribute checks -- so the parent can classify whether the
module honored the restriction (PKCS#11 v3.2 requires ``CKR_KEY_FUNCTION_NOT_PERMITTED``).

Runs through ``probe_main`` at ``Level.LOGIN``: the infra does C_Initialize + slot
discovery + ``C_OpenSession`` + (only when ``_P11CHECK_PIN`` is set) ``C_Login`` before
handing the probe ``ctx.raw`` / ``ctx.sh`` -- mirroring the legacy child, which opened a
session and logged in only when a PIN was configured.  The PIN travels ONLY via the
``_P11CHECK_PIN`` env var; it is never read, printed, or embedded here or in the probe
params (Invariant I3).  Session teardown + rv-trace are handled by ``probe_main`` atexit.

Dispatch on ``extra["probe"]`` (one child body each):
  ``"encrypt"`` -> key with CKA_ENCRYPT=False, then ``C_EncryptInit`` (CKM_AES_ECB)
  ``"sign"``    -> key with CKA_SIGN=False, then ``C_SignInit`` (CKM_SHA256_HMAC
                 on a generic-secret key; AES fallback, then setup-xfail)
  ``"decrypt"`` -> key with CKA_DECRYPT=False, then ``C_DecryptInit`` (CKM_AES_ECB)

Output protocol (for ``assert_ckr_subprocess_ok`` plus the parent's
permission-probe classifier):
  ``ATTRIBUTE_EVENT:{json}``                                 -- claim readback event
      ``event=boolean,value=false``                           -- present flag is False
      ``event=boolean,value=true``                            -- present flag is True
      ``event=omitted``                                      -- requested flag was absent
      ``event=malformed,value_type/value_repr``              -- present non-bool value
  ``CKR:0x{rv:08x}``                                          -- return value of the C_*Init call
  ``OK``                                                      -- probe reached its end
  ``SETUP_REFUSED:{C_Op}:0x{rv:08x}``                           -- numeric setup/control refusal
      (generic keygen/import, AES keygen, or a failed R4-3 positive control;
      undefined RVs fail as metadata in the parent, defined ones xfail)
  ``BREAK:{reason}``                                          -- void control twin (R5-1):
      aliased handle or twin disclaiming/mangling the flag; parent hard-fails
  ``DEVIATION_XFAIL:{reason}``                                -- twin omitting the flag
      (R6-1): enforcement oracle disabled, denial uncredited, parent xfails

Required ``extra`` keys:
  ``"probe"`` -- ``"encrypt"``, ``"sign"``, or ``"decrypt"``.

Launch with ``coverage="session"`` and ``pin=pin_from_config(p11_config)``.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Mapping
from ctypes import byref, cast
from typing import Any

from pkcs11_check.raw.metadata_std import ATTR_NAMES
from pkcs11_check.raw.pack import attr_bool, attr_bytes, attr_ulong, mech_simple, template
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE_PTR,
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKK_GENERIC_SECRET,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_SHA256_HMAC,
    CKO_SECRET_KEY,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_OK,
)
from pkcs11_check.testcases._attribute_values import refusal_for
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _template_ptr(attrs: Any) -> Any:
    return cast(attrs.array, CK_ATTRIBUTE_PTR)


def _classify_readback(vals: Mapping[int, Any], attr: int) -> dict[str, Any]:
    """Classify one attribute readback into a self-describing partial event.

    Absence and malformed values stay distinct from booleans: treating either
    as a false claim would invent a provider assertion. Both branches below
    are terminal returns, so there is no absence branch left to silently
    collapse a provider omission into a fabricated value.
    """
    if attr in vals:
        value = vals[attr]
        if isinstance(value, bool):
            return {"event": "boolean", "value": value}
        return {
            "event": "malformed",
            "value_type": type(value).__name__[:64],
            "value_repr": repr(value)[:256],
        }
    return {"event": "omitted"}


def _claim(
    ctx: ProbeContext, sh: int, key_value: int, attr: int, *, operation: str
) -> dict[str, Any]:
    # The event is self-describing so the parent can reject output copied from
    # another probe.
    vals = read_attributes(ctx.raw, sh, key_value, [attr])
    attr_id = int(attr)
    attr_descriptor = {"name": ATTR_NAMES.get(attr_id, str(attr)), "id": attr_id}
    event: dict[str, Any] = {
        "operation": operation,
        "attribute": attr_descriptor,
        **_classify_readback(vals, attr),
    }
    print("ATTRIBUTE_EVENT:" + json.dumps(event, separators=(",", ":")))
    return event


#: Same-route enabled-key factory for the R4-3 positive control: returns
#: (key-or-None, creation RV, creation op name for the refusal marker).
_ControlFactory = Callable[[], tuple[int | None, int, str]]


def _finish_flag_probe(
    ctx: ProbeContext,
    sh: int,
    key: int,
    *,
    false_attr: int,
    op_mech: int,
    op_init: str,
    control: _ControlFactory | None = None,
) -> None:
    """Claim the flag, call *op_init*, and report the CKR without asserting.

    R4-3: when a same-route enabled-key factory is given and the transcript
    would otherwise award a pass (clean False claim + NOT_PERMITTED), the
    control twin must initialize first; anything but its acceptance leaves
    the denial uncredited (numeric setup marker, no CKR/OK). R5-1: the twin
    must be a distinct handle reading back enabled, else BREAK (a twin
    that aliases the disabled key or disclaims the flag proves nothing).
    """
    event = _claim(ctx, sh, key, false_attr, operation=op_init)
    mech = mech_simple(op_mech)
    init = getattr(ctx.raw, op_init)
    rv = init(sh, mech.byref(), key)
    if (
        control is not None
        and event.get("event") == "boolean"
        and event.get("value") is False
        and rv == int(CKR_KEY_FUNCTION_NOT_PERMITTED)
    ):
        control_key, control_rv, control_op = control()
        if control_key is None:
            print(f"SETUP_REFUSED:{control_op}:0x{control_rv:08x}")
            return
        if control_key == key:
            print(f"BREAK:control twin aliases the disabled key (handle {key})")
            return
        twin_vals = read_attributes(ctx.raw, sh, control_key, [false_attr], raw_bool=True)
        twin_refusal = refusal_for(twin_vals, false_attr)
        attr_name = ATTR_NAMES.get(int(false_attr), str(false_attr))
        if twin_refusal is not None and twin_refusal.leaked_len is not None:
            print(
                f"BREAK:control twin answered {ckr_name(twin_refusal.ckr)} "
                f"for {attr_name} but wrote {twin_refusal.leaked_len} bytes"
            )
            return
        if false_attr not in twin_vals:
            if twin_refusal is not None and twin_refusal.malformed:
                print(
                    f"DEVIATION_XFAIL:control twin omits {attr_name} "
                    f"(malformed refusal: {ckr_name(twin_refusal.ckr)} with a "
                    "retained finite length, no write); enforcement oracle disabled"
                )
            elif twin_refusal is not None:
                print(
                    f"DEVIATION_XFAIL:control twin omits {attr_name} "
                    f"(refused with {ckr_name(twin_refusal.ckr)}); "
                    "enforcement oracle disabled"
                )
            else:
                print(
                    f"DEVIATION_XFAIL:control twin omits {attr_name}; enforcement oracle disabled"
                )
            return
        if twin_vals[false_attr] != 1:
            # R10-1: only the canonical TRUE byte verifies the twin. A
            # disclaimed flag, a mangled value, or an untouched canary
            # (out-of-range write) all void the control loudly.
            print(
                f"BREAK:control twin does not read back canonical {attr_name}=True "
                f"(got {twin_vals[false_attr]!r})"
            )
            return
        control_init_rv = init(sh, mech.byref(), control_key)
        if control_init_rv != CKR_OK:
            print(f"SETUP_REFUSED:{op_init}:0x{control_init_rv:08x}")
            return
        print(
            f"positive control: enabled-key {op_init} accepted; denial credited",
            file=sys.stderr,
        )
    print(f"CKR:0x{rv:08x}")
    # Report result without asserting -- outer test checks security compliance
    print("OK")


def _generate_aes_key(
    ctx: ProbeContext,
    sh: int,
    *,
    false_attr: int,
    counterpart_attr: int,
    flag: bool = False,
) -> tuple[int | None, int]:
    """Generate an AES key with *false_attr*=flag; (None, rv) when refused."""
    attrs = template(
        attr_ulong(CKA_VALUE_LEN, 32),
        attr_bool(false_attr, flag),
        attr_bool(counterpart_attr, True),
        attr_bool(CKA_TOKEN, False),
    )
    mech_kg = mech_simple(CKM_AES_KEY_GEN)
    key = CK_OBJECT_HANDLE(0)
    rv = ctx.raw.C_GenerateKey(sh, mech_kg.byref(), _template_ptr(attrs), attrs.count, byref(key))
    return (key.value, rv) if rv == CKR_OK else (None, rv)


def _flag_not_permitted(
    ctx: ProbeContext,
    *,
    false_attr: int,
    counterpart_attr: int,
    op_mech: int,
    op_init: str,
    control: _ControlFactory | None = None,
) -> None:
    """Generate an AES key with *false_attr*=False, then call *op_init* on it."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    key, rv = _generate_aes_key(ctx, sh, false_attr=false_attr, counterpart_attr=counterpart_attr)
    if key is None:
        print(f"SETUP_REFUSED:C_GenerateKey:0x{rv:08x}")
        return
    _finish_flag_probe(
        ctx, sh, key, false_attr=false_attr, op_mech=op_mech, op_init=op_init, control=control
    )


_HMAC_FALLBACK_VALUE = bytes([0x07]) * 32


def _generate_hmac_key(ctx: ProbeContext, sh: int, *, sign: bool = False) -> tuple[int | None, int]:
    """Generate a generic-secret key with CKA_SIGN=sign; (None, rv) when refused."""
    attrs = template(
        attr_ulong(CKA_VALUE_LEN, 32),
        attr_bool(CKA_SIGN, sign),
        attr_bool(CKA_VERIFY, True),
        attr_bool(CKA_TOKEN, False),
    )
    mech_kg = mech_simple(CKM_GENERIC_SECRET_KEY_GEN)
    key = CK_OBJECT_HANDLE(0)
    rv = ctx.raw.C_GenerateKey(sh, mech_kg.byref(), _template_ptr(attrs), attrs.count, byref(key))
    return (key.value, rv) if rv == CKR_OK else (None, rv)


def _create_hmac_key(ctx: ProbeContext, sh: int, *, sign: bool = False) -> tuple[int | None, int]:
    """CreateObject a generic-secret key with CKA_SIGN=sign; (None, rv) when refused."""
    attrs = template(
        attr_ulong(CKA_CLASS, int(CKO_SECRET_KEY)),
        attr_ulong(CKA_KEY_TYPE, int(CKK_GENERIC_SECRET)),
        attr_bytes(CKA_VALUE, _HMAC_FALLBACK_VALUE),
        attr_bool(CKA_SIGN, sign),
        attr_bool(CKA_VERIFY, True),
        attr_bool(CKA_TOKEN, False),
    )
    key = CK_OBJECT_HANDLE(0)
    rv = ctx.raw.C_CreateObject(sh, _template_ptr(attrs), attrs.count, byref(key))
    return (key.value, rv) if rv == CKR_OK else (None, rv)


def _is_routable_setup_rv(rv: int) -> bool:
    """Whether a setup refusal may fall back (F6a): defined RVs route onward.

    An undefined (neither standard nor vendor) setup RV is itself the
    finding -- falling back would silently erase it -- so the probe
    reports setup-xfail immediately instead.
    """
    return bool(is_standard_ckr(rv) or is_vendor_defined_ckr(rv))


def _encrypt(ctx: ProbeContext) -> None:
    _flag_not_permitted(
        ctx,
        false_attr=CKA_ENCRYPT,
        counterpart_attr=CKA_DECRYPT,
        op_mech=CKM_AES_ECB,
        op_init="C_EncryptInit",
    )


def _sign(ctx: ProbeContext) -> None:
    """CKA_SIGN=False, then C_SignInit (CKM_SHA256_HMAC) on a type-consistent key.

    fw#96: an AES key makes the SignInit refusal ambiguous (key type vs
    key function), so the probe prefers a generic-secret HMAC key and only
    falls back to the AES route (then SETUP_REFUSED) without generic support.
    R4-3: whichever route produces the disabled key also builds the enabled
    twin for the positive control, so a credited denial proves enforcement
    on the probed key rather than a blanket route refusal.
    """
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    def _control_via_generate() -> tuple[int | None, int, str]:
        control_key, control_rv = _generate_hmac_key(ctx, sh, sign=True)
        return control_key, control_rv, "C_GenerateKey"

    def _control_via_create() -> tuple[int | None, int, str]:
        control_key, control_rv = _create_hmac_key(ctx, sh, sign=True)
        return control_key, control_rv, "C_CreateObject"

    def _control_via_aes() -> tuple[int | None, int, str]:
        control_key, control_rv = _generate_aes_key(
            ctx, sh, false_attr=CKA_SIGN, counterpart_attr=CKA_ENCRYPT, flag=True
        )
        return control_key, control_rv, "C_GenerateKey"

    key, rv = _generate_hmac_key(ctx, sh)
    control: _ControlFactory = _control_via_generate
    if key is None:
        if not _is_routable_setup_rv(rv):
            print(f"SETUP_REFUSED:C_GenerateKey:0x{rv:08x}")
            return
        print(
            f"setup fallback: C_GenerateKey refused with {ckr_name(rv)}, trying CreateObject",
            file=sys.stderr,
        )
        key, rv = _create_hmac_key(ctx, sh)
        control = _control_via_create
        if key is None and not _is_routable_setup_rv(rv):
            print(f"SETUP_REFUSED:C_CreateObject:0x{rv:08x}")
            return
    if key is None:
        _flag_not_permitted(
            ctx,
            false_attr=CKA_SIGN,
            counterpart_attr=CKA_ENCRYPT,
            op_mech=CKM_SHA256_HMAC,
            op_init="C_SignInit",
            control=_control_via_aes,
        )
        return
    _finish_flag_probe(
        ctx,
        sh,
        key,
        false_attr=CKA_SIGN,
        op_mech=CKM_SHA256_HMAC,
        op_init="C_SignInit",
        control=control,
    )


def _decrypt(ctx: ProbeContext) -> None:
    _flag_not_permitted(
        ctx,
        false_attr=CKA_DECRYPT,
        counterpart_attr=CKA_ENCRYPT,
        op_mech=CKM_AES_ECB,
        op_init="C_DecryptInit",
    )


_PROBES: dict[str, Callable[[ProbeContext], None]] = {
    "encrypt": _encrypt,
    "sign": _sign,
    "decrypt": _decrypt,
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
