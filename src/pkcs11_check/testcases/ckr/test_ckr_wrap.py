"""CKR compliance tests for C_WrapKey and C_UnwrapKey.

Source: PKCS#11 v3.2 (C_WrapKey, C_UnwrapKey).
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.classification import classify, fail_as, xfail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key, import_secret_key
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_BBOOL,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE_LEN,
    CKA_WRAP,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_KEY_WRAP,
    CKM_SHA256,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_UNWRAPPING_KEY_HANDLE_INVALID,
    CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE,
    CKR_WRAPPING_KEY_HANDLE_INVALID,
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
)
from pkcs11_check.testcases._error_tuples import TEMPLATE_ERRORS
from pkcs11_check.testcases.ckr._ckr_spec import CKR_WRAP, assert_ckr
from pkcs11_check.testcases.ckr._malformed_attrs import make_bool_attr_overlong
from pkcs11_check.testcases.ckr._object_policy import _find_all
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    classify_policy_enforcement,
    gen_aes_key_or_xfail,
)

pytestmark = pytest.mark.access

#: Output-handle prefill for refusal probes (Task 18 O1 sentinel shape).
_HANDLE_SENTINEL = 0x51515151
#: Fixed sentinel-shaped never-issued handle: distinct from 0 and from any
#: handle staged here, and below 2**32 so it fits CK_OBJECT_HANDLE on both
#: LP64 and LLP64 (controller ruling, Task 19 brief §1).
_NEVER_ISSUED_HANDLE = 0x5EEDF00D


def _nonissued_handle(handle_kind: str) -> int:
    """Map a non-destroyed handle class to its stimulus value."""
    if handle_kind == "zero":
        return 0
    if handle_kind == "never_issued":
        return _NEVER_ISSUED_HANDLE
    raise ValueError(f"not a non-issued handle kind: {handle_kind!r}")


def _handle_class(handle_after: int, new_handles: list[int]) -> str:
    if handle_after == _HANDLE_SENTINEL:
        return "sentinel"
    if handle_after == 0:
        return "zero"
    if handle_after in new_handles:
        return "new-live"
    return "dead-nonzero"


def _judge_handle_probe(
    *,
    rv: int,
    canonical: int,
    label: str,
    operation: str,
    mechanism: str,
    new_handles: list[int],
    proved_new_handles: list[int] | None = None,
    handle_after: int | None = None,
    wrapped_len_after: int | None = None,
) -> None:
    """Judge one invalid-handle probe (uniform tiers + Task 18 O1 + R1).

    Canonical RV passes; any other clean standard/vendor refusal xfails
    with the original RV; acceptance and undefined RVs fail. Only a
    proved-new delta object fails (creator roles prove by output-handle
    membership in the delta; wrap roles have no output handle, so their
    delta is always unproved); an unproved delta xfails and is left
    alive. A dead nonzero output-handle write xfails; sentinel/0 writes
    are normalized. Callers destroy only the proved delta before judging.
    """
    proved = list(proved_new_handles) if proved_new_handles is not None else []
    unproved = [handle for handle in new_handles if handle not in proved]
    detail: dict[str, Any] = {
        "new_handles": list(new_handles),
        "proved_new_handles": proved,
        "unproved_new_handles": unproved,
    }
    if handle_after is not None:
        detail["handle_after"] = handle_after
        detail["handle_class"] = _handle_class(handle_after, new_handles)
    if wrapped_len_after is not None:
        detail["wrapped_len_after"] = wrapped_len_after
    if rv == int(CKR_OK):
        fail_as(
            "self_contradiction",
            kind="lifecycle",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=canonical,
            actual=rv,
            spec_ref="PKCS#11 v3.2",
            summary=f"{label}: accepted an invalid handle (expected {ckr_name(canonical)})",
            detail=detail,
        )
    if proved:
        fail_as(
            "self_contradiction",
            kind="lifecycle",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=canonical,
            actual=rv,
            spec_ref="PKCS#11 v3.2",
            summary=f"{label}: refusal {ckr_name(rv)} left an object behind",
            detail=detail,
        )
    if unproved and (is_standard_ckr(rv) or is_vendor_defined_ckr(rv)):
        xfail_as(
            "honest_deviation",
            kind="lifecycle",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=canonical,
            actual=rv,
            spec_ref="PKCS#11 v3.2",
            summary=(
                f"{label}: refusal {ckr_name(rv)} with an unproved "
                "inventory delta; zero-delta unproved"
            ),
            detail={**detail, "disposition": "unproved-effect"},
        )
    if handle_after is None:
        # C_WrapKey has no output handle: judge the RV tiers inline so
        # every record carries the built detail (M1).
        if not (is_standard_ckr(rv) or is_vendor_defined_ckr(rv)):
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation=operation,
                mechanism=mechanism,
                expected=canonical,
                actual=rv,
                spec_ref="PKCS#11 v3.2",
                summary=f"{label}: rejected with undefined CK_RV {ckr_name(rv)}",
                detail=detail,
            )
        if rv == canonical:
            return
        classify(
            "nonspec_reject",
            kind="lifecycle",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=canonical,
            actual=rv,
            spec_ref="PKCS#11 v3.2",
            detail=detail,
        )
        return
    if not (is_standard_ckr(rv) or is_vendor_defined_ckr(rv)):
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=canonical,
            actual=rv,
            spec_ref="PKCS#11 v3.2",
            summary=f"{label}: rejected with undefined CK_RV {ckr_name(rv)}",
            detail=detail,
        )
    if handle_after not in (_HANDLE_SENTINEL, 0):
        xfail_as(
            "honest_deviation",
            kind="lifecycle",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=canonical,
            actual=rv,
            spec_ref="PKCS#11 v3.2",
            summary=(
                f"{label}: refusal {ckr_name(rv)} wrote non-invalid output "
                f"handle {handle_after}; no object created"
            ),
            detail=detail,
        )
    if rv == canonical:
        return
    classify(
        "nonspec_reject",
        kind="lifecycle",
        label=label,
        operation=operation,
        mechanism=mechanism,
        expected=canonical,
        actual=rv,
        spec_ref="PKCS#11 v3.2",
        detail=detail,
    )


def _inventory_or_unproved(
    rs: Any,
    *,
    label: str,
    operation: str,
    mechanism: str,
    canonical: int,
    refusal_rv: int | None = None,
) -> list[int]:
    """Full inventory, or an unproved-effect verdict on failure (M2).

    A clean inventory RV xfails carrying both RVs and destroys nothing;
    an undefined inventory RV keeps its metadata failure classification.
    """
    try:
        return _find_all(rs)
    except CkrAssertionError as exc:
        detail: dict[str, Any] = {
            "disposition": "unproved-effect",
            "inventory_rv": ckr_name(exc.rv),
        }
        if refusal_rv is not None:
            detail["refusal_rv"] = ckr_name(refusal_rv)
        if not (is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv)):
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: inventory",
                operation="C_FindObjects",
                mechanism=mechanism,
                expected=canonical,
                actual=exc.rv,
                spec_ref="PKCS#11 v3.2",
                summary=f"{label}: leak inventory returned undefined CK_RV {ckr_name(exc.rv)}",
                detail=detail,
            )
        xfail_as(
            "honest_deviation",
            kind="lifecycle",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=canonical,
            actual=refusal_rv if refusal_rv is not None else exc.rv,
            spec_ref="PKCS#11 v3.2",
            summary=f"{label}: leak inventory failed with {ckr_name(exc.rv)}; zero-delta unproved",
            detail=detail,
        )
        raise AssertionError("unreachable: xfail_as always raises") from exc


class TestWrapKeyErrors:
    """Error conditions for C_WrapKey (Sec.5.14.3)."""

    def test_key_not_extractable(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Wrapping non-extractable key -> CKR_KEY_UNEXTRACTABLE.

        PKCS#11 v3.2: C_WrapKey on a key with CKA_EXTRACTABLE=False MUST
        return CKR_KEY_UNEXTRACTABLE.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: True},
        )
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: False, CKA_SENSITIVE: True},
        )
        try:
            # Verify the module actually honoured CKA_EXTRACTABLE=False
            check = (CK_ATTRIBUTE * 1)()
            check[0].type = CKA_EXTRACTABLE
            val = CK_BBOOL(0xFF)  # sentinel
            check[0].pValue = ctypes.cast(ctypes.pointer(val), ctypes.c_void_p)
            check[0].ulValueLen = ctypes.sizeof(val)
            rv = rs.raw.C_GetAttributeValue(rs.sh, target, check, 1)
            if rv != CKR_OK:
                classify_negative_rv(
                    rv,
                    (CKR_ATTRIBUTE_TYPE_INVALID,),
                    label="C_GetAttributeValue:CKA_EXTRACTABLE enforcement precondition",
                )
            # policy claim-check: gen_aes_key() above raises unless C_GenerateKey
            # returns CKR_OK, so reaching this point already proves the module
            # accepted the CKA_EXTRACTABLE=False template at creation --
            # independent claim evidence a missing/unreadable readback must not
            # downgrade.  Only an explicit readback showing the key IS
            # extractable is real evidence contradicting the claim.
            claimed = True if rv != CKR_OK else val.value == 0

            mech = mech_simple(CKM_AES_KEY_WRAP)
            wrapped_len = CK_ULONG(256)
            wrapped_buf = (ctypes.c_ubyte * 256)()
            wrap_rv = rs.raw.C_WrapKey(
                rs.sh,
                mech.byref(),
                wrap_key,
                target,
                wrapped_buf,
                byref(wrapped_len),
            )
            # Enforcement-check: wrapping a non-extractable key succeeded ->
            # the protected key material was exported (extraction).
            violated = wrap_rv == CKR_OK
            if claimed and violated:
                note(
                    "C_WrapKey returned CKR_OK on CKA_EXTRACTABLE=False key "
                    "(expected CKR_KEY_UNEXTRACTABLE). Non-extractable keys can be exported.",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.2",
                )
            # Phase 6 C: a module that claims CKA_EXTRACTABLE=False then wraps the
            # key anyway is a self-contradiction -> fail (was masked by skip). A
            # module that does not claim the protection -> xfail (honest non-
            # support). A claimed-and-rejected wrap -> pass.
            classify_policy_enforcement(
                claimed=claimed,
                violated=violated,
                label="C_WrapKey on a CKA_EXTRACTABLE=False key "
                "(PKCS#11 v3.2 requires CKR_KEY_UNEXTRACTABLE)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_key)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using hash mechanism for wrap -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_WRAP: True},
            purpose="CKR wrap mechanism-invalid setup",
        )
        target = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
            purpose="CKR wrap mechanism-invalid target setup",
        )
        try:
            mech = mech_simple(CKM_SHA256)  # Wrong: hash mechanism
            wrapped_len = CK_ULONG(256)
            wrapped_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_WrapKey(
                rs.sh,
                mech.byref(),
                wrap_key,
                target,
                wrapped_buf,
                byref(wrapped_len),
            )
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_WrapKey:digest-mechanism",
                    operation="C_WrapKey",
                    actual=rv,
                    summary="Should have rejected SHA256 as wrap mechanism",
                )
            assert_ckr(CKR_WRAP["wrap_mechanism_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_key)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_wrapping_key_handle_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Stale wrap-key handle -> CKR_WRAPPING_KEY_HANDLE_INVALID.

        PKCS#11 v3.2: "the key handle specified to be used to
        wrap another key is not valid."

        Use a destroyed handle to guarantee invalidity (handle 0 may be
        rejected earlier with CKR_OBJECT_HANDLE_INVALID).
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_WRAP: True})
        target: int | None = None
        wrap_key_destroyed = False
        try:
            # The wrapping key is owned as soon as generation succeeds.  Keep that
            # ownership through target setup so a failed target recipe cannot leak it.
            target_handle = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
            )
            target = target_handle

            # Destroy the wrap key so its handle is now stale.  A clean failure here
            # must retain the original CK_RV while the finally block releases both
            # still-owned objects.
            rv = rs.raw.C_DestroyObject(rs.sh, wrap_key)
            if rv != CKR_OK:
                raise AssertionError(
                    f"Could not destroy wrap key for stale-handle test (CKR=0x{rv:08x})"
                )
            wrap_key_destroyed = True

            mech = mech_simple(CKM_AES_KEY_WRAP)
            wrapped_len = CK_ULONG(256)
            wrapped_buf = (ctypes.c_ubyte * 256)()
            C.set_mechanism("CKM_AES_KEY_WRAP", "C_WrapKey", expect_success=False)
            rv = rs.raw.C_WrapKey(
                rs.sh,
                mech.byref(),
                wrap_key,  # stale
                target_handle,
                wrapped_buf,
                byref(wrapped_len),
            )
            if rv == CKR_OK:
                note(
                    "C_WrapKey returned CKR_OK on a destroyed wrap-key handle "
                    "(expected CKR_WRAPPING_KEY_HANDLE_INVALID).",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.2",
                )
                # Use-after-destroy: the wrap key was destroyed yet C_WrapKey used
                # it and exported key material -> self-contradiction.
                fail_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label="C_WrapKey:stale-wrap-key-handle",
                    operation="C_WrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    spec_ref="PKCS#11 v3.2",
                    summary=(
                        "Module accepted a stale wrap-key handle "
                        "(expected CKR_WRAPPING_KEY_HANDLE_INVALID)"
                    ),
                )
            classify_negative_rv(
                rv,
                (CKR_WRAPPING_KEY_HANDLE_INVALID,),
                label="C_WrapKey:stale-wrap-key-handle",
                kind="lifecycle",
            )
        finally:
            if target is not None:
                destroy_quietly(rs.raw, rs.sh, target)
            if not wrap_key_destroyed:
                destroy_quietly(rs.raw, rs.sh, wrap_key)

    @pytest.mark.parametrize("handle_kind", ["destroyed", "zero", "never_issued"])
    def test_wrapped_key_handle_invalid(
        self, p11_raw_session: Any, ckr_strict: bool, handle_kind: str
    ) -> None:
        """QC8a role 2: invalid wrapped target -> CKR_KEY_HANDLE_INVALID.

        Spec-table key ``wrap_key_handle_invalid`` (target role). Uniform
        tiers for every handle class; the wrapping key stays valid.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")
        wrap_key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_WRAP: True})
        target: int | None = None
        target_destroyed = False
        try:
            target_handle = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
            )
            target = target_handle
            if handle_kind == "destroyed":
                rv = rs.raw.C_DestroyObject(rs.sh, target_handle)
                if rv != CKR_OK:
                    raise AssertionError(
                        f"Could not destroy target for stale-handle test (CKR=0x{rv:08x})"
                    )
                target_destroyed = True
                invalid = target_handle
            else:
                invalid = _nonissued_handle(handle_kind)
            # No object creation between the destroy above and the probe.
            before = _inventory_or_unproved(
                rs,
                label="C_WrapKey:invalid-wrapped-key-handle",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                canonical=int(CKR_KEY_HANDLE_INVALID),
            )
            mech = mech_simple(CKM_AES_KEY_WRAP)
            wrapped_len = CK_ULONG(256)
            wrapped_buf = (ctypes.c_ubyte * 256)()
            C.set_mechanism("CKM_AES_KEY_WRAP", "C_WrapKey", expect_success=False)
            rv = rs.raw.C_WrapKey(
                rs.sh, mech.byref(), wrap_key, invalid, wrapped_buf, byref(wrapped_len)
            )
            after = _inventory_or_unproved(
                rs,
                label="C_WrapKey:invalid-wrapped-key-handle",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                canonical=int(CKR_KEY_HANDLE_INVALID),
                refusal_rv=int(rv),
            )
            new_handles = sorted(set(after) - set(before))
            # C_WrapKey creates no output handle: any delta is unproved
            # and stays alive (R1); the judge xfails it, never destroys.
            _judge_handle_probe(
                rv=int(rv),
                canonical=int(CKR_KEY_HANDLE_INVALID),
                label="C_WrapKey:invalid-wrapped-key-handle",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                new_handles=new_handles,
                proved_new_handles=[],
                wrapped_len_after=int(wrapped_len.value),
            )
        finally:
            if target is not None and not target_destroyed:
                destroy_quietly(rs.raw, rs.sh, target)
            destroy_quietly(rs.raw, rs.sh, wrap_key)

    @pytest.mark.parametrize("handle_kind", ["zero", "never_issued"])
    def test_wrapping_key_handle_invalid_nonissued(
        self, p11_raw_session: Any, ckr_strict: bool, handle_kind: str
    ) -> None:
        """QC8a role 1 extension: zero/never-issued wrapping key.

        Same singleton tier as the settled destroyed-handle leaf, which
        keeps its own node id; no wider pass set for handle 0.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            invalid = _nonissued_handle(handle_kind)
            before = _inventory_or_unproved(
                rs,
                label="C_WrapKey:nonissued-wrapping-key-handle",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                canonical=int(CKR_WRAPPING_KEY_HANDLE_INVALID),
            )
            mech = mech_simple(CKM_AES_KEY_WRAP)
            wrapped_len = CK_ULONG(256)
            wrapped_buf = (ctypes.c_ubyte * 256)()
            C.set_mechanism("CKM_AES_KEY_WRAP", "C_WrapKey", expect_success=False)
            rv = rs.raw.C_WrapKey(
                rs.sh, mech.byref(), invalid, target, wrapped_buf, byref(wrapped_len)
            )
            after = _inventory_or_unproved(
                rs,
                label="C_WrapKey:nonissued-wrapping-key-handle",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                canonical=int(CKR_WRAPPING_KEY_HANDLE_INVALID),
                refusal_rv=int(rv),
            )
            new_handles = sorted(set(after) - set(before))
            # No output handle to correlate: delta stays unproved/alive.
            _judge_handle_probe(
                rv=int(rv),
                canonical=int(CKR_WRAPPING_KEY_HANDLE_INVALID),
                label="C_WrapKey:nonissued-wrapping-key-handle",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                new_handles=new_handles,
                proved_new_handles=[],
                wrapped_len_after=int(wrapped_len.value),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, target)

    def test_wrapping_key_type_inconsistent(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Wrap key of wrong type for mechanism -> CKR_WRAPPING_KEY_TYPE_INCONSISTENT.

        PKCS#11 v3.2: "the type of the key specified to wrap
        another key is not consistent with the mechanism specified for
        wrapping."

        Use a CKK_GENERIC_SECRET key (HMAC-style) as the wrap key with
        CKM_AES_KEY_WRAP (which requires an AES key).
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        # Import a 32-byte generic-secret as the (wrong-type) wrap key.
        try:
            wrap_key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_GENERIC_SECRET,
                value=b"\x00" * 32,
                attrs={CKA_WRAP: True, CKA_EXTRACTABLE: True},
            )
        except CkrAssertionError as exc:
            if exc.rv in (
                CKR_ATTRIBUTE_TYPE_INVALID,
                CKR_ATTRIBUTE_VALUE_INVALID,
                CKR_KEY_TYPE_INCONSISTENT,
                CKR_TEMPLATE_INCOMPLETE,
                CKR_TEMPLATE_INCONSISTENT,
            ):
                pytest.skip(f"Module rejected generic-secret key import for wrap test: {exc}")
            raise

        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            mech = mech_simple(CKM_AES_KEY_WRAP)
            wrapped_len = CK_ULONG(256)
            wrapped_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_WrapKey(
                rs.sh,
                mech.byref(),
                wrap_key,
                target,
                wrapped_buf,
                byref(wrapped_len),
            )
            if rv == CKR_OK:
                note(
                    "C_WrapKey returned CKR_OK with a generic-secret wrap key "
                    "for CKM_AES_KEY_WRAP (expected CKR_WRAPPING_KEY_TYPE_INCONSISTENT).",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.2",
                )
                fail_as(
                    "accepted_invalid",
                    kind="policy",
                    label="C_WrapKey:wrapping-key-type-inconsistent",
                    operation="C_WrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    spec_ref="PKCS#11 v3.2",
                    summary=(
                        "Module accepted a generic-secret key for AES wrap "
                        "(expected CKR_WRAPPING_KEY_TYPE_INCONSISTENT)"
                    ),
                )
            accepted = (
                CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
                CKR_KEY_TYPE_INCONSISTENT,
                CKR_KEY_FUNCTION_NOT_PERMITTED,
            )
            assert rv in accepted, (
                f"Unexpected CK_RV 0x{rv:08x} on type-inconsistent wrap key; "
                f"expected one of {[hex(c) for c in accepted]}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_key)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_wrapping_key_size_range(
        self, p11_raw_session: Any, p11_config: Any, ckr_strict: bool
    ) -> None:
        """Wrap key of out-of-range size -> CKR_WRAPPING_KEY_SIZE_RANGE.

        PKCS#11 v3.2: "the supplied wrapping key's size is
        outside the range of key sizes that it can handle."

        Try to import an undersized AES key (8 bytes / 64 bits) — below
        the AES-128 minimum — and use it for CKM_AES_KEY_WRAP. Most
        modules either reject the import outright (acceptable: we then
        skip) or reject the wrap with a size-related CKR.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        try:
            undersized_wrap = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_AES,
                value=b"\x00" * 8,  # 64-bit, below AES-128 minimum
                attrs={CKA_WRAP: True, CKA_EXTRACTABLE: True},
            )
        except CkrAssertionError as exc:
            if exc.rv in (
                CKR_ATTRIBUTE_TYPE_INVALID,
                CKR_ATTRIBUTE_VALUE_INVALID,
                CKR_KEY_SIZE_RANGE,
                CKR_TEMPLATE_INCOMPLETE,
                CKR_TEMPLATE_INCONSISTENT,
            ):
                pytest.skip(
                    "Module rejected import of undersized AES wrap key "
                    "(itself a valid size-range enforcement)"
                )
            raise

        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            mech = mech_simple(CKM_AES_KEY_WRAP)
            wrapped_len = CK_ULONG(256)
            wrapped_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_WrapKey(
                rs.sh,
                mech.byref(),
                undersized_wrap,
                target,
                wrapped_buf,
                byref(wrapped_len),
            )
            if rv == CKR_OK:
                note(
                    "C_WrapKey returned CKR_OK with a 64-bit AES wrap key "
                    "(expected CKR_WRAPPING_KEY_SIZE_RANGE — AES requires "
                    "128/192/256 bits).",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.2",
                )
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="C_WrapKey:wrapping-key-size-range",
                    operation="C_WrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    actual=rv,
                    spec_ref="PKCS#11 v3.2",
                    summary=(
                        "Module accepted a 64-bit AES wrap key for CKM_AES_KEY_WRAP "
                        "(expected CKR_WRAPPING_KEY_SIZE_RANGE)"
                    ),
                )
            # Code-conformance: the spec mandates CKR_WRAPPING_KEY_SIZE_RANGE for a
            # too-small wrapping key. Classify the reject three ways (assert_ckr):
            #   * a size-or-type spec code -> pass,
            #   * any other clean reject (e.g. a module's catch-all
            #     CKR_GENERAL_ERROR) -> xfail (an honest, recorded deviation),
            #   * CKR_OK -> fail (already handled above as the crypto-correctness break).
            # In strict mode (ckr_strict) a non-spec code is promoted to a hard
            # fail, preserving the strict/compat distinction.
            assert_ckr(CKR_WRAP["wrap_wrapping_key_size_range"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, undersized_wrap)
            destroy_quietly(rs.raw, rs.sh, target)


class TestUnwrapKeyErrors:
    """Error conditions for C_UnwrapKey (Sec.5.14.4)."""

    def test_wrapped_key_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Unwrapping garbage data -> CKR_WRAPPED_KEY_INVALID."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        unwrap_key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_UNWRAP: True, CKA_WRAP: True},
        )
        try:
            mech = mech_simple(CKM_AES_KEY_WRAP)
            # Garbage wrapped data (24 bytes for AES-KW)
            garbage = (ctypes.c_ubyte * 24)(*([0xFF] * 24))
            tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_AES),
                attr_ulong(CKA_VALUE_LEN, 16),
            )
            new_key = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_UnwrapKey(
                rs.sh,
                mech.byref(),
                unwrap_key,
                garbage,
                24,
                tmpl.ptr,
                tmpl.count,
                byref(new_key),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, new_key.value)
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="C_UnwrapKey:garbage-wrapped-data",
                    operation="C_UnwrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    actual=rv,
                    summary="Should have rejected garbage wrapped key data",
                )
            classify_negative_rv(
                rv,
                (CKR_WRAPPED_KEY_INVALID, CKR_WRAPPED_KEY_LEN_RANGE),
                label="C_UnwrapKey:garbage-wrapped-data",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, unwrap_key)

    def test_unwrap_token_bool_overlong_length(self, p11_raw_session: Any) -> None:
        """C_UnwrapKey must reject CK_ULONG-sized CKA_TOKEN template value."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrapping_key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: True, CKA_UNWRAP: True},
        )
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            mech = mech_simple(CKM_AES_KEY_WRAP)
            wrapped_len = CK_ULONG(256)
            wrapped_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_WrapKey(
                rs.sh,
                mech.byref(),
                wrapping_key,
                target,
                wrapped_buf,
                byref(wrapped_len),
            )
            if rv != CKR_OK:
                xfail_as(
                    "not_operational",
                    label="C_WrapKey:AES-key-wrap",
                    operation="C_WrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    actual=rv,
                    summary=f"CKM_AES_KEY_WRAP wrap not operational: {ckr_name(rv)}",
                )
            assert wrapped_len.value > 0, "CKM_AES_KEY_WRAP returned an empty wrapped blob"

            tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_AES),
                attr_ulong(CKA_VALUE_LEN, 16),
                attr_bool(CKA_TOKEN, False),
            )
            _storage = make_bool_attr_overlong(tmpl, 3)
            new_key = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_UnwrapKey(
                rs.sh,
                mech.byref(),
                wrapping_key,
                wrapped_buf,
                wrapped_len.value,
                tmpl.ptr,
                tmpl.count,
                byref(new_key),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, new_key.value)
            classify_negative_rv(
                rv,
                TEMPLATE_ERRORS,
                label="C_UnwrapKey with CK_ULONG-sized CKA_TOKEN boolean attribute",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, target)
            destroy_quietly(rs.raw, rs.sh, wrapping_key)

    @pytest.mark.parametrize("handle_kind", ["destroyed", "zero", "never_issued"])
    def test_unwrapping_key_handle_invalid(
        self, p11_raw_session: Any, ckr_strict: bool, handle_kind: str
    ) -> None:
        """QC8a role 3: invalid unwrapping key -> CKR_UNWRAPPING_KEY_HANDLE_INVALID.

        Spec-table key ``unwrap_unwrapping_key_handle_invalid``. A genuine
        wrapped blob and an otherwise-valid template isolate the handle.
        Refusal side-effects follow Task 18 O1 via the inventory delta.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")
        wrapping_key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: True, CKA_UNWRAP: True},
        )
        target: int | None = None
        wrapping_destroyed = False
        try:
            target_handle = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
            )
            target = target_handle
            mech = mech_simple(CKM_AES_KEY_WRAP)
            wrapped_len = CK_ULONG(256)
            wrapped_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_WrapKey(
                rs.sh,
                mech.byref(),
                wrapping_key,
                target_handle,
                wrapped_buf,
                byref(wrapped_len),
            )
            if rv != CKR_OK:
                xfail_as(
                    "not_operational",
                    label="C_WrapKey:AES-key-wrap",
                    operation="C_WrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    actual=rv,
                    summary=f"CKM_AES_KEY_WRAP wrap not operational: {ckr_name(rv)}",
                )
            assert wrapped_len.value > 0, "CKM_AES_KEY_WRAP returned an empty wrapped blob"
            if handle_kind == "destroyed":
                rv = rs.raw.C_DestroyObject(rs.sh, wrapping_key)
                if rv != CKR_OK:
                    raise AssertionError(
                        f"Could not destroy unwrapping key for stale test (CKR=0x{rv:08x})"
                    )
                wrapping_destroyed = True
                invalid = wrapping_key
            else:
                invalid = _nonissued_handle(handle_kind)
            # No object creation between the destroy above and the probe.
            before = _inventory_or_unproved(
                rs,
                label="C_UnwrapKey:invalid-unwrapping-key-handle",
                operation="C_UnwrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                canonical=int(CKR_UNWRAPPING_KEY_HANDLE_INVALID),
            )
            tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_AES),
                attr_ulong(CKA_VALUE_LEN, 16),
                attr_bool(CKA_TOKEN, False),
            )
            new_key = CK_OBJECT_HANDLE(_HANDLE_SENTINEL)
            C.set_mechanism("CKM_AES_KEY_WRAP", "C_UnwrapKey", expect_success=False)
            rv = rs.raw.C_UnwrapKey(
                rs.sh,
                mech.byref(),
                invalid,
                wrapped_buf,
                wrapped_len.value,
                tmpl.ptr,
                tmpl.count,
                byref(new_key),
            )
            handle_after = int(new_key.value)
            after = _inventory_or_unproved(
                rs,
                label="C_UnwrapKey:invalid-unwrapping-key-handle",
                operation="C_UnwrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                canonical=int(CKR_UNWRAPPING_KEY_HANDLE_INVALID),
                refusal_rv=int(rv),
            )
            new_handles = sorted(set(after) - set(before))
            # Only an output handle proved new by delta membership (and
            # not in the baseline) is owned; the rest stays alive (R1).
            proved_new = (
                [handle_after] if handle_after in new_handles and handle_after not in before else []
            )
            for handle in proved_new:
                destroy_quietly(rs.raw, rs.sh, handle)
            _judge_handle_probe(
                rv=int(rv),
                canonical=int(CKR_UNWRAPPING_KEY_HANDLE_INVALID),
                label="C_UnwrapKey:invalid-unwrapping-key-handle",
                operation="C_UnwrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                new_handles=new_handles,
                proved_new_handles=proved_new,
                handle_after=handle_after,
            )
        finally:
            if target is not None:
                destroy_quietly(rs.raw, rs.sh, target)
            if not wrapping_destroyed:
                destroy_quietly(rs.raw, rs.sh, wrapping_key)
