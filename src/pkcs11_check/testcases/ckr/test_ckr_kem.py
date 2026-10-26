"""CKR compliance tests for C_EncapsulateKey and C_DecapsulateKey.

v3.2 only - requires ML-KEM mechanism support.
Few modules currently implement KEM operations.

Source: PKCS#11 v3.2 Sec.5.14.7 (C_EncapsulateKey), Sec.5.14.8 (C_DecapsulateKey).
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.classification import classify, fail_as, xfail_as
from pkcs11_check.raw.pack import (
    attr_array,
    attr_bool,
    attr_bytes,
    attr_ulong,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_ALLOWED_MECHANISMS,
    CKA_DECAPSULATE,
    CKA_ENCAPSULATE,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_PARAMETER_SET,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKM_AES_ECB,
    CKM_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKP_ML_KEM_768,
    CKR_KEY_HANDLE_INVALID,
    CKR_OK,
    CKR_UNWRAPPING_KEY_HANDLE_INVALID,
)
from pkcs11_check.testcases.ckr import _object_policy as _qc4
from pkcs11_check.testcases.ckr._ckr_spec import CKR_KEM, assert_ckr

pytestmark = [pytest.mark.access, pytest.mark.pqc]

#: Output-handle prefill for refusal probes (Task 18 O1 sentinel shape).
_HANDLE_SENTINEL = 0x51515151
#: Fixed sentinel-shaped never-issued handle, below 2**32 (LP64/LLP64-safe).
_NEVER_ISSUED_HANDLE = 0x5EEDF00D
_CT_LEN = 1088


def _nonissued_handle(handle_kind: str) -> int:
    if handle_kind == "zero":
        return 0
    if handle_kind == "never_issued":
        return _NEVER_ISSUED_HANDLE
    raise ValueError(f"not a non-issued handle kind: {handle_kind!r}")


def _judge_kem_handle_probe(
    *,
    rv: int,
    canonical: int,
    label: str,
    operation: str,
    handle_after: int,
    new_handles: list[int],
    proved_new_handles: list[int] | None = None,
) -> None:
    """Judge one KEM invalid-handle probe (uniform tiers + O1 + R1).

    Only a proved-new delta object fails; templates are empty, so proof
    is output-handle membership in the delta outside the baseline. An
    unproved delta xfails and is left alive by the caller.
    """
    handle_class = (
        "sentinel"
        if handle_after == _HANDLE_SENTINEL
        else "zero"
        if handle_after == 0
        else "new-live"
        if handle_after in new_handles
        else "dead-nonzero"
    )
    proved = list(proved_new_handles) if proved_new_handles is not None else []
    unproved = [handle for handle in new_handles if handle not in proved]
    detail: dict[str, Any] = {
        "handle_after": handle_after,
        "handle_class": handle_class,
        "new_handles": list(new_handles),
        "proved_new_handles": proved,
        "unproved_new_handles": unproved,
    }
    if rv == int(CKR_OK):
        fail_as(
            "self_contradiction",
            kind="lifecycle",
            label=label,
            operation=operation,
            mechanism="CKM_ML_KEM",
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
            mechanism="CKM_ML_KEM",
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
            mechanism="CKM_ML_KEM",
            expected=canonical,
            actual=rv,
            spec_ref="PKCS#11 v3.2",
            summary=(
                f"{label}: refusal {ckr_name(rv)} with an unproved "
                "inventory delta; zero-delta unproved"
            ),
            detail={**detail, "disposition": "unproved-effect"},
        )
    if not (is_standard_ckr(rv) or is_vendor_defined_ckr(rv)):
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation=operation,
            mechanism="CKM_ML_KEM",
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
            mechanism="CKM_ML_KEM",
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
        mechanism="CKM_ML_KEM",
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
    canonical: int,
    refusal_rv: int | None = None,
) -> list[int]:
    """Full inventory, or an unproved-effect verdict on failure (M2)."""
    try:
        return _qc4._find_all(rs)
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
                mechanism="CKM_ML_KEM",
                expected=canonical,
                actual=exc.rv,
                spec_ref="PKCS#11 v3.2",
                summary=f"{label}: leak inventory returned undefined CK_RV {ckr_name(exc.rv)}",
                detail=detail,
            )
        if refusal_rv is not None and not (
            is_standard_ckr(refusal_rv) or is_vendor_defined_ckr(refusal_rv)
        ):
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation=operation,
                mechanism="CKM_ML_KEM",
                expected=canonical,
                actual=refusal_rv,
                spec_ref="PKCS#11 v3.2",
                summary=(
                    f"{label}: refused with undefined CK_RV {ckr_name(refusal_rv)}; "
                    "the failed leak inventory cannot downgrade it"
                ),
                detail=detail,
            )
        xfail_as(
            "honest_deviation",
            kind="lifecycle",
            label=label,
            operation=operation,
            mechanism="CKM_ML_KEM",
            expected=canonical,
            actual=refusal_rv if refusal_rv is not None else exc.rv,
            spec_ref="PKCS#11 v3.2",
            summary=f"{label}: leak inventory failed with {ckr_name(exc.rv)}; zero-delta unproved",
            detail=detail,
        )
        raise AssertionError("unreachable: xfail_as always raises") from exc


def _staging_inventory(rs: Any) -> list[int]:
    """Inventory bracketing decap ciphertext staging (R9-01).

    Staging ownership must be proved before the staged secret may be
    destroyed, exactly as for a judged probe: a clean inventory failure
    xfails the staging as not operational, an undefined inventory RV
    keeps its metadata failure.
    """
    try:
        return _qc4._find_all(rs)
    except CkrAssertionError as exc:
        if not (is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv)):
            fail_as(
                "self_contradiction",
                kind="metadata",
                label="C_EncapsulateKey:ML-KEM staging inventory",
                operation="C_FindObjects",
                mechanism="CKM_ML_KEM",
                actual=exc.rv,
                spec_ref="PKCS#11 v3.2",
                summary=(
                    "Staging inventory returned undefined CK_RV "
                    f"{ckr_name(exc.rv)}; staged-secret ownership unprovable"
                ),
            )
        xfail_as(
            "not_operational",
            label="C_EncapsulateKey:ML-KEM staging inventory",
            operation="C_FindObjects",
            mechanism="CKM_ML_KEM",
            actual=exc.rv,
            spec_ref="PKCS#11 v3.2",
            summary=(
                f"Staging inventory failed with {ckr_name(exc.rv)}; "
                "staged-secret ownership unprovable"
            ),
        )
        raise AssertionError("unreachable: xfail_as always raises") from exc


def _staging_partition(
    rs: Any, before: list[int], handle_after: int
) -> tuple[list[int], list[int] | None, int | None]:
    """Partition a staging output against a best-effort post inventory.

    Used on early-exit paths (R10-02): returns the proved-new handles,
    the new-handle list, and the inventory RV. The new-handle list is
    ``None`` when the inventory itself failed cleanly and nothing is
    provable; the RV is then the evidence for the unproved verdict. An
    undefined inventory RV keeps its metadata failure.
    """
    try:
        after = _qc4._find_all(rs)
    except CkrAssertionError as exc:
        if not (is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv)):
            fail_as(
                "self_contradiction",
                kind="metadata",
                label="C_EncapsulateKey:ML-KEM staging inventory",
                operation="C_FindObjects",
                mechanism="CKM_ML_KEM",
                actual=exc.rv,
                spec_ref="PKCS#11 v3.2",
                summary=(
                    "Staging inventory returned undefined CK_RV "
                    f"{ckr_name(exc.rv)}; staged-secret ownership unprovable"
                ),
            )
        return [], None, exc.rv
    new_handles = sorted(set(after) - set(before))
    return _proved_new(handle_after, before, new_handles), new_handles, None


def _proved_new(handle_after: int, before: list[int], new_handles: list[int]) -> list[int]:
    """Delta membership of the output handle is the only ownership proof."""
    if handle_after in new_handles and handle_after not in before:
        return [handle_after]
    return []


def _probe_cleanup(rs: Any, *, proved_new_handles: list[int]) -> None:
    """Destroy only proved-new handles; unproved delta stays alive (R1)."""
    for handle in proved_new_handles:
        destroy_quietly(rs.raw, rs.sh, handle)


def _generate_ml_kem_keypair(
    raw: Any,
    sh: int,
    *,
    pub_list: list[int] | None = None,
    priv_list: list[int] | None = None,
    tag: str | None = None,
) -> tuple[int, int]:
    """Generate ML-KEM-768 keypair for tests. Returns (pub_handle, priv_handle)."""
    mech = mech_simple(CKM_ML_KEM_KEY_PAIR_GEN)
    pub_packed = [
        attr_bool(CKA_ENCAPSULATE, True),
        attr_ulong(CKA_PARAMETER_SET, CKP_ML_KEM_768),
        attr_bool(CKA_TOKEN, False),
    ]
    priv_packed = [
        attr_bool(CKA_DECAPSULATE, True),
        attr_ulong(CKA_PARAMETER_SET, CKP_ML_KEM_768),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_SENSITIVE, False),
        attr_bool(CKA_EXTRACTABLE, False),
    ]
    if pub_list is not None:
        pub_packed.append(attr_array(CKA_ALLOWED_MECHANISMS, pub_list))
    if priv_list is not None:
        priv_packed.append(attr_array(CKA_ALLOWED_MECHANISMS, priv_list))
    if tag is not None:
        pub_packed.append(attr_bytes(CKA_LABEL, f"{tag}-pub".encode()))
        priv_packed.append(attr_bytes(CKA_LABEL, f"{tag}-priv".encode()))
    pub_tmpl = template(*pub_packed)
    priv_tmpl = template(*priv_packed)
    pub = CK_OBJECT_HANDLE(0)
    priv = CK_OBJECT_HANDLE(0)
    from pkcs11_check.raw.rv import expect_rv

    rv = raw.C_GenerateKeyPair(
        sh,
        mech.byref(),
        pub_tmpl.ptr,
        pub_tmpl.count,
        priv_tmpl.ptr,
        priv_tmpl.count,
        byref(pub),
        byref(priv),
    )
    expect_rv(rv, CKR_OK)
    return pub.value, priv.value


@pytest.mark.needs_function("C_EncapsulateKey")
class TestEncapsulateKeyErrors:
    """Error conditions for C_EncapsulateKey (Sec.5.14.7)."""

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using AES mechanism for encapsulate -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("ML_KEM not supported")
        pub, _priv = _generate_ml_kem_keypair(rs.raw, rs.sh)
        try:
            mech = mech_simple(CKM_AES_ECB)  # Wrong: not a KEM mechanism
            # C_EncapsulateKey(session, mech, key, pTemplate, ulCount, pCiphertext,
            #                  pulCiphertextLen, phSecret)
            ct_len = CK_ULONG(0)
            secret = CK_OBJECT_HANDLE(0)
            secret_tmpl = template()
            rv = rs.raw.C_EncapsulateKey(
                rs.sh,
                mech.byref(),
                pub,
                secret_tmpl.ptr,
                secret_tmpl.count,
                None,
                byref(ct_len),
                byref(secret),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, secret.value)
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_EncapsulateKey:AES-mechanism",
                    operation="C_EncapsulateKey",
                    actual=rv,
                    summary="Should have rejected AES_ECB as encapsulate mechanism",
                )
            assert_ckr(CKR_KEM["encap_mechanism_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, _priv)

    def test_key_type_inconsistent(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """RSA key with ML-KEM mechanism -> CKR_KEY_TYPE_INCONSISTENT."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("ML_KEM not supported")
        from pkcs11_check.raw.recipes import gen_rsa_keypair

        pub, _priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            mech = mech_simple(CKM_ML_KEM)
            ct_len = CK_ULONG(0)
            secret = CK_OBJECT_HANDLE(0)
            secret_tmpl = template()
            rv = rs.raw.C_EncapsulateKey(
                rs.sh,
                mech.byref(),
                pub,
                secret_tmpl.ptr,
                secret_tmpl.count,
                None,
                byref(ct_len),
                byref(secret),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, secret.value)
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_EncapsulateKey:key-type-inconsistent",
                    operation="C_EncapsulateKey",
                    mechanism="CKM_ML_KEM",
                    actual=rv,
                    summary="Should have rejected RSA key with ML-KEM mechanism",
                )
            assert_ckr(CKR_KEM["encap_key_type_inconsistent"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, _priv)

    @pytest.mark.parametrize("handle_kind", ["destroyed", "zero", "never_issued"])
    def test_encapsulation_key_handle_invalid(
        self, p11_raw_session: Any, ckr_strict: bool, handle_kind: str
    ) -> None:
        """QC8a role 4: invalid encap key -> CKR_KEY_HANDLE_INVALID.

        Spec-table key ``encap_key_handle_invalid``. A single raw
        C_EncapsulateKey call with a real ciphertext buffer: the recipe's
        two-call size query could itself create a secret and corrupt a
        refusal probe.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("ML_KEM not supported")
        pub, priv = _generate_ml_kem_keypair(rs.raw, rs.sh)
        pub_destroyed = False
        try:
            if handle_kind == "destroyed":
                rv = rs.raw.C_DestroyObject(rs.sh, pub)
                if rv != CKR_OK:
                    raise AssertionError(
                        f"Could not destroy ML-KEM public key for stale test (CKR=0x{rv:08x})"
                    )
                pub_destroyed = True
                invalid = pub
            else:
                invalid = _nonissued_handle(handle_kind)
            before = _inventory_or_unproved(
                rs,
                label="C_EncapsulateKey:invalid-encapsulation-key-handle",
                operation="C_EncapsulateKey",
                canonical=int(CKR_KEY_HANDLE_INVALID),
            )
            mech = mech_simple(CKM_ML_KEM)
            ct_buf = (ctypes.c_ubyte * _CT_LEN)()
            ct_len = CK_ULONG(_CT_LEN)
            secret = CK_OBJECT_HANDLE(_HANDLE_SENTINEL)
            secret_tmpl = template()
            C.set_mechanism("CKM_ML_KEM", "C_EncapsulateKey", expect_success=False)
            rv = rs.raw.C_EncapsulateKey(
                rs.sh,
                mech.byref(),
                invalid,
                secret_tmpl.ptr,
                secret_tmpl.count,
                ct_buf,
                byref(ct_len),
                byref(secret),
            )
            after = _inventory_or_unproved(
                rs,
                label="C_EncapsulateKey:invalid-encapsulation-key-handle",
                operation="C_EncapsulateKey",
                canonical=int(CKR_KEY_HANDLE_INVALID),
                refusal_rv=int(rv),
            )
            new_handles = sorted(set(after) - set(before))
            proved_new = _proved_new(int(secret.value), before, new_handles)
            _probe_cleanup(rs, proved_new_handles=proved_new)
            _judge_kem_handle_probe(
                rv=int(rv),
                canonical=int(CKR_KEY_HANDLE_INVALID),
                label="C_EncapsulateKey:invalid-encapsulation-key-handle",
                operation="C_EncapsulateKey",
                handle_after=int(secret.value),
                new_handles=new_handles,
                proved_new_handles=proved_new,
            )
        finally:
            if not pub_destroyed:
                destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


@pytest.mark.needs_function("C_DecapsulateKey")
class TestDecapsulateKeyErrors:
    """Error conditions for C_DecapsulateKey (Sec.5.14.8)."""

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using AES mechanism for decapsulate -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("ML_KEM not supported")
        _pub, priv = _generate_ml_kem_keypair(rs.raw, rs.sh)
        try:
            mech = mech_simple(CKM_AES_ECB)  # Wrong: not a KEM mechanism
            ct_buf = (ctypes.c_ubyte * 1088)(*([0] * 1088))  # ML-KEM-768 ct size
            secret = CK_OBJECT_HANDLE(0)
            secret_tmpl = template()
            rv = rs.raw.C_DecapsulateKey(
                rs.sh,
                mech.byref(),
                priv,
                secret_tmpl.ptr,
                secret_tmpl.count,
                ct_buf,
                1088,
                byref(secret),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, secret.value)
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_DecapsulateKey:AES-mechanism",
                    operation="C_DecapsulateKey",
                    actual=rv,
                    summary="Should have rejected AES_ECB as decapsulate mechanism",
                )
            assert_ckr(CKR_KEM["decap_mechanism_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, _pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_garbage_ciphertext(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Decapsulate garbage ciphertext - reject or implicit rejection."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("ML_KEM not supported")
        _pub, priv = _generate_ml_kem_keypair(rs.raw, rs.sh)
        try:
            exp = CKR_KEM["decap_ciphertext_invalid"]
            mech = mech_simple(CKM_ML_KEM)
            # ML-KEM-768 ciphertext = 1088 bytes. Provide garbage.
            ct_buf = (ctypes.c_ubyte * 1088)(*([0xFF] * 1088))
            secret = CK_OBJECT_HANDLE(0)
            secret_tmpl = template()
            rv = rs.raw.C_DecapsulateKey(
                rs.sh,
                mech.byref(),
                priv,
                secret_tmpl.ptr,
                secret_tmpl.count,
                ct_buf,
                1088,
                byref(secret),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, secret.value)
                # ML-KEM implicit rejection: may produce a key (spec allows this)
                if not exp.allow_success:
                    classify(
                        "accepted_invalid",
                        kind="crypto",
                        label="C_DecapsulateKey:garbage-ciphertext",
                        operation="C_DecapsulateKey",
                        mechanism="CKM_ML_KEM",
                        actual=rv,
                        summary="Should have rejected garbage ciphertext",
                    )
            else:
                assert_ckr(exp, rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, _pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize("handle_kind", ["destroyed", "zero", "never_issued"])
    def test_decapsulation_key_handle_invalid(
        self, p11_raw_session: Any, ckr_strict: bool, handle_kind: str
    ) -> None:
        """QC8a role 5: invalid decap key -> CKR_UNWRAPPING_KEY_HANDLE_INVALID.

        Spec-table key ``decap_unwrapping_key_handle_invalid``. The
        ciphertext is a real encapsulation against the valid public half,
        so no ciphertext defect can mask the handle check.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("ML_KEM not supported")
        pub, priv = _generate_ml_kem_keypair(rs.raw, rs.sh)
        priv_destroyed = False
        staged_secret = 0
        try:
            # Stage a real ciphertext with a single raw encapsulate call.
            mech = mech_simple(CKM_ML_KEM)
            stage_buf = (ctypes.c_ubyte * _CT_LEN)()
            stage_len = CK_ULONG(_CT_LEN)
            stage_secret = CK_OBJECT_HANDLE(0)
            stage_tmpl = template()
            stage_before = _staging_inventory(rs)
            rv = rs.raw.C_EncapsulateKey(
                rs.sh,
                mech.byref(),
                pub,
                stage_tmpl.ptr,
                stage_tmpl.count,
                stage_buf,
                byref(stage_len),
                byref(stage_secret),
            )
            stage_handle = int(stage_secret.value)
            if rv != CKR_OK:
                # Early-exit cleanup (R10-02): a staging refusal may still
                # have created the secret, which must not leak alive.
                proved, new_handles, inv_rv = _staging_partition(rs, stage_before, stage_handle)
                _probe_cleanup(rs, proved_new_handles=proved)
                if not (is_standard_ckr(int(rv)) or is_vendor_defined_ckr(int(rv))):
                    fail_as(
                        "self_contradiction",
                        kind="metadata",
                        label="C_EncapsulateKey:ML-KEM staging",
                        operation="C_EncapsulateKey",
                        mechanism="CKM_ML_KEM",
                        actual=int(rv),
                        spec_ref="PKCS#11 v3.2",
                        summary=(
                            "ML-KEM encapsulate staging refused with undefined "
                            f"CK_RV {ckr_name(int(rv))}"
                        ),
                    )
                if proved:
                    fail_as(
                        "self_contradiction",
                        kind="lifecycle",
                        label="C_EncapsulateKey:ML-KEM staging",
                        operation="C_EncapsulateKey",
                        mechanism="CKM_ML_KEM",
                        actual=int(rv),
                        spec_ref="PKCS#11 v3.2",
                        summary=(
                            "Staging encapsulate refused with "
                            f"{ckr_name(int(rv))} but created secret "
                            f"{proved[0]}"
                        ),
                        detail={
                            "handle_after": stage_handle,
                            "new_handles": new_handles,
                            "proved_new_handles": proved,
                        },
                    )
                if new_handles is None:
                    # The partition inventory failed cleanly: nothing is
                    # provable, so the refusal cannot read as a clean
                    # zero-delta refusal (self-review followup).
                    inv_name = ckr_name(inv_rv) if inv_rv is not None else "unknown"
                    xfail_as(
                        "honest_deviation",
                        kind="lifecycle",
                        label="C_EncapsulateKey:ML-KEM staging",
                        operation="C_EncapsulateKey",
                        mechanism="CKM_ML_KEM",
                        actual=int(rv),
                        spec_ref="PKCS#11 v3.2",
                        summary=(
                            "Staging encapsulate refused but the cleanup "
                            f"inventory failed with {inv_name}; "
                            "zero-delta unproved"
                        ),
                        detail={
                            "disposition": "unproved-effect",
                            "handle_after": stage_handle,
                            "inventory_rv": inv_name,
                            "refusal_rv": ckr_name(int(rv)),
                        },
                    )
                if new_handles:
                    xfail_as(
                        "honest_deviation",
                        kind="lifecycle",
                        label="C_EncapsulateKey:ML-KEM staging",
                        operation="C_EncapsulateKey",
                        mechanism="CKM_ML_KEM",
                        actual=int(rv),
                        spec_ref="PKCS#11 v3.2",
                        summary=(
                            "Staging encapsulate refused but the inventory "
                            f"gained unproved objects {new_handles}"
                        ),
                        detail={
                            "handle_after": stage_handle,
                            "new_handles": new_handles,
                            "proved_new_handles": proved,
                        },
                    )
                xfail_as(
                    "not_operational",
                    label="C_EncapsulateKey:ML-KEM staging",
                    operation="C_EncapsulateKey",
                    mechanism="CKM_ML_KEM",
                    actual=rv,
                    summary=f"ML-KEM encapsulate staging not operational: {ckr_name(rv)}",
                    detail={
                        "handle_after": stage_handle,
                        "new_handles": new_handles,
                        "proved_new_handles": proved,
                    },
                )
            # A success returning a zero or already-known handle is a
            # knowable contradiction; no after inventory can rescue it
            # (R10-01), so it is judged before any further inventory.
            if stage_handle == 0 or stage_handle in stage_before:
                fail_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label="C_EncapsulateKey:ML-KEM staging",
                    operation="C_EncapsulateKey",
                    mechanism="CKM_ML_KEM",
                    actual=int(rv),
                    spec_ref="PKCS#11 v3.2",
                    summary=(
                        "Staging encapsulate reported success but its secret "
                        f"handle {stage_handle} is "
                        + (
                            "zero"
                            if stage_handle == 0
                            else "a pre-existing object from the before inventory"
                        )
                    ),
                    detail={"handle_after": stage_handle},
                )
            if not (0 < int(stage_len.value) <= _CT_LEN):
                proved, new_handles, part_inv_rv = _staging_partition(
                    rs, stage_before, stage_handle
                )
                _probe_cleanup(rs, proved_new_handles=proved)
                fail_as(
                    "wrong_result",
                    kind="metadata",
                    label="C_EncapsulateKey:ML-KEM staging ciphertext length",
                    operation="C_EncapsulateKey",
                    mechanism="CKM_ML_KEM",
                    actual=int(stage_len.value),
                    summary="Staging encapsulate reported an implausible ciphertext length",
                    detail={
                        "handle_after": stage_handle,
                        "new_handles": new_handles,
                        "proved_new_handles": proved,
                        "inventory_rv": (
                            ckr_name(part_inv_rv) if part_inv_rv is not None else None
                        ),
                    },
                )
            # The staging output handle is owned only when the exhaustive
            # delta proves it new; a pre-existing handle handed back as
            # the staged secret is never destroyed here (R9-01).
            stage_after = _staging_inventory(rs)
            stage_new = sorted(set(stage_after) - set(stage_before))
            stage_proved = _proved_new(stage_handle, stage_before, stage_new)
            if not stage_proved:
                fail_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label="C_EncapsulateKey:ML-KEM staging",
                    operation="C_EncapsulateKey",
                    mechanism="CKM_ML_KEM",
                    actual=int(rv),
                    spec_ref="PKCS#11 v3.2",
                    summary=(
                        "Staging encapsulate reported success but its secret "
                        f"handle {stage_handle} is not a proved-new "
                        "object in the exhaustive inventory delta"
                    ),
                    detail={
                        "handle_after": stage_handle,
                        "new_handles": stage_new,
                        "proved_new_handles": stage_proved,
                    },
                )
            staged_secret = stage_proved[0]
            ciphertext = bytes(stage_buf[: int(stage_len.value)])
            if staged_secret:
                destroy_quietly(rs.raw, rs.sh, staged_secret)
                staged_secret = 0
            if handle_kind == "destroyed":
                rv = rs.raw.C_DestroyObject(rs.sh, priv)
                if rv != CKR_OK:
                    raise AssertionError(
                        f"Could not destroy ML-KEM private key for stale test (CKR=0x{rv:08x})"
                    )
                priv_destroyed = True
                invalid = priv
            else:
                invalid = _nonissued_handle(handle_kind)
            # No object creation between the destroy above and the probe.
            before = _inventory_or_unproved(
                rs,
                label="C_DecapsulateKey:invalid-decapsulation-key-handle",
                operation="C_DecapsulateKey",
                canonical=int(CKR_UNWRAPPING_KEY_HANDLE_INVALID),
            )
            ct_buf = (ctypes.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext)
            secret = CK_OBJECT_HANDLE(_HANDLE_SENTINEL)
            secret_tmpl = template()
            C.set_mechanism("CKM_ML_KEM", "C_DecapsulateKey", expect_success=False)
            rv = rs.raw.C_DecapsulateKey(
                rs.sh,
                mech.byref(),
                invalid,
                secret_tmpl.ptr,
                secret_tmpl.count,
                ct_buf,
                len(ciphertext),
                byref(secret),
            )
            after = _inventory_or_unproved(
                rs,
                label="C_DecapsulateKey:invalid-decapsulation-key-handle",
                operation="C_DecapsulateKey",
                canonical=int(CKR_UNWRAPPING_KEY_HANDLE_INVALID),
                refusal_rv=int(rv),
            )
            new_handles = sorted(set(after) - set(before))
            proved_new = _proved_new(int(secret.value), before, new_handles)
            _probe_cleanup(rs, proved_new_handles=proved_new)
            _judge_kem_handle_probe(
                rv=int(rv),
                canonical=int(CKR_UNWRAPPING_KEY_HANDLE_INVALID),
                label="C_DecapsulateKey:invalid-decapsulation-key-handle",
                operation="C_DecapsulateKey",
                handle_after=int(secret.value),
                new_handles=new_handles,
                proved_new_handles=proved_new,
            )
        finally:
            if staged_secret:
                destroy_quietly(rs.raw, rs.sh, staged_secret)
            destroy_quietly(rs.raw, rs.sh, pub)
            if not priv_destroyed:
                destroy_quietly(rs.raw, rs.sh, priv)


@pytest.mark.needs_function("C_EncapsulateKey")
class TestAllowedMechanismsEncapsulate:
    """QC4a (#56.1): ALLOWED_MECHANISMS enforcement on the encapsulate public key."""

    @pytest.mark.parametrize("leg", ["included", "excluded"])
    def test_encapsulate_policy_leg(self, p11_raw_session: Any, leg: str) -> None:
        """Included must complete with a verified effect; excluded must refuse."""
        _qc4._run_encapsulate_policy_leg(p11_raw_session, leg)


@pytest.mark.needs_function("C_DecapsulateKey")
class TestAllowedMechanismsDecapsulate:
    """QC4a (#56.1): ALLOWED_MECHANISMS enforcement on the decapsulate private key."""

    @pytest.mark.parametrize("leg", ["included", "excluded"])
    def test_decapsulate_policy_leg(self, p11_raw_session: Any, leg: str) -> None:
        """Included must complete with a verified effect; excluded must refuse."""
        _qc4._run_decapsulate_policy_leg(p11_raw_session, leg)
