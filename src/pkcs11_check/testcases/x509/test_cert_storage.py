"""Certificate-object storage characterization.

No mechanism advertises cert-object storage, so each template is a behavioral probe.
A stored cert -> pass; a clean refusal -> xfail (not_operational), with the refusal CKR
named (and flagged when non-spec, e.g. CKR_KEY_HANDLE_INVALID for a no-input-handle
C_CreateObject). A crash or a non-refusal code is a real finding (propagates / fail).

Reuses cert_storage_templates() + attempt_store_cert() from x509/conftest.py — the same
single source of truth the capability probe uses (no duplicated templates or logic)."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import CKR_TEMPLATE_INCOMPLETE
from pkcs11_check.testcases.x509.conftest import (
    _canonical_self_signed_cert_der,
    _minimal_cert_template,
    attempt_store_cert,
    cert_storage_templates,
)

pytestmark = [pytest.mark.cert, pytest.mark.object]

_NONSPEC_FOR_CREATE = {
    "CKR_KEY_HANDLE_INVALID",
    "CKR_USER_TYPE_INVALID",
}  # meaningless for a no-input-handle C_CreateObject
_CASES = cert_storage_templates(_canonical_self_signed_cert_der())


@pytest.mark.parametrize("name,template", _CASES, ids=[c[0] for c in _CASES])
def test_cert_storage_template(p11_raw_session: Any, name: str, template: dict[int, Any]) -> None:
    rs = p11_raw_session
    handle, rv = attempt_store_cert(rs, template)  # non-refusal CKR / crash propagates here
    if handle is not None:
        destroy_quietly(rs.raw, rs.sh, handle)
        return  # stored -> pass
    assert rv is not None  # a clean refusal always carries a code
    code = ckr_name(rv)
    note = " (non-spec for C_CreateObject)" if code in _NONSPEC_FOR_CREATE else ""
    classify(
        "not_operational",
        label=f"cert-storage:{name}",
        operation="C_CreateObject",
        summary=(
            f"No mechanism advertises certificate-object storage; template '{name}' "
            f"was refused with {code}{note}"
        ),
    )


def test_cert_storage_requires_subject(p11_raw_session: Any) -> None:
    """Negative/conformance: omitting the mandatory CKA_SUBJECT (OASIS PKCS#11
    certificate-objects ^1^ -- MUST be specified at creation) must be rejected.
    CKR_TEMPLATE_INCOMPLETE -> pass
    (correct enforcement); another clean reject -> xfail (nonspec_reject); accepted -> xfail
    (honest_deviation -- the module stored a cert omitting a mandatory attribute). A crash or
    non-refusal CKR propagates as a real finding via attempt_store_cert."""
    rs = p11_raw_session
    handle, rv = attempt_store_cert(rs, _minimal_cert_template(_canonical_self_signed_cert_der()))
    if handle is not None:
        destroy_quietly(rs.raw, rs.sh, handle)
        classify(
            "honest_deviation",
            kind="metadata",
            label="cert-storage:omit-mandatory-subject",
            operation="C_CreateObject",
            summary="Module stored a certificate template omitting the mandatory CKA_SUBJECT",
        )
        return
    assert rv is not None  # a clean refusal always carries a code
    if rv == int(CKR_TEMPLATE_INCOMPLETE):
        return  # pass: module correctly enforces mandatory CKA_SUBJECT
    classify(
        "nonspec_reject",
        kind="metadata",
        label="cert-storage:omit-mandatory-subject",
        operation="C_CreateObject",
        expected=[CKR_TEMPLATE_INCOMPLETE],
        actual=rv,
        summary=(
            f"Cert template omitting mandatory CKA_SUBJECT rejected with {ckr_name(rv)}, "
            f"not the spec-preferred CKR_TEMPLATE_INCOMPLETE"
        ),
    )
