"""C_CreateObject availability conformance test (Phase 3 — provisioning).

Records, once per object class, whether the module provides ``C_CreateObject``
for that class.  On a module where ``C_CreateObject`` is absent or explicitly
prohibited, this single ``honest_deviation`` xfail replaces the thousands of
silent skips that would otherwise accumulate across the key-injection suite.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import xfail_as
from pkcs11_check.testcases._provisioning import profile_for

pytestmark = pytest.mark.provisioning


@pytest.mark.parametrize("obj_class", ["secret", "private", "public", "cert", "data"])
def test_create_object_available(p11_raw_session: Any, obj_class: str) -> None:
    """Record C_CreateObject availability for *obj_class* as a single finding.

    Probes whether the module accepts ``C_CreateObject`` for the given object
    class (``secret``, ``private``, ``public``, ``cert``, or ``data``).  A
    verdict of ``create_available`` is a clean pass.  ``create_absent`` or
    ``create_prohibited`` maps to a single ``honest_deviation`` xfail, making
    the provisioning-skip reason visible instead of leaving it implicit across
    many downstream skips.
    """
    rs = p11_raw_session
    verdict = profile_for(rs).create_verdict(obj_class)
    if verdict in ("create_absent", "create_prohibited"):
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=f"C_CreateObject:{obj_class}",
            operation="C_CreateObject",
            summary=f"C_CreateObject not available for {obj_class} objects ({verdict})",
        )
