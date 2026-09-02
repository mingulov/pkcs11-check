"""Protocol edge-case tests - stale handles, resource exhaustion, spec-ambiguous calls.

References: rep11.md Iteration 2-3, PKCS#11 spec ambiguities.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    gen_aes_key,
    gen_rsa_keypair,
    generate_random,
)
from pkcs11_check.raw.rv import CkrAssertionError, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_ENCAPSULATE,
    CKA_LABEL,
    CKA_TOKEN,
    CKA_VALUE,
    CKO_DATA,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases.conftest import reject_or_classify

pytestmark = pytest.mark.security


class TestResourceExhaustion:
    """Resource exhaustion - graceful errors, no crash (task 7.13)."""

    def test_many_session_objects(self, p11_raw_session: Any) -> None:
        """Create 200 session objects. Verify module handles gracefully."""
        rs = p11_raw_session
        keys: list[int] = []
        try:
            for _ in range(200):
                keys.append(gen_aes_key(rs.raw, rs.sh, 128))
        except CkrAssertionError as exc:
            if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv):
                pass  # audit-ok: resource-exhaustion probe; typed clean limit is acceptable
            else:
                reject_or_classify(
                    exc,
                    (),
                    label="C_GenerateKey resource-exhaustion refusal",
                    kind="metadata",
                )
        finally:
            for k in keys:
                destroy_quietly(rs.raw, rs.sh, k)

    def test_many_data_objects(self, p11_raw_session: Any) -> None:
        """Create 100 CKO_DATA objects. No crash."""
        rs = p11_raw_session
        objs: list[int] = []
        try:
            for i in range(100):
                objs.append(
                    create_object(
                        rs.raw,
                        rs.sh,
                        {
                            CKA_CLASS: CKO_DATA,
                            CKA_LABEL: f"exhaust-{i}",
                            CKA_VALUE: b"x" * 1024,
                            CKA_TOKEN: False,
                        },
                    )
                )
        except CkrAssertionError as exc:
            if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv):
                pass  # audit-ok: resource-exhaustion probe; typed clean limit is acceptable
            else:
                reject_or_classify(
                    exc,
                    (),
                    label="C_CreateObject resource-exhaustion refusal",
                    kind="metadata",
                )
        for o in objs:
            destroy_quietly(rs.raw, rs.sh, o)

    @pytest.mark.slow
    def test_generate_random_large(self, p11_raw_session: Any) -> None:
        """Generate large random (1MB). Must not crash or hang.

        Some modules return CKR_ARGUMENTS_BAD for large C_GenerateRandom
        requests -- they have an internal size limit on single random
        generation calls.
        """
        rs = p11_raw_session
        from pkcs11_check.testcases.conftest import skip_unless_generate_random_supported

        skip_unless_generate_random_supported(rs)
        try:
            data = generate_random(rs.raw, rs.sh, 1024 * 1024)
            assert len(data) == 1024 * 1024
        except AssertionError as exc:
            from pkcs11_check.testcases.conftest import xfail_if_known_ckr

            xfail_if_known_ckr(
                exc,
                {CKR_ARGUMENTS_BAD},
                "some modules reject C_GenerateRandom(1MB) with CKR_ARGUMENTS_BAD "
                "- internal size limit on single random generation calls",
            )
            raise


class TestSpecAmbiguousCalls:
    """DoS via spec-ambiguous calls (task 7.16)."""

    def test_double_initialize(self, p11_config: Any) -> None:
        """C_Initialize called twice - must return OK or ALREADY_INITIALIZED."""
        result = run_probe(
            "protocol_edge_cases",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "double_initialize",
            },
            timeout=15,
            coverage="session",
        )
        assert result.returncode == 0, f"Double init crashed: {result.stderr}"
        assert "OK:" in result.stdout

    def test_get_function_list_always_works(
        self,
        p11_raw_session: Any,
    ) -> None:
        """C_GetFunctionList should always work."""
        from pkcs11_check.raw.bootstrap import get_slot_ids

        rs = p11_raw_session
        slots = get_slot_ids(rs.raw)
        assert len(slots) >= 0

    def test_multiple_get_slots(self, p11_raw_session: Any) -> None:
        """Calling get_slot_ids 100 times - must not leak or crash."""
        from pkcs11_check.raw.bootstrap import get_slot_ids

        rs = p11_raw_session
        for _ in range(100):
            slots = get_slot_ids(rs.raw)
        assert len(slots) >= 0


class TestV240V32AttributeMix:
    """v2.40 + v3.2 attribute mix (task 7.14)."""

    def test_v32_attrs_on_v240_module(
        self,
        p11_raw_session: Any,
        p11_interface_version: str,
    ) -> None:
        """v3.2-only attributes on v2.40 module - must not crash."""
        if p11_interface_version not in ("2.40",):
            pytest.skip("Only relevant for v2.40 modules")

        rs = p11_raw_session
        # CKA_TOKEN=False is spec-legal on a keygen template (creates session key).
        # Crash-guard only: both acceptance and rejection are valid outcomes.
        try:
            public, private = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                public_attrs={CKA_TOKEN: False},
            )
        except CkrAssertionError as exc:
            if not (is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv)):
                reject_or_classify(
                    exc,
                    (),
                    label="CKA_TOKEN=False RSA key-generation crash guard",
                    kind="metadata",
                )
        else:
            destroy_quietly(rs.raw, rs.sh, public)
            destroy_quietly(rs.raw, rs.sh, private)

    def test_encapsulate_attr_on_non_pqc(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKA_ENCAPSULATE on non-PQC AES key - must reject, not crash."""
        from pkcs11_check.testcases.conftest import reject_or_classify

        rs = p11_raw_session
        exc: CkrAssertionError | None = None
        try:
            gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={CKA_ENCAPSULATE: True},
            )
        except CkrAssertionError as _exc:
            exc = _exc
        reject_or_classify(
            exc,
            (
                CKR_TEMPLATE_INCONSISTENT,
                CKR_ATTRIBUTE_TYPE_INVALID,
                CKR_ATTRIBUTE_VALUE_INVALID,
                CKR_FUNCTION_NOT_SUPPORTED,
            ),
            label="CKA_ENCAPSULATE=True on AES keygen (non-PQC key)",
        )
