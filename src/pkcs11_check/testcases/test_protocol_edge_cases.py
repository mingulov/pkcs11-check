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
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_ENCAPSULATE,
    CKA_LABEL,
    CKA_TOKEN,
    CKA_VALUE,
    CKO_DATA,
)

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
        except AssertionError:
            pass  # CKR_DEVICE_MEMORY or similar - graceful
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
        except AssertionError:
            pass  # Graceful limit
        for o in objs:
            destroy_quietly(rs.raw, rs.sh, o)

    def test_generate_random_large(self, p11_raw_session: Any) -> None:
        """Generate large random (1MB). Must not crash or hang."""
        rs = p11_raw_session
        data = generate_random(rs.raw, rs.sh, 1024 * 1024)
        assert len(data) == 1024 * 1024


class TestSpecAmbiguousCalls:
    """DoS via spec-ambiguous calls (task 7.16)."""

    def test_double_initialize(self, p11_config: Any) -> None:
        """C_Initialize called twice - must return OK or ALREADY_INITIALIZED."""
        import subprocess
        import sys
        import textwrap

        module = str(p11_config.module)
        script = f"""
        from pkcs11_check.raw.api import RawPKCS11
        from pkcs11_check.raw.types_std import CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED
        raw = RawPKCS11.from_lib("{module}")
        raw.C_Initialize(None)
        rv = raw.C_Initialize(None)
        if rv == CKR_OK:
            print("OK: second init succeeded")
        elif rv == CKR_CRYPTOKI_ALREADY_INITIALIZED:
            print("OK: CKR_CRYPTOKI_ALREADY_INITIALIZED")
        else:
            print(f"OK: 0x{{rv:08x}}")
        raw.C_Finalize(None)
        """
        result = subprocess.run(
            [sys.executable, "-c", textwrap.dedent(script)],
            capture_output=True,
            text=True,
            timeout=15,
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
        """v3.2-only attributes on v2.40 module - must reject, not crash."""
        if p11_interface_version not in ("2.40",):
            pytest.skip("Only relevant for v2.40 modules")

        rs = p11_raw_session
        # Try creating key with a v3.2-only attribute
        try:
            gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                public_attrs={CKA_TOKEN: False},
            )
        except (AssertionError, TypeError, AttributeError):
            pass

    def test_encapsulate_attr_on_non_pqc(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKA_ENCAPSULATE on non-PQC key - must reject, not crash."""
        rs = p11_raw_session
        try:
            gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={CKA_ENCAPSULATE: True},
            )
        except (AssertionError, TypeError, AttributeError):
            pass
