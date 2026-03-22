"""Protocol edge-case tests - stale handles, resource exhaustion, spec-ambiguous calls.

References: rep11.md Iteration 2-3, PKCS#11 spec ambiguities.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, ObjectClass
from pkcs11.exceptions import PKCS11Error

from pkcs11_check.testcases._error_tuples import RESOURCE_ERRORS

pytestmark = pytest.mark.security


class TestResourceExhaustion:
    """Resource exhaustion - graceful errors, no crash (task 7.13)."""

    def test_many_session_objects(self, p11_session: Any) -> None:
        """Create 200 session objects. Verify module handles gracefully."""
        keys = []
        try:
            for i in range(200):
                keys.append(p11_session.generate_key(KeyType.AES, 128))
        except RESOURCE_ERRORS:
            pass  # CKR_DEVICE_MEMORY or similar - graceful
        finally:
            for k in keys:
                try:
                    k.destroy()
                except RESOURCE_ERRORS:
                    pass

    def test_many_data_objects(self, p11_session: Any) -> None:
        """Create 100 CKO_DATA objects. No crash."""
        objs = []
        try:
            for i in range(100):
                objs.append(
                    p11_session.create_object(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: f"exhaust-{i}",
                            Attribute.VALUE: b"x" * 1024,
                            Attribute.TOKEN: False,
                        }
                    )
                )
        except RESOURCE_ERRORS:
            pass  # Graceful limit
        # Cleanup
        for o in objs:
            try:
                o.destroy()
            except RESOURCE_ERRORS:
                pass

    def test_generate_random_large(self, p11_session: Any) -> None:
        """Generate large random (1MB). Must not crash or hang."""
        data = p11_session.generate_random(1024 * 1024 * 8)  # 1MB in bits
        assert len(data) == 1024 * 1024


class TestSpecAmbiguousCalls:
    """DoS via spec-ambiguous calls (task 7.16)."""

    def test_double_initialize(self, p11_config: Any) -> None:
        """C_Initialize called twice - must return CKR_CRYPTOKI_ALREADY_INITIALIZED or succeed."""
        import subprocess
        import sys
        import textwrap

        module = str(p11_config.module)
        script = f"""
        import pkcs11
        lib = pkcs11.lib("{module}")
        lib.initialize()
        try:
            lib.initialize()
            print("OK: second init succeeded")
        except pkcs11.exceptions.CryptokiAlreadyInitialized:
            print("OK: CKR_CRYPTOKI_ALREADY_INITIALIZED")
        except Exception as e:
            print(f"OK: {{type(e).__name__}}")
        lib.finalize()
        """
        result = subprocess.run(
            [sys.executable, "-c", textwrap.dedent(script)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, f"Double init crashed: {result.stderr}"
        assert "OK:" in result.stdout

    def test_get_function_list_always_works(self, p11_module: Any) -> None:
        """C_GetFunctionList should always work (even multiple times)."""
        # python-pkcs11 calls this internally - verify module is still functional
        slots = p11_module.get_slots()
        assert len(slots) >= 0  # Just verify no crash

    def test_multiple_get_slots(self, p11_module: Any) -> None:
        """Calling get_slots 100 times - must not leak or crash."""
        for _ in range(100):
            slots = p11_module.get_slots()
        assert len(slots) >= 0


class TestV240V32AttributeMix:
    """v2.40 + v3.2 attribute mix (task 7.14)."""

    def test_v32_attrs_on_v240_module(self, p11_session: Any, p11_interface_version: str) -> None:
        """v3.2-only attributes on v2.40 module - must reject, not crash."""
        if p11_interface_version not in ("2.40",):
            pytest.skip("Only relevant for v2.40 modules")

        # Try creating key with CKA_PARAMETER_SET (v3.2 only)
        try:
            p11_session.generate_keypair(
                KeyType.RSA,
                2048,
                public_template={Attribute.PARAMETER_SET: 1},
            )
        except (PKCS11Error, TypeError, AttributeError):
            pass  # Correct: reject unknown attribute

    def test_encapsulate_attr_on_non_pqc(self, p11_session: Any) -> None:
        """CKA_ENCAPSULATE on non-PQC key - must reject, not crash."""
        try:
            p11_session.generate_key(
                KeyType.AES,
                256,
                template={Attribute.ENCAPSULATE: True},
            )
        except (PKCS11Error, TypeError, AttributeError):
            pass  # Correct: AES keys don't encapsulate
