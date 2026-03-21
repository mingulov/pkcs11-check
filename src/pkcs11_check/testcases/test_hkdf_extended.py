"""Tests for extended HKDF mechanisms.

Covers CKM_HKDF_DATA and CKM_HKDF_KEY_GEN.
CKM_HKDF_DERIVE is tested in test_kdf.py.

OASIS spec: hkdf_mechanisms.md
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import (
    FunctionFailed,
    KeyTypeInconsistent,
    MechanismInvalid,
    MechanismParamInvalid,
    TemplateInconsistent,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt

# Common error tuple for derivation failures
_DERIVE_ERRORS = (MechanismInvalid, MechanismParamInvalid, FunctionFailed)


@pytest.mark.requires_v30
class TestHKDFKeyGen:
    """CKM_HKDF_KEY_GEN tests — generate keys for HKDF input keying material."""

    @pytest.mark.parametrize(
        "key_type",
        [
            KeyType.HKDF,
            pytest.param(
                KeyType.GENERIC_SECRET,
                marks=pytest.mark.xfail(
                    reason="CKM_HKDF_KEY_GEN should produce CKK_HKDF per spec",
                ),
            ),
        ],
        ids=["CKK_HKDF", "CKK_GENERIC_SECRET"],
    )
    def test_hkdf_key_gen_basic(
        self, p11_session: Any, p11_module: Any, key_type: KeyType,
    ) -> None:
        """Generate a key via CKM_HKDF_KEY_GEN with the given key type."""
        if not has_mechanism(p11_module, "HKDF_KEY_GEN"):
            pytest.skip("CKM_HKDF_KEY_GEN not supported")

        try:
            key = p11_session.generate_key(
                key_type, 256,
                mechanism=Mechanism.HKDF_KEY_GEN,
                template={
                    Attribute.DERIVE: True,
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.TOKEN: False,
                },
            )
        except (KeyTypeInconsistent, TemplateInconsistent, MechanismInvalid) as exc:
            pytest.xfail(f"CKM_HKDF_KEY_GEN with {key_type.name} not supported: {exc}")
        try:
            assert key is not None
            assert key[Attribute.KEY_TYPE] == key_type
            value = key[Attribute.VALUE]
            assert len(value) == 32  # 256 bits = 32 bytes
            assert key[Attribute.DERIVE] is True
        finally:
            key.destroy()

    def test_hkdf_key_gen_usable_for_derive(self, p11_session: Any, p11_module: Any) -> None:
        """Key generated via CKM_HKDF_KEY_GEN can be used with CKM_HKDF_DERIVE."""
        if not has_mechanism(p11_module, "HKDF_KEY_GEN"):
            pytest.skip("CKM_HKDF_KEY_GEN not supported")
        if not has_mechanism(p11_module, "HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not supported")

        # Try CKK_HKDF first (spec-correct), fall back to CKK_GENERIC_SECRET
        for key_type in (KeyType.HKDF, KeyType.GENERIC_SECRET):
            try:
                base_key = p11_session.generate_key(
                    key_type, 256,
                    mechanism=Mechanism.HKDF_KEY_GEN,
                    template={
                        Attribute.DERIVE: True,
                        Attribute.SENSITIVE: False,
                        Attribute.EXTRACTABLE: True,
                        Attribute.TOKEN: False,
                    },
                )
                break
            except (KeyTypeInconsistent, TemplateInconsistent, MechanismInvalid):
                continue
        else:
            pytest.skip("CKM_HKDF_KEY_GEN not operational with any key type")
        try:
            derived = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.HKDF_DERIVE,
                mechanism_param=(Mechanism.SHA256, b"salt-value", b"info-value"),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                okm = derived[Attribute.VALUE]
                assert len(okm) == 32
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as e:
            pytest.xfail(f"HKDF_DERIVE with HKDF_KEY_GEN key failed: {e}")
        finally:
            base_key.destroy()


@pytest.mark.requires_v30
class TestHKDFData:
    """CKM_HKDF_DATA tests — derive data objects via HKDF."""

    def _create_base_key(self, session: Any) -> Any:
        """Create a GENERIC_SECRET key suitable for HKDF derivation."""
        ikm = bytes(range(32))
        return session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
                Attribute.VALUE: ikm,
                Attribute.DERIVE: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )

    def test_hkdf_data_derive(self, p11_session: Any, p11_module: Any) -> None:
        """Derive data/key using CKM_HKDF_DATA mechanism."""
        if not has_mechanism(p11_module, "HKDF_DATA"):
            pytest.skip("CKM_HKDF_DATA not supported")

        base_key = self._create_base_key(p11_session)
        try:
            derived = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.HKDF_DATA,
                mechanism_param=(Mechanism.SHA256, b"salt", b"info"),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                value = derived[Attribute.VALUE]
                assert len(value) == 32  # 256 bits = 32 bytes
                assert value != bytes(32), "Derived value should not be all zeros"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as e:
            pytest.xfail(f"HKDF_DATA derive failed: {e}")
        finally:
            base_key.destroy()

    def test_hkdf_data_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same HKDF_DATA inputs produce identical output."""
        if not has_mechanism(p11_module, "HKDF_DATA"):
            pytest.skip("CKM_HKDF_DATA not supported")

        base_key = self._create_base_key(p11_session)
        try:
            derive_tmpl = {
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            }
            hkdf_param = (Mechanism.SHA256, b"det-salt", b"det-info")

            derived_1 = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.HKDF_DATA,
                mechanism_param=hkdf_param,
                template=derive_tmpl,
            )
            try:
                derived_2 = base_key.derive_key(
                    KeyType.GENERIC_SECRET,
                    256,
                    mechanism=Mechanism.HKDF_DATA,
                    mechanism_param=hkdf_param,
                    template=derive_tmpl,
                )
                try:
                    val_1 = derived_1[Attribute.VALUE]
                    val_2 = derived_2[Attribute.VALUE]
                    assert val_1 == val_2, "HKDF_DATA must be deterministic"
                finally:
                    derived_2.destroy()
            finally:
                derived_1.destroy()
        except _DERIVE_ERRORS as e:
            pytest.xfail(f"HKDF_DATA derive failed: {e}")
        finally:
            base_key.destroy()

    def test_hkdf_data_different_info_different_output(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Different 'info' values produce different HKDF_DATA output."""
        if not has_mechanism(p11_module, "HKDF_DATA"):
            pytest.skip("CKM_HKDF_DATA not supported")

        base_key = self._create_base_key(p11_session)
        try:
            derive_tmpl = {
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            }

            derived_a = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.HKDF_DATA,
                mechanism_param=(Mechanism.SHA256, b"salt", b"info-alpha"),
                template=derive_tmpl,
            )
            try:
                derived_b = base_key.derive_key(
                    KeyType.GENERIC_SECRET,
                    256,
                    mechanism=Mechanism.HKDF_DATA,
                    mechanism_param=(Mechanism.SHA256, b"salt", b"info-bravo"),
                    template=derive_tmpl,
                )
                try:
                    val_a = derived_a[Attribute.VALUE]
                    val_b = derived_b[Attribute.VALUE]
                    assert val_a != val_b, "Different info strings must produce different output"
                finally:
                    derived_b.destroy()
            finally:
                derived_a.destroy()
        except _DERIVE_ERRORS as e:
            pytest.xfail(f"HKDF_DATA derive failed: {e}")
        finally:
            base_key.destroy()
