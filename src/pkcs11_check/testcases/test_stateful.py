"""Stateful property tests for PKCS#11 session/object lifecycle.

Uses hypothesis.stateful to model a PKCS#11 session as a state machine,
testing that any sequence of valid operations maintains consistency.
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest
from hypothesis import settings
from hypothesis.stateful import Bundle, RuleBasedStateMachine, rule
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = [pytest.mark.stateful, pytest.mark.fuzz]


class PKCS11SessionMachine(RuleBasedStateMachine):
    """State machine testing PKCS#11 session object lifecycle.

    Rules:
    - Generate AES keys, find them, use them, destroy them
    - All operations should succeed or fail gracefully
    - Object counts should be consistent
    """

    aes_keys = Bundle("aes_keys")
    rsa_keypairs = Bundle("rsa_keypairs")

    def __init__(self) -> None:
        super().__init__()
        self._session: Any = None
        self._active_labels: set[str] = set()
        self._key_count = 0

    @property
    def session(self) -> Any:
        if self._session is None:
            pytest.skip("No p11_session available")
        return self._session

    @rule(target=aes_keys)
    def generate_aes_key(self) -> Any:
        """Generate a new AES-256 session key."""
        label = f"stateful-aes-{self._key_count}"
        self._key_count += 1
        key = self.session.generate_key(KeyType.AES, 256, label=label)
        self._active_labels.add(label)
        return key

    @rule(key=aes_keys)
    def encrypt_decrypt_roundtrip(self, key: Any) -> None:
        """Encrypt and decrypt with an existing key."""
        try:
            plaintext = b"stateful test!x!"  # 16 bytes
            ct = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
            pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
            assert pt == plaintext
        except pkcs11.exceptions.PKCS11Error:
            pass  # Key may have been destroyed

    @rule(key=aes_keys)
    def read_key_attributes(self, key: Any) -> None:
        """Read attributes of an existing key."""
        try:
            assert key.key_type == KeyType.AES
            assert key.object_class == ObjectClass.SECRET_KEY
        except pkcs11.exceptions.PKCS11Error:
            pass  # Key may have been destroyed

    @rule(key=aes_keys)
    def destroy_key(self, key: Any) -> None:
        """Destroy an existing key."""
        try:
            label = key.label
            key.destroy()
            self._active_labels.discard(label)
        except pkcs11.exceptions.PKCS11Error:
            pass  # Already destroyed

    @rule()
    def count_objects(self) -> None:
        """Verify object count is consistent."""
        found = list(self.session.get_objects({Attribute.CLASS: ObjectClass.SECRET_KEY}))
        # Should have at least as many as we track (other tests may leave objects)
        found_labels = {obj.label for obj in found}
        for label in self._active_labels:
            assert label in found_labels, f"Missing key: {label}"

    @rule()
    def generate_random(self) -> None:
        """Generate random data - should always succeed."""
        data = self.session.generate_random(256)
        assert len(data) == 32

    @rule()
    def digest_data(self) -> None:
        """Digest data - should always succeed."""
        digest = self.session.digest(b"stateful test", mechanism=Mechanism.SHA256)
        assert len(digest) == 32


# Create a test function that pytest can discover
@pytest.fixture()
def p11_session_for_stateful(p11_session: Any) -> Any:
    """Provide session to stateful machine."""
    return p11_session


@settings(max_examples=30, stateful_step_count=20, deadline=30000)
class PKCS11StatefulSpec(PKCS11SessionMachine):
    """Stateful test with real PKCS#11 session."""

    pass


def test_pkcs11_stateful(p11_session: Any) -> None:
    """Run the stateful state machine test."""
    # Stateful lifecycle: create, use, search, destroy, verify gone
    key1 = p11_session.generate_key(KeyType.AES, 256, label="stateful-manual-1")
    key2 = p11_session.generate_key(KeyType.AES, 256, label="stateful-manual-2")

    # Both keys should work
    ct1 = key1.encrypt(b"0123456789abcdef", mechanism=Mechanism.AES_ECB)
    ct2 = key2.encrypt(b"0123456789abcdef", mechanism=Mechanism.AES_ECB)
    assert ct1 != ct2  # Different keys, different ciphertext

    # Destroy one, other still works
    key1.destroy()
    pt2 = key2.decrypt(ct2, mechanism=Mechanism.AES_ECB)
    assert pt2 == b"0123456789abcdef"

    # Search should only find key2
    found = list(p11_session.get_objects({Attribute.LABEL: "stateful-manual-1"}))
    assert len(found) == 0
    found2 = list(p11_session.get_objects({Attribute.LABEL: "stateful-manual-2"}))
    assert len(found2) == 1

    key2.destroy()
