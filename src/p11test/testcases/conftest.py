"""Shared fixtures and helpers for p11test PKCS#11 test cases.

Note: Test skipping for missing module, version, and destructive markers
is handled in plugin.py's pytest_collection_modifyitems hook.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as _p11
from pkcs11 import Attribute, KeyType, ObjectClass


def mech_name(m: Any) -> str:
    """Get mechanism name safely — handles both Mechanism enum and raw int."""
    name = getattr(m, "name", None)
    if isinstance(name, str):
        return name
    if name is not None:
        return str(name)
    if isinstance(m, int):
        return f"0x{m:08x}"
    return str(m)


def import_aes_key(session: Any, key_bytes: bytes, **extra: Any) -> Any:
    """Import raw AES key bytes into a PKCS#11 session object.

    Returns a secret key object with encrypt, decrypt, and extract capabilities.
    """
    template: dict[Attribute, Any] = {
        Attribute.CLASS: ObjectClass.SECRET_KEY,
        Attribute.KEY_TYPE: KeyType.AES,
        Attribute.VALUE: key_bytes,
        Attribute.ENCRYPT: True,
        Attribute.DECRYPT: True,
        Attribute.TOKEN: False,
        Attribute.SENSITIVE: False,
        Attribute.EXTRACTABLE: True,
    }
    template.update(extra)
    return session.create_object(template)


def has_mechanism(p11_module: Any, name: str) -> bool:
    """Check if a PKCS#11 module supports a named mechanism."""
    slot = p11_module.get_slots(token_present=True)[0]
    names = {mech_name(m) for m in slot.get_mechanisms()}
    return name in names


def open_session(token: Any, rw: bool = True, pin: str | None = None) -> Any:
    """Open a PKCS#11 session, handling UserAlreadyLoggedIn gracefully.

    PKCS#11 login is per-token, not per-session. If another test left a login
    active, token.open(user_pin=...) will fail. This helper catches that and
    opens without re-login.
    """
    try:
        return token.open(rw=rw, user_pin=pin)
    except _p11.exceptions.UserAlreadyLoggedIn:
        session = token.open(rw=rw)
        try:
            if pin is not None:
                session.login(_p11.UserType.USER, pin)
        except _p11.exceptions.UserAlreadyLoggedIn:
            pass
        return session


def extract_ec_point(ec_point_der: Any) -> Any:
    """Extract raw uncompressed EC point from DER OCTET STRING wrapper.

    PKCS#11 EC_POINT attribute is DER-encoded: 0x04 <length> <point_bytes>.
    Returns the raw point bytes (starting with 0x04 uncompressed prefix).
    """
    if ec_point_der[0] == 0x04:
        if ec_point_der[1] < 128:
            return ec_point_der[2:]
        return ec_point_der[3:]
    return ec_point_der
