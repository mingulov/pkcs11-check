"""Shared subprocess session preamble for PKCS#11 test scripts.

Generates Python code strings that set up a PKCS#11 session in a subprocess.
Used by test files that need crash-safe isolation via subprocess.run().
"""

from __future__ import annotations

import textwrap


def subprocess_session_preamble(
    module_path: str,
    slot_id: int | None = None,
    pin: str | None = None,
    *,
    extra_imports: str = "",
    slot_label: str | None = None,
) -> str:
    """Return Python code that sets up a PKCS#11 session.

    After executing the returned code, these variables are available:
    - ``raw``: RawPKCS11 instance (initialized)
    - ``sh``: int session handle (opened, logged in if pin provided)
    - ``slot_id``: int slot used

    Call ``cleanup()`` to close the session and finalize the module.

    Args:
        module_path: Path to the PKCS#11 .so module.
        slot_id: Explicit slot ID. If None, uses first available slot.
        pin: User PIN for login. If None, skips login.
        extra_imports: Additional import lines to include in the script.
        slot_label: If set, filter slots by token label substring.
    """
    slot_discovery = ""
    if slot_id is not None:
        slot_discovery = f"slot_id = {slot_id}"
    elif slot_label is not None:
        slot_discovery = textwrap.dedent(f"""\
            slots = get_slot_ids(raw, label="{slot_label}")
            if not slots:
                slots = get_slot_ids(raw)
            slot_id = slots[0]""")
    else:
        slot_discovery = "slot_id = get_slot_ids(raw)[0]"

    login_block = ""
    if pin is not None:
        login_block = f'login_user(raw, sh, CKU_USER, b"{pin}")'

    extra_line = f"\n{extra_imports}" if extra_imports else ""

    return textwrap.dedent(f"""\
        from pkcs11_check.raw.api import RawPKCS11
        from pkcs11_check.raw.bootstrap import (
            close_session_quietly, get_slot_ids, login_user, open_session,
        )
        from pkcs11_check.raw.types_std import (
            CKF_RW_SESSION, CKF_SERIAL_SESSION, CKR_OK, CKU_USER,
        ){extra_line}

        raw = RawPKCS11.from_lib("{module_path}")
        rv = raw.C_Initialize(None)
        assert rv in (CKR_OK, 0x00000191), f"C_Initialize: 0x{{rv:08x}}"

        {slot_discovery}
        sh = open_session(raw, slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        {login_block}

        def cleanup():
            close_session_quietly(raw, sh)
            raw.C_Finalize(None)
    """)
